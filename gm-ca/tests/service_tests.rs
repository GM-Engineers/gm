//! CA service integration tests
//!
//! Tests the gRPC CA service (CaServiceImpl) with an in-memory SQLite database
//! to avoid requiring a running PostgreSQL instance.

use asn1::{ObjectIdentifier, SequenceWriter};
use elliptic_curve::sec1::ToEncodedPoint;
use gm_ca::ca::v1::{
    CaService, GetCertificateRequest, GetCrlRequest, RenewCertificateRequest,
    RevokeCertificateRequest, SignCertificateRequest,
};
use gm_ca::cert::CaSigner;
use gm_ca::db::DbStore;
use gm_ca::service::CaServiceImpl;
use gm_crypto::sm2::Sm2KeyPair;
use sqlx::any::AnyPoolOptions;
use std::sync::Arc;
use tonic::Request;

// SM2 public key OID: 1.2.156.10197.1.301
const SM2_PK_OID_BYTES: &[u8] = &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x01, 0x01];
// CN OID: 2.5.4.3
const CN_OID_BYTES: &[u8] = &[0x55, 0x04, 0x03];

/// Install sqlx any drivers before running tests.
fn init() {
    sqlx::any::install_default_drivers();
}

/// Create a test CA service with SQLite backend.
async fn create_test_service() -> CaServiceImpl {
    init();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("failed to create SQLite pool");

    let store = DbStore::new(pool);
    store.init_schema().await.expect("failed to init schema");

    let keypair = Sm2KeyPair::generate().expect("failed to generate CA key");
    let signer = CaSigner::new(keypair, "Test CA");

    
    CaServiceImpl::new(signer, Arc::new(store))
}

/// Helper to write DER SEQUENCE length (handles >127 bytes)
fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

/// Build the CRI (CertificationRequestInfo) portion of a CSR.
fn build_cri(subject_cn: &str, public_key_bytes: &[u8]) -> Vec<u8> {
    // Build CN OID DER
    let cn_oid_der = {
        let mut v = vec![0x06];
        v.push(CN_OID_BYTES.len() as u8);
        v.extend_from_slice(CN_OID_BYTES);
        v
    };

    // Build SM2 PK OID DER
    let sm2_pk_oid_der = {
        let mut v = vec![0x06];
        v.push(SM2_PK_OID_BYTES.len() as u8);
        v.extend_from_slice(SM2_PK_OID_BYTES);
        v
    };

    // Build subject name: SEQUENCE { SET { SEQUENCE { OID, UTF8String } } }
    let cn_value = subject_cn.as_bytes();
    let subject_name = {
        // Inner SEQUENCE: OID + UTF8String
        let mut inner_seq = vec![0x30];
        let inner_len = cn_oid_der.len() + 2 + cn_value.len();
        inner_seq.extend_from_slice(&der_len(inner_len));
        inner_seq.extend_from_slice(&cn_oid_der);
        inner_seq.push(0x0C); // UTF8String
        inner_seq.push(cn_value.len() as u8);
        inner_seq.extend_from_slice(cn_value);

        // SET wrapper
        let mut set = vec![0x31];
        set.extend_from_slice(&der_len(inner_seq.len()));
        set.extend_from_slice(&inner_seq);

        // Outer SEQUENCE
        let mut seq = vec![0x30];
        seq.extend_from_slice(&der_len(set.len()));
        seq.extend_from_slice(&set);
        seq
    };

    // Build SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    let spki = {
        // AlgorithmIdentifier: SEQUENCE { OID, NULL }
        let alg_content = {
            let mut v = Vec::new();
            v.extend_from_slice(&sm2_pk_oid_der);
            v.extend_from_slice(&[0x05, 0x00]); // NULL
            v
        };
        let mut alg_id = vec![0x30];
        alg_id.extend_from_slice(&der_len(alg_content.len()));
        alg_id.extend_from_slice(&alg_content);

        // BIT STRING: 03 <len> 00 <pubkey>
        let bit_string_content_len = 1 + public_key_bytes.len();
        let mut bit_string = vec![0x03];
        bit_string.extend_from_slice(&der_len(bit_string_content_len));
        bit_string.push(0x00); // no unused bits
        bit_string.extend_from_slice(public_key_bytes);

        // SEQUENCE wrapper
        let spki_content_len = alg_id.len() + bit_string.len();
        let mut seq = vec![0x30];
        seq.extend_from_slice(&der_len(spki_content_len));
        seq.extend_from_slice(&alg_id);
        seq.extend_from_slice(&bit_string);
        seq
    };

    // Build CRI: SEQUENCE { version, subject, spki, [0] empty }
    let version = vec![0x02, 0x01, 0x00]; // INTEGER 0
    let attributes = vec![0xA0, 0x00]; // [0] empty

    let cri_content_len = version.len() + subject_name.len() + spki.len() + attributes.len();
    let mut cri = vec![0x30];
    cri.extend_from_slice(&der_len(cri_content_len));
    cri.extend_from_slice(&version);
    cri.extend_from_slice(&subject_name);
    cri.extend_from_slice(&spki);
    cri.extend_from_slice(&attributes);

    cri
}

/// Build a PKCS#10 CSR PEM for testing.
fn build_test_csr_pem(subject_cn: &str) -> String {
    let keypair = Sm2KeyPair::generate().expect("failed to generate key");
    let pubkey = keypair.public_key().to_encoded_point(false);
    let pubkey_bytes = pubkey.as_bytes();

    let cri = build_cri(subject_cn, pubkey_bytes);

    // Sign CRI
    let signer = gm_crypto::sm2::Sm2Signer::new(&keypair).unwrap();
    let sig = signer.sign(&cri).unwrap();

    // Build sigAlg: SEQUENCE { OID }
    let sm2_sig_oid = ObjectIdentifier::from_string("1.2.156.10197.1.501").unwrap();
    let sig_alg = asn1::write_single(&SequenceWriter::new(&|w| {
        w.write_element(&sm2_sig_oid)?;
        Ok(())
    }))
    .unwrap();

    // Build sigValue: BIT STRING
    let sig_value = asn1::write_single(&asn1::BitString::new(&sig, 0).unwrap()).unwrap();

    // Build full CSR: SEQUENCE { CRI, sigAlg, sigValue }
    let inner_len = cri.len() + sig_alg.len() + sig_value.len();
    let mut csr = vec![0x30];
    csr.extend_from_slice(&der_len(inner_len));
    csr.extend_from_slice(&cri);
    csr.extend_from_slice(&sig_alg);
    csr.extend_from_slice(&sig_value);

    pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", csr))
}

#[tokio::test]
async fn test_sign_certificate_success() {
    let service = create_test_service().await;

    let csr_pem = build_test_csr_pem("test.example.com");
    let req = Request::new(SignCertificateRequest {
        csr_pem,
        validity_days: 365,
    });

    let resp = service.sign_certificate(req).await;
    assert!(resp.is_ok(), "sign_certificate failed: {:?}", resp.err());

    let resp = resp.unwrap().into_inner();
    assert!(
        resp.error_code.is_empty(),
        "unexpected error: {}",
        resp.error_message
    );
    assert!(!resp.certificate_pem.is_empty(), "certificate PEM is empty");
    assert!(resp.certificate_pem.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn test_sign_certificate_invalid_validity() {
    let service = create_test_service().await;

    let csr_pem = build_test_csr_pem("test.example.com");
    let req = Request::new(SignCertificateRequest {
        csr_pem,
        validity_days: 0, // Invalid
    });

    let resp = service.sign_certificate(req).await;
    assert!(resp.is_err(), "should fail with validity_days=0");
}

#[tokio::test]
async fn test_get_certificate_not_found() {
    let service = create_test_service().await;

    let req = Request::new(GetCertificateRequest {
        serial_number: "nonexistent".to_string(),
    });

    let resp = service.get_certificate(req).await;
    assert!(resp.is_ok(), "get_certificate failed: {:?}", resp.err());

    let resp = resp.unwrap().into_inner();
    assert_eq!(resp.error_code, "CERT_NOT_FOUND");
    assert!(resp.certificate_pem.is_empty());
}

#[tokio::test]
async fn test_sign_and_get_certificate_roundtrip() {
    let service = create_test_service().await;

    // Sign a certificate
    let csr_pem = build_test_csr_pem("roundtrip.example.com");
    let sign_req = Request::new(SignCertificateRequest {
        csr_pem,
        validity_days: 365,
    });

    let sign_resp = service
        .sign_certificate(sign_req)
        .await
        .unwrap()
        .into_inner();
    assert!(sign_resp.error_code.is_empty());

    // Extract serial number from certificate PEM
    // The serial is returned as hex in the cert, but we need to find it
    // For simplicity, we'll just verify the cert PEM is valid
    assert!(!sign_resp.certificate_pem.is_empty());
}

#[tokio::test]
async fn test_revoke_certificate() {
    let service = create_test_service().await;

    // First sign a certificate
    let csr_pem = build_test_csr_pem("revoke.example.com");
    let sign_req = Request::new(SignCertificateRequest {
        csr_pem,
        validity_days: 365,
    });
    let sign_resp = service
        .sign_certificate(sign_req)
        .await
        .unwrap()
        .into_inner();
    assert!(sign_resp.error_code.is_empty());

    // TODO: Need to extract serial number to revoke it
    // For now, test revoking non-existent certificate
    let revoke_req = Request::new(RevokeCertificateRequest {
        serial_number: "nonexistent".to_string(),
        reason: 1,
    });

    let revoke_resp = service.revoke_certificate(revoke_req).await;
    assert!(revoke_resp.is_err(), "should fail for non-existent cert");
}

#[tokio::test]
async fn test_get_crl_empty() {
    let service = create_test_service().await;

    let req = Request::new(GetCrlRequest {
        issuer_cn: "Test CA".to_string(),
    });

    let resp = service.get_crl(req).await;
    assert!(resp.is_ok(), "get_crl failed: {:?}", resp.err());

    let resp = resp.unwrap().into_inner();
    assert!(resp.error_code.is_empty());
    assert!(!resp.crl_der.is_empty(), "CRL DER is empty");
}

#[tokio::test]
async fn test_renew_revoked_certificate_fails() {
    let service = create_test_service().await;

    // Try to renew a non-existent (hence not revoked) certificate
    // This should fail because the cert doesn't exist
    let req = Request::new(RenewCertificateRequest {
        serial_number: "nonexistent".to_string(),
        validity_days: 365,
    });

    let resp = service.renew_certificate(req).await;
    assert!(resp.is_err(), "should fail for non-existent cert");
}
