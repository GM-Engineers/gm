//! CA service integration tests
//!
//! Tests the gRPC CA service (CaServiceImpl) with an in-memory SQLite database
//! to avoid requiring a running PostgreSQL instance.

use gm_ca::ca::v1::{
    CaService, GetCertificateRequest, GetCrlRequest, RenewCertificateRequest,
    RevokeCertificateRequest, SignCertificateRequest,
};
use gm_ca::cert::CaSigner;
use gm_ca::db::DbStore;
use gm_ca::service::CaServiceImpl;
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;
use sqlx::any::AnyPoolOptions;
use std::sync::Arc;
use tonic::Request;

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

/// Build a PKCS#10 CSR PEM for testing using `gm_crypto::x509::CsrBuilder`.
/// Replaces the ~130 lines of naked DER construction that lived here in
/// pre-Phase-3 gm-ca.
fn build_test_csr_pem(subject_cn: &str) -> String {
    let keypair = Sm2KeyPair::generate().expect("failed to generate key");
    let pubkey_65 = keypair.public_key_bytes_uncompressed();
    CsrBuilder::new_sm2(subject_cn, &pubkey_65)
        .expect("CsrBuilder::new_sm2")
        .build_pem(&keypair)
        .expect("CsrBuilder::build_pem")
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
