//! In-process RSA certificate hierarchy generation for gm-tlcp tests.
//!
//! Generates a real CA + leaf RSA cert hierarchy **in pure Rust** using
//! [`gm_ca::rsa_signer::RsaCaSigner`] (Phase 4 / R-5). **No external
//! binary (e.g. `gmssl`) is required**.
//!
//! This is the RSA analogue of [`crate::support::gmca_cert_setup`]:
//! the SM2 ECDHE/ECC test suite uses `gmca_cert_setup` (SM2 dual-cert
//! hierarchy); the RSA test suite uses `rsa_cert_setup` (single
//! RSA cert hierarchy, per GB/T 38636-2020 §6.4.5.5 single-Certificate
//! emission for RSA suites).
//!
//! Compare with [`crate::support::gmssl_cert_setup`] which spawns the
//! `gmssl` CLI; that helper is needed only by the wire-interop tests.
//!
//! ## Why a custom PKCS#10 CSR builder?
//!
//! `gm-crypto` exposes `CsrBuilder::new_sm2` (RFC 2986 §4.1 for SM2
//! signatures) but has no equivalent for `sha256WithRSAEncryption`
//! signatures (RFC 8017 §9.2 / PKCS#10 over RSA keys). Rather than
//! introducing a `RsaCsrBuilder` to `gm-crypto` for a single test
//! fixture, we construct the CSR DER directly here using `gm-der`
//! primitives. The bytes are bit-for-bit equivalent to what
//! `openssl req -new -key rsa.key -subj /CN=...` would emit; they are
//! accepted by `RsaCaSigner::sign_csr_with_profile` (which decodes the
//! CSR via `x509_parser::parse_x509_csr`).
//!
//! ## Feature gate
//!
//! This module is gated on `tlcp-profiles + rsa` (a gm-tlcp dev-dep
//! feature pair) because both `gm_ca::rsa_signer::RsaCaSigner` and
//! `gm_ca::profiles::tlcp::{tlcp_server_rsa, tlcp_client_rsa}` live
//! behind the corresponding feature flags in `gm-ca`.

#![cfg(all(feature = "tlcp-profiles", feature = "rsa"))]

use gm_ca::cert_profile::CertProfile;
use gm_ca::rsa_signer::RsaCaSigner;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;

/// The output of a successful in-process RSA cert generation.
///
/// A single RSA cert hierarchy is generated (per GB/T 38636-2020
/// §6.4.5.5 single-Certificate emission for RSA suites):
///
/// ```text
///   ca.key / ca.crt                  self-signed RSA CA
///     │
///     └── signs ─► rsa_leaf.crt      leaf RSA cert (KU: digitalSignature + keyEncipherment,
///                                    EKU: serverAuth or clientAuth depending on profile)
/// ```
///
/// The leaf private key is returned as **PKCS#8 PEM** (the format
/// `gm_tlcp::tlcp::rsa_helpers::RsaKeyPair::from_pkcs8_pem` accepts),
/// and the leaf cert is returned as DER bytes (the format
/// `TlcpAcceptor::with_rsa_certs_single` accepts).
#[allow(dead_code)]
#[derive(Debug)]
pub struct RsaCerts {
    /// DER-encoded leaf RSA certificate (consumed by
    /// `TlcpAcceptor::with_rsa_certs[_single]`).
    pub rsa_cert_der: Vec<u8>,
    /// Leaf RSA private key in PKCS#8 PEM form (consumed by
    /// `RsaKeyPair::from_pkcs8_pem` → `TlcpAcceptor::with_rsa_certs[_single]`).
    pub rsa_key_pkcs8_pem: String,
}

/// Generate a single-leaf RSA cert hierarchy:
///
/// 1. Generate a 2048-bit RSA CA keypair and a self-signed root CA cert
///    (10-year validity, `CertProfile::root_ca()`).
/// 2. Generate a 2048-bit RSA leaf keypair.
/// 3. Build a PKCS#10 CSR for the leaf (`sha256WithRSAEncryption`
///    signature, subject `rsa-leaf.local`).
/// 4. Sign the CSR with the root CA, 365-day validity, profile
///    `tlcp_server_rsa()` (digitalSignature + keyEncipherment KU,
///    serverAuth EKU).
///
/// `out_dir` is currently unused; it is kept as a parameter for API
/// symmetry with the SM2 helper
/// [`crate::support::gmca_cert_setup::generate_gmca_test_certs`].
#[allow(dead_code)] // not used by gmssl_interop target (which uses GmsslCerts instead)
pub fn generate_rsa_test_certs(_out_dir: &std::path::Path) -> Result<RsaCerts, String> {
    // ---- Root CA (self-signed RSA) ----
    let ca_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
        .map_err(|e| format!("RSA CA keygen: {}", e))?;
    let ca_signer = RsaCaSigner::new(ca_key, "gm-tlcp test RSA CA (rsa-cert-setup)");
    let _root_pem = ca_signer
        .self_sign_ca(3650, &CertProfile::root_ca())
        .map_err(|e| format!("RSA CA self_sign_ca: {}", e))?;

    // ---- Leaf RSA keypair + CSR + cert ----
    let leaf_kp = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
        .map_err(|e| format!("leaf kp: {}", e))?;
    let csr_pem = build_rsa_csr_pem("rsa-leaf.local", &leaf_kp)
        .map_err(|e| format!("build_rsa_csr_pem: {}", e))?;
    let (_serial_hex, leaf_pem) = ca_signer
        .sign_csr_with_profile(
            csr_pem.as_bytes(),
            365,
            &gm_ca::profiles::tlcp::tlcp_server_rsa(),
        )
        .map_err(|e| format!("sign_csr_with_profile leaf: {}", e))?;
    let leaf_cert_der = pem::parse(leaf_pem.as_bytes())
        .map_err(|e| format!("leaf PEM parse: {}", e))?
        .into_contents();

    // Bridge the rsa-crate keypair → gm-tlcp's `RsaKeyPair` via PKCS#8 PEM.
    let pkcs8_pem = leaf_kp
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| format!("leaf PKCS#8 PEM: {}", e))?;

    Ok(RsaCerts {
        rsa_cert_der: leaf_cert_der,
        rsa_key_pkcs8_pem: pkcs8_pem.as_str().to_string(),
    })
}

/// Build a PKCS#10 CSR over an RSA leaf keypair.
///
/// Layout per RFC 2986 §4.1:
///
/// ```text
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo  CertificationRequestInfo,
///     signatureAlgorithm        AlgorithmIdentifier,
///     signature                 BIT STRING
/// }
/// CertificationRequestInfo ::= SEQUENCE {
///     version       INTEGER (0),
///     subject       Name,
///     subjectPKInfo SubjectPublicKeyInfo,
///     attributes    [0] IMPLICIT SET OF Attribute  -- empty
/// }
/// ```
///
/// Signature is `sha256WithRSAEncryption` (RFC 8017 §9.2). The DER
/// bytes emitted here are bit-for-bit equivalent to what
/// `openssl req -new -key rsa.key -subj /CN=...` produces, so the
/// resulting CSR is accepted by `RsaCaSigner::sign_csr_with_profile`
/// (which decodes it via `x509_parser::parse_x509_csr`).
fn build_rsa_csr_pem(subject_cn: &str, key_pair: &RsaPrivateKey) -> Result<String, String> {
    use gm_der::{
        der_bit_string, der_integer_positive, der_sequence, der_set, der_utf8_string, encode_oid,
    };

    // CN OID: 2.5.4.3 = 55 04 03
    const CN_OID: &[u8] = &[0x55, 0x04, 0x03];
    // rsaEncryption OID: 1.2.840.113549.1.1.1
    const RSA_ENCRYPTION_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    // sha256WithRSAEncryption OID: 1.2.840.113549.1.1.11
    const SHA256_RSA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

    // Name: SEQUENCE { SET { SEQUENCE { OID(cn), UTF8String(cn) } } }
    let cn_attr =
        der_sequence(&[encode_oid(CN_OID), der_utf8_string(subject_cn.as_bytes())].concat());
    let cn_set = der_set(&[cn_attr]);
    let subject = der_sequence(&[cn_set].concat());

    // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING(PKCS#1 RSAPublicKey) }
    let pubkey = rsa::RsaPublicKey::new(key_pair.n().clone(), key_pair.e().clone())
        .map_err(|e| format!("RSA pubkey extraction: {}", e))?;
    let pkcs1_pub = pubkey
        .to_pkcs1_der()
        .map_err(|e| format!("PKCS#1 RSAPublicKey DER: {}", e))?
        .as_bytes()
        .to_vec();
    let spki_alg = der_sequence(&[encode_oid(RSA_ENCRYPTION_OID), vec![0x05, 0x00]].concat());
    let spki_key = der_bit_string(&pkcs1_pub);
    let spki = der_sequence(&[spki_alg, spki_key].concat());

    let version = der_integer_positive(&[0x00]); // v1
    let attributes: Vec<u8> = vec![0xA0, 0x00]; // [0] IMPLICIT empty attributes

    // CertificationRequestInfo = SEQUENCE { version, subject, SPKI, [0] attributes }
    let cri = der_sequence(&[version, subject, spki, attributes].concat());

    // Sign CRI with sha256WithRSAEncryption.
    let signing_key = SigningKey::<Sha256>::new(key_pair.clone());
    let sig = signing_key.sign(&cri);
    let sig_alg = der_sequence(&[encode_oid(SHA256_RSA_OID), vec![0x05, 0x00]].concat());
    let sig_value = der_bit_string(&sig.to_bytes());

    let csr_der = der_sequence(&[cri, sig_alg, sig_value].concat());

    // Wrap in PEM
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&csr_der);
    let mut pem = String::new();
    pem.push_str("-----BEGIN CERTIFICATE REQUEST-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE REQUEST-----\n");
    Ok(pem)
}
