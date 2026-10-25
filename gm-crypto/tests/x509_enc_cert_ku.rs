//! Enc-cert KeyUsage "present-must-match" enforcement (GB/T 38636-2020
//! §6.4.6.1.2 b).
//!
//! `CertRole::TlcEncServer` / `CertRole::TlcEncClient` only assert
//! something when a KeyUsage extension is actually present: it must
//! carry a key-agreement bit (`keyAgreement` for SM2 ECDH, or
//! `keyEncipherment` for the static-RSA-style KEM layout). A cert that
//! omits KeyUsage entirely stays accepted, because KU is optional per
//! RFC 5280 §4.2.1.3 and real-world TLCP enc certs (GmSSL / Tongsuo)
//! frequently omit it — so this rule must not break interop. EKU is
//! never enforced for enc certs.
//!
//! These tests exercise `verify_cert_role` directly (guard path,
//! synthetic in-process certs) rather than a full handshake, matching
//! the gm-crypto unit-test convention for extension checks.

use gm_ca::cert::CaSigner;
use gm_ca::cert_profile::{CertProfile, KeyUsageBits};
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;
use gm_crypto::x509::verify::{CertRole, OwnedCert, verify_cert_role};

/// Issue a leaf cert signed by a fresh in-process CA, carrying exactly
/// the supplied `key_usage` bits (an all-false `KeyUsageBits` omits the
/// KeyUsage extension entirely).
fn issue_leaf_with_ku(key_usage: KeyUsageBits) -> Vec<u8> {
    let ca_key = Sm2KeyPair::generate().expect("ca keygen");
    let ca = CaSigner::new(ca_key, "enc-ku test CA");
    ca.self_sign_ca(365, &CertProfile::root_ca())
        .expect("self-sign CA");

    let leaf_key = Sm2KeyPair::generate().expect("leaf keygen");
    let leaf_pub = leaf_key.public_key_bytes_uncompressed();
    let csr = CsrBuilder::new_sm2("enc-leaf", &leaf_pub)
        .expect("csr builder")
        .build_pem(&leaf_key)
        .expect("csr build");
    let profile = CertProfile {
        key_usage,
        ext_key_usage: vec![],
        ..CertProfile::server_end_entity()
    };
    let (_serial, leaf_pem) = ca
        .sign_csr_with_profile(csr.as_bytes(), 365, &profile)
        .expect("sign leaf");
    leaf_pem.into_bytes()
}

fn check(pem: &[u8], role: CertRole) -> Result<(), String> {
    let owned = OwnedCert::from_pem_or_der(pem);
    let cert = owned.as_x509().map_err(|e| format!("parse: {e}"))?;
    verify_cert_role(&cert, role).map_err(|e| e.to_string())
}

#[test]
fn enc_cert_with_key_agreement_is_accepted() {
    let pem = issue_leaf_with_ku(KeyUsageBits {
        key_agreement: true,
        ..Default::default()
    });
    assert!(check(&pem, CertRole::TlcEncServer).is_ok());
    assert!(check(&pem, CertRole::TlcEncClient).is_ok());
}

#[test]
fn enc_cert_with_key_encipherment_is_accepted() {
    let pem = issue_leaf_with_ku(KeyUsageBits {
        key_encipherment: true,
        ..Default::default()
    });
    assert!(check(&pem, CertRole::TlcEncServer).is_ok());
}

#[test]
fn enc_cert_without_agreement_bits_is_rejected() {
    // digitalSignature-only KU contradicts the enc-cert role.
    let pem = issue_leaf_with_ku(KeyUsageBits::digital_signature());
    let err = check(&pem, CertRole::TlcEncServer).expect_err("must reject");
    assert!(
        err.contains("keyAgreement") && err.contains("keyEncipherment"),
        "error must name both acceptable bits, got: {err}"
    );
    // Same rule on the client side.
    assert!(check(&pem, CertRole::TlcEncClient).is_err());
}

#[test]
fn enc_cert_without_key_usage_is_accepted_permissively() {
    // All-false bits => the gm-ca builder omits the KeyUsage extension
    // entirely, which the present-must-match rule must accept (RFC 5280
    // §4.2.1.3 optionality + GmSSL/Tongsuo interop).
    let pem = issue_leaf_with_ku(KeyUsageBits::default());
    assert!(check(&pem, CertRole::TlcEncServer).is_ok());
}
