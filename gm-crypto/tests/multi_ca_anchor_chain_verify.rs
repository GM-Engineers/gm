//! Unit-level multi-CA trust anchor regression tests.
//!
//! Calls `verify_cert_chain_sm2_chain_with_distid_policy`
//! directly with the leaf cert and two trust anchor pools,
//! and asserts that both `[ca_a, ca_b]` and `[ca_b, ca_a]`
//! orderings succeed (the verifier must iterate the pool to
//! find the matching anchor; a `trust[0]`-only lookup would
//! silently break the second ordering).

use gm_ca::cert::CaSigner;
use gm_ca::cert_profile::{CertProfile, ExtendedKeyUsage, GeneralName, KeyUsageBits};
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;
use gm_crypto::x509::verify::{
    CertRole, DistidPolicy, OwnedCert, verify_cert_chain_sm2_chain_with_distid_policy,
};
use time::OffsetDateTime;

fn issue_ca(name: &str) -> (Vec<u8>, CaSigner) {
    let key = Sm2KeyPair::generate().expect("CA keygen");
    let signer = CaSigner::new(key, name);
    let pem = signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("CA self-sign");
    (pem.into_bytes(), signer)
}

fn issue_leaf(ca: &CaSigner, cn: &str) -> (Vec<u8>, Vec<u8>) {
    let leaf_key = Sm2KeyPair::generate().expect("leaf keygen");
    let leaf_pub_65 = leaf_key.public_key_bytes_uncompressed();
    let csr_pem = CsrBuilder::new_sm2(cn, &leaf_pub_65)
        .expect("CsrBuilder")
        .build_pem(&leaf_key)
        .expect("CSR build");

    let profile = CertProfile {
        sans: vec![GeneralName::DnsName("localhost".to_string())],
        key_usage: KeyUsageBits::digital_signature(),
        ext_key_usage: vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
        ..CertProfile::server_end_entity()
    };
    let (_, leaf_pem) = ca
        .sign_csr_with_profile(csr_pem.as_bytes(), 365, &profile)
        .expect("sign CSR");
    let leaf_key_pem = leaf_key.private_key_pem().expect("leaf key PEM");
    (leaf_pem.into_bytes(), leaf_key_pem.into_bytes())
}

fn build_leaf_only(leaf_pem: &[u8]) -> Vec<OwnedCert> {
    vec![OwnedCert::from_pem_or_der(leaf_pem)]
}

fn build_anchors(ordered_pems: &[&[u8]]) -> Vec<OwnedCert> {
    ordered_pems
        .iter()
        .map(|pem| OwnedCert::from_pem_or_der(pem))
        .collect()
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::seconds(60)
}

#[test]
fn chain_verify_first_anchor_match() {
    let (ca_a_pem, _ca_a) = issue_ca("ca-a");
    let (ca_b_pem, ca_b) = issue_ca("ca-b");
    let (leaf_b_pem, _leaf_b_key) = issue_leaf(&ca_b, "server-b");
    let chain = build_leaf_only(&leaf_b_pem);
    let anchors = build_anchors(&[&ca_b_pem, &ca_a_pem]);
    let result = verify_cert_chain_sm2_chain_with_distid_policy(
        &chain,
        &anchors,
        now(),
        Some("localhost"),
        Some(CertRole::TlcServer),
        DistidPolicy::Strict,
    );
    assert!(
        result.is_ok(),
        "expected Ok when matching CA is first, got: {:?}",
        result.err()
    );
}

#[test]
fn chain_verify_wrong_first_right_second_falls_through() {
    let (ca_a_pem, _ca_a) = issue_ca("ca-a");
    let (ca_b_pem, ca_b) = issue_ca("ca-b");
    let (leaf_b_pem, _leaf_b_key) = issue_leaf(&ca_b, "server-b");
    let chain = build_leaf_only(&leaf_b_pem);
    let anchors = build_anchors(&[&ca_a_pem, &ca_b_pem]);
    let result = verify_cert_chain_sm2_chain_with_distid_policy(
        &chain,
        &anchors,
        now(),
        Some("localhost"),
        Some(CertRole::TlcServer),
        DistidPolicy::Strict,
    );
    assert!(
        result.is_ok(),
        "expected Ok when matching CA is second (fall-through), got: {:?}",
        result.err()
    );
}

#[test]
fn chain_verify_only_wrong_anchor_fails() {
    let (ca_a_pem, _ca_a) = issue_ca("ca-a");
    let (_ca_b_pem, ca_b) = issue_ca("ca-b");
    let (leaf_b_pem, _leaf_b_key) = issue_leaf(&ca_b, "server-b");
    let chain = build_leaf_only(&leaf_b_pem);
    let anchors = build_anchors(&[&ca_a_pem]);
    let result = verify_cert_chain_sm2_chain_with_distid_policy(
        &chain,
        &anchors,
        now(),
        Some("localhost"),
        Some(CertRole::TlcServer),
        DistidPolicy::Strict,
    );
    let err = result.expect_err("expected Err when no anchor matches");
    let msg = format!("{:?}", err);
    assert!(
        msg.contains("issuer") || msg.contains("Certificate"),
        "expected cert-related error, got: {msg}"
    );
}
