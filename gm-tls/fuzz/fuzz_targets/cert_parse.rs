//! Fuzz target for X.509 certificate parsing
//!
//! This fuzz target tests:
//! 1. Certificate PEM/DER parsing
//! 2. Certificate chain parsing
//! 3. CRL parsing and verification
//! 4. Domain validation

#![no_main]

use gm_tls::gm::{CrlInfo, OwnedCert, validate_cert_pem};
use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};
use time::OffsetDateTime;

#[derive(Arbitrary, Debug)]
#[allow(dead_code)] // fuzz-only fields kept for input diversity
struct CertFuzzInput {
    pem_data: Vec<u8>,
    domain: Option<String>,
    // For CRL
    crl_data: Vec<u8>,
    cert_serial: Vec<u8>,
    // For chain verification
    intermediate_pem: Option<Vec<u8>>,
    root_pem: Vec<u8>,
}

fuzz_target!(|input: CertFuzzInput| {
    // Test certificate validation with current time
    let now = OffsetDateTime::now_utc();

    let _ = validate_cert_pem(&input.pem_data, now, input.domain.as_deref());

    if let Ok(certs) = OwnedCert::chain_from_pem_concat(&input.pem_data) {
        for cert in certs {
            let _ = cert.as_x509();
        }
    }

    // Test CRL parsing
    if let Ok(crl_info) = CrlInfo::from_pem(&input.crl_data) {
        let _ = crl_info.is_valid(now);
        let _ = crl_info.is_cert_revoked(&input.cert_serial);
        let _ = crl_info.issuer_str();
    }

    if let Ok(crl_info) = CrlInfo::from_der(&input.crl_data) {
        let _ = crl_info.is_valid(now);
        let _ = crl_info.is_cert_revoked(&input.cert_serial);
    }

    // Empty DER should fail
    let _ = CrlInfo::from_der(&[]);

    // Test chain verification
    if !input.pem_data.is_empty() && !input.root_pem.is_empty() {
        let mut chain = Vec::new();
        if let Ok(leaf) = OwnedCert::from_pem(&input.pem_data) {
            chain.push(leaf);
        }

        let mut trust_anchors = Vec::new();
        if let Ok(root) = OwnedCert::from_pem(&input.root_pem) {
            trust_anchors.push(root);
        }

        if !chain.is_empty() && !trust_anchors.is_empty() {
            let _ = gm_tls::gm::verify_cert_chain_sm2_chain(
                &chain,
                &trust_anchors,
                now,
                input.domain.as_deref(),
            );
        }
    }
});
