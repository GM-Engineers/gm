//! CRL generation and parsing tests

use gm_ca::cert::{CaSigner, CrlEntry};
use gm_crypto::sm2::Sm2KeyPair;
use sqlx::types::chrono::Utc;

fn create_test_ca_signer() -> CaSigner {
    let keypair = Sm2KeyPair::generate().expect("failed to generate CA key pair");
    CaSigner::new(keypair, "Test CA")
}

#[test]
fn test_generate_empty_crl() {
    let signer = create_test_ca_signer();

    let result = signer.generate_crl(&[], 1);
    assert!(result.is_ok());

    let crl_der = result.unwrap();
    // CRL should have at least: TBS + AlgorithmIdentifier + Signature
    assert!(crl_der.len() > 100);
}

#[test]
fn test_generate_crl_with_revoked_certs() {
    let signer = create_test_ca_signer();

    let revoked_serials = vec![
        CrlEntry {
            serial_number: "0102030405060708090a0b0c0d0e0f".to_string(),
            revoked_at: Utc::now(),
            reason: 1, // unspecified
        },
        CrlEntry {
            serial_number: "ffddeeffaabbccdd".to_string(),
            revoked_at: Utc::now(),
            reason: 4, // superseded
        },
    ];

    let result = signer.generate_crl(&revoked_serials, 1);
    assert!(result.is_ok());

    let crl_der = result.unwrap();
    assert!(crl_der.len() > 100);
}

#[test]
fn test_generate_crl_invalid_serial() {
    let signer = create_test_ca_signer();

    let revoked_serials = vec![CrlEntry {
        serial_number: "not_valid_hex".to_string(),
        revoked_at: Utc::now(),
        reason: 1,
    }];

    let result = signer.generate_crl(&revoked_serials, 1);
    assert!(result.is_err());
}

#[test]
fn test_generate_multiple_crls() {
    let signer = create_test_ca_signer();

    let crl1 = signer.generate_crl(&[], 1).unwrap();
    let crl2 = signer.generate_crl(&[], 2).unwrap();

    // Both CRLs should be valid DER and non-empty
    assert!(crl1.len() > 100);
    assert!(crl2.len() > 100);
}

#[test]
fn test_ca_signer_creation() {
    let keypair = Sm2KeyPair::generate().expect("failed to generate CA key pair");
    let signer = CaSigner::new(keypair, "Test CA CN");

    // Verify the signer can be used to generate CRLs
    let result = signer.generate_crl(&[], 1);
    assert!(result.is_ok());
}
