//! X.509 certificate parsing tests

use gm_crypto::x509::parse_cert_pem;

#[test]
fn test_parse_cert_pem_invalid_input() {
    let result = parse_cert_pem("not a certificate");
    assert!(result.is_err());
}

#[test]
fn test_parse_cert_pem_invalid_pem_block() {
    let result = parse_cert_pem("-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----");
    assert!(result.is_err());
}

#[test]
fn test_parse_cert_pem_empty_string() {
    let result = parse_cert_pem("");
    assert!(result.is_err());
}

#[test]
fn test_parse_cert_pem_wrong_pem_type() {
    // PEM block with wrong label (private key, not certificate)
    let key_pem = "-----BEGIN EC PRIVATE KEY-----\n\
MHQCAQEEIxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxOCO6+Jo3aLQo\n\
oAAoGCCqGSM49AwEHoUQDQgAE+EAuZ0kY8TRNxogjbhNKl8NLFkoiwo7Ta6t3/L4D\n\
FX9CzROGalNHOKyZOGN0Swd4EOg9B9BSpQmewatUt6M=\n\
-----END EC PRIVATE KEY-----";
    let result = parse_cert_pem(key_pem);
    assert!(result.is_err());
}
