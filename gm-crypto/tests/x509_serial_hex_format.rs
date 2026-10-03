//! Regression tests for `CertInfo::serial_hex` format.
//!
//! Format invariant: lowercase hexadecimal encoding of the
//! DER-encoded serial-number INTEGER bytes (`cert.raw_serial()`).
//! Callers (e.g. gm-ca's renewal flow → DB `serial_number` column,
//! CRL `hex::decode` in gm-ca/src/cert.rs) depend on this being hex,
//! not decimal.
//!
//! Pre-PR-5 this field was populated via `cert.serial.to_string()`
//! where `cert.serial: BigUint`, which returns decimal — silently
//! breaking every downstream caller that expected hex per the
//! field name + doc comment.

use gm_crypto::x509::parse_cert_pem;

/// Self-signed cert with serial `52991d7ec04e877dee5c7af409995896fdc06979`
/// (20 bytes; chosen because openssl and Python both give the same value,
/// making cross-verification trivial).
const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIUUpkdfsBOh33uXHr0CZlYlv3AaXkwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSdGVzdC1zZXJpYWwtZm9ybWF0MB4XDTI2MTAwMzEwNTc1
M1oXDTI3MTAwMzEwNTc1M1owHTEbMBkGA1UEAwwSdGVzdC1zZXJpYWwtZm9ybWF0
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3n+2Z21GkjQldld8OQnS
BHz4uiup4z/fMy0aAfukRHgGxeveuBfCBw8/ffHAD21oICJYD2Gqz1oERF5SxFnH
B8goh9YO/TbiAki0COOyzHazaCxZ3kxd4qcQfghgyn5WIhxEffk1yc2lctLeiVaX
0qSIBus1mpJ5AKQ5DDu6LOaNVJ8XeiqFaO1HQm7gycvZ0HolbHu2jv4QRC6ZYmok
nmySuq/4HsYnCgQirgutPfJDtvQF4G/59wKxFQzdccFNX6tIIwp3GfyNcf7XAn/v
v63QpMpJ5Z8dsOJdg8I7LUVjtuFWxTd8zCiuThfiJ02nMGVXFPHEcqo3HTkLC0w/
YQIDAQABo1MwUTAdBgNVHQ4EFgQUNzg4l7IjX/dz9CUA7tVIzAn5lO0wHwYDVR0j
BBgwFoAUNzg4l7IjX/dz9CUA7tVIzAn5lO0wDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAQEAQgcxzrXKSefDwq3a0piQwc8iqsOSGcSglRg7lElGMh9M
+vbNzYXdV4lHWfkOPZLIJ4PcwLE2hmJsGxDeh+YTDtVsD6edxC0+fw74zR7tvB7i
ipimTG22bxfR5Gcv/swdSPS5TVimIaQ4iMd3jEu0z99vTDs7fgYKu6dBUUitBHen
zwgBrP+9TVob74/+6pyTXXRU9vryFviP8tBmCnlUrzu/rqoWTTYzylw6QHTFYoPt
NGOXkNMMLOPsXbVP7tM/YOzhjyNlqYIpfbdTMQNBC1piCK9epbltkz4PQ9b221A8
hyTr1qVKAeGOjvD2oht3b2DDwlX1gRKnr9TNqxoBog==
-----END CERTIFICATE-----";

#[test]
fn serial_hex_is_lowercase_hex_matching_openssl() {
    let info = parse_cert_pem(TEST_CERT_PEM).expect("parse");
    let hex_str = info.serial_hex.expect("serial_hex present");

    // Must match what `openssl x509 -serial -noout` reports (uppercase
    // here is converted to lowercase by `hex::encode`).
    assert_eq!(
        hex_str, "52991d7ec04e877dee5c7af409995896fdc06979",
        "serial_hex must be the lowercase hex encoding of cert.raw_serial()"
    );
}

#[test]
fn serial_hex_round_trips_through_hex_decode() {
    let info = parse_cert_pem(TEST_CERT_PEM).expect("parse");
    let hex_str = info.serial_hex.expect("serial_hex present");

    // The downstream contract (gm-ca's CRL generator, etc.) is
    // `hex::decode(&serial_number)`. Must succeed.
    let bytes = hex::decode(&hex_str).expect("serial_hex must be valid hex");
    assert_eq!(bytes.len(), 20, "20-byte serial → 40-char hex string");
}

#[test]
fn serial_hex_is_all_lowercase_hex_chars() {
    let info = parse_cert_pem(TEST_CERT_PEM).expect("parse");
    let hex_str = info.serial_hex.expect("serial_hex present");

    for c in hex_str.chars() {
        assert!(
            matches!(c, '0'..='9' | 'a'..='f'),
            "serial_hex contains non-lowercase-hex char {:?} in {:?}",
            c,
            hex_str
        );
    }
}

#[test]
fn serial_hex_length_matches_raw_serial() {
    let info = parse_cert_pem(TEST_CERT_PEM).expect("parse");
    let hex_str = info.serial_hex.expect("serial_hex present");

    // 20 raw bytes → exactly 40 hex chars (2 chars per byte, no prefix).
    assert_eq!(
        hex_str.len(),
        40,
        "20-byte raw_serial must produce exactly 40-char hex string"
    );
}
