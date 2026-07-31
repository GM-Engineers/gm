//! Utility function tests

use gm_crypto::CryptoError;
use gm_crypto::utils::{base64_to_bytes, bytes_to_base64, bytes_to_hex, hex_to_bytes};

#[test]
fn test_bytes_to_hex_roundtrip() {
    let data = b"\x01\x23\x45\x67\x89\xab\xcd\xef";
    let hex = bytes_to_hex(data);
    assert_eq!(hex, "0123456789abcdef");

    let decoded = hex_to_bytes(&hex).unwrap();
    assert_eq!(decoded, data.as_slice());
}

#[test]
fn test_bytes_to_hex_empty() {
    assert_eq!(bytes_to_hex(&[]), "");
}

#[test]
fn test_hex_to_bytes_invalid_chars() {
    let result = hex_to_bytes("not_hex!!");
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::InvalidHex(_) => {}
        other => panic!("expected InvalidHex, got {:?}", other),
    }
}

#[test]
fn test_hex_to_bytes_odd_length() {
    let result = hex_to_bytes("abc");
    assert!(result.is_err());
}

#[test]
fn test_bytes_to_base64_roundtrip() {
    let data = b"Hello, World!";
    let b64 = bytes_to_base64(data);
    let decoded = base64_to_bytes(&b64).unwrap();
    assert_eq!(decoded, data.as_slice());
}

#[test]
fn test_bytes_to_base64_empty() {
    assert_eq!(bytes_to_base64(&[]), "");
}

#[test]
fn test_base64_to_bytes_invalid() {
    let result = base64_to_bytes("not!!!valid!!!base64===");
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::InvalidBase64(_) => {}
        other => panic!("expected InvalidBase64, got {:?}", other),
    }
}

#[test]
fn test_base64_binary_roundtrip() {
    // Test with all byte values
    let data: Vec<u8> = (0u8..=255).collect();
    let b64 = bytes_to_base64(&data);
    let decoded = base64_to_bytes(&b64).unwrap();
    assert_eq!(decoded, data);
}
