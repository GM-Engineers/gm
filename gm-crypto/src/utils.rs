//! Utility functions module

use crate::error::CryptoError;
use base64::Engine;

/// Convert byte array to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to byte array
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, CryptoError> {
    hex::decode(hex_str).map_err(|e| CryptoError::InvalidHex(e.to_string()))
}

/// Convert byte array to Base64 string
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Convert Base64 string to byte array
pub fn base64_to_bytes(base64_str: &str) -> Result<Vec<u8>, CryptoError> {
    base64::engine::general_purpose::STANDARD
        .decode(base64_str)
        .map_err(|e| CryptoError::InvalidBase64(e.to_string()))
}
