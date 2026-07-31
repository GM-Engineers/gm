//! Cryptography error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("SM2 error: {0}")]
    Sm2Error(String),

    #[error("SM2 KEX error: {0}")]
    Sm2KexError(String),

    #[error("SM3 error: {0}")]
    Sm3Error(String),

    #[error("SM4 error: {0}")]
    Sm4Error(String),

    #[error("SM9 error: {0}")]
    Sm9Error(String),

    #[error("invalid hex string: {0}")]
    InvalidHex(String),

    #[error("invalid Base64 string: {0}")]
    InvalidBase64(String),

    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("invalid data length: {0}")]
    InvalidDataLength(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("invalid PKCS#7 padding: expected {expected} padding bytes")]
    InvalidPadding { expected: usize },
}
