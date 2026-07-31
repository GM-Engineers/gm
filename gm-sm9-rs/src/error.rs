//! Error types for SM9

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum Sm9Error {
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("KGC error: {0}")]
    KgcError(String),

    #[error("cryptography error: {0}")]
    CryptoError(String),

    #[error("not implemented")]
    NotImplemented,

    #[error("invalid point")]
    InvalidPoint,

    #[error("signing error: {0}")]
    SigningError(String),

    #[error("encryption error: {0}")]
    EncryptionError(String),

    #[error("arithmetic error: {0}")]
    ArithError(#[from] crate::arith::ArithError),
}
