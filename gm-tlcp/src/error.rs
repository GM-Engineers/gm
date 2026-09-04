//! TLCP error types
//!
//! This is a TLCP-specific subset of the TlsError enum, extracted during
//! the gm-tls → gm-tlcp crate split. See ADR-001 for the split rationale.

use thiserror::Error;

/// TLCP error type.
///
/// Subset of `gm_tls::TlsError` containing only variants used by the TLCP
/// implementation. Other variants (config errors, session store errors, etc.)
/// are not relevant to the TLCP protocol itself.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlcpError {
    /// Handshake protocol error
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(String),

    /// GCM nonce sequence overflow (connection exhausted)
    #[error("sequence overflow: GCM nonce cannot exceed 2^64-1")]
    SequenceOverflow,

    /// TLS record layer framing error
    #[error("TLS record error: {0}")]
    TlsRecordError(String),

    /// Message parse error
    #[error("parse error: {0}")]
    ParseError(String),

    /// GCM nonce reuse detected (catastrophic security failure)
    #[error("GCM nonce reuse detected: same nonce used twice with the same key")]
    NonceReuse,

    /// Invalid handshake message type
    #[error("invalid handshake type: {0:#x}")]
    InvalidHandshakeType(u8),

    /// Invalid message format
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Invalid state for operation
    #[error("invalid state: {0}")]
    InvalidState(String),
}

impl From<std::io::Error> for TlcpError {
    fn from(e: std::io::Error) -> Self {
        TlcpError::IoError(e.to_string())
    }
}

impl From<gm_crypto::CryptoError> for TlcpError {
    fn from(e: gm_crypto::CryptoError) -> Self {
        TlcpError::HandshakeFailed(e.to_string())
    }
}

/// Backward-compat alias for code that previously used `TlsError` from
/// `gm_tls`. The split retained the TLCP error semantics; rename is intentional.
pub type TlsError = TlcpError;
