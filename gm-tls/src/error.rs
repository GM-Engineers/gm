//! TLS error types

use thiserror::Error;

/// Structured error codes for programmatic error handling and metrics.
///
/// Each variant corresponds to a specific failure mode in the TLS stack.
/// Use [`TlsError::code()`] to get the error code for a given error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Configuration error (missing/invalid cert, key, CA)
    ConfigError,
    /// Handshake protocol error
    HandshakeFailed,
    /// Handshake failed with a chained source error
    HandshakeFailedSource,
    /// Certificate chain validation failed
    CertificateVerificationFailed,
    /// CRL check failed
    CrlVerificationFailed,
    /// I/O error
    IoError,
    /// Feature not yet implemented
    Unimplemented,
    /// GCM nonce sequence overflow (connection exhausted)
    SequenceOverflow,
    /// Session store backend error
    SessionStoreError,
    /// DER encoding/decoding error
    DerParseError,
    /// Internal serialization error
    SerializationFailed,
    /// TLS record layer framing error
    TlsRecordError,
    /// Message parse error
    ParseError,
    /// GCM nonce reuse detected (catastrophic security failure)
    NonceReuse,
    /// Invalid handshake message type
    InvalidHandshakeType,
    /// Invalid message format
    InvalidMessage,
    /// Invalid state for operation
    InvalidState,
    /// PR-4.16: session-ticket-related failure (any of
    /// `TlsError::SessionTicketInvalid`, `SessionTicketExpired`,
    /// `SessionTicketReplay`). Pre-PR-4.16 these were all
    /// collapsed into `HandshakeFailed` with string-only
    /// differentiation; `classify_ticket_error` had to
    /// substring-match `Display` output.
    SessionTicket,
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TlsError {
    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("handshake failed: {msg}")]
    HandshakeFailedSource {
        msg: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("certificate verification failed: {0}")]
    CertificateVerificationFailed(String),

    #[error("CRL verification failed: {0}")]
    CrlVerificationFailed(String),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("not implemented: {0}")]
    Unimplemented(String),

    #[error("sequence overflow: GCM nonce cannot exceed 2^64-1")]
    SequenceOverflow,

    #[error("session store error: {0}")]
    SessionStoreError(String),

    #[error("DER parse error: {0}")]
    DerParseError(String),

    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    #[error("TLS record error: {0}")]
    TlsRecordError(String),

    #[error("parse error: {0}")]
    ParseError(String),

    #[error("GCM nonce reuse detected: same nonce used twice with the same key")]
    NonceReuse,

    #[error("invalid handshake type: {0}")]
    InvalidHandshakeType(u8),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("invalid state: {0}")]
    InvalidState(String),

    /// PR-4.16 / PR-4.13 follow-up: session ticket failed
    /// validation that indicates tampering or wrong key.
    /// Distinguished from `HandshakeFailed` so callers can
    /// pattern-match without string parsing. Covers: bad
    /// length, unknown key ID, SM4-GCM decryption failure,
    /// deserialize failure, client-auth-required mismatch,
    /// ticket-too-large.
    #[error("session ticket invalid: {0}")]
    SessionTicketInvalid(String),

    /// PR-4.16 / PR-4.13 follow-up: legitimate ticket expiry.
    /// Distinct from `SessionTicketInvalid` because the
    /// right operator response is "fall back to full
    /// handshake" (always), not "abort if fail-closed" (the
    /// latter is the fail-closed mode for tampered tickets).
    #[error("session ticket has expired")]
    SessionTicketExpired,

    /// PR-4.16 / PR-4.13 follow-up: replay protection
    /// triggered. Always abort (regardless of fail-closed
    /// mode).
    #[error("session ticket replay detected")]
    SessionTicketReplay,
}

impl TlsError {
    /// Return the structured error code for this error.
    pub fn code(&self) -> ErrorCode {
        match self {
            TlsError::ConfigError(_) => ErrorCode::ConfigError,
            TlsError::HandshakeFailed(_) => ErrorCode::HandshakeFailed,
            TlsError::HandshakeFailedSource { .. } => ErrorCode::HandshakeFailedSource,
            TlsError::CertificateVerificationFailed(_) => ErrorCode::CertificateVerificationFailed,
            TlsError::CrlVerificationFailed(_) => ErrorCode::CrlVerificationFailed,
            TlsError::IoError(_) => ErrorCode::IoError,
            TlsError::Unimplemented(_) => ErrorCode::Unimplemented,
            TlsError::SequenceOverflow => ErrorCode::SequenceOverflow,
            TlsError::SessionStoreError(_) => ErrorCode::SessionStoreError,
            TlsError::DerParseError(_) => ErrorCode::DerParseError,
            TlsError::SerializationFailed(_) => ErrorCode::SerializationFailed,
            TlsError::TlsRecordError(_) => ErrorCode::TlsRecordError,
            TlsError::ParseError(_) => ErrorCode::ParseError,
            TlsError::NonceReuse => ErrorCode::NonceReuse,
            TlsError::InvalidHandshakeType(_) => ErrorCode::InvalidHandshakeType,
            TlsError::InvalidMessage(_) => ErrorCode::InvalidMessage,
            TlsError::InvalidState(_) => ErrorCode::InvalidState,
            // PR-4.16: ticket-related variants all map to a
            // single `ErrorCode::SessionTicket`. Callers that
            // need to distinguish Replay / Expired / Invalid
            // should match on the `TlsError` variant directly
            // (the whole point of PR-4.16's typed variants) or
            // use `classify_ticket_error` for the higher-level
            // `ReplayDetected` / `Expired` / `TamperedOrForged`
            // three-way split.
            TlsError::SessionTicketInvalid(_)
            | TlsError::SessionTicketExpired
            | TlsError::SessionTicketReplay => ErrorCode::SessionTicket,
        }
    }

    /// Returns true if this error is a configuration error
    /// (i.e., the connection should not be retried without fixing config).
    pub fn is_config_error(&self) -> bool {
        matches!(self.code(), ErrorCode::ConfigError)
    }

    /// Returns true if this error is transient and may succeed on retry.
    pub fn is_transient(&self) -> bool {
        matches!(
            self.code(),
            ErrorCode::IoError | ErrorCode::SessionStoreError
        )
    }

    /// Create a HandshakeFailed error with a source error preserved in the chain.
    pub fn handshake_failed<E>(msg: &str, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        TlsError::HandshakeFailedSource {
            msg: msg.to_string(),
            source: Box::new(source),
        }
    }
}

impl From<std::io::Error> for TlsError {
    fn from(e: std::io::Error) -> Self {
        TlsError::IoError(e.to_string())
    }
}

impl From<gm_crypto::CryptoError> for TlsError {
    fn from(e: gm_crypto::CryptoError) -> Self {
        // Phase D-1: preserve the specific cert/CRL variants so
        // callers can still pattern-match on `TlsError::CertificateVerificationFailed`
        // and `TlsError::CrlVerificationFailed`. Other CryptoError
        // variants fall back to `HandshakeFailed` to preserve the
        // pre-D-1 behaviour.
        match e {
            gm_crypto::CryptoError::CertificateVerificationFailed(msg) => {
                TlsError::CertificateVerificationFailed(msg)
            }
            gm_crypto::CryptoError::CrlVerificationFailed(msg) => {
                TlsError::CrlVerificationFailed(msg)
            }
            other => TlsError::HandshakeFailed(other.to_string()),
        }
    }
}
