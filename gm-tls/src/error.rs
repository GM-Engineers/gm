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
    /// PR-4.18: any cipher primitive failure (SM3 hash,
    /// SM4-GCM encrypt/decrypt, SM2 sign/verify/key-parse,
    /// close_notify). Distinct from `HandshakeFailed` so
    /// metrics can alert on "GM cipher error rate" without
    /// contaminating the count with protocol-level errors.
    Cipher,
    /// PR-4.18: handshake message parse / validate failed
    /// (Finished, Certificate, CertificateVerify, etc.).
    HandshakeMessageParse,
    /// PR-4.18: SM2 key construction / parse / load
    /// failure. Distinct from `Cipher` because key errors
    /// are usually config-time (bad PEM) not runtime
    /// (bad wire format).
    Sm2Key,
    /// PR-4.18: KAT (Known Answer Test) self-test
    /// failure. A deployment-health indicator.
    Kat,
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

    /// PR-4.18: cryptographic primitive failed (SM3
    /// hash, SM4-GCM encrypt/decrypt, SM2 sign/verify/
    /// key-parse, close_notify). Inner `String` keeps the
    /// underlying `ring`/`gm-crypto` error message for log
    /// scraping. Display prefix is "GM cipher error:".
    #[error("GM cipher error: {0}")]
    CipherError(String),

    /// PR-4.18: handshake message parse / validate
    /// failed (Finished, Certificate, CertificateVerify,
    /// etc.). Distinct from `CipherError` because the
    /// right operator response is "check wire-format
    /// compat" not "check crypto provider config".
    #[error("handshake message parse failed: {0}")]
    HandshakeMessageParse(String),

    /// PR-4.18: SM2 key construction / parse / load
    /// failed. Wraps both PEM decode and
    /// `Sm2KeyPair::from_private_key` failures. Distinct
    /// from `CipherError` because key errors are usually
    /// config-time (bad PEM) not runtime (bad wire
    /// format).
    #[error("SM2 key error: {0}")]
    Sm2KeyError(String),

    /// PR-4.18: KAT (Known Answer Test) self-test
    /// failed. This is a deployment-health indicator
    /// (the cryptographic library is broken in this
    /// binary); it should never fire in production but
    /// if it does the process should refuse to start
    /// (handled by caller).
    #[error("KAT self-test failed: {0}")]
    KatFailed(String),
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
            // PR-4.18: typed variants for crypto,
            // handshake-message-parse, SM2-key, and KAT
            // failures. Each maps to a distinct
            // `ErrorCode` so metrics can alert on the
            // specific subsystem that's broken (e.g.,
            // "cipher error rate" vs "wire-format
            // incompat rate").
            TlsError::CipherError(_) => ErrorCode::Cipher,
            TlsError::HandshakeMessageParse(_) => ErrorCode::HandshakeMessageParse,
            TlsError::Sm2KeyError(_) => ErrorCode::Sm2Key,
            TlsError::KatFailed(_) => ErrorCode::Kat,
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

// ============================================================================
// PR-4.18 tests: typed TlsError variants for cipher / handshake-parse / SM2 / KAT
// ============================================================================
//
// PR-4.16 introduced typed `SessionTicket*` variants and
// rewrote `classify_ticket_error` to exhaustive `match`.
// PR-4.18 extends the same pattern to four additional
// failure-mode families:
//
//   - `CipherError`           — GM cipher primitive failed
//                                (SM3, SM4-GCM, SM2 sign/verify)
//   - `HandshakeMessageParse` — handshake message
//                                parse/validate failed (Finished,
//                                Certificate, CertificateVerify)
//   - `Sm2KeyError`           — SM2 key construction / parse
//                                failed (PEM decode, key load)
//   - `KatFailed`             — KAT self-test failed
//                                (deployment-health indicator)
//
// Pre-PR-4.18 all 27 migrated call sites used
// `TlsError::HandshakeFailed(format!("...: {:?}", e))` and
// mapped to a single `ErrorCode::HandshakeFailed`. Post-PR-4.18
// they carry typed variants and `code()` returns a distinct
// `ErrorCode` so metrics can alert on each subsystem
// independently.

#[cfg(test)]
mod pr418_typed_crypto_errors_tests {
    use super::*;

    #[test]
    fn pr418_cipher_error_maps_to_cipher_code() {
        let e = TlsError::CipherError("GCM encrypt: tag mismatch".into());
        assert_eq!(e.code(), ErrorCode::Cipher);
        let s = e.to_string();
        assert!(s.starts_with("GM cipher error:"), "Display prefix: {s}");
        assert!(s.contains("GCM encrypt"), "payload preserved: {s}");
    }

    #[test]
    fn pr418_handshake_message_parse_maps_to_parse_code() {
        let e = TlsError::HandshakeMessageParse("Finished parse: too short".into());
        assert_eq!(e.code(), ErrorCode::HandshakeMessageParse);
        let s = e.to_string();
        assert!(
            s.starts_with("handshake message parse failed:"),
            "Display prefix: {s}"
        );
        assert!(s.contains("Finished parse"), "payload preserved: {s}");
    }

    #[test]
    fn pr418_sm2_key_error_maps_to_sm2_key_code() {
        let e = TlsError::Sm2KeyError("PEM UTF-8: invalid byte 0xff".into());
        assert_eq!(e.code(), ErrorCode::Sm2Key);
        let s = e.to_string();
        assert!(s.starts_with("SM2 key error:"), "Display prefix: {s}");
        assert!(s.contains("PEM UTF-8"), "payload preserved: {s}");
    }

    #[test]
    fn pr418_kat_failed_maps_to_kat_code() {
        let e = TlsError::KatFailed("SM3 KAT: output mismatch".into());
        assert_eq!(e.code(), ErrorCode::Kat);
        let s = e.to_string();
        assert!(
            s.starts_with("KAT self-test failed:"),
            "Display prefix: {s}"
        );
        assert!(s.contains("SM3 KAT"), "payload preserved: {s}");
    }

    #[test]
    fn pr418_distinct_from_handshake_failed() {
        // Operators alerting on "cipher error rate" or
        // "wire-format incompat rate" must not see
        // HandshakeFailed traffic. Each new variant
        // maps to a unique ErrorCode.
        let codes = [
            TlsError::CipherError("x".into()).code(),
            TlsError::HandshakeMessageParse("x".into()).code(),
            TlsError::Sm2KeyError("x".into()).code(),
            TlsError::KatFailed("x".into()).code(),
        ];
        for c in codes {
            assert_ne!(
                c,
                ErrorCode::HandshakeFailed,
                "PR-4.18 typed variant must not regress to HandshakeFailed: {c:?}"
            );
        }
        // Distinct from each other too.
        let mut sorted = codes.to_vec();
        sorted.sort_by_key(|c| *c as u8);
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "all four codes must be unique");
    }

    #[test]
    fn pr418_display_preserves_payload_for_log_scrapers() {
        // Log scrapers that grep for substrings like
        // "GCM", "Finished", "SM2", "KAT" must continue
        // to match post-PR-4.18.
        let cases: &[(&str, &str)] = &[
            ("GCM encrypt", "GCM encrypt: ring rejected tag"),
            ("Finished sign", "Finished sign: SM2 sign failed"),
            ("SM2 key parse", "SM2 key parse: invalid scalar"),
            ("KAT self-test", "KAT self-test: SM3 mismatch"),
        ];
        for (substring, payload) in cases {
            let contains = match substring {
                s if s.starts_with("GCM") => TlsError::CipherError((*payload).into())
                    .to_string()
                    .contains(substring),
                s if s.starts_with("Finished") => {
                    TlsError::HandshakeMessageParse((*payload).into())
                        .to_string()
                        .contains(substring)
                }
                s if s.starts_with("SM2") => TlsError::Sm2KeyError((*payload).into())
                    .to_string()
                    .contains(substring),
                s if s.starts_with("KAT") => TlsError::KatFailed((*payload).into())
                    .to_string()
                    .contains(substring),
                _ => panic!("unexpected substring key {substring}"),
            };
            assert!(
                contains,
                "Display of payload {payload:?} must contain substring {substring:?}"
            );
        }
    }
}
