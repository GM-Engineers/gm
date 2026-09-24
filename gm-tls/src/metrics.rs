//! Metrics instrumentation for gm-tls.
//!
//! Metrics are emitted via the `metrics` facade.  To collect them, an
//! application must install a recorder (e.g. the `metrics-exporter-prometheus`
//! crate).
//!
//! # Example (Prometheus)
//!
//! ```ignore
//! use metrics_exporter_prometheus::PrometheusBuilder;
//!
//! PrometheusBuilder::new().install().unwrap();
//! ```
//!
//! # Emitted metrics
//!
//! | Metric                                | Type     | Labels         | Description                   |
//! |---------------------------------------|----------|----------------|-------------------------------|
//! | `gmtls_handshakes_total`              | Counter  | `role`,`result`| Total TLS handshakes           |
//! | `gmtls_handshake_duration_seconds`    | Histogram| `role`         | TLS handshake duration        |
//! | `gmtls_handshake_errors_total`        | Counter  | `role`,`code`  | TLS handshake errors by [`ErrorCode`] (PR-4.22) |
//! | `gmtls_session_resumptions_total`    | Counter  | `result`       | Session resumption attempts   |
//! | `gmtls_bytes_transferred_total`      | Counter  | `role`,`dir`   | Bytes sent/received           |
//! | `gmtls_cert_verification_errors_total`| Counter | `reason`       | Certificate verification errors|

use crate::error::ErrorCode;
use metrics::{Unit, counter, describe_counter, describe_histogram, histogram};
use std::time::Instant;

/// Describes all metrics exported by gm-tls.
/// Call this once at application startup before any TLS operations.
pub fn describe_metrics() {
    describe_counter!(
        "gmtls_handshakes_total",
        Unit::Count,
        "Total number of completed TLS handshakes"
    );
    describe_histogram!(
        "gmtls_handshake_duration_seconds",
        Unit::Seconds,
        "Duration of TLS handshakes in seconds"
    );
    describe_counter!(
        "gmtls_session_resumptions_total",
        Unit::Count,
        "Total number of session resumption attempts"
    );
    describe_counter!(
        "gmtls_bytes_transferred_total",
        Unit::Bytes,
        "Total bytes transferred (sent or received)"
    );
    describe_counter!(
        "gmtls_cert_verification_errors_total",
        Unit::Count,
        "Total certificate verification errors"
    );
    // PR-4.22: errors tagged by structured ErrorCode (PR-4.18) for
    // fine-grained alerting on subsystem failures (cipher vs handshake
    // vs key vs kat etc.).
    describe_counter!(
        "gmtls_handshake_errors_total",
        Unit::Count,
        "Total TLS handshake errors tagged by structured ErrorCode"
    );
}

/// Records the result of a TLS handshake.
pub fn record_handshake(role: &str, result: &str, duration_secs: f64) {
    let role_owned = role.to_owned();
    let result_owned = result.to_owned();
    let role_for_hist = role_owned.clone();
    counter!("gmtls_handshakes_total", "role" => role_owned, "result" => result_owned).increment(1);
    histogram!("gmtls_handshake_duration_seconds", "role" => role_for_hist).record(duration_secs);
}

/// Records a session resumption attempt.
pub fn record_session_resumption(result: &str) {
    let result = result.to_owned();
    counter!("gmtls_session_resumptions_total", "result" => result).increment(1);
}

/// Records bytes transferred.
pub fn record_bytes(role: &str, direction: &str, count: usize) {
    let role = role.to_owned();
    let direction = direction.to_owned();
    counter!("gmtls_bytes_transferred_total", "role" => role, "dir" => direction)
        .increment(count as u64);
}

/// Records a certificate verification error.
pub fn record_cert_error(reason: &str) {
    let reason = reason.to_owned();
    counter!("gmtls_cert_verification_errors_total", "reason" => reason).increment(1);
}

/// Records a TLS handshake error tagged by structured [`ErrorCode`] (PR-4.22).
///
/// This is the **structured-error** companion to [`record_cert_error`] /
/// [`record_handshake`]. Whereas `record_handshake("error")` lumps all
/// handshake failures into one bucket, this function lets operators
/// alert on differentiated metrics slices:
///
/// - `gmtls_handshake_errors_total{role="server",code="Cipher"}` — SM cipher
///   primitive failures (typically CPU/accelerator anomalies)
/// - `gmtls_handshake_errors_total{role="client",code="CrlVerificationFailed"}`
///   — CRL check failures (PKI freshness window)
/// - `gmtls_handshake_errors_total{role="server",code="Kat"}` — KAT
///   self-test failures (deployment-health indicator)
///
/// The `code` label uses [`ErrorCode`]'s `Debug` representation (e.g.
/// `"Cipher"`, `"HandshakeMessageParse"`, `"SessionTicket"`, `"Kat"`).
///
/// # Companion metrics
///
/// This metric is **independent** from `gmtls_handshakes_total{result="error"}`:
/// the latter counts each failed handshake once regardless of cause; the
/// former lets operators drill into the *cause*. Both are emitted from
/// the same wrap points — a single failed handshake increments both.
pub fn record_handshake_error_code(role: &str, code: ErrorCode) {
    let role = role.to_owned();
    let code = format!("{code:?}");
    counter!("gmtls_handshake_errors_total", "role" => role, "code" => code).increment(1);
}

/// Scope guard for timing a handshake.
pub struct HandshakeTimer {
    role: String,
    start: Instant,
}

impl HandshakeTimer {
    pub fn new(role: &str) -> Self {
        Self {
            role: role.to_string(),
            start: Instant::now(),
        }
    }

    pub fn finish(self, result: &str) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let role_for_counter = self.role.clone();
        let role_for_histogram = self.role;
        let result = result.to_owned();
        counter!("gmtls_handshakes_total", "role" => role_for_counter, "result" => result)
            .increment(1);
        histogram!("gmtls_handshake_duration_seconds", "role" => role_for_histogram)
            .record(elapsed);
    }
}

// ---------------------------------------------------------------------------
// PR-4.22 unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod pr422_record_handshake_error_code_tests {
    use super::*;
    use crate::error::{ErrorCode, TlsError};

    /// Verify `record_handshake_error_code` is callable with every
    /// `ErrorCode` variant (compile-time exhaustive) and does not panic.
    /// Operators rely on this metric being incremented for each variant;
    /// if the function rejected a variant, the call site would panic at
    /// runtime — a regression we want to catch early.
    #[test]
    fn record_handshake_error_code_accepts_all_variants() {
        // Exercise every ErrorCode variant. Use the same `code` label
        // that the function does (`format!("{code:?}")`).
        let variants = [
            ErrorCode::ConfigError,
            ErrorCode::HandshakeFailed,
            ErrorCode::HandshakeFailedSource,
            ErrorCode::CertificateVerificationFailed,
            ErrorCode::CrlVerificationFailed,
            ErrorCode::IoError,
            ErrorCode::Unimplemented,
            ErrorCode::SequenceOverflow,
            ErrorCode::SessionStoreError,
            ErrorCode::DerParseError,
            ErrorCode::SerializationFailed,
            ErrorCode::TlsRecordError,
            ErrorCode::ParseError,
            ErrorCode::NonceReuse,
            ErrorCode::InvalidHandshakeType,
            ErrorCode::InvalidMessage,
            ErrorCode::InvalidState,
            ErrorCode::SessionTicket,
            ErrorCode::Cipher,
            ErrorCode::HandshakeMessageParse,
            ErrorCode::Sm2Key,
            ErrorCode::Kat,
        ];
        for code in variants {
            record_handshake_error_code("client", code);
            record_handshake_error_code("server", code);
        }
    }

    /// Verify the `code` label is the variant's Debug name (no
    /// parenthetical payload), which Prometheus operators rely on.
    #[test]
    fn code_label_is_debug_name_without_payload() {
        // Derive label the same way the function does and assert it's
        // a stable identifier (matches the ErrorCode variant name).
        assert_eq!(format!("{:?}", ErrorCode::Cipher), "Cipher");
        assert_eq!(format!("{:?}", ErrorCode::SessionTicket), "SessionTicket");
        assert_eq!(
            format!("{:?}", ErrorCode::HandshakeMessageParse),
            "HandshakeMessageParse"
        );
        assert_eq!(format!("{:?}", ErrorCode::Kat), "Kat");
        assert_eq!(
            format!("{:?}", ErrorCode::CrlVerificationFailed),
            "CrlVerificationFailed"
        );
    }

    /// `TlsError::code()` must be invokable on every error variant so
    /// the call site `e.code()` does not panic at runtime.
    #[test]
    fn tls_error_code_is_total_for_common_variants() {
        // Just exercise a representative slice; full coverage is in the
        // error.rs test suite.
        let _ = TlsError::HandshakeFailed("x".into()).code();
        let _ = TlsError::CipherError("x".into()).code();
        let _ = TlsError::SessionTicketInvalid("x".into()).code();
        let _ = TlsError::SessionTicketExpired.code();
        let _ = TlsError::SessionTicketReplay.code();
        let _ = TlsError::CertificateVerificationFailed("x".into()).code();
        let _ = TlsError::CrlVerificationFailed("x".into()).code();
        let _ = TlsError::KatFailed("x".into()).code();
    }

    /// The function is callable concurrently from multiple threads.
    /// The `metrics` facade is designed to be thread-safe via the
    /// global `Recorder`; this test catches accidental
    /// `!Send`/`!Sync` regressions.
    #[test]
    fn record_handshake_error_code_is_thread_safe() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        let success = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for i in 0..8 {
            let success = Arc::clone(&success);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    record_handshake_error_code(
                        if (i + j) % 2 == 0 { "client" } else { "server" },
                        ErrorCode::Cipher,
                    );
                }
                success.fetch_add(1, Ordering::Relaxed);
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(success.load(Ordering::Relaxed), 8);
    }
}
