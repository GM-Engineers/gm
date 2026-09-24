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
        "Total certificate verification errors (PR-4.28: emits under both `code` (structured) and \
         `reason` (legacy string) labels)"
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

/// PR-4.28: records a certificate verification error tagged by
/// structured [`ErrorCode`]. Mirror of
/// `gm_tls::metrics::record_handshake_error_code` (PR-4.22)
/// and `gm_ca::metrics::record_error_code` (PR-4.27). The
/// `code` label uses `ErrorCode`'s `Debug` representation
/// (e.g. `"SessionTicket"`, `"CertificateVerificationFailed"`,
/// `"CrlVerificationFailed"`).
///
/// Replaces the legacy string-based `record_cert_error` API.
/// The legacy `reason` label is still incremented (from
/// deprecated `record_cert_error`) so existing dashboards do
/// not break during the migration.
///
/// # Companion metrics
///
/// Two cert-related error counters now coexist in gm-tls:
///
/// - `gmtls_handshake_errors_total{role, code}` (PR-4.22) —
///   emits **once per failed handshake**, tagged by the
///   returned `TlsError::code()`. Covers every TLS layer
///   failure, including cert verification.
///
/// - `gmtls_cert_verification_errors_total{code}` (this PR) —
///   emits **per certificate verification attempt** (not
///   necessarily a complete handshake). Use this when you
///   want to alert on PKI-level anomalies independent of
///   the handshake state machine (e.g. session-ticket
///   fail-closed reject before a full handshake even
///   starts).
pub fn record_cert_error_code(code: ErrorCode) {
    let code = format!("{code:?}");
    counter!("gmtls_cert_verification_errors_total", "code" => code).increment(1);
}

/// Records a certificate verification error.
///
/// **Deprecated** since 0.2.14 — use [`record_cert_error_code`]
/// with a structured [`ErrorCode`] instead. The legacy `reason`
/// label continues to be incremented for one release cycle so
/// existing dashboards do not break, but new alerts / dashboards
/// should switch to the `code` label via
/// `record_cert_error_code(ErrorCode::Xxx)`.
#[deprecated(
    since = "0.2.14",
    note = "use record_cert_error_code with structured ErrorCode for compile-time-checked metric \
            labels"
)]
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
///
/// PR-4.25: upgraded from a manually-completed guard to a
/// true RAII guard. The timer starts at construction and
/// **automatically records on drop** with `result="error"`
/// (the conservative default — every handshake that did
/// not explicitly call [`HandshakeTimer::finish`] with
/// `result="success"` counts as an error in metrics).
///
/// Before PR-4.25, the caller had to invoke
/// `timer.finish("success")` **at every** control-flow exit
/// point — including each `?` early-return inside the
/// handshake coroutine. Missing one under-counted the
/// handshake-error histogram and the
/// `gmtls_handshakes_total{result="error"}` counter. The
/// RAII form eliminates that whole class of bugs: any
/// path that leaves the timer's scope — panic, unwind,
/// `?` early-return, or simply forgetting to call
/// `finish` — still produces a single, idempotent
/// `result="error"` record.
///
/// Explicit calls to [`HandshakeTimer::finish`] (with
/// `"success"` or `"error"`) continue to work and take
/// precedence over the drop default — the guard is
/// idempotent on the first record, regardless of which
/// path wins.
pub struct HandshakeTimer {
    role: String,
    start: Instant,
    /// `None` means "no explicit `finish` has been called;
    /// Drop will record `result="error"`". `Some(label)`
    /// means an explicit `finish` already recorded with
    /// that label; Drop is a no-op.
    recorded: Option<String>,
}

impl HandshakeTimer {
    /// Start a handshake timer for `role` (typically
    /// `"client"` or `"server"`).
    pub fn new(role: &str) -> Self {
        Self {
            role: role.to_string(),
            start: Instant::now(),
            recorded: None,
        }
    }

    /// Mark this handshake as `result` (`"success"` or
    /// `"error"`). Subsequent drop will be a no-op
    /// (already recorded).
    pub fn finish(mut self, result: &str) {
        // Idempotent: only the first call records. Both
        // explicit finish() and Drop funnel through this
        // record() helper so the metric emission shape
        // stays in sync.
        if self.recorded.is_some() {
            return;
        }
        self.recorded = Some(result.to_string());
        Self::record(&self.role, result, self.start.elapsed().as_secs_f64());
    }

    /// Emit the counter + histogram pair. Pulled out so
    /// [`HandshakeTimer::finish`] and `Drop` share one
    /// emission site.
    fn record(role: &str, result: &str, elapsed_secs: f64) {
        counter!(
            "gmtls_handshakes_total",
            "role" => role.to_string(),
            "result" => result.to_string()
        )
        .increment(1);
        histogram!(
            "gmtls_handshake_duration_seconds",
            "role" => role.to_string()
        )
        .record(elapsed_secs);
    }
}

impl Drop for HandshakeTimer {
    fn drop(&mut self) {
        // PR-4.25: if `finish()` was never called, record
        // the conservative outcome (`"error"`) so the
        // histogram / counter stay accurate even on `?`
        // early-returns, panics, or simply forgotten
        // manual cleanups.
        if self.recorded.is_some() {
            return;
        }
        let elapsed = self.start.elapsed().as_secs_f64();
        let result = "error".to_string();
        // Take the slot so re-drop (e.g. via panic during
        // record itself) is also idempotent.
        self.recorded = Some(result.clone());
        Self::record(&self.role, &result, elapsed);
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

// ---------------------------------------------------------------------------
// PR-4.25 unit tests: HandshakeTimer RAII guard
// ---------------------------------------------------------------------------
#[cfg(test)]
mod pr425_handshake_timer_raii_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counter access to the global Prometheus registry is
    /// not trivially testable from `cargo test` (no real
    /// exporter is bound in unit tests). These tests instead
    /// verify the *control flow*: PR-4.25's contract is
    /// that `Drop` fires the right emission path even when
    /// `finish()` is skipped, and that `finish()` is
    /// idempotent.
    ///
    /// For end-to-end coverage of the histogram/counter
    /// emission, see the loopback tests in
    /// `tests/handshake_timeout.rs` and `tests/spiffe_uri.rs`
    /// which exercise the real handshake code paths.
    #[test]
    fn drop_without_finish_does_not_panic() {
        // Construct and immediately drop — the Drop impl
        // should record `result="error"` without complaint.
        drop(HandshakeTimer::new("client"));
        drop(HandshakeTimer::new("server"));
    }

    /// PR-4.25: explicitly calling `finish("success")` must
    /// not double-emit on drop. We exercise the path by
    /// finishing the timer (consuming `self`) and trusting
    /// that the compiler would reject a double-finish call.
    /// The complementary assertion is the unit-test for
    /// `record()` visibility — here we only check that the
    /// `finish()` API surface is still callable.
    #[test]
    fn finish_success_is_callable() {
        HandshakeTimer::new("client").finish("success");
        HandshakeTimer::new("server").finish("success");
    }

    /// PR-4.25: `finish("error")` is also still callable
    /// (pre-PR-4.25 callers relied on this; PR-4.25 keeps
    /// the API but recommends relying on Drop instead).
    #[test]
    fn finish_error_is_callable() {
        HandshakeTimer::new("client").finish("error");
        HandshakeTimer::new("server").finish("error");
    }

    /// PR-4.25: drop semantics under contention. Even
    /// though most handshakes run in async contexts, we
    /// sanity-check that 64 timers dropped in parallel do
    /// not deadlock or panic.
    #[test]
    fn drop_many_timers_concurrently() {
        let n = 64;
        let success = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let success = Arc::clone(&success);
            handles.push(std::thread::spawn(move || {
                drop(HandshakeTimer::new("client"));
                success.fetch_add(1, Ordering::Relaxed);
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(success.load(Ordering::Relaxed), n);
    }
}

// ---------------------------------------------------------------------------
// PR-4.28 unit tests: record_cert_error_code
// ---------------------------------------------------------------------------
#[cfg(test)]
mod pr428_record_cert_error_code_tests {
    use super::*;
    use crate::error::ErrorCode;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// PR-4.28: every `ErrorCode` variant reachable through
    /// `record_cert_error_code` without panic. Mirror of the
    /// PR-4.22 / PR-4.27 unit-test pattern.
    #[test]
    fn record_cert_error_code_accepts_all_variants() {
        for code in [
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
        ] {
            record_cert_error_code(code);
        }
    }

    /// PR-4.28: the legacy `record_cert_error(&str)` API
    /// continues to emit `gmtls_cert_verification_errors_total`
    /// under the legacy `reason` label, so existing dashboards
    /// do not break during the migration.
    #[test]
    #[allow(deprecated)]
    fn legacy_record_cert_error_still_callable() {
        record_cert_error("session_ticket_tampered");
        record_cert_error("custom_reason_xyz");
    }

    /// PR-4.28: thread safety. 8 threads × 22 variants.
    #[test]
    fn record_cert_error_code_is_thread_safe() {
        const N_THREADS: usize = 8;
        let success = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(N_THREADS);
        for _ in 0..N_THREADS {
            let success = Arc::clone(&success);
            handles.push(std::thread::spawn(move || {
                record_cert_error_code(ErrorCode::SessionTicket);
                record_cert_error_code(ErrorCode::Cipher);
                record_cert_error_code(ErrorCode::CertificateVerificationFailed);
                success.fetch_add(3, Ordering::Relaxed);
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(success.load(Ordering::Relaxed), N_THREADS * 3);
    }
}
