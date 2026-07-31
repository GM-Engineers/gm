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
//! | `gmtls_session_resumptions_total`    | Counter  | `result`       | Session resumption attempts   |
//! | `gmtls_bytes_transferred_total`      | Counter  | `role`,`dir`   | Bytes sent/received           |
//! | `gmtls_cert_verification_errors_total`| Counter | `reason`       | Certificate verification errors|

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
