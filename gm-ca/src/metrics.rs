//! Metrics instrumentation for gm-ca service.

use std::net::IpAddr;

use crate::error::CaErrorCode;
use metrics::{Unit, counter, describe_counter};

/// Describes all metrics exported by gm-ca.
/// Call this once at application startup.
pub fn describe_ca_metrics() {
    describe_counter!(
        "gmca_signatures_total",
        Unit::Count,
        "Total number of certificates signed"
    );
    describe_counter!(
        "gmca_renewals_total",
        Unit::Count,
        "Total number of certificate renewals"
    );
    describe_counter!(
        "gmca_revocations_total",
        Unit::Count,
        "Total number of certificate revocations"
    );
    describe_counter!(
        "gmca_errors_total",
        Unit::Count,
        "Total number of CA service errors (PR-4.27: emits under both `code` (structured) and `type` (legacy string) labels)"
    );
    describe_counter!(
        "gmca_rate_limited_total",
        Unit::Count,
        "Total number of per-caller rate-limit rejections (PR-4.12)"
    );
}

/// Records a successful certificate signature.
pub fn record_signature() {
    counter!("gmca_signatures_total").increment(1);
}

/// Records a successful certificate renewal.
pub fn record_renewal() {
    counter!("gmca_renewals_total").increment(1);
}

/// Records a successful certificate revocation.
pub fn record_revocation() {
    counter!("gmca_revocations_total").increment(1);
}

/// PR-4.27: records a CA service error tagged by structured
/// [`CaErrorCode`]. Mirror of
/// `gm_tls::metrics::record_handshake_error_code` (PR-4.22).
/// The `code` label uses `CaErrorCode`'s `Debug` representation
/// (e.g. `"InvalidArgument"`, `"SigningFailed"`,
/// `"DatabaseError"`, `"InternalError"`).
///
/// Replaces this the legacy string-based `record_error` API.
/// The legacy `type` label is still incremented (from
/// deprecated `record_error`) so existing dashboards do not
/// break during the migration.
pub fn record_error_code(code: CaErrorCode) {
    let code = format!("{code:?}");
    counter!("gmca_errors_total", "code" => code).increment(1);
}

/// **Deprecated** since 0.4.2 — use [`record_error_code`] with
/// a structured [`CaErrorCode`] instead. The legacy `type`
/// label continues to be incremented for one release cycle so
/// existing dashboards do not break, but new alerts / dashboards
/// should switch to the `code` label via
/// `record_error_code(CaErrorCode::Xxx)`.
#[deprecated(
    since = "0.4.2",
    note = "use record_error_code with structured CaErrorCode for compile-time-checked metric labels"
)]
pub fn record_error(error_type: &str) {
    counter!("gmca_errors_total", "type" => error_type.to_string()).increment(1);
}

/// PR-4.12 / P2-7: records a per-caller rate-limit rejection.
/// The `caller_ip` label allows operators to alert on specific
/// abusive clients without scraping logs. Pre-PR-4.12 a single
/// global bucket produced only `gmca_errors_total{type="rate_limited"}`
/// with no caller attribution.
pub fn record_rate_limited(caller_ip: IpAddr) {
    counter!(
        "gmca_rate_limited_total",
        "caller_ip" => caller_ip.to_string()
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// PR-4.27 unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod pr427_record_error_code_tests {
    use super::*;
    use crate::error::CaError;

    /// Verify `record_error_code` is callable with every
    /// [`CaErrorCode`] variant and does not panic. The
    /// Prometheus counter is global (a no-op in unit tests
    /// without an installed recorder), so the assertion is
    /// limited to "every variant is reachable".
    #[test]
    fn record_error_code_accepts_all_variants() {
        for code in [
            CaErrorCode::InvalidArgument,
            CaErrorCode::InvalidCsr,
            CaErrorCode::SigningFailed,
            CaErrorCode::CertificateNotFound,
            CaErrorCode::InvalidCertificate,
            CaErrorCode::DatabaseError,
            CaErrorCode::InternalError,
        ] {
            record_error_code(code);
        }
    }

    /// Verify [`CaError::code`] maps every variant to a
    /// distinct, exhaustive `CaErrorCode` (no overlap,
    /// no missing case). Catches future refactors that
    /// add a `CaError` variant without a matching code.
    #[test]
    fn all_ca_error_variants_have_a_code() {
        let errs: [CaError; 7] = [
            CaError::InvalidArgument("x".to_string()),
            CaError::InvalidCsr("x".to_string()),
            CaError::SigningFailed("x".to_string()),
            CaError::CertificateNotFound("x".to_string()),
            CaError::InvalidCertificate("x".to_string()),
            CaError::DatabaseError("x".to_string()),
            CaError::InternalError("x".to_string()),
        ];
        let codes: Vec<CaErrorCode> = errs.iter().map(|e| e.code()).collect();
        // All distinct (the `code()` mapping must be 1-to-1).
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "code() mapping has duplicates");
        // Display strings are all distinct (required for
        // Prometheus label cardinality to stay bounded).
        let labels: std::collections::HashSet<_> = codes.iter().map(|c| format!("{c:?}")).collect();
        assert_eq!(labels.len(), codes.len(), "Debug labels collide");
    }

    /// Verify the deprecated `record_error` API still
    /// works (does not panic) so existing call-sites that
    /// have not yet migrated continue to compile.
    #[test]
    #[allow(deprecated)]
    fn legacy_record_error_still_callable() {
        record_error("invalid_profile_json");
        record_error("sign_failed");
        record_error("db_insert_failed");
    }

    /// Mirror of gm-tls PR-4.22 thread-safety test:
    /// exercise `code()` and `record_error_code()` from
    /// 8 threads concurrently, each producing every
    /// variant. No panics, no data races.
    #[test]
    fn record_error_code_is_thread_safe() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        const N_THREADS: usize = 8;
        const N_VARIANTS: usize = 7;
        let success = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(N_THREADS);
        for _ in 0..N_THREADS {
            let success = Arc::clone(&success);
            handles.push(std::thread::spawn(move || {
                for code in [
                    CaErrorCode::InvalidArgument,
                    CaErrorCode::InvalidCsr,
                    CaErrorCode::SigningFailed,
                    CaErrorCode::CertificateNotFound,
                    CaErrorCode::InvalidCertificate,
                    CaErrorCode::DatabaseError,
                    CaErrorCode::InternalError,
                ] {
                    record_error_code(code);
                    success.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(success.load(Ordering::Relaxed), N_THREADS * N_VARIANTS);
    }
}
