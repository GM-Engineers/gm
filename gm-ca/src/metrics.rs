//! Metrics instrumentation for gm-ca service.

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
        "Total number of CA service errors"
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

/// Records a CA service error.
pub fn record_error(error_type: &str) {
    counter!("gmca_errors_total", "type" => error_type.to_string()).increment(1);
}
