//! Metrics instrumentation for gm-ca service.

use std::net::IpAddr;

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

/// Records a CA service error.
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
