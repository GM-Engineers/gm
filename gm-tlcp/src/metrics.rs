//! TLCP metrics module
//!
//! Minimal metrics wrapper for TLCP. Currently exposes `record_bytes` only;
//! additional metrics will be added as the crate matures. Uses the same
//! `metrics` crate as gm-tls for compatibility.

use metrics::counter;

/// Records bytes transferred through a TLCP stream.
///
/// Mirrors `gm_tls::metrics::record_bytes` so existing monitoring
/// infrastructure can aggregate TLCP traffic with the same labels.
pub fn record_bytes(role: &str, direction: &str, count: usize) {
    let role = role.to_owned();
    let direction = direction.to_owned();
    counter!("gmtlcp_bytes_transferred_total", "role" => role, "dir" => direction)
        .increment(count as u64);
}
