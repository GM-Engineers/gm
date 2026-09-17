//! Backward-compatible wrapper over `gm_crypto::x509::verify`.
//!
//! Phase D-1 of the cert-verification plan moved the TLS-version-agnostic
//! X.509 chain validation logic out of `gm-tls` so that `gm-tlcp` can
//! share the same implementation. The original ~860-line `cert_verify.rs`
//! lived here; this file is now a thin shim that:
//!
//! 1. Re-exports every public item from `gm_crypto::x509::verify`
//!    (`OwnedCert`, `CrlInfo`, `validate_cert_pem`,
//!    `verify_cert_chain_sm2_chain`, `verify_crl`, `verify_cert_crl`,
//!    `extract_server_pubkey_for_cert_verify`, `MAX_CERT_CHAIN_DEPTH`)
//!    so callers of `gm_tls::cert_verify::*` continue to compile.
//!
//! 2. Re-wraps the two functions that touch PEM/DER/X509Certificate
//!    parsing with the original `TlsError` return type, so existing
//!    `?` propagation in gm-tls continues to work without rewriting
//!    every call site. The conversion is identity-preserving for the
//!    cert/CRL error variants (see `From<gm_crypto::CryptoError> for
//!    TlsError` in `gm-tls/src/error.rs`).
//!
//! **No behaviour changed** — the moved code in
//! `gm_crypto::x509::verify` is a verbatim port of the prior
//! implementation, with `TlsError` replaced by `CryptoError`.
//! `gm-tls`'s existing test suite is the regression net for this refactor.

use crate::error::TlsError;
use time::OffsetDateTime;

// Re-export everything from gm-crypto at the same path.
pub use gm_crypto::x509::verify::{
    CrlInfo, MAX_CERT_CHAIN_DEPTH, OwnedCert, extract_server_pubkey_for_cert_verify,
    verify_cert_crl, verify_crl,
};

// Re-wrap the two public functions that take/return `TlsError` so the
// call sites in gm-tls don't need to be touched. The body is a one-liner
// that delegates to gm-crypto and lets `From<CryptoError>` do the error
// translation (preserving `CertificateVerificationFailed` /
// `CrlVerificationFailed` variants).
pub use gm_crypto::x509::verify as inner;

/// PEM certificate validation (parse + validity + optional hostname).
///
/// Wrapper around [`gm_crypto::x509::verify::validate_cert_pem`] that
/// preserves the original `TlsError` return type.
pub fn validate_cert_pem(
    cert_pem: &[u8],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
) -> Result<(), TlsError> {
    inner::validate_cert_pem(cert_pem, now, expected_domain)?;
    Ok(())
}

/// Verify a full certificate chain against one or more trust anchors.
///
/// Wrapper around [`gm_crypto::x509::verify::verify_cert_chain_sm2_chain`].
pub fn verify_cert_chain_sm2_chain(
    leaf_chain: &[OwnedCert],
    trust_anchors: &[OwnedCert],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
) -> Result<(), TlsError> {
    inner::verify_cert_chain_sm2_chain(leaf_chain, trust_anchors, now, expected_domain)?;
    Ok(())
}
