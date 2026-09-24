//! CA service error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CaError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("invalid CSR: {0}")]
    InvalidCsr(String),

    #[error("certificate signing failed: {0}")]
    SigningFailed(String),

    #[error("certificate not found: {0}")]
    CertificateNotFound(String),

    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("database error: {0}")]
    DatabaseError(String),

    #[error("internal error: {0}")]
    InternalError(String),
}

/// PR-4.27: structured error code for [`CaError`].
/// Mirror of `gm_tls::error::ErrorCode` (PR-4.18) and
/// `gm_tlcp::TlcpErrorCode` (PR-4.21). The `code` label
/// uses `CaErrorCode`'s `Debug` representation (e.g.
/// `"InvalidArgument"`, `"InvalidCsr"`, `"SigningFailed"`,
/// `"CertificateNotFound"`, `"InvalidCertificate"`,
/// `"DatabaseError"`, `"InternalError"`) so dashboards can
/// alert on differentiated subsystems independently.
///
/// Acquire the code via [`CaError::code()`]. Emit metrics
/// via `gm_ca::metrics::record_error_code(code)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CaErrorCode {
    /// Caller-supplied argument failed validation
    /// (e.g. malformed profile JSON, missing required
    /// fields, empty CN).
    InvalidArgument,
    /// Submitted CSr failed structural / signature
    /// validation (parse failure, missing public key,
    /// missing SAN, etc.).
    InvalidCsr,
    /// Underlying cryptographic operation (sign, verify,
    /// encrypt) failed at runtime.
    SigningFailed,
    /// Caller-supplied serial / CN does not match a
    /// stored certificate.
    CertificateNotFound,
    /// Stored certificate failed structural / validity
    /// checks (expired, revoked, malformed).
    InvalidCertificate,
    /// Backend database (sqlx, sqlite, postgres) failed.
    DatabaseError,
    /// Catch-all for unexpected internal errors. Operators
    /// should treat this label as the highest-severity
    /// alert — it indicates the CA is operating outside
    /// its expected envelope.
    InternalError,
}

impl CaError {
    /// PR-4.27: structured error code. Mirror of
    /// `TlsError::code` (gm-tls PR-4.18) and
    /// `TlcpError::code` (gm-tlcp PR-4.21). Always defined
    /// — every `CaError` variant maps to exactly one
    /// `CaErrorCode`.
    pub fn code(&self) -> CaErrorCode {
        match self {
            CaError::InvalidArgument(_) => CaErrorCode::InvalidArgument,
            CaError::InvalidCsr(_) => CaErrorCode::InvalidCsr,
            CaError::SigningFailed(_) => CaErrorCode::SigningFailed,
            CaError::CertificateNotFound(_) => CaErrorCode::CertificateNotFound,
            CaError::InvalidCertificate(_) => CaErrorCode::InvalidCertificate,
            CaError::DatabaseError(_) => CaErrorCode::DatabaseError,
            CaError::InternalError(_) => CaErrorCode::InternalError,
        }
    }
}
