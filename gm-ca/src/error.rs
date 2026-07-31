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
