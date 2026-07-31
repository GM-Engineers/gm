//! HTTP client error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum HttpClientError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("request failed: {0}")]
    RequestFailed(String),

    #[error("response parse failed: {0}")]
    ResponseParseError(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("URL validation failed: {0}")]
    UrlValidationError(String),
}
