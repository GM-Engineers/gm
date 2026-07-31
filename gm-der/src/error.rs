//! DER error types.

use thiserror::Error;

/// Errors that can occur during DER encoding or decoding.
#[derive(Error, Debug)]
pub enum DerError {
    #[error("DER parse error: {0}")]
    ParseError(String),
    #[error("DER encode error: {0}")]
    EncodeError(String),
}
