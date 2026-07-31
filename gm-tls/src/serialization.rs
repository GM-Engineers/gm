//! Serialization module for TLS internal state.
//!
//! This module handles serialization of internal TLS state that is not
//! part of the wire protocol (handshake messages use ASN.1 DER per RFC 8446).
//!
//! Uses `postcard` for binary serialization of internal state structures
//! (session tickets, session state).
//!
//! Previously used `bincode`, which is unmaintained. Migration to `postcard`
//! is NOT backwards-compatible: existing serialized session state will not
//! deserialize with the new format. This is acceptable for session tickets
//! (which are short-lived) but requires all clients to reconnect.

use crate::error::TlsError;

/// Serialize a value to bytes using postcard.
pub fn serialize<T: serde::Serialize>(msg: &T) -> Result<Vec<u8>, TlsError> {
    postcard::to_allocvec(msg).map_err(|e| TlsError::SerializationFailed(e.to_string()))
}

/// Deserialize a value from bytes using postcard.
pub fn deserialize<'de, T: serde::de::Deserialize<'de>>(data: &'de [u8]) -> Result<T, TlsError> {
    postcard::from_bytes(data).map_err(|e| TlsError::SerializationFailed(e.to_string()))
}
