//! TLCP ServerHelloDone message.
//!
//! GB/T 38636-2020 §6.4.1.7. Empty body; carries no payload. Sends
//! as a 4-byte header `[type=0x0E | length=0]`.

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;

/// TLCP ServerHelloDone message (GB/T 38636-2020 §6.4.1.7)
///
/// Empty message sent by server to signal end of server hello phase.
#[derive(Debug, Clone)]
pub struct TlcpServerHelloDone;

impl TlcpServerHelloDone {
    /// Serialize to TLS record bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![HandshakeType::ServerHelloDone as u8, 0, 0, 0]
    }

    /// Deserialize (body is empty)
    pub fn from_body(_body: &[u8]) -> Result<Self, TlcpError> {
        Ok(Self)
    }
}
