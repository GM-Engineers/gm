//! TLCP handshake message type codes.
//!
//! GB/T 38636-2020 §6.4.5.2.1 assigns a one-byte code to each handshake
//! message. These match RFC 5246 §7.4 exactly except for the dual-cert
//! additions (Certificate is reused for the signing certificate).
//!
//! All variants are re-exported from [`crate::tlcp`]; the public API
//! (`gm_tlcp::tlcp::HandshakeType`) is unchanged by the file split.

use crate::error::TlcpError;

/// TLCP handshake type codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// Client hello
    ClientHello = 0x01,
    /// Server hello
    ServerHello = 0x02,
    /// Server certificate (signing)
    Certificate = 0x0B,
    /// Server key exchange (ECDHE parameters)
    ServerKeyExchange = 0x0C,
    /// Certificate request
    CertificateRequest = 0x0D,
    /// Server hello done
    ServerHelloDone = 0x0E,
    /// Certificate verify
    CertificateVerify = 0x0F,
    /// Client key exchange
    ClientKeyExchange = 0x10,
    /// Finished
    Finished = 0x14,
}

impl TryFrom<u8> for HandshakeType {
    type Error = TlcpError;
    fn try_from(value: u8) -> Result<Self, TlcpError> {
        match value {
            0x01 => Ok(Self::ClientHello),
            0x02 => Ok(Self::ServerHello),
            0x0B => Ok(Self::Certificate),
            0x0C => Ok(Self::ServerKeyExchange),
            0x0D => Ok(Self::CertificateRequest),
            0x0E => Ok(Self::ServerHelloDone),
            0x0F => Ok(Self::CertificateVerify),
            0x10 => Ok(Self::ClientKeyExchange),
            0x14 => Ok(Self::Finished),
            _ => Err(TlcpError::InvalidHandshakeType(value)),
        }
    }
}
