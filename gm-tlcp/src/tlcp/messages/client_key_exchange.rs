//! TLCP ClientKeyExchange message.
//!
//! GB/T 38636-2020 §6.4.1.6. For ECDHE cipher suites, contains the
//! client's ephemeral SM2 public key wrapped in RFC 4492
//! `ECParameters` (curve_type + named_curve + 1-byte length + point
//! bytes). For ECC cipher suites, contains the SM2-encrypted
//! pre-master secret.
//!
//! Wire layout (the body of the handshake message, after the
//! 4-byte handshake header):
//!
//! ```text
//!   uint16      payload_length
//!   opaque      payload[payload_length]
//! ```
//!
//! where `payload` is either the ECParameters-wrapped ephemeral
//! public key (ECDHE) or the encrypted pre-master secret (ECC).

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;
use crate::tlcp::constants::TLCP_ECH_PARAMS_PREFIX;

/// TLCP ClientKeyExchange message (GB/T 38636-2020 §6.4.1.6)
///
/// For ECDHE cipher suites, contains the client's ephemeral SM2 public
/// key wrapped in RFC 4492 `ECParameters` (curve_type + named_curve +
/// 1-byte length + point bytes). For ECC cipher suites, contains the
/// SM2-encrypted pre-master secret.
///
/// Wire layout (the body of the handshake message, after the
/// 4-byte handshake header):
///
/// ```text
///   uint16      payload_length
///   opaque      payload[payload_length]
/// ```
///
/// where `payload` is either the ECParameters-wrapped ephemeral
/// public key (ECDHE) or the encrypted pre-master secret (ECC).
#[derive(Debug, Clone)]
pub struct TlcpClientKeyExchange {
    /// ECDHE mode: full ECParameters-wrapped ephemeral public key
    /// (4 bytes prefix + 65-byte uncompressed SM2 point = 69 bytes).
    /// ECC mode: SM2-encrypted pre-master secret (variable length).
    pub key_exchange: Vec<u8>,
}

impl TlcpClientKeyExchange {
    /// Create for ECDHE mode from a raw (uncompressed, 65-byte)
    /// SM2 public key. Wraps it in the standard RFC 4492
    /// `ECParameters` envelope expected by GmSSL 2026-06+ master.
    pub fn new_ecdhe(ephemeral_public: Vec<u8>) -> Self {
        let mut wrapped =
            Vec::with_capacity(TLCP_ECH_PARAMS_PREFIX.len() + 1 + ephemeral_public.len());
        wrapped.extend_from_slice(&TLCP_ECH_PARAMS_PREFIX);
        wrapped.push(ephemeral_public.len() as u8);
        wrapped.extend_from_slice(&ephemeral_public);
        Self {
            key_exchange: wrapped,
        }
    }

    /// Create for ECC mode with SM2-encrypted pre-master secret.
    pub fn new_ecc(encrypted_pms: Vec<u8>) -> Self {
        Self {
            key_exchange: encrypted_pms,
        }
    }

    /// For ECDHE mode, extract the raw 65-byte SM2 public key from
    /// the ECParameters-wrapped payload. Returns `None` if the
    /// payload is not a valid sm2p256v1 ECParameters blob.
    pub fn ecdhe_public_key(&self) -> Option<&[u8]> {
        let prefix_len = TLCP_ECH_PARAMS_PREFIX.len();
        if self.key_exchange.len() < prefix_len + 1 {
            return None;
        }
        if self.key_exchange[..prefix_len] != TLCP_ECH_PARAMS_PREFIX {
            return None;
        }
        let pub_len = self.key_exchange[prefix_len] as usize;
        let point_offset = prefix_len + 1;
        if self.key_exchange.len() != point_offset + pub_len {
            return None;
        }
        Some(&self.key_exchange[point_offset..point_offset + pub_len])
    }

    /// Serialize to TLS handshake message bytes
    /// (`type=0x10 || 24-bit length || body`), where the body
    /// itself is a 16-bit length-prefixed payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.key_exchange.len();
        let body_len = 2 + payload_len;
        let mut buf = Vec::with_capacity(4 + body_len);
        buf.push(HandshakeType::ClientKeyExchange as u8);
        buf.push((body_len >> 16) as u8);
        buf.push((body_len >> 8) as u8);
        buf.push(body_len as u8);
        // 16-bit payload length prefix (matches GmSSL 2026-06+
        // tls_uint16array_to_bytes format). The previous version of
        // this code used a 1-byte length prefix which was non-standard
        // and rejected by GmSSL master.
        buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.key_exchange);
        buf
    }

    /// Deserialize from the body of a handshake message (after the
    /// 4-byte `type || 24-bit length` prefix has already been
    /// stripped).
    pub fn from_body(body: &[u8]) -> Result<Self, TlcpError> {
        if body.len() < 2 {
            return Err(TlcpError::InvalidMessage(format!(
                "ClientKeyExchange body too short: {} bytes, need at least 2",
                body.len()
            )));
        }
        let payload_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if body.len() < 2 + payload_len {
            return Err(TlcpError::InvalidMessage(format!(
                "ClientKeyExchange too short: {} bytes, need {}",
                body.len(),
                2 + payload_len
            )));
        }
        let key_exchange = body[2..2 + payload_len].to_vec();
        Ok(Self { key_exchange })
    }
}
