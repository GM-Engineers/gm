//! TLCP ServerHello message.
//!
//! GB/T 38636-2020 §6.4.1.2. The body is
//!
//! ```text
//!   ProtocolVersion version;     // 2 bytes
//!   Random          random;      // 32 bytes
//!   opaque          session_id<0..32>;
//!   CipherSuite     cipher_suite;   // 2 bytes (selected)
//!   CompressionMethod compression_method;   // 1 byte
//!   // optional SM2 ECDHE extension (TLCP-specific)
//!   opaque          sm2_ephemeral_public<0..2^16-1>;
//! ```

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;
use crate::tlcp::constants::{TLS_ECC_SM4_GCM_SM3, TLS_ECDHE_SM4_CBC_SM3, TLS_ECDHE_SM4_GCM_SM3};

/// TLCP ServerHello message
///
/// GB/T 38636-2020 §6.4.1.2
#[derive(Debug, Clone)]
pub struct TlcpServerHello {
    /// Server version
    pub version: [u8; 2],
    /// Server random (32 bytes)
    pub random: [u8; 32],
    /// Selected session ID
    pub session_id: Vec<u8>,
    /// Selected cipher suite
    pub cipher_suite: [u8; 2],
    /// Selected compression method
    pub compression_method: u8,
    /// SM2 ephemeral public key for ECDHE
    pub sm2_ephemeral_public: Option<Vec<u8>>,
}

impl TlcpServerHello {
    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlcpError> {
        if data.len() < 38 {
            return Err(TlcpError::InvalidMessage(
                "ServerHello too short".to_string(),
            ));
        }

        let version = [data[0], data[1]];
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[2..34]);

        let session_id_len = data[34] as usize;
        if data.len() < 35 + session_id_len + 3 {
            return Err(TlcpError::InvalidMessage(
                "ServerHello truncated".to_string(),
            ));
        }

        let session_id = data[35..35 + session_id_len].to_vec();
        let offset = 35 + session_id_len;

        let cipher_suite = [data[offset], data[offset + 1]];
        let compression_method = data[offset + 2];

        // Parse SM2 ECDHE extension if present
        let sm2_ephemeral_public = if data.len() > offset + 3 + 2 {
            let ext_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
            if data.len() >= offset + 5 + ext_len {
                Some(data[offset + 5..offset + 5 + ext_len].to_vec())
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            sm2_ephemeral_public,
        })
    }

    /// Check if this server hello selected an ECDHE cipher suite
    pub fn is_ecdhe(&self) -> bool {
        self.cipher_suite == TLS_ECDHE_SM4_GCM_SM3 || self.cipher_suite == TLS_ECDHE_SM4_CBC_SM3
    }

    /// Check if this server hello selected a GCM cipher suite
    pub fn is_gcm(&self) -> bool {
        self.cipher_suite == TLS_ECDHE_SM4_GCM_SM3 || self.cipher_suite == TLS_ECC_SM4_GCM_SM3
    }

    /// Serialize to handshake message bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(64);
        body.extend_from_slice(&self.version);
        body.extend_from_slice(&self.random);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&self.cipher_suite);
        body.push(self.compression_method);

        // SM2 ECDHE extension if present
        if let Some(ref key) = self.sm2_ephemeral_public {
            body.extend_from_slice(&(key.len() as u16).to_be_bytes());
            body.extend_from_slice(key);
        }

        let mut buf = Vec::with_capacity(4 + body.len());
        buf.push(HandshakeType::ServerHello as u8);
        let body_len = body.len() as u32;
        buf.push((body_len >> 16) as u8);
        buf.push((body_len >> 8) as u8);
        buf.push(body_len as u8);
        buf.extend(body);
        buf
    }
}
