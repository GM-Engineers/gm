//! TLCP ClientHello message.
//!
//! GB/T 38636-2020 §6.4.1.1. The body is
//!
//! ```text
//!   ProtocolVersion version;     // 2 bytes
//!   Random          random;      // 32 bytes
//!   opaque          session_id<0..32>;
//!   CipherSuites    cipher_suites<2..2^16-1>;   // each suite is 2 bytes
//!   CompressionMethods compression_methods<1..2^8-1>;
//!   // optional SM2 ECDHE extension (TLCP-specific)
//!   opaque          sm2_ephemeral_public<0..2^16-1>;
//! ```
//!
//! Serialization prepends a 4-byte handshake header
//! `[type=0x01 | length(3 bytes)]` per RFC 5246 §7.4.

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;
use crate::tlcp::constants::{
    TLCP_VERSION_1_0, TLS_ECC_SM4_CBC_SM3, TLS_ECC_SM4_GCM_SM3, TLS_ECDHE_SM4_CBC_SM3,
    TLS_ECDHE_SM4_GCM_SM3,
};

/// TLCP ClientHello message
///
/// GB/T 38636-2020 §6.4.1.1
#[derive(Debug, Clone)]
pub struct TlcpClientHello {
    /// Client version (always TLCP_VERSION_1_0)
    pub version: [u8; 2],
    /// Client random (32 bytes)
    pub random: [u8; 32],
    /// Session ID (variable length, 0-32 bytes)
    pub session_id: Vec<u8>,
    /// Cipher suites offered by client
    pub cipher_suites: Vec<[u8; 2]>,
    /// Compression methods (always \[0\] = null)
    pub compression_methods: Vec<u8>,
    /// SM2 ephemeral public key for ECDHE (uncompressed, 65 bytes)
    pub sm2_ephemeral_public: Option<Vec<u8>>,
}

impl TlcpClientHello {
    /// Create a new ClientHello with default settings
    pub fn new() -> Result<Self, TlcpError> {
        let mut random = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random);

        Ok(Self {
            version: TLCP_VERSION_1_0,
            random,
            session_id: Vec::new(),
            cipher_suites: vec![
                TLS_ECDHE_SM4_GCM_SM3,
                TLS_ECDHE_SM4_CBC_SM3,
                TLS_ECC_SM4_GCM_SM3,
                TLS_ECC_SM4_CBC_SM3,
            ],
            compression_methods: vec![0x00],
            sm2_ephemeral_public: None,
        })
    }

    /// Set the SM2 ephemeral public key for ECDHE
    pub fn with_ephemeral_key(mut self, public_key: &[u8]) -> Self {
        self.sm2_ephemeral_public = Some(public_key.to_vec());
        self
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlcpError> {
        let mut buf = Vec::with_capacity(128);

        // Handshake header: type + length (3 bytes)
        buf.push(HandshakeType::ClientHello as u8);
        // Length will be filled after body is built

        let mut body = Vec::with_capacity(96);

        // Version
        body.extend_from_slice(&self.version);

        // Random
        body.extend_from_slice(&self.random);

        // Session ID
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);

        // Cipher suites
        let cs_len = (self.cipher_suites.len() * 2) as u16;
        body.extend_from_slice(&cs_len.to_be_bytes());
        for suite in &self.cipher_suites {
            body.extend_from_slice(suite);
        }

        // Compression methods
        body.push(self.compression_methods.len() as u8);
        body.extend_from_slice(&self.compression_methods);

        // SM2 ephemeral key (if present, as custom extension)
        if let Some(ref key) = self.sm2_ephemeral_public {
            // TLCP extension type for SM2 ECDHE parameters
            // Using a simple approach: append as raw data with length prefix
            body.extend_from_slice(&(key.len() as u16).to_be_bytes());
            body.extend_from_slice(key);
        }

        // Fill in length
        let body_len = body.len() as u32;
        buf.push((body_len >> 16) as u8);
        buf.push((body_len >> 8) as u8);
        buf.push(body_len as u8);
        buf.extend(body);

        Ok(buf)
    }

    /// Deserialize a ClientHello from handshake message bytes.
    ///
    /// `data` should be the body (after the 4-byte handshake header).
    pub fn from_body(data: &[u8]) -> Result<Self, TlcpError> {
        if data.len() < 36 {
            return Err(TlcpError::InvalidMessage(
                "ClientHello too short".to_string(),
            ));
        }
        let version = [data[0], data[1]];
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[2..34]);

        let mut pos = 34;

        // Session ID
        if pos >= data.len() {
            return Err(TlcpError::InvalidMessage(
                "ClientHello truncated at session_id_len".to_string(),
            ));
        }
        let sid_len = data[pos] as usize;
        pos += 1;
        if pos + sid_len > data.len() {
            return Err(TlcpError::InvalidMessage(
                "ClientHello truncated at session_id".to_string(),
            ));
        }
        let session_id = data[pos..pos + sid_len].to_vec();
        pos += sid_len;

        // Cipher suites
        if pos + 2 > data.len() {
            return Err(TlcpError::InvalidMessage(
                "ClientHello truncated at cipher_suites_len".to_string(),
            ));
        }
        let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + cs_len > data.len() || cs_len % 2 != 0 {
            return Err(TlcpError::InvalidMessage(
                "ClientHello truncated at cipher_suites".to_string(),
            ));
        }
        let mut cipher_suites = Vec::new();
        for i in (0..cs_len).step_by(2) {
            cipher_suites.push([data[pos + i], data[pos + i + 1]]);
        }
        pos += cs_len;

        // Compression methods
        if pos >= data.len() {
            return Err(TlcpError::InvalidMessage(
                "ClientHello truncated at compression_len".to_string(),
            ));
        }
        let comp_len = data[pos] as usize;
        pos += 1;
        if pos + comp_len > data.len() {
            return Err(TlcpError::InvalidMessage(
                "ClientHello truncated at compression".to_string(),
            ));
        }
        let compression_methods = data[pos..pos + comp_len].to_vec();
        pos += comp_len;

        // Optional SM2 ephemeral key extension
        let sm2_ephemeral_public = if pos + 2 <= data.len() {
            let key_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + key_len <= data.len() {
                Some(data[pos..pos + key_len].to_vec())
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
            cipher_suites,
            compression_methods,
            sm2_ephemeral_public,
        })
    }
}

impl Default for TlcpClientHello {
    fn default() -> Self {
        Self::new().expect("ClientHello creation should not fail")
    }
}
