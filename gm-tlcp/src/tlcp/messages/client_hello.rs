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
//! ```
//!
//! TLCP does not define any Hello-extension semantics in §6.4.1.1;
//! any extensions that ever appear on the wire are forwarded as
//! opaque bytes by [`TlcpClientHello::from_body`] (currently: silently
//! discarded after the compression-method block).
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
}

impl TlcpClientHello {
    /// Create a new ClientHello with default settings
    pub fn new() -> Result<Self, TlcpError> {
        let mut random = [0u8; 32];
        // Per RFC 5246 §7.4.1.2 / GB/T 38636-2020 §6.4.1.1, the first
        // 4 bytes are the GMT Unix time (seconds since 1970-01-01
        // 00:00:00 UTC, ignoring leap seconds). The remaining 28 bytes
        // are random. Filling the time field gives us RFC-compliant
        // `random` and `gmt_unix_time` (audit m-1).
        let gmt_unix_time = crate::tlcp::constants::current_gmt_unix_time();
        random[0..4].copy_from_slice(&gmt_unix_time.to_be_bytes());
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random[4..]);

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
        })
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
        // GB/T 38636-2020 §6.4.1.1: session_id_len must be 0..=32.
        if sid_len > crate::tlcp::constants::MAX_SESSION_ID_LEN {
            return Err(TlcpError::InvalidMessage(format!(
                "ClientHello session_id_len {} exceeds MAX_SESSION_ID_LEN ({})",
                sid_len,
                crate::tlcp::constants::MAX_SESSION_ID_LEN
            )));
        }
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
        // GB/T 38636-2020 §6.4.1.1: TLCP only supports the null
        // compression method (0x00). Reject peer-sent non-null methods
        // to fail loud rather than silently accepting a divergent
        // peer (audit m-4).
        if !compression_methods.iter().all(|m| *m == 0x00) {
            return Err(TlcpError::InvalidMessage(
                "ClientHello compression_methods must be all 0x00 (TLCP only supports null)"
                    .to_string(),
            ));
        }

        // TLCP §6.4.1.1 does not define any post-compression fields. Any
        // trailing bytes are silently ignored for forward compatibility
        // with peers that append custom data; this matches GmSSL/Tongsuo
        // behaviour (they don't validate the trailing region either).
        let _ = pos;

        Ok(Self {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
        })
    }
}

impl Default for TlcpClientHello {
    fn default() -> Self {
        Self::new().expect("ClientHello creation should not fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // m-1: the first 4 bytes of the random are the GMT Unix time at
    // the moment of construction. We can't pin the exact value, but
    // we can verify the format (a recent timestamp within the last
    // few hours of the system clock).
    #[test]
    fn ch_random_starts_with_recent_gmt_unix_time() {
        let ch = TlcpClientHello::new().expect("new");
        let now = crate::tlcp::constants::current_gmt_unix_time();
        let bytes = u32::from_be_bytes([ch.random[0], ch.random[1], ch.random[2], ch.random[3]]);
        let delta = now.abs_diff(bytes);
        // Allow 1 hour of clock skew; covers leap-second hiccups and
        // test-runners with stale clocks.
        assert!(delta <= 3600, "random[0..4] = {} differs from now = {} by {}", bytes, now, delta);
    }

    // m-4: compression_methods must contain only 0x00.
    #[test]
    fn ch_rejects_non_null_compression_methods() {
        // Build a minimal valid ClientHello body, then patch the
        // compression-methods byte to 0x01.
        let mut ch = TlcpClientHello::new().expect("new");
        ch.compression_methods = vec![0x01];
        let body = ch.to_bytes().expect("to_bytes");
        // Strip the 4-byte handshake header before calling from_body.
        let err = TlcpClientHello::from_body(&body[4..]).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("compression_methods must be all 0x00"),
            "unexpected error: {}",
            msg
        );
    }
    #[test]
    fn ch_accepts_null_compression_methods() {
        let ch = TlcpClientHello::new().expect("new");
        let body = ch.to_bytes().expect("to_bytes");
        let parsed = TlcpClientHello::from_body(&body[4..]).expect("from_body roundtrip");
        assert_eq!(parsed.compression_methods, vec![0x00u8]);
    }

    // m-6: session_id_len must be 0..=32.
    #[test]
    fn ch_rejects_oversized_session_id_len() {
        // Build a body long enough to pass the < 36 length check, then
        // set sid_len = 33. The remaining fields after sid_len are
        // filler (the parser rejects on sid_len before reading them).
        let mut body = Vec::new();
        body.extend_from_slice(&TLCP_VERSION_1_0);
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(33); // sid_len = 33 (exceeds MAX_SESSION_ID_LEN=32)
        body.extend_from_slice(&[0u8; 64]); // padding so the body is >= 36 bytes
        let err = TlcpClientHello::from_body(&body).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("session_id_len") && msg.contains("exceeds"),
            "unexpected error: {}",
            msg
        );
    }
    #[test]
    fn ch_accepts_max_session_id_len() {
        // sid_len = 32 (the max) is fine. We only test the cap check
        // here; a full roundtrip with 32 bytes of session_id would
        // also need a valid cipher_suites and compression_methods
        // region after the session_id.
        let mut body = Vec::new();
        body.extend_from_slice(&TLCP_VERSION_1_0);
        body.extend_from_slice(&[0u8; 32]);
        body.push(32); // sid_len = 32
        body.extend_from_slice(&[0u8; 32]); // 32 bytes of session_id
        body.extend_from_slice(&2u16.to_be_bytes()); // 1 cipher suite
        body.extend_from_slice(&TLS_ECDHE_SM4_GCM_SM3);
        body.push(1); // 1 compression method
        body.push(0x00);
        let parsed = TlcpClientHello::from_body(&body).expect("from_body");
        assert_eq!(parsed.session_id.len(), 32);
    }
}
