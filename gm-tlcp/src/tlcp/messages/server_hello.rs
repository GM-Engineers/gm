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
//! ```
//!
//! TLCP does not define any post-compression fields in §6.4.1.2;
//! [`TlcpServerHello::from_bytes`] silently ignores any trailing bytes,
//! matching GmSSL/Tongsuo behaviour.

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;
use crate::tlcp::constants::{
    TLS_ECC_SM4_CBC_SM3, TLS_ECC_SM4_GCM_SM3, TLS_ECDHE_SM4_CBC_SM3, TLS_ECDHE_SM4_GCM_SM3,
    TLS_IBC_SM4_CBC_SM3, TLS_IBC_SM4_GCM_SM3, TLS_IBSDH_SM4_CBC_SM3, TLS_IBSDH_SM4_GCM_SM3,
};

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
        // GB/T 38636-2020 §6.4.5.2.1 表 2 defines 12 cipher suites (4
        // ECDHE/ECC + 4 SM9 IBSDH/IBC + 4 RSA). gm-tlcp 0.5.x wires the
        // 4 SM2 suites + the 2 SM9 IBC suites (R-4 / R-4.1-hotfix). The
        // remaining 6 (SM9 IBSDH + RSA) are still pending R-4.2 / R-5 and
        // are intentionally rejected here so callers get a clear error.
        if !matches!(
            cipher_suite,
            TLS_ECDHE_SM4_GCM_SM3
                | TLS_ECDHE_SM4_CBC_SM3
                | TLS_ECC_SM4_GCM_SM3
                | TLS_ECC_SM4_CBC_SM3
                | TLS_IBC_SM4_GCM_SM3
                | TLS_IBC_SM4_CBC_SM3
                | TLS_IBSDH_SM4_GCM_SM3
                | TLS_IBSDH_SM4_CBC_SM3
        ) {
            return Err(TlcpError::InvalidMessage(format!(
                "ServerHello cipher_suite {:02X?} is not a known TLCP suite \
                 (gm-tlcp 0.5.3 supports ECDHE/ECC + IBC + IBSDH; RSA pending R-5)",
                cipher_suite
            )));
        }
        let compression_method = data[offset + 2];
        if compression_method != 0x00 {
            return Err(TlcpError::InvalidMessage(format!(
                "ServerHello compression_method {} must be 0x00 (TLCP null compression)",
                compression_method
            )));
        }

        Ok(Self {
            version,
            random,
            session_id,
            cipher_suite,
            compression_method,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TLCP_VERSION_1_0;

    // m-5: cipher_suite must be one of the four TLCP suites.
    #[test]
    fn sh_rejects_unknown_cipher_suite() {
        let mut data = Vec::new();
        data.extend_from_slice(&TLCP_VERSION_1_0); // version
        data.extend_from_slice(&[0u8; 32]); // random
        data.push(0); // session_id_len
        data.extend_from_slice(&[0xAA, 0xBB]); // bogus cipher suite
        data.push(0x00); // compression
        let err = TlcpServerHello::from_bytes(&data).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("not a known TLCP suite"),
            "unexpected error: {}",
            msg
        );
    }
    #[test]
    fn sh_rejects_non_null_compression_method() {
        let mut data = Vec::new();
        data.extend_from_slice(&TLCP_VERSION_1_0);
        data.extend_from_slice(&[0u8; 32]);
        data.push(0); // session_id_len
        data.extend_from_slice(&TLS_ECDHE_SM4_GCM_SM3);
        data.push(0x01); // compression = 1, TLCP only allows 0
        let err = TlcpServerHello::from_bytes(&data).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("compression_method") && msg.contains("0x00"),
            "unexpected error: {}",
            msg
        );
    }
    #[test]
    fn sh_accepts_all_four_tlcp_suites() {
        for suite in [
            TLS_ECDHE_SM4_GCM_SM3,
            TLS_ECDHE_SM4_CBC_SM3,
            TLS_ECC_SM4_GCM_SM3,
            TLS_ECC_SM4_CBC_SM3,
        ] {
            let mut data = Vec::new();
            data.extend_from_slice(&TLCP_VERSION_1_0);
            data.extend_from_slice(&[0u8; 32]);
            data.push(0);
            data.extend_from_slice(&suite);
            data.push(0x00);
            let parsed = TlcpServerHello::from_bytes(&data)
                .unwrap_or_else(|e| panic!("suite {:?}: {}", suite, e));
            assert_eq!(parsed.cipher_suite, suite);
        }
    }
}
