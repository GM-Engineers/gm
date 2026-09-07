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
//!   /* strict mode (feature `tlcp-strict`):
//!    * body = opaque body[length]
//!    * (no overall length prefix; the 24-bit HS length field covers it) */
//!   opaque body[length]
//!   /* default (GmSSL-compatible) mode:
//!    * body = uint16 payload_length || opaque payload[payload_length]
//!    * (matches GmSSL 2026-06+ master `tls_uint16array_to_bytes` format) */
//!   uint16      payload_length
//!   opaque      payload[payload_length]
//! ```
//!
//! `payload` (or `body`, in strict mode) is either the ECParameters-wrapped
//! ephemeral public key (ECDHE) or the encrypted pre-master secret (ECC).

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
///   /* strict mode (feature `tlcp-strict`):
///    * body = opaque body[length] (no length prefix)
///    *
///    * default (GmSSL-compatible) mode:
///    * body = uint16 payload_length || opaque payload[payload_length]
///    * (matches GmSSL 2026-06+ master `tls_uint16array_to_bytes`)
/// ```
///
/// `payload` (or `body`, in strict mode) is either the ECParameters-wrapped
/// ephemeral public key (ECDHE) or the encrypted pre-master secret (ECC).
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
    /// (`type=0x10 || 24-bit length || body`).
    ///
    /// In default (GmSSL-compatible) mode, the body is prefixed with a
    /// 16-bit length to match GmSSL 2026-06+ master's
    /// `tls_uint16array_to_bytes` format.
    ///
    /// In strict mode (feature `tlcp-strict`), the body is emitted without
    /// that prefix, per RFC 5246 §7.4.7 / GB/T 38636-2020 §6.4.1.6.
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.key_exchange.len();
        // Pre-allocate for the worst case (default mode: 4-byte HS header
        // + 2-byte uint16 + body). Strict mode wastes 2 bytes of capacity.
        let mut buf = Vec::with_capacity(4 + 2 + payload_len);
        buf.push(HandshakeType::ClientKeyExchange as u8);

        #[cfg(not(feature = "tlcp-strict"))]
        let body_len: usize = 2 + payload_len;
        #[cfg(feature = "tlcp-strict")]
        let body_len: usize = payload_len;

        buf.push((body_len >> 16) as u8);
        buf.push((body_len >> 8) as u8);
        buf.push(body_len as u8);

        #[cfg(not(feature = "tlcp-strict"))]
        {
            // 16-bit payload length prefix (matches GmSSL 2026-06+
            // tls_uint16array_to_bytes format). The previous version of
            // this code used a 1-byte length prefix which was non-standard
            // and rejected by GmSSL master.
            buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
        }
        // strict mode (feature `tlcp-strict`): no uint16 prefix; the
        // HS header's 24-bit length field is the only framing.
        buf.extend_from_slice(&self.key_exchange);
        buf
    }

    /// Deserialize from the body of a handshake message (after the
    /// 4-byte `type || 24-bit length` prefix has already been
    /// stripped).
    ///
    /// In default mode the body is `uint16 payload_length || payload`.
    /// In strict mode (feature `tlcp-strict`) the body is the raw
    /// ECDH params / encrypted PMS — no uint16 prefix.
    pub fn from_body(body: &[u8]) -> Result<Self, TlcpError> {
        #[cfg(not(feature = "tlcp-strict"))]
        {
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
            Ok(Self {
                key_exchange: body[2..2 + payload_len].to_vec(),
            })
        }
        #[cfg(feature = "tlcp-strict")]
        {
            // Strict mode: body is the raw ECDH params or encrypted PMS,
            // exactly as it sits in the HS body. The 24-bit HS length
            // field above this body already covered the framing.
            Ok(Self {
                key_exchange: body.to_vec(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KAT: a 65-byte SM2 uncompressed ephemeral public key, copied from
    /// the openHiTLS-bundled test cert for ECDHE SKE / CKE round-trips.
    /// It is referenced by name (not value) so the wire bytes asserted
    /// below are still meaningful if the test cert gets regenerated.
    fn sample_pubkey() -> Vec<u8> {
        vec![
            0x04, 0xca, 0x9f, 0xdb, 0x5a, 0xba, 0x25, 0xed, 0x11, 0x90, 0x69, 0x07, 0xd2, 0x68,
            0xc8, 0x11, 0x40, 0x68, 0x12, 0x04, 0xd5, 0x7c, 0x3e, 0xee, 0x8c, 0xe8, 0x99, 0x7b,
            0x8d, 0x82, 0xcd, 0x95, 0x73, 0x10, 0xdc, 0xd6, 0xdc, 0xde, 0xb5, 0x37, 0xe9, 0xfe,
            0xed, 0x7a, 0x2a, 0xca, 0xb6, 0xdb, 0x29, 0x95, 0x96, 0x15, 0xa7, 0x4d, 0x03, 0x82,
            0xef, 0x70, 0x0f, 0xfa, 0xe3, 0x19, 0xa7, 0x7a, 0xe0,
        ]
    }

    /// `key_exchange` after `new_ecdhe`: 3 ECParams + 1 pub_len + 65 pub = 69 bytes.
    const ECDHE_BODY_LEN: usize = 3 + 1 + 65;

    fn make_ecdhe_cke() -> TlcpClientKeyExchange {
        TlcpClientKeyExchange::new_ecdhe(sample_pubkey())
    }

    // -----------------------------------------------------------------
    // Default mode (GmSSL-compatible): uint16 prefix is emitted/expected
    // -----------------------------------------------------------------

    #[cfg(not(feature = "tlcp-strict"))]
    #[test]
    fn default_to_bytes_emits_uint16_length_prefix() {
        let cke = make_ecdhe_cke();
        let bytes = cke.to_bytes();
        // HS header: 4 bytes. After that: uint16 payload_len = 69.
        assert_eq!(bytes.len(), 4 + 2 + ECDHE_BODY_LEN);
        assert_eq!(bytes[0], HandshakeType::ClientKeyExchange as u8);
        let hs_len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        assert_eq!(hs_len, 2 + ECDHE_BODY_LEN, "HS length covers uint16 + body");
        // uint16 prefix
        assert_eq!(&bytes[4..6], &(ECDHE_BODY_LEN as u16).to_be_bytes());
        // body starts at offset 6
        assert_eq!(&bytes[6..6 + ECDHE_BODY_LEN], &cke.key_exchange[..]);
    }

    #[cfg(not(feature = "tlcp-strict"))]
    #[test]
    fn default_from_body_roundtrip() {
        let cke = make_ecdhe_cke();
        let bytes = cke.to_bytes();
        let parsed = TlcpClientKeyExchange::from_body(&bytes[4..]).unwrap();
        assert_eq!(parsed.key_exchange, cke.key_exchange);
    }

    #[cfg(not(feature = "tlcp-strict"))]
    #[test]
    fn default_from_body_rejects_truncated_input() {
        // Need at least 2 bytes for the uint16 prefix.
        assert!(TlcpClientKeyExchange::from_body(&[]).is_err());
        assert!(TlcpClientKeyExchange::from_body(&[0x00]).is_err());
        // uint16 says 100 bytes follow, but we only provide 2.
        let mut body = vec![0x00, 0x64];
        body.resize(2 + 50, 0xAA);
        assert!(TlcpClientKeyExchange::from_body(&body).is_err());
    }

    // -----------------------------------------------------------------
    // Strict mode (GB/T 38636-2020): NO uint16 prefix
    // -----------------------------------------------------------------

    #[cfg(feature = "tlcp-strict")]
    #[test]
    fn strict_to_bytes_emits_no_uint16_prefix() {
        let cke = make_ecdhe_cke();
        let bytes = cke.to_bytes();
        // Total: 4-byte HS header + body (no 2-byte prefix).
        assert_eq!(bytes.len(), 4 + ECDHE_BODY_LEN);
        assert_eq!(bytes[0], HandshakeType::ClientKeyExchange as u8);
        let hs_len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        assert_eq!(
            hs_len, ECDHE_BODY_LEN,
            "HS length covers body only (no uint16 prefix)"
        );
        // body starts right after the HS header
        assert_eq!(&bytes[4..4 + ECDHE_BODY_LEN], &cke.key_exchange[..]);
    }

    #[cfg(feature = "tlcp-strict")]
    #[test]
    fn strict_from_body_roundtrip() {
        let cke = make_ecdhe_cke();
        let bytes = cke.to_bytes();
        let parsed = TlcpClientKeyExchange::from_body(&bytes[4..]).unwrap();
        assert_eq!(parsed.key_exchange, cke.key_exchange);
    }

    #[cfg(feature = "tlcp-strict")]
    #[test]
    fn strict_from_body_accepts_standard_conformant_peer_wire() {
        // Simulate a peer that follows RFC 5246 §7.4.7 exactly: body is
        // the raw ClientECDHParams, no uint16 prefix.
        let mut body = vec![0x03, 0x00, 0x29, 65]; // ECParams + pub_len
        body.extend_from_slice(&sample_pubkey());
        assert_eq!(body.len(), ECDHE_BODY_LEN);
        let parsed = TlcpClientKeyExchange::from_body(&body).unwrap();
        assert_eq!(parsed.key_exchange, body);
    }
}
