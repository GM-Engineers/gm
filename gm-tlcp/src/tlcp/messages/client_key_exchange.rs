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
//!   /* spec-default mode:
//!    * body = opaque body[length]
//!    * (no overall length prefix; the 24-bit HS length field covers it) */
//!   opaque body[length]
//!   /* GmSSL-master shim (--features tlcp-gmssl-compat):
//!    * body = uint16 payload_length || opaque payload[payload_length]
//!    * (matches GmSSL 2026-06+ master `tls_uint16array_to_bytes` format) */
//!   uint16      payload_length
//!   opaque      payload[payload_length]
//! ```
//!
//! `payload` (or `body`, in spec mode) is either the ECParameters-wrapped
//! ephemeral public key (ECDHE) or the encrypted pre-master secret (ECC).

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;
use crate::tlcp::constants::TLCP_ECH_PARAMS_PREFIX;

/// TLCP ClientKeyExchange body — GB/T 38636-2020 §6.4.1.6
///
/// Two variants, one per cipher-suite family:
///
/// - `Ecdhe { ephemeral_public }` for ECDHE suites (E011 / E051).
///   The wire body is the standard RFC 4492 ECParameters blob
///   (`curve_type || named_curve || pub_len || pub`).
/// - `Ecc { ciphertext }` for static-ECC suites (E013 / E053).
///   The wire body is the SM2-encrypted pre-master secret
///   (`ECCEncryptedPreMasterSecret` per §6.4.5.8 c)).
///
/// The server distinguishes the two by the negotiated suite
/// (`is_ecc_mode` from `ServerHello.cipher_suite`), since the
/// GmSSL-master shim's uint16 prefix wraps either form and
/// prefix-only auto-detection is unreliable under
/// `--features tlcp-gmssl-compat`.
#[derive(Debug, Clone)]
pub enum ClientKeyExchangeBody {
    /// ECDHE body for ECDHE suites (E011 / E051).
    /// Contains the client's ephemeral SM2 public key, already
    /// wrapped in the RFC 4492 ECParameters envelope on the wire.
    Ecdhe {
        /// Full ECParameters envelope (`ECParameters || pub_len || pub`).
        ephemeral_public: Vec<u8>,
    },
    /// Static-ECC body for E013 / E053.
    /// Contains the SM2-encrypted pre-master secret ciphertext
    /// (`ECCEncryptedPreMasterSecret`, DER-encoded SM2Cipher by
    /// default; auto-detection in `Sm2Decryptor::decrypt` handles
    /// raw and versioned forms too).
    Ecc { ciphertext: Vec<u8> },
}

/// TLCP ClientKeyExchange message (GB/T 38636-2020 §6.4.1.6).
///
/// Wraps the variant chosen by the negotiated cipher suite. R-3
/// (gm-tlcp 0.4.0) restructured this from a single `key_exchange: Vec<u8>`
/// field into an enum-backed struct so the server's static-ECC
/// PMS-decrypt path can safely borrow the inner ciphertext via
/// `as_ecc_ciphertext()` without having to re-parse the wire body.
#[derive(Debug, Clone)]
pub struct TlcpClientKeyExchange {
    /// Variant body of the ClientKeyExchange, chosen by suite type.
    pub body: ClientKeyExchangeBody,
}

impl TlcpClientKeyExchange {
    /// Create a ClientKeyExchange wrapping an ECDHE ephemeral public key.
    ///
    /// `ephemeral_public` is the raw 65-byte uncompressed SM2 SEC1
    /// public key. This constructor wraps it in the RFC 4492
    /// `ECParameters` envelope (sm2p256v1 curve) on the wire.
    pub fn new_ecdhe(ephemeral_public: Vec<u8>) -> Self {
        let mut wrapped =
            Vec::with_capacity(TLCP_ECH_PARAMS_PREFIX.len() + 1 + ephemeral_public.len());
        wrapped.extend_from_slice(&TLCP_ECH_PARAMS_PREFIX);
        wrapped.push(ephemeral_public.len() as u8);
        wrapped.extend_from_slice(&ephemeral_public);
        Self {
            body: ClientKeyExchangeBody::Ecdhe {
                ephemeral_public: wrapped,
            },
        }
    }

    /// Create a ClientKeyExchange wrapping the SM2-encrypted
    /// pre-master secret ciphertext (static-ECC suites).
    pub fn new_ecc(encrypted_pms: Vec<u8>) -> Self {
        Self {
            body: ClientKeyExchangeBody::Ecc {
                ciphertext: encrypted_pms,
            },
        }
    }

    /// Borrow the inner ECDHE body (the ECParameters-wrapped
    /// ephemeral public key), or `None` if this is an ECC body.
    ///
    /// Note: returns the full wire envelope, NOT the raw 65-byte
    /// SEC1 point. For the raw point, see [`Self::ecdhe_public_key`].
    pub fn as_ecdhe_wire_body(&self) -> Option<&[u8]> {
        match &self.body {
            ClientKeyExchangeBody::Ecdhe { ephemeral_public } => Some(ephemeral_public),
            ClientKeyExchangeBody::Ecc { .. } => None,
        }
    }

    /// Borrow the inner ECC body (SM2-encrypted PMS ciphertext),
    /// or `None` if this is an ECDHE body.
    ///
    /// Used by the server-side static-ECC PMS-decrypt path
    /// (R-3, audit C-4).
    pub fn as_ecc_ciphertext(&self) -> Option<&[u8]> {
        match &self.body {
            ClientKeyExchangeBody::Ecc { ciphertext } => Some(ciphertext),
            ClientKeyExchangeBody::Ecdhe { .. } => None,
        }
    }

    /// For ECDHE mode, extract the raw 65-byte SM2 SEC1 public key
    /// from the ECParameters-wrapped body. Returns `None` if the
    /// payload is not a valid sm2p256v1 ECParameters blob or if
    /// this is an ECC body.
    pub fn ecdhe_public_key(&self) -> Option<&[u8]> {
        let envelope = self.as_ecdhe_wire_body()?;
        let prefix_len = TLCP_ECH_PARAMS_PREFIX.len();
        if envelope.len() < prefix_len + 1 {
            return None;
        }
        if envelope[..prefix_len] != TLCP_ECH_PARAMS_PREFIX {
            return None;
        }
        let pub_len = envelope[prefix_len] as usize;
        let point_offset = prefix_len + 1;
        if envelope.len() != point_offset + pub_len {
            return None;
        }
        Some(&envelope[point_offset..point_offset + pub_len])
    }

    /// Serialize to TLS handshake message bytes
    /// (`type=0x10 || 24-bit length || body`).
    ///
    /// Spec-default mode emits the body without any length prefix;
    /// the 24-bit HS length field above the body is the only
    /// framing (RFC 5246 §7.4.7 / GB/T 38636-2020 §6.4.1.6).
    ///
    /// GmSSL-master shim (`--features tlcp-gmssl-compat`) adds a
    /// redundant `uint16` length prefix to match GmSSL 2026-06+
    /// master's `tls_uint16array_to_bytes` format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = match &self.body {
            ClientKeyExchangeBody::Ecdhe { ephemeral_public } => ephemeral_public.len(),
            ClientKeyExchangeBody::Ecc { ciphertext } => ciphertext.len(),
        };
        // Pre-allocate for the worst case (GmSSL shim: 4-byte HS
        // header + 2-byte uint16 + body). Spec mode wastes 2 bytes
        // of capacity.
        let mut buf = Vec::with_capacity(4 + 2 + payload_len);
        buf.push(HandshakeType::ClientKeyExchange as u8);

        #[cfg(feature = "tlcp-gmssl-compat")]
        let body_len: usize = 2 + payload_len;
        #[cfg(not(feature = "tlcp-gmssl-compat"))]
        let body_len: usize = payload_len;

        buf.push((body_len >> 16) as u8);
        buf.push((body_len >> 8) as u8);
        buf.push(body_len as u8);

        #[cfg(feature = "tlcp-gmssl-compat")]
        {
            // 16-bit payload length prefix (matches GmSSL 2026-06+
            // tls_uint16array_to_bytes format). The previous version of
            // this code used a 1-byte length prefix which was non-standard
            // and rejected by GmSSL master.
            buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
        }
        // spec-default mode: no uint16 prefix; the HS header's
        // 24-bit length field is the only framing.
        match &self.body {
            ClientKeyExchangeBody::Ecdhe { ephemeral_public } => {
                buf.extend_from_slice(ephemeral_public);
            }
            ClientKeyExchangeBody::Ecc { ciphertext } => {
                buf.extend_from_slice(ciphertext);
            }
        }
        buf
    }

    /// Deserialize from the body of a handshake message (after the
    /// 4-byte `type || 24-bit length` prefix has already been
    /// stripped).
    ///
    /// **Caller must pass `is_ecc_mode`** based on the negotiated
    /// cipher suite: this is required because the GmSSL-master
    /// shim's `uint16` length prefix wraps both ECDHE and ECC
    /// bodies, so wire-prefix auto-detection is unreliable under
    /// `--features tlcp-gmssl-compat`.
    ///
    /// GmSSL-master shim: body is `uint16 payload_length || payload`.
    /// Spec-default mode: body is the raw ECDH params / encrypted
    /// PMS — no uint16 prefix.
    pub fn from_body(body: &[u8], is_ecc_mode: bool) -> Result<Self, TlcpError> {
        // The variant is chosen by the negotiated suite (is_ecc_mode).
        // The wire framing differs by feature flag:
        //   * `tlcp-gmssl-compat`: body = uint16 payload_len || payload
        //     (the GmSSL master `tls_uint16array_to_bytes` format
        //     wraps BOTH ECDHE and ECC variants).
        //   * spec-default: body is the raw payload (no prefix);
        //     the 24-bit HS length field above this body is the
        //     only framing.
        //
        // Note: prefix stripping is gated ONLY by the feature flag,
        // NOT by `is_ecc_mode`. Both variants share the same
        // framing semantics; `is_ecc_mode` only selects which
        // variant the payload is stored under.
        #[cfg(feature = "tlcp-gmssl-compat")]
        let payload = {
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
            body[2..2 + payload_len].to_vec()
        };
        #[cfg(not(feature = "tlcp-gmssl-compat"))]
        let payload = {
            // Spec-default: body is the raw ECDH params or encrypted
            // PMS, exactly as it sits in the HS body. The 24-bit HS
            // length field above this body already covered the framing.
            body.to_vec()
        };

        Ok(if is_ecc_mode {
            Self {
                body: ClientKeyExchangeBody::Ecc {
                    ciphertext: payload,
                },
            }
        } else {
            Self {
                body: ClientKeyExchangeBody::Ecdhe {
                    ephemeral_public: payload,
                },
            }
        })
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

    /// `ephemeral_public` after `new_ecdhe`: 3 ECParams + 1 pub_len + 65 pub = 69 bytes.
    const ECDHE_BODY_LEN: usize = 3 + 1 + 65;

    fn make_ecdhe_cke() -> TlcpClientKeyExchange {
        TlcpClientKeyExchange::new_ecdhe(sample_pubkey())
    }

    // -----------------------------------------------------------------
    // GmSSL-master shim (--features tlcp-gmssl-compat): uint16 prefix
    // -----------------------------------------------------------------

    #[cfg(feature = "tlcp-gmssl-compat")]
    #[test]
    fn gmssl_compat_to_bytes_emits_uint16_length_prefix() {
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
        let envelope = cke.as_ecdhe_wire_body().expect("ECDHE variant");
        assert_eq!(&bytes[6..6 + ECDHE_BODY_LEN], envelope);
    }

    #[cfg(feature = "tlcp-gmssl-compat")]
    #[test]
    fn gmssl_compat_from_body_roundtrip() {
        let cke = make_ecdhe_cke();
        let bytes = cke.to_bytes();
        let parsed = TlcpClientKeyExchange::from_body(&bytes[4..], false).unwrap();
        let parsed_env = parsed.as_ecdhe_wire_body().expect("ECDHE variant");
        assert_eq!(parsed_env, cke.as_ecdhe_wire_body().unwrap());
    }

    #[cfg(feature = "tlcp-gmssl-compat")]
    #[test]
    fn gmssl_compat_from_body_rejects_truncated_input() {
        // Need at least 2 bytes for the uint16 prefix.
        assert!(TlcpClientKeyExchange::from_body(&[], false).is_err());
        assert!(TlcpClientKeyExchange::from_body(&[0x00], false).is_err());
        // uint16 says 100 bytes follow, but we only provide 2.
        let mut body = vec![0x00, 0x64];
        body.resize(2 + 50, 0xAA);
        assert!(TlcpClientKeyExchange::from_body(&body, false).is_err());
    }

    // -----------------------------------------------------------------
    // Spec-default (GB/T 38636-2020): NO uint16 prefix
    // -----------------------------------------------------------------

    #[cfg(not(feature = "tlcp-gmssl-compat"))]
    #[test]
    fn spec_default_to_bytes_emits_no_uint16_prefix() {
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
        let envelope = cke.as_ecdhe_wire_body().expect("ECDHE variant");
        assert_eq!(&bytes[4..4 + ECDHE_BODY_LEN], envelope);
    }

    #[cfg(not(feature = "tlcp-gmssl-compat"))]
    #[test]
    fn spec_default_from_body_roundtrip() {
        let cke = make_ecdhe_cke();
        let bytes = cke.to_bytes();
        let parsed = TlcpClientKeyExchange::from_body(&bytes[4..], false).unwrap();
        let parsed_env = parsed.as_ecdhe_wire_body().expect("ECDHE variant");
        assert_eq!(parsed_env, cke.as_ecdhe_wire_body().unwrap());
    }

    #[cfg(not(feature = "tlcp-gmssl-compat"))]
    #[test]
    fn spec_default_from_body_accepts_standard_conformant_peer_wire() {
        // Simulate a peer that follows RFC 5246 §7.4.7 exactly: body is
        // the raw ClientECDHParams, no uint16 prefix.
        let mut body = vec![0x03, 0x00, 0x29, 65]; // ECParams + pub_len
        body.extend_from_slice(&sample_pubkey());
        assert_eq!(body.len(), ECDHE_BODY_LEN);
        let parsed = TlcpClientKeyExchange::from_body(&body, false).unwrap();
        assert_eq!(parsed.as_ecdhe_wire_body().unwrap(), body.as_slice());
    }

    // -----------------------------------------------------------------
    // R-3: ECC variant (static-ECC suites E013 / E053)
    // -----------------------------------------------------------------

    /// Helper: 100-byte dummy ciphertext stand-in (the actual bytes
    /// don't matter for the wire-layout tests — those test format,
    /// not SM2 semantics).
    fn sample_ecc_ciphertext() -> Vec<u8> {
        (0u8..100).collect()
    }

    #[test]
    fn cke_ecc_ciphertext_returns_bytes_for_ecc_body() {
        let cke = TlcpClientKeyExchange::new_ecc(sample_ecc_ciphertext());
        let ciphertext = cke.as_ecc_ciphertext().expect("Ecc variant");
        assert_eq!(ciphertext, sample_ecc_ciphertext().as_slice());
        assert!(cke.as_ecdhe_wire_body().is_none());
        assert!(cke.ecdhe_public_key().is_none());
    }

    #[test]
    fn cke_ecc_ciphertext_returns_none_for_ecdhe_body() {
        let cke = make_ecdhe_cke();
        assert!(cke.as_ecc_ciphertext().is_none());
        // ECDHE helper should still work.
        assert!(cke.as_ecdhe_wire_body().is_some());
        assert_eq!(cke.ecdhe_public_key().unwrap(), sample_pubkey().as_slice());
    }

    #[cfg(not(feature = "tlcp-gmssl-compat"))]
    #[test]
    fn cke_ecc_roundtrip_via_enum_body() {
        // Spec-default roundtrip: HS header (4B) + body (no prefix).
        let cke = TlcpClientKeyExchange::new_ecc(sample_ecc_ciphertext());
        let bytes = cke.to_bytes();
        assert_eq!(bytes[0], HandshakeType::ClientKeyExchange as u8);
        let hs_len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        assert_eq!(
            hs_len,
            sample_ecc_ciphertext().len(),
            "HS length covers ciphertext only"
        );
        assert_eq!(bytes.len(), 4 + sample_ecc_ciphertext().len());
        let parsed = TlcpClientKeyExchange::from_body(&bytes[4..], true).unwrap();
        let parsed_ct = parsed.as_ecc_ciphertext().expect("Ecc variant");
        assert_eq!(parsed_ct, sample_ecc_ciphertext().as_slice());
        assert!(parsed.as_ecdhe_wire_body().is_none());
    }

    #[cfg(feature = "tlcp-gmssl-compat")]
    #[test]
    fn cke_ecc_roundtrip_via_enum_body() {
        // GmSSL-master shim: HS header (4B) + uint16 payload_len + ciphertext.
        let cke = TlcpClientKeyExchange::new_ecc(sample_ecc_ciphertext());
        let bytes = cke.to_bytes();
        assert_eq!(bytes[0], HandshakeType::ClientKeyExchange as u8);
        let hs_len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        assert_eq!(
            hs_len,
            2 + sample_ecc_ciphertext().len(),
            "HS length covers uint16 prefix + ciphertext"
        );
        assert_eq!(
            &bytes[4..6],
            &(sample_ecc_ciphertext().len() as u16).to_be_bytes()
        );
        let parsed = TlcpClientKeyExchange::from_body(&bytes[4..], true).unwrap();
        let parsed_ct = parsed.as_ecc_ciphertext().expect("Ecc variant");
        assert_eq!(parsed_ct, sample_ecc_ciphertext().as_slice());
    }

    #[test]
    fn from_body_rejects_wrong_is_ecc_mode_flag() {
        // Build a CKE, then parse it with the wrong is_ecc_mode flag.
        // We can't easily "fail" the parsing — the parser will happily
        // store the body under whichever variant the flag selects —
        // but the helpers should then disagree with each other.
        let cke_ecdhe = make_ecdhe_cke();
        let bytes = cke_ecdhe.to_bytes();
        // Pass is_ecc_mode=true even though it's an ECDHE wire body.
        let parsed = TlcpClientKeyExchange::from_body(&bytes[4..], true).unwrap();
        assert!(parsed.as_ecc_ciphertext().is_some(), "stored under Ecc");
        assert!(parsed.as_ecdhe_wire_body().is_none());
        assert!(parsed.ecdhe_public_key().is_none());
        // And the other way:
        let cke_ecc = TlcpClientKeyExchange::new_ecc(sample_ecc_ciphertext());
        let bytes_ecc = cke_ecc.to_bytes();
        let parsed2 = TlcpClientKeyExchange::from_body(&bytes_ecc[4..], false).unwrap();
        assert!(parsed2.as_ecdhe_wire_body().is_some(), "stored under Ecdhe");
        assert!(parsed2.as_ecc_ciphertext().is_none());
        // The "ECParameters envelope" parse will likely fail because the
        // body bytes don't match the sm2p256v1 prefix.
        assert!(parsed2.ecdhe_public_key().is_none());
    }
}
