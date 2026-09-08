//! ECDHE parameters + ServerKeyExchange message.
//!
//! `Sm2EcdheParams` is the wire-format ECDH parameters block
//! `[ECParameters | ECPoint | signature]` that appears in the
//! `ServerKeyExchange` for ECDHE suites (E011 / E051).
//!
//! `TlcpServerKeyExchange` wraps either the ECDHE body or a
//! sig-only static-ECC body (GB/T 38636-2020 §6.4.5.4
//! interpretation-B, used by openHiTLS / Tongsuo for E013 / E053).
//! The 4-byte handshake header is identical in both cases
//! (`[type=0x0C | length(3)])`).

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;
use crate::tlcp::constants::TLCP_ECH_PARAMS_PREFIX;
use gm_crypto::sm2::{Sm2EcdhKeypair, Sm2Signer, Sm2Verifier};

/// SM2 ECDHE parameters for TLCP key exchange
#[derive(Debug, Clone)]
pub struct Sm2EcdheParams {
    /// Ephemeral SM2 public key (uncompressed, 65 bytes: 04 || x || y)
    pub ephemeral_public: Vec<u8>,
    /// SM2 signature over the key exchange parameters
    pub signature: Vec<u8>,
}

impl Sm2EcdheParams {
    /// Create new ECDHE parameters from a generated key
    pub fn new(ephemeral_public: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            ephemeral_public,
            signature,
        }
    }

    /// Serialize as ServerKeyExchange body.
    ///
    /// Wire layout (TLCP / GB/T 38636-2020 §6.4.1.5 + RFC 4492):
    ///
    /// ```text
    ///   ECParameters {
    ///       curve_type   = 0x03  (named_curve, 1 byte)
    ///       named_curve  = 0x0029 (sm2p256v1,   2 bytes)
    ///   }
    ///   ECPoint {
    ///       point_length = N      (1 byte)
    ///       point        = N bytes (uncompressed SM2 public key)
    ///   }
    ///   uint16 signature_length
    ///   opaque signature[signature_length]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // ECParameters prefix (curve_type + named_curve). TLCP only
        // defines one curve (sm2p256v1) so this is constant.
        buf.extend_from_slice(&TLCP_ECH_PARAMS_PREFIX);
        // ECPoint: 1-byte length + point bytes.
        buf.push(self.ephemeral_public.len() as u8);
        buf.extend_from_slice(&self.ephemeral_public);
        // Signature: 2-byte length + signature bytes.
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Deserialize from ServerKeyExchange body bytes.
    ///
    /// See [`Self::to_bytes`] for the layout. We deliberately reject
    /// any `curve_type` other than `named_curve` and any `named_curve`
    /// other than `sm2p256v1` — TLCP only ships the one curve and a
    /// malformed record would be a downgrade or a fuzz attempt.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlcpError> {
        // ECParameters (curve_type + named_curve) = 3 bytes minimum.
        if data.len() < TLCP_ECH_PARAMS_PREFIX.len() + 1 + 2 {
            return Err(TlcpError::InvalidMessage(format!(
                "ECDHE params too short: {} bytes, need at least {}",
                data.len(),
                TLCP_ECH_PARAMS_PREFIX.len() + 1 + 2
            )));
        }
        if data[..TLCP_ECH_PARAMS_PREFIX.len()] != TLCP_ECH_PARAMS_PREFIX {
            return Err(TlcpError::InvalidMessage(format!(
                "ECDHE params have wrong ECParameters prefix: got {:02X?}, want {:02X?}",
                &data[..TLCP_ECH_PARAMS_PREFIX.len()],
                TLCP_ECH_PARAMS_PREFIX
            )));
        }
        let params_offset = TLCP_ECH_PARAMS_PREFIX.len();
        let pub_len = data[params_offset] as usize;
        if data.len() < params_offset + 1 + pub_len + 2 {
            return Err(TlcpError::InvalidMessage(format!(
                "ECDHE params too short: {} bytes, need at least {}",
                data.len(),
                params_offset + 1 + pub_len + 2
            )));
        }
        let ephemeral_public = data[params_offset + 1..params_offset + 1 + pub_len].to_vec();
        let sig_len_offset = params_offset + 1 + pub_len;
        let sig_len = u16::from_be_bytes([data[sig_len_offset], data[sig_len_offset + 1]]) as usize;
        if data.len() < sig_len_offset + 2 + sig_len {
            return Err(TlcpError::InvalidMessage(format!(
                "ECDHE signature too short: {} bytes, need {}",
                data.len() - sig_len_offset - 2,
                sig_len
            )));
        }
        let signature = data[sig_len_offset + 2..sig_len_offset + 2 + sig_len].to_vec();
        Ok(Self {
            ephemeral_public,
            signature,
        })
    }
}

/// TLCP ServerKeyExchange body — GB/T 38636-2020 §6.4.5.4
///
/// Two variants are defined for the four SM2 cipher suites:
///
/// - `Ecdhe(...)` for ECDHE suites (E011 / E051). Body is the standard
///   RFC 4492 ECParameters blob (`curve_type || named_curve ||
///   pub_len || pub || sig_len || sig`), signed over
///   `client_random || server_random || server_ecdh_params`.
///
/// - `Ecc { signature }` for static-ECC suites (E013 / E053) per the
///   spec's interpretation-B reading. Body is just `sig_len || sig`,
///   signed over `client_random || server_random ||
///   (3-byte big-endian enc_cert_len) || enc_cert_der`. This is what
///   openHiTLS and Tongsuo 8.3.0 emit on the wire.
///
/// Note: GmSSL master 2026-06+ emits the **ECDHE-style** body for
/// static-ECC too (interpretation-C). For GmSSL-master interop on
/// static-ECC suites, the gm-tlcp client must be built with
/// `--features tlcp-gmssl-compat`; otherwise it expects the
/// interpretation-B body.
#[derive(Debug, Clone)]
pub enum ServerKeyExchangeBody {
    /// ECDHE body for ECDHE suites (E011 / E051).
    Ecdhe(Sm2EcdheParams),
    /// Sig-only body for static-ECC suites (E013 / E053, interpretation B).
    Ecc {
        /// SM2 signature over `cr ∥ sr ∥ enc_cert_header ∥ enc_cert`
        /// (DER-encoded, ≤ 65535 bytes)
        signature: Vec<u8>,
    },
}

/// TLCP ServerKeyExchange message (GB/T 38636-2020 §6.4.1.5)
///
/// Sent by the server during the handshake. The variant of `body`
/// depends on the negotiated cipher suite:
///
/// - **ECDHE (E011 / E051)**: `body = Ecdhe(Sm2EcdheParams)`,
///   signature covers `client_random || server_random || server_ecdh_params`.
///
/// - **Static-ECC (E013 / E053), interpretation B** (default in
///   gm-tlcp ≥ 0.3.1; openHiTLS / Tongsuo): `body = Ecc { signature }`,
///   signature covers `client_random || server_random ||
///   (3-byte big-endian len(enc_cert_der)) || enc_cert_der`.
#[derive(Debug, Clone)]
pub struct TlcpServerKeyExchange {
    /// Body of the ServerKeyExchange message, variant depends on suite type.
    pub body: ServerKeyExchangeBody,
}

impl TlcpServerKeyExchange {
    /// Create a new ServerKeyExchange wrapping ECDHE parameters.
    pub fn new(ecdhe_params: Sm2EcdheParams) -> Self {
        Self {
            body: ServerKeyExchangeBody::Ecdhe(ecdhe_params),
        }
    }

    /// Create a new ServerKeyExchange wrapping a sig-only ECC body.
    pub fn new_ecc(signature: Vec<u8>) -> Self {
        Self {
            body: ServerKeyExchangeBody::Ecc { signature },
        }
    }

    /// Borrow the inner ECDHE parameters, or `None` if this is an ECC body.
    pub fn as_ecdhe(&self) -> Option<&Sm2EcdheParams> {
        match &self.body {
            ServerKeyExchangeBody::Ecdhe(p) => Some(p),
            ServerKeyExchangeBody::Ecc { .. } => None,
        }
    }

    /// Borrow the inner ECC signature, or `None` if this is an ECDHE body.
    pub fn as_ecc_signature(&self) -> Option<&[u8]> {
        match &self.body {
            ServerKeyExchangeBody::Ecc { signature } => Some(signature),
            ServerKeyExchangeBody::Ecdhe(_) => None,
        }
    }

    /// Create an ECDHE ServerKeyExchange by generating an ephemeral
    /// keypair and signing.
    ///
    /// The signature covers: `client_random || server_random || server_ecdh_params`,
    /// where `server_ecdh_params` is the full RFC 4492 ECParameters blob
    /// (`[curve_type=3][named_curve=0x0029][pub_len][pub]`) that this
    /// message will send on the wire. GmSSL 2026-06+ master signs over
    /// this exact byte range — signing over only the raw 65-byte public
    /// key (as we did before) produces a signature that no peer will
    /// accept.
    pub fn generate(
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        sign_key: &Sm2Signer,
    ) -> Result<(Self, Sm2EcdhKeypair), TlcpError> {
        let ephemeral_kp = Sm2EcdhKeypair::generate()
            .map_err(|e| TlcpError::HandshakeFailed(format!("ECDHE keygen failed: {:?}", e)))?;
        let ephemeral_pub = ephemeral_kp.public_key_bytes();

        // Sign over the *wire-format* ECDH params (ECParameters-wrapped
        // blob), not the raw 65-byte pub key, because that's what
        // GmSSL 2026-06+ master and every other standards-compliant
        // peer signs over.
        let mut to_sign =
            Vec::with_capacity(32 + 32 + TLCP_ECH_PARAMS_PREFIX.len() + 1 + ephemeral_pub.len());
        to_sign.extend_from_slice(client_random);
        to_sign.extend_from_slice(server_random);
        to_sign.extend_from_slice(&TLCP_ECH_PARAMS_PREFIX);
        to_sign.push(ephemeral_pub.len() as u8);
        to_sign.extend_from_slice(&ephemeral_pub);

        let signature = sign_key
            .sign(&to_sign)
            .map_err(|e| TlcpError::HandshakeFailed(format!("SKE sign failed: {:?}", e)))?;

        Ok((
            Self {
                body: ServerKeyExchangeBody::Ecdhe(Sm2EcdheParams::new(ephemeral_pub, signature)),
            },
            ephemeral_kp,
        ))
    }

    /// Create a sig-only static-ECC ServerKeyExchange by signing
    /// `client_random || server_random || (3B enc_cert_len_be) || enc_cert_der`
    /// under the server's signing certificate private key.
    ///
    /// This is the GB/T 38636-2020 §6.4.5.4 interpretation-B reading
    /// of the static-ECC branch — what openHiTLS and Tongsuo 8.3.0
    /// emit on the wire for E013 / E053.
    ///
    /// The SM2 signature is encoded in DER (ASN.1) form on the wire,
    /// matching the openHiTLS / Tongsuo convention and the format
    /// accepted by [`crate::tlcp::crypto::verify::verify_ske_signature`]
    /// when `is_ecc_mode = true`.
    ///
    /// # Arguments
    /// * `client_random` — 32-byte client random
    /// * `server_random` — 32-byte server random
    /// * `enc_cert_der` — DER bytes of the server's encryption certificate
    /// * `sign_key` — SM2 signer bound to the server's signing cert
    pub fn generate_ecc(
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        enc_cert_der: &[u8],
        sign_key: &Sm2Signer,
    ) -> Result<Self, TlcpError> {
        if enc_cert_der.len() > 0xFFFFFF {
            return Err(TlcpError::HandshakeFailed(format!(
                "enc_cert_der too long for static-ECC SKE: {} bytes (max 16777215)",
                enc_cert_der.len()
            )));
        }
        // Sign over `cr || sr || enc_cert_header || enc_cert`
        //   where enc_cert_header = 3-byte big-endian len(enc_cert_der)
        let mut to_sign = Vec::with_capacity(32 + 32 + 3 + enc_cert_der.len());
        to_sign.extend_from_slice(client_random);
        to_sign.extend_from_slice(server_random);
        let cert_len = enc_cert_der.len() as u32;
        to_sign.push((cert_len >> 16) as u8);
        to_sign.push((cert_len >> 8) as u8);
        to_sign.push(cert_len as u8);
        to_sign.extend_from_slice(enc_cert_der);

        let raw_signature = sign_key
            .sign(&to_sign)
            .map_err(|e| TlcpError::HandshakeFailed(format!("ECC SKE sign failed: {:?}", e)))?;
        // Convert raw r||s (64 bytes) to DER (ASN.1) for wire compatibility
        // with openHiTLS / Tongsuo 8.3.0, which both emit DER on the wire.
        let raw_arr: [u8; 64] = raw_signature
            .as_slice()
            .try_into()
            .map_err(|_| TlcpError::HandshakeFailed("ECC SKE raw sig not 64 bytes".to_string()))?;
        let signature = gm_crypto::sm2::sm2_signature_raw_to_der(&raw_arr);

        Ok(Self {
            body: ServerKeyExchangeBody::Ecc { signature },
        })
    }

    /// Verify the server's signature on the ECDHE-flavored ServerKeyExchange.
    ///
    /// Signed data: `client_random || server_random || server_ecdh_params`,
    /// where `server_ecdh_params` is the full ECParameters-wrapped
    /// blob on the wire (see [`Sm2EcdheParams::to_bytes`]).
    ///
    /// Returns `Err(InvalidMessage)` if the body is not the ECDHE variant.
    pub fn verify_signature(
        &self,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        verifier: &Sm2Verifier,
    ) -> Result<(), TlcpError> {
        let params = self.as_ecdhe().ok_or_else(|| {
            TlcpError::InvalidMessage(
                "verify_signature called on non-ECDHE ServerKeyExchange".to_string(),
            )
        })?;
        // Reconstruct the exact ECParameters wire bytes the server
        // emitted by serializing our parsed fields through the same
        // `Sm2EcdheParams::to_bytes` path (with the signature zeroed
        // out, since the signer covers only the prefix + pub key).
        let mut signed_data = Vec::with_capacity(
            32 + 32 + TLCP_ECH_PARAMS_PREFIX.len() + 1 + params.ephemeral_public.len(),
        );
        signed_data.extend_from_slice(client_random);
        signed_data.extend_from_slice(server_random);
        signed_data.extend_from_slice(&TLCP_ECH_PARAMS_PREFIX);
        signed_data.push(params.ephemeral_public.len() as u8);
        signed_data.extend_from_slice(&params.ephemeral_public);

        verifier
            .verify(&signed_data, &params.signature)
            .map_err(|e| TlcpError::HandshakeFailed(format!("SKE signature verify failed: {}", e)))
    }

    /// Serialize the ServerKeyExchange body to wire bytes (the body
    /// portion only — does not include the 4-byte handshake header).
    ///
    /// - Ecdhe: `Sm2EcdheParams::to_bytes()` (full ECParameters blob).
    /// - Ecc:   `uint16 sig_len || sig_der` (interpretation B).
    fn body_to_bytes(&self) -> Vec<u8> {
        match &self.body {
            ServerKeyExchangeBody::Ecdhe(p) => p.to_bytes(),
            ServerKeyExchangeBody::Ecc { signature } => {
                let mut buf = Vec::with_capacity(2 + signature.len());
                buf.extend_from_slice(&(signature.len() as u16).to_be_bytes());
                buf.extend_from_slice(signature);
                buf
            }
        }
    }

    /// Serialize to the full TLS record bytes (4-byte handshake header + body).
    pub fn to_bytes(&self) -> Vec<u8> {
        let body = self.body_to_bytes();
        let mut buf = Vec::with_capacity(4 + body.len());
        buf.push(HandshakeType::ServerKeyExchange as u8);
        buf.push((body.len() >> 16) as u8);
        buf.push((body.len() >> 8) as u8);
        buf.push(body.len() as u8);
        buf.extend_from_slice(&body);
        buf
    }

    /// Deserialize from a ServerKeyExchange body (after the 4-byte
    /// `type || 24-bit length` handshake header has been stripped).
    ///
    /// Auto-detects the variant: if the body starts with the
    /// ECParameters prefix (`0x03 0x00 0x29`), it's `Ecdhe`; otherwise
    /// it's `Ecc { signature }`. This auto-detection lets us talk to
    /// ECDHE peers (GmSSL/Tongsuo/openHiTLS for ECDHE suites) and
    /// sig-only peers (openHiTLS/Tongsuo for static-ECC suites) from
    /// the same parser.
    pub fn from_body(body: &[u8]) -> Result<Self, TlcpError> {
        if body.len() >= TLCP_ECH_PARAMS_PREFIX.len()
            && body[..TLCP_ECH_PARAMS_PREFIX.len()] == TLCP_ECH_PARAMS_PREFIX
        {
            // ECDHE body.
            let ecdhe_params = Sm2EcdheParams::from_bytes(body)?;
            Ok(Self {
                body: ServerKeyExchangeBody::Ecdhe(ecdhe_params),
            })
        } else {
            // Ecc body = uint16 sig_len || sig_der
            if body.len() < 2 {
                return Err(TlcpError::InvalidMessage(format!(
                    "ECC SKE body too short: {} bytes, need at least 2",
                    body.len()
                )));
            }
            let sig_len = u16::from_be_bytes([body[0], body[1]]) as usize;
            if body.len() < 2 + sig_len {
                return Err(TlcpError::InvalidMessage(format!(
                    "ECC SKE signature truncated: body {} < 2 + sig_len {}",
                    body.len(),
                    sig_len
                )));
            }
            let signature = body[2..2 + sig_len].to_vec();
            Ok(Self {
                body: ServerKeyExchangeBody::Ecc { signature },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlcp::HandshakeType;

    // ----- ECDHE roundtrip -----

    #[test]
    fn ske_ecdhe_roundtrip() {
        let ephemeral_pub = vec![
            0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41,
        ];
        let signature = vec![0xAA; 64];
        let params = Sm2EcdheParams::new(ephemeral_pub.clone(), signature.clone());
        let ske = TlcpServerKeyExchange::new(params);
        let bytes = ske.to_bytes();
        // 4-byte HS header: type=0x0C, 24-bit length, then body
        assert_eq!(bytes[0], HandshakeType::ServerKeyExchange as u8);
        let body_len =
            ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        let parsed = TlcpServerKeyExchange::from_body(&bytes[4..4 + body_len]).unwrap();
        let parsed_ecdhe = parsed.as_ecdhe().expect("expected ECDHE variant");
        assert_eq!(parsed_ecdhe.ephemeral_public, ephemeral_pub);
        assert_eq!(parsed_ecdhe.signature, signature);
        assert!(parsed.as_ecc_signature().is_none());
    }

    // ----- ECC (sig-only) roundtrip -----

    #[test]
    fn ske_ecc_to_bytes_writes_uint16_sig_len_prefix() {
        // DER-encoded SM2 sig is typically 70-72 bytes for sm2p256v1.
        // Use a 72-byte sig here so we can pin the exact uint16 prefix.
        let signature = vec![0xBB; 72];
        let ske = TlcpServerKeyExchange::new_ecc(signature.clone());
        let bytes = ske.to_bytes();
        // 4-byte HS header
        assert_eq!(bytes[0], HandshakeType::ServerKeyExchange as u8);
        let body_len =
            ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        // body = uint16(72) || sig_72 = 74 bytes
        assert_eq!(body_len, 74);
        assert_eq!(bytes[4], 0x00);
        assert_eq!(bytes[5], 0x48); // 72 == 0x48
        assert_eq!(&bytes[6..6 + 72], &signature[..]);
        // No ECParameters prefix in the body
        assert_ne!(
            &bytes[4..4 + TLCP_ECH_PARAMS_PREFIX.len()],
            &TLCP_ECH_PARAMS_PREFIX[..]
        );
    }

    #[test]
    fn ske_ecc_from_body_parses_back() {
        let signature = vec![0xCC; 70]; // typical DER SM2 sig length
        let ske = TlcpServerKeyExchange::new_ecc(signature.clone());
        let bytes = ske.to_bytes();
        let body_len =
            ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        let parsed = TlcpServerKeyExchange::from_body(&bytes[4..4 + body_len]).unwrap();
        assert!(parsed.as_ecdhe().is_none());
        let parsed_sig = parsed.as_ecc_signature().expect("expected Ecc variant");
        assert_eq!(parsed_sig, signature.as_slice());
    }

    #[test]
    fn ske_ecc_from_body_rejects_truncated_input() {
        // body = 1 byte (less than the uint16 sig_len prefix)
        assert!(TlcpServerKeyExchange::from_body(&[0x00]).is_err());
        // body = uint16(10) but no payload
        assert!(TlcpServerKeyExchange::from_body(&[0x00, 0x0A]).is_err());
    }

    // ----- variant auto-detection: body starting with ECParameters
    //       prefix → Ecdhe, else → Ecc.

    #[test]
    fn ske_from_body_autodetects_ecdhe_by_ecparameters_prefix() {
        // Construct a minimal valid ECDHE body: ECParameters (3 bytes)
        // + pub_len (1 byte = 1) + 1 byte pub + sig_len (2 bytes = 0)
        let mut body = Vec::new();
        body.extend_from_slice(&TLCP_ECH_PARAMS_PREFIX);
        body.push(0x01); // pub_len
        body.push(0x04); // pub byte (compressed/uncompressed marker; we
        // don't validate the 65-byte shape in this test
        // since the parser only requires pub_len bytes
        // are present, then reads sig_len bytes)
        body.extend_from_slice(&0u16.to_be_bytes()); // sig_len = 0
        let parsed = TlcpServerKeyExchange::from_body(&body).expect("parse should succeed");
        assert!(parsed.as_ecdhe().is_some());
        assert!(parsed.as_ecc_signature().is_none());
    }

    #[test]
    fn ske_from_body_autodetects_ecc_when_prefix_absent() {
        // body = uint16(0) || (no sig bytes) — short but valid empty-sig Ecc.
        let body = vec![0x00, 0x00];
        let parsed = TlcpServerKeyExchange::from_body(&body).expect("parse should succeed");
        assert!(parsed.as_ecdhe().is_none());
        assert_eq!(parsed.as_ecc_signature().map(|s| s.len()), Some(0));
    }

    // ----- spec-B round-trip via the verify path (R-2 integration test) -----

    #[test]
    fn generate_ecc_then_verify_roundtrip_succeeds() {
        use crate::tlcp::crypto::verify::verify_ske_signature;
        use gm_crypto::sm2::Sm2KeyPair;

        // Generate a real signing keypair.
        let sign_kp = Sm2KeyPair::generate().expect("sm2 keypair generate");
        let sign_signer = gm_crypto::sm2::Sm2Signer::new(&sign_kp).expect("signer");
        let verifier =
            gm_crypto::sm2::Sm2Verifier::new(&sign_kp.public_key_bytes(), sign_kp.distid())
                .expect("verifier");

        let cr = [0xAAu8; 32];
        let sr = [0xBBu8; 32];
        let enc_cert: Vec<u8> = (0u8..=200).collect();

        // Server emits sig-only SKE (interpretation-B).
        let ske = TlcpServerKeyExchange::generate_ecc(&cr, &sr, &enc_cert, &sign_signer)
            .expect("generate_ecc");
        // generate_ecc emits DER-encoded sig on the wire.
        let sig_der = ske.as_ecc_signature().expect("Ecc variant").to_vec();
        assert_eq!(
            sig_der.first(),
            Some(&0x30),
            "generate_ecc must emit DER (starts with 0x30 SEQUENCE tag)"
        );

        // Reconstruct the body the client would receive: uint16 sig_len || sig_der.
        let mut body = Vec::with_capacity(2 + sig_der.len());
        body.extend_from_slice(&(sig_der.len() as u16).to_be_bytes());
        body.extend_from_slice(&sig_der);

        // Client verifies — must succeed with correct random + verifier.
        verify_ske_signature(
            true, /* is_ecc_mode */
            &body, &cr, &sr, &enc_cert, &verifier,
        )
        .expect("ECC SKE verification must succeed for spec-B roundtrip");

        // Bad random must reject.
        let wrong_cr = [0xCCu8; 32];
        assert!(
            verify_ske_signature(true, &body, &wrong_cr, &sr, &enc_cert, &verifier).is_err(),
            "ECC SKE verification must reject when client_random is wrong"
        );
    }

    #[test]
    fn generate_ecc_to_bytes_matches_interp_b_layout() {
        use gm_crypto::sm2::Sm2KeyPair;

        let sign_kp = Sm2KeyPair::generate().expect("sm2 keypair generate");
        let sign_signer = gm_crypto::sm2::Sm2Signer::new(&sign_kp).expect("signer");
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];
        let enc_cert = vec![0xAA; 1500]; // arbitrary size up to 2^24 - 1

        let ske = TlcpServerKeyExchange::generate_ecc(&cr, &sr, &enc_cert, &sign_signer)
            .expect("generate_ecc");
        let bytes = ske.to_bytes();

        // bytes[0] = 0x0C (ServerKeyExchange HS type)
        assert_eq!(bytes[0], 0x0C);
        // bytes[1..4] = 24-bit body length
        let body_len =
            ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        // body = uint16 sig_len || sig_der (DER for sm2p256v1 is typically 70-72 bytes).
        let sig_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        assert!(
            (68..=74).contains(&sig_len),
            "DER sig for sm2p256v1 should be ~70-72 bytes, got {sig_len}"
        );
        // DER signature starts with 0x30 (SEQUENCE tag).
        assert_eq!(bytes[6], 0x30, "DER sig must start with 0x30 SEQUENCE tag");
        assert_eq!(body_len, 2 + sig_len);
        assert_eq!(bytes.len(), 4 + body_len);
    }
}
