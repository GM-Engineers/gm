//! ECDHE parameters + ServerKeyExchange message.
//!
//! `Sm2EcdheParams` is the wire-format ECDH parameters block
//! `[ECParameters | ECPoint | signature]` that appears in both
//! `ServerKeyExchange` (server → client) and (after sign verification)
//! in `ClientKeyExchange` (client → server).
//!
//! `TlcpServerKeyExchange` wraps `Sm2EcdheParams` with the
//! `ServerKeyExchange` handshake header (4 bytes:
//! `[type=0x0C | length(3)])`.

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

/// TLCP ServerKeyExchange message (GB/T 38636-2020 §6.4.1.5)
///
/// Sent by the server during ECDHE handshake to convey:
/// - Server's ephemeral SM2 public key
/// - SM2 signature over (client_random || server_random || ephemeral_public)
///   using the server's signing certificate private key
#[derive(Debug, Clone)]
pub struct TlcpServerKeyExchange {
    /// ECDHE parameters
    pub ecdhe_params: Sm2EcdheParams,
}

impl TlcpServerKeyExchange {
    /// Create a new ServerKeyExchange with the given ECDHE parameters
    pub fn new(ecdhe_params: Sm2EcdheParams) -> Self {
        Self { ecdhe_params }
    }

    /// Create a ServerKeyExchange by generating an ephemeral keypair and signing
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
                ecdhe_params: Sm2EcdheParams::new(ephemeral_pub, signature),
            },
            ephemeral_kp,
        ))
    }

    /// Verify the server's signature on the ServerKeyExchange.
    ///
    /// Signed data: `client_random || server_random || server_ecdh_params`,
    /// where `server_ecdh_params` is the full ECParameters-wrapped
    /// blob on the wire (see [`Sm2EcdheParams::to_bytes`]).
    pub fn verify_signature(
        &self,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        verifier: &Sm2Verifier,
    ) -> Result<(), TlcpError> {
        // Reconstruct the exact ECParameters wire bytes the server
        // emitted by serializing our parsed fields through the same
        // `Sm2EcdheParams::to_bytes` path (with the signature zeroed
        // out, since the signer covers only the prefix + pub key).
        let mut signed_data = Vec::with_capacity(
            32 + 32 + TLCP_ECH_PARAMS_PREFIX.len() + 1 + self.ecdhe_params.ephemeral_public.len(),
        );
        signed_data.extend_from_slice(client_random);
        signed_data.extend_from_slice(server_random);
        signed_data.extend_from_slice(&TLCP_ECH_PARAMS_PREFIX);
        signed_data.push(self.ecdhe_params.ephemeral_public.len() as u8);
        signed_data.extend_from_slice(&self.ecdhe_params.ephemeral_public);

        verifier
            .verify(&signed_data, &self.ecdhe_params.signature)
            .map_err(|e| TlcpError::HandshakeFailed(format!("SKE signature verify failed: {}", e)))
    }

    /// Serialize to TLS record bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let body = self.ecdhe_params.to_bytes();
        let mut buf = Vec::with_capacity(4 + body.len());
        buf.push(HandshakeType::ServerKeyExchange as u8);
        buf.push(0);
        buf.push((body.len() >> 8) as u8);
        buf.push(body.len() as u8);
        buf.extend_from_slice(&body);
        buf
    }

    /// Deserialize from handshake message body (after type + length prefix)
    pub fn from_body(body: &[u8]) -> Result<Self, TlcpError> {
        let ecdhe_params = Sm2EcdheParams::from_bytes(body)?;
        Ok(Self { ecdhe_params })
    }
}
