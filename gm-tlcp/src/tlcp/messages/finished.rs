//! TLCP Finished message.
//!
//! GB/T 38636-2020 §6.4.1.9.
//!
//! ```text
//!   verify_data = PRF(master_secret, finished_label,
//!                     SM3(handshake_messages))[0..12]
//! ```
//!
//! The PRF is the SM3-based TLS 1.2 PRF (iterated expansion),
//! **not** a single SM3 invocation. This matches the same
//! `prf_expand` used by `TlcpKeyMaterial::derive` for master_secret
//! derivation.

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;
use crate::tlcp::TlcpKeyMaterial;

/// TLCP Finished message
///
/// GB/T 38636-2020 §6.4.1.9
///
/// `verify_data = PRF(master_secret, finished_label, SM3(handshake_messages))[0..12]`
/// where `finished_label` is `"client finished"` or `"server finished"`. The PRF
/// is the SM3-based TLS 1.2 iterated expansion defined by [`TlcpKeyMaterial::prf_expand`]
/// (RFC 5246 §5 P_hash adapted for SM3), **not** a single SM3 invocation.
#[derive(Debug, Clone)]
pub struct TlcpFinished {
    /// verify_data (12 bytes)
    pub verify_data: [u8; 12],
}

impl TlcpFinished {
    /// Compute verify_data for a Finished message
    ///
    /// Per GB/T 38636-2020, the verify_data is computed as:
    ///   verify_data = PRF(master_secret, finished_label, SM3(handshake_messages))[0..12]
    ///
    /// For TLCP, the PRF is the SM3-based TLS 1.2 PRF (iterated expansion),
    /// **not** a single SM3 invocation. This matches the same `prf_expand`
    /// used by [`TlcpKeyMaterial::derive`] for master_secret derivation.
    ///
    /// Security: see the security-audit comment on `prf_expand` (defined on
    /// `TlcpKeyMaterial`) for why a real PRF is required.
    pub fn compute(
        master_secret: &[u8],
        label: &str,
        transcript: &[u8],
    ) -> Result<Self, TlcpError> {
        let transcript_hash = gm_crypto::sm3::Sm3Hasher::hash(transcript)
            .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;

        // PRF: TLS 1.2-style SM3 expansion of (label || transcript_hash)
        // keyed by master_secret, taking the first 12 bytes.
        let prf_output =
            TlcpKeyMaterial::prf_expand(master_secret, label.as_bytes(), &transcript_hash, 12)?;

        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&prf_output[..12]);

        Ok(Self { verify_data })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        // Handshake type
        buf.push(HandshakeType::Finished as u8);
        // Length (3 bytes) = 12
        buf.push(0);
        buf.push(0);
        buf.push(12);
        // verify_data
        buf.extend_from_slice(&self.verify_data);
        buf
    }

    /// Verify against expected verify_data
    pub fn verify(&self, expected: &[u8; 12]) -> bool {
        subtle::ConstantTimeEq::ct_eq(&self.verify_data[..], &expected[..]).into()
    }

    /// Parse the 12-byte verify_data from a Finished message body.
    ///
    /// `body` is the handshake-message body (i.e. the bytes that follow the
    /// 4-byte handshake header `[type(1) | length(3)]`). Per GB/T 38636-2020
    /// the Finished body is exactly the 12-byte verify_data.
    pub fn from_body(body: &[u8]) -> Result<Self, TlcpError> {
        if body.len() != 12 {
            return Err(TlcpError::HandshakeFailed(format!(
                "TLCP Finished body must be 12 bytes, got {}",
                body.len()
            )));
        }
        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&body[..12]);
        Ok(Self { verify_data })
    }
}
