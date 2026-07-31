//! TLS 1.3 KeyUpdate mechanism (RFC 8446 §4.6.3).
//!
//! The KeyUpdate handshake message is used to rotate traffic keys when the
//! sequence number approaches the GCM confidentiality limit (2^32 records
//! per NIST SP 800-38D) or when the application requests a re-key.
//!
//! # Wire Format
//!
//! ```text
//! struct {
//!     KeyUpdateRequest update_requested;
//! } KeyUpdate;
//! ```
//!
//! Where `KeyUpdateRequest` is:
//! - `update_not_requested(0)`: Sender has already updated their keys
//! - `update_requested(1)`: Sender has updated their keys AND requests
//!   the receiver to also send a KeyUpdate
//!
//! # Key Derivation
//!
//! Per RFC 8446 §7.2:
//! ```text
//! application_traffic_secret_N+1 =
//!     HKDF-Expand-Label(application_traffic_secret_N,
//!                       "traffic upd", "", Hash.length)
//! ```
//!
//! Then the new key and nonce are derived from the updated secret:
//! ```text
//! key = HKDF-Expand-Label(secret, "key", "", key_length)
//! iv  = HKDF-Expand-Label(secret, "iv", "", nonce_length)
//! ```
//!
//! # Sequence Number Reset
//!
//! After a key update, the sequence number for the affected direction
//! is reset to 0 (RFC 8446 §5.3).

use crate::error::TlsError;
use crate::kdf::hkdf_sm3;

/// SM3 hash output length
const SM3_HASH_LEN: usize = 32;

/// SM4-GCM key length
const SM4_KEY_LEN: usize = 16;

/// SM4-GCM nonce length
const SM4_NONCE_LEN: usize = 12;

/// KeyUpdate request types (RFC 8446 §4.6.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyUpdateRequest {
    /// Sender has updated their sending keys; receiver should NOT update
    UpdateNotRequested = 0,
    /// Sender has updated their sending keys; receiver MUST also update
    UpdateRequested = 1,
}

impl KeyUpdateRequest {
    /// Parse from byte value
    pub fn from_byte(b: u8) -> Result<Self, TlsError> {
        match b {
            0 => Ok(Self::UpdateNotRequested),
            1 => Ok(Self::UpdateRequested),
            _ => Err(TlsError::InvalidMessage(format!(
                "invalid KeyUpdateRequest value: {}",
                b
            ))),
        }
    }

    /// Convert to byte value
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// KeyUpdate message (RFC 8446 §4.6.3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUpdate {
    pub update_requested: KeyUpdateRequest,
}

impl KeyUpdate {
    /// Create a new KeyUpdate message
    pub fn new(update_requested: KeyUpdateRequest) -> Self {
        Self { update_requested }
    }

    /// Serialize the KeyUpdate message to bytes.
    ///
    /// Wire format: `[HandshakeType=0x18][length=3 bytes][update_requested(1 byte)]`
    /// The handshake layer adds the type and length; this returns only the
    /// body (1 byte: update_requested).
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![self.update_requested.to_byte()]
    }

    /// Parse a KeyUpdate message from the body bytes (after type+length).
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() != 1 {
            return Err(TlsError::InvalidMessage(format!(
                "KeyUpdate body must be exactly 1 byte, got {}",
                data.len()
            )));
        }
        Ok(Self {
            update_requested: KeyUpdateRequest::from_byte(data[0])?,
        })
    }
}

/// GCM confidentiality limit per NIST SP 800-38D: 2^32 records per key.
/// We trigger KeyUpdate at 80% of this limit to provide a safety margin.
pub const KEY_UPDATE_THRESHOLD: u64 = (1u64 << 32) * 4 / 5; // ~3.4 billion

/// Hard limit: at 2^32 records, GCM confidentiality is no longer guaranteed.
pub const GCM_CONFIDENTIALITY_LIMIT: u64 = 1u64 << 32;

/// Derive updated application traffic secret using HKDF-Expand-Label.
///
/// Per RFC 8446 §7.2:
/// ```text
/// application_traffic_secret_N+1 =
///     HKDF-Expand-Label(application_traffic_secret_N,
///                       "traffic upd", "", Hash.length)
/// ```
///
/// For our GM/TLS implementation, we use HKDF-SM3 with label "traffic upd".
pub fn update_traffic_secret(old_secret: &[u8]) -> Result<Vec<u8>, TlsError> {
    if old_secret.len() != SM3_HASH_LEN {
        return Err(TlsError::HandshakeFailed(format!(
            "traffic secret must be {} bytes, got {}",
            SM3_HASH_LEN,
            old_secret.len()
        )));
    }
    hkdf_sm3(old_secret, &[], b"traffic upd", SM3_HASH_LEN)
}

/// Derive new key and nonce from an updated traffic secret.
///
/// Per RFC 8446 §7.3:
/// ```text
/// key = HKDF-Expand-Label(secret, "key", "", key_length)
/// iv  = HKDF-Expand-Label(secret, "iv", "", nonce_length)
/// ```
///
/// Returns (new_key, new_nonce).
pub fn derive_key_and_nonce(secret: &[u8]) -> Result<(Vec<u8>, [u8; SM4_NONCE_LEN]), TlsError> {
    let new_key = hkdf_sm3(secret, &[], b"key", SM4_KEY_LEN)?;
    let iv_material = hkdf_sm3(secret, &[], b"iv", SM4_NONCE_LEN)?;
    let mut new_nonce = [0u8; SM4_NONCE_LEN];
    new_nonce.copy_from_slice(&iv_material);
    Ok((new_key, new_nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_update_request_from_byte() {
        assert!(matches!(
            KeyUpdateRequest::from_byte(0),
            Ok(KeyUpdateRequest::UpdateNotRequested)
        ));
        assert!(matches!(
            KeyUpdateRequest::from_byte(1),
            Ok(KeyUpdateRequest::UpdateRequested)
        ));
        assert!(KeyUpdateRequest::from_byte(2).is_err());
        assert!(KeyUpdateRequest::from_byte(255).is_err());
    }

    #[test]
    fn test_key_update_serialization() {
        let ku = KeyUpdate::new(KeyUpdateRequest::UpdateNotRequested);
        assert_eq!(ku.to_bytes(), vec![0]);

        let ku = KeyUpdate::new(KeyUpdateRequest::UpdateRequested);
        assert_eq!(ku.to_bytes(), vec![1]);
    }

    #[test]
    fn test_key_update_roundtrip() {
        for req in [
            KeyUpdateRequest::UpdateNotRequested,
            KeyUpdateRequest::UpdateRequested,
        ] {
            let ku = KeyUpdate::new(req);
            let bytes = ku.to_bytes();
            let parsed = KeyUpdate::from_bytes(&bytes).unwrap();
            assert_eq!(ku, parsed);
        }
    }

    #[test]
    fn test_key_update_invalid_body() {
        // Empty body
        assert!(KeyUpdate::from_bytes(&[]).is_err());
        // Too long
        assert!(KeyUpdate::from_bytes(&[0, 1]).is_err());
    }

    #[test]
    fn test_update_traffic_secret_deterministic() {
        let secret = [0xABu8; 32];
        let updated1 = update_traffic_secret(&secret).unwrap();
        let updated2 = update_traffic_secret(&secret).unwrap();
        assert_eq!(updated1, updated2);
        // Updated secret should differ from original
        assert_ne!(updated1.as_slice(), &secret[..]);
    }

    #[test]
    fn test_update_traffic_secret_wrong_length() {
        assert!(update_traffic_secret(&[0u8; 16]).is_err());
        assert!(update_traffic_secret(&[0u8; 64]).is_err());
    }

    #[test]
    fn test_derive_key_and_nonce() {
        let secret = [0xCDu8; 32];
        let (key, nonce) = derive_key_and_nonce(&secret).unwrap();
        assert_eq!(key.len(), SM4_KEY_LEN);
        assert_eq!(nonce.len(), SM4_NONCE_LEN);

        // Same secret should produce same key/nonce
        let (key2, nonce2) = derive_key_and_nonce(&secret).unwrap();
        assert_eq!(key, key2);
        assert_eq!(nonce, nonce2);
    }

    #[test]
    fn test_key_update_chain_produces_different_keys() {
        let secret0 = [0x42u8; 32];
        let secret1 = update_traffic_secret(&secret0).unwrap();
        let secret2 = update_traffic_secret(&secret1).unwrap();

        // Each update should produce a different secret
        assert_ne!(secret0.as_slice(), secret1.as_slice());
        assert_ne!(secret1.as_slice(), secret2.as_slice());
        assert_ne!(secret0.as_slice(), secret2.as_slice());

        // Derive keys from each secret — they should all differ
        let (key0, nonce0) = derive_key_and_nonce(&secret0).unwrap();
        let (key1, nonce1) = derive_key_and_nonce(&secret1).unwrap();
        let (key2, nonce2) = derive_key_and_nonce(&secret2).unwrap();

        assert_ne!(key0, key1);
        assert_ne!(key1, key2);
        assert_ne!(nonce0, nonce1);
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_threshold_values() {
        // KEY_UPDATE_THRESHOLD should be less than GCM_CONFIDENTIALITY_LIMIT
        assert!(KEY_UPDATE_THRESHOLD < GCM_CONFIDENTIALITY_LIMIT);
        // KEY_UPDATE_THRESHOLD should be 80% of the limit
        assert_eq!(KEY_UPDATE_THRESHOLD, (1u64 << 32) * 4 / 5);
        // Both should be reasonable numbers (billions)
        assert!(KEY_UPDATE_THRESHOLD > 1_000_000_000);
        assert!(GCM_CONFIDENTIALITY_LIMIT > 1_000_000_000);
    }
}
