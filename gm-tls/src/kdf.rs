//! Key derivation functions for GM/TLS using HKDF-SM3.
//!
//! This module implements RFC 5869 HMAC-based Key Derivation Function (HKDF)
//! using the SM3 hash algorithm as specified for GM/TLS protocol.

use crate::error::TlsError;
use crate::handshake::HandshakeSecrets;
use crate::session_ticket::SessionKeys;
use elliptic_curve::sec1::ToEncodedPoint;
use gm_crypto::sm2::ProjectivePoint;
use gm_crypto::sm3::Sm3Hmac;
use gm_crypto::sm4::SM4_GCM_NONCE_LENGTH;
use zeroize::Zeroizing;

/// SM3 hash output length in bytes
const SM3_HASH_LEN: usize = 32;

/// Maximum HKDF-Expand output length: 255 * HashLen (RFC 5869 Section 2.3)
const HKDF_MAX_OUTPUT: usize = 255 * SM3_HASH_LEN;

/// Derive SM4-GCM key and IV from a traffic secret.
///
/// Per RFC 8446 §7.3:
/// ```text
/// key = HKDF-Expand-Label(secret, "key", "", key_length)
/// iv  = HKDF-Expand-Label(secret, "iv", "", nonce_length)
/// ```
fn derive_key_iv_from_secret(
    secret: &[u8],
) -> Result<(Vec<u8>, [u8; SM4_GCM_NONCE_LENGTH]), TlsError> {
    let key = hkdf_sm3(secret, &[], b"key", SM4_KEY_LEN)?;
    let iv_material = hkdf_sm3(secret, &[], b"iv", SM4_NONCE_LEN)?;
    let mut nonce = [0u8; SM4_GCM_NONCE_LENGTH];
    nonce.copy_from_slice(&iv_material);
    Ok((key, nonce))
}

/// SM4-GCM key length
const SM4_KEY_LEN: usize = 16;

/// SM4-GCM nonce length
const SM4_NONCE_LEN: usize = 12;

/// HMAC-SM3 based HKDF-Extract-Expand (RFC 5869)
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt value (if empty, uses zero-filled key of HashLen bytes per RFC 5869)
/// * `info` - Optional context and application specific information
/// * `len` - Length of output keying material in octets
///
/// # Errors
/// Returns `TlsError::HandshakeFailed` if `len` exceeds 255 * HashLen
pub fn hkdf_sm3(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, TlsError> {
    if len > HKDF_MAX_OUTPUT {
        return Err(TlsError::HandshakeFailed(format!(
            "HKDF output length {} exceeds maximum {} bytes",
            len, HKDF_MAX_OUTPUT
        )));
    }

    // Extract: PRK = HMAC-Hash(salt, IKM)
    // Per RFC 5869 Section 2.2: if salt is not provided, it is set to a string
    // of HashLen zeros.
    let prk: Zeroizing<Vec<u8>> = if salt.is_empty() {
        let zero_salt = vec![0u8; SM3_HASH_LEN];
        Zeroizing::new(
            Sm3Hmac::new(&zero_salt)
                .compute(ikm)
                .map_err(TlsError::from)?,
        )
    } else {
        Zeroizing::new(Sm3Hmac::new(salt).compute(ikm).map_err(TlsError::from)?)
    };

    // Expand: T(1) = HMAC-Hash(PRK, info || 0x01)
    //         T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
    //         OKM  = first len octets of T(1) || ... || T(N)
    let mut okm = Vec::new();
    let mut t_prev = Vec::new(); // T(i-1), empty for first iteration
    let mut counter: u8 = 1;

    while okm.len() < len {
        // Construct input: T(i-1) || info || counter
        let mut input = Vec::with_capacity(t_prev.len() + info.len() + 1);
        input.extend_from_slice(&t_prev);
        input.extend_from_slice(info);
        input.push(counter);

        let t_i = Sm3Hmac::new(&prk).compute(&input).map_err(TlsError::from)?;

        okm.extend_from_slice(&t_i);
        t_prev = t_i;

        // Increment counter only if we need more output.
        // The length check at function entry guarantees counter never exceeds 255.
        if okm.len() < len {
            counter = counter
                .checked_add(1)
                .ok_or_else(|| TlsError::HandshakeFailed("HKDF-Expand counter overflow".into()))?;
        }
    }

    okm.truncate(len);
    Ok(okm)
}

/// Derive session keys from an SM2 ECDH shared point.
///
/// Uses HKDF-SM3 with separate labels for client-to-server and server-to-client
/// traffic keys to ensure directional key separation and prevent GCM nonce reuse.
pub fn derive_session_keys_sm2(
    shared_point: &ProjectivePoint,
) -> Result<HandshakeSecrets, TlsError> {
    let enc = shared_point.to_affine().to_encoded_point(false);
    let x = enc
        .x()
        .ok_or_else(|| TlsError::HandshakeFailed("shared point missing X".into()))?;
    let y = enc
        .y()
        .ok_or_else(|| TlsError::HandshakeFailed("shared point missing Y".into()))?;

    let mut ikm = Vec::with_capacity(x.len() + y.len());
    ikm.extend_from_slice(x);
    ikm.extend_from_slice(y);

    let salt: [u8; 0] = [];
    let info_master = b"GM/TLS-master-secret";
    let master_secret = hkdf_sm3(&ikm, &salt, info_master, 32)?;

    // Derive application traffic secrets (32 bytes each, same as SM3 hash length)
    // These are used for KeyUpdate (RFC 8446 §7.2): each update derives
    // a new traffic secret, then derives new key+iv from that secret.
    let info_client_secret = b"GM/TLS-client-traffic-secret";
    let client_traffic_secret = hkdf_sm3(&master_secret, &salt, info_client_secret, SM3_HASH_LEN)?;

    let info_server_secret = b"GM/TLS-server-traffic-secret";
    let server_traffic_secret = hkdf_sm3(&master_secret, &salt, info_server_secret, SM3_HASH_LEN)?;

    // Derive key + iv from each traffic secret
    let (client_key, client_nonce) = derive_key_iv_from_secret(&client_traffic_secret)?;
    let (server_key, server_nonce) = derive_key_iv_from_secret(&server_traffic_secret)?;

    Ok(HandshakeSecrets {
        master_secret: Zeroizing::new(master_secret),
        client_traffic_secret: Zeroizing::new(client_traffic_secret),
        server_traffic_secret: Zeroizing::new(server_traffic_secret),
        session_keys: SessionKeys {
            client_key,
            client_nonce,
            server_key,
            server_nonce,
        },
    })
}
