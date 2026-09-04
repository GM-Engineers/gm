//! TLCP-specific SM2 / SM3 helpers.
//!
//! These are the TLCP protocol glue built on top of the generic SM2
//! primitives in `gm_crypto::sm2_kex`:
//!
//! * `sm2_compute_z` — compute the SM2 Z value per GB/T 32918.3 §6.1
//!   (used to verify the ServerKeyExchange SM2 signature and to feed
//!   the ECDHE PMS KDF).
//! * `scalar_from_x_hat` — apply the GmSSL-specific 128-bit x̂
//!   transform `2^127 + (x mod 2^127)` to an ECDH shared point's
//!   x-coordinate. Without this, our PMS diverges from GmSSL's.
//! * `compute_tlcp_ecdhe_pms` — compute the TLCP Pre-Master Secret
//!   via the GB/T 32918-2017 §6.4.2 key agreement.
//!
//! These functions were previously in `gm_crypto::sm2_kex` but were
//! only ever used by `gm-tlcp`. They are TLCP-specific (the GmSSL
//! `x̂` transform is a non-standard interop quirk, and `Z` is only
//! computed for the TLCP SKE signature verification path).

use crate::error::TlcpError;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::{Group, PrimeField};
use gm_crypto::error::CryptoError;
use gm_crypto::sm3::Sm3Hasher;
use sm2::{ProjectivePoint, Scalar, SecretKey, Sm2};

/// SM2 curve parameters (a, b, x_G, y_G) as 32-byte big-endian
/// representations, per GB/T 32918.1-2016 §6.1.
const SM2_A_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
];
const SM2_B_BYTES: [u8; 32] = [
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
];
const SM2_X_G_BYTES: [u8; 32] = [
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
];
const SM2_Y_G_BYTES: [u8; 32] = [
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
];

/// Compute the SM2 `Z` value per GB/T 32918.3-2016 §6.1.
///
/// `Z = SM3(ENTL || ID || a || b || x_G || y_G || x_pubA || y_pubA)`.
///
/// * `pub_xy` – 64-byte uncompressed public key (x || y).
/// * `user_id` – Distinguishing identifier bytes (any length up to 65 535).
pub fn sm2_compute_z(pub_xy: &[u8; 64], user_id: &[u8]) -> Result<[u8; 32], TlcpError> {
    if user_id.len() > 0xFFFF {
        return Err(TlcpError::HandshakeFailed(format!(
            "user ID too long: {} bytes",
            user_id.len()
        )));
    }
    let entl = ((user_id.len() as u16) * 8).to_be_bytes();
    let mut input = Vec::with_capacity(2 + user_id.len() + 32 * 6);
    input.extend_from_slice(&entl);
    input.extend_from_slice(user_id);
    input.extend_from_slice(&SM2_A_BYTES);
    input.extend_from_slice(&SM2_B_BYTES);
    input.extend_from_slice(&SM2_X_G_BYTES);
    input.extend_from_slice(&SM2_Y_G_BYTES);
    input.extend_from_slice(&pub_xy[..32]);
    input.extend_from_slice(&pub_xy[32..64]);
    let h = Sm3Hasher::hash(&input).map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    Ok(out)
}

/// Compute the TLCP ECDHE Pre-Master Secret per GB/T 32918-2017 §6.4.2.
///
/// Both parties compute the same shared point `V` using their own
/// static encryption key + ephemeral key and the peer's static
/// encryption pub + ephemeral pub:
///
/// ```text
/// t = (x_self_R_hat * r_self + k_self) mod n
/// V = t * (x_peer_R_hat * R_peer + P_peer)
/// PMS = KDF(x_V || y_V || Z_A || Z_B, klen)
/// ```
///
/// The two Z values are passed in caller-determined order
/// (initiator-first on both sides) so both sides produce the same
/// KDF input.
#[allow(clippy::too_many_arguments)]
pub fn compute_tlcp_ecdhe_pms(
    _local_static_xy: &[u8; 64],
    local_static_priv: &[u8; 32],
    local_ephemeral_xy: &[u8; 64],
    local_ephemeral_priv: &[u8; 32],
    peer_static_xy: &[u8; 64],
    peer_ephemeral_xy: &[u8; 64],
    z_a: &[u8; 32],
    z_b: &[u8; 32],
    klen: usize,
) -> Result<Vec<u8>, TlcpError> {
    let local_ephemeral_point = parse_uncompressed_point(local_ephemeral_xy)
        .map_err(|e| TlcpError::HandshakeFailed(format!("local ephemeral point: {}", e)))?;
    let peer_ephemeral_point = parse_uncompressed_point(peer_ephemeral_xy)
        .map_err(|e| TlcpError::HandshakeFailed(format!("peer ephemeral point: {}", e)))?;
    let peer_static_point = parse_uncompressed_point(peer_static_xy)
        .map_err(|e| TlcpError::HandshakeFailed(format!("peer static point: {}", e)))?;

    let (local_ephemeral_x, _) = point_xy_bytes(&local_ephemeral_point)
        .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;
    let local_x_hat = scalar_from_x_hat(&local_ephemeral_x)
        .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;
    let local_ephemeral_scalar = scalar_from_bytes_checked(local_ephemeral_priv)
        .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;
    let local_static_scalar = scalar_from_bytes_checked(local_static_priv)
        .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;
    let t = local_x_hat * local_ephemeral_scalar + local_static_scalar;

    let (peer_ephemeral_x, _) = point_xy_bytes(&peer_ephemeral_point)
        .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;
    let peer_x_hat = scalar_from_x_hat(&peer_ephemeral_x)
        .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;
    let shared_point = peer_ephemeral_point * peer_x_hat + peer_static_point;
    if bool::from(shared_point.is_identity()) {
        return Err(TlcpError::HandshakeFailed(
            "shared point V is identity element".to_string(),
        ));
    }
    let v = shared_point * t;
    if bool::from(v.is_identity()) {
        return Err(TlcpError::HandshakeFailed(
            "shared point V is identity element".to_string(),
        ));
    }
    let (v_x, v_y) = point_xy_bytes(&v).map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;

    let mut kdf_input = Vec::with_capacity(128);
    kdf_input.extend_from_slice(&v_x);
    kdf_input.extend_from_slice(&v_y);
    kdf_input.extend_from_slice(z_a);
    kdf_input.extend_from_slice(z_b);

    sm2_kdf(&kdf_input, klen).map_err(|e| TlcpError::HandshakeFailed(e.to_string()))
}

// ============================================================================
// Private helpers (inlined from gm-crypto::sm2_kex)
// ============================================================================

fn parse_uncompressed_point(r_pub: &[u8; 64]) -> Result<ProjectivePoint, CryptoError> {
    // 65 bytes: 0x04 || x(32) || y(32)
    let mut bytes = [0u8; 65];
    bytes[0] = 0x04;
    bytes[1..33].copy_from_slice(&r_pub[..32]);
    bytes[33..65].copy_from_slice(&r_pub[32..64]);
    let encoded = elliptic_curve::sec1::EncodedPoint::<Sm2>::from_bytes(bytes.as_slice())
        .map_err(|e| CryptoError::Sm2KexError(format!("invalid SM2 point bytes: {}", e)))?;
    let pt = Option::from(ProjectivePoint::from_encoded_point(&encoded))
        .ok_or_else(|| CryptoError::Sm2KexError("invalid SM2 point encoding".to_string()))?;
    Ok(pt)
}

fn point_xy_bytes(p: &ProjectivePoint) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let aff = p.to_affine();
    let encoded = aff.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.is_empty() || bytes[0] != 0x04 || bytes.len() != 65 {
        return Err(CryptoError::Sm2KexError(format!(
            "SM2 affine point has unexpected wire format (len={}, tag={:#x})",
            bytes.len(),
            bytes.first().copied().unwrap_or(0)
        )));
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    Ok((x, y))
}

fn scalar_from_bytes_checked(bytes: &[u8; 32]) -> Result<Scalar, CryptoError> {
    let secret = SecretKey::from_bytes(bytes.as_ref().into())
        .map_err(|e| CryptoError::Sm2KexError(format!("invalid scalar (must be 1..n-1): {}", e)))?;
    Ok(*secret.to_nonzero_scalar())
}

/// Apply the GmSSL x̂ transform `2^127 + (x mod 2^127)` to a 32-byte
/// big-endian x-coordinate and return the resulting Montgomery
/// `Scalar`. This is **not** a normal `x mod n` reduction; see the
/// long doc-comment in `gm_crypto::sm2_kex::scalar_from_x_hat` for
/// the bit-level details. Required for TLCP ECDHE interop with
/// GmSSL master.
fn scalar_from_x_hat(x_bytes: &[u8; 32]) -> Result<Scalar, CryptoError> {
    let x_lo = u64::from_be_bytes(x_bytes[24..32].try_into().expect("32-byte slice"));
    let x_mid = u64::from_be_bytes(x_bytes[16..24].try_into().expect("32-byte slice"));

    let xh_lo = x_lo;
    let xh_mid = (x_mid & 0x7fff_ffff_ffff_ffff) | 0x8000_0000_0000_0000;

    let mut out = [0u8; 32];
    out[16..24].copy_from_slice(&xh_mid.to_be_bytes());
    out[24..32].copy_from_slice(&xh_lo.to_be_bytes());

    let fb: elliptic_curve::FieldBytes<Sm2> = out.into();
    let scalar = Scalar::from_repr(fb).into_option().ok_or_else(|| {
        CryptoError::Sm2KexError("invalid x̂ transform (canonical decode failed)".to_string())
    })?;
    if bool::from(scalar.is_zero()) {
        return Err(CryptoError::Sm2KexError(
            "x̂ transform produced zero scalar".to_string(),
        ));
    }
    Ok(scalar)
}

/// SM3-KDF per GB/T 32918.3-2017 §6.4.2.1: `KDF(Z, klen) = SM3(Z || ct(1)) ||
/// SM3(Z || ct(2)) || ...` where `ct(i)` is a 4-byte big-endian counter.
/// Stops when the concatenation reaches `klen` bytes; the last block is
/// truncated if necessary.
fn sm2_kdf(z: &[u8], klen: usize) -> Result<Vec<u8>, CryptoError> {
    const CT_LEN: usize = 4;
    const H_LEN: usize = 32;
    if klen == 0 || klen > 16 * 1024 {
        return Err(CryptoError::Sm2KexError(format!(
            "sm2_kdf: invalid klen {}",
            klen
        )));
    }
    let n_blocks = klen.div_ceil(H_LEN);
    if n_blocks > u32::MAX as usize {
        return Err(CryptoError::Sm2KexError(
            "sm2_kdf: klen too large".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(n_blocks * H_LEN);
    for i in 1..=n_blocks {
        let ct = (i as u32).to_be_bytes();
        let mut input = Vec::with_capacity(z.len() + CT_LEN);
        input.extend_from_slice(z);
        input.extend_from_slice(&ct);
        let h = Sm3Hasher::hash(&input)?;
        out.extend_from_slice(&h);
    }
    out.truncate(klen);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sm2::SecretKey;

    /// Round-trip: A and B compute the same 48-byte PMS via
    /// `compute_tlcp_ecdhe_pms`. This is the critical TLCP interop
    /// guarantee: the Finished-MAC must match across both sides.
    #[test]
    fn compute_tlcp_ecdhe_pms_roundtrip() {
        let default_id: &[u8] = b"1234567812345678";

        // Long-term static SM2 key pairs.
        let a_sk = SecretKey::from_bytes((&[0x11u8; 32]).as_ref().into()).expect("A static sk");
        let b_sk = SecretKey::from_bytes((&[0x22u8; 32]).as_ref().into()).expect("B static sk");
        let a_apk = a_sk.public_key().to_encoded_point(false);
        let b_apk = b_sk.public_key().to_encoded_point(false);

        // Ephemeral key pairs.
        let ra_sk = SecretKey::from_bytes((&[0x33u8; 32]).as_ref().into()).expect("A eph sk");
        let rb_sk = SecretKey::from_bytes((&[0x44u8; 32]).as_ref().into()).expect("B eph sk");
        let ra_apk = ra_sk.public_key().to_encoded_point(false);
        let rb_apk = rb_sk.public_key().to_encoded_point(false);

        // 64-byte (x || y) SEC1 pub keys.
        let mut pk_a_xy = [0u8; 64];
        pk_a_xy.copy_from_slice(&a_apk.as_bytes()[1..65]);
        let mut pk_b_xy = [0u8; 64];
        pk_b_xy.copy_from_slice(&b_apk.as_bytes()[1..65]);
        let mut ra_xy = [0u8; 64];
        ra_xy.copy_from_slice(&ra_apk.as_bytes()[1..65]);
        let mut rb_xy = [0u8; 64];
        rb_xy.copy_from_slice(&rb_apk.as_bytes()[1..65]);

        // A is the initiator: Z_A first, Z_B second.
        let z_a = sm2_compute_z(&pk_a_xy, default_id).expect("Z_A");
        let z_b = sm2_compute_z(&pk_b_xy, default_id).expect("Z_B");

        let a_sk_bytes: [u8; 32] = a_sk.to_bytes().into();
        let b_sk_bytes: [u8; 32] = b_sk.to_bytes().into();
        let ra_sk_bytes: [u8; 32] = ra_sk.to_bytes().into();
        let rb_sk_bytes: [u8; 32] = rb_sk.to_bytes().into();

        let pms_a = compute_tlcp_ecdhe_pms(
            &pk_a_xy,
            &a_sk_bytes,
            &ra_xy,
            &ra_sk_bytes,
            &pk_b_xy,
            &rb_xy,
            &z_a,
            &z_b,
            48,
        )
        .expect("A PMS");

        // B is the responder: same Z order (Z_A first, Z_B second)
        // per GB/T 32918 §6.4 and GmSSL's sm2_key_exchange.
        let pms_b = compute_tlcp_ecdhe_pms(
            &pk_b_xy,
            &b_sk_bytes,
            &rb_xy,
            &rb_sk_bytes,
            &pk_a_xy,
            &ra_xy,
            &z_a,
            &z_b,
            48,
        )
        .expect("B PMS");

        assert_eq!(pms_a.len(), 48, "TLCP PMS must be 48 bytes");
        assert_eq!(pms_a, pms_b, "A and B must compute the same PMS");
        assert!(pms_a.iter().any(|b| *b != 0), "PMS must not be all zeros");
    }

    /// Z is deterministic for identical input.
    #[test]
    fn sm2_compute_z_known_vector() {
        let pub_xy = [0x42u8; 64];
        let user_id = b"1234567812345678";

        let z1 = sm2_compute_z(&pub_xy, user_id).expect("z1");
        let z2 = sm2_compute_z(&pub_xy, user_id).expect("z2");
        assert_eq!(z1, z2, "Z must be deterministic for identical input");
        assert_eq!(z1.len(), 32);

        // Different user ID → different Z.
        let z3 = sm2_compute_z(&pub_xy, b"different-id-here!!").expect("z3");
        assert_ne!(z1, z3, "Z must vary with user ID");

        // Different pub key → different Z.
        let mut pub_xy2 = [0x42u8; 64];
        pub_xy2[0] = 0x43;
        let z4 = sm2_compute_z(&pub_xy2, user_id).expect("z4");
        assert_ne!(z1, z4, "Z must vary with public key");
    }

    /// Cross-validation against the gmssl master C implementation
    /// (`src/sm3.c::sm3_update + sm3_finish`):
    ///
    ///   Z(G) = SM3(ENTL=0x0080 || ID || a || b || x_G || y_G || x_G || y_G)
    ///        = 5b32bfe35482899b195d72c09d33ccdb465b2ded883240ff91f120a68bc91de8
    ///
    /// Verified by linking against `libgmssl.dylib` and printing the
    /// result — `gmssl SM3 = 5b32bfe35482899b...`.
    #[test]
    fn sm2_compute_z_generator_known_vector() {
        let g_xy: [u8; 64] = [
            0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39,
            0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89,
            0x33, 0x4C, 0x74, 0xC7, 0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD,
            0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
            0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
        ];
        let expected = [
            0x5b, 0x32, 0xbf, 0xe3, 0x54, 0x82, 0x89, 0x9b, 0x19, 0x5d, 0x72, 0xc0, 0x9d, 0x33,
            0xcc, 0xdb, 0x46, 0x5b, 0x2d, 0xed, 0x88, 0x32, 0x40, 0xff, 0x91, 0xf1, 0x20, 0xa6,
            0x8b, 0xc9, 0x1d, 0xe8,
        ];
        let actual = sm2_compute_z(&g_xy, b"1234567812345678").expect("Z(G)");
        assert_eq!(actual, expected, "Z(G) must match gmssl C implementation");
    }
}
