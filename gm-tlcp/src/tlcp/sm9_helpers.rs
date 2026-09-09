//! SM9 wire-format helpers — G1Point ↔ 65-byte uncompressed bytes.
//!
//! Used by SM9 IBSDH (R-4.2) to serialize `R_A` / `R_B` on the wire.
//! The wire layout matches what `gm_sm9_rs::key_exchange::g1_to_kdf_bytes`
//! (a private helper in `gm-sm9-rs/src/key_exchange.rs:401`) already
//! emits internally for the KDF input: `0x04 || x (32 bytes BE) ||
//! y (32 bytes BE)`. We reimplement this here as a public, cross-module
//! helper so the IBSDH state machine (in `src/tlcp/mod.rs`) can
//! round-trip between `gm_sm9_rs::G1Point` and the TLCP wire bytes
//! without depending on gm-sm9-rs's private internals.
//!
//! Per GM/T 0044.3-2016 §7.2 (and the matching GB/T 38636-2020
//! §6.4.5.4 reading used for IBSDH suites E055 / E015), the IBSDH
//! SKE body is:
//!
//! ```text
//!   uint16 ra_len || ra (65 bytes, uncompressed SM9 G1 point)
//!   uint16 rb_len || rb (65 bytes, uncompressed SM9 G1 point)
//!   uint16 sb_len || sb (32 bytes, SM3 hash per SM9 §7.2 B6)
//! ```
//!
//! `ra` / `rb` use the standard SEC1 uncompressed form. We do NOT
//! support the compressed form (no known TLCP peer emits it; the
//! gm-sm9-rs KDF code also expects uncompressed).

use crate::error::TlcpError;
use gm_sm9_rs::arith::Fp;
use gm_sm9_rs::pairing::curve::g1::G1Point;

/// Wire length of an uncompressed SM9 G1 point: `0x04 + x + y = 1 + 32 + 32`.
pub const SM9_G1_WIRE_LEN: usize = 65;

/// Serialize a `gm_sm9_rs::G1Point` to the 65-byte uncompressed wire
/// form used by SM9 IBSDH `R_A` / `R_B`:
/// `0x04 || x (32 bytes BE) || y (32 bytes BE)`.
///
/// Returns `Err(TlcpError::InvalidMessage)` if the point is the
/// identity (point at infinity), since the SEC1 uncompressed form
/// has no representation for that case.
pub fn g1_point_to_uncompressed(point: &G1Point) -> Result<Vec<u8>, TlcpError> {
    let (x, y) = point.to_affine().ok_or_else(|| {
        TlcpError::InvalidMessage(
            "SM9 G1Point at infinity — invalid wire form (no SEC1 encoding)".to_string(),
        )
    })?;
    let mut out = Vec::with_capacity(SM9_G1_WIRE_LEN);
    out.push(0x04);
    out.extend_from_slice(&x.to_bytes());
    out.extend_from_slice(&y.to_bytes());
    Ok(out)
}

/// Parse the 65-byte uncompressed wire form back into a
/// `gm_sm9_rs::G1Point`. Returns an error if the input is not
/// exactly `0x04 || x || y` with `x` and `y` each 32 bytes.
///
/// **Note**: this does NOT check that the resulting point lies on
/// the SM9 G1 curve — the parser only enforces the wire shape.
/// Callers that need an on-curve check should call
/// `G1Point::is_on_curve()` after parsing.
pub fn g1_point_from_uncompressed(bytes: &[u8]) -> Result<G1Point, TlcpError> {
    if bytes.len() != SM9_G1_WIRE_LEN {
        return Err(TlcpError::InvalidMessage(format!(
            "SM9 G1Point wire form must be {} bytes, got {}",
            SM9_G1_WIRE_LEN,
            bytes.len()
        )));
    }
    if bytes[0] != 0x04 {
        return Err(TlcpError::InvalidMessage(format!(
            "SM9 G1Point wire form must start with 0x04, got 0x{:02x}",
            bytes[0]
        )));
    }
    let x = Fp::from_bytes(&bytes[1..33])
        .map_err(|e| TlcpError::InvalidMessage(format!("SM9 G1Point x-coord parse: {}", e)))?;
    let y = Fp::from_bytes(&bytes[33..65])
        .map_err(|e| TlcpError::InvalidMessage(format!("SM9 G1Point y-coord parse: {}", e)))?;
    Ok(G1Point::from_affine(x, y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_sm9_rs::Identity;
    use gm_sm9_rs::params::g1_generator;

    #[test]
    fn g1_point_roundtrip_preserves_affine_coords() {
        // Use the G1 generator as a known-valid non-identity point.
        let p = g1_generator();
        let wire = g1_point_to_uncompressed(&p).expect("to_uncompressed");
        assert_eq!(wire.len(), SM9_G1_WIRE_LEN);
        assert_eq!(wire[0], 0x04);
        let p2 = g1_point_from_uncompressed(&wire).expect("from_uncompressed");
        let (x1, y1) = p.to_affine().expect("affine p");
        let (x2, y2) = p2.to_affine().expect("affine p2");
        assert_eq!(x1, x2, "x-coord roundtrip");
        assert_eq!(y1, y2, "y-coord roundtrip");
    }

    #[test]
    fn g1_point_from_uncompressed_rejects_truncated_input() {
        // Too short (no tag byte).
        assert!(g1_point_from_uncompressed(&[]).is_err());
        // Tag present but only 32 + a few bytes.
        let mut short = vec![0x04];
        short.extend_from_slice(&[0u8; 10]);
        assert!(g1_point_from_uncompressed(&short).is_err());
        // 64 bytes (tag + x, no y).
        let mut too_short = vec![0x04];
        too_short.extend_from_slice(&[0u8; 64]);
        assert_eq!(too_short.len(), 65);
        // Actually 65 bytes but no y is impossible since len==65 — we
        // need a different shape: 66 bytes (tag + 33 bytes x + ...).
        let mut too_long = vec![0x04];
        too_long.extend_from_slice(&[0u8; 66]);
        assert!(g1_point_from_uncompressed(&too_long).is_err());
    }

    #[test]
    fn g1_point_from_uncompressed_rejects_wrong_tag() {
        // Any tag other than 0x04 is rejected. We don't support
        // compressed form (0x02 / 0x03) here — a TLCP peer that
        // emits compressed would fail this check, matching the
        // GmSSL convention.
        let mut wrong_tag = vec![0x02]; // compressed form
        wrong_tag.extend_from_slice(&[0u8; 64]);
        assert!(g1_point_from_uncompressed(&wrong_tag).is_err());
        let mut zero_tag = vec![0x00];
        zero_tag.extend_from_slice(&[0u8; 64]);
        assert!(g1_point_from_uncompressed(&zero_tag).is_err());
    }

    #[test]
    fn g1_point_to_uncompressed_rejects_identity() {
        // G1Point::identity() is at infinity; SEC1 uncompressed has
        // no representation. The serializer must reject it.
        let id = G1Point::identity();
        assert!(g1_point_to_uncompressed(&id).is_err());
    }
}
