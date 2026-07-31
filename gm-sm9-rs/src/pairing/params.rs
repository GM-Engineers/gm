//! SM9 standard parameters from GM/T 0044-2016
//!
//! These are the official curve parameters and generator points
//! for the SM9 identity-based cryptographic algorithm.

use crate::pairing::curve::{g1::G1Point, g2::G2Point};
use crate::arith::z256::Z256;
use crate::arith::{Fp, Fp2};

/// Prime p for SM9 BN curve
/// p = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
pub const SM9_P: Z256 = Z256([
    0xE351457DE56F9B27,
    0x1A7AEEDB21F2934B,
    0xFF58EC745D603AB4,
    0xB640000002A3A6F1,
]);

/// Curve coefficient b = 5
pub const SM9_B: Z256 = Z256([
    0x0000000000000005,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
]);

/// G1 generator P1 (from GM/T 0044-2016)
/// x_P1 = 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
/// y_P1 = 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616
///
/// GmSSL stores these as little-endian uint32_t\[8\], where each u64 contains
/// two u32 limbs with the lower 32 bits being the active limb.
pub const P1_X: Z256 = Z256([
    0xE8C4E481_7C66DDDD,
    0xE1E40869_09DC3280,
    0xF5ED0704_487D01D6,
    0x93DE051D_62BF718F,
]);

pub const P1_Y: Z256 = Z256([
    0x0C464CD7_0A3EA616,
    0x1C1C00CB_FA602435,
    0x63106512_5C395BBC,
    0x21FE8DDA_4F21E607,
]);

/// G2 generator P2 (from GM/T 0044-2016)
/// P2 is on the twist curve E'(Fp2)
/// x_P2 = (x0, x1) where:
///   x0 = 0x85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141
///   x1 = 0x3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B
/// y_P2 = (y0, y1) where:
///   y0 = 0x17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96
///   y1 = 0xA7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7
pub const P2_X0: Z256 = Z256([
    0xF9B7213B_AF82D65B,
    0xEE265948_D19C17AB,
    0xD2AAB97F_D34EC120,
    0x37227552_92130B08,
]);

pub const P2_X1: Z256 = Z256([
    0x54806C11_D8806141,
    0xF1DD2C19_0F5E93C4,
    0x597B6027_B441A01F,
    0x85AEF3D0_78640C98,
]);

pub const P2_Y0: Z256 = Z256([
    0x6215BBA5_C999A7C7,
    0x47EFBA98_A71A0811,
    0x5F317015_3D278FF2,
    0xA7CF28D5_19BE3DA6,
]);

pub const P2_Y1: Z256 = Z256([
    0x856DC76B_84EBEB96,
    0x0736A96F_A347C8BD,
    0x66BA0D26_2CBEE6ED,
    0x17509B09_2E845C12,
]);

/// Get the standard G1 generator P1
pub fn g1_generator() -> G1Point {
    // Convert from standard coordinates to Montgomery form
    let x = Fp::from_raw(P1_X);
    let y = Fp::from_raw(P1_Y);
    G1Point::from_affine(x, y)
}

/// Get the standard G2 generator P2
///
/// Fp2 element: c0 + c1*u where u^2 = -2
/// P2 = (x, y) where x = x0 + x1*u, y = y0 + y1*u
pub fn g2_generator() -> G2Point {
    let x0 = Fp::from_raw(P2_X0);
    let x1 = Fp::from_raw(P2_X1);
    let y0 = Fp::from_raw(P2_Y0);
    let y1 = Fp::from_raw(P2_Y1);

    let x = Fp2::new(x0, x1);
    let y = Fp2::new(y0, y1);
    G2Point::from_affine(x, y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p1_on_curve() {
        let p1 = g1_generator();
        assert!(p1.is_on_curve(), "P1 must be on the curve");
    }

    #[test]
    fn test_p2_on_curve() {
        let p2 = g2_generator();
        assert!(p2.is_on_curve(), "P2 must be on the twist curve");
    }
}
