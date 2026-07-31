//! Elliptic curve points for SM9
//!
//! - G1: Points on y² = x³ + 5 over Fp
//! - G2: Twist points over Fp2

use crate::arith::{FieldElement, Fp, Fp2};

/// G1 curve: y² = x³ + 5 over Fp
pub mod g1;

/// G2 twist curve over Fp2
pub mod g2;

pub use g1::G1Point;
pub use g2::G2Point;

/// Curve coefficient for SM9: a = 0, b = 5
/// Note: Fp::from_raw is not const, so we use lazy_static or init at runtime
pub fn curve_b() -> Fp {
    Fp::from_raw(crate::arith::z256::Z256([5, 0, 0, 0]))
}

/// Point at infinity (identity element)
pub trait Identity {
    fn identity() -> Self;
    fn is_identity(&self) -> bool;
}

/// Scalar multiplication trait (constant-time)
pub trait ScalarMul {
    fn scalar_mul(&self, scalar: &crate::arith::z256::Z256) -> Self;
}

/// Check if a point is on the curve y² = x³ + b
pub fn is_on_curve_g1(x: &Fp, y: &Fp) -> bool {
    let y2 = y.square();
    let x3 = x.square().mul(x);
    let rhs = x3.add(&curve_b());
    y2 == rhs
}

/// Check if a twist point is on the curve
pub fn is_on_curve_g2(x: &Fp2, y: &Fp2) -> bool {
    let y2 = y.square();
    let x3 = x.square().mul(x);
    // For twist: y² = x³ + b * u where u is the Fp2 generator (u² = -2)
    let b_u = Fp2::new(Fp::ZERO, curve_b());
    let rhs = x3.add(&b_u);
    y2 == rhs
}
