//! G1 curve point operations
//!
//! G1: y² = x³ + 5 over Fp
//! Points use Jacobian projective coordinates: (X:Y:Z) representing (X/Z², Y/Z³)

use super::{Identity, ScalarMul};
use crate::arith::z256::Z256;
use crate::arith::{FieldElement, Fp};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// G1 point in Jacobian projective coordinates
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct G1Point {
    pub x: Fp,
    pub y: Fp,
    pub z: Fp,
}

impl G1Point {
    /// Create a new point (not checked to be on curve)
    pub fn new(x: Fp, y: Fp, z: Fp) -> Self {
        Self { x, y, z }
    }

    /// Create from affine coordinates
    pub fn from_affine(x: Fp, y: Fp) -> Self {
        Self { x, y, z: Fp::ONE }
    }

    /// Convert to affine coordinates (returns None if point is at infinity)
    pub fn to_affine(&self) -> Option<(Fp, Fp)> {
        if self.is_identity() {
            return None;
        }
        let z_inv = self.z.inv()?;
        let z_inv2 = z_inv.square();
        let z_inv3 = z_inv2.mul(&z_inv);
        let x = self.x.mul(&z_inv2);
        let y = self.y.mul(&z_inv3);
        Some((x, y))
    }

    /// Point doubling: 2*P
    pub fn double(&self) -> Self {
        if self.is_identity() {
            return Self::identity();
        }

        // Formula for Jacobian doubling:
        // λ1 = 3*X²
        // λ2 = 4*X*Y²
        // λ3 = 8*Y⁴
        // X' = λ1² - 2*λ2
        // Y' = λ1*(λ2 - X') - λ3
        // Z' = 2*Y*Z

        let x2 = self.x.square();
        let y2 = self.y.square();
        let y4 = y2.square();

        let lambda1 = x2.add(&x2).add(&x2); // 3*X²
        let lambda2 = self.x.mul(&y2).double().double(); // 4*X*Y²
        let lambda3 = y4.double().double().double(); // 8*Y⁴

        let x_prime = lambda1.square().sub(&lambda2.double());
        let y_prime = lambda1.mul(&lambda2.sub(&x_prime)).sub(&lambda3);
        let z_prime = self.y.mul(&self.z).double();

        Self::new(x_prime, y_prime, z_prime)
    }

    /// Point addition: P + Q (mixed: P projective, Q affine)
    pub fn add_mixed(&self, q: &G1Affine) -> Self {
        if self.is_identity() {
            return q.to_projective();
        }
        if q.is_identity() {
            return *self;
        }

        // Z², Z³
        let z2 = self.z.square();
        let z3 = z2.mul(&self.z);

        // U2 = Xq * Z², S2 = Yq * Z³
        let u2 = q.x.mul(&z2);
        let s2 = q.y.mul(&z3);

        if self.x == u2 {
            if self.y == s2 {
                return self.double();
            } else {
                return Self::identity();
            }
        }

        // H = U2 - X, R = S2 - Y
        let h = u2.sub(&self.x);
        let r = s2.sub(&self.y);

        // H², H³
        let h2 = h.square();
        let h3 = h2.mul(&h);

        // X' = R² - H³ - 2*X*H²
        let x_prime = r.square().sub(&h3).sub(&self.x.mul(&h2).double());

        // Y' = R*(X*H² - X') - Y*H³
        let y_prime = r.mul(&self.x.mul(&h2).sub(&x_prime)).sub(&self.y.mul(&h3));

        // Z' = Z * H
        let z_prime = self.z.mul(&h);

        Self::new(x_prime, y_prime, z_prime)
    }

    /// Point addition: P + Q (both projective)
    pub fn add(&self, other: &Self) -> Self {
        if self.is_identity() {
            return *other;
        }
        if other.is_identity() {
            return *self;
        }

        // Z1², Z2²
        let z1_2 = self.z.square();
        let z2_2 = other.z.square();

        // U1 = X1 * Z2², U2 = X2 * Z1²
        let u1 = self.x.mul(&z2_2);
        let u2 = other.x.mul(&z1_2);

        // S1 = Y1 * Z2³, S2 = Y2 * Z1³
        let z2_3 = z2_2.mul(&other.z);
        let z1_3 = z1_2.mul(&self.z);
        let s1 = self.y.mul(&z2_3);
        let s2 = other.y.mul(&z1_3);

        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            } else {
                return Self::identity();
            }
        }

        // H = U2 - U1, R = 2*(S2 - S1)  [note: R is doubled for optimized formula]
        let h = u2.sub(&u1);
        let r = s2.sub(&s1).double(); // r = 2*(S2 - S1)

        // H², I = 4*H², J = H*I
        let h2 = h.square();
        let i = h2.double().double();
        let j = h.mul(&i);

        // V = U1 * I
        let v = u1.mul(&i);

        // X3 = R² - J - 2*V
        let x3 = r.square().sub(&j).sub(&v.double());

        // Y3 = R*(V - X3) - 2*S1*J
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).double());

        // Z3 = ((Z1 + Z2)² - Z1² - Z2²) * H
        let z_sum = self.z.add(&other.z);
        let z3 = z_sum.square().sub(&z1_2).sub(&z2_2).mul(&h);

        Self::new(x3, y3, z3)
    }

    /// Constant-time point doubling.
    /// No data-dependent branches; safe against timing side channels.
    pub fn double_ct(&self) -> Self {
        // For the identity point (z=0), doubling formula naturally produces identity:
        // z' = 2*y*z = 0, so result is still identity.
        // No early return needed.
        let x2 = self.x.square();
        let y2 = self.y.square();
        let y4 = y2.square();

        let lambda1 = x2.add(&x2).add(&x2); // 3*X²
        let lambda2 = self.x.mul(&y2).double().double(); // 4*X*Y²
        let lambda3 = y4.double().double().double(); // 8*Y⁴

        let x_prime = lambda1.square().sub(&lambda2.double());
        let y_prime = lambda1.mul(&lambda2.sub(&x_prime)).sub(&lambda3);
        let z_prime = self.y.mul(&self.z).double();

        Self::new(x_prime, y_prime, z_prime)
    }

    /// Constant-time point addition.
    /// Handles all edge cases (identity, P==Q, P==-Q) without branching.
    pub fn add_ct(&self, other: &Self) -> Self {
        // Detect identity points in constant time
        let self_is_id = self.z.ct_eq(&Fp::ZERO);
        let other_is_id = other.z.ct_eq(&Fp::ZERO);

        let z1_2 = self.z.square();
        let z2_2 = other.z.square();

        let u1 = self.x.mul(&z2_2);
        let u2 = other.x.mul(&z1_2);

        let z2_3 = z2_2.mul(&other.z);
        let z1_3 = z1_2.mul(&self.z);
        let s1 = self.y.mul(&z2_3);
        let s2 = other.y.mul(&z1_3);

        // Constant-time comparisons
        let u_eq = u1.ct_eq(&u2);
        let s_eq = s1.ct_eq(&s2);
        // Only treat as double/inverse if neither point is identity
        let is_double = u_eq & s_eq & (!self_is_id) & (!other_is_id);
        let is_inverse = u_eq & (!s_eq) & (!self_is_id) & (!other_is_id);

        // --- Compute standard addition result (assumes u1 != u2) ---
        let h = u2.sub(&u1);
        let r = s2.sub(&s1).double();
        let h2 = h.square();
        let i = h2.double().double();
        let j = h.mul(&i);
        let v = u1.mul(&i);
        let x3_add = r.square().sub(&j).sub(&v.double());
        let y3_add = r.mul(&v.sub(&x3_add)).sub(&s1.mul(&j).double());
        let z_sum = self.z.add(&other.z);
        let z3_add = z_sum.square().sub(&z1_2).sub(&z2_2).mul(&h);
        let add_result = Self::new(x3_add, y3_add, z3_add);

        // --- Compute doubling result (for P == Q case) ---
        let double_result = self.double_ct();

        // --- Identity (for P == -Q case) ---
        let identity = Self::identity();

        // Base selection: if self is identity, return other; if other is identity, return self
        let base = Self::conditional_select(&add_result, other, self_is_id);
        let base = Self::conditional_select(&base, self, other_is_id);

        // Override: double if P==Q, identity if P==-Q (only when both are non-identity)
        let result = Self::conditional_select(&base, &double_result, is_double);
        Self::conditional_select(&result, &identity, is_inverse)
    }

    /// Constant-time scalar multiplication using double-and-add-always pattern.
    /// No data-dependent branches on the scalar value.
    pub fn scalar_mul_ct(&self, scalar: &Z256) -> Self {
        let mut result = Self::identity();

        // Process bits from most significant to least significant (left-to-right)
        // Using "double-and-add-always": always perform both add and dummy add,
        // then conditionally select.
        for i in (0..256).rev() {
            result = result.double_ct();
            let bit = scalar.ct_bit(i);
            let added = result.add_ct(self);
            result = Self::conditional_select(&result, &added, bit);
        }

        result
    }

    /// Negation: -P
    pub fn neg(&self) -> Self {
        Self::new(self.x, self.y.neg(), self.z)
    }

    /// Check if point is on curve
    pub fn is_on_curve(&self) -> bool {
        if self.is_identity() {
            return true;
        }
        match self.to_affine() {
            Some((x, y)) => super::is_on_curve_g1(&x, &y),
            None => false,
        }
    }
}

impl Identity for G1Point {
    fn identity() -> Self {
        Self {
            x: Fp::ONE,
            y: Fp::ONE,
            z: Fp::ZERO,
        }
    }

    fn is_identity(&self) -> bool {
        self.z.is_zero()
    }
}

impl ScalarMul for G1Point {
    fn scalar_mul(&self, scalar: &Z256) -> Self {
        // Constant-time double-and-add-always
        // No data-dependent branches on scalar value
        self.scalar_mul_ct(scalar)
    }
}

impl PartialEq for G1Point {
    fn eq(&self, other: &Self) -> bool {
        // Compare in Jacobian: X1/Z1² == X2/Z2², Y1/Z1³ == Y2/Z2³
        if self.is_identity() && other.is_identity() {
            return true;
        }
        if self.is_identity() || other.is_identity() {
            return false;
        }

        let z1_2 = self.z.square();
        let z2_2 = other.z.square();
        let z1_3 = z1_2.mul(&self.z);
        let z2_3 = z2_2.mul(&other.z);

        let x1 = self.x.mul(&z2_2);
        let x2 = other.x.mul(&z1_2);
        let y1 = self.y.mul(&z2_3);
        let y2 = other.y.mul(&z1_3);

        x1 == x2 && y1 == y2
    }
}

impl Eq for G1Point {}

impl ConditionallySelectable for G1Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            z: Fp::conditional_select(&a.z, &b.z, choice),
        }
    }
}

/// G1 point in affine coordinates
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct G1Affine {
    pub x: Fp,
    pub y: Fp,
}

impl G1Affine {
    pub fn new(x: Fp, y: Fp) -> Self {
        Self { x, y }
    }

    pub fn to_projective(&self) -> G1Point {
        G1Point::from_affine(self.x, self.y)
    }

    pub fn is_identity(&self) -> bool {
        false // Affine coordinates can't represent infinity
    }
}

impl Identity for G1Affine {
    fn identity() -> Self {
        // This is a placeholder; affine can't truly represent infinity
        Self {
            x: Fp::ZERO,
            y: Fp::ZERO,
        }
    }

    fn is_identity(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g1_generator() {
        // A valid point on G1: y^2 = x^3 + 5
        // x = 4, y = 0x40dae26669315487192e30c1c62ed4b91012bf119754206cae9249e0f0e51098
        let x = Fp::from_u64(4);
        let y = Fp::from_raw(crate::arith::z256::Z256([
            0xae9249e0f0e51098,
            0x1012bf119754206c,
            0x192e30c1c62ed4b9,
            0x40dae26669315487,
        ]));

        let p = G1Point::from_affine(x, y);
        assert!(p.is_on_curve());
    }

    #[test]
    fn test_g1_double() {
        let x = Fp::from_u64(1);
        let y = Fp::from_u64(2);
        let p = G1Point::from_affine(x, y);
        let _d = p.double();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_scalar_mul() {
        let x = Fp::from_u64(1);
        let y = Fp::from_u64(2);
        let p = G1Point::from_affine(x, y);
        let two_p = p.scalar_mul(&Z256([2, 0, 0, 0]));
        let doubled = p.double();
        assert_eq!(two_p, doubled);
    }

    #[test]
    fn test_ct_add_identity() {
        let p = crate::pairing::params::g1_generator();
        let identity = G1Point::identity();
        // identity + P should = P
        let sum_ct = identity.add_ct(&p);
        let sum_old = identity.add(&p);
        assert_eq!(sum_ct, sum_old, "add_ct(identity, P) != add(identity, P)");
    }

    #[test]
    fn test_ct_double() {
        let p = crate::pairing::params::g1_generator();
        let double_ct = p.double_ct();
        let double_old = p.double();
        assert_eq!(double_ct, double_old, "double_ct != double");
    }

    #[test]
    fn test_ct_scalar_mul_generator() {
        let p = crate::pairing::params::g1_generator();
        let one = Z256([1, 0, 0, 0]);
        let result = p.scalar_mul_ct(&one);
        // 1*P should equal P
        // Compare affine coordinates
        let (rx, ry) = result.to_affine().unwrap();
        let (px, py) = p.to_affine().unwrap();
        assert_eq!(rx, px, "1*P x mismatch");
        assert_eq!(ry, py, "1*P y mismatch");
    }
}
