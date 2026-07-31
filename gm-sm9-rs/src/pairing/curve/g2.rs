//! G2 twist curve point operations
//!
//! G2: y² = x³ + b*u over Fp2 (twist of G1)
//! Points use Jacobian projective coordinates

use super::{Identity, ScalarMul};
use crate::arith::z256::Z256;
use crate::arith::{FieldElement, Fp2};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// G2 point in Jacobian projective coordinates
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct G2Point {
    pub x: Fp2,
    pub y: Fp2,
    pub z: Fp2,
}

impl G2Point {
    pub fn new(x: Fp2, y: Fp2, z: Fp2) -> Self {
        Self { x, y, z }
    }

    pub fn from_affine(x: Fp2, y: Fp2) -> Self {
        Self { x, y, z: Fp2::ONE }
    }

    pub fn to_affine(&self) -> Option<(Fp2, Fp2)> {
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

    pub fn double(&self) -> Self {
        if self.is_identity() {
            return Self::identity();
        }

        // Same formula as G1 but over Fp2
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

    pub fn add(&self, other: &Self) -> Self {
        if self.is_identity() {
            return *other;
        }
        if other.is_identity() {
            return *self;
        }

        let z1_2 = self.z.square();
        let z2_2 = other.z.square();

        let u1 = self.x.mul(&z2_2);
        let u2 = other.x.mul(&z1_2);

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

        let h = u2.sub(&u1);
        let r = s2.sub(&s1);

        let h2 = h.square();
        let j = h.mul(&h2); // H³
        let v = u1.mul(&h2); // U1*H²

        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j));
        let z3 = self.z.mul(&other.z).mul(&h);

        Self::new(x3, y3, z3)
    }

    /// Constant-time point doubling.
    /// No data-dependent branches; safe against timing side channels.
    pub fn double_ct(&self) -> Self {
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
        let self_is_id = self.z.ct_eq(&Fp2::ZERO);
        let other_is_id = other.z.ct_eq(&Fp2::ZERO);

        let z1_2 = self.z.square();
        let z2_2 = other.z.square();

        let u1 = self.x.mul(&z2_2);
        let u2 = other.x.mul(&z1_2);

        let z2_3 = z2_2.mul(&other.z);
        let z1_3 = z1_2.mul(&self.z);
        let s1 = self.y.mul(&z2_3);
        let s2 = other.y.mul(&z1_3);

        let u_eq = u1.ct_eq(&u2);
        let s_eq = s1.ct_eq(&s2);
        // Only treat as double/inverse if neither point is identity
        let is_double = u_eq & s_eq & (!self_is_id) & (!other_is_id);
        let is_inverse = u_eq & (!s_eq) & (!self_is_id) & (!other_is_id);

        // Standard addition result
        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        let h2 = h.square();
        let j = h.mul(&h2); // H³
        let v = u1.mul(&h2);
        let x3_add = r.square().sub(&j).sub(&v.double());
        let y3_add = r.mul(&v.sub(&x3_add)).sub(&s1.mul(&j));
        let z3_add = self.z.mul(&other.z).mul(&h);
        let add_result = Self::new(x3_add, y3_add, z3_add);

        let double_result = self.double_ct();
        let identity = Self::identity();

        // Base: if self is identity → other; if other is identity → self
        let base = Self::conditional_select(&add_result, other, self_is_id);
        let base = Self::conditional_select(&base, self, other_is_id);

        let result = Self::conditional_select(&base, &double_result, is_double);
        Self::conditional_select(&result, &identity, is_inverse)
    }

    /// Constant-time scalar multiplication using double-and-add-always pattern.
    pub fn scalar_mul_ct(&self, scalar: &Z256) -> Self {
        let mut result = Self::identity();

        for i in (0..256).rev() {
            result = result.double_ct();
            let bit = scalar.ct_bit(i);
            let added = result.add_ct(self);
            result = Self::conditional_select(&result, &added, bit);
        }

        result
    }

    pub fn neg(&self) -> Self {
        Self::new(self.x, self.y.neg(), self.z)
    }

    pub fn is_on_curve(&self) -> bool {
        if self.is_identity() {
            return true;
        }
        match self.to_affine() {
            Some((x, y)) => super::is_on_curve_g2(&x, &y),
            None => false,
        }
    }
}

impl Identity for G2Point {
    fn identity() -> Self {
        Self {
            x: Fp2::ONE,
            y: Fp2::ONE,
            z: Fp2::ZERO,
        }
    }

    fn is_identity(&self) -> bool {
        self.z.is_zero()
    }
}

impl ScalarMul for G2Point {
    fn scalar_mul(&self, scalar: &Z256) -> Self {
        // Constant-time double-and-add-always
        self.scalar_mul_ct(scalar)
    }
}

impl PartialEq for G2Point {
    fn eq(&self, other: &Self) -> bool {
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

impl Eq for G2Point {}

impl ConditionallySelectable for G2Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: Fp2::conditional_select(&a.x, &b.x, choice),
            y: Fp2::conditional_select(&a.y, &b.y, choice),
            z: Fp2::conditional_select(&a.z, &b.z, choice),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::Fp;

    #[test]
    fn test_g2_identity() {
        let id = G2Point::identity();
        assert!(id.is_identity());
    }

    #[test]
    fn test_g2_double() {
        let x = Fp2::new(Fp::from_u64(1), Fp::ZERO);
        let y = Fp2::new(Fp::from_u64(2), Fp::ZERO);
        let p = G2Point::from_affine(x, y);
        let _d = p.double();
    }
}
