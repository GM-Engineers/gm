//! Quartic extension field Fp4 = Fp2\[v\]/(v^2 - u)
//!
//! where u is the Fp2 generator with u² = -2

use crate::arith::FieldElement;
use crate::arith::{fp::Fp, fp2::Fp2};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

/// Fp4 element: a + b*v where v² = u (Fp2 generator)
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct Fp4 {
    pub c0: Fp2, // a
    pub c1: Fp2, // b
}

impl Fp4 {
    pub fn new(c0: Fp2, c1: Fp2) -> Self {
        Self { c0, c1 }
    }

    /// Multiply by v
    pub fn mul_v(&self) -> Self {
        // (a + bv) * v = av + bv² = bu + av
        Self {
            c0: self.c1.mul_u(), // b * u
            c1: self.c0,         // a
        }
    }

    /// Frobenius map (power p)
    pub fn frobenius(&self) -> Self {
        // v^p = v^(p-1) * v = (v²)^((p-1)/2) * v = u^((p-1)/2) * v
        // For p ≡ 3 mod 4, u^((p-1)/2) = -1, so v^p = -v
        Self {
            c0: self.c0.frobenius(),
            c1: self.c1.frobenius().neg(),
        }
    }

    /// Conjugate: copy c0, negate c1
    /// GmSSL: sm9_z256_fp4_conjugate
    pub fn conjugate(&self) -> Self {
        Self {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }

    /// Frobenius squared (power p²) = conjugate in Fp4
    /// GmSSL: sm9_z256_fp4_frobenius2 = sm9_z256_fp4_conjugate
    /// Result: copy c0, negate c1
    pub fn frobenius_sq(&self) -> Self {
        self.conjugate()
    }

    /// Multiply by an Fp element
    pub fn mul_fp(&self, fp: &Fp) -> Self {
        Self {
            c0: self.c0.mul_fp(fp),
            c1: self.c1.mul_fp(fp),
        }
    }

    /// Convert to bytes: c0 || c1 (each 64 bytes)
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        bytes[0..64].copy_from_slice(&self.c0.to_bytes());
        bytes[64..128].copy_from_slice(&self.c1.to_bytes());
        bytes
    }
}

impl FieldElement for Fp4 {
    const ZERO: Self = Self {
        c0: Fp2::ZERO,
        c1: Fp2::ZERO,
    };

    const ONE: Self = Self {
        c0: Fp2::ONE,
        c1: Fp2::ZERO,
    };

    fn add(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
        }
    }

    fn sub(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.sub(&other.c0),
            c1: self.c1.sub(&other.c1),
        }
    }

    fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    fn mul(&self, other: &Self) -> Self {
        // (a + bv)(c + dv) = ac + (ad + bc)v + bdv²
        // = (ac + bdu) + (ad + bc)v
        let ac = self.c0.mul(&other.c0);
        let bd = self.c1.mul(&other.c1);
        let ad = self.c0.mul(&other.c1);
        let bc = self.c1.mul(&other.c0);

        Self {
            c0: ac.add(&bd.mul_u()), // ac + bd*u
            c1: ad.add(&bc),         // ad + bc
        }
    }

    fn square(&self) -> Self {
        // (a + bv)² = a² + b²u + 2abv
        let a2 = self.c0.square();
        let b2 = self.c1.square();
        let ab = self.c0.mul(&self.c1);

        Self {
            c0: a2.add(&b2.mul_u()),
            c1: ab.add(&ab),
        }
    }

    fn inv(&self) -> Option<Self> {
        // (a + bv)^-1 = (a - bv) / (a² - b²u)
        let norm = self.c0.square().sub(&self.c1.square().mul_u());
        let norm_inv = norm.inv()?;

        Some(Self {
            c0: self.c0.mul(&norm_inv),
            c1: self.c1.neg().mul(&norm_inv),
        })
    }

    fn double(&self) -> Self {
        self.add(self)
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    fn is_one(&self) -> bool {
        self.c0.is_one() && self.c1.is_zero()
    }
}

impl PartialEq for Fp4 {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}

impl Eq for Fp4 {}

impl ConditionallySelectable for Fp4 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            c0: Fp2::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp2::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::fp::Fp;

    #[test]
    fn test_fp4_mul() {
        let a = Fp4::new(Fp2::ONE, Fp2::new(Fp::from_u64(1), Fp::ZERO));
        let b = Fp4::new(Fp2::ONE, Fp2::new(Fp::from_u64(2), Fp::ZERO));
        let c = a.mul(&b);
        assert!(!c.is_zero());
    }

    #[test]
    fn test_fp4_inv() {
        let a = Fp4::new(
            Fp2::new(Fp::from_u64(3), Fp::ZERO),
            Fp2::new(Fp::from_u64(4), Fp::ZERO),
        );
        let a_inv = a.inv().unwrap();
        let product = a.mul(&a_inv);
        assert!(product.is_one());
    }
}
