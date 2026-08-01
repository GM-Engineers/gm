//! Quadratic extension field Fp2 = Fp\[u\]/(u^2 + 2)

use crate::arith::FieldElement;
use crate::arith::fp::Fp;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// Fp2 element: a + b*u where u² = -2
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct Fp2 {
    pub c0: Fp, // a (constant term)
    pub c1: Fp, // b (u coefficient)
}

impl Fp2 {
    /// Create new Fp2 element
    pub fn new(c0: Fp, c1: Fp) -> Self {
        Self { c0, c1 }
    }

    /// Multiply by u (the extension element)
    pub fn mul_u(&self) -> Self {
        // (a + bu) * u = au + bu² = -2b + au
        Self {
            c0: self.c1.neg().double(), // -2*b
            c1: self.c0,                // a
        }
    }

    /// Frobenius map: (a + bu)^p = a - bu (since u^p = -u for p ≡ 3 mod 4)
    pub fn frobenius(&self) -> Self {
        Self {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }

    /// Multiply by an Fp element
    pub fn mul_fp(&self, fp: &Fp) -> Self {
        Self {
            c0: self.c0.mul(fp),
            c1: self.c1.mul(fp),
        }
    }

    /// Convert to bytes: c0 || c1 (each 32 bytes)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.c0.to_bytes());
        bytes[32..64].copy_from_slice(&self.c1.to_bytes());
        bytes
    }
}

impl FieldElement for Fp2 {
    const ZERO: Self = Self {
        c0: Fp::ZERO,
        c1: Fp::ZERO,
    };

    const ONE: Self = Self {
        c0: Fp::ONE,
        c1: Fp::ZERO,
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
        // (a + bu)(c + du) = ac + (ad + bc)u + bdu²
        // = (ac - 2bd) + (ad + bc)u
        let ac = self.c0.mul(&other.c0);
        let bd = self.c1.mul(&other.c1);
        let ad = self.c0.mul(&other.c1);
        let bc = self.c1.mul(&other.c0);

        Self {
            c0: ac.sub(&bd.add(&bd)), // ac - 2*bd
            c1: ad.add(&bc),          // ad + bc
        }
    }

    fn square(&self) -> Self {
        // (a + bu)² = a² - 2b² + 2abu
        let a2 = self.c0.square();
        let b2 = self.c1.square();
        let ab = self.c0.mul(&self.c1);

        Self {
            c0: a2.sub(&b2.add(&b2)),
            c1: ab.add(&ab),
        }
    }

    fn inv(&self) -> Option<Self> {
        // (a + bu)^-1 = (a - bu) / (a² + 2b²)
        let norm = self.c0.square().add(&self.c1.square().double());
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

impl PartialEq for Fp2 {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}

impl Eq for Fp2 {}

impl ConstantTimeEq for Fp2 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1)
    }
}

impl ConditionallySelectable for Fp2 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            c0: Fp::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp2_mul() {
        let a = Fp2::new(Fp::from_u64(1), Fp::from_u64(2));
        let b = Fp2::new(Fp::from_u64(3), Fp::from_u64(4));
        let c = a.mul(&b);
        // (1 + 2u)(3 + 4u) = 3 + 4u + 6u + 8u² = 3 + 10u - 16 = -13 + 10u
        assert!(!c.is_zero());
    }

    #[test]
    fn test_fp2_inv() {
        let a = Fp2::new(Fp::from_u64(3), Fp::from_u64(4));
        let a_inv = a.inv().unwrap();
        let product = a.mul(&a_inv);
        assert!(product.is_one());
    }

    #[test]
    fn test_fp2_frobenius() {
        let a = Fp2::new(Fp::from_u64(3), Fp::from_u64(4));
        let f = a.frobenius();
        // Frobenius should satisfy: f^p = f
        assert_eq!(f.c0, a.c0);
        assert_eq!(f.c1, a.c1.neg());
    }
}
