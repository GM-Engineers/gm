//! Degree-12 extension field Fp12 = Fp4\[w\]/(w³ - v)
//!
//! where v is the Fp4 generator with v² = u (Fp2 generator)
//!
//! Fp12 is the target group GT for the pairing.

use crate::arith::z256::Z256;
use crate::arith::FieldElement;
use crate::arith::{fp::Fp, fp2::Fp2, fp4::Fp4};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

/// Fp12 element: a + b·w + c·w² where w³ = v
/// NOTE: To match GmSSL's convention, we store:
///   c0 = a (constant term)
///   c1 = c (w² coefficient)  <- SWAPPED to match GmSSL
///   c2 = b (w coefficient)   <- SWAPPED to match GmSSL
/// GmSSL's fp12_t is \[Fp4; 3\] where:
///   a\[0\] = c0, a\[1\] = c2, a\[2\] = c1
/// So the element is: a\[0\] + a\[2\]*w + a\[1\]*w²
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct Fp12 {
    pub c0: Fp4, // a (constant term)
    pub c1: Fp4, // c (w² coefficient) - matches GmSSL a[1]
    pub c2: Fp4, // b (w coefficient) - matches GmSSL a[2]
}

impl Fp12 {
    pub fn new(c0: Fp4, c1: Fp4, c2: Fp4) -> Self {
        Self { c0, c1, c2 }
    }

    /// Multiply by w
    pub fn mul_w(&self) -> Self {
        // (a + bw + cw²) * w = aw + bw² + cw³ = cv + aw + bw²
        // In GmSSL convention: c0=a, c1=c, c2=b
        // Result: c0'=c*v, c1'=a, c2'=b
        Self {
            c0: self.c1.mul_v(), // c * v
            c1: self.c0,         // a
            c2: self.c2,         // b
        }
    }

    /// Frobenius map (power p)
    /// Based on GmSSL's sm9_z256_fp12_frobenius
    pub fn frobenius(&self) -> Self {
        // Constants for Frobenius (from GmSSL):
        // ALPHA1 = 0x9ef74015d5a16393f51f5eac13df846c9ec8547b245c54fd1a98dfbd4575299f
        // ALPHA2 = 0x1c753e748601c9929c705db2fd91512a08296b3557ed0186b626197dce4736ca
        // ALPHA3 = 0x9848eec25498cab5b8554ab054ac91e3db043bf50858278239b4ef0f3ee72529
        // ALPHA4 = 0x88f53e748b4917764877b452e8aedfb44c0e91cb8ce2df3e81054fcd94e9c1c4
        // ALPHA5 = 0xaf91aeac819b0e1399399754365bd4bc5e2e7ac4fe76c161048baa79dcc34107

        // NOTE: These constants are already in Montgomery form (from GmSSL SM9_MONT_ALPHA*)
        // Use Fp(raw) directly, NOT Fp::from_raw() which would double-convert
        let alpha1 = Fp(Z256::new([
            0x1a98dfbd4575299f,
            0x9ec8547b245c54fd,
            0xf51f5eac13df846c,
            0x9ef74015d5a16393,
        ]));
        let alpha2 = Fp(Z256::new([
            0xb626197dce4736ca,
            0x08296b3557ed0186,
            0x9c705db2fd91512a,
            0x1c753e748601c992,
        ]));
        let alpha3 = Fp(Z256::new([
            0x39b4ef0f3ee72529,
            0xdb043bf508582782,
            0xb8554ab054ac91e3,
            0x9848eec25498cab5,
        ]));
        let alpha4 = Fp(Z256::new([
            0x81054fcd94e9c1c4,
            0x4c0e91cb8ce2df3e,
            0x4877b452e8aedfb4,
            0x88f53e748b491776,
        ]));
        let alpha5 = Fp(Z256::new([
            0x048baa79dcc34107,
            0x5e2e7ac4fe76c161,
            0x99399754365bd4bc,
            0xaf91aeac819b0e13,
        ]));

        Self {
            c0: Fp4::new(
                self.c0.c0.frobenius(),
                self.c0.c1.frobenius().mul_fp(&alpha3),
            ),
            c1: Fp4::new(
                self.c1.c0.frobenius().mul_fp(&alpha1),
                self.c1.c1.frobenius().mul_fp(&alpha4),
            ),
            c2: Fp4::new(
                self.c2.c0.frobenius().mul_fp(&alpha2),
                self.c2.c1.frobenius().mul_fp(&alpha5),
            ),
        }
    }

    /// Frobenius squared (power p²)
    /// Based on GmSSL's sm9_z256_fp12_frobenius2
    pub fn frobenius_sq(&self) -> Self {
        // Already in Montgomery form
        let alpha2 = Fp(Z256::new([
            0xb626197dce4736ca,
            0x08296b3557ed0186,
            0x9c705db2fd91512a,
            0x1c753e748601c992,
        ]));
        let alpha4 = Fp(Z256::new([
            0x81054fcd94e9c1c4,
            0x4c0e91cb8ce2df3e,
            0x4877b452e8aedfb4,
            0x88f53e748b491776,
        ]));

        Self {
            c0: self.c0.frobenius_sq(),
            c1: self.c1.frobenius_sq().mul_fp(&alpha2),
            c2: self.c2.frobenius_sq().mul_fp(&alpha4),
        }
    }

    /// Frobenius cubed (power p³)
    /// Based on GmSSL's sm9_z256_fp12_frobenius3
    pub fn frobenius_cu(&self) -> Self {
        // Already in Montgomery form (SM9_MONT_BETA)
        let beta = Fp2::new(
            Fp(Z256::new([
                0x39b4ef0f3ee72529,
                0xdb043bf508582782,
                0xb8554ab054ac91e3,
                0x9848eec25498cab5,
            ])),
            Fp::ZERO,
        );

        Self {
            c0: Fp4::new(
                self.c0.c0.frobenius().frobenius().frobenius(),
                self.c0
                    .c1
                    .frobenius()
                    .frobenius()
                    .frobenius()
                    .mul(&beta)
                    .neg(),
            ),
            c1: Fp4::new(
                self.c1.c0.frobenius().frobenius().frobenius().mul(&beta),
                self.c1.c1.frobenius().frobenius().frobenius(),
            ),
            c2: Fp4::new(
                self.c2.c0.frobenius().frobenius().frobenius().neg(),
                self.c2.c1.frobenius().frobenius().frobenius().mul(&beta),
            ),
        }
    }

    /// Frobenius to the 6th power (power p⁶)
    /// Based on GmSSL's sm9_z256_fp12_frobenius6
    /// f^(p^6): conjugate each Fp4 component, then negate the middle one
    pub fn frobenius_six(&self) -> Self {
        Self {
            c0: self.c0.conjugate(),
            c1: self.c1.conjugate().neg(),
            c2: self.c2.conjugate(),
        }
    }

    /// Cyclotomic squaring (optimized for GT elements)
    pub fn cyclotomic_square(&self) -> Self {
        // For elements in the cyclotomic subgroup, we can use a faster formula
        // This is used in final exponentiation
        self.square()
    }

    /// Exponentiation by a Z256 scalar
    pub fn pow(&self, exp: &crate::arith::z256::Z256) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;
        let mut e = *exp;

        while !e.is_zero() {
            if e.0[0] & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.square();
            // Right shift
            let mut carry = 0u64;
            for i in (0..4).rev() {
                let new_carry = e.0[i] << 63;
                e.0[i] = (e.0[i] >> 1) | carry;
                carry = new_carry;
            }
        }

        result
    }
}

impl FieldElement for Fp12 {
    const ZERO: Self = Self {
        c0: Fp4::ZERO,
        c1: Fp4::ZERO,
        c2: Fp4::ZERO,
    };

    const ONE: Self = Self {
        c0: Fp4::ONE,
        c1: Fp4::ZERO,
        c2: Fp4::ZERO,
    };

    fn add(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
            c2: self.c2.add(&other.c2),
        }
    }

    fn sub(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.sub(&other.c0),
            c1: self.c1.sub(&other.c1),
            c2: self.c2.sub(&other.c2),
        }
    }

    fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
            c2: self.c2.neg(),
        }
    }

    fn mul(&self, other: &Self) -> Self {
        // (a + bw + cw²)(d + ew + fw²)
        // = ad + (ae + bd)w + (af + be + cd)w² + (bf + ce)w³ + cfw⁴
        // = ad + (ae + bd)w + (af + be + cd)w² + (bf + ce)v + cfw²v
        // = (ad + (bf + ce)v) + (ae + bd + cfv)w + (af + be + cd)w²

        let ad = self.c0.mul(&other.c0);
        let ae = self.c0.mul(&other.c1);
        let af = self.c0.mul(&other.c2);
        let bd = self.c1.mul(&other.c0);
        let be = self.c1.mul(&other.c1);
        let bf = self.c1.mul(&other.c2);
        let cd = self.c2.mul(&other.c0);
        let ce = self.c2.mul(&other.c1);
        let cf = self.c2.mul(&other.c2);

        Self {
            c0: ad.add(&bf.add(&ce).mul_v()), // ad + (bf + ce)*v
            c1: ae.add(&bd).add(&cf.mul_v()), // ae + bd + cf*v
            c2: af.add(&be).add(&cd),         // af + be + cd
        }
    }

    fn square(&self) -> Self {
        // Optimized squaring formula
        let s0 = self.c0.square();
        let s1 = self.c1.square();
        let s2 = self.c2.square();

        let t0 = self.c0.mul(&self.c1);
        let t1 = self.c0.mul(&self.c2);
        let t2 = self.c1.mul(&self.c2);

        Self {
            c0: s0.add(&t2.mul_v().add(&t2.mul_v())),
            c1: t0.add(&t0).add(&s2.mul_v()),
            c2: s1.add(&t1.add(&t1)),
        }
    }

    fn inv(&self) -> Option<Self> {
        // For x = a + bw + cw² in Fp4[w]/(w³-v):
        // x⁻¹ = (A + Bw + Cw²) / D
        // where:
        //   A = a² - b*c*v
        //   B = c²*v - a*b
        //   C = b² - a*c
        //   D = a³ + b³*v + c³*v² - 3*a*b*c*v (norm)

        let a = &self.c0;
        let b = &self.c1;
        let c = &self.c2;

        let a2 = a.square();
        let b2 = b.square();
        let c2 = c.square();

        let ab = a.mul(b);
        let ac = a.mul(c);
        let bc = b.mul(c);

        // A = a² - bc*v
        let a_val = a2.sub(&bc.mul_v());

        // B = c²*v - ab
        let b_val = c2.mul_v().sub(&ab);

        // C = b² - ac
        let c_val = b2.sub(&ac);

        // D = a³ + b³*v + c³*v² - 3*abc*v
        let a3 = a2.mul(a);
        let b3_v = b2.mul(b).mul_v();
        let c3_v2 = c2.mul(c).mul_v().mul_v();
        let abc_v = ab.mul(c).mul_v();
        let d = a3.add(&b3_v).add(&c3_v2).sub(&abc_v.double()).sub(&abc_v);

        let d_inv = d.inv()?;

        Some(Self {
            c0: a_val.mul(&d_inv),
            c1: b_val.mul(&d_inv),
            c2: c_val.mul(&d_inv),
        })
    }

    fn double(&self) -> Self {
        self.add(self)
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero() && self.c2.is_zero()
    }

    fn is_one(&self) -> bool {
        self.c0.is_one() && self.c1.is_zero() && self.c2.is_zero()
    }
}

impl Fp12 {
    /// Convert to bytes: c0 || c1 || c2 (each 128 bytes, total 384 bytes)
    /// Serialize to bytes in internal order (c0 || c1 || c2)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(384);
        bytes.extend_from_slice(&self.c0.to_bytes());
        bytes.extend_from_slice(&self.c1.to_bytes());
        bytes.extend_from_slice(&self.c2.to_bytes());
        bytes
    }

    /// Serialize to bytes in GmSSL-compatible order (c2 || c1 || c0)
    /// with each Fp4 as c1 || c0 and each Fp2 as c1 || c0
    /// This matches GmSSL's fp12_to_bytes output format
    pub fn to_bytes_gmssl(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 * 12);
        // c2 (GmSSL outputs a[2] first)
        bytes.extend_from_slice(&self.c2.c1.c1.to_bytes()); // c2.c1.c1
        bytes.extend_from_slice(&self.c2.c1.c0.to_bytes()); // c2.c1.c0
        bytes.extend_from_slice(&self.c2.c0.c1.to_bytes()); // c2.c0.c1
        bytes.extend_from_slice(&self.c2.c0.c0.to_bytes()); // c2.c0.c0
                                                            // c1 (GmSSL outputs a[1] second)
        bytes.extend_from_slice(&self.c1.c1.c1.to_bytes()); // c1.c1.c1
        bytes.extend_from_slice(&self.c1.c1.c0.to_bytes()); // c1.c1.c0
        bytes.extend_from_slice(&self.c1.c0.c1.to_bytes()); // c1.c0.c1
        bytes.extend_from_slice(&self.c1.c0.c0.to_bytes()); // c1.c0.c0
                                                            // c0 (GmSSL outputs a[0] last)
        bytes.extend_from_slice(&self.c0.c1.c1.to_bytes()); // c0.c1.c1
        bytes.extend_from_slice(&self.c0.c1.c0.to_bytes()); // c0.c1.c0
        bytes.extend_from_slice(&self.c0.c0.c1.to_bytes()); // c0.c0.c1
        bytes.extend_from_slice(&self.c0.c0.c0.to_bytes()); // c0.c0.c0
        bytes
    }
}

impl PartialEq for Fp12 {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1 && self.c2 == other.c2
    }
}

impl Eq for Fp12 {}

impl ConditionallySelectable for Fp12 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            c0: Fp4::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp4::conditional_select(&a.c1, &b.c1, choice),
            c2: Fp4::conditional_select(&a.c2, &b.c2, choice),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::fp2::Fp2;

    #[test]
    fn test_fp12_mul() {
        let a = Fp12::new(Fp4::ONE, Fp4::ZERO, Fp4::ZERO);
        let b = Fp12::new(Fp4::ZERO, Fp4::ONE, Fp4::ZERO);
        let c = a.mul(&b);
        assert_eq!(c.c1, Fp4::ONE);
        assert!(c.c0.is_zero());
    }

    #[test]
    fn test_fp12_inv() {
        let a = Fp12::new(Fp4::ONE, Fp4::new(Fp2::ONE, Fp2::ZERO), Fp4::ZERO);
        let a_inv = a.inv().unwrap();
        let product = a.mul(&a_inv);
        assert!(product.is_one());
    }

    #[test]
    fn test_fp12_pow() {
        let a = Fp12::new(Fp4::ONE, Fp4::new(Fp2::ONE, Fp2::ZERO), Fp4::ZERO);
        let exp = crate::arith::z256::Z256([3, 0, 0, 0]);
        let result = a.pow(&exp);
        let expected = a.mul(&a).mul(&a);
        assert_eq!(result, expected);
    }

    #[test]
    fn bench_fp12_pow_small() {
        use std::time::Instant;
        let a = Fp12::new(Fp4::ONE, Fp4::new(Fp2::ONE, Fp2::ZERO), Fp4::ZERO);
        let exp = crate::arith::z256::Z256([123456789, 0, 0, 0]);

        let start = Instant::now();
        let _result = a.pow(&exp);
        let elapsed = start.elapsed();

    }
}
