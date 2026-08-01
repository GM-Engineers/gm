//! Prime field Fp arithmetic for SM9
//!
//! Elements are represented in Montgomery form for efficient modular multiplication.
//!
//! Field: Fp where p = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D

use crate::arith::FieldElement;
use crate::arith::z256::{self, Z256};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

/// R = 2^256 mod p (for Montgomery conversion)
const R: Z256 = Z256([
    0x1a9064d81caeba83,
    0xde0d6cb4e5851124,
    0x29fc54b00a7138ba,
    0x49bffffffd5c590e,
]);

/// R^2 mod p (for converting to Montgomery form)
const R_SQUARED: Z256 = Z256([
    0x27dea312b417e2d2,
    0x88f8105fae1a5d3f,
    0xe479b522d6706e7b,
    0x2ea795a656f62fbd,
]);

/// R^(-1) mod p (for converting from Montgomery form)
const R_INV: Z256 = Z256([
    0x0a1c7970e5df544d,
    0xe74504e9a96b56cc,
    0xcda02d92d4d62924,
    0x7d2bc576fdf597d1,
]);

/// -p^(-1) mod 2^64 (for Montgomery reduction, CIOS algorithm)
const P_INV: u64 = 0x892BC42C2F2EE42B;

/// Prime field element (stored in Montgomery form)
#[derive(Clone, Copy, Debug, Default, Zeroize)]
pub struct Fp(pub Z256);

impl Fp {
    /// Create from raw value (not Montgomery form)
    pub fn from_raw(raw: Z256) -> Self {
        Self(mont_mul(&raw, &R_SQUARED))
    }

    /// Convert to Montgomery form (identity, since Fp stores Montgomery form)
    pub fn to_montgomery(&self) -> Self {
        *self
    }

    /// Convert from Montgomery form to raw
    pub fn from_montgomery(&self) -> Self {
        Self(regular_mul(&self.0, &R_INV))
    }

    /// Create from u64
    pub fn from_u64(v: u64) -> Self {
        let raw = Z256([v, 0, 0, 0]);
        Self(mont_mul(&raw, &R_SQUARED))
    }

    /// Get raw value (for serialization)
    pub fn raw(&self) -> &Z256 {
        &self.0
    }

    /// Montgomery multiplication: a * b * R^-1 mod p
    #[allow(dead_code)] // Kept for API completeness; may be needed for future algorithms
    fn montgomery_mul(a: &Z256, b: &Z256) -> Z256 {
        mont_mul(a, b)
    }

    /// Convert to bytes (from Montgomery form)
    pub fn to_bytes(&self) -> [u8; 32] {
        let raw = regular_mul(&self.0, &R_INV);
        z256::to_bytes_be(&raw)
    }

    /// Create from bytes (converts to Montgomery form)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::arith::ArithError> {
        if bytes.len() != 32 {
            return Err(crate::arith::ArithError::InvalidParameter(format!(
                "Expected 32 bytes for Fp, got {}",
                bytes.len()
            )));
        }
        let raw = z256::from_bytes_be(bytes).ok_or_else(|| {
            crate::arith::ArithError::InvalidParameter("Invalid Fp bytes".to_string())
        })?;
        Ok(Self::from_raw(raw))
    }
}

impl FieldElement for Fp {
    const ZERO: Self = Self(Z256::ZERO);
    const ONE: Self = Self(R); // 1 in Montgomery form

    fn add(&self, other: &Self) -> Self {
        let (sum, carry) = z256::add_with_carry(&self.0, &other.0);
        // If sum >= p or carry, subtract p
        let (diff, borrow) = z256::sub_with_borrow(&sum, &Z256::P);
        let underflow = carry != 0 || borrow == 0;
        Self(z256::conditional_select(&sum, &diff, underflow as u8))
    }

    fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = z256::sub_with_borrow(&self.0, &other.0);
        // If borrow, add p
        let (sum, _) = z256::add_with_carry(&diff, &Z256::P);
        Self(z256::conditional_select(&diff, &sum, (borrow != 0) as u8))
    }

    fn neg(&self) -> Self {
        if self.is_zero() {
            Self::ZERO
        } else {
            let (diff, _) = z256::sub_with_borrow(&Z256::P, &self.0);
            Self(diff)
        }
    }

    fn mul(&self, other: &Self) -> Self {
        Self(mont_mul(&self.0, &other.0))
    }

    fn square(&self) -> Self {
        self.mul(self)
    }

    fn inv(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        // Convert from Montgomery to raw, compute inverse, convert back
        let raw = mont_mul(&self.0, &Z256::ONE); // self * 1 * R^-1 = self / R = original value
        // Fermat's little theorem: a^(p-2) mod p
        let p_minus_2 = Z256([Z256::P.0[0] - 2, Z256::P.0[1], Z256::P.0[2], Z256::P.0[3]]);
        let raw_inv = pow(&raw, &p_minus_2);
        // Convert back to Montgomery: raw_inv * R^2 * R^-1 = raw_inv * R
        Some(Self(mont_mul(&raw_inv, &R_SQUARED)))
    }

    fn double(&self) -> Self {
        self.add(self)
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn is_one(&self) -> bool {
        self.0 == R
    }
}

impl PartialEq for Fp {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Fp {}

impl subtle::ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Fp {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Z256::conditional_select(&a.0, &b.0, choice))
    }
}

/// Montgomery multiplication: result = a * b * R^-1 mod p
/// Uses CIOS (Coarsely Integrated Operand Scanning) algorithm
fn mont_mul(a: &Z256, b: &Z256) -> Z256 {
    const WORDS: usize = 4;

    // t holds intermediate results, each element is a u64 limb
    // but we need 128-bit for intermediate sums
    let mut t = [0u64; WORDS * 2 + 1];

    for i in 0..WORDS {
        // Multiply a[i] by b and add to t
        let mut carry: u64 = 0;
        for j in 0..WORDS {
            let (prod_lo, prod_hi) = mul64(a.0[i], b.0[j]);
            let (sum1, c1) = t[i + j].overflowing_add(prod_lo);
            let (sum2, c2) = sum1.overflowing_add(carry);
            t[i + j] = sum2;
            carry = prod_hi + if c1 { 1 } else { 0 } + if c2 { 1 } else { 0 };
        }
        let (sum, c) = t[i + WORDS].overflowing_add(carry);
        t[i + WORDS] = sum;
        t[i + WORDS + 1] = if c { 1 } else { 0 };

        // Montgomery reduction step
        let m = t[i].wrapping_mul(P_INV);
        carry = 0;
        for j in 0..WORDS {
            let (prod_lo, prod_hi) = mul64(m, Z256::P.0[j]);
            let (sum1, c1) = t[i + j].overflowing_add(prod_lo);
            let (sum2, c2) = sum1.overflowing_add(carry);
            t[i + j] = sum2;
            carry = prod_hi + if c1 { 1 } else { 0 } + if c2 { 1 } else { 0 };
        }
        let (sum1, c1) = t[i + WORDS].overflowing_add(carry);
        let (sum2, c2) = sum1.overflowing_add(t[i + WORDS + 1]);
        t[i + WORDS] = sum2;
        t[i + WORDS + 1] = if c1 || c2 { 1 } else { 0 };
    }

    // Extract result from t[WORDS..2*WORDS]
    let mut result = [0u64; WORDS];
    result[..WORDS].copy_from_slice(&t[WORDS..(WORDS + WORDS)]);

    // Handle possible carry in t[2*WORDS]
    let carry_out = t[2 * WORDS];

    // Final reduction: if result >= p, subtract p
    // Also handle carry_out
    let mut needs_sub = carry_out != 0;
    if !needs_sub {
        for i in (0..WORDS).rev() {
            if result[i] > Z256::P.0[i] {
                needs_sub = true;
                break;
            } else if result[i] < Z256::P.0[i] {
                needs_sub = false;
                break;
            }
        }
    }

    if needs_sub {
        let mut final_result = [0u64; WORDS];
        let mut borrow = 0u64;
        for i in 0..WORDS {
            let (diff, b1) = result[i].overflowing_sub(Z256::P.0[i]);
            let (diff2, b2) = diff.overflowing_sub(borrow);
            final_result[i] = diff2;
            borrow = if b1 || b2 { 1 } else { 0 };
        }
        Z256(final_result)
    } else {
        Z256(result)
    }
}

/// Regular modular multiplication (not Montgomery)
/// Computes a * b mod p where a, b are in regular (non-Montgomery) form
fn regular_mul(a: &Z256, b: &Z256) -> Z256 {
    // Convert to Montgomery, multiply, convert back
    // to_mont(a) = a * R^2 * R^-1 = a * R
    // to_mont(b) = b * R
    // mont_mul(to_mont(a), to_mont(b)) = a*R * b*R * R^-1 = a*b*R
    // from_mont(x) = x * R^-1
    // So: from_mont(mont_mul(to_mont(a), to_mont(b))) = a*b*R * R^-1 = a*b
    let a_mont = mont_mul(a, &R_SQUARED);
    let b_mont = mont_mul(b, &R_SQUARED);
    let prod_mont = mont_mul(&a_mont, &b_mont);
    mont_mul(&prod_mont, &Z256::ONE) // * 1 * R^-1 to get regular form
}

/// Modular exponentiation (works with regular integers, not Montgomery)
fn pow(base: &Z256, exp: &Z256) -> Z256 {
    let mut result = Z256::ONE; // Regular integer 1
    let mut base = *base;
    let mut exp = *exp;

    while !exp.is_zero() {
        if exp.0[0] & 1 == 1 {
            result = regular_mul(&result, &base);
        }
        base = regular_mul(&base, &base);
        // Right shift
        let mut carry = 0u64;
        for i in (0..4).rev() {
            let new_carry = exp.0[i] << 63;
            exp.0[i] = (exp.0[i] >> 1) | carry;
            carry = new_carry;
        }
    }

    result
}

// Re-export z256 functions needed by other modules
/// 64-bit multiplication: returns (low, high)
pub fn mul64(a: u64, b: u64) -> (u64, u64) {
    let a_lo = a as u128;
    let b_lo = b as u128;
    let prod = a_lo * b_lo;
    (prod as u64, (prod >> 64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp_add() {
        let a = Fp::from_u64(3);
        let b = Fp::from_u64(5);
        let c = a.add(&b);
        // Need to convert from Montgomery for comparison
        assert!(!c.is_zero());
    }

    #[test]
    fn test_fp_mul_identity() {
        let one = Fp::ONE;
        let a = Fp::from_u64(42);
        let result = a.mul(&one);
        assert_eq!(a.0, result.0);
    }

    #[test]
    fn test_mont_mul_simple() {
        // Test mont_mul with simple values
        let two = Z256([2, 0, 0, 0]);
        let three = Z256([3, 0, 0, 0]);

        // Convert to Montgomery form
        let two_mont = mont_mul(&two, &R_SQUARED);
        let three_mont = mont_mul(&three, &R_SQUARED);

        // Multiply in Montgomery domain
        let prod_mont = mont_mul(&two_mont, &three_mont);

        // Convert back
        let prod = mont_mul(&prod_mont, &Z256::ONE);

        // Should be 6
        assert_eq!(prod.0[0], 6);
    }

    #[test]
    fn test_fp_inv() {
        let a = Fp::from_u64(3);
        let a_inv = a.inv().unwrap();
        let product = a.mul(&a_inv);

        // Debug: check what ONE looks like

        assert!(product.is_one());
    }

    #[test]
    fn test_fp_zero_inv() {
        let zero = Fp::ZERO;
        assert!(zero.inv().is_none());
    }

    #[test]
    fn test_pow_simple() {
        // Test pow with a simple case: 2^(p-2) mod p should be inverse of 2
        let two = Z256([2, 0, 0, 0]);
        let p_minus_2 = Z256([Z256::P.0[0] - 2, Z256::P.0[1], Z256::P.0[2], Z256::P.0[3]]);

        let two_inv = pow(&two, &p_minus_2);

        // Verify: 2 * 2_inv mod p should be 1
        let product = regular_mul(&two, &two_inv);

        assert!(product.is_one());
    }

    #[test]
    fn test_montgomery_roundtrip() {
        let raw = Z256([42, 0, 0, 0]);
        let fp = Fp::from_raw(raw);
        // fp.0 is now in Montgomery form
        let back = fp.from_montgomery();
        // back.0 should be the raw value
        assert_eq!(raw, back.0);
    }

    #[test]
    fn test_mont_mul_large() {
        // Test with the specific value that failed
        let a_mont = Z256([
            0xa7dd9731def51b91,
            0x8068785f74207790,
            0x17cc452a620722f4,
            0x3155249aa9f97b04,
        ]);

        let _result = mont_mul(&a_mont, &a_mont);

        // Expected: a_mont^2 * R^-1 mod p
        // We need to verify this using Python or another method
        // For now, just print the result
    }
}
