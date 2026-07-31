//! 256-bit integer arithmetic for SM9
//!
//! This module implements 256-bit unsigned integer operations needed
//! for SM9's prime field arithmetic.
//!
//! Representation: 4 x u64 limbs (little-endian)

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// 256-bit unsigned integer: 4 x u64 limbs (little-endian)
#[derive(Clone, Copy, Debug, Default, Zeroize)]
#[repr(C)]
pub struct Z256(pub [u64; 4]);

impl Z256 {
    /// Zero value
    pub const ZERO: Self = Self([0; 4]);

    /// One value (integer 1)
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// R^2 mod p (for converting to Montgomery form)
    /// Precomputed: R = 2^256, R_SQUARED = R^2 mod p
    pub const R_SQUARED: Self = Self([
        0x27dea312b417e2d2,
        0x88f8105fae1a5d3f,
        0xe479b522d6706e7b,
        0x2ea795a656f62fbd,
    ]);

    /// R^(-1) mod p (for Montgomery-to-raw conversion)
    pub const R_INV: Self = Self([
        0x0a1c7970e5df544d,
        0xe74504e9a96b56cc,
        0xcda02d92d4d62924,
        0x7d2bc576fdf597d1,
    ]);

    /// SM9 prime p
    pub const P: Self = Self([
        0xE56F9B27E351457D,
        0x21F2934B1A7AEEDB,
        0xD603AB4FF58EC745,
        0xB640000002A3A6F1,
    ]);

    /// SM9 order N
    /// N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
    pub const N: Self = Self([
        0xE56EE19CD69ECF25,
        0x49F2934B18EA8BEE,
        0xD603AB4FF58EC744,
        0xB640000002A3A6F1,
    ]);

    /// p^-1 mod 2^64 (for Montgomery reduction)
    pub const P_INV: u64 = 0x76D43BD3D0D11BD5;

    /// Barrett reduction constant for N: MU_N = floor(2^512 / N) - 2^256
    /// (the low 256 bits of MU_N; full MU_N = 2^256 + MU_N_LOW)
    pub const MU_N_LOW: Self = Self([
        0x74DF4FD4DFC97C2F,
        0x9C95D85EC9C073B0,
        0x55F73AEBDCD1312C,
        0x67980E0BEB5759A6,
    ]);

    /// Barrett reduction constant for P: MU_P = floor(2^512 / P) - 2^256
    pub const MU_P_LOW: Self = Self([
        0x71188F90D5C22146,
        0xF2665F6D1E36081C,
        0x55F73AEBDCD1312A,
        0x67980E0BEB5759A6,
    ]);

    /// Create from raw limbs
    pub const fn new(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Check if one
    pub fn is_one(&self) -> bool {
        self.0[0] == 1 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Test if the high bit is set
    pub fn bit(&self, n: usize) -> bool {
        let limb = n / 64;
        let bit = n % 64;
        if limb < 4 {
            (self.0[limb] >> bit) & 1 == 1
        } else {
            false
        }
    }

    /// Constant-time bit access: returns Choice(1) if bit `n` is set, Choice(0) otherwise.
    /// Does not branch on the bit value.
    pub fn ct_bit(&self, n: usize) -> Choice {
        let limb = n / 64;
        let bit = n % 64;
        if limb < 4 {
            // Mask out the bit, then check if non-zero in constant time
            let bit_val = (self.0[limb] >> bit) & 1;
            Choice::from(bit_val as u8)
        } else {
            Choice::from(0)
        }
    }

    /// Constant-time check if self is zero
    pub fn ct_is_zero(&self) -> Choice {
        ConstantTimeEq::ct_eq(self, &Self::ZERO)
    }

    /// Number of bits needed to represent this value
    pub fn bits(&self) -> usize {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// Right shift by 1 bit
    pub fn shr1(&self) -> Self {
        let mut r = Self::ZERO;
        r.0[0] = (self.0[0] >> 1) | ((self.0[1] & 1) << 63);
        r.0[1] = (self.0[1] >> 1) | ((self.0[2] & 1) << 63);
        r.0[2] = (self.0[2] >> 1) | ((self.0[3] & 1) << 63);
        r.0[3] = self.0[3] >> 1;
        r
    }
}

impl PartialEq for Z256 {
    fn eq(&self, other: &Self) -> bool {
        self.0[0] == other.0[0]
            && self.0[1] == other.0[1]
            && self.0[2] == other.0[2]
            && self.0[3] == other.0[3]
    }
}

impl Eq for Z256 {}

impl subtle::ConstantTimeEq for Z256 {
    fn ct_eq(&self, other: &Self) -> Choice {
        // XOR each limb, OR the differences, then check if zero
        let diff0 = self.0[0] ^ other.0[0];
        let diff1 = self.0[1] ^ other.0[1];
        let diff2 = self.0[2] ^ other.0[2];
        let diff3 = self.0[3] ^ other.0[3];
        let or_diff = diff0 | diff1 | diff2 | diff3;
        Choice::from((or_diff == 0) as u8)
    }
}

impl ConditionallySelectable for Z256 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

/// Addition with carry: returns (result, carry)
pub fn add_with_carry(a: &Z256, b: &Z256) -> (Z256, u64) {
    let mut r = Z256::ZERO;
    let mut carry = 0u64;

    for i in 0..4 {
        let (sum1, c1) = a.0[i].overflowing_add(b.0[i]);
        let (sum2, c2) = sum1.overflowing_add(carry);
        r.0[i] = sum2;
        carry = if c1 || c2 { 1 } else { 0 };
    }

    (r, carry)
}

/// Subtraction with borrow: returns (result, borrow)
pub fn sub_with_borrow(a: &Z256, b: &Z256) -> (Z256, u64) {
    let mut r = Z256::ZERO;
    let mut borrow = 0u64;

    for i in 0..4 {
        let (diff1, b1) = a.0[i].overflowing_sub(b.0[i]);
        let (diff2, b2) = diff1.overflowing_sub(borrow);
        r.0[i] = diff2;
        borrow = if b1 || b2 { 1 } else { 0 };
    }

    (r, borrow)
}

/// 256-bit multiplication: returns 512-bit result (low, high)
pub fn mul_wide(a: &Z256, b: &Z256) -> (Z256, Z256) {
    let mut t = [0u64; 8];

    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let (prod, c) = mul64(a.0[i], b.0[j]);
            let (sum1, c1) = t[i + j].overflowing_add(prod);
            let (sum2, c2) = sum1.overflowing_add(carry);
            t[i + j] = sum2;
            carry = c + c1 as u64 + c2 as u64;
        }
        t[i + 4] = carry;
    }

    let low = Z256([t[0], t[1], t[2], t[3]]);
    let high = Z256([t[4], t[5], t[6], t[7]]);
    (low, high)
}

/// 64-bit multiplication: returns (low, high)
fn mul64(a: u64, b: u64) -> (u64, u64) {
    let a_lo = a as u128;
    let b_lo = b as u128;
    let prod = a_lo * b_lo;
    (prod as u64, (prod >> 64) as u64)
}

/// Compare two Z256 values: returns -1, 0, or 1
pub fn cmp(a: &Z256, b: &Z256) -> i8 {
    for i in (0..4).rev() {
        if a.0[i] > b.0[i] {
            return 1;
        } else if a.0[i] < b.0[i] {
            return -1;
        }
    }
    0
}

/// Conditional select (constant time)
pub fn conditional_select(a: &Z256, b: &Z256, choice: u8) -> Z256 {
    let mask = if choice != 0 { u64::MAX } else { 0 };
    Z256([
        (a.0[0] & !mask) | (b.0[0] & mask),
        (a.0[1] & !mask) | (b.0[1] & mask),
        (a.0[2] & !mask) | (b.0[2] & mask),
        (a.0[3] & !mask) | (b.0[3] & mask),
    ])
}

/// Conditional swap (constant time)
pub fn cswap(a: &mut Z256, b: &mut Z256, swap: u8) {
    let mask = if swap != 0 { u64::MAX } else { 0 };
    for i in 0..4 {
        let t = (a.0[i] ^ b.0[i]) & mask;
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// Conditional copy: dst = src if copy != 0 (constant time)
pub fn ccopy(dst: &mut Z256, src: &Z256, copy: u8) {
    let mask = if copy != 0 { u64::MAX } else { 0 };
    for i in 0..4 {
        dst.0[i] = (dst.0[i] & !mask) | (src.0[i] & mask);
    }
}

/// Convert from bytes (big-endian)
pub fn from_bytes_be(bytes: &[u8]) -> Option<Z256> {
    if bytes.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);

    Some(Z256([
        u64::from_be_bytes(padded[24..32].try_into().unwrap()),
        u64::from_be_bytes(padded[16..24].try_into().unwrap()),
        u64::from_be_bytes(padded[8..16].try_into().unwrap()),
        u64::from_be_bytes(padded[0..8].try_into().unwrap()),
    ]))
}

/// Convert to bytes (big-endian)
pub fn to_bytes_be(a: &Z256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&a.0[3].to_be_bytes());
    bytes[8..16].copy_from_slice(&a.0[2].to_be_bytes());
    bytes[16..24].copy_from_slice(&a.0[1].to_be_bytes());
    bytes[24..32].copy_from_slice(&a.0[0].to_be_bytes());
    bytes
}

/// Reduce a 512-bit number (represented as high||low) modulo m.
///
/// Uses Barrett reduction with precomputed MU constant for ~2x speedup
/// over the previous schoolbook trial-division approach.
///
/// Barrett reduction: q = floor(x * MU / 2^512), then r = x - q*m.
/// Since MU = floor(2^512 / m) = 2^256 + MU_LOW, we decompose:
///   q = high + mul_wide(high, MU_LOW).high + mid_carry + last_carry
/// where mid_carry and last_carry account for lower-order terms.
/// Result r < 2*m, so at most one conditional subtraction is needed.
///
/// Falls back to schoolbook reduction for arbitrary moduli without a
/// precomputed MU constant (only P and N have MU constants defined).
pub fn mod_reduce_512(low: &Z256, high: &Z256, m: &Z256) -> Z256 {
    // Use Barrett reduction for SM9's known moduli (P and N)
    let mu_low = if m == &Z256::N {
        &Z256::MU_N_LOW
    } else if m == &Z256::P {
        &Z256::MU_P_LOW
    } else {
        return mod_reduce_512_schoolbook(low, high, m);
    };

    // Barrett reduction: compute q = floor(x * MU / 2^512)
    // where MU = 2^256 + MU_LOW, x = high * 2^256 + low
    //
    // q = high + mul_wide(high, MU_LOW).high
    //       + mid_carry_from_(hmu_lo + low)
    //       + last_carry_from_(mid_lo + lmu_hi)

    // Step 1: hmu = high * MU_LOW (256x256 -> 512)
    let (hmu_lo, hmu_hi) = mul_wide(high, mu_low);

    // Step 2: mid = hmu_lo + low (256-bit add, may carry)
    let (mid_lo, mid_carry) = add_with_carry(&hmu_lo, low);

    // Step 3: lmu = low * MU_LOW (256x256 -> 512), we only need high half
    let (_, lmu_hi) = mul_wide(low, mu_low);

    // Step 4: last_carry = 1 if mid_lo + lmu_hi >= 2^256
    let (_, last_carry) = add_with_carry(&mid_lo, &lmu_hi);

    // Step 5: q = high + hmu_hi + mid_carry + last_carry
    // (each term is at most 256 bits; total q is at most 257 bits)
    let (q_lo, carry1) = add_with_carry(high, &hmu_hi);
    let (q_lo, carry2) = add_with_carry(&q_lo, &Z256::new([mid_carry, 0, 0, 0]));
    let (q_lo, carry3) = add_with_carry(&q_lo, &Z256::new([last_carry, 0, 0, 0]));
    let q_hi = carry1 + carry2 + carry3; // 0 or 1 (q fits in 257 bits)

    // Step 6: Compute q*m (q is 257 bits, m is 256 bits, product fits in 513 bits)
    // q = q_hi * 2^256 + q_lo, so q*m = q_lo*m + q_hi*m * 2^256
    let (qm_lo, qm_hi) = mul_wide(&q_lo, m);
    // q_hi is 0 or 1. If 1, add m to qm_hi (the high 256 bits of q*m)
    let (qm_hi_final, qm_overflow) = if q_hi != 0 {
        let (sum, carry) = add_with_carry(&qm_hi, m);
        (sum, carry)
    } else {
        (qm_hi, 0u64)
    };
    // qm_overflow (bit 512) should be 0 since q*m <= x < 2^512
    debug_assert!(qm_overflow == 0, "Barrett reduction: q*m overflow");

    // Step 7: r = x - q*m = (high:low) - (qm_hi_final:qm_lo)
    // Subtract low 256 bits
    let (r_lo, borrow1) = sub_with_borrow(low, &qm_lo);
    // Subtract high 256 bits (with borrow)
    let (r_hi, borrow2) = sub_with_borrow(high, &qm_hi_final);
    let (r_hi, borrow3) = sub_with_borrow(&r_hi, &Z256::new([borrow1, 0, 0, 0]));
    let total_borrow = borrow2 + borrow3; // 0 or 1 (shouldn't be 2)

    // If borrow != 0, q was 1 too large — add m back to the 512-bit r
    let (r_hi, r_lo) = if total_borrow != 0 {
        // r is negative (as 512-bit signed). Add m (256-bit) to r_lo,
        // carrying into r_hi if needed.
        let (sum_lo, carry) = add_with_carry(&r_lo, m);
        let (sum_hi, _) = add_with_carry(&r_hi, &Z256::new([carry, 0, 0, 0]));
        (sum_hi, sum_lo)
    } else {
        (r_hi, r_lo)
    };

    // Now r = (r_hi:r_lo) is a 512-bit value with 0 <= r < 2*m.
    // Since 2*m < 2^257, r_hi is either 0 or 1 (if r_hi == 1, r_lo < 2*m - 2^256).
    //
    // Final reduction: if r >= m (comparing as 512-bit), subtract m.
    // r >= m iff r_hi > 0 OR (r_hi == 0 AND r_lo >= m)
    let r_ge_m = !r_hi.is_zero() || cmp(&r_lo, m) >= 0;
    if r_ge_m {
        let (diff_lo, borrow) = sub_with_borrow(&r_lo, m);
        let (diff_hi, _) = sub_with_borrow(&r_hi, &Z256::new([borrow, 0, 0, 0]));
        // After subtraction, diff_hi should be 0
        debug_assert!(
            diff_hi.is_zero(),
            "Barrett final reduction: diff_hi not zero"
        );
        diff_lo
    } else {
        r_lo
    }
}

/// Schoolbook reduction (fallback for arbitrary moduli without precomputed MU)
fn mod_reduce_512_schoolbook(low: &Z256, high: &Z256, m: &Z256) -> Z256 {
    let limbs = [
        high.0[3], high.0[2], high.0[1], high.0[0], low.0[3], low.0[2], low.0[1], low.0[0],
    ];

    let mut rem = [0u64; 5];

    for limb in limbs.iter() {
        rem = [*limb, rem[0], rem[1], rem[2], rem[3]];

        if rem[4] == 0 {
            let mut is_lt = rem[3] < m.0[3];
            if rem[3] == m.0[3] {
                for i in (0..3).rev() {
                    if rem[i] < m.0[i] {
                        is_lt = true;
                        break;
                    }
                    if rem[i] > m.0[i] {
                        break;
                    }
                }
            }
            if is_lt {
                continue;
            }
        }

        let q_est: u128 = if rem[4] > 0 {
            ((rem[4] as u128) << 64 | rem[3] as u128) / m.0[3] as u128
        } else {
            rem[3] as u128 / m.0[3] as u128
        };

        let mut q = if q_est > u64::MAX as u128 {
            u64::MAX
        } else {
            q_est as u64
        };

        loop {
            let mut qm = [0u64; 5];
            let mut carry: u128 = 0;
            for (i, m_i) in m.0.iter().enumerate() {
                let prod = (q as u128) * (*m_i as u128) + carry;
                qm[i] = prod as u64;
                carry = prod >> 64;
            }
            qm[4] = carry as u64;

            let mut is_ge = true;
            for i in (0..5).rev() {
                if rem[i] > qm[i] {
                    break;
                }
                if rem[i] < qm[i] {
                    is_ge = false;
                    break;
                }
            }

            if is_ge {
                let mut borrow = 0u64;
                for i in 0..5 {
                    let (d1, b1) = rem[i].overflowing_sub(qm[i]);
                    let (d2, b2) = d1.overflowing_sub(borrow);
                    rem[i] = d2;
                    borrow = if b1 || b2 { 1 } else { 0 };
                }
                break;
            }

            q -= 1;
            if q == 0 {
                break;
            }
        }

        loop {
            let mut is_ge = rem[4] > 0;
            if !is_ge && rem[3] >= m.0[3] {
                is_ge = true;
                for i in (0..4).rev() {
                    if rem[i] > m.0[i] {
                        break;
                    }
                    if rem[i] < m.0[i] {
                        is_ge = false;
                        break;
                    }
                }
            }
            if !is_ge {
                break;
            }

            let mut borrow = 0u64;
            for (i, rem_i) in rem.iter_mut().enumerate() {
                let mi = if i < 4 { m.0[i] } else { 0 };
                let (d1, b1) = (*rem_i).overflowing_sub(mi);
                let (d2, b2) = d1.overflowing_sub(borrow);
                *rem_i = d2;
                borrow = if b1 || b2 { 1 } else { 0 };
            }
        }
    }

    Z256([rem[0], rem[1], rem[2], rem[3]])
}

/// Modular multiplication: (a * b) mod m
/// Uses mul_wide + proper reduction
pub fn modmul(a: &Z256, b: &Z256, m: &Z256) -> Z256 {
    let (low, high) = mul_wide(a, b);
    if high.is_zero() {
        let mut result = low;
        while cmp(&result, m) >= 0 {
            let (diff, borrow) = sub_with_borrow(&result, m);
            if borrow == 0 {
                result = diff;
            } else {
                break;
            }
        }
        result
    } else {
        mod_reduce_512(&low, &high, m)
    }
}

/// Compute 2^256 mod m
pub fn compute_2_256_mod_m(m: &Z256) -> Z256 {
    let mut r = Z256::ONE;
    for _ in 0..256 {
        let (r_doubled, carry) = add_with_carry(&r, &r);
        if carry != 0 || cmp(&r_doubled, m) >= 0 {
            let (diff, _) = sub_with_borrow(&r_doubled, m);
            r = diff;
        } else {
            r = r_doubled;
        }
    }
    r
}

/// Subtraction modulo m
pub fn sub_mod(a: &Z256, b: &Z256, m: &Z256) -> Z256 {
    let (diff, borrow) = sub_with_borrow(a, b);
    if borrow != 0 {
        let (sum, _) = add_with_carry(&diff, m);
        sum
    } else {
        diff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = Z256([1, 0, 0, 0]);
        let b = Z256([2, 0, 0, 0]);
        let (r, carry) = add_with_carry(&a, &b);
        assert_eq!(r.0[0], 3);
        assert_eq!(carry, 0);
    }

    #[test]
    fn test_add_carry() {
        let a = Z256([u64::MAX, 0, 0, 0]);
        let b = Z256([1, 0, 0, 0]);
        let (r, carry) = add_with_carry(&a, &b);
        assert_eq!(r.0[0], 0);
        assert_eq!(r.0[1], 1);
        assert_eq!(carry, 0);
    }

    #[test]
    fn test_sub() {
        let a = Z256([3, 0, 0, 0]);
        let b = Z256([1, 0, 0, 0]);
        let (r, borrow) = sub_with_borrow(&a, &b);
        assert_eq!(r.0[0], 2);
        assert_eq!(borrow, 0);
    }

    #[test]
    fn test_mul() {
        let a = Z256([2, 0, 0, 0]);
        let b = Z256([3, 0, 0, 0]);
        let (low, high) = mul_wide(&a, &b);
        assert_eq!(low.0[0], 6);
        assert!(high.is_zero());
    }

    #[test]
    fn test_cswap() {
        let mut a = Z256([1, 2, 3, 4]);
        let mut b = Z256([5, 6, 7, 8]);
        cswap(&mut a, &mut b, 1);
        assert_eq!(a.0, [5, 6, 7, 8]);
        assert_eq!(b.0, [1, 2, 3, 4]);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let a = Z256([
            0x0102030405060708,
            0x090A0B0C0D0E0F10,
            0x1112131415161718,
            0x191A1B1C1D1E1F20,
        ]);
        let bytes = to_bytes_be(&a);
        let b = from_bytes_be(&bytes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_sm9_p_value() {
        // Verify P matches expected value
        let p_hex = "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";
        let p_bytes = hex::decode(p_hex).unwrap();
        let p = from_bytes_be(&p_bytes).unwrap();
        assert_eq!(p, Z256::P);
    }
}
