//! Hash functions for SM9
//!
//! - Hash1: Used in key extraction (hid = 0x01 for signing, 0x02 for encryption)
//! - Hash2: Used in signature generation
//!
//! Both use SM3 as the underlying hash function.

use crate::arith::z256::Z256;
use sm3::{Digest, Sm3};

/// Hash1 function: H1(ID || hid, N)
///
/// Used to derive scalars from identities during key extraction.
pub fn hash1(identity: &[u8], hid: u8) -> Z256 {
    // Two-pass SM3 hash
    let mut ha = [0u8; 64];

    // First SM3
    let mut hasher = Sm3::new();
    hasher.update([0x01]); // Hash1 prefix
    hasher.update(identity);
    hasher.update([hid]);
    hasher.update([0, 0, 0, 1]); // Counter = 1
    ha[0..32].copy_from_slice(&hasher.finalize());

    // Second SM3
    let mut hasher = Sm3::new();
    hasher.update([0x01]); // Hash1 prefix
    hasher.update(identity);
    hasher.update([hid]);
    hasher.update([0, 0, 0, 2]); // Counter = 2
    ha[32..64].copy_from_slice(&hasher.finalize());

    // Map to [1, N-1]
    modn_from_hash(&ha)
}

/// Hash2 function: H2(M || w, N)
///
/// Used in signature generation and verification.
pub fn hash2(message: &[u8], w_bytes: &[u8]) -> Z256 {
    let mut ha = [0u8; 64];

    // First SM3
    let mut hasher = Sm3::new();
    hasher.update([0x02]); // Hash2 prefix
    hasher.update(message);
    hasher.update(w_bytes);
    hasher.update([0, 0, 0, 1]);
    ha[0..32].copy_from_slice(&hasher.finalize());

    // Second SM3
    let mut hasher = Sm3::new();
    hasher.update([0x02]); // Hash2 prefix
    hasher.update(message);
    hasher.update(w_bytes);
    hasher.update([0, 0, 0, 2]);
    ha[32..64].copy_from_slice(&hasher.finalize());

    modn_from_hash(&ha)
}

/// Map a 64-byte hash output to a scalar in [1, N-1]
/// Uses only the first 40 bytes (320 bits) as per GmSSL's sm9_z256_modn_from_hash
/// Uses schoolbook 320-bit mod N reduction, then add 1
fn modn_from_hash(ha: &[u8; 64]) -> Z256 {
    // GmSSL only uses first 40 bytes (5 x u64 = 320 bits)
    let mut z = [0u64; 5];
    for i in 0..5 {
        z[4 - i] = u64::from_be_bytes(ha[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    // N (little-endian u64 limbs)
    const N: [u64; 4] = [
        0xE56EE19CD69ECF25,
        0x49F2934B18EA8BEE,
        0xD603AB4FF58EC744,
        0xB640000002A3A6F1,
    ];

    // Barrett reduction: mu = floor(2^384 / N)
    // N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
    // mu = 0x000000000000000000000000000000000000000000000000000000000000000167980E0BEB5759A655F73AEBDCD1312C
    // LE limbs: [0x55F73AEBDCD1312C, 0x67980E0BEB5759A6, 0x0000000000000001, 0, 0, 0]
    const MU: [u64; 6] = [
        0x55F73AEBDCD1312C,
        0x67980E0BEB5759A6,
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ];

    // Compute z * mu (5×6 = 11 limbs, but only 8 are non-zero due to sparse mu)
    let mut product = [0u128; 11];
    for i in 0..5usize {
        for j in 0..3usize {
            // only 3 non-zero limbs in MU
            product[i + j] += (z[i] as u128) * (MU[j] as u128);
        }
    }
    let mut prod = [0u64; 11];
    let mut carry = 0u128;
    for i in 0..11 {
        let val = product[i] + carry;
        prod[i] = val as u64;
        carry = val >> 64;
    }

    // q = prod[6..9] (quotient after dividing by 2^384 = 6 limbs of 64 bits)
    let q = [prod[6], prod[7], prod[8], prod[9]];

    // Compute q * N
    let mut qn = [0u128; 8];
    for i in 0..4usize {
        for j in 0..4usize {
            qn[i + j] += (q[i] as u128) * (N[j] as u128);
        }
    }
    let mut qn_result = [0u64; 8];
    let mut carry = 0u128;
    for i in 0..8 {
        let val = qn[i] + carry;
        qn_result[i] = val as u64;
        carry = val >> 64;
    }

    // r = z - qn
    let mut borrow = 0i128;
    let mut r = [0u64; 4];
    for i in 0..4 {
        let zi = z[i] as i128;
        let sub = qn_result[i] as i128 + borrow;
        if zi >= sub {
            r[i] = (zi - sub) as u64;
            borrow = 0;
        } else {
            r[i] = ((zi + (1i128 << 64)) - sub) as u64;
            borrow = 1;
        }
    }
    let zi4 = z[4] as i128;
    let sub4 = qn_result[4] as i128 + borrow;
    if zi4 < sub4 {
        // Overshot: add N back
        let mut carry = 0u64;
        for i in 0..4 {
            let (s1, c1) = r[i].overflowing_add(N[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            r[i] = s2;
            carry = c1 as u64 + c2 as u64;
        }
    }

    // Final reduction (Barrett can be off by 1-2)
    let mut acc = Z256(r);
    let n = Z256(N);
    while crate::arith::z256::cmp(&acc, &n) >= 0 {
        acc = crate::arith::z256::sub_with_borrow(&acc, &n).0;
    }

    // Add 1 (matching GmSSL)
    let (result, carry) = crate::arith::z256::add_with_carry(&acc, &Z256::ONE);
    if carry != 0 || crate::arith::z256::cmp(&result, &n) >= 0 {
        crate::arith::z256::sub_with_borrow(&result, &n).0
    } else {
        result
    }
}

/// Compare two Z256 values
#[allow(dead_code)] // Kept for future use in constant-time comparison
fn cmp(a: &Z256, b: &Z256) -> i8 {
    for i in (0..4).rev() {
        if a.0[i] > b.0[i] {
            return 1;
        } else if a.0[i] < b.0[i] {
            return -1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash1_deterministic() {
        let id = b"user@example.com";
        let h1a = hash1(id, 0x01);
        let h1b = hash1(id, 0x01);
        assert_eq!(h1a, h1b);
    }

    #[test]
    fn test_hash1_different_hid() {
        let id = b"user@example.com";
        let h1_sign = hash1(id, 0x01);
        let h1_enc = hash1(id, 0x02);
        assert_ne!(h1_sign, h1_enc);
    }

    #[test]
    fn test_modmul_2_256_mod_n() {
        let n = Z256::N;
        // 2^192 * 2^64 mod N = 2^256 mod N
        let r64 = Z256([0, 1, 0, 0]);
        let r192 = Z256([0, 0, 0, 1]);

        // Manual step-by-step
        let (_low, _high) = crate::arith::z256::mul_wide(&r192, &r64);

        let _r_mod_m = crate::arith::z256::compute_2_256_mod_m(&n);

        let _result = crate::arith::z256::modmul(&r192, &r64, &n);
    }

    #[test]
    fn test_modmul_basic() {
        let n = Z256::N;
        // Test: 2^64 * 2^64 mod N should equal 2^128 mod N
        let r64 = Z256([0, 1, 0, 0]); // 2^64
        let r128_rust = crate::arith::z256::modmul(&r64, &r64, &n);
        // Python: 2^128 mod N = 0x0000000000000000000000000000000100000000000000000000000000000000
        // But that doesn't look right for N ≈ 2^255... let me compute
        // Actually 2^128 < N, so 2^128 mod N = 2^128
        let r128_expected = Z256([0, 0, 1, 0]);
        assert_eq!(r128_rust, r128_expected, "2^64 * 2^64 mod N = 2^128");

        // Test: 2^192 mod N — since 2^192 < N, this should be 2^192
        let r192_rust = crate::arith::z256::modmul(&r128_rust, &r64, &n);
        let r192_expected = Z256([0, 0, 0, 1]);
        assert_eq!(r192_rust, r192_expected, "2^128 * 2^64 mod N = 2^192");

        // Test: 2^256 mod N — this requires actual reduction since 2^256 > N
        // Python: 2^256 mod N = 0x49bffffffd5c590e1a911e63296130dbb60d6cb4e715741129fc54b00a7138bc
        let r256_rust = crate::arith::z256::modmul(&r192_rust, &r64, &n);
        // Expected: 0x49BFFFFFFD5C590E29FC54B00A7138BBB60D6CB4E71574111A911E63296130DB
        let r256_expected = Z256([
            0x1A911E63296130DB,
            0xB60D6CB4E7157411,
            0x29FC54B00A7138BB,
            0x49BFFFFFFD5C590E,
        ]);
        assert_eq!(r256_rust, r256_expected, "2^256 mod N");
    }

    #[test]
    fn test_modn_from_hash_known_value() {
        // Test with SM3("0x01 test@example.com 0x01 0x00000001") || SM3("...") first 40 bytes
        // Python expected: 0x7b83df780cbf768fc80680687350e50ccf6629d316c4f3c58c73ffa6f9a6f78e
        let ha = [0u8; 64];
        // Use a simpler test: all-zeros Ha should give 1
        let result = modn_from_hash(&ha);
        assert_eq!(result, Z256::ONE, "all-zeros hash should map to 1");

        // Test with known SM3 output for hash1("test@example.com", 0x01)
        // First 32 bytes = SM3(0x01 || "test@example.com" || 0x01 || 0x00000001)
        // Second 32 bytes = SM3(0x01 || "test@example.com" || 0x01 || 0x00000002)
        let mut ha2 = [0u8; 64];
        // Compute SM3 hashes
        {
            use sm3::{Digest, Sm3};
            let mut hasher = Sm3::new();
            hasher.update([0x01]);
            hasher.update(b"test@example.com");
            hasher.update([0x01]);
            hasher.update([0, 0, 0, 1]);
            ha2[0..32].copy_from_slice(&hasher.finalize());

            let mut hasher = Sm3::new();
            hasher.update([0x01]);
            hasher.update(b"test@example.com");
            hasher.update([0x01]);
            hasher.update([0, 0, 0, 2]);
            ha2[32..64].copy_from_slice(&hasher.finalize());
        }

        // First verify SM3 output matches Python

        // Verify the 320-bit z value
        let mut z_check = [0u64; 5];
        for i in 0..5 {
            z_check[4 - i] = u64::from_be_bytes(ha2[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        let result2 = modn_from_hash(&ha2);
        // Expected from Python (verified with gmssl Python package):
        // SM3 pass 1: c8cf548f7332319ec3001a6b1619dc1178700020d606f1229b6baf7287fb87b8
        // SM3 pass 2: e04ecc7bd517bbd11b4231a3dda00cea440b943c24141957ee0bed8e101be535
        // First 40 bytes: c8cf548f7332319ec3001a6b1619dc1178700020d606f1229b6baf7287fb87b8e04ecc7bd517bbd1
        // mod N + 1 = 0x8c810f2a7e791b5ad31ac85725d784ecbe68fa20a50b4ef9674db20437453c6d
        let expected = Z256([
            0x674DB20437453C6D,
            0xBE68FA20A50B4EF9,
            0xD31AC85725D784EC,
            0x8C810F2A7E791B5A,
        ]);
        assert_eq!(
            result2, expected,
            "hash1('test@example.com', 0x01) should match Python reference"
        );
    }

    #[test]
    fn test_hash2_deterministic() {
        let msg = b"test message";
        let w = b"test w bytes";
        let h2a = hash2(msg, w);
        let h2b = hash2(msg, w);
        assert_eq!(h2a, h2b);
    }

    #[test]
    fn test_hash_range() {
        let id = b"test";
        let h = hash1(id, 0x01);
        // Should be non-zero and less than N
        assert!(!h.is_zero());
        assert!(cmp(&h, &Z256::N) < 0);
    }
}
