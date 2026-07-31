//! Key generation and management for SM9

use crate::curve::g1::G1Point;
use crate::curve::g2::G2Point;
use crate::curve::ScalarMul;
// use crate::field::FieldElement;
use crate::hash;
use crate::z256::Z256;
use crate::Sm9Error;
use rand::CryptoRng;
use subtle::ConditionallySelectable;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SM9 signing master key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignMasterKey {
    /// Master secret scalar s
    pub s: Z256,
    /// Master public key Ppubs = s * P2
    pub ppubs: G2Point,
}

/// SM9 signing user key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignUserKey {
    /// User private key ds = [s/(h1+s)] * P1
    pub ds: G1Point,
    /// Master public key
    pub ppubs: G2Point,
}

/// SM9 encryption master key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncMasterKey {
    /// Master secret scalar s
    pub s: Z256,
    /// Master public key Ppube = s * P1
    pub ppube: G1Point,
}

/// SM9 encryption user key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncUserKey {
    /// User private key de = [s/(h1+s)] * P2
    pub de: G2Point,
    /// Master public key
    pub ppube: G1Point,
}

impl SignMasterKey {
    /// Generate a new signing master key
    pub fn generate(rng: &mut impl CryptoRng) -> Result<Self, Sm9Error> {
        let s = random_scalar(rng)?;
        let p2 = crate::params::g2_generator();
        let ppubs = p2.scalar_mul(&s);
        Ok(Self { s, ppubs })
    }

    /// Serialize public key (Ppubs) to raw bytes (128 bytes uncompressed G2 point)
    /// Format: X (64 bytes) || Y (64 bytes), each Fp2 element as c0 (32 bytes) || c1 (32 bytes)
    pub fn to_bytes(&self) -> Result<[u8; 128], Sm9Error> {
        let mut bytes = [0u8; 128];

        // Convert G2Point from Jacobian to affine
        let (x, y) = self.ppubs.to_affine().ok_or_else(|| {
            Sm9Error::CryptoError("Identity point cannot be serialized".to_string())
        })?;

        // Serialize X = c0 || c1
        let x_bytes = x.to_bytes();
        bytes[0..64].copy_from_slice(&x_bytes);

        // Serialize Y = c0 || c1
        let y_bytes = y.to_bytes();
        bytes[64..128].copy_from_slice(&y_bytes);

        Ok(bytes)
    }

    /// Deserialize public key (Ppubs) from raw bytes (128 bytes uncompressed G2 point)
    pub fn from_bytes(bytes: &[u8; 128]) -> Result<Self, Sm9Error> {
        // Parse X coordinate (Fp2)
        let x_c0 = crate::field::fp::Fp::from_bytes(&bytes[0..32])
            .map_err(|e| Sm9Error::CryptoError(format!("Invalid X c0: {:?}", e)))?;
        let x_c1 = crate::field::fp::Fp::from_bytes(&bytes[32..64])
            .map_err(|e| Sm9Error::CryptoError(format!("Invalid X c1: {:?}", e)))?;
        let x = crate::field::fp2::Fp2::new(x_c0, x_c1);

        // Parse Y coordinate (Fp2)
        let y_c0 = crate::field::fp::Fp::from_bytes(&bytes[64..96])
            .map_err(|e| Sm9Error::CryptoError(format!("Invalid Y c0: {:?}", e)))?;
        let y_c1 = crate::field::fp::Fp::from_bytes(&bytes[96..128])
            .map_err(|e| Sm9Error::CryptoError(format!("Invalid Y c1: {:?}", e)))?;
        let y = crate::field::fp2::Fp2::new(y_c0, y_c1);

        let ppubs = G2Point::from_affine(x, y);

        // We don't have the secret key s from public key bytes alone
        // For cross-validation, we set s to zero (indicating we only have public key)
        Ok(Self {
            s: Z256::ZERO,
            ppubs,
        })
    }

    /// Extract user signing key for identity
    pub fn extract_key(&self, identity: &[u8]) -> Result<SignUserKey, Sm9Error> {
        if self.s.is_zero() {
            return Err(Sm9Error::CryptoError(
                "Cannot extract key: master secret s is zero (public-key-only instance)"
                    .to_string(),
            ));
        }

        let h1 = hash::hash1(identity, 0x01);

        // Compute (s + h1) mod N
        let (s_plus_h1, carry) = crate::z256::add_with_carry(&self.s, &h1);
        let s_plus_h1 = if carry != 0 || crate::z256::cmp(&s_plus_h1, &Z256::N) >= 0 {
            // s + h1 >= N, reduce mod N
            crate::z256::sub_with_borrow(&s_plus_h1, &Z256::N).0
        } else {
            s_plus_h1
        };

        // Compute (s + h1)^-1 mod N
        let inv = modinv(&s_plus_h1, &Z256::N)
            .ok_or_else(|| Sm9Error::CryptoError("modular inverse failed".to_string()))?;

        // Compute s * (s + h1)^-1 mod N
        let scalar = modmul(&self.s, &inv, &Z256::N);

        // ds = scalar * P1
        let p1 = crate::params::g1_generator();
        let ds = p1.scalar_mul(&scalar);

        Ok(SignUserKey {
            ds,
            ppubs: self.ppubs,
        })
    }
}

impl EncMasterKey {
    /// Generate a new encryption master key
    pub fn generate(rng: &mut impl CryptoRng) -> Result<Self, Sm9Error> {
        let s = random_scalar(rng)?;
        let p1 = crate::params::g1_generator();
        let ppube = p1.scalar_mul(&s);
        Ok(Self { s, ppube })
    }

    /// Extract user encryption key for identity (default hid = 0x02 for encryption)
    pub fn extract_key(&self, identity: &[u8]) -> Result<EncUserKey, Sm9Error> {
        self.extract_key_with_hid(identity, 0x02)
    }

    /// Extract user encryption key for key exchange (hid = 0x03 per GM/T 0044.3)
    pub fn extract_key_exchange(&self, identity: &[u8]) -> Result<EncUserKey, Sm9Error> {
        self.extract_key_with_hid(identity, 0x03)
    }

    /// Extract user encryption key with a specific hid value
    ///
    /// - hid = 0x02: encryption (GM/T 0044.2)
    /// - hid = 0x03: key exchange (GM/T 0044.3)
    pub fn extract_key_with_hid(&self, identity: &[u8], hid: u8) -> Result<EncUserKey, Sm9Error> {
        if self.s.is_zero() {
            return Err(Sm9Error::CryptoError(
                "Cannot extract key: master secret s is zero (public-key-only instance)"
                    .to_string(),
            ));
        }

        let h1 = hash::hash1(identity, hid);

        let (s_plus_h1, carry) = crate::z256::add_with_carry(&self.s, &h1);
        let s_plus_h1 = if carry != 0 || crate::z256::cmp(&s_plus_h1, &Z256::N) >= 0 {
            crate::z256::sub_with_borrow(&s_plus_h1, &Z256::N).0
        } else {
            s_plus_h1
        };

        let inv = modinv(&s_plus_h1, &Z256::N)
            .ok_or_else(|| Sm9Error::CryptoError("modular inverse failed".to_string()))?;

        let scalar = modmul(&self.s, &inv, &Z256::N);

        let p2 = crate::params::g2_generator();
        let de = p2.scalar_mul(&scalar);

        Ok(EncUserKey {
            de,
            ppube: self.ppube,
        })
    }
}

// =============================================================================
// KgcMasterKey — Composite key combining signing and encryption master keys
// =============================================================================

/// KGC (Key Generation Center) master key
///
/// Combines both the signing master key and encryption master key.
/// This is the primary key material for SM9 identity-based cryptography.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KgcMasterKey {
    sign_master: SignMasterKey,
    enc_master: EncMasterKey,
}

impl core::fmt::Debug for KgcMasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KgcMasterKey")
            .field("sign_master", &"<redacted>")
            .field("enc_master", &"<redacted>")
            .finish()
    }
}

impl KgcMasterKey {
    /// Generate a new KGC master key pair (both signing and encryption)
    pub fn generate() -> Result<Self, Sm9Error> {
        let sign_master = SignMasterKey::generate(&mut rand::rng())?;
        let enc_master = EncMasterKey::generate(&mut rand::rng())?;
        Ok(Self {
            sign_master,
            enc_master,
        })
    }

    /// Derive a signing user key for the given identity
    pub fn derive_signing_key(&self, identity: &[u8]) -> Result<SignUserKey, Sm9Error> {
        self.sign_master.extract_key(identity)
    }

    /// Derive an encryption user key for the given identity
    pub fn derive_encryption_key(&self, identity: &[u8]) -> Result<EncUserKey, Sm9Error> {
        self.enc_master.extract_key(identity)
    }

    /// Get a reference to the signing master key
    pub fn sign_master(&self) -> &SignMasterKey {
        &self.sign_master
    }

    /// Get a reference to the encryption master key
    pub fn enc_master(&self) -> &EncMasterKey {
        &self.enc_master
    }

    /// Serialize to bytes (sign_master || enc_master)
    /// Format: [sign_len(8) || sign_bytes(128) || enc_len(8) || enc_bytes(96)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Sm9Error> {
        let sign_bytes = self.sign_master.to_bytes()?;
        let enc_bytes = {
            // Serialize enc_master: s (32 bytes BE) || ppube (uncompressed G1: 64 bytes)
            let mut buf = Vec::with_capacity(96);
            buf.extend_from_slice(&crate::z256::to_bytes_be(&self.enc_master.s));
            // G1 point: x (32 bytes) || y (32 bytes)
            let (x, y) = self.enc_master.ppube.to_affine().ok_or_else(|| {
                Sm9Error::CryptoError("Identity point cannot be serialized".to_string())
            })?;
            buf.extend_from_slice(&x.to_bytes());
            buf.extend_from_slice(&y.to_bytes());
            buf
        };
        let mut result = Vec::with_capacity(128 + 96 + 16);
        result.extend_from_slice(&(sign_bytes.len() as u64).to_le_bytes());
        result.extend_from_slice(&sign_bytes);
        result.extend_from_slice(&(enc_bytes.len() as u64).to_le_bytes());
        result.extend_from_slice(&enc_bytes);
        Ok(result)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Sm9Error> {
        if bytes.len() < 16 {
            return Err(Sm9Error::InvalidParameter(
                "insufficient bytes for KgcMasterKey".to_string(),
            ));
        }
        let sign_len = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
        if bytes.len() < 8 + sign_len + 8 {
            return Err(Sm9Error::InvalidParameter(
                "insufficient bytes for sign master key".to_string(),
            ));
        }
        let sign_bytes: [u8; 128] = bytes[8..8 + sign_len]
            .try_into()
            .map_err(|_| Sm9Error::InvalidParameter("invalid sign key length".to_string()))?;
        let sign_master = SignMasterKey::from_bytes(&sign_bytes)?;

        let enc_offset = 8 + sign_len;
        let enc_len =
            u64::from_le_bytes(bytes[enc_offset..enc_offset + 8].try_into().unwrap()) as usize;
        if bytes.len() < enc_offset + 8 + enc_len {
            return Err(Sm9Error::InvalidParameter(
                "insufficient bytes for enc master key".to_string(),
            ));
        }
        let enc_data = &bytes[enc_offset + 8..enc_offset + 8 + enc_len];
        if enc_data.len() < 96 {
            return Err(Sm9Error::InvalidParameter(
                "enc master key data too short".to_string(),
            ));
        }
        let s = crate::z256::from_bytes_be(&enc_data[0..32])
            .ok_or_else(|| Sm9Error::CryptoError("Invalid enc master s".to_string()))?;
        if s.is_zero() {
            return Err(Sm9Error::CryptoError(
                "enc master s must not be zero".to_string(),
            ));
        }
        let x = crate::field::fp::Fp::from_bytes(&enc_data[32..64])
            .map_err(|e| Sm9Error::CryptoError(format!("Invalid ppube x: {:?}", e)))?;
        let y = crate::field::fp::Fp::from_bytes(&enc_data[64..96])
            .map_err(|e| Sm9Error::CryptoError(format!("Invalid ppube y: {:?}", e)))?;
        let ppube = G1Point::from_affine(x, y);
        let enc_master = EncMasterKey { s, ppube };

        Ok(Self {
            sign_master,
            enc_master,
        })
    }
}

/// Generate a random scalar in [1, N-1]
pub(crate) fn random_scalar<R: CryptoRng>(rng: &mut R) -> Result<Z256, Sm9Error> {
    // Reduce mod N using constant-time approach:
    // Generate 512 random bits and reduce mod N, then check for zero.
    // This avoids timing variability from reject sampling.
    // Probability of zero is < 2^-256, so retry is virtually never needed.
    let mut buf512 = [0u8; 64]; // 512 bits for bias-free reduction
    rng.fill_bytes(&mut buf512);
    let hi = Z256([
        u64::from_le_bytes(buf512[0..8].try_into().unwrap()),
        u64::from_le_bytes(buf512[8..16].try_into().unwrap()),
        u64::from_le_bytes(buf512[16..24].try_into().unwrap()),
        u64::from_le_bytes(buf512[24..32].try_into().unwrap()),
    ]);
    let lo = Z256([
        u64::from_le_bytes(buf512[32..40].try_into().unwrap()),
        u64::from_le_bytes(buf512[40..48].try_into().unwrap()),
        u64::from_le_bytes(buf512[48..56].try_into().unwrap()),
        u64::from_le_bytes(buf512[56..64].try_into().unwrap()),
    ]);
    let s_reduced = crate::z256::mod_reduce_512(&lo, &hi, &Z256::N);
    if s_reduced.is_zero() {
        // Extremely unlikely (< 2^-256), but handle it
        return random_scalar(rng);
    }
    Ok(s_reduced)
}

/// Compute 2^256 mod m by repeated doubling
/// Cached 2^256 mod m for SM9 prime N
/// N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
static R_MOD_N: once_cell::sync::Lazy<Z256> = once_cell::sync::Lazy::new(|| {
    let _n = Z256([
        0xE56EE19CD69ECF25,
        0x49F2934B18EA8BEE,
        0xD603AB4FF58EC744,
        0xB640000002A3A6F1,
    ]);
    // Pre-computed: 2^256 mod N = 0x49BFFFFFFD5C590E29FC54B00A7138BBB60D6CB4E71574111A911E63296130DB
    Z256([
        0x1A911E63296130DB,
        0xB60D6CB4E7157411,
        0x29FC54B00A7138BB,
        0x49BFFFFFFD5C590E,
    ])
});

pub fn compute_2_256_mod_m(m: &Z256) -> Z256 {
    // For SM9 prime N, use cached value
    let n = Z256([
        0xE56EE19CD69ECF25,
        0x49F2934B18EA8BEE,
        0xD603AB4FF58EC744,
        0xB640000002A3A6F1,
    ]);
    if crate::arith::z256::cmp(m, &n) == 0 {
        *R_MOD_N
    } else {
        crate::arith::z256::compute_2_256_mod_m(m)
    }
}

/// Modular multiplication: (a * b) mod m
/// Uses mul_wide + proper reduction
pub fn modmul(a: &Z256, b: &Z256, m: &Z256) -> Z256 {
    crate::arith::z256::modmul(a, b, m)
}

/// Subtraction modulo m
pub(crate) fn sub_mod(a: &Z256, b: &Z256, m: &Z256) -> Z256 {
    crate::arith::z256::sub_mod(a, b, m)
}

/// Compare two Z256 values
pub(crate) fn cmp(a: &Z256, b: &Z256) -> i8 {
    crate::arith::z256::cmp(a, b)
}

/// Modular inverse using Fermat's little theorem
/// Only correct when m is prime: a^(-1) ≡ a^(m-2) (mod m)
pub(crate) fn modinv(a: &Z256, m: &Z256) -> Option<Z256> {
    if a.is_zero() {
        return None;
    }
    // a^(-1) = a^(m-2) mod m
    let m_minus_2 = {
        // m - 2 = m + (-2) in two's complement, but we do it properly
        let (diff, borrow) = crate::z256::sub_with_borrow(m, &Z256([2, 0, 0, 0]));
        if borrow != 0 {
            return None; // m < 2, shouldn't happen
        }
        diff
    };
    Some(pow_mod(a, &m_minus_2, m))
}

/// Modular exponentiation: base^exp mod m (constant-time)
///
/// Uses square-and-multiply-always pattern to avoid timing side channels.
/// No data-dependent branches on exponent bits.
///
/// # Panics
/// Panics if m is zero.
pub(crate) fn pow_mod(base: &Z256, exp: &Z256, m: &Z256) -> Z256 {
    assert!(!m.is_zero(), "pow_mod: modulus must not be zero");
    let mut result = Z256::ONE;
    let mut base = *base;

    // Reduce base mod m first (at most one subtraction needed)
    if cmp(&base, m) >= 0 {
        let (diff, borrow) = crate::z256::sub_with_borrow(&base, m);
        if borrow == 0 {
            base = diff;
        }
    }

    // Constant-time: always square and always multiply, use conditional select
    for i in 0..256 {
        let bit = exp.ct_bit(i);
        // Always multiply result * base (even if bit is 0, we discard it)
        let product = modmul(&result, &base, m);
        result = Z256::conditional_select(&result, &product, bit);
        base = modmul(&base, &base, m);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modinv() {
        let a = Z256([3, 0, 0, 0]);
        let m = Z256([7, 0, 0, 0]);
        let inv = modinv(&a, &m).unwrap();
        // 3 * 5 = 15 ≡ 1 mod 7
        assert_eq!(inv.0[0], 5);
    }

    #[test]
    fn test_modinv_small() {
        // Test with small numbers
        let a = Z256([5, 0, 0, 0]);
        let m = Z256([17, 0, 0, 0]);
        let inv = modinv(&a, &m).unwrap();
        // Verify: 5 * 7 = 35 ≡ 1 mod 17
        let product = modmul(&a, &inv, &m);
        assert_eq!(product.0[0], 1);
    }

    #[test]
    fn test_modmul() {
        let a = Z256([3, 0, 0, 0]);
        let b = Z256([5, 0, 0, 0]);
        let m = Z256([7, 0, 0, 0]);
        let result = modmul(&a, &b, &m);
        // 3 * 5 = 15 ≡ 1 mod 7
        assert_eq!(result.0[0], 1);
    }

    #[test]
    fn bench_modinv_large() {
        use std::time::Instant;
        let a = Z256([123456789, 0, 0, 0]);
        let m = Z256([
            0xE56EE19CD69ECF25,
            0x49F2934B18EA8BEE,
            0xD603AB4FF58EC744,
            0xB640000002A3A6F1,
        ]);

        let start = Instant::now();
        let result = modinv(&a, &m);
        let elapsed = start.elapsed();

        println!("modinv: {:?}", elapsed);
        assert!(result.is_some());
    }

    #[test]
    fn test_modmul_against_python() {
        let n = Z256::N;
        let a = Z256([
            0x0000000000000001,
            0x90ABCDEF12345678,
            0xCAFEBABEDEADBEEF,
            0x0000000000000000,
        ]);
        let b = Z256([
            0x6666666666666666,
            0x5555555555555555,
            0x4444444444444444,
            0x2222222211111111,
        ]);
        let result = modmul(&a, &b, &n);
        // Python expected: [0x8330250A54E01D80, 0xFBD19454EBCF500D, 0x347B2FA11036FBC3, 0x09C19685B3A61B47]
        let expected = Z256([
            0x8330250A54E01D80,
            0xFBD19454EBCF500D,
            0x347B2FA11036FBC3,
            0x09C19685B3A61B47,
        ]);
        assert_eq!(
            result, expected,
            "modmul doesn't match Python: got {:?}",
            result
        );
    }

    #[test]
    fn test_modmul_square_large() {
        let n = Z256::N;
        let a = Z256([
            0x08AB47CA82CD91EA,
            0xFF6670E8CBCE1488,
            0xA0067D790E99F279,
            0x3E2A3CA3794BA51B,
        ]);

        // First test mod_reduce_512 directly
        let (low, high) = crate::z256::mul_wide(&a, &a);
        println!("low  = {:?}", low);
        println!("high = {:?}", high);

        let result = crate::z256::mod_reduce_512(&low, &high, &n);
        println!("mod_reduce_512 result = {:?}", result);

        let result2 = modmul(&a, &a, &n);
        println!("modmul result = {:?}", result2);

        // Python: a^2 mod N = [0xAC7FD73D6698D82C, 0x38FEC876E0947F48, 0x3C3C64220E55C4D1, 0x948826430BE32BBF]
        let expected = Z256([
            0xAC7FD73D6698D82C,
            0x38FEC876E0947F48,
            0x3C3C64220E55C4D1,
            0x948826430BE32BBF,
        ]);
        assert_eq!(
            result, expected,
            "mod_reduce_512 doesn't match Python: got {:?}",
            result
        );
    }

    #[test]
    fn test_modinv_against_python() {
        // Python verification with correct N:
        // N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
        // s_plus_h1 = (s + h1) % N where s and h1 are from seed=42 test run
        // Python inv(s_plus_h1) via pow(s_plus_h1, N-2, N):
        //   [0x4BEEEF0B946E2908, 0xDA8CC53D08CC3EFA, 0x421E05BE53AD4B41, 0x85A576ADFCE92A56]
        // Python scalar = s * inv(s_plus_h1) % N:
        //   [0x5701846581C15CD8, 0x4B5E5AA7F538FFD3, 0x33D4A6573FDB6171, 0x9E4E7B50B2F4E915]

        let n = Z256::N;

        // s_plus_h1 mod N
        let s_plus_h1 = Z256([
            0x08AB47CA82CD91EA,
            0xFF6670E8CBCE1488,
            0xA0067D790E99F279,
            0x3E2A3CA3794BA51B,
        ]);

        let inv = modinv(&s_plus_h1, &n).expect("modinv should succeed for N prime");

        // Verify: inv * (s+h1) mod N == 1
        let product = modmul(&s_plus_h1, &inv, &n);
        assert_eq!(
            product,
            Z256::ONE,
            "inv * (s+h1) mod N should be 1, got {:?}",
            product
        );

        // Compare with Python expected value
        let expected_inv = Z256([
            0x4BEEEF0B946E2908,
            0xDA8CC53D08CC3EFA,
            0x421E05BE53AD4B41,
            0x85A576ADFCE92A56,
        ]);
        assert_eq!(inv, expected_inv, "modinv result doesn't match Python");

        // Also test scalar = s * inv(s+h1) mod N
        let s = Z256([
            9713269763989775522,
            10011513049433592189,
            11740708795755607249,
            7487565853151867058,
        ]);
        let scalar = modmul(&s, &inv, &n);
        let expected_scalar = Z256([
            0x5701846581C15CD8,
            0x4B5E5AA7F538FFD3,
            0x33D4A6573FDB6171,
            0x9E4E7B50B2F4E915,
        ]);
        assert_eq!(scalar, expected_scalar, "scalar doesn't match Python");

        // Ultimate check: scalar * (s+h1) mod N == s
        let check = modmul(&scalar, &s_plus_h1, &n);
        assert_eq!(check, s, "scalar * (s+h1) mod N != s");
    }

    #[test]
    fn test_pow_mod_small_exp() {
        let n = Z256::N;
        let a = Z256([
            0x08AB47CA82CD91EA,
            0xFF6670E8CBCE1488,
            0xA0067D790E99F279,
            0x3E2A3CA3794BA51B,
        ]);

        // Test modmul(a, a, N) = a^2 mod N
        let a2 = modmul(&a, &a, &n);
        let a2_pow = pow_mod(&a, &Z256([2, 0, 0, 0]), &n);
        assert_eq!(a2, a2_pow, "a^2 via modmul != a^2 via pow_mod");

        // Test modmul(a, a^2, N) = a^3 mod N
        let a3 = modmul(&a, &a2, &n);
        let a3_pow = pow_mod(&a, &Z256([3, 0, 0, 0]), &n);
        assert_eq!(a3, a3_pow, "a^3 via modmul != a^3 via pow_mod");

        // Verify against Python reference values
        let expected_a2 = Z256([
            0xAC7FD73D6698D82C,
            0x38FEC876E0947F48,
            0x3C3C64220E55C4D1,
            0x948826430BE32BBF,
        ]);
        let expected_a3 = Z256([
            0x1D928799BF5DA0B0,
            0x640508EB2BED99AD,
            0x1EE47600FA40D745,
            0x874B545A0FC0652F,
        ]);
        assert_eq!(a2, expected_a2, "a^2 doesn't match Python");
        assert_eq!(a3, expected_a3, "a^3 doesn't match Python");
    }
}
