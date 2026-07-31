//! SM9 encryption algorithm

use crate::curve::g1::G1Point;
use crate::curve::ScalarMul;
// use crate::field::FieldElement;
use crate::hash;
use crate::key::random_scalar;
use crate::key::EncUserKey;
use crate::pairing;
use crate::Sm9Error;
use rand::CryptoRng;
use sm3::{Digest, Sm3};
use zeroize::ZeroizeOnDrop;

/// SM9 ciphertext
#[derive(Clone, ZeroizeOnDrop)]
pub struct Ciphertext {
    /// C1: G1 point (KEM output)
    pub c1: G1Point,
    /// C2: encrypted data (XOR with key stream)
    pub c2: Vec<u8>,
    /// C3: authentication tag
    pub c3: Vec<u8>,
}

impl core::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ciphertext")
            .field("c1", &self.c1)
            .field("c2_len", &self.c2.len())
            .field("c3_len", &self.c3.len())
            .finish()
    }
}

impl Ciphertext {
    /// Serialize ciphertext to bytes in GM/T 0044-2016 preferred order: C1‖C3‖C2.
    /// C1: 65 bytes (uncompressed G1 point), C3: 32 bytes (HMAC-SM3), C2: variable.
    ///
    /// This is the default serialization per GM/T 0044-2016 and newer standards.
    /// For the legacy C1‖C2‖C3 order, use `to_bytes_c1c2c3()`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_c1c3c2()
    }

    /// Serialize ciphertext in legacy C1‖C2‖C3 order (older SM9 standards).
    /// C1: 65 bytes, C2: variable, C3: 32 bytes (HMAC-SM3).
    /// Prefer `to_bytes()` (C1‖C3‖C2) for new implementations.
    pub fn to_bytes_c1c2c3(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(65 + self.c2.len() + self.c3.len());
        if let Some((x, y)) = self.c1.to_affine() {
            bytes.push(0x04);
            bytes.extend_from_slice(&x.to_bytes());
            bytes.extend_from_slice(&y.to_bytes());
        } else {
            bytes.push(0x00);
            bytes.extend_from_slice(&[0u8; 64]);
        }
        bytes.extend_from_slice(&self.c2);
        bytes.extend_from_slice(&self.c3);
        bytes
    }

    /// Serialize ciphertext in GM/T 0044-2016 preferred order: C1‖C3‖C2.
    /// C1: 65 bytes, C3: 32 bytes (HMAC-SM3), C2: variable.
    /// This is the recommended format per newer SM9 standards.
    pub fn to_bytes_c1c3c2(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(65 + self.c3.len() + self.c2.len());
        if let Some((x, y)) = self.c1.to_affine() {
            bytes.push(0x04);
            bytes.extend_from_slice(&x.to_bytes());
            bytes.extend_from_slice(&y.to_bytes());
        } else {
            bytes.push(0x00);
            bytes.extend_from_slice(&[0u8; 64]);
        }
        bytes.extend_from_slice(&self.c3);
        bytes.extend_from_slice(&self.c2);
        bytes
    }

    /// Parse ciphertext from C1‖C3‖C2 format (GM/T 0044-2016 preferred).
    /// C3 immediately follows C1, then C2 fills the remainder.
    pub fn from_bytes_c1c3c2(bytes: &[u8]) -> Result<Self, Sm9Error> {
        if bytes.len() < 65 + 32 {
            return Err(Sm9Error::InvalidParameter(format!(
                "Ciphertext too short: {} bytes, need at least 97",
                bytes.len()
            )));
        }
        if bytes[0] != 0x04 && bytes[0] != 0x00 {
            return Err(Sm9Error::InvalidParameter(format!(
                "Invalid C1 prefix: expected 0x04 or 0x00, got 0x{:02x}",
                bytes[0]
            )));
        }
        let x = crate::field::fp::Fp::from_bytes(&bytes[1..33])?;
        let y = crate::field::fp::Fp::from_bytes(&bytes[33..65])?;
        let c1 = crate::curve::g1::G1Point::from_affine(x, y);
        let c3 = bytes[65..97].to_vec(); // HMAC-SM3 = 32 bytes
        let c2 = bytes[97..].to_vec();
        Ok(Self { c1, c2, c3 })
    }

    /// Parse ciphertext from bytes.
    /// Default format: C1‖C3‖C2 (GM/T 0044-2016 preferred).
    /// For legacy C1‖C2‖C3 format, use `from_bytes_c1c2c3()`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Sm9Error> {
        Self::from_bytes_c1c3c2(bytes)
    }

    /// Parse ciphertext from legacy C1‖C2‖C3 format.
    /// Format: 0x04||c1_x||c1_y || c2 || c3
    /// Total: 65 (C1) + (len - 65 - 32) (C2) + 32 (C3)
    pub fn from_bytes_c1c2c3(bytes: &[u8]) -> Result<Self, Sm9Error> {
        if bytes.len() < 65 + 32 {
            return Err(Sm9Error::InvalidParameter(format!(
                "Ciphertext too short: {} bytes, need at least 97",
                bytes.len()
            )));
        }
        if bytes[0] != 0x04 && bytes[0] != 0x00 {
            return Err(Sm9Error::InvalidParameter(format!(
                "Invalid C1 prefix: expected 0x04 or 0x00, got 0x{:02x}",
                bytes[0]
            )));
        }
        let x = crate::field::fp::Fp::from_bytes(&bytes[1..33])?;
        let y = crate::field::fp::Fp::from_bytes(&bytes[33..65])?;
        let c1 = crate::curve::g1::G1Point::from_affine(x, y);
        let c3_len = 32; // HMAC-SM3 output
        let c2_len = bytes.len() - 65 - c3_len;
        let c2 = bytes[65..65 + c2_len].to_vec();
        let c3 = bytes[65 + c2_len..].to_vec();
        Ok(Self { c1, c2, c3 })
    }
}

/// SM9 encryptor
pub struct Encryptor {
    recipient_id: Vec<u8>,
    ppube: G1Point,
}

impl Encryptor {
    /// Create a new encryptor for a recipient
    pub fn new(recipient_id: &[u8], ppube: &G1Point) -> Self {
        Self {
            recipient_id: recipient_id.to_vec(),
            ppube: *ppube,
        }
    }

    /// Encrypt a message per GM/T 0044-2016
    pub fn encrypt(
        &self,
        message: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<Ciphertext, Sm9Error> {
        let klen = message.len() + 32; // key stream length + MAC key length

        // KEM
        let (k, c1) = self.kem_encrypt(rng, klen)?;

        // DEM: XOR encrypt with key stream
        let c2 = xor_bytes(message, &k[..message.len()]);

        // C3 = SM3(K2 ‖ C2) per GM/T 0044-2016 §6.4
        // K2 = K[message.len()..] (last 32 bytes of KDF output)
        // Note: was incorrectly using HMAC-SM3
        let k2 = &k[message.len()..];
        let c3 = Sm3::digest([k2, &c2].concat()).to_vec();

        Ok(Ciphertext { c1, c2, c3 })
    }

    /// SM9 KEM encryption per GM/T 0044-2016
    fn kem_encrypt(
        &self,
        rng: &mut impl CryptoRng,
        klen: usize,
    ) -> Result<(Vec<u8>, G1Point), Sm9Error> {
        let p1 = crate::params::g1_generator();

        // Q = H1(ID || hid, N) * P1 + Ppube
        let h1 = hash::hash1(&self.recipient_id, 0x02);
        let q_scalar = h1;
        let q_point = p1.scalar_mul(&q_scalar).add(&self.ppube);

        const MAX_ENCRYPT_RETRIES: u32 = 128;
        for _ in 0..MAX_ENCRYPT_RETRIES {
            // rand r in [1, N-1]
            let r = random_scalar(rng)?;

            // C1 = r * Q
            let c1 = q_point.scalar_mul(&r);

            // g = e(Ppube, P2)
            let p2 = crate::params::g2_generator();
            let g = pairing::pairing(&self.ppube, &p2);

            // w = g^r
            let w = g.pow(&r);
            let w_bytes = w.to_bytes_gmssl();

            // K = KDF(C1 || w || ID, klen)
            let c1_bytes = g1_to_bytes(&c1)?;
            let k = sm9_kdf(&c1_bytes, &w_bytes, &self.recipient_id, klen);

            if !is_all_zeros(&k) {
                return Ok((k, c1));
            }
        }
        Err(Sm9Error::EncryptionError(
            "Max retries exceeded — KDF output all zeros".to_string(),
        ))
    }
}

/// SM9 decryptor
pub struct Decryptor {
    key: EncUserKey,
}

impl Decryptor {
    /// Create a new decryptor with a user encryption key
    pub fn new(key: EncUserKey) -> Self {
        Self { key }
    }

    /// Decrypt a ciphertext
    pub fn decrypt(&self, ciphertext: &Ciphertext, id: &[u8]) -> Result<Vec<u8>, Sm9Error> {
        let klen = ciphertext.c2.len() + 32; // message length + MAC key length

        // KEM decrypt
        let k = self.kem_decrypt(&ciphertext.c1, id, klen)?;

        // Verify C3 = SM3(K2 ‖ C2) per GM/T 0044-2016 §6.4
        let k2 = &k[ciphertext.c2.len()..];
        let computed_c3 = Sm3::digest([k2, &ciphertext.c2].concat()).to_vec();

        use subtle::ConstantTimeEq;
        let c3_matches: bool = computed_c3.ct_eq(&ciphertext.c3).into();
        if !c3_matches {
            return Err(Sm9Error::DecryptionFailed);
        }

        // XOR decrypt
        let plaintext = xor_bytes(&ciphertext.c2, &k[..ciphertext.c2.len()]);
        Ok(plaintext)
    }

    /// SM9 KEM decryption
    fn kem_decrypt(&self, c1: &G1Point, id: &[u8], klen: usize) -> Result<Vec<u8>, Sm9Error> {
        // w = e(C1, de)
        let w = pairing::pairing(c1, &self.key.de);
        let w_bytes = w.to_bytes_gmssl();

        // K = KDF(C1 || w || ID, klen)
        let c1_bytes = g1_to_bytes(c1)?;
        let k = sm9_kdf(&c1_bytes, &w_bytes, id, klen);

        if is_all_zeros(&k) {
            return Err(Sm9Error::DecryptionFailed);
        }

        Ok(k)
    }
}

/// SM9 KDF: KDF(C1 || w || ID, klen)
fn sm9_kdf(c1: &[u8], w: &[u8], id: &[u8], klen: usize) -> Vec<u8> {
    let mut k = Vec::with_capacity(klen);
    let mut counter = 1u32;

    while k.len() < klen {
        let mut hasher = Sm3::new();
        hasher.update(c1);
        hasher.update(w);
        hasher.update(id);
        hasher.update(counter.to_be_bytes());
        let hash = hasher.finalize();
        k.extend_from_slice(&hash);
        counter += 1;
    }

    k.truncate(klen);
    k
}

/// Convert G1 point to bytes (uncompressed format)
fn g1_to_bytes(point: &G1Point) -> Result<Vec<u8>, Sm9Error> {
    // Uncompressed format: 0x04 || x || y
    // Each coordinate is 32 bytes (256 bits)
    let mut bytes = Vec::with_capacity(65);
    bytes.push(0x04); // Uncompressed point marker

    // Get affine coordinates
    let (x, y) = point.to_affine().ok_or(Sm9Error::InvalidPoint)?;
    let x_bytes = x.to_bytes();
    let y_bytes = y.to_bytes();

    bytes.extend_from_slice(&x_bytes);
    bytes.extend_from_slice(&y_bytes);

    Ok(bytes)
}

/// XOR bytes
fn xor_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

/// Check if all bytes are zero — constant-time to avoid branch-based side channel
fn is_all_zeros(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| acc | b) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::EncMasterKey;

    #[test]
    fn test_kdf() {
        let c1 = b"c1";
        let w = b"w";
        let id = b"id";
        let k = sm9_kdf(c1, w, id, 64);
        assert_eq!(k.len(), 64);
    }

    #[test]
    fn test_xor_roundtrip() {
        let data = b"hello world";
        let key = b"key";
        let encrypted = xor_bytes(data, key);
        let decrypted = xor_bytes(&encrypted, key);
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut rng = rand::rng();
        let master = EncMasterKey::generate(&mut rng).expect("generate master key");
        let identity = b"test@example.com";
        let user_key = master.extract_key(identity).expect("extract key");

        let encryptor = Encryptor::new(identity, &master.ppube);
        let decryptor = Decryptor::new(user_key);

        let message = b"Hello, SM9 encryption!";
        let ciphertext = encryptor.encrypt(message, &mut rng).expect("encrypt");
        let decrypted = decryptor.decrypt(&ciphertext, identity).expect("decrypt");

        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_different_message() {
        let mut rng = rand::rng();
        let master = EncMasterKey::generate(&mut rng).expect("generate master key");
        let identity = b"test2@example.com";
        let user_key = master.extract_key(identity).expect("extract key");

        let encryptor = Encryptor::new(identity, &master.ppube);
        let decryptor = Decryptor::new(user_key);

        let message = b"Secret message for testing";
        let ciphertext = encryptor.encrypt(message, &mut rng).expect("encrypt");

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        tampered.c2[0] ^= 0xFF;

        let result = decryptor.decrypt(&tampered, identity);
        assert!(
            result.is_err(),
            "tampered ciphertext should fail decryption"
        );
    }
}
