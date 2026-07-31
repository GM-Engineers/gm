//! SM3 hash algorithm implementation

use crate::error::CryptoError;
use crate::utils::{bytes_to_base64, bytes_to_hex};
use sm3::{Digest, Sm3};
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;
use zeroize::Zeroizing;

/// SM3 hasher
pub struct Sm3Hasher;

impl Sm3Hasher {
    /// Compute SM3 hash of data
    pub fn hash(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut hasher = Sm3::new();
        hasher.update(data);
        let result = hasher.finalize();
        Ok(result.to_vec())
    }

    /// Compute SM3 hash of data, return hex string
    pub fn hash_hex(data: &[u8]) -> Result<String, CryptoError> {
        let hash = Self::hash(data)?;
        Ok(bytes_to_hex(&hash))
    }

    /// Compute SM3 hash of data, return Base64 string
    pub fn hash_base64(data: &[u8]) -> Result<String, CryptoError> {
        let hash = Self::hash(data)?;
        Ok(bytes_to_base64(&hash))
    }
}

/// SM3 HMAC calculator
#[derive(ZeroizeOnDrop)]
pub struct Sm3Hmac {
    key: Vec<u8>,
}

impl Sm3Hmac {
    /// Create HMAC calculator
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Compute HMAC value
    pub fn compute(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // SM3 HMAC implementation: HMAC(K, m) = H(K' || H(K' || m))
        // where K' is key padded to block size (64 bytes)
        let block_size = 64;
        let mut key_padded = Zeroizing::new(vec![0u8; block_size]);

        if self.key.len() > block_size {
            // If key length exceeds block size, hash the key first
            let key_hash = Sm3Hasher::hash(&self.key)?;
            key_padded[..key_hash.len()].copy_from_slice(&key_hash);
        } else {
            key_padded[..self.key.len()].copy_from_slice(&self.key);
        }

        // internal padding: ipad = 0x36 repeated
        let mut ipad = Zeroizing::new(vec![0x36u8; block_size]);
        for i in 0..block_size {
            ipad[i] ^= key_padded[i];
        }

        // compute H(K' ^ ipad || m)
        let mut hasher1 = Sm3::new();
        hasher1.update(ipad.as_slice());
        hasher1.update(data);
        let inner_hash = hasher1.finalize();

        // external padding: opad = 0x5C repeated
        let mut opad = Zeroizing::new(vec![0x5Cu8; block_size]);
        for i in 0..block_size {
            opad[i] ^= key_padded[i];
        }

        // compute H(K' ^ opad || H(K' ^ ipad || m))
        let mut hasher2 = Sm3::new();
        hasher2.update(opad.as_slice());
        hasher2.update(inner_hash);
        let hmac = hasher2.finalize();

        Ok(hmac.to_vec())
    }

    /// Compute HMAC value, return hex string
    pub fn compute_hex(&self, data: &[u8]) -> Result<String, CryptoError> {
        let hmac = self.compute(data)?;
        Ok(bytes_to_hex(&hmac))
    }

    /// Verify HMAC value
    pub fn verify(&self, data: &[u8], hmac: &[u8]) -> Result<bool, CryptoError> {
        let computed = self.compute(data)?;
        if computed.len() != hmac.len() {
            return Ok(false);
        }
        // Constant-time comparison to prevent timing attacks
        Ok(computed.ct_eq(hmac).into())
    }
}
