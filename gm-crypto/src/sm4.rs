//! SM4 symmetric encryption algorithm implementation

// Suppress deprecation warnings from the `generic_array` crate (used by `sm4` crate).
// Our own deprecated ECB methods should still produce warnings for callers.
#![allow(deprecated)]

use crate::error::CryptoError;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ghash::GHash;
use sm4::Sm4;
use sm4::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use subtle::ConstantTimeEq;
use typenum;
use typenum::U16;
use universal_hash::UniversalHash;
use zeroize::ZeroizeOnDrop;

/// SM4 key length (bytes)
pub const SM4_KEY_LENGTH: usize = 16;

/// SM4 block size (bytes)
pub const SM4_BLOCK_SIZE: usize = 16;

/// GCM tag length (bytes)
pub const SM4_GCM_TAG_LENGTH: usize = 16;

/// Recommended GCM Nonce length (bytes)
pub const SM4_GCM_NONCE_LENGTH: usize = 12;

/// SM4 encryptor/decryptor
pub struct Sm4Cipher {
    cipher: Sm4,
    key_bytes: KeyBytes,
}

/// Key bytes wrapper that zeroizes on drop
#[derive(ZeroizeOnDrop)]
struct KeyBytes([u8; SM4_KEY_LENGTH]);

impl KeyBytes {
    fn new(key: &[u8]) -> Self {
        let mut kb = [0u8; SM4_KEY_LENGTH];
        kb.copy_from_slice(key);
        Self(kb)
    }
}

impl Sm4Cipher {
    /// Create SM4 encryptor/decryptor
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != SM4_KEY_LENGTH {
            return Err(CryptoError::InvalidKeyLength {
                expected: SM4_KEY_LENGTH,
                actual: key.len(),
            });
        }
        let key_bytes = KeyBytes::new(key);
        // Sm4::new only needs a reference; the cipher makes its own copy of the key
        let key_array = GenericArray::from_slice(&key_bytes.0);
        let cipher = Sm4::new(key_array);
        Ok(Self { cipher, key_bytes })
    }

    /// Create from hex string
    pub fn from_hex(hex_key: &str) -> Result<Self, CryptoError> {
        let key = crate::hex_to_bytes(hex_key)?;
        Self::new(&key)
    }

    /// ECB mode encryption
    ///
    /// # Security Warning
    ///
    /// ECB mode does not provide semantic security — identical plaintext blocks produce
    /// identical ciphertext blocks, leaking patterns. Use CBC or GCM mode instead.
    /// ECB should only be used for compatibility with legacy systems.
    #[deprecated(
        since = "0.2.0",
        note = "ECB mode is insecure: use CBC or GCM mode instead"
    )]
    pub fn encrypt_ecb(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() % SM4_BLOCK_SIZE != 0 {
            return Err(CryptoError::InvalidDataLength(format!(
                "Data length must be a multiple of {} bytes",
                SM4_BLOCK_SIZE
            )));
        }

        let mut result = Vec::with_capacity(data.len());
        for chunk in data.chunks_exact(SM4_BLOCK_SIZE) {
            let mut block = *GenericArray::from_slice(chunk);
            self.cipher.encrypt_block(&mut block);
            result.extend_from_slice(block.as_slice());
        }
        Ok(result)
    }

    /// ECB mode decryption
    #[deprecated(
        since = "0.2.0",
        note = "ECB mode is insecure: use CBC or GCM mode instead"
    )]
    pub fn decrypt_ecb(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if encrypted_data.len() % SM4_BLOCK_SIZE != 0 {
            return Err(CryptoError::InvalidDataLength(format!(
                "Data length must be a multiple of {} bytes",
                SM4_BLOCK_SIZE
            )));
        }

        let mut result = Vec::with_capacity(encrypted_data.len());
        for chunk in encrypted_data.chunks_exact(SM4_BLOCK_SIZE) {
            let mut block = *GenericArray::from_slice(chunk);
            self.cipher.decrypt_block(&mut block);
            result.extend_from_slice(block.as_slice());
        }
        Ok(result)
    }

    /// CBC mode encryption
    pub fn encrypt_cbc(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if iv.len() != SM4_BLOCK_SIZE {
            return Err(CryptoError::InvalidDataLength(format!(
                "IV length must be {} bytes",
                SM4_BLOCK_SIZE
            )));
        }

        // Always add PKCS#7 padding, even if data is already block-aligned.
        // This ensures decryption can always correctly remove padding without
        // accidentally stripping valid plaintext bytes.
        let padding_len = SM4_BLOCK_SIZE - (data.len() % SM4_BLOCK_SIZE);
        let mut padded_data = data.to_vec();
        padded_data.extend(vec![padding_len as u8; padding_len]);

        let mut result = Vec::with_capacity(padded_data.len());
        let mut prev_block = iv.to_vec();

        for chunk in padded_data.chunks_exact(SM4_BLOCK_SIZE) {
            let block_data: Vec<u8> = chunk
                .iter()
                .zip(prev_block.iter())
                .map(|(a, b)| a ^ b)
                .collect();

            let mut block = *GenericArray::from_slice(&block_data);
            self.cipher.encrypt_block(&mut block);
            result.extend_from_slice(block.as_slice());
            prev_block = block.as_slice().to_vec();
        }

        Ok(result)
    }

    /// CBC mode decryption
    pub fn decrypt_cbc(&self, encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if iv.len() != SM4_BLOCK_SIZE {
            return Err(CryptoError::InvalidDataLength(format!(
                "IV length must be {} bytes",
                SM4_BLOCK_SIZE
            )));
        }

        if encrypted_data.len() % SM4_BLOCK_SIZE != 0 {
            return Err(CryptoError::InvalidDataLength(format!(
                "Data length must be a multiple of {} bytes",
                SM4_BLOCK_SIZE
            )));
        }

        let mut result = Vec::with_capacity(encrypted_data.len());
        let mut prev_block = iv.to_vec();

        for chunk in encrypted_data.chunks_exact(SM4_BLOCK_SIZE) {
            let mut block = *GenericArray::from_slice(chunk);
            self.cipher.decrypt_block(&mut block);

            for (i, byte) in block.as_slice().iter().enumerate() {
                result.push(byte ^ prev_block[i]);
            }

            prev_block = chunk.to_vec();
        }

        // Remove PKCS#7 padding (constant-time to prevent padding oracle attacks)
        if let Some(&padding_byte) = result.last() {
            let padding_len = padding_byte as usize;
            if padding_len > 0 && padding_len <= SM4_BLOCK_SIZE {
                let expected_len = result.len() - padding_len;
                // Constant-time validation: check all padding bytes match
                let mut valid = 1u8;
                for &b in result[expected_len..].iter() {
                    // valid stays 1 only if every byte equals padding_len
                    valid &= (b == padding_byte) as u8;
                }
                if valid == 1 {
                    result.truncate(expected_len);
                } else {
                    // Padding validation failed - return error to prevent padding oracle attack
                    return Err(CryptoError::InvalidPadding {
                        expected: padding_len,
                    });
                }
            } else {
                // Invalid: padding_len == 0 (last byte is 0x00) or > block size.
                // Per PKCS#7, valid padding has last byte in range [1, SM4_BLOCK_SIZE].
                // A last byte of 0x00 indicates corrupted or manipulated ciphertext.
                return Err(CryptoError::InvalidPadding {
                    expected: padding_len,
                });
            }
        }

        Ok(result)
    }

    /// GCM mode encryption (with authentication)
    pub fn encrypt_gcm(
        &self,
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if nonce.len() != SM4_GCM_NONCE_LENGTH {
            return Err(CryptoError::InvalidDataLength(format!(
                "Nonce length must be {} bytes",
                SM4_GCM_NONCE_LENGTH
            )));
        }

        // Generate J0 = nonce || 0x00000001
        let mut j0 = [0u8; 16];
        j0[..SM4_GCM_NONCE_LENGTH].copy_from_slice(nonce);
        j0[15] = 1;

        // Compute H = E_k(0)
        let mut h_block = GenericArray::default();
        self.cipher.encrypt_block(&mut h_block);
        let h = GenericArray::clone_from_slice(h_block.as_slice());
        let mut ghash = GHash::new(&h);

        // GHASH(AAD || ciphertext || len(AAD)*8 || len(C)*8)
        ghash_update(&mut ghash, aad);

        // Encrypt: use ctr starting from inc32(J0)
        let mut ctr_iv = j0;
        inc32(&mut ctr_iv);
        let mut ctr = ctr::Ctr128BE::<Sm4>::new(
            GenericArray::from_slice(&self.key_bytes.0),
            GenericArray::from_slice(&ctr_iv),
        );

        let mut ciphertext = data.to_vec();
        ctr.apply_keystream(&mut ciphertext);

        ghash_update(&mut ghash, &ciphertext);
        ghash_lengths(&mut ghash, aad.len(), ciphertext.len());
        let s = ghash.finalize();

        // Tag = E_k(J0) xor S
        let mut t_block = GenericArray::clone_from_slice(&j0);
        self.cipher.encrypt_block(&mut t_block);
        let mut tag = [0u8; SM4_GCM_TAG_LENGTH];
        for i in 0..SM4_GCM_TAG_LENGTH {
            tag[i] = t_block[i] ^ s[i];
        }

        Ok((ciphertext, tag.to_vec()))
    }

    /// GCM mode decryption (with authentication)
    pub fn decrypt_gcm(
        &self,
        encrypted_data: &[u8],
        nonce: &[u8],
        aad: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != SM4_GCM_NONCE_LENGTH {
            return Err(CryptoError::InvalidDataLength(format!(
                "Nonce length must be {} bytes",
                SM4_GCM_NONCE_LENGTH
            )));
        }
        if tag.len() != SM4_GCM_TAG_LENGTH {
            return Err(CryptoError::InvalidDataLength(format!(
                "Tag length must be {} bytes",
                SM4_GCM_TAG_LENGTH
            )));
        }

        // Generate J0
        let mut j0 = [0u8; 16];
        j0[..SM4_GCM_NONCE_LENGTH].copy_from_slice(nonce);
        j0[15] = 1;

        // H
        let mut h_block = GenericArray::default();
        self.cipher.encrypt_block(&mut h_block);
        let h = GenericArray::clone_from_slice(h_block.as_slice());
        let mut ghash = GHash::new(&h);

        // GHASH over AAD and ciphertext
        ghash_update(&mut ghash, aad);
        ghash_update(&mut ghash, encrypted_data);
        ghash_lengths(&mut ghash, aad.len(), encrypted_data.len());
        let s = ghash.finalize();

        // Compute expected Tag
        let mut t_block = GenericArray::clone_from_slice(&j0);
        self.cipher.encrypt_block(&mut t_block);
        let mut expected_tag = [0u8; SM4_GCM_TAG_LENGTH];
        for i in 0..SM4_GCM_TAG_LENGTH {
            expected_tag[i] = t_block[i] ^ s[i];
        }

        if !bool::from(expected_tag.ct_eq(tag)) {
            return Err(CryptoError::Sm4Error(
                "SM4-GCM authentication failed".to_string(),
            ));
        }

        // Decrypt
        let mut ctr_iv = j0;
        inc32(&mut ctr_iv);
        let mut ctr = ctr::Ctr128BE::<Sm4>::new(
            GenericArray::from_slice(&self.key_bytes.0),
            GenericArray::from_slice(&ctr_iv),
        );

        let mut plaintext = encrypted_data.to_vec();
        ctr.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}

/// GHASH padding block handling
fn ghash_update(ghash: &mut GHash, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mut blocks: Vec<GenericArray<u8, U16>> = Vec::new();
    let mut chunks = data.chunks_exact(16);
    for chunk in chunks.by_ref() {
        blocks.push(*GenericArray::from_slice(chunk));
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut block = [0u8; 16];
        block[..rem.len()].copy_from_slice(rem);
        blocks.push(*GenericArray::from_slice(&block));
    }
    if !blocks.is_empty() {
        ghash.update(&blocks);
    }
}

/// GHASH length block
fn ghash_lengths(ghash: &mut GHash, aad_len: usize, c_len: usize) {
    let mut block = [0u8; 16];
    let aad_bits = (aad_len as u64).wrapping_mul(8);
    let c_bits = (c_len as u64).wrapping_mul(8);
    block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    block[8..].copy_from_slice(&c_bits.to_be_bytes());
    ghash.update(&[*GenericArray::from_slice(&block)]);
}

/// 32-bit counter increment
fn inc32(block: &mut [u8; 16]) {
    let mut counter = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    counter = counter.wrapping_add(1);
    block[12..16].copy_from_slice(&counter.to_be_bytes());
}
