//! Unified cryptographic trait definitions for the GM suite.
//!
//! Provides abstract interfaces for SM2/SM3/SM4/SM9 operations, enabling:
//! - Backend-agnostic crypto operations (pure Rust vs GmSSL FFI)
//! - Dependency injection for testing (mock implementations)
//! - Crypto agility (algorithm substitution without API changes)
//!
//! # Design Principles
//!
//! 1. **Minimal surface**: Only operations actually used by gm-tls/gm-kms are exposed
//! 2. **Fallible**: All operations return `Result` to accommodate backend errors
//! 3. **Zeroize-aware**: Key-bearing types implement `ZeroizeOnDrop`
//! 4. **Constant-time**: Implementations MUST use constant-time comparison for verification
//!
//! # Example
//!
//! ```rust,ignore
//! use gm_crypto::traits::{Digest, AsymmetricSign, AsymmetricVerify};
//!
//! fn verify_message<V: AsymmetricVerify>(
//!     verifier: &V,
//!     message: &[u8],
//!     signature: &[u8],
//! ) -> Result<bool, gm_crypto::error::CryptoError> {
//!     match verifier.verify(message, signature) {
//!         Ok(()) => Ok(true),
//!         Err(gm_crypto::error::CryptoError::SignatureVerificationFailed) => Ok(false),
//!         Err(e) => Err(e),
//!     }
//! }
//! ```

use crate::error::CryptoError;

// ============================================================================
// Hash Traits
// ============================================================================

/// Cryptographic hash function trait (e.g., SM3)
pub trait Digest: Send + Sync {
    /// Output size in bytes (32 for SM3)
    const OUTPUT_SIZE: usize;

    /// Compute hash of data
    fn hash(data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Compute hash and return hex string
    fn hash_hex(data: &[u8]) -> Result<String, CryptoError> {
        let bytes = Self::hash(data)?;
        Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
    }
}

/// Message Authentication Code trait (e.g., SM3-HMAC)
pub trait Mac: Send + Sync {
    /// Compute MAC over data with the given key
    fn mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Verify MAC (constant-time comparison)
    fn verify(key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool, CryptoError>;
}

// ============================================================================
// Asymmetric Signature Traits
// ============================================================================

/// Asymmetric signing trait (e.g., SM2, SM9 signature)
pub trait AsymmetricSign: Send + Sync {
    /// Sign data, returning signature bytes
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Sign data with explicit identity (for IBS schemes like SM9)
    fn sign_with_identity(&self, data: &[u8], _identity: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Default: identity is implicit in the key
        self.sign(data)
    }
}

/// Asymmetric verification trait (e.g., SM2, SM9 signature)
pub trait AsymmetricVerify: Send + Sync {
    /// Verify a signature on data.
    ///
    /// Returns `Ok(())` if valid, `Err(SignatureVerificationFailed)` if invalid.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;

    /// Verify a signature with explicit identity (for IBS schemes like SM9)
    fn verify_with_identity(
        &self,
        data: &[u8],
        signature: &[u8],
        _identity: &[u8],
    ) -> Result<(), CryptoError> {
        // Default: identity is implicit in the key
        self.verify(data, signature)
    }
}

// ============================================================================
// Key Encapsulation / Encryption Traits
// ============================================================================

/// Asymmetric encryption trait (e.g., SM2 encryption, SM9 KEM)
pub trait AsymmetricEncrypt: Send + Sync {
    /// Encrypt data, returning ciphertext
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Encrypt with identity (for IBE schemes like SM9)
    fn encrypt_with_identity(
        &self,
        plaintext: &[u8],
        _identity: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.encrypt(plaintext)
    }
}

/// Asymmetric decryption trait
pub trait AsymmetricDecrypt: Send + Sync {
    /// Decrypt ciphertext, returning plaintext
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt with identity (for IBE schemes like SM9)
    fn decrypt_with_identity(
        &self,
        ciphertext: &[u8],
        _identity: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.decrypt(ciphertext)
    }
}

// ============================================================================
// Symmetric Encryption Traits
// ============================================================================

/// Authenticated symmetric encryption trait (e.g., SM4-GCM)
pub trait AeadEncrypt: Send + Sync {
    /// Nonce length in bytes
    const NONCE_SIZE: usize;
    /// Tag length in bytes
    const TAG_SIZE: usize;

    /// Encrypt with associated data, returning (ciphertext, tag)
    fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Decrypt with associated data, verifying tag
    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Symmetric block cipher trait (without AEAD, e.g., SM4-CBC)
pub trait BlockCipher: Send + Sync {
    /// Key length in bytes
    const KEY_SIZE: usize;
    /// Block size in bytes
    const BLOCK_SIZE: usize;

    /// Encrypt in CBC mode with PKCS#7 padding
    fn encrypt_cbc(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt in CBC mode, removing PKCS#7 padding
    fn decrypt_cbc(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

// ============================================================================
// Key Agreement Traits
// ============================================================================

/// Key agreement / key exchange trait (e.g., SM2-KEX, ECDH)
pub trait KeyAgreement: Send + Sync {
    /// Public key type for exchange
    type PublicKey: AsRef<[u8]> + Send + Sync;
    /// Shared secret type
    type SharedSecret: AsRef<[u8]> + ZeroizeOnDrop + Send + Sync;

    /// Generate an ephemeral key pair and return the public key
    fn generate_ephemeral(&mut self) -> Result<Self::PublicKey, CryptoError>;

    /// Compute shared secret from peer's public key
    fn compute_shared_secret(
        &mut self,
        peer_public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, CryptoError>;
}

// Re-export for trait bound
pub use zeroize::ZeroizeOnDrop;

// ============================================================================
// SM2 Trait Implementations
// ============================================================================

impl AsymmetricSign for crate::sm2::Sm2Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.sign(data)
    }
}

impl AsymmetricVerify for crate::sm2::Sm2Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        self.verify(data, signature)
    }
}

impl AsymmetricEncrypt for crate::sm2::Sm2Encryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt(plaintext)
    }
}

impl AsymmetricDecrypt for crate::sm2::Sm2Decryptor {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt(ciphertext)
    }
}

// ============================================================================
// SM2 ECDH KeyAgreement Implementation
// ============================================================================

/// Zeroizing wrapper for SM2 ECDH shared secret bytes.
///
/// Automatically zeroizes on drop to prevent secret leakage.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Sm2SharedSecret(Vec<u8>);

impl AsRef<[u8]> for Sm2SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl KeyAgreement for crate::sm2::Sm2EcdhKeypair {
    type PublicKey = Vec<u8>;
    type SharedSecret = Sm2SharedSecret;

    fn generate_ephemeral(&mut self) -> Result<Self::PublicKey, CryptoError> {
        // Sm2EcdhKeypair is already ephemeral; just return the public key
        Ok(self.public_key_bytes())
    }

    fn compute_shared_secret(
        &mut self,
        peer_public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, CryptoError> {
        let secret = crate::sm2::Sm2EcdhKeypair::compute_shared_secret(self, peer_public)?;
        Ok(Sm2SharedSecret(secret))
    }
}

// ============================================================================
// Default Implementations
// ============================================================================

/// SM3 Digest implementation
impl Digest for crate::sm3::Sm3Hasher {
    const OUTPUT_SIZE: usize = 32;

    fn hash(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Self::hash(data)
    }
}

/// SM3 HMAC implementation
impl Mac for crate::sm3::Sm3Hmac {
    fn mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let hmac = Self::new(key);
        hmac.compute(data)
    }

    fn verify(key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool, CryptoError> {
        let hmac = Self::new(key);
        hmac.verify(data, expected)
    }
}

/// SM4-GCM AEAD implementation
impl AeadEncrypt for crate::sm4::Sm4Cipher {
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.encrypt_gcm(plaintext, nonce, aad)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_gcm(ciphertext, nonce, aad, tag)
    }
}

/// SM4-CBC block cipher implementation
impl BlockCipher for crate::sm4::Sm4Cipher {
    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 16;

    fn encrypt_cbc(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt_cbc(data, iv)
    }

    fn decrypt_cbc(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_cbc(ciphertext, iv)
    }
}

// ============================================================================
// Cipher Suite Identifier
// ============================================================================

/// GM cipher suite identifiers per GM/T 0024-2014 and IANA-like registration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GmCipherSuite {
    /// TLS 1.3 + SM2 + SM3 + SM4-GCM
    /// Corresponds to RFC 8998 suite: TLS_SM4_GCM_SM3
    TlsSm4GcmSm3,
    /// TLCP + SM2 + SM3 + SM4-CBC
    /// Corresponds to GB/T 38636-2020 suite: ECDHE_SM4_CBC_SM3
    TlcpEcdheSm4CbcSm3,
    /// TLCP + SM2 + SM3 + SM4-GCM (proposed)
    TlcpEcdheSm4GcmSm3,
}

impl GmCipherSuite {
    /// Get the signature algorithm name for this suite
    pub fn signature_algo(&self) -> &'static str {
        match self {
            Self::TlsSm4GcmSm3 | Self::TlcpEcdheSm4CbcSm3 | Self::TlcpEcdheSm4GcmSm3 => "SM2",
        }
    }

    /// Get the hash algorithm name for this suite
    pub fn hash_algo(&self) -> &'static str {
        match self {
            Self::TlsSm4GcmSm3 | Self::TlcpEcdheSm4CbcSm3 | Self::TlcpEcdheSm4GcmSm3 => "SM3",
        }
    }

    /// Get the symmetric cipher name for this suite
    pub fn cipher_algo(&self) -> &'static str {
        match self {
            Self::TlsSm4GcmSm3 | Self::TlcpEcdheSm4GcmSm3 => "SM4-GCM",
            Self::TlcpEcdheSm4CbcSm3 => "SM4-CBC",
        }
    }

    /// Returns true if this suite uses AEAD (GCM) mode
    pub fn is_aead(&self) -> bool {
        matches!(self, Self::TlsSm4GcmSm3 | Self::TlcpEcdheSm4GcmSm3)
    }

    /// Returns true if this suite is for TLCP protocol
    pub fn is_tlcp(&self) -> bool {
        matches!(self, Self::TlcpEcdheSm4CbcSm3 | Self::TlcpEcdheSm4GcmSm3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm3_digest_trait() {
        let hash = <crate::sm3::Sm3Hasher as Digest>::hash(b"abc").unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sm3_mac_trait() {
        let key = b"test-key-12345678901234567890";
        let data = b"test data for HMAC";
        let mac_val = <crate::sm3::Sm3Hmac as Mac>::mac(key, data).unwrap();
        assert_eq!(mac_val.len(), 32);
        assert!(<crate::sm3::Sm3Hmac as Mac>::verify(key, data, &mac_val).unwrap());
    }

    #[test]
    fn test_sm4_aead_trait() {
        let key = [0x42u8; 16];
        let cipher = crate::sm4::Sm4Cipher::new(&key).unwrap();
        let nonce = [0u8; 12];
        let aad = b"aad";
        let plaintext = b"hello world";

        let (ct, tag) =
            <crate::sm4::Sm4Cipher as AeadEncrypt>::encrypt(&cipher, plaintext, &nonce, aad)
                .unwrap();
        let pt = <crate::sm4::Sm4Cipher as AeadEncrypt>::decrypt(&cipher, &ct, &nonce, aad, &tag)
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_sm4_block_cipher_trait() {
        let key = [0x42u8; 16];
        let cipher = crate::sm4::Sm4Cipher::new(&key).unwrap();
        let iv = [0u8; 16];
        let plaintext = b"hello world test";

        let ct =
            <crate::sm4::Sm4Cipher as BlockCipher>::encrypt_cbc(&cipher, plaintext, &iv).unwrap();
        let pt = <crate::sm4::Sm4Cipher as BlockCipher>::decrypt_cbc(&cipher, &ct, &iv).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_cipher_suite_properties() {
        let suite = GmCipherSuite::TlsSm4GcmSm3;
        assert_eq!(suite.signature_algo(), "SM2");
        assert_eq!(suite.hash_algo(), "SM3");
        assert_eq!(suite.cipher_algo(), "SM4-GCM");
        assert!(suite.is_aead());
        assert!(!suite.is_tlcp());

        let tlcp = GmCipherSuite::TlcpEcdheSm4CbcSm3;
        assert!(tlcp.is_tlcp());
        assert!(!tlcp.is_aead());
    }

    #[test]
    fn test_sm2_sign_verify_traits() {
        let key_pair = crate::sm2::Sm2KeyPair::generate().unwrap();
        let signer = crate::sm2::Sm2Signer::new(&key_pair).unwrap();
        let data = b"test data for trait";

        let signature = <crate::sm2::Sm2Signer as AsymmetricSign>::sign(&signer, data).unwrap();
        assert_eq!(signature.len(), 64);

        let verifier = crate::sm2::Sm2Verifier::new(
            &key_pair.public_key_bytes_uncompressed(),
            key_pair.distid(),
        )
        .unwrap();
        <crate::sm2::Sm2Verifier as AsymmetricVerify>::verify(&verifier, data, &signature).unwrap();
    }

    #[test]
    fn test_sm2_encrypt_decrypt_traits() {
        let key_pair = crate::sm2::Sm2KeyPair::generate().unwrap();
        let encryptor =
            crate::sm2::Sm2Encryptor::new(&key_pair.public_key_bytes_uncompressed()).unwrap();
        let plaintext = b"secret message";

        let ciphertext =
            <crate::sm2::Sm2Encryptor as AsymmetricEncrypt>::encrypt(&encryptor, plaintext)
                .unwrap();

        let decryptor = crate::sm2::Sm2Decryptor::new(key_pair.duplicate());
        let decrypted =
            <crate::sm2::Sm2Decryptor as AsymmetricDecrypt>::decrypt(&decryptor, &ciphertext)
                .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm2_key_agreement_trait() {
        let mut alice = crate::sm2::Sm2EcdhKeypair::generate().unwrap();
        let mut bob = crate::sm2::Sm2EcdhKeypair::generate().unwrap();

        let alice_pk =
            <crate::sm2::Sm2EcdhKeypair as KeyAgreement>::generate_ephemeral(&mut alice).unwrap();
        let bob_pk =
            <crate::sm2::Sm2EcdhKeypair as KeyAgreement>::generate_ephemeral(&mut bob).unwrap();

        let alice_secret = <crate::sm2::Sm2EcdhKeypair as KeyAgreement>::compute_shared_secret(
            &mut alice, &bob_pk,
        )
        .unwrap();
        let bob_secret = <crate::sm2::Sm2EcdhKeypair as KeyAgreement>::compute_shared_secret(
            &mut bob, &alice_pk,
        )
        .unwrap();

        assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
    }

    #[test]
    fn test_digest_output_size() {
        assert_eq!(<crate::sm3::Sm3Hasher as Digest>::OUTPUT_SIZE, 32);
        assert_eq!(<crate::sm4::Sm4Cipher as AeadEncrypt>::NONCE_SIZE, 12);
        assert_eq!(<crate::sm4::Sm4Cipher as AeadEncrypt>::TAG_SIZE, 16);
        assert_eq!(<crate::sm4::Sm4Cipher as BlockCipher>::KEY_SIZE, 16);
        assert_eq!(<crate::sm4::Sm4Cipher as BlockCipher>::BLOCK_SIZE, 16);
    }
}
