//! Cryptographic operation traits for gm-tls.
//!
//! These traits abstract the underlying cryptographic operations, allowing:
//! - Unit testing with mock implementations
//! - Future flexibility to swap crypto backends
//! - Dependency injection for cryptographic operations
//!
//! # Example (Mock for testing)
//!
//! ```rust,ignore
//! use gm_tls::crypto_traits::{Signer, Verifier, Hasher, BlockCipher};
//!
//! struct MockSigner;
//!
//! impl Signer for MockSigner {
//!     fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TlsError> {
//!         Ok(vec![]) // Return empty signature for testing
//!     }
//! }
//! ```

use crate::error::TlsError;

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, TlsError>;

/// Trait for signature operations (SM2 signing)
pub trait Signer: Send + Sync {
    /// Sign data and return the signature (64 bytes for SM2)
    fn sign(&self, data: &[u8]) -> CryptoResult<Vec<u8>>;
}

/// Trait for signature verification (SM2 verification)
pub trait Verifier: Send + Sync {
    /// Verify a signature on data.
    ///
    /// Returns `Ok(())` if signature is valid, `Err` otherwise.
    fn verify(&self, data: &[u8], signature: &[u8]) -> CryptoResult<()>;
}

/// Trait for hash operations (SM3)
pub trait Hasher: Send + Sync {
    /// Compute hash of data (32 bytes for SM3)
    fn hash(&self, data: &[u8]) -> CryptoResult<Vec<u8>>;
}

/// Trait for HMAC operations (SM3-HMAC)
pub trait Hmac: Send + Sync {
    /// Compute HMAC over data
    fn hmac(&self, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>>;
}

/// Trait for symmetric encryption (SM4-GCM)
pub trait BlockCipher: Send + Sync {
    /// Encrypt data with associated data
    /// Returns (ciphertext, tag)
    fn encrypt_gcm(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> CryptoResult<(Vec<u8>, Vec<u8>)>;

    /// Decrypt data with associated data
    fn decrypt_gcm(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
        tag: &[u8],
    ) -> CryptoResult<Vec<u8>>;
}

// ============================================================================
// Default implementations using gm-crypto
// ============================================================================

/// Default crypto implementation module
pub mod default {
    use super::*;
    use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier};
    use gm_crypto::sm3::{Sm3Hasher, Sm3Hmac};
    use gm_crypto::sm4::Sm4Cipher;

    /// Default SM2 signer using gm-crypto
    pub struct DefaultSigner {
        signer: Sm2Signer,
    }

    impl DefaultSigner {
        /// Create a new default signer from a key pair
        pub fn new(key_pair: &Sm2KeyPair) -> Result<Self, TlsError> {
            let signer =
                Sm2Signer::new(key_pair).map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
            Ok(Self { signer })
        }
    }

    impl Signer for DefaultSigner {
        fn sign(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
            self.signer
                .sign(data)
                .map_err(|e| TlsError::HandshakeFailed(e.to_string()))
        }
    }

    /// Default SM2 verifier using gm-crypto
    pub struct DefaultVerifier {
        verifier: Sm2Verifier,
    }

    impl DefaultVerifier {
        /// Create a new default verifier from public key bytes
        pub fn new(pubkey_bytes: &[u8], dist_id: &str) -> Result<Self, TlsError> {
            let verifier = Sm2Verifier::new(pubkey_bytes, dist_id)
                .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
            Ok(Self { verifier })
        }
    }

    impl Verifier for DefaultVerifier {
        fn verify(&self, data: &[u8], signature: &[u8]) -> CryptoResult<()> {
            self.verifier
                .verify(data, signature)
                .map_err(|e| TlsError::HandshakeFailed(e.to_string()))
        }
    }

    /// Default SM3 hasher using gm-crypto
    pub struct DefaultHasher;

    impl DefaultHasher {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for DefaultHasher {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Hasher for DefaultHasher {
        fn hash(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
            Sm3Hasher::hash(data).map_err(|e| TlsError::HandshakeFailed(e.to_string()))
        }
    }

    /// Default SM3 HMAC using gm-crypto
    pub struct DefaultHmac;

    impl DefaultHmac {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for DefaultHmac {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Hmac for DefaultHmac {
        fn hmac(&self, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
            let h = Sm3Hmac::new(key);
            h.compute(data)
                .map_err(|e| TlsError::HandshakeFailed(e.to_string()))
        }
    }

    /// Default SM4-GCM cipher using gm-crypto
    pub struct DefaultBlockCipher {
        cipher: Sm4Cipher,
    }

    impl DefaultBlockCipher {
        pub fn new(key: &[u8]) -> Result<Self, TlsError> {
            let cipher = Sm4Cipher::new(key)
                .map_err(|e| TlsError::HandshakeFailed(format!("cipher error: {}", e)))?;
            Ok(Self { cipher })
        }
    }

    impl BlockCipher for DefaultBlockCipher {
        fn encrypt_gcm(
            &self,
            plaintext: &[u8],
            nonce: &[u8],
            aad: &[u8],
        ) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
            self.cipher
                .encrypt_gcm(plaintext, nonce, aad)
                .map_err(|e| TlsError::HandshakeFailed(format!("encrypt error: {}", e)))
        }

        fn decrypt_gcm(
            &self,
            ciphertext: &[u8],
            nonce: &[u8],
            aad: &[u8],
            tag: &[u8],
        ) -> CryptoResult<Vec<u8>> {
            self.cipher
                .decrypt_gcm(ciphertext, nonce, aad, tag)
                .map_err(|e| TlsError::HandshakeFailed(format!("decrypt error: {}", e)))
        }
    }
}
