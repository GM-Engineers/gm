//! GM cryptography algorithm library (gm-crypto)
//!
//! Provides unified interface for SM2, SM3, SM4
//!
//! # Examples
//!
//! ```rust
//! use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier};
//! use gm_crypto::sm3::Sm3Hasher;
//! use gm_crypto::sm4::Sm4Cipher;
//!
//! // SM2 sign/verify
//! let keypair = Sm2KeyPair::generate().unwrap();
//! let signer = Sm2Signer::new(&keypair).unwrap();
//! let signature = signer.sign(b"hello").unwrap();
//!
//! // SM3 hash
//! let hash = Sm3Hasher::hash(b"hello").unwrap();
//!
//! // SM4-GCM encryption
//! let key = [0u8; 16];
//! let cipher = Sm4Cipher::new(&key).unwrap();
//! let nonce = [0u8; 12];
//! let (ct, tag) = cipher.encrypt_gcm(b"hello", &nonce, &[]).unwrap();
//! ```

/// Cryptography error type definitions
pub mod error;

/// SM2 elliptic curve public key cryptography (signing/verification/key management)
pub mod sm2;

/// SM2 Key Exchange Protocol (SM2-KEX)
pub mod sm2_kex;

/// SM3 cryptographic hash algorithm
pub mod sm3;

/// SM4 block cipher algorithm (encryption/decryption)
pub mod sm4;

/// Encryption utility functions
pub mod utils;

/// X.509 certificate parsing
pub mod x509;

/// Known Answer Tests (KAT) for cryptographic self-testing
pub mod kat;

/// Unified cryptographic trait definitions
pub mod traits;

/// Encryption operation error types
pub use error::CryptoError;
pub use utils::*;
