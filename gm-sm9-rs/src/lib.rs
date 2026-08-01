//! GM SM9 Identity-Based Cryptography - Pure Rust Implementation
//!
//! This crate provides a standards-compliant implementation of SM9
//! (GM/T 0044-2016) identity-based cryptography.
//!
//! # Architecture
//!
//! The implementation follows a layered approach within this single crate:
//!
//! - `arith`: 256-bit integer arithmetic (z256), prime field and
//!   extensions (Fp, Fp2, Fp4, Fp12)
//! - `pairing`: Elliptic curve points (G1, G2), bilinear pairing
//!   (R-ate), hash-to-curve, standard parameters
//! - High-level API (key generation, sign/verify, encrypt/decrypt,
//!   key rotation, FFI backend)
//!
//! # Features
//!
//! - `pure-rust` (default): Pure Rust implementation
//! - `gmssl`: GmSSL FFI backend (requires GmSSL 3.1.1 installed)

#![cfg_attr(not(feature = "gmssl"), allow(dead_code))]

pub mod error;

// Internal arithmetic and pairing layers
pub mod arith;
pub mod pairing;

// Re-export arithmetic layer
pub use crate::arith::{ArithError, FieldElement, Fp, Fp2, Fp4, Fp12, Z256, z256};
pub mod fp {
    pub use crate::arith::fp::*;
}
pub mod fp2 {
    pub use crate::arith::fp2::*;
}
pub mod fp4 {
    pub use crate::arith::fp4::*;
}
pub mod fp12 {
    pub use crate::arith::fp12::*;
}
/// Legacy field module (re-exports from `arith`)
pub mod field {
    pub use crate::{FieldElement, Fp, Fp2, Fp4, Fp12};
    pub mod fp {
        pub use crate::fp::*;
    }
    pub mod fp2 {
        pub use crate::fp2::*;
    }
    pub mod fp4 {
        pub use crate::fp4::*;
    }
    pub mod fp12 {
        pub use crate::fp12::*;
    }
}
// Re-export pairing layer
pub use crate::pairing::ate::pairing as sm9_pairing;
pub use crate::pairing::{G1Point, G2Point, Identity, g1_generator, g2_generator};
pub use crate::pairing::{curve, hash, params};
pub use crate::pairing::{hash1, hash2};

// Pure Rust implementation modules (high-level API)
#[cfg(feature = "pure-rust")]
pub mod encrypt;
#[cfg(feature = "pure-rust")]
pub mod kat;
#[cfg(feature = "pure-rust")]
pub mod key;
#[cfg(feature = "pure-rust")]
pub mod key_rotation;
#[cfg(feature = "pure-rust")]
pub mod sign;
#[cfg(feature = "pure-rust")]
pub mod traits;

// GmSSL FFI backend (legacy, kept for compatibility)
#[cfg(feature = "gmssl")]
pub mod ffi;
#[cfg(feature = "gmssl")]
mod gmssl_backend;

#[cfg(feature = "gmssl")]
pub use gmssl_backend::*;

pub use error::Sm9Error;

// Re-export pure Rust key and sign types
#[cfg(feature = "pure-rust")]
pub use encrypt::{Ciphertext, Decryptor, Encryptor};
#[cfg(feature = "pure-rust")]
pub use key::{EncMasterKey, EncUserKey, KgcMasterKey, SignMasterKey, SignUserKey};
#[cfg(feature = "pure-rust")]
pub use sign::{Signature, Signer, Verifier};

// Key exchange module
pub mod key_exchange;
