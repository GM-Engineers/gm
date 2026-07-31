//! SM9 pairing computation layer
//!
//! Provides elliptic curve points (G1, G2), bilinear pairing (R-ate),
//! hash-to-curve functions, and standard SM9 parameters.

pub mod curve;
pub mod hash;
pub mod pairing;
pub mod params;

pub use curve::{g1::G1Point, g2::G2Point, Identity};
pub use hash::{hash1, hash2};
pub use pairing::pairing;
pub use params::{g1_generator, g2_generator};
