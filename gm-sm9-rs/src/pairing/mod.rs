//! SM9 pairing computation layer
//!
//! Provides elliptic curve points (G1, G2), bilinear pairing (R-ate),
//! hash-to-curve functions, and standard SM9 parameters.

pub mod ate;
pub mod curve;
pub mod hash;
pub mod params;

pub use ate::pairing;
pub use curve::{Identity, g1::G1Point, g2::G2Point};
pub use hash::{hash1, hash2};
pub use params::{g1_generator, g2_generator};
