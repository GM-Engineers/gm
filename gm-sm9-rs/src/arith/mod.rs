//! SM9 low-level field arithmetic
//!
//! Provides 256-bit integer arithmetic (z256) and prime field extensions
//! (Fp, Fp2, Fp4, Fp12) used by SM9 pairing-based cryptography.

pub mod fp;
pub mod fp12;
pub mod fp2;
pub mod fp4;
pub mod z256;

pub use fp::Fp;
pub use fp2::Fp2;
pub use fp4::Fp4;
pub use fp12::Fp12;
pub use z256::Z256;

/// Arithmetic error type
#[derive(Debug, thiserror::Error)]
pub enum ArithError {
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}

impl Clone for ArithError {
    fn clone(&self) -> Self {
        match self {
            ArithError::InvalidParameter(s) => ArithError::InvalidParameter(s.clone()),
        }
    }
}

/// Field element trait
pub trait FieldElement: Clone + Copy + Sized + 'static {
    /// Additive identity
    const ZERO: Self;
    /// Multiplicative identity
    const ONE: Self;
    /// Add two field elements
    fn add(&self, other: &Self) -> Self;
    /// Subtract two field elements
    fn sub(&self, other: &Self) -> Self;
    /// Multiply two field elements
    fn mul(&self, other: &Self) -> Self;
    /// Negate a field element
    fn neg(&self) -> Self;
    /// Square a field element
    fn square(&self) -> Self;
    /// Multiplicative inverse
    fn inv(&self) -> Option<Self>;
    /// Double a field element (add to self)
    fn double(&self) -> Self;
    /// Check if zero
    fn is_zero(&self) -> bool;
    /// Check if one (multiplicative identity)
    fn is_one(&self) -> bool;
}
