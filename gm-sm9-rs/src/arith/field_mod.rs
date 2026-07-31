//! Finite field arithmetic for SM9
//!
//! This module defines the field trait and implementations for:
//! - Fp: Prime field modulo p
//! - Fp2: Quadratic extension Fp[u]/(u^2 + 2)
//! - Fp4: Quartic extension Fp2[v]/(v^2 - u)
//! - Fp12: Degree-12 extension Fp4[w]/(w^3 - v)

use subtle::ConditionallySelectable;
use zeroize::Zeroize;

/// Trait for finite field elements
pub trait FieldElement:
    Clone + Copy + PartialEq + Eq + Zeroize + ConditionallySelectable + std::fmt::Debug
{
    /// Zero element
    const ZERO: Self;

    /// One element
    const ONE: Self;

    /// Addition
    fn add(&self, other: &Self) -> Self;

    /// Subtraction
    fn sub(&self, other: &Self) -> Self;

    /// Negation
    fn neg(&self) -> Self;

    /// Multiplication
    fn mul(&self, other: &Self) -> Self;

    /// Squaring
    fn square(&self) -> Self;

    /// Double: 2 * self
    fn double(&self) -> Self {
        self.add(self)
    }

    /// Inversion (returns None if element is zero)
    fn inv(&self) -> Option<Self>;

    /// Division: self * other^-1
    fn div(&self, other: &Self) -> Option<Self> {
        other.inv().map(|inv| self.mul(&inv))
    }

    /// Check if zero
    fn is_zero(&self) -> bool;

    /// Check if one
    fn is_one(&self) -> bool;

    // Note: conditional_assign comes from subtle::ConditionallySelectable
    // Do not define it here to avoid ambiguity
}

pub mod fp;
pub mod fp12;
pub mod fp2;
pub mod fp4;

pub use fp::Fp;
pub use fp12::Fp12;
pub use fp2::Fp2;
pub use fp4::Fp4;
