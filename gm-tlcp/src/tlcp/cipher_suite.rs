//! TLCP cipher suite definitions and registry.
//!
//! TLCP defines exactly four cipher suites in GB/T 38636-2020 §6.4.5.2.1
//! 表 2:
//!
//! | id       | name                | kex   | record cipher   |
//! |----------|---------------------|-------|------------------|
//! | `0xE051` | `ECDHE_SM4_GCM_SM3` | ECDHE | SM4-GCM-128      |
//! | `0xE011` | `ECDHE_SM4_CBC_SM3` | ECDHE | SM4-CBC + HMAC   |
//! | `0xE053` | `ECC_SM4_GCM_SM3`   | ECC (static) | SM4-GCM-128 |
//! | `0xE013` | `ECC_SM4_CBC_SM3`   | ECC (static) | SM4-CBC + HMAC |
//!
//! This module is data-only; the cipher-suite selection / negotiation
//! lives in the handshake state machine.

use super::constants::{
    TLS_ECC_SM4_CBC_SM3, TLS_ECC_SM4_GCM_SM3, TLS_ECDHE_SM4_CBC_SM3, TLS_ECDHE_SM4_GCM_SM3,
};

/// TLCP cipher suite information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlcpCipherSuite {
    /// Suite identifier bytes
    pub id: [u8; 2],
    /// Human-readable name
    pub name: &'static str,
    /// Uses ECDHE key exchange
    pub ecdhe: bool,
    /// Uses GCM mode (vs CBC)
    pub gcm: bool,
}

impl TlcpCipherSuite {
    /// ECDHE + SM4-GCM + SM3
    pub const ECDHE_SM4_GCM_SM3: Self = Self {
        id: TLS_ECDHE_SM4_GCM_SM3,
        name: "ECDHE_SM4_GCM_SM3",
        ecdhe: true,
        gcm: true,
    };

    /// ECDHE + SM4-CBC + SM3
    pub const ECDHE_SM4_CBC_SM3: Self = Self {
        id: TLS_ECDHE_SM4_CBC_SM3,
        name: "ECDHE_SM4_CBC_SM3",
        ecdhe: true,
        gcm: false,
    };

    /// ECC + SM4-GCM + SM3 (static key)
    pub const ECC_SM4_GCM_SM3: Self = Self {
        id: TLS_ECC_SM4_GCM_SM3,
        name: "ECC_SM4_GCM_SM3",
        ecdhe: false,
        gcm: true,
    };

    /// ECC + SM4-CBC + SM3 (static key)
    pub const ECC_SM4_CBC_SM3: Self = Self {
        id: TLS_ECC_SM4_CBC_SM3,
        name: "ECC_SM4_CBC_SM3",
        ecdhe: false,
        gcm: false,
    };

    /// Look up cipher suite by ID
    pub fn from_id(id: [u8; 2]) -> Option<Self> {
        match id {
            TLS_ECDHE_SM4_GCM_SM3 => Some(Self::ECDHE_SM4_GCM_SM3),
            TLS_ECDHE_SM4_CBC_SM3 => Some(Self::ECDHE_SM4_CBC_SM3),
            TLS_ECC_SM4_GCM_SM3 => Some(Self::ECC_SM4_GCM_SM3),
            TLS_ECC_SM4_CBC_SM3 => Some(Self::ECC_SM4_CBC_SM3),
            _ => None,
        }
    }

    /// All supported cipher suites in preference order
    pub fn all() -> &'static [TlcpCipherSuite] {
        &[
            Self::ECDHE_SM4_GCM_SM3,
            Self::ECDHE_SM4_CBC_SM3,
            Self::ECC_SM4_GCM_SM3,
            Self::ECC_SM4_CBC_SM3,
        ]
    }
}
