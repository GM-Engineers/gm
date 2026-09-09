//! TLCP cipher suite definitions and registry.
//!
//! TLCP defines twelve cipher suites in GB/T 38636-2020 §6.4.5.2.1
//! 表 2, spanning five `KeyExchangeAlgorithm` branches (§6.4.5.4):
//!
//! | id       | name                  | kex              | record cipher   |
//! |----------|-----------------------|------------------|------------------|
//! | `0xE051` | `ECDHE_SM4_GCM_SM3`   | ECDHE            | SM4-GCM-128      |
//! | `0xE011` | `ECDHE_SM4_CBC_SM3`   | ECDHE            | SM4-CBC + HMAC   |
//! | `0xE053` | `ECC_SM4_GCM_SM3`     | ECC (static)     | SM4-GCM-128      |
//! | `0xE013` | `ECC_SM4_CBC_SM3`     | ECC (static)     | SM4-CBC + HMAC   |
//! | `0xE057` | `IBC_SM4_GCM_SM3`     | IBC (static)     | SM4-GCM-128      |
//! | `0xE017` | `IBC_SM4_CBC_SM3`     | IBC (static)     | SM4-CBC + HMAC   |
//!
//! SM9 IBSDH dynamic suites E055/E015 (added in gm-tlcp 0.5.3, R-4.2).
//! RSA suites E019 / E01C / E059 / E05A pending R-5 / gm-tlcp 0.6.0.
//!
//! This module is data-only; the cipher-suite selection / negotiation
//! lives in the handshake state machine.
//!
//! `#![allow(deprecated)]` because the suite constants still populate
//! the deprecated `ecdhe: bool` field for backward compatibility with
//! 0.4.x callers; the field will be removed in gm-tlcp 1.0.
#![allow(deprecated)]

use super::constants::{
    TLS_ECC_SM4_CBC_SM3, TLS_ECC_SM4_GCM_SM3, TLS_ECDHE_SM4_CBC_SM3, TLS_ECDHE_SM4_GCM_SM3,
    TLS_IBC_SM4_CBC_SM3, TLS_IBC_SM4_GCM_SM3, TLS_IBSDH_SM4_CBC_SM3, TLS_IBSDH_SM4_GCM_SM3,
    TLS_RSA_SM4_CBC_SHA256, TLS_RSA_SM4_CBC_SM3, TLS_RSA_SM4_GCM_SHA256, TLS_RSA_SM4_GCM_SM3,
};

/// TLCP key-exchange algorithm (`KeyExchangeAlgorithm` per
/// GB/T 38636-2020 §6.4.5.4).
///
/// Drives the SKE emit, the CKE decrypt, and the PMS derivation
/// branches in the handshake state machine. R-4 (gm-tlcp 0.5.0)
/// replaces the previous binary `ecdhe: bool` discriminant with
/// this 5-value enum so SM9 (IBC + future IBSDH) and RSA suites
/// can be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeMode {
    /// ECDHE: server emits ECParameters+pub+sig in SKE; client
    /// returns its own ephemeral pub; both sides run SM2 KAP
    /// per GB/T 32918.3-2016.
    Ecdhe,
    /// Static-ECC: server emits sig-only SKE; client encrypts a
    /// 48-byte PMS under server's enc cert; server SM2-decrypts.
    Ecc,
    /// SM9 IBC (static): identity-based encryption. Server emits
    /// sig-only SKE carrying server identity; client SM9-encrypts
    /// 48-byte PMS to server's identity (KGC public params);
    /// server SM9-decrypts. (R-4 / gm-tlcp 0.5.0.)
    Ibc,
    /// SM9 IBSDH (dynamic): 2-round identity-based key exchange
    /// per GM/T 0044-2016 §6.1. Not yet implemented; pending
    /// R-4.1 / gm-tlcp 0.5.1.
    Ibsdh,
    /// RSA: server emits RSA-signed SKE; client RSAES-PKCS1-v1_5
    /// encrypts 48-byte PMS under server's RSA cert; server
    /// RSA-decrypts. (Pending R-5 / gm-tlcp 0.6.0.)
    Rsa,
}

/// TLCP cipher suite information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlcpCipherSuite {
    /// Suite identifier bytes
    pub id: [u8; 2],
    /// Human-readable name
    pub name: &'static str,
    /// Key-exchange algorithm (drives SKE / CKE / PMS branches)
    pub key_exchange: KeyExchangeMode,
    /// Uses GCM mode (vs CBC)
    pub gcm: bool,
    /// **Deprecated**: use `key_exchange == KeyExchangeMode::Ecdhe`.
    /// Kept for backward compatibility with 0.4.x callers that
    /// read this field directly. Will be removed in gm-tlcp 1.0.
    #[deprecated(
        since = "0.5.0",
        note = "use `key_exchange == KeyExchangeMode::Ecdhe` instead"
    )]
    pub ecdhe: bool,
}

impl TlcpCipherSuite {
    /// ECDHE + SM4-GCM + SM3
    pub const ECDHE_SM4_GCM_SM3: Self = Self {
        id: TLS_ECDHE_SM4_GCM_SM3,
        name: "ECDHE_SM4_GCM_SM3",
        key_exchange: KeyExchangeMode::Ecdhe,
        gcm: true,
        ecdhe: true,
    };

    /// ECDHE + SM4-CBC + SM3
    pub const ECDHE_SM4_CBC_SM3: Self = Self {
        id: TLS_ECDHE_SM4_CBC_SM3,
        name: "ECDHE_SM4_CBC_SM3",
        key_exchange: KeyExchangeMode::Ecdhe,
        gcm: false,
        ecdhe: true,
    };

    /// ECC + SM4-GCM + SM3 (static key)
    pub const ECC_SM4_GCM_SM3: Self = Self {
        id: TLS_ECC_SM4_GCM_SM3,
        name: "ECC_SM4_GCM_SM3",
        key_exchange: KeyExchangeMode::Ecc,
        gcm: true,
        ecdhe: false,
    };

    /// ECC + SM4-CBC + SM3 (static key)
    pub const ECC_SM4_CBC_SM3: Self = Self {
        id: TLS_ECC_SM4_CBC_SM3,
        name: "ECC_SM4_CBC_SM3",
        key_exchange: KeyExchangeMode::Ecc,
        gcm: false,
        ecdhe: false,
    };

    /// SM9 IBC + SM4-GCM + SM3 (static key, R-4)
    pub const IBC_SM4_GCM_SM3: Self = Self {
        id: TLS_IBC_SM4_GCM_SM3,
        name: "IBC_SM4_GCM_SM3",
        key_exchange: KeyExchangeMode::Ibc,
        gcm: true,
        ecdhe: false,
    };

    /// SM9 IBC + SM4-CBC + SM3 (static key, R-4)
    pub const IBC_SM4_CBC_SM3: Self = Self {
        id: TLS_IBC_SM4_CBC_SM3,
        name: "IBC_SM4_CBC_SM3",
        key_exchange: KeyExchangeMode::Ibc,
        gcm: false,
        ecdhe: false,
    };

    /// SM9 IBSDH + SM4-GCM + SM3 (dynamic key, R-4.2)
    pub const IBSDH_SM4_GCM_SM3: Self = Self {
        id: TLS_IBSDH_SM4_GCM_SM3,
        name: "IBSDH_SM4_GCM_SM3",
        key_exchange: KeyExchangeMode::Ibsdh,
        gcm: true,
        ecdhe: false,
    };

    /// SM9 IBSDH + SM4-CBC + SM3 (dynamic key, R-4.2)
    pub const IBSDH_SM4_CBC_SM3: Self = Self {
        id: TLS_IBSDH_SM4_CBC_SM3,
        name: "IBSDH_SM4_CBC_SM3",
        key_exchange: KeyExchangeMode::Ibsdh,
        gcm: false,
        ecdhe: false,
    };

    /// RSA + SM4-CBC + SM3 (static key, R-5)
    pub const RSA_SM4_CBC_SM3: Self = Self {
        id: TLS_RSA_SM4_CBC_SM3,
        name: "RSA_SM4_CBC_SM3",
        key_exchange: KeyExchangeMode::Rsa,
        gcm: false,
        ecdhe: false,
    };

    /// RSA + SM4-CBC + SHA-256 (static key, R-5)
    ///
    /// Spec ambiguity: we treat the PRF as SM3 (matches GmSSL
    /// master + openHiTLS convention); see R-5 plan §2.
    pub const RSA_SM4_CBC_SHA256: Self = Self {
        id: TLS_RSA_SM4_CBC_SHA256,
        name: "RSA_SM4_CBC_SHA256",
        key_exchange: KeyExchangeMode::Rsa,
        gcm: false,
        ecdhe: false,
    };

    /// RSA + SM4-GCM + SM3 (static key, R-5)
    pub const RSA_SM4_GCM_SM3: Self = Self {
        id: TLS_RSA_SM4_GCM_SM3,
        name: "RSA_SM4_GCM_SM3",
        key_exchange: KeyExchangeMode::Rsa,
        gcm: true,
        ecdhe: false,
    };

    /// RSA + SM4-GCM + SHA-256 (static key, R-5)
    ///
    /// Spec ambiguity: we treat the PRF as SM3 (matches GmSSL
    /// master + openHiTLS convention); see R-5 plan §2.
    pub const RSA_SM4_GCM_SHA256: Self = Self {
        id: TLS_RSA_SM4_GCM_SHA256,
        name: "RSA_SM4_GCM_SHA256",
        key_exchange: KeyExchangeMode::Rsa,
        gcm: true,
        ecdhe: false,
    };

    /// True iff the suite uses a static (non-ephemeral) key
    /// agreement. Useful for distinguishing the SKE / CKE
    /// branches in the handshake state machine.
    pub fn is_static(&self) -> bool {
        matches!(
            self.key_exchange,
            KeyExchangeMode::Ecc | KeyExchangeMode::Ibc | KeyExchangeMode::Rsa
        )
    }

    /// True iff the suite is SM9-based (IBSDH or IBC).
    /// Lets the handshake state machine quickly route to the
    /// gm-sm9-rs code paths.
    pub fn is_sm9(&self) -> bool {
        matches!(
            self.key_exchange,
            KeyExchangeMode::Ibc | KeyExchangeMode::Ibsdh
        )
    }

    /// Look up cipher suite by ID
    pub fn from_id(id: [u8; 2]) -> Option<Self> {
        match id {
            TLS_ECDHE_SM4_GCM_SM3 => Some(Self::ECDHE_SM4_GCM_SM3),
            TLS_ECDHE_SM4_CBC_SM3 => Some(Self::ECDHE_SM4_CBC_SM3),
            TLS_ECC_SM4_GCM_SM3 => Some(Self::ECC_SM4_GCM_SM3),
            TLS_ECC_SM4_CBC_SM3 => Some(Self::ECC_SM4_CBC_SM3),
            TLS_IBC_SM4_GCM_SM3 => Some(Self::IBC_SM4_GCM_SM3),
            TLS_IBC_SM4_CBC_SM3 => Some(Self::IBC_SM4_CBC_SM3),
            TLS_IBSDH_SM4_GCM_SM3 => Some(Self::IBSDH_SM4_GCM_SM3),
            TLS_IBSDH_SM4_CBC_SM3 => Some(Self::IBSDH_SM4_CBC_SM3),
            TLS_RSA_SM4_GCM_SM3 => Some(Self::RSA_SM4_GCM_SM3),
            TLS_RSA_SM4_CBC_SM3 => Some(Self::RSA_SM4_CBC_SM3),
            TLS_RSA_SM4_GCM_SHA256 => Some(Self::RSA_SM4_GCM_SHA256),
            TLS_RSA_SM4_CBC_SHA256 => Some(Self::RSA_SM4_CBC_SHA256),
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
            Self::IBC_SM4_GCM_SM3,
            Self::IBC_SM4_CBC_SM3,
            Self::IBSDH_SM4_GCM_SM3,
            Self::IBSDH_SM4_CBC_SM3,
            Self::RSA_SM4_GCM_SM3,
            Self::RSA_SM4_CBC_SM3,
            Self::RSA_SM4_GCM_SHA256,
            Self::RSA_SM4_CBC_SHA256,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sm9_ibc_suites_have_correct_key_exchange_mode() {
        assert_eq!(
            TlcpCipherSuite::IBC_SM4_GCM_SM3.key_exchange,
            KeyExchangeMode::Ibc
        );
        assert_eq!(
            TlcpCipherSuite::IBC_SM4_CBC_SM3.key_exchange,
            KeyExchangeMode::Ibc
        );
        assert!(TlcpCipherSuite::IBC_SM4_GCM_SM3.is_sm9());
        assert!(TlcpCipherSuite::IBC_SM4_GCM_SM3.is_static());
        assert!(!TlcpCipherSuite::ECDHE_SM4_GCM_SM3.is_sm9());
        assert!(!TlcpCipherSuite::ECDHE_SM4_GCM_SM3.is_static());
    }

    #[test]
    fn sm9_ibsdh_suites_have_correct_key_exchange_mode() {
        // R-4.2: SM9 IBSDH suites are dynamic (ephemeral R_A / R_B)
        // and use SM9 — so `is_sm9()` returns true, `is_static()`
        // returns false.
        assert_eq!(
            TlcpCipherSuite::IBSDH_SM4_GCM_SM3.key_exchange,
            KeyExchangeMode::Ibsdh
        );
        assert_eq!(
            TlcpCipherSuite::IBSDH_SM4_CBC_SM3.key_exchange,
            KeyExchangeMode::Ibsdh
        );
        assert!(TlcpCipherSuite::IBSDH_SM4_GCM_SM3.is_sm9());
        assert!(TlcpCipherSuite::IBSDH_SM4_CBC_SM3.is_sm9());
        assert!(!TlcpCipherSuite::IBSDH_SM4_GCM_SM3.is_static());
        assert!(!TlcpCipherSuite::IBSDH_SM4_CBC_SM3.is_static());
        assert_eq!(TlcpCipherSuite::IBSDH_SM4_GCM_SM3.id, [0xE0, 0x55]);
        assert_eq!(TlcpCipherSuite::IBSDH_SM4_CBC_SM3.id, [0xE0, 0x15]);
    }

    #[test]
    fn from_id_resolves_all_twelve_suites() {
        let all = TlcpCipherSuite::all();
        // 4 SM2-based (ECDHE/ECC × GCM/CBC) + 2 SM9-IBC (GCM/CBC)
        // + 2 SM9-IBSDH (GCM/CBC, R-4.2) + 4 RSA (GCM/CBC × SM3/SHA-256, R-5)
        // = 12 total (full GB/T 38636-2020 §6.4.5.2.1 表 2 set).
        assert_eq!(all.len(), 12);
        for suite in all {
            assert_eq!(
                TlcpCipherSuite::from_id(suite.id),
                Some(*suite),
                "roundtrip lookup failed for {:?}",
                suite.id
            );
        }
    }
}
