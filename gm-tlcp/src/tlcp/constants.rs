//! TLCP protocol-level constants.
//!
//! These values are **on the wire** — defined by GB/T 38636-2020 and
//! (where inherited) GM/T 0024-2014. They must not change without
//! updating both the encoder and the decoder simultaneously, and they
//! must be agreed with peer implementations during interop testing
//! (GmSSL 3.3.0-dev, Tongsuo 8.3.0, etc).
//!
//! ## What lives here vs. elsewhere
//!
//! | Constant | Lives here because |
//! |---|---|
//! | `TLCP_VERSION_1_0` | wire protocol version |
//! | `TLS_ECDHE_SM4_GCM_SM3`, `TLS_ECDHE_SM4_CBC_SM3`, `TLS_ECC_SM4_GCM_SM3`, `TLS_ECC_SM4_CBC_SM3` | wire cipher-suite IDs |
//! | `MAX_TLCP_RECORD_SIZE` | wire protocol limit (TLCP record fragment cap) |
//! | `TLCP_EC_CURVE_TYPE_NAMED_CURVE`, `TLCP_NAMED_CURVE_SM2P256V1`, `TLCP_ECH_PARAMS_PREFIX`, `SM2_UNCOMPRESSED_PUBLIC_KEY_LENGTH` | ECDHE parameter encoding (RFC 4492 §5.4) |
//! | `MAX_SESSION_ID_LEN`, `DEFAULT_SESSION_LIFETIME`, `MAX_CACHED_SESSIONS` | session-cache tuning; could live with [`crate::tlcp::session`] but kept here to centralize tunable values |
//!
//! ## Naming convention
//!
//! Three prefix styles appear in this file — intentional, not a slip:
//!
//! - **`TLS_*`** — cipher-suite code points (`0xE011`, `0xE013`,
//!   `0xE051`, `0xE053`). These names were first defined by
//!   **GM/T 0024-2014《SSL VPN 技术规范》** (which predates TLCP),
//!   following the TLS 1.0/1.1-era `TLS_*_WITH_*` naming habit
//!   (cf. IANA TLS cipher-suite registry). GB/T 38636-2020 §6.4.5.2.1
//!   表 2 inherits the code points unchanged; GmSSL and Tongsuo use
//!   the same names. The `TLS_` prefix is preserved so wire-format
//!   IDs stay visually aligned with peer implementations during
//!   interop testing — renaming would not change a single byte on
//!   the wire, but would make diff-with-peer trace logs harder to
//!   read.
//!
//! - **`TLCP_*`** — values defined by TLCP itself: the protocol
//!   version, record-size cap, EC curve type / named-curve code,
//!   and the ECParameters header prefix.
//!
//! - **No prefix** (or `MAX_*` / `DEFAULT_*`) — non-wire tunables:
//!   session-cache limits and lifetimes, SM2 public-key length.
//!
//! The per-constant doc comments on `TLS_ECDHE_SM4_CBC_SM3` and
//! `TLS_ECC_SM4_CBC_SM3` already carry the explicit
//! "Inherited unchanged from GM/T 0024-2014" note.

use std::time::Duration;

/// TLCP protocol version 1.0 (GB/T 38636-2020)
pub const TLCP_VERSION_1_0: [u8; 2] = [0x01, 0x01];

/// TLCP cipher suite: ECDHE + SM4-GCM + SM3
///
/// GB/T 38636-2020 §6.4.5.2.1 表 2: code point `0xE051`.
pub const TLS_ECDHE_SM4_GCM_SM3: [u8; 2] = [0xE0, 0x51];

/// TLCP cipher suite: ECDHE + SM4-CBC + SM3
///
/// GB/T 38636-2020 §6.4.5.2.1 表 2: code point `0xE011`.
/// Inherited unchanged from GM/T 0024-2014.
pub const TLS_ECDHE_SM4_CBC_SM3: [u8; 2] = [0xE0, 0x11];

/// TLCP cipher suite: ECC + SM4-GCM + SM3 (no ECDHE)
///
/// GB/T 38636-2020 §6.4.5.2.1 表 2: code point `0xE053`.
pub const TLS_ECC_SM4_GCM_SM3: [u8; 2] = [0xE0, 0x53];

/// TLCP cipher suite: ECC + SM4-CBC + SM3 (no ECDHE)
///
/// GB/T 38636-2020 §6.4.5.2.1 表 2: code point `0xE013`.
/// Inherited unchanged from GM/T 0024-2014.
pub const TLS_ECC_SM4_CBC_SM3: [u8; 2] = [0xE0, 0x13];

/// Maximum TLCP record size
pub const MAX_TLCP_RECORD_SIZE: usize = 16 * 1024;

/// RFC 4492 ECParameters `curve_type` value: named curve.
///
/// Used in TLCP/GB/T 38636-2020 ECDHE ServerKeyExchange and
/// ClientKeyExchange to identify the curve. The only TLCP-defined
/// curve is `sm2p256v1` (GB/T 32918.5-2016 §5); it is **not** the
/// same as NIST P-256 / `prime256v1` / `secp256r1` — same field size
/// but different curve parameters, generator, and order. TLCP only
/// supports this curve, so this constant is the only `curve_type`
/// value we ever emit or accept.
pub const TLCP_EC_CURVE_TYPE_NAMED_CURVE: u8 = 0x03;

/// RFC 4492 / GB/T 38636-2020 named-curve code for SM2P256V1
/// (`sm2p256v1`, GB/T 32918.5-2016 §5). Note this is **distinct**
/// from NIST P-256 / `prime256v1` / `secp256r1` (RFC 8422 §5.1.1).
/// GmSSL 2026-06+ master encodes it as the 16-bit value `0x0029`; TLCP
/// only supports this curve.
pub const TLCP_NAMED_CURVE_SM2P256V1: [u8; 2] = [0x00, 0x29];

/// Wire-format prefix bytes that precede an ECDHE ECPoint (the
/// ephemeral public key) in TLCP ECDHE ServerKeyExchange and
/// ClientKeyExchange messages.
///
/// Layout: `[curve_type=0x03][named_curve=0x0029]`. The 1-byte
/// `pub_len` and the actual point bytes follow immediately after.
pub const TLCP_ECH_PARAMS_PREFIX: [u8; 3] = [
    TLCP_EC_CURVE_TYPE_NAMED_CURVE,
    TLCP_NAMED_CURVE_SM2P256V1[0],
    TLCP_NAMED_CURVE_SM2P256V1[1],
];

/// Standard uncompressed SM2 public key length (1 + 32 + 32 = 65
/// bytes: `04 || x || y`).
pub const SM2_UNCOMPRESSED_PUBLIC_KEY_LENGTH: usize = 65;

/// Maximum session ID length (per GB/T 38636-2020)
pub const MAX_SESSION_ID_LEN: usize = 32;

/// Default session lifetime (24 hours)
pub const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(86400);

/// Maximum cached sessions (eviction limit)
pub const MAX_CACHED_SESSIONS: usize = 1024;
