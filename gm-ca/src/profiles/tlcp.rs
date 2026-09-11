//! TLCP end-entity `CertProfile` presets — GB/T 38636-2020 §6.4.6.
//!
//! TLCP ([GB/T 38636-2020]) defines 12 cipher suites split into two
//! algorithm families:
//!   * 8 ECC suites — SM2 ECDHE / static ECDH key exchange (E001-E008,
//!     E009-E016). Server holds two certs (sign + enc); client holds one.
//!   * 4 RSA suites — RSA-PKCS#1-v1_5 key transport or ECDHE-RSA sign
//!     (E019/E01C/E059/E05A). Server / client each hold one RSA cert.
//!
//! [`GB/T 38636-2020`]: https://openstd.samr.gov.cn/
//!
//! This module exposes 5 preset constructors that produce `CertProfile`
//! values with the KU / EKU / BC layout the spec / GmSSL master /
//! openHiTLS implementations expect:
//!
//! | Preset | KU | EKU | Algorithm | Feature gate |
//! |---|---|---|---|---|
//! | [`tlcp_server_sign_ecc`] | digitalSignature \| keyAgreement | serverAuth | SM2 | `tlcp-profiles` |
//! | [`tlcp_server_enc_ecc`] | keyEncipherment \| keyAgreement \| dataEncipherment | (none) | SM2 | `tlcp-profiles` |
//! | [`tlcp_client_sign_ecc`] | digitalSignature \| keyAgreement | clientAuth | SM2 | `tlcp-profiles` |
//! | [`tlcp_server_rsa`] | digitalSignature \| keyEncipherment | serverAuth | RSA | `tlcp-profiles` + `rsa` |
//! | [`tlcp_client_rsa`] | digitalSignature \| keyEncipherment | clientAuth | RSA | `tlcp-profiles` + `rsa` |
//!
//! ## Common field defaults (all 5 presets)
//!
//!   * `is_ca = false`
//!   * `ca_path_len_constraint = None`
//!   * `include_basic_constraints = true` (BC CA:FALSE)
//!   * `include_ski = true` / `include_aki = true`
//!   * `include_san = true` (caller populates `sans` with dNSName / IP)
//!
//! ## Why `tlcp_server_enc_ecc` has no EKU
//!
//! Per §6.4.6.1.2 b) the enc cert's KU must include `keyAgreement` and
//! "扩展密钥用法可包括 id-kp-serverAuth 或 id-kp-clientAuth"
//! (EKU MAY include serverAuth / clientAuth). GmSSL master emits **no
//! EKU** at all for the TLSE enc cert, and openHiTLS's example enc
//! certs match. We mirror that choice — verifiers won't reject a cert
//! for missing EKU; they might reject it for an unexpected one.
//!
//! ## Why `tlcp_server_rsa` and `tlcp_client_rsa` need both digitalSignature + keyEncipherment
//!
//! RSA-PKCS#1-v1_5 key transport (RSA-SM4-CBC/GCM-SM3 suites) uses
//! `keyEncipherment` to wrap the 48-byte PMS; ECDHE-RSA handshake
//! signatures use `digitalSignature`. The same RSA cert is reused for
//! both, so both bits must be set.
//!
//! ## Builder-style overrides
//!
//! Callers can override `sans` (or any other field) after calling a
//! preset, since `CertProfile` is plain data:
//!
//! ```ignore
//! use gm_ca::profiles::tlcp::tlcp_server_sign_ecc;
//!
//! let mut profile = tlcp_server_sign_ecc();
//! profile.sans.push(gm_ca::cert_profile::GeneralName::DnsName(
//!     "tlcp.example.com".into(),
//! ));
//! ```

use crate::cert_profile::{CertProfile, ExtendedKeyUsage, KeyUsageBits};

// ---------------------------------------------------------------------------
// Shared boilerplate — `CertProfile::default()` minus the EKU/KU bits we
// override per preset.
// ---------------------------------------------------------------------------
//
// We can't call `CertProfile::default()` and then mutate because the
// default EKU is `[ServerAuth, ClientAuth]` (matching the v0.1.x
// end-entity behavior) and the default KU includes `digitalSignature |
// keyEncipherment` (matching the RSA-style end-entity). Both are wrong
// for the TLCP ECC sign preset (which wants `digitalSignature |
// keyAgreement` + a single EKU). So we inline the construction.

/// Shared "leaf cert" defaults: `is_ca = false`, BC / SKI / AKI / SAN
/// extensions enabled, no pathLenConstraint. KU and EKU are preset-
/// specific.
fn leaf_cert_profile(ku: KeyUsageBits, ekus: Vec<ExtendedKeyUsage>) -> CertProfile {
    CertProfile {
        key_usage: ku,
        ext_key_usage: ekus,
        is_ca: false,
        ca_path_len_constraint: None,
        sans: Vec::new(),
        include_san: true,
        include_aki: true,
        include_basic_constraints: true,
        include_ski: true,
    }
}

// ---------------------------------------------------------------------------
// ECC (SM2) presets — required for the 8 ECC suites
// (ECDHE-ECDSA-SM4-{CBC,GCM}-SM3 / ECC-SM4-{CBC,GCM}-SM3)
// ---------------------------------------------------------------------------

/// TLCP server **sign** cert (ECC / SM2). Used by the 4 ECDHE-ECDSA +
/// 4 ECDHE-SM2 suites to authenticate the server's ECDSA signature over
/// the ServerKeyExchange body.
///
/// KU: `digitalSignature | keyAgreement` (covers both ECDHE sign and
/// static ECDH, per §6.4.6.1.2 a)).
/// EKU: `serverAuth`.
pub fn tlcp_server_sign_ecc() -> CertProfile {
    leaf_cert_profile(
        KeyUsageBits {
            digital_signature: true,
            key_agreement: true,
            ..Default::default()
        },
        vec![ExtendedKeyUsage::ServerAuth],
    )
}

/// TLCP server **enc** cert (ECC / SM2). Used by the 4 static-ECDH /
/// fixed-ECDH suites to transport the server's static ECDH public key
/// (this is the second cert the TLCP server carries for the ECC suites).
///
/// KU: `keyEncipherment | keyAgreement | dataEncipherment`. Per
/// §6.4.6.1.2 b) only `keyAgreement` is mandatory; the other two
/// match GmSSL master's TLSE enc cert layout and signal "this key
/// may be used for raw key transport", which is the practical meaning
/// of the static-ECDH enc cert.
/// EKU: **empty** — GmSSL + openHiTLS both emit no EKU for the enc
/// cert, and §6.4.6.1.2 b) explicitly makes EKU optional.
pub fn tlcp_server_enc_ecc() -> CertProfile {
    leaf_cert_profile(
        KeyUsageBits {
            key_encipherment: true,
            key_agreement: true,
            data_encipherment: true,
            ..Default::default()
        },
        Vec::new(),
    )
}

/// TLCP client **sign** cert (ECC / SM2). Used by the 4 ECDHE-ECDSA
/// suites on the client side to authenticate the client's optional
/// CertificateVerify signature.
///
/// KU: `digitalSignature | keyAgreement`.
/// EKU: `clientAuth`.
pub fn tlcp_client_sign_ecc() -> CertProfile {
    leaf_cert_profile(
        KeyUsageBits {
            digital_signature: true,
            key_agreement: true,
            ..Default::default()
        },
        vec![ExtendedKeyUsage::ClientAuth],
    )
}

// ---------------------------------------------------------------------------
// RSA presets — required for the 4 RSA suites
// (ECDHE-RSA-SM4-{CBC,GCM}-SM3 + RSA-SM4-{CBC,GCM}-SM3)
// ---------------------------------------------------------------------------

/// TLCP server cert (RSA). Used by all 4 RSA suites — the same cert
/// covers both RSA-PKCS#1-v1_5 key transport (`keyEncipherment`) and
/// ECDHE-RSA handshake signatures (`digitalSignature`).
///
/// KU: `digitalSignature | keyEncipherment`.
/// EKU: `serverAuth`.
#[cfg(feature = "rsa")]
pub fn tlcp_server_rsa() -> CertProfile {
    leaf_cert_profile(
        KeyUsageBits {
            digital_signature: true,
            key_encipherment: true,
            ..Default::default()
        },
        vec![ExtendedKeyUsage::ServerAuth],
    )
}

/// TLCP client cert (RSA). Used by all 4 RSA suites on the client side.
///
/// KU: `digitalSignature | keyEncipherment`.
/// EKU: `clientAuth`.
#[cfg(feature = "rsa")]
pub fn tlcp_client_rsa() -> CertProfile {
    leaf_cert_profile(
        KeyUsageBits {
            digital_signature: true,
            key_encipherment: true,
            ..Default::default()
        },
        vec![ExtendedKeyUsage::ClientAuth],
    )
}

// ---------------------------------------------------------------------------
// Tests — wire-format smoke checks for each preset.
//
// We verify the KU byte encoding (MSB-first per KeyUsageBits::to_der_bytes)
// and the EKU presence/absence. The full x509-parser round-trip is
// already covered by `cert::tests` for SM2 and `rsa_signer::tests` for
// RSA; here we focus on the *profile* layer to lock in the spec-mandated
// KU/EKU combinations.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_profile::{ExtendedKeyUsage, KeyUsageBits};

    /// digitalSignature(bit 0) + keyAgreement(bit 4) = 0x80 | 0x08 = 0x88.
    /// Highest set bit = 4, so unused-bits = 7 - 4 = 3.
    const TLCP_ECC_SIGN_KU_BYTES: [u8; 2] = [0x03, 0x88];

    /// keyEncipherment(2) + keyAgreement(4) + dataEncipherment(3)
    /// = 0x20 | 0x08 | 0x10 = 0x38. Highest set bit = 4, unused = 3.
    const TLCP_ECC_ENC_KU_BYTES: [u8; 2] = [0x03, 0x38];

    /// digitalSignature(0) + keyEncipherment(2) = 0x80 | 0x20 = 0xA0.
    /// Highest set bit = 2, unused = 5.
    #[cfg(feature = "rsa")]
    const TLCP_RSA_KU_BYTES: [u8; 2] = [0x05, 0xA0];

    fn assert_leaf_basics(profile: &CertProfile, expected_eku: &[ExtendedKeyUsage]) {
        assert!(!profile.is_ca, "leaf cert must not be CA");
        assert_eq!(
            profile.ca_path_len_constraint, None,
            "leaf cert has no pathLenConstraint"
        );
        assert!(
            profile.include_basic_constraints,
            "leaf cert includes BC CA:FALSE"
        );
        assert!(profile.include_ski, "leaf cert includes SKI");
        assert!(profile.include_aki, "leaf cert includes AKI");
        assert!(
            profile.include_san,
            "leaf cert includes SAN (caller fills sans)"
        );
        assert!(
            profile.sans.is_empty(),
            "presets leave sans empty; caller pushes GeneralName entries"
        );
        assert_eq!(
            profile.ext_key_usage, expected_eku,
            "EKU must match the preset's expected purposes"
        );
    }

    #[test]
    fn tlcp_server_sign_ecc_has_digital_sig_and_key_agreement_with_serverauth() {
        let p = tlcp_server_sign_ecc();
        assert_leaf_basics(&p, &[ExtendedKeyUsage::ServerAuth]);
        assert_eq!(
            p.key_usage.to_der_bytes(),
            TLCP_ECC_SIGN_KU_BYTES,
            "KU bytes must be digitalSignature(0)|keyAgreement(4) = 0x88, unused=3"
        );
        assert!(p.key_usage.digital_signature);
        assert!(p.key_usage.key_agreement);
        assert!(!p.key_usage.key_encipherment);
        assert!(!p.key_usage.key_cert_sign);
    }

    #[test]
    fn tlcp_server_enc_ecc_has_key_agreement_key_encipherment_no_eku() {
        let p = tlcp_server_enc_ecc();
        assert_leaf_basics(&p, &[]);
        assert_eq!(
            p.key_usage.to_der_bytes(),
            TLCP_ECC_ENC_KU_BYTES,
            "KU bytes must be keyEncipherment(2)|keyAgreement(4)|dataEncipherment(3) = 0x38, unused=3"
        );
        assert!(p.key_usage.key_agreement);
        assert!(p.key_usage.key_encipherment);
        assert!(p.key_usage.data_encipherment);
        assert!(
            !p.key_usage.digital_signature,
            "enc cert must not have digitalSignature"
        );
        // EKU MUST be empty for the enc cert (GmSSL / openHiTLS convention;
        // §6.4.6.1.2 b) makes EKU optional).
        assert!(p.ext_key_usage.is_empty(), "enc cert must not have EKU");
    }

    #[test]
    fn tlcp_client_sign_ecc_has_digital_sig_and_key_agreement_with_clientauth() {
        let p = tlcp_client_sign_ecc();
        assert_leaf_basics(&p, &[ExtendedKeyUsage::ClientAuth]);
        assert_eq!(
            p.key_usage.to_der_bytes(),
            TLCP_ECC_SIGN_KU_BYTES,
            "KU bytes must match server_sign_ecc (same KU; only EKU differs)"
        );
        // The only difference from server_sign_ecc must be the EKU.
        let server = tlcp_server_sign_ecc();
        assert_ne!(
            p.ext_key_usage, server.ext_key_usage,
            "client and server sign certs must have different EKUs"
        );
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn tlcp_server_rsa_has_digital_sig_and_key_encipherment_with_serverauth() {
        let p = tlcp_server_rsa();
        assert_leaf_basics(&p, &[ExtendedKeyUsage::ServerAuth]);
        assert_eq!(
            p.key_usage.to_der_bytes(),
            TLCP_RSA_KU_BYTES,
            "KU bytes must be digitalSignature(0)|keyEncipherment(2) = 0xA0, unused=5"
        );
        assert!(p.key_usage.digital_signature);
        assert!(p.key_usage.key_encipherment);
        // KU for the RSA path must NOT include keyAgreement — RSA is
        // not an ECDH key-exchange algorithm.
        assert!(!p.key_usage.key_agreement);
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn tlcp_client_rsa_has_digital_sig_and_key_encipherment_with_clientauth() {
        let p = tlcp_client_rsa();
        assert_leaf_basics(&p, &[ExtendedKeyUsage::ClientAuth]);
        assert_eq!(p.key_usage.to_der_bytes(), TLCP_RSA_KU_BYTES);
        // Difference from server_rsa must be only EKU (and KU shape
        // must be identical to server_rsa).
        let server = tlcp_server_rsa();
        assert_eq!(
            p.key_usage, server.key_usage,
            "RSA client / server must share the same KU layout"
        );
        assert_ne!(p.ext_key_usage, server.ext_key_usage);
    }

    #[test]
    fn preset_overrides_remain_possible() {
        // `CertProfile` is plain data — callers can override any field.
        // This test pins that contract: pushing to `sans` after the
        // preset must NOT panic and must survive into the resulting cert.
        let mut p = tlcp_server_sign_ecc();
        use crate::cert_profile::GeneralName;
        p.sans.push(GeneralName::DnsName("tlcp.example.com".into()));
        assert_eq!(p.sans.len(), 1);
        assert!(matches!(
            &p.sans[0],
            GeneralName::DnsName(name) if name == "tlcp.example.com"
        ));
    }

    #[test]
    fn key_usage_default_is_all_false() {
        // Sanity check: KeyUsageBits::default() is what we rely on for
        // the per-preset struct-update syntax. If this ever stops being
        // true, the preset KU encoding math above (which assumes a
        // default-starting struct) silently shifts.
        let ku = KeyUsageBits::default();
        assert!(!ku.digital_signature);
        assert!(!ku.key_agreement);
        assert!(!ku.key_encipherment);
    }
}
