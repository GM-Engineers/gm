//! Certificate profile: declarative specification of what extensions /
//! fields a certificate issued by [`CaSigner`](crate::cert::CaSigner)
//! (or [`RsaCaSigner`](crate::rsa_signer::RsaCaSigner) behind the
//! `rsa` feature) should carry.
//!
//! ## Why a profile
//!
//! The original [`CaSigner::sign_csr`](crate::cert::CaSigner::sign_csr)
//! API hard-codes a single "end-entity" extension set: KeyUsage =
//! `digitalSignature | keyEncipherment`, EKU = `serverAuth | clientAuth`,
//! plus SKI + SAN. That's fine for gm-ca v0.1.x (which only signs
//! leaf SM2 certs for the gRPC service), but it blocks three classes
//! of cert that the broader GM ecosystem needs:
//!
//! 1. **TLCP server enc cert** — needs `keyEncipherment | keyAgreement |
//!    dataEncipherment` and no `digitalSignature`.
//! 2. **TLCP client cert** — needs `clientAuth` and
//!    `keyEncipherment | keyAgreement` per GB/T 38636-2020 §6.4.6.
//! 3. **Intermediate / root CA cert** — needs `keyCertSign | cRLSign`
//!    and `BasicConstraints CA:TRUE` so the gm-tls chain verifier can
//!    accept the link (gm-tls/src/cert_verify.rs requires CA:TRUE on
//!    every intermediate, see `verify_cert_chain_sm2_chain`).
//!
//! [`CertProfile`] is the declarative answer. It lets callers say
//! "this is a TLCP server-enc cert, give me the right KU/EKU/SAN/AKI"
//! instead of having to construct extension DER by hand.
//!
//! ## TLCP-specific presets
//!
//! When the `tlcp-profiles` feature is enabled, [`profiles::tlcp`]
//! exposes the 6 standard TLCP end-entity profiles (server sign, server
//! enc, client sign, client enc, plus the RSA variants behind the
//! `rsa` feature) matching the exact KU/EKU layout the TLCP spec /
//! GmSSL / openHiTLS implementations expect.
//!
//! ## Backward compatibility
//!
//! [`CertProfile::default`] produces the same extension set as the
//! legacy `sign_csr(csr, days)` path did in gm-ca v0.1.x: end-entity
//! with digitalSignature, keyEncipherment, serverAuth, clientAuth,
//! SKI, and SAN. A new explicit BasicConstraints CA:FALSE was added
//! (RFC 5280 §4.2.1.9 allows omitting it; emitting it is safer and
//! gm-tls does not reject it).

use std::net::IpAddr;

// =============================================================================
// KeyUsage bits (RFC 5280 §4.2.1.3)
// =============================================================================

/// RFC 5280 §4.2.1.3 KeyUsage bitset.
///
/// Each flag maps to a single bit position in the BIT STRING value
/// (LSB-first encoding per DER). Defaults to all-false so callers can
/// use struct-update syntax (`Self { digital_signature: true, .. }`)
/// to opt in bit-by-bit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyUsageBits {
    pub digital_signature: bool, // bit 0
    pub non_repudiation: bool,   // bit 1
    pub key_encipherment: bool,  // bit 2
    pub data_encipherment: bool, // bit 3
    pub key_agreement: bool,     // bit 4
    pub key_cert_sign: bool,     // bit 5
    pub crl_sign: bool,          // bit 6
    pub encipher_only: bool,     // bit 7
    pub decipher_only: bool,     // bit 8
}

impl KeyUsageBits {
    /// `digitalSignature` only — typical TLS server / client leaf.
    pub fn digital_signature() -> Self {
        Self {
            digital_signature: true,
            ..Default::default()
        }
    }

    /// `digitalSignature | keyEncipherment` — typical RSA TLS leaf.
    pub fn digital_signature_and_key_encipherment() -> Self {
        Self {
            digital_signature: true,
            key_encipherment: true,
            ..Default::default()
        }
    }

    /// `keyEncipherment | keyAgreement | dataEncipherment` — TLCP
    /// server-enc cert (used to wrap the SM2 ECDH key share).
    pub fn key_encipherment_and_agreement() -> Self {
        Self {
            key_encipherment: true,
            key_agreement: true,
            data_encipherment: true,
            ..Default::default()
        }
    }

    /// `keyCertSign | cRLSign` — CA cert (root or intermediate).
    pub fn ca() -> Self {
        Self {
            key_cert_sign: true,
            crl_sign: true,
            ..Default::default()
        }
    }

    /// Encode to the BIT STRING value bytes per RFC 5280 §4.2.1.3.
    ///
    /// Format: `BIT STRING { unused-bits-in-last-byte, byte0, byte1, ... }`
    /// where `unused-bits` is the count of unused trailing bits in the
    /// **last** byte (always in `[0, 7]`).
    ///
    /// The 9 KeyUsage flags occupy bit positions 0..=8 with the canonical
    /// RFC ordering. We emit 1 or 2 bytes depending on whether
    /// `decipherOnly` (bit 8) is set, and we compute `unused-bits`
    /// from the highest set bit position so encoders downstream can
    /// round-trip the value via x509-parser.
    #[allow(dead_code)] // consumed in Phase 2
    pub(crate) fn to_der_bytes(&self) -> Vec<u8> {
        // bit position -> byte index + mask
        // (pos / 8, 0x80 >> (pos % 8))
        let mut byte0 = 0u8;
        let mut byte1 = 0u8;
        let mut last_bit: i32 = -1;
        macro_rules! set_bit {
            ($byte:expr, $bit_pos:expr) => {{
                if $bit_pos < 8 {
                    $byte |= 0x80 >> ($bit_pos as u32);
                } else {
                    // bit positions 8+ (decipherOnly) live in byte1
                }
                if $bit_pos as i32 > last_bit {
                    last_bit = $bit_pos as i32;
                }
            }};
        }
        if self.digital_signature {
            set_bit!(byte0, 0);
        }
        if self.non_repudiation {
            set_bit!(byte0, 1);
        }
        if self.key_encipherment {
            set_bit!(byte0, 2);
        }
        if self.data_encipherment {
            set_bit!(byte0, 3);
        }
        if self.key_agreement {
            set_bit!(byte0, 4);
        }
        if self.key_cert_sign {
            set_bit!(byte0, 5);
        }
        if self.crl_sign {
            set_bit!(byte0, 6);
        }
        if self.encipher_only {
            set_bit!(byte0, 7);
        }
        if self.decipher_only {
            byte1 |= 0x80; // bit 8 = MSB of byte 1
            last_bit = 8;
        }

        if last_bit < 0 {
            // No flags set — empty bit string. Per RFC 5280 the cert
            // shouldn't be issued without KeyUsage, but emitting an empty
            // BIT STRING (unused-bits=0, no payload bytes) is the least-bad
            // fallback; the parser will see zero bits and reject at the
            // application layer.
            return vec![0x00];
        }

        // unused-bits in the last byte:
        //   last_bit in [0..=7] -> last byte is byte0 -> unused = 7 - last_bit
        //   last_bit == 8       -> last byte is byte1 -> unused = 7
        let unused_bits = if last_bit < 8 {
            (7 - last_bit) as u8
        } else {
            7u8
        };

        if last_bit < 8 {
            vec![unused_bits, byte0]
        } else {
            vec![unused_bits, byte0, byte1]
        }
    }
}

// =============================================================================
// ExtendedKeyUsage (RFC 5280 §4.2.1.12)
// =============================================================================

/// RFC 5280 §4.2.1.12 ExtendedKeyUsage purpose OID.
///
/// The TLCP / gm-tls use cases only need a small subset (ServerAuth +
/// ClientAuth). CodeSigning / EmailProtection / TimeStamping / OCSP
/// are exposed for completeness; gm-ca does not check any of these
/// against an actual TLS peer so including them is purely declarative.
#[allow(dead_code)] // consumed in Phase 2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OCSPSigning,
}

impl ExtendedKeyUsage {
    /// DER-encoded OID bytes (raw, no tag / no length).
    pub(crate) fn oid_bytes(&self) -> &'static [u8] {
        // serverAuth       1.3.6.1.5.5.7.3.1  = 2B 06 01 05 05 07 03 01
        // clientAuth       1.3.6.1.5.5.7.3.2  = 2B 06 01 05 05 07 03 02
        // codeSigning      1.3.6.1.5.5.7.3.3  = 2B 06 01 05 05 07 03 03
        // emailProtection  1.3.6.1.5.5.7.3.4  = 2B 06 01 05 05 07 03 04
        // timeStamping     1.3.6.1.5.5.7.3.8  = 2B 06 01 05 05 07 03 08
        // OCSPSigning      1.3.6.1.5.5.7.3.9  = 2B 06 01 05 05 07 03 09
        match self {
            Self::ServerAuth => &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01],
            Self::ClientAuth => &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02],
            Self::CodeSigning => &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03],
            Self::EmailProtection => &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04],
            Self::TimeStamping => &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08],
            Self::OCSPSigning => &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09],
        }
    }

    /// Encode the SEQUENCE OF KeyPurposeId value (the `extnValue` body).
    #[allow(dead_code)] // consumed in Phase 2 cert.rs integration
    pub(crate) fn build_ext_key_usage_value(purposes: &[ExtendedKeyUsage]) -> Vec<u8> {
        use gm_der::encode_oid;
        let mut inner = Vec::new();
        for p in purposes {
            let oid = encode_oid(p.oid_bytes());
            inner.extend_from_slice(&oid);
        }
        gm_der::der_sequence(&inner)
    }
}

// =============================================================================
// GeneralName (RFC 5280 §4.2.1.6 — SubjectAltName entry)
// =============================================================================

/// Single SubjectAltName entry. Tagged per RFC 5280:
/// - `dNSName` = IA5String, tag `[2]` (context, primitive, IMPLICIT)
/// - `iPAddress` = OCTET STRING, tag `[7]` (context, primitive, IMPLICIT)
/// - `uniformResourceIdentifier` = IA5String, tag `[6]`
/// - `rfc822Name` = IA5String, tag `[1]`
#[allow(dead_code)] // consumed in Phase 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralName {
    DnsName(String),
    IpAddress(IpAddr),
    UniformResourceIdentifier(String),
    Rfc822Name(String),
}

impl GeneralName {
    /// Encode the IMPLICIT-tagged GeneralName body bytes (no outer SEQUENCE).
    #[allow(dead_code)] // consumed in Phase 2 cert.rs integration
    pub(crate) fn to_der(&self) -> Vec<u8> {
        use gm_der::der_len;
        match self {
            // [2] IMPLICIT IA5String -> tag byte = 0x82 (context-specific 2, primitive)
            Self::DnsName(s) => {
                let mut out = vec![0x82];
                out.extend_from_slice(&der_len(s.len()));
                out.extend_from_slice(s.as_bytes());
                out
            }
            // [7] IMPLICIT OCTET STRING
            // IPv4: 4 bytes; IPv6: 16 bytes (raw network order, no length prefix here)
            Self::IpAddress(ip) => {
                let mut out = vec![0x87];
                match ip {
                    IpAddr::V4(v4) => {
                        out.push(4);
                        out.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        out.push(16);
                        out.extend_from_slice(&v6.octets());
                    }
                }
                out
            }
            // [6] IMPLICIT IA5String
            Self::UniformResourceIdentifier(s) => {
                let mut out = vec![0x86];
                out.extend_from_slice(&der_len(s.len()));
                out.extend_from_slice(s.as_bytes());
                out
            }
            // [1] IMPLICIT IA5String
            Self::Rfc822Name(s) => {
                let mut out = vec![0x81];
                out.extend_from_slice(&der_len(s.len()));
                out.extend_from_slice(s.as_bytes());
                out
            }
        }
    }

    /// Build the SubjectAltName extension `extnValue` OCTET STRING content.
    #[allow(dead_code)] // consumed in Phase 2 cert.rs integration
    pub(crate) fn build_san_value(sans: &[GeneralName]) -> Vec<u8> {
        let mut inner = Vec::new();
        for gn in sans {
            inner.extend_from_slice(&gn.to_der());
        }
        gm_der::der_sequence_v(&[inner])
    }
}

// =============================================================================
// CertProfile — top-level declarative container
// =============================================================================

/// Declarative specification of the extension set + flags a certificate
/// should carry. Used by [`CaSigner::sign_csr`](crate::cert::CaSigner::sign_csr)
/// to determine which X.509 extensions to emit.
///
/// The struct is plain data — no hidden defaults — so callers can
/// `..Default::default()` and override only the fields they care about.
///
/// ## Example
///
/// ```ignore
/// use gm_ca::cert_profile::{CertProfile, ExtendedKeyUsage};
///
/// // TLCP server-enc cert: keyEncipherment | keyAgreement | dataEncipherment
/// let profile = CertProfile {
///     key_usage: KeyUsageBits::key_encipherment_and_agreement(),
///     ext_key_usage: vec![],  // no EKU — GmSSL doesn't require it for enc cert
///     sans: vec![GeneralName::DnsName("localhost".into())],
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct CertProfile {
    /// KeyUsage bitset (RFC 5280 §4.2.1.3).
    pub key_usage: KeyUsageBits,
    /// ExtendedKeyUsage purposes (RFC 5280 §4.2.1.12).
    /// Empty = omit the EKU extension entirely.
    pub ext_key_usage: Vec<ExtendedKeyUsage>,

    /// `true` for CA certs (root or intermediate). Affects:
    /// - `BasicConstraints CA:TRUE` (vs `CA:FALSE` for end-entity)
    /// - KeyUsage defaulting to `keyCertSign | cRLSign`
    /// - Whether the cert may be used to sign other certs
    pub is_ca: bool,

    /// `BasicConstraints pathLenConstraint` (RFC 5280 §4.2.1.9).
    /// Only meaningful when `is_ca = true`. `None` = omit, `Some(0)` = no
    /// intermediate CAs below this one, `Some(n)` = at most n intermediates.
    pub ca_path_len_constraint: Option<u8>,

    /// SAN entries to include. The first DNS entry, if any, is also used
    /// as the implicit `dns_name` for legacy `sign_csr(csr, days)` calls
    /// that pull the CN from the CSR.
    pub sans: Vec<GeneralName>,

    /// Whether to emit the SubjectAltName extension at all.
    /// Set `false` for root CA certs (no SAN for a CA).
    pub include_san: bool,

    /// Whether to emit the AuthorityKeyIdentifier extension (RFC 5280
    /// §4.2.1.1, keyIdentifier only, derived from CA's SPKI per RFC 7093
    /// Method 1 + SM3 hash). Required by GmSSL master for chain walks
    /// in TLCP (see gm-tlcp/interop/AUDIT v2-rev11 C-1 fix).
    pub include_aki: bool,

    /// Whether to emit the BasicConstraints extension (RFC 5280 §4.2.1.9).
    /// gm-tls's `verify_cert_chain_sm2_chain` requires CA:TRUE on
    /// intermediate CAs, so this should be `true` for any CA cert.
    /// End-entity certs with `include_basic_constraints = false` are
    /// also accepted by both gm-tls and gm-tlcp.
    pub include_basic_constraints: bool,

    /// Whether to emit the SubjectKeyIdentifier extension (RFC 5280
    /// §4.2.1.2, SM3-hash of SPKI, first 20 bytes per RFC 7093 Method 1).
    pub include_ski: bool,
}

impl Default for CertProfile {
    fn default() -> Self {
        // Matches gm-ca v0.1.x `sign_csr` behavior:
        //   KU = digitalSignature | keyEncipherment
        //   EKU = serverAuth | clientAuth
        //   SKI = SM3(SPKI)[:20]
        //   SAN = dNSName (from CSR subject CN)
        //   + BasicConstraints CA:FALSE (NEW vs v0.1.x; gm-tls + gm-tlcp accept it)
        Self {
            key_usage: KeyUsageBits {
                digital_signature: true,
                key_encipherment: true,
                ..Default::default()
            },
            ext_key_usage: vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
            is_ca: false,
            ca_path_len_constraint: None,
            sans: Vec::new(),
            include_san: true,
            include_aki: true,
            include_basic_constraints: true,
            include_ski: true,
        }
    }
}

impl CertProfile {
    /// Server end-entity leaf: digitalSignature + serverAuth + clientAuth.
    pub fn server_end_entity() -> Self {
        Self::default()
    }

    /// Client end-entity leaf: digitalSignature + clientAuth only.
    pub fn client_end_entity() -> Self {
        Self {
            key_usage: KeyUsageBits::digital_signature(),
            ext_key_usage: vec![ExtendedKeyUsage::ClientAuth],
            ..Default::default()
        }
    }

    /// Intermediate CA cert: keyCertSign + cRLSign + BasicConstraints CA:TRUE
    /// with pathLenConstraint=0 (no further intermediate CAs below).
    pub fn intermediate_ca() -> Self {
        Self {
            key_usage: KeyUsageBits::ca(),
            ext_key_usage: Vec::new(),
            is_ca: true,
            ca_path_len_constraint: Some(0),
            sans: Vec::new(),
            include_san: false,
            include_aki: true,
            include_basic_constraints: true,
            include_ski: true,
        }
    }

    /// Root CA cert: keyCertSign + cRLSign + BasicConstraints CA:TRUE,
    /// no pathLenConstraint (root can issue any chain depth).
    pub fn root_ca() -> Self {
        Self {
            key_usage: KeyUsageBits::ca(),
            ext_key_usage: Vec::new(),
            is_ca: true,
            ca_path_len_constraint: None,
            sans: Vec::new(),
            include_san: false,
            include_aki: true,
            include_basic_constraints: true,
            include_ski: true,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_usage_default_is_all_false() {
        let ku = KeyUsageBits::default();
        assert!(!ku.digital_signature);
        assert!(!ku.non_repudiation);
        assert!(!ku.key_encipherment);
        assert!(!ku.data_encipherment);
        assert!(!ku.key_agreement);
        assert!(!ku.key_cert_sign);
        assert!(!ku.crl_sign);
        assert!(!ku.encipher_only);
        assert!(!ku.decipher_only);
    }

    #[test]
    fn key_usage_ca_has_correct_bits() {
        let ku = KeyUsageBits::ca();
        // keyCertSign(5) | cRLSign(6) = 0b00000110 = 0x06 (MSB-first)
        // Highest set bit is bit 6, so unused-bits = 7 - 6 = 1
        let bytes = ku.to_der_bytes();
        assert_eq!(bytes, vec![0x01, 0x06]);
    }

    #[test]
    fn key_usage_digital_signature_and_encipherment() {
        let ku = KeyUsageBits::digital_signature_and_key_encipherment();
        // digitalSig(bit 0) + keyEnc(bit 2) = byte 0 = 0x80 | 0x20 = 0xA0
        // Highest set bit is bit 2, so unused-bits = 7 - 2 = 5
        let bytes = ku.to_der_bytes();
        assert_eq!(bytes, vec![0x05, 0xA0]);
    }

    #[test]
    fn key_usage_key_agreement_set() {
        let ku = KeyUsageBits::key_encipherment_and_agreement();
        // keyEnc(2) + keyAgr(4) + dataEnc(3) = 0b00010110 = 0x18 (MSB-first)
        // Wait: bit 0=0x80, bit 1=0x40, bit 2=0x20, bit 3=0x10, bit 4=0x08
        // keyEnc(2)=0x20, keyAgr(4)=0x08, dataEnc(3)=0x10
        // byte 0 = 0x20 | 0x08 | 0x10 = 0x38
        // Highest set bit is bit 4, so unused-bits = 7 - 4 = 3
        let bytes = ku.to_der_bytes();
        assert_eq!(bytes, vec![0x03, 0x38]);
    }

    #[test]
    fn key_usage_decipher_only_emits_two_bytes() {
        let ku = KeyUsageBits {
            decipher_only: true,
            ..Default::default()
        };
        // Only bit 8 set in byte 1, byte 0 unused.
        // unused-bits = 7 (byte 1 only bit 0 used).
        let bytes = ku.to_der_bytes();
        assert_eq!(bytes, vec![0x07, 0x00, 0x80]);
    }

    #[test]
    fn default_profile_matches_v0_1_x_behavior() {
        let p = CertProfile::default();
        assert!(p.key_usage.digital_signature);
        assert!(p.key_usage.key_encipherment);
        assert_eq!(p.ext_key_usage.len(), 2);
        assert!(p.ext_key_usage.contains(&ExtendedKeyUsage::ServerAuth));
        assert!(p.ext_key_usage.contains(&ExtendedKeyUsage::ClientAuth));
        assert!(!p.is_ca);
        assert!(p.include_san);
        assert!(p.include_aki);
        assert!(p.include_ski);
    }

    #[test]
    fn intermediate_ca_profile_is_marked_ca() {
        let p = CertProfile::intermediate_ca();
        assert!(p.is_ca);
        assert!(p.key_usage.key_cert_sign);
        assert!(p.key_usage.crl_sign);
        assert_eq!(p.ca_path_len_constraint, Some(0));
        assert!(p.ext_key_usage.is_empty());
        assert!(!p.include_san);
    }

    #[test]
    fn root_ca_profile_has_no_pathlen() {
        let p = CertProfile::root_ca();
        assert!(p.is_ca);
        assert_eq!(p.ca_path_len_constraint, None);
    }

    #[test]
    fn client_end_entity_profile_has_only_client_auth() {
        let p = CertProfile::client_end_entity();
        assert_eq!(p.ext_key_usage, vec![ExtendedKeyUsage::ClientAuth]);
        assert!(p.key_usage.digital_signature);
    }

    #[test]
    fn dns_name_san_encodes_correctly() {
        let gn = GeneralName::DnsName("localhost".into());
        // tag 0x82, length 9, "localhost"
        let der = gn.to_der();
        assert_eq!(
            der,
            vec![
                0x82, 0x09, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't'
            ]
        );
    }

    #[test]
    fn ipv4_san_encodes_correctly() {
        let gn = GeneralName::IpAddress("127.0.0.1".parse().unwrap());
        let der = gn.to_der();
        // tag 0x87, length 4, 4 bytes
        assert_eq!(der, vec![0x87, 0x04, 127, 0, 0, 1]);
    }

    #[test]
    fn san_value_wraps_in_sequence() {
        let sans = vec![
            GeneralName::DnsName("a.example".into()),
            GeneralName::DnsName("b.example".into()),
        ];
        let val = GeneralName::build_san_value(&sans);
        // SEQUENCE OF { dNSName "a.example", dNSName "b.example" }
        //   30 16  82 09 61 2e ...  82 09 62 2e ...
        //   tag  len  11-byte entry  11-byte entry
        //   30 + 16(=22) + 11 + 11 = 24
        assert_eq!(val.len(), 24);
        assert_eq!(val[0], 0x30);
        assert_eq!(val[1], 22); // 0x16 = 22 (each entry is 11 bytes, two = 22)
        // First entry: dNSName [2] IMPLICIT IA5String "a.example"
        assert_eq!(val[2], 0x82);
        assert_eq!(val[3], 9);
        assert_eq!(&val[4..13], b"a.example");
        // Second entry
        assert_eq!(val[13], 0x82);
        assert_eq!(val[14], 9);
        assert_eq!(&val[15..24], b"b.example");
    }
}
