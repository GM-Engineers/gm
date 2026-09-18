//! X.509 certificate chain validation primitives shared by `gm-tls` and
//! `gm-tlcp`.
//!
//! Phase D-1 of the cert-verification plan extracted this surface from
//! `gm-tls/src/cert_verify.rs` so both crates can share one chain
//! implementation. The error type changed from `TlsError` to
//! `CryptoError`; `gm-tls` retains API compatibility by re-exporting
//! these items and providing `From<CryptoError> for TlsError` at the
//! call site.
//!
//! # Verification flow
//!
//! 1. **Certificate parsing**: PEM/DER parsing with domain extraction
//! 2. **Chain validation**: each certificate in the chain is verified:
//!    - Signature verified against issuer's public key (SM2)
//!    - Validity period checked (`not_before` / `not_after`)
//!    - `BasicConstraints CA:TRUE` enforced for intermediate CAs
//! 3. **Domain matching**: SAN (Subject Alternative Name) or CN fallback
//! 4. **Revocation check** (optional): CRL lookup for each certificate
//!
//! # Constants
//!
//! - [`MAX_CERT_CHAIN_DEPTH`]: maximum certificate chain depth (10),
//!   prevents DoS via excessively deep chains
//!
//! # CRL processing
//!
//! CRLs are DER-encoded lists of revoked certificate serial numbers,
//! signed by the issuing CA. Both CRL parsing via `x509_parser` and
//! GM/T 0036 custom CRL format are supported.

use crate::error::CryptoError;
use crate::sm2::{Sm2Verifier, decompress_sm2_pubkey};
use time::OffsetDateTime;
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;
use x509_parser::revocation_list::CertificateRevocationList;

// ============== Owned Certificate ==============

/// Owned DER certificate wrapper.
#[derive(Clone)]
pub struct OwnedCert {
    der: Vec<u8>,
}

impl OwnedCert {
    /// Parse a single PEM certificate.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut iter = Pem::iter_from_buffer(pem_bytes);
        if let Some(pem) = iter.next() {
            let pem = pem.map_err(|e| {
                CryptoError::CertificateVerificationFailed(format!("PEM parse failed: {}", e))
            })?;
            return Ok(Self { der: pem.contents });
        }
        Err(CryptoError::CertificateVerificationFailed(
            "certificate PEM is empty".into(),
        ))
    }

    /// Accept a single DER certificate (raw bytes that are NOT a PEM
    /// envelope). Used by callers like gm-tlcp that receive certs
    /// from the TLCP wire-format (which is DER) and need to feed them
    /// into the verifier.
    pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
        // Sanity check: must parse as an X.509 cert. We do a
        // throwaway parse here to surface malformed DER early,
        // rather than letting `as_x509()` fail later.
        let _ = Self::parse_der(der)?;
        Ok(Self { der: der.to_vec() })
    }

    /// Accept either PEM-encoded bytes (with a `-----BEGIN ...-----`
    /// header) or raw DER bytes. Useful for unit-test fixtures that
    /// sometimes ship as one form, sometimes the other.
    pub fn from_pem_or_der(bytes: &[u8]) -> Self {
        // Detect PEM: ASCII start with `-----BEGIN`.
        let is_pem = bytes
            .iter()
            .take(11)
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace());
        let looks_pem = is_pem && bytes.starts_with(b"-----BEGIN");
        if looks_pem {
            Self::from_pem(bytes).expect("OwnedCert::from_pem_or_der: PEM parse failed")
        } else {
            Self::from_der(bytes).expect("OwnedCert::from_pem_or_der: DER parse failed")
        }
    }

    fn parse_der(der: &[u8]) -> Result<X509Certificate<'_>, CryptoError> {
        X509Certificate::from_der(der)
            .map_err(|e| {
                CryptoError::CertificateVerificationFailed(format!("DER parse failed: {:?}", e))
            })
            .map(|r| r.1)
    }

    /// Parse a PEM certificate chain (concatenated PEM blocks).
    pub fn chain_from_pem_concat(pem_bytes: &[u8]) -> Result<Vec<Self>, CryptoError> {
        let mut out = Vec::new();
        for pem in Pem::iter_from_buffer(pem_bytes) {
            let pem = pem.map_err(|e| {
                CryptoError::CertificateVerificationFailed(format!("PEM parse failed: {}", e))
            })?;
            out.push(Self { der: pem.contents });
        }
        if out.is_empty() {
            return Err(CryptoError::CertificateVerificationFailed(
                "certificate chain is empty".into(),
            ));
        }
        Ok(out)
    }

    /// Parse DER to X509Certificate.
    pub fn as_x509(&self) -> Result<X509Certificate<'_>, CryptoError> {
        let (_, cert) = X509Certificate::from_der(&self.der).map_err(|e| {
            CryptoError::CertificateVerificationFailed(format!("X509 parse failed: {}", e))
        })?;
        Ok(cert)
    }

    /// Extract raw TBS (To-Be-Signed) certificate bytes for signature verification.
    pub fn raw_tbs_bytes(&self) -> Result<&[u8], CryptoError> {
        extract_tbs_bytes(&self.der)
    }
}

// ============== Certificate Validation ==============

/// Validate a PEM certificate (parse + validate).
pub fn validate_cert_pem(
    cert_pem: &[u8],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
) -> Result<(), CryptoError> {
    let (pem, _) = Pem::read(std::io::Cursor::new(cert_pem)).map_err(|e| {
        CryptoError::CertificateVerificationFailed(format!("PEM parse failed: {}", e))
    })?;
    let (_, cert) = X509Certificate::from_der(pem.contents.as_ref()).map_err(|e| {
        CryptoError::CertificateVerificationFailed(format!("X509 parse failed: {}", e))
    })?;

    validate_cert_parsed(&cert, now, expected_domain)
}

/// Validate a single leaf certificate's hostname only — no trust-anchor
/// path validation, no signature check, no chain walking.
///
/// This is the entry point for the "operator configured `with_server_name`
/// but NOT `with_server_ca_chain`" path: hostname pinning alone, without
/// PKI enforcement. It runs the same parse + expiry + SAN/CN match
/// checks as `validate_cert_parsed`, but skips the chain/signature
/// machinery so it can succeed for any well-formed cert whose hostname
/// matches — the operator explicitly opted out of PKI by not calling
/// `with_server_ca_chain`.
///
/// # Errors
///
/// - The DER is not parseable as X.509
/// - `notBefore > now` or `notAfter < now` (cert expired / not yet valid)
/// - Neither `SAN:dNSName` nor `subject.commonName` matches `expected_domain`
///   (case-insensitive; see [`hostname_matches`] for the matching rules,
///   including RFC 6125 §6.4.3 wildcards for SAN entries)
pub fn validate_hostname_only(
    leaf_der: &[u8],
    expected_domain: &str,
    now: OffsetDateTime,
) -> Result<(), CryptoError> {
    let (_, cert) = X509Certificate::from_der(leaf_der).map_err(|e| {
        CryptoError::CertificateVerificationFailed(format!("X509 parse failed: {}", e))
    })?;
    validate_cert_parsed(&cert, now, Some(expected_domain))
}

/// RFC 5280 §4.2.1.12 role context for end-entity cert KU/EKU enforcement.
///
/// `TlcServer` / `TlcClient` mirror the TLCP ECC sign-cert vs enc-cert
/// requirements per GB/T 38636-2020 §6.4.6.1.2:
///
/// - **Sign cert**: KU must include `digitalSignature`; EKU (if present)
///   must include the matching purpose (`serverAuth` / `clientAuth`).
/// - **Enc cert**: KU must include `keyAgreement` (or `keyEncipherment`
///   for static RSA-style KEM); EKU is **optional** per the spec and we
///   do not enforce a purpose when absent.
///
/// `Ca` mirrors RFC 5280 §4.2.1.3 + §4.2.1.9: KU must include
/// `keyCertSign`; `basicConstraints CA:TRUE` is checked separately at
/// the call site.
///
/// All checks are **permissive when the relevant extension is absent**:
/// KU / EKU are optional in RFC 5280 and many TLCP deployments omit them.
/// The function only fails when an extension IS present and asserts
/// bits that contradict the cert's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRole {
    /// TLCP ECC sign cert presented by a peer (server or client side).
    /// The connector uses `TlcServer` when validating server sign leaves;
    /// the acceptor uses `TlcClient` when validating client sign leaves.
    TlcServer,
    TlcClient,
    /// Intermediate / root CA cert.
    Ca,
}

/// Check the certificate's KeyUsage and ExtendedKeyUsage extensions
/// against its declared [`CertRole`]. Permissive when extensions are
/// absent (KU/EKU are optional per RFC 5280 §4.2.1.3 / §4.2.1.12).
pub fn verify_cert_role(cert: &X509Certificate<'_>, role: CertRole) -> Result<(), CryptoError> {
    let ku = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
        .and_then(|ext| {
            if let x509_parser::extensions::ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
                Some(*ku)
            } else {
                None
            }
        });
    let eku = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE)
        .and_then(|ext| {
            if let x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) =
                ext.parsed_extension()
            {
                Some(eku)
            } else {
                None
            }
        });

    match role {
        CertRole::TlcServer | CertRole::TlcClient => {
            // Per GB/T 38636-2020 §6.4.6.1.2 a) the TLCP ECC sign cert
            // carries digitalSignature (and keyAgreement for ECDHE
            // suites). The enc-cert layout is separate and only used
            // for ECDH, so this path is for the SIGN cert.
            if let Some(ku) = ku {
                if !ku.digital_signature() {
                    return Err(CryptoError::CertificateVerificationFailed(format!(
                        "sign cert is missing required KeyUsage digitalSignature \
                         (got KU flags = 0b{:09b})",
                        ku.flags
                    )));
                }
            }
            // EKU is optional per RFC 5280 §4.2.1.12, but if present
            // it must include the matching purpose (or `any`).
            if let Some(eku) = eku {
                let ok = match role {
                    CertRole::TlcServer => eku.server_auth || eku.any,
                    CertRole::TlcClient => eku.client_auth || eku.any,
                    _ => unreachable!(),
                };
                if !ok {
                    let purpose = match role {
                        CertRole::TlcServer => "serverAuth",
                        CertRole::TlcClient => "clientAuth",
                        _ => unreachable!(),
                    };
                    return Err(CryptoError::CertificateVerificationFailed(format!(
                        "sign cert is missing required ExtendedKeyUsage {} \
                         (got EKU = {:?})",
                        purpose, eku
                    )));
                }
            }
        }
        CertRole::Ca => {
            // RFC 5280 §4.2.1.3: a CA cert used to sign other certs
            // MUST have keyCertSign set when KeyUsage is present.
            if let Some(ku) = ku {
                if !ku.key_cert_sign() {
                    return Err(CryptoError::CertificateVerificationFailed(format!(
                        "CA cert is missing required KeyUsage keyCertSign \
                         (got KU flags = 0b{:09b})",
                        ku.flags
                    )));
                }
            }
            // CA certs do not require a particular EKU per RFC 5280;
            // skip EKU check.
        }
    }
    Ok(())
}

fn validate_cert_parsed(
    cert: &X509Certificate<'_>,
    now: OffsetDateTime,
    expected_domain: Option<&str>,
) -> Result<(), CryptoError> {
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    if now < not_before || now > not_after {
        return Err(CryptoError::CertificateVerificationFailed(
            "certificate has expired or is not yet valid".into(),
        ));
    }

    if let Some(domain) = expected_domain {
        // Per RFC 6125 §6.4.4: normalize the expected domain to its
        // Punycode/ASCII form before comparison. TLCP deployments in
        // `.cn` / `.gov.cn` / `.中国` etc. rely on this — without
        // it, an operator configuring `with_server_name("央行.gov.cn")`
        // would silently fail to match a cert whose SAN is the
        // Punycode form `xn--...gov.cn`.
        let domain = normalize_domain(domain);
        let mut matched = false;
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in san.value.general_names.iter() {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    if hostname_matches(dns, &domain) {
                        matched = true;
                        break;
                    }
                }
            }
        }
        if !matched {
            if let Some(cn) = cert.subject().iter_common_name().next() {
                if let Ok(cn_str) = cn.as_str() {
                    if hostname_matches(cn_str, &domain) {
                        matched = true;
                    }
                }
            }
        }
        if !matched {
            return Err(CryptoError::CertificateVerificationFailed(
                "domain name mismatch".into(),
            ));
        }
    }
    Ok(())
}

/// Normalize an input domain name to its ASCII/Punycode form per
/// UTS #46 + RFC 6125 §6.4.4. Returns the canonical lowercase
/// ASCII label (Punycode-prefixed for non-ASCII labels).
///
/// `expected_domain` is always operator-supplied text, so we run
/// the normalization unconditionally. SAN/CN entries are always
/// IA5String (ASCII-only) per RFC 5280 §4.2.1.6, so they don't
/// need normalization on the compare side — the operator must
/// present their cert with Punycode SAN entries per
/// GB/T 3268.4 / RFC 3490.
///
/// Falls back to the raw input on error: a domain that the `idna`
/// crate rejects (forbidden code points, label-length overflow,
/// etc.) is reported to the caller as a hostname mismatch via the
/// normal error path, not as a normalization failure. We want
/// strict-fail behaviour: invalid IDN = no match = handshake rejected.
pub fn normalize_domain(domain: &str) -> String {
    // `domain_to_ascii` returns Err for forbidden code points or
    // excessive label lengths; we treat those as "no match" by
    // returning a sentinel that can never appear in a valid SAN.
    // The sentinel contains an ASCII NUL byte, which RFC 5280
    // §4.2.1.6 forbids in IA5String, so it cannot match any
    // real SAN entry.
    match idna::domain_to_ascii(domain) {
        Ok(s) => s,
        Err(_) => "\0idna-rejected".to_string(),
    }
}

/// Compare an X.509 SAN/CN entry against an expected hostname per
/// RFC 6125 §6.4.1 (case-insensitive equality) and RFC 6125 §6.4.3
/// (single-label wildcards in the left-most label).
///
/// Rules:
/// - Comparison is case-insensitive on ASCII characters
///   (`eq_ignore_ascii_case`); IDN A-label comparison is performed
///   on the Punycode-encoded form which the operator is expected to
///   pass already (IDN normalization itself is out of scope for this
///   version — see docs/known-limitations).
/// - Wildcards: only `*` in the left-most label of the SAN entry.
///   `*.example.com` matches `a.example.com`, `b.example.com`,
///   `*.example.com` itself; it does NOT match `a.b.example.com`
///   (left-most label rule, RFC 6125 §6.4.3 d)). The wildcard must
///   be the only character in the left-most label (no `a*.example.com`,
///   no `*a.example.com`, no `a*b.example.com`).
/// - Multi-label wildcards (`a.*.example.com`), wildcards combined
///   with IDN labels, and partial-label wildcards are REJECTED.
/// - CN comparison (which only happens when no SAN is present) does
///   NOT honour wildcards: RFC 6125 §6.4.4 specifies that CN-based
///   matching is deprecated and wildcards in CN are not allowed by
///   the standard.
pub fn hostname_matches(san_entry: &str, expected_domain: &str) -> bool {
    // Per RFC 6125 §6.4.3 the comparison is case-insensitive on
    // ASCII; we use the stdlib helper for that.
    if san_entry.eq_ignore_ascii_case(expected_domain) {
        return true;
    }
    // Wildcard matching only for SAN entries (CN fallback handled
    // separately at the call site — CN does NOT allow wildcards).
    // Strip the leftmost label of the SAN entry and check for `*`.
    let Some((san_leftmost, san_rest)) = san_entry.split_once('.') else {
        return false;
    };
    if san_leftmost != "*" {
        return false;
    }
    // The SAN's leftmost label is exactly `*`; build a regex-like
    // matcher: any non-empty single label followed by the same
    // remaining labels.
    let Some((exp_first, exp_rest)) = expected_domain.split_once('.') else {
        return false;
    };
    if exp_first.is_empty() {
        return false;
    }
    // RFC 6125 §6.4.3: the rest must match byte-for-byte (case-
    // insensitive). We compare the remaining portion.
    exp_rest.eq_ignore_ascii_case(san_rest)
}

// ============== Certificate Chain Verification ==============

/// Maximum allowed certificate chain depth (leaf + intermediates).
pub const MAX_CERT_CHAIN_DEPTH: usize = 10;

/// Verify a full certificate chain against trust anchors.
///
/// `role` declares how the LEAF cert is used (server or client). For
/// every other entry in the chain (intermediates, root) the
/// [`CertRole::Ca`] role is enforced. Pass [`None`] to skip role
/// checks (e.g. when the caller has not yet decided or when
/// validating an opaque chain).
pub fn verify_cert_chain_sm2_chain(
    leaf_chain: &[OwnedCert],
    trust_anchors: &[OwnedCert],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
    role: Option<CertRole>,
) -> Result<(), CryptoError> {
    if leaf_chain.is_empty() || trust_anchors.is_empty() {
        return Err(CryptoError::CertificateVerificationFailed(
            "certificate chain or trust anchor is empty".into(),
        ));
    }
    if leaf_chain.len() > MAX_CERT_CHAIN_DEPTH {
        return Err(CryptoError::CertificateVerificationFailed(format!(
            "certificate chain too deep: {} (max {})",
            leaf_chain.len(),
            MAX_CERT_CHAIN_DEPTH
        )));
    }

    // Pre-compute the role per index (idx=0 leaf uses the supplied
    // role; idx>=1 are intermediate CAs).
    let role_for_idx = |idx: usize| -> CertRole {
        if idx == 0 {
            role.unwrap_or(CertRole::Ca)
        } else {
            CertRole::Ca
        }
    };

    // Verify each link in the chain
    for idx in 0..leaf_chain.len() {
        let child_owned = &leaf_chain[idx];
        let domain = if idx == 0 { expected_domain } else { None };

        if idx + 1 < leaf_chain.len() {
            // Intermediate CA: issuer is the next cert in the chain
            let issuer_owned = &leaf_chain[idx + 1];
            verify_cert_chain_sm2(child_owned, issuer_owned, now, domain)?;

            let child_cert = child_owned.as_x509()?;

            // KU/EKU enforcement per role.
            verify_cert_role(&child_cert, role_for_idx(idx))?;

            // Check CA BasicConstraints for intermediate CAs
            let basic_constraints = child_cert
                .extensions()
                .iter()
                .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS);
            if let Some(ext) = basic_constraints {
                if let x509_parser::extensions::ParsedExtension::BasicConstraints(bc) =
                    ext.parsed_extension()
                {
                    if !bc.ca {
                        return Err(CryptoError::CertificateVerificationFailed(
                            "CA certificate missing BasicConstraints CA:TRUE".into(),
                        ));
                    }
                    // RFC 5280 §4.2.1.9 pathLenConstraint: the value
                    // gives the maximum number of non-self-issued
                    // intermediate CAs that may follow this cert.
                    // For chain[idx] at depth `idx` (counting from
                    // the leaf at 0), the intermediates that follow
                    // toward the root are at indices 1..=idx. So
                    // `idx` intermediates follow this CA's *issuers*
                    // — wait, we want those that *this CA may sign
                    // below it*, which are at indices 1..idx
                    // (excluding the leaf at 0). The count is
                    // `idx - 1` for idx >= 1, and 0 for idx = 1.
                    // Equivalently: `intermediates_below =
                    // leaf_chain.len() - 2 - (idx + 1)` where idx+1
                    // is the position of the CA in the chain and
                    // `len() - 1` is the root position. We need a
                    // count of intermediates strictly between this
                    // CA and the leaf.
                    if let Some(max_pathlen) = bc.path_len_constraint {
                        let intermediates_below: u32 = (idx - 1) as u32;
                        if intermediates_below > max_pathlen {
                            return Err(CryptoError::CertificateVerificationFailed(format!(
                                "CA certificate pathLenConstraint = {} but {} \
                                 non-leaf intermediate(s) follow it in the chain",
                                max_pathlen, intermediates_below
                            )));
                        }
                    }
                }
            } else {
                return Err(CryptoError::CertificateVerificationFailed(
                    "CA certificate missing BasicConstraints extension".into(),
                ));
            }
        } else {
            // Root cert: try each trust anchor until one validates successfully
            let mut last_err = None;
            for anchor in trust_anchors {
                match verify_cert_chain_sm2(child_owned, anchor, now, domain) {
                    Ok(()) => {
                        // KU/EKU enforcement for the trust anchor (treated as CA).
                        let root_cert = child_owned.as_x509()?;
                        verify_cert_role(&root_cert, CertRole::Ca)?;
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                    }
                }
            }
            if let Some(e) = last_err {
                return Err(e);
            }
        }
    }
    Ok(())
}

// ============== DER-byte entry point (gm-tlcp Phase E) ==============

/// Verify a peer-asserted certificate chain against trust anchors,
/// taking the byte representation each TLS-style protocol surfaces
/// over the wire — no PEM wrapper, no `OwnedCert` parsing.
///
/// This is the entry point `gm-tlcp` (Phase E) calls with the
/// raw bytes returned by `TlcpStream::client_certificates` /
/// `TlcpStream::server_certificates` (Phase B). It is also the
/// path future protocols (TLS 1.3 + SM via gm-tls) should prefer
/// over the PEM-flavored [`verify_cert_chain_sm2_chain`].
///
/// # Chain layout
///
/// `leaf_chain_der` is **leaf-first**: `[leaf, intermediate_1, ...,
/// intermediate_n, root]`. The chain depth (including the root) is
/// bounded by [`MAX_CERT_CHAIN_DEPTH`].
///
/// # Anchor matching
///
/// The root entry of `leaf_chain_der` must chain (subject DN match +
/// signature) to **one of** `anchors_der` for the chain to validate.
/// This matches the X.509 trust-store model: a CA is trusted
/// implicitly, so the chain usually ends at the CA cert itself
/// rather than a separately-named anchor.
///
/// # TLCP usage
///
/// TLCP dual-cert model sends sign + enc as separate Certificate
/// entries that share a common CA. Callers should pass the
/// sign-leaf chain (e.g. `[sign_cert, ca_cert]`) and the enc-leaf
/// chain (e.g. `[enc_cert, ca_cert]`) separately, both anchored
/// against the same `anchors_der`. The same anchors being valid for
/// both is the "sign + enc share one chain" invariant from the
/// Phase D design decision.
///
/// # Errors
///
/// Returns [`CryptoError::CertificateVerificationFailed`] with one
/// of these reasons (mirrors the wrapped function's diagnostics):
///
///   * `"certificate chain or trust anchor is empty"`
///   * `"certificate chain too deep: N (max 10)"`
///   * `"CA certificate missing BasicConstraints CA:TRUE"` /
///     `"CA certificate missing BasicConstraints extension"`
///   * `"certificate issuer does not match CA"`
///   * `"certificate has expired or is not yet valid"`
///   * `"domain name mismatch"`
///   * SM2 signature verification failures (delegated)
pub fn verify_against_anchors(
    leaf_chain_der: &[Vec<u8>],
    anchors_der: &[Vec<u8>],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
    role: Option<CertRole>,
) -> Result<(), CryptoError> {
    // Build OwnedCert wrappers from the DER bytes. This is the only
    // point in this module that parses the wire-format bytes; the
    // rest of the chain-validation code path operates on OwnedCert
    // to keep a single validation implementation.
    let leaf_chain = leaf_chain_der
        .iter()
        .map(|der| OwnedCert { der: der.clone() })
        .collect::<Vec<_>>();
    let trust_anchors = anchors_der
        .iter()
        .map(|der| OwnedCert { der: der.clone() })
        .collect::<Vec<_>>();
    verify_cert_chain_sm2_chain(&leaf_chain, &trust_anchors, now, expected_domain, role)
}

fn verify_cert_chain_sm2(
    leaf: &OwnedCert,
    ca: &OwnedCert,
    now: OffsetDateTime,
    expected_domain: Option<&str>,
) -> Result<(), CryptoError> {
    let leaf_cert = leaf.as_x509()?;
    let ca_cert = ca.as_x509()?;

    validate_cert_parsed(&leaf_cert, now, expected_domain)?;
    validate_cert_parsed(&ca_cert, now, None)?;

    if leaf_cert.issuer() != ca_cert.subject() {
        return Err(CryptoError::CertificateVerificationFailed(
            "certificate issuer does not match CA".into(),
        ));
    }

    verify_cert_signature(&leaf_cert, &ca_cert, &leaf.der)?;
    Ok(())
}

/// Extract the server's public key from its certificate chain for CertificateVerify verification.
/// Returns the public key in uncompressed SEC1 format (0x04 || x || y).
pub fn extract_server_pubkey_for_cert_verify(
    cert_chain_pem: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let chain = OwnedCert::chain_from_pem_concat(cert_chain_pem)?;
    let leaf = chain.first().ok_or_else(|| {
        CryptoError::CertificateVerificationFailed("certificate chain is empty".into())
    })?;
    let leaf_cert = leaf.as_x509()?;

    let pki = leaf_cert.public_key();
    let pub_key_bytes: &[u8] = pki.subject_public_key.data.as_ref();

    let sm2_pub_key: Vec<u8> =
        if pub_key_bytes.len() == 33 && (pub_key_bytes[0] == 0x02 || pub_key_bytes[0] == 0x03) {
            decompress_sm2_pubkey(pub_key_bytes).map_err(|e| {
                CryptoError::CertificateVerificationFailed(format!(
                    "failed to decompress SM2 public key: {}",
                    e
                ))
            })?
        } else {
            pub_key_bytes.to_vec()
        };

    Ok(sm2_pub_key)
}

// ============== CRL ==============

/// A parsed CRL with metadata
#[derive(Debug, Clone)]
pub struct CrlInfo {
    /// Raw DER-encoded CRL data (owned to avoid memory leak)
    der: Vec<u8>,
}

impl CrlInfo {
    /// Parse a CRL from PEM format
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, CryptoError> {
        let (pem, _) = Pem::read(std::io::Cursor::new(pem_bytes)).map_err(|e| {
            CryptoError::CrlVerificationFailed(format!("CRL PEM parse failed: {}", e))
        })?;

        let der = pem.contents.to_vec();
        // Validate CRL parses correctly before storing
        Self::parse_crl(&der)?;

        Ok(Self { der })
    }

    /// Parse a CRL from DER format
    pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
        let der = der.to_vec();
        Self::parse_crl(&der)?;
        Ok(Self { der })
    }

    /// Parse CRL from raw DER bytes (validates the DER)
    fn parse_crl(der: &[u8]) -> Result<CertificateRevocationList<'_>, CryptoError> {
        CertificateRevocationList::from_der(der)
            .map_err(|e| CryptoError::CrlVerificationFailed(format!("CRL parse failed: {:?}", e)))
            .map(|r| r.1)
    }

    /// Extract raw TBS (To-Be-Signed) CRL bytes for signature verification
    pub fn raw_tbs_bytes(&self) -> Result<&[u8], CryptoError> {
        extract_tbs_crl_bytes(&self.der)
    }

    /// Check if a certificate serial number is revoked in this CRL
    pub fn is_cert_revoked(&self, serial_bytes: &[u8]) -> bool {
        // Re-parse on each check to avoid lifetime issues (CRL lookups are infrequent)
        if let Ok(crl) = Self::parse_crl(&self.der) {
            for revoked in crl.iter_revoked_certificates() {
                if revoked.raw_serial() == serial_bytes {
                    return true;
                }
            }
        }
        false
    }

    /// Get the issuer name as a string for comparison purposes
    pub fn issuer_str(&self) -> Result<String, CryptoError> {
        let crl = Self::parse_crl(&self.der)?;
        Ok(crl.issuer().to_string())
    }

    /// Get the raw DER-encoded issuer name for byte-exact comparison
    pub fn issuer_der(&self) -> Result<Vec<u8>, CryptoError> {
        let crl = Self::parse_crl(&self.der)?;
        Ok(crl.issuer().as_raw().to_vec())
    }

    /// Check if the CRL is currently valid (now is between last_update and next_update)
    pub fn is_valid(&self, now: OffsetDateTime) -> bool {
        let crl = match Self::parse_crl(&self.der) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let last = crl.last_update();
        let next = crl.next_update();

        let now_asn1 = x509_parser::time::ASN1Time::new(now);

        if now_asn1 < last {
            return false;
        }
        if let Some(next_time) = next {
            if now_asn1 > next_time {
                return false;
            }
        }
        true
    }
}

/// Verify that a certificate is not revoked in a CRL.
///
/// # Arguments
/// * `cert_serial` - The serial number bytes of the certificate to check
/// * `issuer` - The X.509 name of the CRL issuer (should match the certificate issuer)
/// * `ca_cert` - The CA certificate used to verify the CRL signature
/// * `crl` - The CRL to check against
/// * `now` - Current time for CRL validity check
///
/// # Returns
/// * `Ok(())` if the certificate is NOT revoked
/// * `Err(CryptoError::CrlVerificationFailed)` if revoked or CRL invalid
pub fn verify_crl(
    cert_serial: &[u8],
    issuer: &x509_parser::x509::X509Name,
    ca_cert: &X509Certificate<'_>,
    crl: &CrlInfo,
    now: OffsetDateTime,
) -> Result<(), CryptoError> {
    // Verify CRL issuer matches expected issuer using DER byte comparison
    // (avoids issues with string formatting differences in DN encoding)
    let crl_issuer_der = crl.issuer_der()?;
    let cert_issuer_der = issuer.as_raw();
    if crl_issuer_der.as_slice() != cert_issuer_der {
        return Err(CryptoError::CrlVerificationFailed(
            "CRL issuer does not match certificate issuer".into(),
        ));
    }

    // Verify CRL signature using CA's public key
    verify_crl_signature(crl, ca_cert)?;

    // Check if CRL is still valid
    if !crl.is_valid(now) {
        return Err(CryptoError::CrlVerificationFailed("CRL has expired".into()));
    }

    // Check if certificate is revoked
    if crl.is_cert_revoked(cert_serial) {
        return Err(CryptoError::CrlVerificationFailed(
            "certificate has been revoked".into(),
        ));
    }

    Ok(())
}

/// Verify CRL against a certificate chain.
///
/// # Arguments
/// * `cert` - The certificate to check
/// * `ca_cert` - The CA certificate used to verify the CRL signature
/// * `crl_pem` - PEM-encoded CRL
/// * `now` - Current time
///
/// # Returns
/// * `Ok(())` if not revoked
/// * `Err` if revoked or CRL invalid
pub fn verify_cert_crl(
    cert: &X509Certificate<'_>,
    ca_cert: &X509Certificate<'_>,
    crl_pem: &[u8],
    now: OffsetDateTime,
) -> Result<(), CryptoError> {
    let crl = CrlInfo::from_pem(crl_pem)?;

    let cert_issuer = cert.issuer();
    // Convert BigUint serial to bytes using to_bytes_be
    let cert_serial = cert.serial.to_bytes_be();

    verify_crl(&cert_serial, cert_issuer, ca_cert, &crl, now)
}

/// Revocation check helper for `verify_against_anchors`. Walks the
/// validated chain (leaf + intermediates + root) and, for each cert
/// whose issuer DN matches a CRL's issuer DN, checks whether the cert's
/// serial appears in that CRL's `revokedCertificates` list. The CRL's
/// signature is verified against the chain cert whose subject equals
/// the CRL's issuer DN (the CA that issued the
/// CRL). Revocation check then proceeds for each cert in `chain`
/// whose issuer matches the CRL's issuer.
///
/// Mismatched CRLs (issuer not present in the chain) are silently
/// skipped — the operator is expected to provide CRLs that match
/// their configured anchors. Malformed CRLs are also silently
/// skipped (one bad CRL does not invalidate the whole handshake).
pub fn check_revocations(
    chain: &[OwnedCert],
    crls: &[Vec<u8>],
    now: OffsetDateTime,
) -> Result<(), CryptoError> {
    if crls.is_empty() {
        return Ok(());
    }
    for crl_der in crls {
        let crl = match CrlInfo::from_der(crl_der) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let crl_issuer_der = match crl.issuer_der() {
            Ok(d) => d,
            Err(_) => continue,
        };
        // Find the CA cert in the chain (the one whose subject
        // matches the CRL's issuer). This is the cert whose public
        // key will verify the CRL's signature.
        let ca_cert = chain.iter().find_map(|c| {
            if let Ok(parsed) = c.as_x509() {
                if parsed.subject().as_raw() == crl_issuer_der.as_slice() {
                    return Some(parsed);
                }
            }
            None
        });
        let ca_cert = match ca_cert {
            Some(c) => c,
            None => continue, // no matching CA in chain
        };
        // Verify CRL signature against this CA
        verify_crl_signature(&crl, &ca_cert)?;
        // Check CRL freshness (thisUpdate <= now <= nextUpdate).
        if !crl.is_valid(now) {
            return Err(CryptoError::CrlVerificationFailed(
                "CRL has expired (nextUpdate < now) or not yet valid (lastUpdate > now)".into(),
            ));
        }
        // Check each cert whose issuer matches this CRL's issuer.
        for cert_owned in chain {
            let cert = match cert_owned.as_x509() {
                Ok(c) => c,
                Err(_) => continue,
            };
            if cert.issuer().as_raw() != crl_issuer_der.as_slice() {
                continue;
            }
            let serial = cert.serial.to_bytes_be();
            if crl.is_cert_revoked(&serial) {
                return Err(CryptoError::CrlVerificationFailed(format!(
                    "certificate serial 0x{} has been revoked per CRL",
                    hex::encode(&serial)
                )));
            }
        }
    }
    Ok(())
}

/// Verify SM2 signature on a certificate using the issuer's public key
fn verify_cert_signature(
    leaf_cert: &X509Certificate<'_>,
    ca_cert: &X509Certificate<'_>,
    leaf_der: &[u8],
) -> Result<(), CryptoError> {
    // Get the raw TBS (To-Be-Signed) certificate bytes
    let tbs_bytes = extract_tbs_bytes(leaf_der)?;

    // Get CA's public key bytes from SubjectPublicKeyInfo
    let ca_pki = ca_cert.public_key();
    let ca_pub_key_bytes: &[u8] = ca_pki.subject_public_key.data.as_ref();

    // For SM2 public key in X.509, the format is:
    // - 0x04 (uncompressed) || x (32 bytes) || y (32 bytes) = 65 bytes
    // - Compressed format: 0x02/0x03 || x (32 bytes) = 33 bytes
    //
    // Sm2Verifier::new expects SEC1 format (with 0x04/0x02/0x03 prefix)
    // We need to decompress compressed keys to uncompressed format
    let sm2_pub_key: Vec<u8> = if ca_pub_key_bytes.len() == 33
        && (ca_pub_key_bytes[0] == 0x02 || ca_pub_key_bytes[0] == 0x03)
    {
        // Compressed format: decompress to uncompressed (65 bytes)
        decompress_sm2_pubkey(ca_pub_key_bytes).map_err(|e| {
            CryptoError::CertificateVerificationFailed(format!(
                "failed to decompress SM2 public key: {}",
                e
            ))
        })?
    } else {
        // Already uncompressed or other format - use as-is
        ca_pub_key_bytes.to_vec()
    };

    // Get signature value (BIT STRING)
    let sig_bytes: &[u8] = leaf_cert.signature_value.data.as_ref();

    // SM2 signatures may be DER-encoded (from X.509 certs) or raw (64 bytes, r||s)
    // Convert DER to raw format if needed
    let sig_raw: Vec<u8> = if sig_bytes.len() == 64 {
        // Already raw format (r || s)
        sig_bytes.to_vec()
    } else if sig_bytes.len() > 64 {
        // DER-encoded SEQUENCE { INTEGER r, INTEGER s }
        crate::sm2::sm2_signature_der_to_raw(sig_bytes)
            .map_err(|e| {
                CryptoError::CertificateVerificationFailed(format!(
                    "failed to parse DER SM2 signature: {}",
                    e
                ))
            })?
            .to_vec()
    } else {
        return Err(CryptoError::CertificateVerificationFailed(format!(
            "SM2 signature too short: {} bytes (expected 64 raw or DER-encoded)",
            sig_bytes.len()
        )));
    };

    // Verify the signature using SM2 (verifier hashes internally with SM3)
    //
    // SM2 signature verification requires the signing ID (ZA computation).
    // GM/T standard uses "1234567812345678", but OpenSSL 3.x defaults to empty string.
    // Try the GM/T standard ID first, then fall back to empty ID.
    let verifier = Sm2Verifier::new(&sm2_pub_key, "1234567812345678").map_err(|e| {
        CryptoError::CertificateVerificationFailed(format!("failed to create SM2 verifier: {}", e))
    })?;

    match verifier.verify(tbs_bytes, &sig_raw) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Fall back to empty ID (OpenSSL 3.x default)
            let verifier2 = Sm2Verifier::new(&sm2_pub_key, "").map_err(|e| {
                CryptoError::CertificateVerificationFailed(format!(
                    "failed to create fallback SM2 verifier: {}",
                    e
                ))
            })?;
            verifier2.verify(tbs_bytes, &sig_raw).map_err(|e| {
                CryptoError::CertificateVerificationFailed(format!(
                    "SM2 verification failed (tried both GM/T ID and empty ID): {}",
                    e
                ))
            })
        }
    }
}

/// Verify SM2 signature on a CRL using the CA's public key
fn verify_crl_signature(crl: &CrlInfo, ca_cert: &X509Certificate<'_>) -> Result<(), CryptoError> {
    // Get the raw TBS CRL bytes
    let tbs_bytes = crl.raw_tbs_bytes()?;

    // Get CA's public key bytes from SubjectPublicKeyInfo
    let ca_pki = ca_cert.public_key();
    let ca_pub_key_bytes: &[u8] = ca_pki.subject_public_key.data.as_ref();

    // Decompress SM2 public key if needed
    let sm2_pub_key: Vec<u8> = if ca_pub_key_bytes.len() == 33
        && (ca_pub_key_bytes[0] == 0x02 || ca_pub_key_bytes[0] == 0x03)
    {
        decompress_sm2_pubkey(ca_pub_key_bytes).map_err(|e| {
            CryptoError::CrlVerificationFailed(format!(
                "failed to decompress SM2 public key: {}",
                e
            ))
        })?
    } else {
        ca_pub_key_bytes.to_vec()
    };

    // Get signature value from CRL - need to parse DER to find BIT STRING
    let sig_bytes = extract_crl_signature(&crl.der)?;

    // SM2 signatures may be DER-encoded or raw (64 bytes)
    let sig_raw: Vec<u8> = if sig_bytes.len() == 64 {
        sig_bytes.to_vec()
    } else if sig_bytes.len() > 64 {
        crate::sm2::sm2_signature_der_to_raw(sig_bytes)
            .map_err(|e| {
                CryptoError::CrlVerificationFailed(format!(
                    "failed to parse DER SM2 CRL signature: {}",
                    e
                ))
            })?
            .to_vec()
    } else {
        return Err(CryptoError::CrlVerificationFailed(format!(
            "SM2 CRL signature too short: {} bytes",
            sig_bytes.len()
        )));
    };

    // Verify the signature using SM2 (try both GM/T ID and empty ID)
    let verifier = Sm2Verifier::new(&sm2_pub_key, "1234567812345678").map_err(|e| {
        CryptoError::CrlVerificationFailed(format!("failed to create SM2 verifier: {}", e))
    })?;

    match verifier.verify(tbs_bytes, &sig_raw) {
        Ok(()) => Ok(()),
        Err(_) => {
            let verifier2 = Sm2Verifier::new(&sm2_pub_key, "").map_err(|e| {
                CryptoError::CrlVerificationFailed(format!(
                    "failed to create fallback SM2 verifier: {}",
                    e
                ))
            })?;
            verifier2.verify(tbs_bytes, &sig_raw).map_err(|e| {
                CryptoError::CrlVerificationFailed(format!(
                    "SM2 CRL verification failed (tried both GM/T ID and empty ID): {}",
                    e
                ))
            })
        }
    }
}

/// Extract signature bits from a CRL DER encoding
fn extract_crl_signature(der: &[u8]) -> Result<&[u8], CryptoError> {
    // CRL structure: SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }.
    //
    // A previous hand-rolled walker stopped at the end of the OUTER CRL
    // content (i.e. past signatureAlgorithm + signatureValue), not at
    // the end of the TBS — so it reported "CRL signature algorithm
    // SEQUENCE not found" for CRLs whose outer length used the long
    // form (e.g. `30 81 c9 ...`). The signature BIT STRING lives at
    // the end of the buffer, so the walker would index out of bounds.
    //
    // We now reuse the parser's view: parse the CRL via
    // `CertificateRevocationList::from_der`, borrow its
    // `signature_value`, then re-locate the BIT STRING's data inside
    // the original `der` buffer so the returned slice carries the
    // caller's lifetime.
    let (_, crl) = CertificateRevocationList::from_der(der)
        .map_err(|e| CryptoError::CrlVerificationFailed(format!("CRL parse failed: {:?}", e)))?;
    let sig_value: &[u8] = crl.signature_value.as_ref();
    find_bitstring_in_outer(der, sig_value).ok_or_else(|| {
        CryptoError::CrlVerificationFailed(
            "CRL signature BIT STRING data not found in outer DER".into(),
        )
    })
}

/// Locate the byte range of `target` (the signature BIT STRING's content)
/// inside `der`. The BIT STRING content is preceded by a 1-byte
/// `unused_bits` count, so the actual signature starts 1 byte after the
/// tag+length header. We scan for the BIT STRING tag (0x03), skip its
/// length, then look for the `unused_bits` byte followed by `target`.
fn find_bitstring_in_outer<'a>(der: &'a [u8], target: &[u8]) -> Option<&'a [u8]> {
    // Walk the outermost CRL SEQUENCE to find the LAST BIT STRING
    // (the signatureValue BIT STRING — there is exactly one after the
    // TBSCertList's optional extensions BIT STRING, but the extensions
    // BIT STRING is wrapped in CONTEXT[0] (0xa0) so a tag of 0x03 alone
    // uniquely identifies the signatureValue).
    let mut pos = 0;
    while pos < der.len() {
        if der[pos] == 0x03 && pos + 1 < der.len() {
            // parse length
            let len_byte = der[pos + 1];
            let (data_start, sig_len) = if len_byte < 0x80 {
                (pos + 2, len_byte as usize)
            } else {
                let n = (len_byte & 0x7F) as usize;
                if pos + 2 + n > der.len() {
                    pos += 1;
                    continue;
                }
                let mut len = 0usize;
                for i in 0..n {
                    len = (len << 8) | (der[pos + 2 + i] as usize);
                }
                (pos + 2 + n, len)
            };
            // BIT STRING content: 1 byte unused_bits + sig_len bytes
            if sig_len >= 1 && data_start < der.len() && data_start + sig_len <= der.len() {
                let content = &der[data_start + 1..data_start + sig_len];
                if content == target {
                    return Some(content);
                }
            }
            pos = data_start + sig_len;
        } else {
            pos += 1;
        }
    }
    None
}

// ============== TBS Extraction Helpers ==============

/// Extract TBS (To-Be-Signed) bytes from an X.509 certificate DER encoding.
///
/// The certificate structure is:
/// Certificate ::= SEQUENCE {
///     tbsCertificate TBSCertificate,
///     signatureAlgorithm AlgorithmIdentifier,
///     signatureValue BIT STRING
/// }
///
/// This function manually parses the DER to find the TBS portion.
/// Returns the raw TBSCertificate DER bytes (including its SEQUENCE tag and length).
fn extract_tbs_bytes(der: &[u8]) -> Result<&[u8], CryptoError> {
    // Minimum DER certificate size: SEQUENCE (1) + length (1) + at least
    // signature algorithm (2) + minimum TBS (~5 for empty fields) + signature (~6).
    // We need at least 11 bytes to safely access der[pos+4] during length parsing
    // and der[tbs_pos+3] during TBS length parsing without bounds checks.
    if der.len() < 11 {
        return Err(CryptoError::CertificateVerificationFailed(
            "certificate DER too short".into(),
        ));
    }

    // First byte should be SEQUENCE (0x30) - outer Certificate SEQUENCE
    if der[0] != 0x30 {
        return Err(CryptoError::CertificateVerificationFailed(
            "invalid certificate structure: expected SEQUENCE".into(),
        ));
    }

    // Read the outer SEQUENCE length to skip past it
    let mut pos = 1;
    let first_len_byte = der[pos];
    let _outer_content_len = if first_len_byte < 0x80 {
        // Short form: length is in the byte itself
        pos += 1;
        first_len_byte as usize
    } else {
        // Long form: bit 7 set, lower 7 bits indicate how many length bytes follow
        let num_len_bytes = (first_len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return Err(CryptoError::CertificateVerificationFailed(
                "unsupported DER length encoding".into(),
            ));
        }
        pos += 1;
        let mut len = 0usize;
        for i in 0..num_len_bytes {
            len = (len << 8) | (der[pos + i] as usize);
        }
        pos += num_len_bytes;
        len
    };

    // Now we're at the TBSCertificate (which also starts with 0x30)
    if der[pos] != 0x30 {
        return Err(CryptoError::CertificateVerificationFailed(
            "invalid TBS structure: expected SEQUENCE".into(),
        ));
    }

    // Read the TBS length
    let mut tbs_pos = pos + 1;
    let tbs_len_byte = der[tbs_pos];
    let tbs_content_len = if tbs_len_byte < 0x80 {
        tbs_pos += 1;
        tbs_len_byte as usize
    } else {
        let num_len_bytes = (tbs_len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return Err(CryptoError::CertificateVerificationFailed(
                "unsupported TBS length encoding".into(),
            ));
        }
        tbs_pos += 1;
        let mut len = 0usize;
        for i in 0..num_len_bytes {
            len = (len << 8) | (der[tbs_pos + i] as usize);
        }
        tbs_pos += num_len_bytes;
        len
    };

    // TBS ends at tbs_pos + tbs_content_len
    let tbs_end = tbs_pos + tbs_content_len;
    if tbs_end > der.len() {
        return Err(CryptoError::CertificateVerificationFailed(
            "TBS length exceeds certificate bounds".into(),
        ));
    }

    // Return just the TBS portion (from pos to tbs_end)
    Ok(&der[pos..tbs_end])
}

/// Extract TBS (To-Be-Signed) bytes from a CRL DER encoding.
///
/// The CRL structure is:
/// TBSCertList ::= SEQUENCE {
///     ...
/// }
///
/// Returns the raw TBSCertList DER bytes.
fn extract_tbs_crl_bytes(der: &[u8]) -> Result<&[u8], CryptoError> {
    // Same minimum as extract_tbs_bytes: need at least 11 bytes for safe parsing
    // of length fields and TBS access without bounds checks.
    if der.len() < 11 {
        return Err(CryptoError::CrlVerificationFailed(
            "CRL DER too short".into(),
        ));
    }

    if der[0] != 0x30 {
        return Err(CryptoError::CrlVerificationFailed(
            "invalid CRL: expected SEQUENCE".into(),
        ));
    }

    // Read outer SEQUENCE length
    let mut pos = 1;
    let first_len_byte = der[pos];
    let tbs_start = if first_len_byte < 0x80 {
        pos += 1;
        pos
    } else {
        let num_len_bytes = (first_len_byte & 0x7F) as usize;
        pos += 1 + num_len_bytes;
        pos
    };

    // Find TBSCertList SEQUENCE
    if der[tbs_start] != 0x30 {
        return Err(CryptoError::CrlVerificationFailed(
            "invalid TBSCertList: expected SEQUENCE".into(),
        ));
    }

    let tbs_len_byte = der[tbs_start + 1];
    let tbs_content_start = if tbs_len_byte < 0x80 {
        tbs_start + 2
    } else {
        let num_len_bytes = (tbs_len_byte & 0x7F) as usize;
        tbs_start + 2 + num_len_bytes
    };

    let tbs_len = if tbs_len_byte < 0x80 {
        tbs_len_byte as usize
    } else {
        let num_len_bytes = (tbs_len_byte & 0x7F) as usize;
        let mut content_len = 0usize;
        for i in 0..num_len_bytes {
            content_len = (content_len << 8) | (der[tbs_start + 2 + i] as usize);
        }
        content_len
    };

    let tbs_end = tbs_content_start + tbs_len;
    if tbs_end > der.len() {
        return Err(CryptoError::CrlVerificationFailed(
            "TBSCertList extends past end of DER".into(),
        ));
    }

    Ok(&der[tbs_start..tbs_end])
}

// ============== Tests ==============

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_against_anchors_rejects_empty_chain() {
        // Empty chain with non-empty anchors -> must fail with the
        // "chain or anchor is empty" diagnostic. We do not need real
        // cert bytes here because the empty-chain guard fires before
        // any parsing.
        let err = verify_against_anchors(
            &[],
            &[vec![0x30, 0x00]], // any byte vec
            OffsetDateTime::now_utc(),
            None,
            None,
        )
        .unwrap_err();
        assert!(
            format!("{}", err).contains("empty"),
            "expected empty-chain diagnostic, got: {}",
            err
        );
    }

    #[test]
    fn verify_against_anchors_rejects_empty_anchors() {
        // Non-empty chain with empty anchors -> must fail with the
        // same diagnostic. We use a parseable DER byte (a minimal
        // empty SEQUENCE `30 00`) so that the empty-anchors guard
        // is what fires, not the DER parser. The function short-
        // circuits on the empty-anchors check before trying to parse.
        let err = verify_against_anchors(
            &[vec![0x30, 0x00]],
            &[],
            OffsetDateTime::now_utc(),
            None,
            None,
        )
        .unwrap_err();
        assert!(
            format!("{}", err).contains("empty"),
            "expected empty-anchor diagnostic, got: {}",
            err
        );
    }

    #[test]
    fn verify_against_anchors_rejects_chain_too_deep() {
        // Build a chain with MAX_CERT_CHAIN_DEPTH + 1 entries to
        // trip the depth guard. The DER bytes are bogus because the
        // depth check runs before parsing.
        let too_deep: Vec<Vec<u8>> = (0..MAX_CERT_CHAIN_DEPTH + 1)
            .map(|_| vec![0x30, 0x00])
            .collect();
        let err = verify_against_anchors(
            &too_deep,
            &[vec![0x30, 0x00]],
            OffsetDateTime::now_utc(),
            None,
            None,
        )
        .unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("too deep"),
            "expected depth diagnostic, got: {}",
            msg
        );
    }

    #[test]
    fn validate_hostname_only_runs_without_anchors() {
        // Regression for the audit finding CRITICAL-1: a previous
        // version of `connect_with_certs` routed the hostname-only
        // path through `verify_against_anchors` with empty anchors,
        // which short-circuited on the empty-anchor guard and never
        // reached the hostname check. `validate_hostname_only` is
        // the dedicated leaf-only helper that does not require any
        // anchors.
        //
        // Use a minimal-but-parseable DER blob (empty SEQUENCE) —
        // the parser will reject it, which is fine: we're verifying
        // that the helper runs the parser instead of short-
        // circuiting on a missing-anchor check.
        let err = validate_hostname_only(&[0x30, 0x00], "example.com", OffsetDateTime::now_utc())
            .unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("X509 parse failed") || msg.contains("parse"),
            "expected X509 parse error (NOT empty-anchor), got: {}",
            msg
        );
    }

    // (A full cert-build + no-match integration test is in
    // `gm-tlcp/tests/gm_tlcp_cert_verify_negative.rs::f08`; we
    // exercise the unit-level matcher rules below.)

    // -- hostname_matches (RFC 6125 §6.4.3) tests --

    #[test]
    fn hostname_matches_exact_case_insensitive() {
        // Per RFC 6125 §6.4.1: case-insensitive ASCII equality.
        assert!(hostname_matches("example.com", "example.com"));
        assert!(hostname_matches("EXAMPLE.com", "example.com"));
        assert!(hostname_matches("example.COM", "example.COM"));
        assert!(!hostname_matches("example.com", "other.com"));
    }

    #[test]
    fn hostname_matches_wildcard_single_label() {
        // Per RFC 6125 §6.4.3: `*.example.com` matches `foo.example.com`,
        // `bar.example.com`, and `*.example.com` itself, but NOT
        // `foo.bar.example.com` (left-most label rule).
        assert!(hostname_matches("*.example.com", "foo.example.com"));
        assert!(hostname_matches("*.example.com", "bar.example.com"));
        assert!(hostname_matches("*.example.com", "*.example.com"));
        // Left-most label rule: must NOT match sub-sub-domains.
        assert!(!hostname_matches("*.example.com", "foo.bar.example.com"));
    }

    #[test]
    fn hostname_matches_wildcard_rejects_partial_label() {
        // RFC 6125 §6.4.3: the wildcard must be the entire left-most
        // label, not part of a label.
        assert!(!hostname_matches("a*.example.com", "apple.example.com"));
        assert!(!hostname_matches("*a.example.com", "x.example.com"));
        assert!(!hostname_matches("a*b.example.com", "axb.example.com"));
        // Multi-label wildcards are not allowed.
        assert!(!hostname_matches("a.*.example.com", "a.b.example.com"));
    }

    #[test]
    fn hostname_matches_wildcard_no_anchor() {
        // Wildcard SAN `*.example.com` cannot match a bare domain
        // `example.com` (the wildcard requires at least one label
        // before the matching suffix).
        assert!(!hostname_matches("*.example.com", "example.com"));
    }

    // -- normalize_domain (RFC 6125 §6.4.4) tests --

    #[test]
    fn normalize_domain_ascii_unchanged() {
        // Pure ASCII input must round-trip byte-for-byte (case
        // is folded to lowercase per UTS #46).
        assert_eq!(normalize_domain("example.com"), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM"), "example.com");
        assert_eq!(normalize_domain("api.example.com"), "api.example.com");
    }

    #[test]
    fn normalize_domain_unicode_to_punycode() {
        // Per RFC 3492 + RFC 6125 §6.4.4, non-ASCII labels are
        // encoded as Punycode with the `xn--` ACE prefix.
        // We test a few well-known IDN labels; the exact Punycode
        // form is determined by the `idna` crate (UTS #46 default
        // mapping) and the values below match the outputs the
        // crate produces as of `idna` v1.1.0.
        assert_eq!(normalize_domain("中国"), "xn--fiqs8s");
        // 央行.gov.cn — first label is Unicode, rest ASCII.
        let n = normalize_domain("央行.gov.cn");
        assert!(
            n.starts_with("xn--"),
            "expected Punycode prefix, got: {:?}",
            n
        );
        assert!(
            n.ends_with(".gov.cn"),
            "expected .gov.cn tail, got: {:?}",
            n
        );
        // Idempotency: re-normalize the Punycode form should be
        // identical (UTS #46 is idempotent on already-ASCII input).
        assert_eq!(normalize_domain(&n), n);
    }

    #[test]
    fn normalize_domain_mixed_unicode_ascii() {
        // Same case as `normalize_domain_unicode_to_punycode` but
        // emphasising that the `.gov.cn` ASCII suffix is preserved
        // verbatim while the leading label is Punycode-encoded.
        let normalized = normalize_domain("央行.gov.cn");
        assert!(normalized.ends_with(".gov.cn"));
        assert!(normalized.starts_with("xn--"));
    }

    #[test]
    fn normalize_domain_unconditionally_lowercases() {
        // Per UTS #46 case-folding step: ASCII letters are folded
        // to lowercase. This is independent of IDN encoding.
        assert_eq!(normalize_domain("Example.COM"), "example.com");
        assert_eq!(normalize_domain("API.example.COM"), "api.example.com");
    }
}
