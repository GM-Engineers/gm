//! RSA CA signer — X.509 certificates with RSA SPKI + sha256WithRSAEncryption.
//!
//! Required by the TLCP RSA cipher suites ([GB/T 38636-2020] §6.4.5.2.1
//! 表 2 — `TLS_RSA_WITH_*`: E019/E01C/E059/E05A), where the certificate
//! chain must use RSA keys (国密 TLS retains RSA as a legacy bridge
//! because some PKIs still issue RSA certs). Note that the *handshake*
//! signatures for those suites are still SM3+RSA-PKCS#1-v1_5 — handled
//! by [`gm_tlcp::rsa_helpers`] (R-5 plan §8); this module only owns
//! the X.509 certificate surface.
//!
//! [`gm_tlcp::rsa_helpers`]: ../gm_tlcp_src_path
//!
//! ## Why sha256WithRSAEncryption (not sm3WithRSAEncryption) for the cert?
//!
//! X.509 certificate signatures live outside the TLCP/SM3 sphere: the
//! chain is consumed by general-purpose X.509 verifiers (GmSSL master,
//! openHiTLS, OpenSSL, etc.), all of which expect
//! `sha256WithRSAEncryption` (1.2.840.113549.1.1.11) for an RSA cert.
//! `sm3WithRSAEncryption` (1.2.156.10197.1.502) is GM/T-internal and
//! reserved for the *handshake* path, not the cert path. So we hash the
//! TBSCertificate with SHA-256 and sign with RSA-PKCS#1-v1_5 — exactly
//! what an OpenSSL-issued RSA cert would look like.
//!
//! ## SKI/AKI key-id derivation
//!
//! RFC 7093 §2 Method 1 says "hash the BIT STRING subjectPublicKey
//! *value*" with SHA-1 for interop with the global PKI (X.509 SKI/AKI
//! has used SHA-1 since RFC 5280 days). For SM2 we use `SM3[:20]`
//! (a GM/T convention). For RSA we use `SHA-1` here so the certs we
//! produce are wire-compatible with GmSSL/openHiTLS RSA chains.
//!
//! ## Feature flag
//!
//! This module is gated behind the `rsa` feature (off by default) so
//! the default GM/CA build stays strictly SM2 + 国密.
//!
//! [GB/T 38636-2020]: https://openstd.samr.gov.cn/

use crate::cert::{build_certificate_der, build_extensions, build_tbs_certificate};
use crate::cert_profile::{CertProfile, GeneralName};
use crate::error::CaError;
use gm_der::{der_sequence, der_set, der_utf8_string, encode_oid};
use rand::Rng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;

// rsaEncryption OID: 1.2.840.113549.1.1.1 = 2A 86 48 86 F7 0D 01 01 01
// (RFC 4055 / RFC 8017 §8 — public-key algorithm for RSA)
const RSA_ENCRYPTION_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
// sha256WithRSAEncryption OID: 1.2.840.113549.1.1.11 = 2A 86 48 86 F7 0D 01 01 0B
// (RFC 4055 §1.2 — signature algorithm for RSA over SHA-256)
const SHA256_RSA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
// CN OID: 2.5.4.3 = 55 04 03
const CN_OID: &[u8] = &[0x55, 0x04, 0x03];

// ---------------------------------------------------------------------------
// Algorithm-agnostic primitives the RSA path needs
// ---------------------------------------------------------------------------

/// SHA-1(data) — 20 bytes.
///
/// Used for RFC 7093 §2 Method 1 SKI/AKI derivation for RSA certs
/// (must match GmSSL / openHiTLS RSA chain behavior for cross-stack
/// interop).
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

/// SHA-256(data) — 32 bytes.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// AlgorithmIdentifier for the SPKI of an RSA public key:
///
///   SEQUENCE { OID(rsaEncryption), NULL }
///
/// The `NULL` parameter is mandatory per RFC 8017 §A.1 / RFC 4055 §1.1
/// (subject to debate for `rsaEncryption` vs `RSASSA-PSS`, but GmSSL
/// / openHiTLS all emit NULL).
fn rsa_spki_alg_id() -> Vec<u8> {
    der_sequence(&[encode_oid(RSA_ENCRYPTION_OID), vec![0x05, 0x00]].concat())
}

/// AlgorithmIdentifier for the cert's outer signature:
///
///   SEQUENCE { OID(sha256WithRSAEncryption), NULL }
fn rsa_sig_alg_id() -> Vec<u8> {
    der_sequence(&[encode_oid(SHA256_RSA_OID), vec![0x05, 0x00]].concat())
}

/// Encode the RSA public key as PKCS#1 `RSAPublicKey` DER:
///
///   SEQUENCE { INTEGER n, INTEGER e }
///
/// This is the BIT STRING *value* of the SPKI for an RSA cert
/// (RFC 4055 §1.1 — `RSAPublicKey ::= SEQUENCE { modulus INTEGER,
/// publicExponent INTEGER }`).
fn pkcs1_pubkey_der(key_pair: &RsaPrivateKey) -> Vec<u8> {
    let pubkey = RsaPublicKey::new(key_pair.n().clone(), key_pair.e().clone())
        .expect("RSA pubkey extraction from a valid private key cannot fail");
    let der = pubkey
        .to_pkcs1_der()
        .expect("PKCS#1 RSAPublicKey DER encoding of a valid key cannot fail");
    der.as_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// RsaCaSigner
// ---------------------------------------------------------------------------

/// X.509 CA signer backed by an RSA private key.
///
/// Mirrors [`crate::cert::CaSigner`] (SM2) 1-for-1. Both expose:
///   * `self_sign_ca(validity_days, profile)` — root CA
///   * `sign_csr_with_profile(csr_input, validity_days, profile)` — issue leaf
///   * `renew_certificate_with_profile(existing_cert_pem, validity_days, profile)`
///
/// The only surface differences are:
///   * SPKI uses `rsaEncryption` (1.2.840.113549.1.1.1) instead of
///     the SM2 OID.
///   * Cert signatures use `sha256WithRSAEncryption`
///     (1.2.840.113549.1.1.11) instead of `sm3WithSM2`.
///   * SKI/AKI key-id derivation uses SHA-1 instead of SM3 (so the
///     produced chain interoperates with GmSSL / openHiTLS).
///
/// `ca_pubkey_pkcs1` is cached on `new()` so AKI computation doesn't
/// re-encode the public key on every `sign_csr_with_profile` /
/// `self_sign_ca` call.
#[derive(Clone)]
pub struct RsaCaSigner {
    key_pair: RsaPrivateKey,
    ca_subject_cn: String,
    /// PKCS#1 RSAPublicKey DER bytes (`SEQUENCE { INTEGER n, INTEGER e }`).
    /// This is the BIT STRING *value* of the CA's SPKI.
    ca_pubkey_pkcs1: Vec<u8>,
}

impl RsaCaSigner {
    /// Create an `RsaCaSigner` from an in-memory RSA private key.
    pub fn new(key_pair: RsaPrivateKey, ca_subject_cn: &str) -> Self {
        let ca_pubkey_pkcs1 = pkcs1_pubkey_der(&key_pair);
        Self {
            key_pair,
            ca_subject_cn: ca_subject_cn.to_string(),
            ca_pubkey_pkcs1,
        }
    }

    /// Create an `RsaCaSigner` from a PKCS#8 PEM-encoded RSA private key
    /// (the modern format produced by `openssl genpkey` / `gmssl keypair`).
    pub fn from_pkcs8_pem(pem_str: &str, ca_subject_cn: &str) -> Result<Self, CaError> {
        let key_pair = RsaPrivateKey::from_pkcs8_pem(pem_str)
            .map_err(|e| CaError::SigningFailed(format!("RSA PKCS#8 PEM parse failed: {}", e)))?;
        Ok(Self::new(key_pair, ca_subject_cn))
    }

    /// Borrow the CA subject CN.
    pub fn ca_subject_cn(&self) -> &str {
        &self.ca_subject_cn
    }

    /// Borrow the PKCS#1 RSAPublicKey DER (the SPKI BIT STRING value).
    /// Useful for chain construction in non-CA-signed scenarios.
    pub fn ca_public_key_pkcs1(&self) -> &[u8] {
        &self.ca_pubkey_pkcs1
    }

    /// Borrow the inner RSA private key.
    pub fn key_pair(&self) -> &RsaPrivateKey {
        &self.key_pair
    }

    // -----------------------------------------------------------------------
    // self_sign_ca
    // -----------------------------------------------------------------------

    /// Self-sign the CA certificate using the CA's own RSA key.
    ///
    /// The resulting certificate is the trust anchor for any chain
    /// `sign_csr_with_profile` issues. To reproduce a standard RSA
    /// root-CA cert (KeyUsage keyCertSign | cRLSign, BasicConstraints
    /// CA:TRUE), pass [`CertProfile::root_ca`].
    ///
    /// Returns the PEM-encoded self-signed cert.
    pub fn self_sign_ca(
        &self,
        validity_days: i64,
        profile: &CertProfile,
    ) -> Result<String, CaError> {
        if validity_days <= 0 || validity_days > 3650 {
            return Err(CaError::InvalidArgument(format!(
                "validity_days must be 1-3650, got {}",
                validity_days
            )));
        }

        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + std::time::Duration::from_secs(86400 * validity_days as u64);

        // Random 20-byte positive serial number.
        let mut serial_bytes = [0u8; 20];
        rand::rng().fill_bytes(&mut serial_bytes);
        serial_bytes[0] &= 0x7F;

        // Issuer == Subject for self-signed root.
        let subject_der = der_name(self.ca_subject_cn.as_bytes());

        // Algorithm-specific identifiers and key-id derivation.
        let sig_alg_id = rsa_sig_alg_id();
        let spki_alg_id = rsa_spki_alg_id();
        let subject_key_id = sha1(&self.ca_pubkey_pkcs1);
        let ca_key_id = subject_key_id; // self-signed

        let extensions = Some(build_extensions(&subject_key_id, &ca_key_id, &[], profile));

        let tbs_der = build_tbs_certificate(
            &serial_bytes,
            not_before,
            not_after,
            self.ca_subject_cn.as_bytes(),
            &subject_der,
            sig_alg_id.clone(),
            spki_alg_id,
            self.ca_pubkey_pkcs1.clone(),
            extensions,
        )?;

        let signature = rsa_sign_tbs(&self.key_pair, &tbs_der)?;
        let cert_der = build_certificate_der(&tbs_der, sig_alg_id, &signature);
        let pem_obj = pem::Pem::new("CERTIFICATE", cert_der);
        Ok(pem::encode(&pem_obj))
    }

    // -----------------------------------------------------------------------
    // sign_csr_with_profile
    // -----------------------------------------------------------------------

    /// Sign an RSA CSR and return `(serial_hex, cert_pem)`.
    ///
    /// The CSR's SPKI must use `rsaEncryption` (1.2.840.113549.1.1.1).
    /// SM2-signed CSRs are rejected (mixing SM2 CSR with RSA-issued cert
    /// would embed an SM2 pubkey in an RSA cert — silent algorithm
    /// mismatch that's catastrophic for verifiers).
    ///
    /// The CSR's signature is verified before issuing, so the requester
    /// must own the corresponding private key.
    ///
    /// The certificate extensions are taken from `profile`. To reproduce a
    /// standard RSA end-entity cert (digitalSignature, keyEncipherment,
    /// serverAuth, clientAuth, SKI, SAN, BasicConstraints CA:FALSE), pass
    /// [`CertProfile::default`].
    pub fn sign_csr_with_profile(
        &self,
        csr_input: &[u8],
        validity_days: i64,
        profile: &CertProfile,
    ) -> Result<(String, String), CaError> {
        if validity_days <= 0 || validity_days > 3650 {
            return Err(CaError::InvalidArgument(format!(
                "validity_days must be 1-3650, got {}",
                validity_days
            )));
        }

        let csr_der = decode_csr(csr_input)?;
        let (_, csr) = X509CertificationRequest::from_der(&csr_der)
            .map_err(|e| CaError::InvalidCsr(format!("CSR parse failed: {}", e)))?;

        let csr_info = &csr.certification_request_info;

        // Subject DN raw DER bytes from CSR (for embedding in certificate).
        let subject_der = csr_info.subject.as_raw();

        // Extract subject public key bytes (BIT STRING value of SPKI =
        // PKCS#1 RSAPublicKey DER) and the SPKI algorithm OID.
        let subject_pubkey_pkcs1 = &csr_info.subject_pki.subject_public_key.data;
        let spki_algorithm_oid = csr_info.subject_pki.algorithm.algorithm.as_bytes();

        // Reject non-RSA CSRs up front.
        if spki_algorithm_oid != RSA_ENCRYPTION_OID {
            return Err(CaError::InvalidCsr(format!(
                "CSR public key must use rsaEncryption OID (1.2.840.113549.1.1.1), got OID {}",
                hex::encode(spki_algorithm_oid)
            )));
        }

        // Verify CSR signature to prove requester owns the private key.
        // Build a VerifyingKey from the CSR's SPKI pubkey and verify with
        // sha256WithRSAEncryption. We don't trust the CSR's claim about
        // its own signature algorithm — we look at the embedded public
        // key, hash the CertificationRequestInfo DER ourselves, and
        // verify with PKCS#1 v1.5 / SHA-256. This is what RFC 2986
        // §4.2 prescribes for the SHA-256-with-RSA case.
        let verifying_key = VerifyingKey::<RsaSha256>::new(csr_rsa_pubkey(csr_info)?);
        let sig_bytes = csr.signature_value.data.as_ref();
        let sig = Signature::try_from(sig_bytes)
            .map_err(|e| CaError::InvalidCsr(format!("CSR signature length invalid: {}", e)))?;
        let csr_info_bytes = csr.certification_request_info.raw;
        let prehash = sha256(csr_info_bytes);
        verifying_key.verify_prehash(&prehash, &sig).map_err(|e| {
            CaError::InvalidCsr(format!(
                "CSR signature verification failed (sha256WithRSAEncryption): {}",
                e
            ))
        })?;

        // Validity period
        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + std::time::Duration::from_secs(86400 * validity_days as u64);

        // Random 20-byte positive serial number.
        let mut serial_bytes = [0u8; 20];
        rand::rng().fill_bytes(&mut serial_bytes);
        serial_bytes[0] &= 0x7F;

        // Build end-entity extensions per profile. SAN: take the first
        // DNS entry from the profile if any, otherwise fall back to
        // the CSR's subject CN.
        let sans: Vec<GeneralName> = if !profile.sans.is_empty() {
            profile.sans.clone()
        } else {
            let cn = extract_csr_subject_cn(csr_input).unwrap_or_default();
            if cn.is_empty() {
                Vec::new()
            } else {
                vec![GeneralName::DnsName(cn)]
            }
        };
        let extensions = if sans.is_empty() && !profile.include_basic_constraints {
            None
        } else {
            // RSA key-id derivation: SHA-1(PKCS#1 RSAPublicKey DER)[:20].
            let subject_key_id = sha1(subject_pubkey_pkcs1);
            let ca_key_id = sha1(&self.ca_pubkey_pkcs1);
            Some(build_extensions(
                &subject_key_id,
                &ca_key_id,
                &sans,
                profile,
            ))
        };

        let tbs_der = build_tbs_certificate(
            &serial_bytes,
            not_before,
            not_after,
            self.ca_subject_cn.as_bytes(),
            subject_der,
            rsa_sig_alg_id(),
            rsa_spki_alg_id(),
            subject_pubkey_pkcs1.to_vec(),
            extensions,
        )?;

        let signature = rsa_sign_tbs(&self.key_pair, &tbs_der)?;

        let cert_der = build_certificate_der(&tbs_der, rsa_sig_alg_id(), &signature);

        let pem_obj = pem::Pem::new("CERTIFICATE", cert_der);
        let pem_str = pem::encode(&pem_obj);

        let serial_hex = hex::encode(serial_bytes);
        Ok((serial_hex, pem_str))
    }

    // -----------------------------------------------------------------------
    // renew_certificate_with_profile
    // -----------------------------------------------------------------------

    /// Renew an existing certificate: issue a new certificate with the
    /// same subject and public key but a new validity period and serial
    /// number. The existing cert's SPKI algorithm must be RSA.
    ///
    /// Extensions are rebuilt per `profile`; the existing cert's SAN
    /// DNS name is carried over (matches the SM2 CaSigner behavior).
    pub fn renew_certificate_with_profile(
        &self,
        existing_cert_pem: &str,
        validity_days: i64,
        profile: &CertProfile,
    ) -> Result<String, CaError> {
        if validity_days <= 0 || validity_days > 3650 {
            return Err(CaError::InvalidArgument(format!(
                "validity_days must be 1-3650, got {}",
                validity_days
            )));
        }
        use gm_crypto::x509::parse_cert_pem;

        let cert_info = parse_cert_pem(existing_cert_pem)
            .map_err(|e| CaError::InvalidCertificate(format!("certificate parse failed: {}", e)))?;

        let now = time::OffsetDateTime::now_utc();
        if now > cert_info.not_after {
            return Err(CaError::InvalidCertificate(
                "cannot renew an expired certificate".to_string(),
            ));
        }

        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + std::time::Duration::from_secs(86400 * validity_days as u64);

        let mut serial_bytes = [0u8; 20];
        rand::rng().fill_bytes(&mut serial_bytes);
        serial_bytes[0] &= 0x7F;

        let sans: Vec<GeneralName> = if !profile.sans.is_empty() {
            profile.sans.clone()
        } else if let Some(cn) = &cert_info.san_dns_name {
            vec![GeneralName::DnsName(cn.clone())]
        } else {
            Vec::new()
        };
        let extensions = if sans.is_empty() && !profile.include_basic_constraints {
            None
        } else {
            let subject_key_id = sha1(&cert_info.spki_bytes);
            let ca_key_id = sha1(&self.ca_pubkey_pkcs1);
            Some(build_extensions(
                &subject_key_id,
                &ca_key_id,
                &sans,
                profile,
            ))
        };

        let tbs_der = build_tbs_certificate(
            &serial_bytes,
            not_before,
            not_after,
            self.ca_subject_cn.as_bytes(),
            &cert_info.subject_der,
            rsa_sig_alg_id(),
            rsa_spki_alg_id(),
            cert_info.spki_bytes.clone(),
            extensions,
        )?;

        let signature = rsa_sign_tbs(&self.key_pair, &tbs_der)?;
        let cert_der = build_certificate_der(&tbs_der, rsa_sig_alg_id(), &signature);
        let pem_obj = pem::Pem::new("CERTIFICATE", cert_der);
        Ok(pem::encode(&pem_obj))
    }
}

// ---------------------------------------------------------------------------
// Free functions — mirroring the SM2 path's PEM/DER helpers
// ---------------------------------------------------------------------------

/// Decode CSR from PEM or raw DER. Mirrors the SM2 CaSigner.
fn decode_csr(csr_input: &[u8]) -> Result<Vec<u8>, CaError> {
    if let Ok(pem_obj) = pem::parse(csr_input)
        && pem_obj.tag() == "CERTIFICATE REQUEST"
    {
        return Ok(pem_obj.contents().to_vec());
    }
    if X509CertificationRequest::from_der(csr_input).is_ok() {
        return Ok(csr_input.to_vec());
    }
    Err(CaError::InvalidCsr(
        "Invalid CSR format: expected PEM or DER".to_string(),
    ))
}

/// Extract the Common Name (CN) from a CSR's subject. Mirrors the
/// SM2 CaSigner; here we only pull the string form.
fn extract_csr_subject_cn(csr_input: &[u8]) -> Result<String, CaError> {
    let csr_der = decode_csr(csr_input)?;
    let (_, csr) = X509CertificationRequest::from_der(&csr_der)
        .map_err(|e| CaError::InvalidCsr(format!("CSR parse failed: {}", e)))?;
    let subject_str = csr.certification_request_info.subject.to_string();
    let trimmed = subject_str.trim();
    if !trimmed.is_empty() && trimmed != "(empty)" {
        if let Some(cn_part) = trimmed.split(',').next() {
            let cn = cn_part.trim_start_matches("CN=").trim();
            if !cn.is_empty() {
                return Ok(cn.to_string());
            }
        }
        return Ok(trimmed.to_string());
    }
    Ok(format!(
        "csr_{}",
        hex::encode(csr.certification_request_info.subject.as_raw())
    ))
}

/// Build an `RsaPublicKey` from the CSR's embedded SubjectPublicKeyInfo.
/// We use x509-parser's parsed public-key API to lift the modulus /
/// exponent out of the BIT STRING value (which is PKCS#1 RSAPublicKey
/// DER per RFC 4055 §1.1).
fn csr_rsa_pubkey(
    csr_info: &x509_parser::certification_request::X509CertificationRequestInfo,
) -> Result<RsaPublicKey, CaError> {
    let parsed = csr_info
        .subject_pki
        .parsed()
        .map_err(|e| CaError::InvalidCsr(format!("CSR SPKI parse failed: {}", e)))?;
    match parsed {
        PublicKey::RSA(rsa_pk) => {
            // x509-parser exposes the modulus/exponent as raw byte
            // slices (with a possible leading 0 if MSB is 1, which
            // BigUint::from_bytes_be handles correctly).
            let n = rsa::BigUint::from_bytes_be(rsa_pk.modulus);
            let e = rsa::BigUint::from_bytes_be(rsa_pk.exponent);
            RsaPublicKey::new(n, e)
                .map_err(|e| CaError::InvalidCsr(format!("CSR SPKI RSA components invalid: {}", e)))
        }
        _ => Err(CaError::InvalidCsr(
            "CSR SPKI is not RSA (expected rsaEncryption 1.2.840.113549.1.1.1)".to_string(),
        )),
    }
}

/// Sign the TBSCertificate DER with sha256WithRSAEncryption.
///
/// We hash the TBS with SHA-256 ourselves and call `sign_prehash` so we
/// don't pull in rsa 0.9's `digest` 0.11 wrapper (gm-crypto's transitive
/// `sm3 0.5` is on `digest 0.10`; mixing both is the version-conflict
/// trap R-5 documented for gm-tlcp).
fn rsa_sign_tbs(key_pair: &RsaPrivateKey, tbs_der: &[u8]) -> Result<Vec<u8>, CaError> {
    let prehash = sha256(tbs_der);
    let signing_key = SigningKey::<RsaSha256>::new(key_pair.clone());
    let sig = signing_key
        .sign_prehash(&prehash)
        .map_err(|e| CaError::SigningFailed(format!("RSA cert signature failed: {}", e)))?;
    Ok(sig.to_vec())
}

/// Build a DER-encoded Name (CN-only) — mirrors the SM2 path's
/// `der_name`. Used only when we have to synthesise a subject DN; the
/// sign_csr / renew paths reuse the CSR's existing subject_der instead.
#[allow(dead_code)]
fn der_name(cn: &[u8]) -> Vec<u8> {
    let oid = encode_oid(CN_OID);
    let atv = der_sequence(&[oid, der_utf8_string(cn)].concat());
    let set = der_set(&[atv]);
    der_sequence(&[set].concat())
}

// ---------------------------------------------------------------------------
// Tests — wire-format smoke checks for the new RSA CA signer.
//
// These tests round-trip the produced PEM through x509-parser to verify
// gm-tls / gm-tlcp will accept the certs.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use gm_der::{der_bit_string, der_integer_positive, der_sequence_v};
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::prelude::{FromDer, X509Certificate};

    const KEY_USAGE_OID: &[u8] = &[0x55, 0x1D, 0x0F];
    const SUBJECT_KEY_ID_OID: &[u8] = &[0x55, 0x1D, 0x0E];
    const AUTHORITY_KEY_ID_OID: &[u8] = &[0x55, 0x1D, 0x23];
    const BASIC_CONSTRAINTS_OID: &[u8] = &[0x55, 0x1D, 0x13];
    const SUBJECT_ALT_NAME_OID: &[u8] = &[0x55, 0x1D, 0x11];

    fn parse_cert_der<'a>(der_bytes: &'a [u8]) -> X509Certificate<'a> {
        let (_, cert) = X509Certificate::from_der(der_bytes).expect("DER parse");
        cert
    }

    fn find_ext<'a, 'b>(
        cert: &'a X509Certificate<'b>,
        oid: &[u8],
    ) -> Option<&'a x509_parser::extensions::X509Extension<'b>> {
        cert.extensions().iter().find(|e| e.oid.as_bytes() == oid)
    }

    fn make_rsa_signer(cn: &str) -> (RsaCaSigner, RsaPrivateKey) {
        let mut rng = rsa::rand_core::OsRng;
        let kp = RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen 2048");
        let signer = RsaCaSigner::new(kp.clone(), cn);
        (signer, kp)
    }

    #[test]
    fn from_pkcs8_pem_roundtrips_keypair() {
        let (signer_a, kp_a) = make_rsa_signer("Test PKCS#8 Roundtrip CA");
        let pem = rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&kp_a, rsa::pkcs8::LineEnding::LF)
            .expect("encode PKCS#8 PEM");
        let pem_str = std::str::from_utf8(pem.as_bytes()).expect("PEM is UTF-8");

        let signer_b = RsaCaSigner::from_pkcs8_pem(pem_str, "Test PKCS#8 Roundtrip CA")
            .expect("from_pkcs8_pem");
        assert_eq!(signer_a.ca_subject_cn(), signer_b.ca_subject_cn());
        assert_eq!(
            signer_a.ca_public_key_pkcs1(),
            signer_b.ca_public_key_pkcs1(),
            "PKCS#1 RSAPublicKey must round-trip through PKCS#8 PEM"
        );
    }

    #[test]
    fn root_ca_self_signed_has_sha256_rsa_sig_and_rsa_spki() {
        let (signer, _) = make_rsa_signer("Test RSA Root CA");
        let pem_str = signer
            .self_sign_ca(365, &CertProfile::root_ca())
            .expect("self_sign_ca");

        let pem_obj = pem::parse(pem_str.as_bytes()).expect("PEM parse");
        let cert = parse_cert_der(pem_obj.contents());

        // Outer signature algorithm = sha256WithRSAEncryption
        let sig_oid = cert.signature_algorithm.algorithm.as_bytes();
        assert_eq!(
            sig_oid, SHA256_RSA_OID,
            "outer signature OID must be sha256WithRSAEncryption"
        );

        // SPKI algorithm = rsaEncryption
        let spki_oid = cert.public_key().algorithm.algorithm.as_bytes();
        assert_eq!(
            spki_oid, RSA_ENCRYPTION_OID,
            "SPKI OID must be rsaEncryption"
        );

        // BC: CA:TRUE, critical
        let bc = find_ext(&cert, BASIC_CONSTRAINTS_OID).expect("BC present");
        assert!(bc.critical, "BC must be critical when CA:TRUE");
        match bc.parsed_extension() {
            ParsedExtension::BasicConstraints(bc_inner) => {
                assert!(bc_inner.ca, "CA must be TRUE for root");
                assert!(
                    bc_inner.path_len_constraint.is_none(),
                    "no pathLenConstraint on root_ca() profile"
                );
            }
            other => panic!("expected BC, got {:?}", other),
        }

        // KU: keyCertSign | cRLSign (same bit positions as SM2)
        let ku = find_ext(&cert, KEY_USAGE_OID).expect("KU present");
        assert!(ku.critical);
        assert_eq!(ku.value[1], 0x06, "KU bits must be keyCertSign|cRLSign");

        // SKI = SHA-1(CA PKCS#1 RSAPublicKey)[:20]
        let ski = find_ext(&cert, SUBJECT_KEY_ID_OID).expect("SKI present");
        let expected_ski = sha1(signer.ca_public_key_pkcs1());
        assert_eq!(
            &ski.value[2..],
            &expected_ski[..],
            "SKI must match SHA-1 hash"
        );

        // AKI = SHA-1(CA PKCS#1 RSAPublicKey)[:20] (self-signed, AKI == SKI)
        let aki = find_ext(&cert, AUTHORITY_KEY_ID_OID).expect("AKI present");
        let found = aki.value.windows(20).any(|w| w == &expected_ski[..]);
        assert!(found, "AKI keyIdentifier must equal SKI (self-signed root)");
    }

    #[test]
    fn end_entity_default_profile_is_signed_by_rsa_ca() {
        // Root CA
        let (ca_signer, _) = make_rsa_signer("Test RSA CA");

        // Generate leaf RSA keypair via a separate signer (so we get
        // a fresh keypair) — and we use `sign_csr_with_profile` against
        // an RSA CSR. The CSR signature is sha256WithRSAEncryption
        // (matches what gmssl/openssl produce for RSA CSRs).
        let mut rng = rsa::rand_core::OsRng;
        let leaf_kp = RsaPrivateKey::new(&mut rng, 2048).expect("leaf keygen");
        let leaf_pkcs1 = pkcs1_pubkey_der(&leaf_kp);

        // Build a minimal RSA PKCS#10 CSR by hand:
        //   SEQUENCE {
        //     SEQUENCE { INTEGER 0, subject Name, SPKI, [0] attributes }
        //     SEQUENCE { sig_alg }
        //     BIT STRING { sig }
        //   }
        // For the test, the most important thing is that the CSR
        // signature verifies and the SPKI algorithm is rsaEncryption.
        let subject_cn = "leaf.example.com";
        let csr_pem = build_test_rsa_csr_pem(subject_cn, &leaf_kp);

        let (_, cert_pem) = ca_signer
            .sign_csr_with_profile(csr_pem.as_bytes(), 365, &CertProfile::default())
            .expect("sign_csr_with_profile");

        let pem_obj = pem::parse(cert_pem.as_bytes()).expect("PEM parse");
        let cert = parse_cert_der(pem_obj.contents());

        // Sig OID
        assert_eq!(
            cert.signature_algorithm.algorithm.as_bytes(),
            SHA256_RSA_OID
        );
        // SPKI OID
        assert_eq!(
            cert.public_key().algorithm.algorithm.as_bytes(),
            RSA_ENCRYPTION_OID
        );

        // SPKI BIT STRING content = the leaf's PKCS#1 RSAPublicKey DER
        let spki_value = cert.public_key().subject_public_key.data.as_ref();
        assert_eq!(
            spki_value,
            &leaf_pkcs1[..],
            "SPKI BIT STRING value must equal the leaf's PKCS#1 RSAPublicKey DER"
        );

        // BC: CA:FALSE
        let bc = find_ext(&cert, BASIC_CONSTRAINTS_OID).expect("BC present");
        match bc.parsed_extension() {
            ParsedExtension::BasicConstraints(bc_inner) => {
                assert!(!bc_inner.ca, "CA must be FALSE for end-entity");
            }
            other => panic!("expected BC, got {:?}", other),
        }

        // KU: digitalSignature(0) | keyEncipherment(2) = 0xA0
        let ku = find_ext(&cert, KEY_USAGE_OID).expect("KU present");
        assert_eq!(
            ku.value[1], 0xA0,
            "KU bits must be digitalSignature|keyEncipherment"
        );

        // AKI must key on the CA's pubkey (NOT the leaf's)
        let aki = find_ext(&cert, AUTHORITY_KEY_ID_OID).expect("AKI present");
        let expected_aki = sha1(ca_signer.ca_public_key_pkcs1());
        let found = aki.value.windows(20).any(|w| w == &expected_aki[..]);
        assert!(
            found,
            "AKI keyIdentifier must equal SHA-1(CA pubkey)[:20] — NOT the subject's"
        );

        // SAN
        let san = find_ext(&cert, SUBJECT_ALT_NAME_OID).expect("SAN present");
        assert!(
            san.value.windows(16).any(|w| w == b"leaf.example.com"),
            "SAN must contain dNSName leaf.example.com"
        );
    }

    #[test]
    fn sign_csr_rejects_sm2_signed_csr() {
        let (ca_signer, _) = make_rsa_signer("Test RSA CA");
        let leaf_key = gm_crypto::sm2::Sm2KeyPair::generate().expect("SM2 keygen");
        let leaf_pub_65 = leaf_key.public_key_bytes_uncompressed();
        let sm2_csr = gm_crypto::x509::CsrBuilder::new_sm2("sm2.leaf.example.com", &leaf_pub_65)
            .expect("CsrBuilder::new_sm2")
            .build_pem(&leaf_key)
            .expect("CsrBuilder::build_pem");

        let result =
            ca_signer.sign_csr_with_profile(sm2_csr.as_bytes(), 365, &CertProfile::default());
        assert!(
            result.is_err(),
            "RsaCaSigner must reject SM2-signed CSRs (would produce algorithm-mismatch cert)"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("rsaEncryption") || err.contains("RSA"),
            "error must explain that CSR must use rsaEncryption, got: {}",
            err
        );
    }

    #[test]
    fn renew_rsa_certificate_keeps_subject_pubkey() {
        let (ca_signer, _) = make_rsa_signer("Test RSA CA");
        let mut rng = rsa::rand_core::OsRng;
        let leaf_kp = RsaPrivateKey::new(&mut rng, 2048).expect("leaf keygen");
        let leaf_pkcs1 = pkcs1_pubkey_der(&leaf_kp);

        let csr_pem = build_test_rsa_csr_pem("renew.example.com", &leaf_kp);
        let (_, original_cert_pem) = ca_signer
            .sign_csr_with_profile(csr_pem.as_bytes(), 365, &CertProfile::default())
            .expect("initial issue");

        let renewed_pem = ca_signer
            .renew_certificate_with_profile(&original_cert_pem, 180, &CertProfile::default())
            .expect("renew");

        let pem_obj = pem::parse(renewed_pem.as_bytes()).expect("PEM parse");
        let cert = parse_cert_der(pem_obj.contents());

        // Same SPKI BIT STRING content (subject's key didn't change).
        let spki_value = cert.public_key().subject_public_key.data.as_ref();
        assert_eq!(
            spki_value,
            &leaf_pkcs1[..],
            "renew must keep the subject pubkey"
        );

        // Same CA (issuer == CA subject CN)
        let ca_cn_attr = cert.tbs_certificate.issuer.to_string();
        assert!(
            ca_cn_attr.contains("Test RSA CA"),
            "issuer must still be the CA, got: {}",
            ca_cn_attr
        );
    }

    /// Build a minimal RSA PKCS#10 CSR (PEM-encoded) signed with
    /// sha256WithRSAEncryption. This is what `openssl req -newkey rsa
    /// ...` / `gmssl x509req ...` would produce — the same shape is
    /// what `RsaCaSigner::sign_csr_with_profile` parses.
    fn build_test_rsa_csr_pem(subject_cn: &str, key_pair: &RsaPrivateKey) -> String {
        // Build CertificationRequestInfo DER
        let version = der_integer_positive(&[0x00]); // INTEGER 0
        let subject = der_name(subject_cn.as_bytes());

        // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING(PKCS#1 RSAPublicKey) }
        let pubkey_pkcs1 = pkcs1_pubkey_der(key_pair);
        let spki = der_sequence(&[rsa_spki_alg_id(), der_bit_string(&pubkey_pkcs1)].concat());

        // [0] IMPLICIT Attributes — empty (no extensionRequest etc).
        // RFC 2986 §4.1: `attributes [0] IMPLICIT SET OF Attribute`.
        // For empty attributes the DER is `A0 00` (context-specific tag 0,
        // length 0) — the IMPLICIT keyword hides the SET OF tag.
        let attributes: Vec<u8> = vec![0xA0, 0x00];

        let cri = der_sequence_v(&[version, subject, spki, attributes]);
        // Sign CRI with sha256WithRSAEncryption
        let prehash = sha256(&cri);
        let signing_key = SigningKey::<RsaSha256>::new(key_pair.clone());
        let sig = signing_key.sign_prehash(&prehash).expect("CSR sign");

        let sig_alg = rsa_sig_alg_id();
        let sig_bits = der_bit_string(&sig.to_vec());
        let csr = der_sequence(&[cri, sig_alg, sig_bits].concat());

        let pem_obj = pem::Pem::new("CERTIFICATE REQUEST", csr);
        pem::encode(&pem_obj)
    }
}
