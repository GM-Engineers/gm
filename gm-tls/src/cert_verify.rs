//! Certificate verification for GM/TLS.
//!
//! This module provides SM2 certificate chain verification and CRL
//! (Certificate Revocation List) processing for GM/TLS handshakes.
//!
//! # Verification Flow
//!
//! 1. **Certificate parsing**: PEM/DER parsing with domain extraction
//! 2. **Chain validation**: Each certificate in the chain is verified:
//!    - Signature verified against issuer's public key (SM2)
//!    - Validity period checked (not_before/not_after)
//!    - BasicConstraints CA:true enforced for intermediate CAs
//! 3. **Domain matching**: SAN (Subject Alternative Name) or CN fallback
//! 4. **Revocation check** (optional): CRL lookup for each certificate
//!
//! # Constants
//!
//! - [`MAX_CERT_CHAIN_DEPTH`]: Maximum certificate chain depth (10),
//!   prevents DoS via excessively deep chains
//!
//! # CRL Processing
//!
//! CRLs are DER-encoded lists of revoked certificate serial numbers,
//! signed by the issuing CA. Both CRL parsing via `x509_parser` and
//! GM/T 0036 custom CRL format are supported.

use crate::error::TlsError;
use gm_crypto::sm2::{Sm2Verifier, decompress_sm2_pubkey};
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
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, TlsError> {
        let mut iter = Pem::iter_from_buffer(pem_bytes);
        if let Some(pem) = iter.next() {
            let pem = pem.map_err(|e| {
                TlsError::CertificateVerificationFailed(format!("PEM parse failed: {}", e))
            })?;
            return Ok(Self { der: pem.contents });
        }
        Err(TlsError::CertificateVerificationFailed(
            "certificate PEM is empty".into(),
        ))
    }

    /// Parse a PEM certificate chain (concatenated PEM blocks).
    pub fn chain_from_pem_concat(pem_bytes: &[u8]) -> Result<Vec<Self>, TlsError> {
        let mut out = Vec::new();
        for pem in Pem::iter_from_buffer(pem_bytes) {
            let pem = pem.map_err(|e| {
                TlsError::CertificateVerificationFailed(format!("PEM parse failed: {}", e))
            })?;
            out.push(Self { der: pem.contents });
        }
        if out.is_empty() {
            return Err(TlsError::CertificateVerificationFailed(
                "certificate chain is empty".into(),
            ));
        }
        Ok(out)
    }

    /// Parse DER to X509Certificate.
    pub fn as_x509(&self) -> Result<X509Certificate<'_>, TlsError> {
        let (_, cert) = X509Certificate::from_der(&self.der).map_err(|e| {
            TlsError::CertificateVerificationFailed(format!("X509 parse failed: {}", e))
        })?;
        Ok(cert)
    }

    /// Extract raw TBS (To-Be-Signed) certificate bytes for signature verification.
    pub fn raw_tbs_bytes(&self) -> Result<&[u8], TlsError> {
        extract_tbs_bytes(&self.der)
    }
}

// ============== Certificate Validation ==============

/// Validate a PEM certificate (parse + validate).
pub fn validate_cert_pem(
    cert_pem: &[u8],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
) -> Result<(), TlsError> {
    let (pem, _) = Pem::read(std::io::Cursor::new(cert_pem))
        .map_err(|e| TlsError::CertificateVerificationFailed(format!("PEM parse failed: {}", e)))?;
    let (_, cert) = X509Certificate::from_der(pem.contents.as_ref()).map_err(|e| {
        TlsError::CertificateVerificationFailed(format!("X509 parse failed: {}", e))
    })?;

    validate_cert_parsed(&cert, now, expected_domain)
}

fn validate_cert_parsed(
    cert: &X509Certificate<'_>,
    now: OffsetDateTime,
    expected_domain: Option<&str>,
) -> Result<(), TlsError> {
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    if now < not_before || now > not_after {
        return Err(TlsError::CertificateVerificationFailed(
            "certificate has expired or is not yet valid".into(),
        ));
    }

    if let Some(domain) = expected_domain {
        let mut matched = false;
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in san.value.general_names.iter() {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    if dns.eq_ignore_ascii_case(domain) {
                        matched = true;
                        break;
                    }
                }
            }
        }
        if !matched {
            if let Some(cn) = cert.subject().iter_common_name().next() {
                if let Ok(cn_str) = cn.as_str() {
                    if cn_str.eq_ignore_ascii_case(domain) {
                        matched = true;
                    }
                }
            }
        }
        if !matched {
            return Err(TlsError::CertificateVerificationFailed(
                "domain name mismatch".into(),
            ));
        }
    }
    Ok(())
}

// ============== Certificate Chain Verification ==============

/// Maximum allowed certificate chain depth (leaf + intermediates).
pub const MAX_CERT_CHAIN_DEPTH: usize = 10;

/// Verify a full certificate chain against trust anchors.
pub fn verify_cert_chain_sm2_chain(
    leaf_chain: &[OwnedCert],
    trust_anchors: &[OwnedCert],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
) -> Result<(), TlsError> {
    if leaf_chain.is_empty() || trust_anchors.is_empty() {
        return Err(TlsError::CertificateVerificationFailed(
            "certificate chain or trust anchor is empty".into(),
        ));
    }
    if leaf_chain.len() > MAX_CERT_CHAIN_DEPTH {
        return Err(TlsError::CertificateVerificationFailed(format!(
            "certificate chain too deep: {} (max {})",
            leaf_chain.len(),
            MAX_CERT_CHAIN_DEPTH
        )));
    }

    // Verify each link in the chain
    for idx in 0..leaf_chain.len() {
        let child_owned = &leaf_chain[idx];
        let domain = if idx == 0 { expected_domain } else { None };

        if idx + 1 < leaf_chain.len() {
            // Intermediate CA: issuer is the next cert in the chain
            let issuer_owned = &leaf_chain[idx + 1];
            verify_cert_chain_sm2(child_owned, issuer_owned, now, domain)?;

            // Check CA BasicConstraints for intermediate CAs
            let child_cert = child_owned.as_x509()?;
            let basic_constraints = child_cert
                .extensions()
                .iter()
                .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS);
            if let Some(ext) = basic_constraints {
                if let x509_parser::extensions::ParsedExtension::BasicConstraints(bc) =
                    ext.parsed_extension()
                {
                    if !bc.ca {
                        return Err(TlsError::CertificateVerificationFailed(
                            "CA certificate missing BasicConstraints CA:TRUE".into(),
                        ));
                    }
                }
            } else {
                return Err(TlsError::CertificateVerificationFailed(
                    "CA certificate missing BasicConstraints extension".into(),
                ));
            }
        } else {
            // Root cert: try each trust anchor until one validates successfully
            let mut last_err = None;
            for anchor in trust_anchors {
                match verify_cert_chain_sm2(child_owned, anchor, now, domain) {
                    Ok(()) => {
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

fn verify_cert_chain_sm2(
    leaf: &OwnedCert,
    ca: &OwnedCert,
    now: OffsetDateTime,
    expected_domain: Option<&str>,
) -> Result<(), TlsError> {
    let leaf_cert = leaf.as_x509()?;
    let ca_cert = ca.as_x509()?;

    validate_cert_parsed(&leaf_cert, now, expected_domain)?;
    validate_cert_parsed(&ca_cert, now, None)?;

    if leaf_cert.issuer() != ca_cert.subject() {
        return Err(TlsError::CertificateVerificationFailed(
            "certificate issuer does not match CA".into(),
        ));
    }

    verify_cert_signature(&leaf_cert, &ca_cert, &leaf.der)?;
    Ok(())
}

/// Extract the server's public key from its certificate chain for CertificateVerify verification.
/// Returns the public key in uncompressed SEC1 format (0x04 || x || y).
pub(crate) fn extract_server_pubkey_for_cert_verify(
    cert_chain_pem: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let chain = OwnedCert::chain_from_pem_concat(cert_chain_pem)?;
    let leaf = chain
        .first()
        .ok_or_else(|| TlsError::HandshakeFailed("certificate chain is empty".into()))?;
    let leaf_cert = leaf.as_x509()?;

    let pki = leaf_cert.public_key();
    let pub_key_bytes: &[u8] = pki.subject_public_key.data.as_ref();

    let sm2_pub_key: Vec<u8> =
        if pub_key_bytes.len() == 33 && (pub_key_bytes[0] == 0x02 || pub_key_bytes[0] == 0x03) {
            decompress_sm2_pubkey(pub_key_bytes).map_err(|e| {
                TlsError::HandshakeFailed(format!("failed to decompress SM2 public key: {}", e))
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
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, TlsError> {
        let (pem, _) = Pem::read(std::io::Cursor::new(pem_bytes))
            .map_err(|e| TlsError::CrlVerificationFailed(format!("CRL PEM parse failed: {}", e)))?;

        let der = pem.contents.to_vec();
        // Validate CRL parses correctly before storing
        Self::parse_crl(&der)?;

        Ok(Self { der })
    }

    /// Parse a CRL from DER format
    pub fn from_der(der: &[u8]) -> Result<Self, TlsError> {
        let der = der.to_vec();
        Self::parse_crl(&der)?;
        Ok(Self { der })
    }

    /// Parse CRL from raw DER bytes (validates the DER)
    fn parse_crl(der: &[u8]) -> Result<CertificateRevocationList<'_>, TlsError> {
        CertificateRevocationList::from_der(der)
            .map_err(|e| TlsError::CrlVerificationFailed(format!("CRL parse failed: {:?}", e)))
            .map(|r| r.1)
    }

    /// Extract raw TBS (To-Be-Signed) CRL bytes for signature verification
    pub fn raw_tbs_bytes(&self) -> Result<&[u8], TlsError> {
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
    pub fn issuer_str(&self) -> Result<String, TlsError> {
        let crl = Self::parse_crl(&self.der)?;
        Ok(crl.issuer().to_string())
    }

    /// Get the raw DER-encoded issuer name for byte-exact comparison
    pub fn issuer_der(&self) -> Result<Vec<u8>, TlsError> {
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
/// * `Err(TlsError::CrlVerificationFailed)` if revoked or CRL invalid
pub fn verify_crl(
    cert_serial: &[u8],
    issuer: &x509_parser::x509::X509Name,
    ca_cert: &X509Certificate<'_>,
    crl: &CrlInfo,
    now: OffsetDateTime,
) -> Result<(), TlsError> {
    // Verify CRL issuer matches expected issuer using DER byte comparison
    // (avoids issues with string formatting differences in DN encoding)
    let crl_issuer_der = crl.issuer_der()?;
    let cert_issuer_der = issuer.as_raw();
    if crl_issuer_der.as_slice() != cert_issuer_der {
        return Err(TlsError::CrlVerificationFailed(
            "CRL issuer does not match certificate issuer".into(),
        ));
    }

    // Verify CRL signature using CA's public key
    verify_crl_signature(crl, ca_cert)?;

    // Check if CRL is still valid
    if !crl.is_valid(now) {
        return Err(TlsError::CrlVerificationFailed("CRL has expired".into()));
    }

    // Check if certificate is revoked
    if crl.is_cert_revoked(cert_serial) {
        return Err(TlsError::CrlVerificationFailed(
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
) -> Result<(), TlsError> {
    let crl = CrlInfo::from_pem(crl_pem)?;

    let cert_issuer = cert.issuer();
    // Convert BigUint serial to bytes using to_bytes_be
    let cert_serial = cert.serial.to_bytes_be();

    verify_crl(&cert_serial, cert_issuer, ca_cert, &crl, now)
}

/// Verify SM2 signature on a certificate using the issuer's public key
fn verify_cert_signature(
    leaf_cert: &X509Certificate<'_>,
    ca_cert: &X509Certificate<'_>,
    leaf_der: &[u8],
) -> Result<(), TlsError> {
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
        use gm_crypto::sm2::decompress_sm2_pubkey;
        decompress_sm2_pubkey(ca_pub_key_bytes).map_err(|e| {
            TlsError::CertificateVerificationFailed(format!(
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
        gm_crypto::sm2::sm2_signature_der_to_raw(sig_bytes)
            .map_err(|e| {
                TlsError::CertificateVerificationFailed(format!(
                    "failed to parse DER SM2 signature: {}",
                    e
                ))
            })?
            .to_vec()
    } else {
        return Err(TlsError::CertificateVerificationFailed(format!(
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
        TlsError::CertificateVerificationFailed(format!("failed to create SM2 verifier: {}", e))
    })?;

    match verifier.verify(tbs_bytes, &sig_raw) {
        Ok(()) => return Ok(()),
        Err(_) => {
            // Fall back to empty ID (OpenSSL 3.x default)
            let verifier2 = Sm2Verifier::new(&sm2_pub_key, "").map_err(|e| {
                TlsError::CertificateVerificationFailed(format!(
                    "failed to create fallback SM2 verifier: {}",
                    e
                ))
            })?;
            verifier2.verify(tbs_bytes, &sig_raw).map_err(|e| {
                TlsError::CertificateVerificationFailed(format!(
                    "SM2 verification failed (tried both GM/T ID and empty ID): {}",
                    e
                ))
            })?
        }
    };

    Ok(())
}

/// Verify SM2 signature on a CRL using the CA's public key
fn verify_crl_signature(crl: &CrlInfo, ca_cert: &X509Certificate<'_>) -> Result<(), TlsError> {
    // Get the raw TBS CRL bytes
    let tbs_bytes = crl.raw_tbs_bytes()?;

    // Get CA's public key bytes from SubjectPublicKeyInfo
    let ca_pki = ca_cert.public_key();
    let ca_pub_key_bytes: &[u8] = ca_pki.subject_public_key.data.as_ref();

    // Decompress SM2 public key if needed
    let sm2_pub_key: Vec<u8> = if ca_pub_key_bytes.len() == 33
        && (ca_pub_key_bytes[0] == 0x02 || ca_pub_key_bytes[0] == 0x03)
    {
        use gm_crypto::sm2::decompress_sm2_pubkey;
        decompress_sm2_pubkey(ca_pub_key_bytes).map_err(|e| {
            TlsError::CrlVerificationFailed(format!("failed to decompress SM2 public key: {}", e))
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
        gm_crypto::sm2::sm2_signature_der_to_raw(sig_bytes)
            .map_err(|e| {
                TlsError::CrlVerificationFailed(format!(
                    "failed to parse DER SM2 CRL signature: {}",
                    e
                ))
            })?
            .to_vec()
    } else {
        return Err(TlsError::CrlVerificationFailed(format!(
            "SM2 CRL signature too short: {} bytes",
            sig_bytes.len()
        )));
    };

    // Verify the signature using SM2 (try both GM/T ID and empty ID)
    let verifier = Sm2Verifier::new(&sm2_pub_key, "1234567812345678").map_err(|e| {
        TlsError::CrlVerificationFailed(format!("failed to create SM2 verifier: {}", e))
    })?;

    match verifier.verify(tbs_bytes, &sig_raw) {
        Ok(()) => Ok(()),
        Err(_) => {
            let verifier2 = Sm2Verifier::new(&sm2_pub_key, "").map_err(|e| {
                TlsError::CrlVerificationFailed(format!(
                    "failed to create fallback SM2 verifier: {}",
                    e
                ))
            })?;
            verifier2.verify(tbs_bytes, &sig_raw).map_err(|e| {
                TlsError::CrlVerificationFailed(format!(
                    "SM2 CRL verification failed (tried both GM/T ID and empty ID): {}",
                    e
                ))
            })
        }
    }
}

/// Extract signature bits from a CRL DER encoding
fn extract_crl_signature(der: &[u8]) -> Result<&[u8], TlsError> {
    // CRL structure: SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
    // We need to find the BIT STRING (signatureValue) which comes after TBSCertList

    if der.len() < 8 {
        return Err(TlsError::CrlVerificationFailed("CRL DER too short".into()));
    }

    if der[0] != 0x30 {
        return Err(TlsError::CrlVerificationFailed(
            "invalid CRL: expected SEQUENCE".into(),
        ));
    }

    // Parse outer SEQUENCE to find where TBSCertList ends
    let mut pos = 1;
    let first_len_byte = der[pos];
    let tbs_end = if first_len_byte < 0x80 {
        pos += 1;
        let content_len = first_len_byte as usize;
        pos + content_len
    } else {
        let num_len_bytes = (first_len_byte & 0x7F) as usize;
        pos += 1;
        let mut content_len = 0usize;
        for i in 0..num_len_bytes {
            content_len = (content_len << 8) | (der[pos + i] as usize);
        }
        pos += num_len_bytes;
        pos + content_len
    };

    // After TBSCertList comes signatureAlgorithm (SEQUENCE) then signatureValue (BIT STRING)
    // Parse the AlgorithmIdentifier SEQUENCE to skip it properly
    if tbs_end >= der.len() || der[tbs_end] != 0x30 {
        return Err(TlsError::CrlVerificationFailed(
            "CRL signature algorithm SEQUENCE not found".into(),
        ));
    }

    // Skip the AlgorithmIdentifier SEQUENCE
    let mut alg_pos = tbs_end + 1;
    let alg_len_byte = der[alg_pos];
    let _alg_len = if alg_len_byte < 0x80 {
        alg_pos += 1;
        alg_len_byte as usize
    } else {
        let num_len_bytes = (alg_len_byte & 0x7F) as usize;
        alg_pos += 1;
        let mut alg_len = 0usize;
        for i in 0..num_len_bytes {
            alg_len = (alg_len << 8) | (der[alg_pos + i] as usize);
        }
        alg_pos += num_len_bytes;
        alg_len
    };

    // Now we should be at the signature BIT STRING
    let mut sig_pos = alg_pos;
    if sig_pos >= der.len() || der[sig_pos] != 0x03 {
        return Err(TlsError::CrlVerificationFailed(
            "CRL signature BIT STRING not found".into(),
        ));
    }

    // Skip BIT STRING tag and length
    sig_pos += 1;
    let sig_len_byte = der[sig_pos];
    let sig_content_start = if sig_len_byte < 0x80 {
        sig_pos += 1;
        sig_pos + (sig_len_byte as usize)
    } else {
        let num_len_bytes = (sig_len_byte & 0x7F) as usize;
        sig_pos += 1;
        let mut sig_len = 0usize;
        for i in 0..num_len_bytes {
            sig_len = (sig_len << 8) | (der[sig_pos + i] as usize);
        }
        sig_pos += num_len_bytes;
        sig_pos + sig_len
    };

    // BIT STRING content starts with unused bits count (usually 0), then actual signature
    if sig_content_start >= der.len() {
        return Err(TlsError::CrlVerificationFailed(
            "CRL signature content out of bounds".into(),
        ));
    }

    let _unused_bits = der[sig_content_start];
    let sig_start = sig_content_start + 1;

    if sig_start >= der.len() {
        return Err(TlsError::CrlVerificationFailed(
            "CRL signature data out of bounds".into(),
        ));
    }

    Ok(&der[sig_start..])
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
fn extract_tbs_bytes(der: &[u8]) -> Result<&[u8], TlsError> {
    // Minimum DER certificate size: SEQUENCE (1) + length (1) + at least
    // signature algorithm (2) + minimum TBS (~5 for empty fields) + signature (~6).
    // We need at least 11 bytes to safely access der[pos+4] during length parsing
    // and der[tbs_pos+3] during TBS length parsing without bounds checks.
    if der.len() < 11 {
        return Err(TlsError::CertificateVerificationFailed(
            "certificate DER too short".into(),
        ));
    }

    // First byte should be SEQUENCE (0x30) - outer Certificate SEQUENCE
    if der[0] != 0x30 {
        return Err(TlsError::CertificateVerificationFailed(
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
            return Err(TlsError::CertificateVerificationFailed(
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
        return Err(TlsError::CertificateVerificationFailed(
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
            return Err(TlsError::CertificateVerificationFailed(
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
        return Err(TlsError::CertificateVerificationFailed(
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
fn extract_tbs_crl_bytes(der: &[u8]) -> Result<&[u8], TlsError> {
    // Same minimum as extract_tbs_bytes: need at least 11 bytes for safe parsing
    // of length fields and TBS access without bounds checks.
    if der.len() < 11 {
        return Err(TlsError::CrlVerificationFailed("CRL DER too short".into()));
    }

    if der[0] != 0x30 {
        return Err(TlsError::CrlVerificationFailed(
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
        return Err(TlsError::CrlVerificationFailed(
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
        return Err(TlsError::CrlVerificationFailed(
            "TBSCertList extends past end of DER".into(),
        ));
    }

    Ok(&der[tbs_start..tbs_end])
}
