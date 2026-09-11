//! Certificate operations

use crate::cert_profile::{CertProfile, ExtendedKeyUsage, GeneralName};
use crate::error::CaError;
use gm_crypto::sm2::decompress_sm2_pubkey;
use gm_crypto::sm2::{GM_TLS_DEFAULT_ID, Sm2KeyPair, Sm2Signer, Sm2Verifier};
use rand::Rng;
use sqlx::types::chrono::{DateTime, Utc};
use x509_parser::certification_request::{X509CertificationRequest, X509CertificationRequestInfo};
use x509_parser::prelude::FromDer;

use zeroize::ZeroizeOnDrop;

/// Decode CSR from PEM or raw DER. Handles both PEM-encoded and raw DER input.
fn decode_csr(csr_input: &[u8]) -> Result<Vec<u8>, CaError> {
    // Try PEM first
    if let Ok(pem_obj) = pem::parse(csr_input)
        && pem_obj.tag() == "CERTIFICATE REQUEST"
    {
        return Ok(pem_obj.contents().to_vec());
    }
    // Try raw DER
    if let Ok((_, _)) = X509CertificationRequest::from_der(csr_input) {
        return Ok(csr_input.to_vec());
    }
    Err(CaError::InvalidCsr(
        "Invalid CSR format: expected PEM or DER".to_string(),
    ))
}

/// Extract the Common Name (CN) from a CSR's subject.
/// Returns the CN string if found, or falls back to the subject's formatted string.
pub fn extract_csr_subject_cn(csr_input: &[u8]) -> Result<String, CaError> {
    let csr_der = decode_csr(csr_input)?;
    let (_, csr) = X509CertificationRequest::from_der(&csr_der)
        .map_err(|e| CaError::InvalidCsr(format!("CSR parse failed: {}", e)))?;

    // Use x509_parser's built-in string representation of subject
    // This gives us "CN=value, O=org, OU=unit" format
    let subject_str = csr.certification_request_info.subject.to_string();
    let trimmed = subject_str.trim();

    // If we got a meaningful subject string, clean it up for use as CN
    if !trimmed.is_empty() && trimmed != "(empty)" {
        // Take only the CN portion if present (before first comma)
        if let Some(cn_part) = trimmed.split(',').next() {
            // Remove "CN=" prefix if present
            let cn = cn_part.trim_start_matches("CN=").trim();
            if !cn.is_empty() {
                return Ok(cn.to_string());
            }
        }
        return Ok(trimmed.to_string());
    }

    // Fallback: use hex fingerprint of subject DER
    Ok(format!(
        "csr_{}",
        hex::encode(csr.certification_request_info.subject.as_raw())
    ))
}

// SM2 signature OID: 1.2.156.10197.1.501
const SM2_SIG_OID: &[u8] = &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x02, 0x01, 0xF5];
// SM2 public key OID: 1.2.156.10197.1.301
const SM2_PK_OID: &[u8] = &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x01, 0x01];
// CN OID: 2.5.4.3
const CN_OID: &[u8] = &[0x55, 0x04, 0x03];
// CRL Number extension OID: 1.2.156.10197.1.106
const CRL_NUM_OID: &[u8] = &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x01, 0x06];

// KeyUsage OID: 2.5.29.15
const KEY_USAGE_OID: &[u8] = &[0x55, 0x1D, 0x0F];
// ExtKeyUsage OID: 2.5.29.37
const EXT_KEY_USAGE_OID: &[u8] = &[0x55, 0x1D, 0x25];
// SubjectKeyIdentifier OID: 2.5.29.14
const SUBJECT_KEY_ID_OID: &[u8] = &[0x55, 0x1D, 0x0E];
// AuthorityKeyIdentifier OID: 2.5.29.35
const AUTHORITY_KEY_ID_OID: &[u8] = &[0x55, 0x1D, 0x23];
// SubjectAltName OID: 2.5.29.17
const SUBJECT_ALT_NAME_OID: &[u8] = &[0x55, 0x1D, 0x11];
// BasicConstraints OID: 2.5.29.19
// Encoding: 0x55 (=2*40+5) || 0x1D (=29) || 0x13 (=19)
const BASIC_CONSTRAINTS_OID: &[u8] = &[0x55, 0x1D, 0x13];

#[derive(Clone, sqlx::FromRow)]
#[allow(dead_code)] // DB row mapping — fields map to columns, not all are read in code
pub struct Certificate {
    pub id: i64,
    pub serial_number: String,
    pub certificate_pem: String,
    pub issuer_cn: String,
    pub subject_cn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub status: String,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("id", &self.id)
            .field("serial_number", &self.serial_number)
            .field("issuer_cn", &self.issuer_cn)
            .field("subject_cn", &self.subject_cn)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("status", &self.status)
            // Intentionally omit certificate_pem, revoked_at, revocation_reason, created_at, updated_at
            .finish()
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)] // DB row mapping — fields map to columns, not all are read in code
pub struct CrlEntry {
    pub serial_number: String,
    pub revoked_at: DateTime<Utc>,
    pub reason: i32,
}

#[derive(ZeroizeOnDrop)]
pub struct CaSigner {
    key_pair: Sm2KeyPair,
    ca_subject_cn: String,
    /// Raw 65-byte uncompressed SM2 public key (SEC1, `04 || x || y`).
    /// Cached on `new()` so AKI computation doesn't recompute it on every
    /// `sign_csr_with_profile` / `self_sign_ca` call.
    ca_pub_65: Vec<u8>,
}

impl CaSigner {
    pub fn new(key_pair: Sm2KeyPair, ca_subject_cn: &str) -> Self {
        let ca_pub_65 = key_pair.public_key_bytes_uncompressed();
        Self {
            key_pair,
            ca_subject_cn: ca_subject_cn.to_string(),
            ca_pub_65,
        }
    }

    /// Get the CA subject CN used for issued certificates.
    pub fn ca_subject_cn(&self) -> &str {
        &self.ca_subject_cn
    }

    /// Get the CA's raw 65-byte uncompressed SM2 public key (SEC1).
    /// Useful for callers that need to wire AKI into peer certificates
    /// or for chain construction in non-CA-signed scenarios.
    pub fn ca_public_key_bytes(&self) -> &[u8] {
        &self.ca_pub_65
    }

    /// Self-sign the CA certificate using the CA's own key.
    ///
    /// The resulting certificate is the trust anchor for any chain
    /// `sign_csr_with_profile` issues. The default profile is
    /// [`CertProfile::root_ca`] (keyCertSign + cRLSign + BasicConstraints
    /// CA:TRUE, no pathLenConstraint). Pass a custom profile if you
    /// need intermediate-CA-style pathLenConstraint.
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

        // Random 20-byte positive serial number
        let mut serial_bytes = [0u8; 20];
        rand::rng().fill_bytes(&mut serial_bytes);
        serial_bytes[0] &= 0x7F;

        // Issuer == Subject for self-signed root.
        let subject_der = der_name(self.ca_subject_cn.as_bytes());

        // SM2-specific algorithm identifiers and key-id derivation.
        let sig_alg_id = sm2_sig_alg_id();
        let spki_alg_id = sm2_spki_alg_id();
        let subject_key_id = sm3_key_id(&self.ca_pub_65);
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
            self.ca_pub_65.clone(),
            extensions,
        )?;

        let signer = Sm2Signer::new_with_distid(&self.key_pair, GM_TLS_DEFAULT_ID)
            .map_err(|e| CaError::SigningFailed(format!("failed to create signer: {}", e)))?;
        let signature = signer
            .sign(&tbs_der)
            .map_err(|e| CaError::SigningFailed(format!("self-sign failed: {}", e)))?;

        let cert_der = build_certificate_der(&tbs_der, sig_alg_id, &signature);
        let pem_obj = pem::Pem::new("CERTIFICATE", cert_der);
        Ok(pem::encode(&pem_obj))
    }

    /// Sign a CSR and return the certificate PEM along with the serial number.
    ///
    /// The certificate extensions are taken from `profile`. To reproduce
    /// the v0.1.x extension set (digitalSignature + keyEncipherment +
    /// serverAuth + clientAuth + SKI + SAN + BasicConstraints CA:FALSE),
    /// pass [`CertProfile::default`] (or use the convenience wrapper
    /// [`CertProfile::server_end_entity`]).
    ///
    /// Returns `(serial_hex, pem_str)` tuple where `serial_hex` is the
    /// hex-encoded serial number for database storage.
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

        let csr_info: &X509CertificationRequestInfo = &csr.certification_request_info;

        // Subject DN raw DER bytes from CSR (for embedding in certificate)
        let subject_der = csr_info.subject.as_raw();

        // Extract public key from CSR's SubjectPublicKeyInfo (already DER encoded)
        // BitString.data contains the raw public key bytes
        let spki_bytes = &csr_info.subject_pki.subject_public_key.data;
        let pk_algorithm_oid = csr_info.subject_pki.algorithm.algorithm.as_bytes();

        // Validate CSR public key is SM2 (only accept SM2_PK_OID, not generic EC OID)
        // RFC 3279 specifies that EC OID (1.2.840.10045.2.1) with brainpoolP256r1
        // or other curves is NOT SM2. Only SM2 OID (1.2.156.10197.1.301) is valid.
        if pk_algorithm_oid != SM2_PK_OID {
            return Err(CaError::InvalidCsr(
                "CSR public key must use SM2 algorithm OID (1.2.156.10197.1.301)".to_string(),
            ));
        }

        // Verify CSR signature to prove the requester owns the corresponding private key
        let sig_bytes = csr.signature_value.data.as_ref();
        let decompressed_pk = decompress_sm2_pubkey(spki_bytes)
            .map_err(|e| CaError::InvalidCsr(format!("invalid CSR public key format: {}", e)))?;
        let verifier = Sm2Verifier::new(&decompressed_pk, GM_TLS_DEFAULT_ID)
            .map_err(|e| CaError::InvalidCsr(format!("failed to create SM2 verifier: {}", e)))?;
        let csr_info_bytes = csr.certification_request_info.raw;
        verifier.verify(csr_info_bytes, sig_bytes).map_err(|e| {
            CaError::InvalidCsr(format!("CSR signature verification failed: {}", e))
        })?;

        // Validity period
        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + std::time::Duration::from_secs(86400 * validity_days as u64);

        // Random 20-byte positive serial number
        let mut serial_bytes = [0u8; 20];
        rand::rng().fill_bytes(&mut serial_bytes);
        serial_bytes[0] &= 0x7F; // ensure positive

        // Build end-entity extensions per profile. SAN: take the first
        // DNS entry from the profile if any, otherwise fall back to
        // the CSR's subject CN (matches v0.1.x behavior).
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
            // SM2 key-id derivation: SM3(subject_pubkey_65)[:20].
            let subject_key_id = sm3_key_id(spki_bytes);
            let ca_key_id = sm3_key_id(&self.ca_pub_65);
            Some(build_extensions(
                &subject_key_id,
                &ca_key_id,
                &sans,
                profile,
            ))
        };

        // Build TBSCertificate DER
        let tbs_der = build_tbs_certificate(
            &serial_bytes,
            not_before,
            not_after,
            self.ca_subject_cn.as_bytes(),
            subject_der,
            sm2_sig_alg_id(),
            sm2_spki_alg_id(),
            spki_bytes.to_vec(),
            extensions,
        )?;

        // Sign TBSCertificate with CA key using GM/T standard distid
        let signer = Sm2Signer::new_with_distid(&self.key_pair, GM_TLS_DEFAULT_ID)
            .map_err(|e| CaError::SigningFailed(format!("failed to create signer: {}", e)))?;
        let signature = signer
            .sign(&tbs_der)
            .map_err(|e| CaError::SigningFailed(format!("signing failed: {}", e)))?;

        // Build full Certificate DER
        let cert_der = build_certificate_der(&tbs_der, sm2_sig_alg_id(), &signature);

        // Encode as PEM
        let pem_obj = pem::Pem::new("CERTIFICATE", cert_der);
        let pem_str = pem::encode(&pem_obj);

        // Return serial number as hex string for database storage
        let serial_hex = hex::encode(serial_bytes);
        Ok((serial_hex, pem_str))
    }

    /// Renew an existing certificate: issue a new certificate with the same
    /// subject and public key but a new validity period and serial number.
    ///
    /// Extensions are rebuilt per `profile`; the existing cert's SAN
    /// DNS name is carried over (matches v0.1.x behavior). Use
    /// [`CertProfile::default`] for backward-compatible extension set.
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
            let subject_key_id = sm3_key_id(&cert_info.spki_bytes);
            let ca_key_id = sm3_key_id(&self.ca_pub_65);
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
            sm2_sig_alg_id(),
            sm2_spki_alg_id(),
            cert_info.spki_bytes.clone(),
            extensions,
        )?;

        let signer = Sm2Signer::new_with_distid(&self.key_pair, GM_TLS_DEFAULT_ID)
            .map_err(|e| CaError::SigningFailed(format!("failed to create signer: {}", e)))?;
        let signature = signer
            .sign(&tbs_der)
            .map_err(|e| CaError::SigningFailed(format!("signing failed: {}", e)))?;

        let cert_der = build_certificate_der(&tbs_der, sm2_sig_alg_id(), &signature);
        let pem_obj = pem::Pem::new("CERTIFICATE", cert_der);
        Ok(pem::encode(&pem_obj))
    }

    pub fn generate_crl(
        &self,
        revoked_serials: &[CrlEntry],
        crl_number: u64,
    ) -> Result<Vec<u8>, CaError> {
        let now = time::OffsetDateTime::now_utc();

        // RevokedCertificates: SEQUENCE OF SEQUENCE { serial INTEGER, date Time }
        let revoked_der: Vec<u8> = if revoked_serials.is_empty() {
            Vec::new()
        } else {
            let entries: Vec<Vec<u8>> = revoked_serials
                .iter()
                .map(|entry| {
                    let serial = hex::decode(&entry.serial_number).map_err(|e| {
                        CaError::InternalError(format!("invalid serial number: {}", e))
                    })?;
                    let serial_int = der_integer_positive(&serial);
                    let revocation_date = utctime_from_datetime(entry.revoked_at);
                    Ok(der_sequence(&[serial_int, revocation_date].concat()))
                })
                .collect::<Result<Vec<Vec<u8>>, _>>()?;
            // Wrap entries in SEQUENCE OF
            let content: Vec<u8> = entries.into_iter().flatten().collect();
            der_sequence(&content)
        };

        // CRL Number extension [0] EXPLICIT INTEGER
        let crl_num_oid = encode_oid(CRL_NUM_OID);
        let crl_num_bytes = crl_number.to_be_bytes();
        let crl_num_ext =
            der_sequence(&[crl_num_oid, der_integer_positive(&crl_num_bytes)].concat());
        let extensions_der = der_explicit_context(0, &der_sequence(&[crl_num_ext].concat()));

        // TBSCertList: version, signature, issuer, thisUpdate, nextUpdate, revokedCerts, extensions
        let tbs_version = der_explicit_context(0, &der_integer_positive(b"\x02\x01\x01")); // v2
        let tbs_sig_alg = sm2_sig_alg_id();
        let tbs_issuer = der_name(self.ca_subject_cn.as_bytes());
        let tbs_this_update = utctime(now);
        let tbs_next_update = utctime(now + time::Duration::days(7));

        let mut tbs_parts: Vec<Vec<u8>> = vec![
            tbs_version,
            tbs_sig_alg,
            tbs_issuer,
            tbs_this_update,
            tbs_next_update,
        ];
        if !revoked_der.is_empty() {
            tbs_parts.push(revoked_der);
        }
        tbs_parts.push(extensions_der);

        let tbs_der = der_sequence(&tbs_parts.into_iter().flatten().collect::<Vec<u8>>());

        // Sign with CA key using GM/T standard distid
        let signer = Sm2Signer::new_with_distid(&self.key_pair, GM_TLS_DEFAULT_ID)
            .map_err(|e| CaError::SigningFailed(format!("failed to create signer: {}", e)))?;
        let signature = signer
            .sign(&tbs_der)
            .map_err(|e| CaError::SigningFailed(format!("CRLsigning failed: {}", e)))?;

        // Full CRL DER: TBS || AlgorithmIdentifier || BIT STRING
        let sig_bits = der_bit_string(&signature);
        let crl = der_sequence(&[tbs_der, sm2_sig_alg_id(), sig_bits].concat());

        Ok(crl)
    }
}

// ---------------------------------------------------------------------------
// DER encoding helpers — re-exported from gm-der crate
// ---------------------------------------------------------------------------

use gm_der::{
    der_bit_string, der_bool, der_explicit_context, der_integer_positive, der_len,
    der_octet_string, der_sequence, der_sequence_v, der_set, der_utf8_string, encode_oid,
};

/// Build a DER-encoded Extension:
///
/// Extension ::= SEQUENCE {
///   extnID OID,
///   critical BOOLEAN DEFAULT FALSE,
///   extnValue OCTET STRING
/// }
fn build_extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut extn = Vec::new();
    extn.extend_from_slice(&encode_oid(oid));
    if critical {
        extn.extend_from_slice(&der_bool(true));
    }
    extn.extend_from_slice(&der_octet_string(value));
    der_sequence(&extn)
}

/// Build BasicConstraints extension value (RFC 5280 §4.2.1.9):
///   BasicConstraints ::= SEQUENCE {
///       cA                  BOOLEAN DEFAULT FALSE,
///       pathLenConstraint   INTEGER (0..MAX) OPTIONAL,
///   }
/// `path_len` is only emitted when `is_ca == true && Some(n)`. Per RFC,
/// pathLenConstraint is meaningless for non-CA certs and MUST be omitted.
fn build_basic_constraints(is_ca: bool, path_len: Option<u8>) -> Vec<u8> {
    let mut content: Vec<u8> = Vec::new();
    content.extend(der_bool(is_ca));
    if is_ca && let Some(n) = path_len {
        content.extend(der_integer_positive(&[n]));
    }
    der_sequence_v(&[content])
}

/// Build AuthorityKeyIdentifier extension value (RFC 5280 §4.2.1.1):
///   AuthorityKeyIdentifier ::= SEQUENCE {
///       keyIdentifier \[0\] EXPLICIT OCTET STRING OPTIONAL, ...
///   }
/// The OCTET STRING content is the 20-byte key-id (already hashed by the
/// caller per RFC 7093 §2 Method 1: SM3[\:20] for SM2 certs, SHA-1[\:20]
/// for RSA certs to interop with the global PKI). The hash function is
/// chosen by the caller; this helper is purely DER layout.
///
/// Produces: `30 <len> A0 <len> 04 14 <20 bytes>`
pub(crate) fn build_authority_key_id_from_hash(key_id: &[u8]) -> Vec<u8> {
    let key_id_tlv = der_octet_string(key_id);
    der_sequence(&[der_explicit_context(0, &key_id_tlv)].concat())
}

/// Build a complete Extensions SEQUENCE for a certificate, driven by
/// `profile`. Extension order is by industry convention (RFC 5280 has
/// no required order):
///   1. BasicConstraints       — critical iff `CA:TRUE` per §4.2.1.9
///   2. KeyUsage               — critical per §4.2.1.3 SHOULD
///   3. ExtendedKeyUsage       — not critical per §4.2.1.12
///   4. SubjectAltName         — not critical per §4.2.1.6
///   5. SubjectKeyIdentifier   — not critical per §4.2.1.2
///   6. AuthorityKeyIdentifier — not critical per §4.2.1.1
///
/// `subject_key_id` and `ca_key_id` are 20-byte key-identifier values
/// already computed by the caller (the hash function is algorithm-
/// specific: SM3[\:20] for SM2 certs, SHA-1[\:20] for RSA certs). This
/// helper is algorithm-agnostic.
///
/// Returns the SEQUENCE OF Extension bytes — caller wraps in \[3\] EXPLICIT
/// via `build_tbs_certificate`. Returns an empty SEQUENCE when the profile
/// disables every optional extension (caller should treat `None` as
/// "omit extensions entirely" instead).
pub(crate) fn build_extensions(
    subject_key_id: &[u8],
    ca_key_id: &[u8],
    sans: &[GeneralName],
    profile: &CertProfile,
) -> Vec<u8> {
    let mut exts: Vec<Vec<u8>> = Vec::new();

    // 1. BasicConstraints — emit when include_basic_constraints
    if profile.include_basic_constraints {
        exts.push(build_extension(
            BASIC_CONSTRAINTS_OID,
            profile.is_ca,
            &build_basic_constraints(profile.is_ca, profile.ca_path_len_constraint),
        ));
    }

    // 2. KeyUsage — emit when at least one bit is set
    let ku_has_any_bit = profile.key_usage.digital_signature
        || profile.key_usage.non_repudiation
        || profile.key_usage.key_encipherment
        || profile.key_usage.data_encipherment
        || profile.key_usage.key_agreement
        || profile.key_usage.key_cert_sign
        || profile.key_usage.crl_sign
        || profile.key_usage.encipher_only
        || profile.key_usage.decipher_only;
    if ku_has_any_bit {
        exts.push(build_extension(
            KEY_USAGE_OID,
            true,
            &profile.key_usage.to_der_bytes(),
        ));
    }

    // 3. ExtendedKeyUsage — emit when at least one purpose
    if !profile.ext_key_usage.is_empty() {
        exts.push(build_extension(
            EXT_KEY_USAGE_OID,
            false,
            &ExtendedKeyUsage::build_ext_key_usage_value(&profile.ext_key_usage),
        ));
    }

    // 4. SubjectAltName — emit when include_san and at least one entry
    if profile.include_san && !sans.is_empty() {
        exts.push(build_extension(
            SUBJECT_ALT_NAME_OID,
            false,
            &GeneralName::build_san_value(sans),
        ));
    }

    // 5. SubjectKeyIdentifier — pre-computed 20-byte key id in OCTET STRING
    if profile.include_ski {
        exts.push(build_extension(
            SUBJECT_KEY_ID_OID,
            false,
            &der_octet_string(subject_key_id),
        ));
    }

    // 6. AuthorityKeyIdentifier — pre-computed 20-byte key id in [0] EXPLICIT
    if profile.include_aki {
        exts.push(build_extension(
            AUTHORITY_KEY_ID_OID,
            false,
            &build_authority_key_id_from_hash(ca_key_id),
        ));
    }

    der_sequence_v(&exts)
}

/// SM2 SPKI AlgorithmIdentifier: SEQUENCE { OID(sm2), NULL }
/// OID: 1.2.156.10197.1.301
fn sm2_spki_alg_id() -> Vec<u8> {
    let oid = encode_oid(SM2_PK_OID);
    der_sequence(&[oid, vec![0x05, 0x00]].concat())
}

/// SM2 Signature AlgorithmIdentifier: SEQUENCE { OID(sm3WithSM2), NULL }
/// OID: 1.2.156.10197.1.501
fn sm2_sig_alg_id() -> Vec<u8> {
    let oid = encode_oid(SM2_SIG_OID);
    der_sequence(&[oid, vec![0x05, 0x00]].concat())
}

/// SM3(pubkey_bytes)[\:20] — RFC 7093 §2 Method 1 key-id derivation for SM2 certs.
fn sm3_key_id(pubkey_bytes: &[u8]) -> [u8; 20] {
    use gm_crypto::sm3::Sm3Hasher;
    let hash = Sm3Hasher::hash(pubkey_bytes).expect("SM3 hash should not fail for bytes");
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[..20]);
    out
}

fn der_name(cn: &[u8]) -> Vec<u8> {
    // AttributeTypeAndValue: SEQUENCE { OID, UTF8String }
    let oid = encode_oid(CN_OID);
    let atv = der_sequence(&[oid, der_utf8_string(cn)].concat());
    // SET containing one ATV
    let set = der_set(&[atv]);
    // Name = SEQUENCE of SETs
    der_sequence(&[set].concat())
}

fn utctime(t: time::OffsetDateTime) -> Vec<u8> {
    let year = t.year();
    let month = t.month() as u8; // Month enum to u8 (1-12)
    let day = t.day();
    let hour = t.hour();
    let minute = t.minute();
    let second = t.second();

    // UTCTime: YYMMDDHHMMSSZ (for years 1950-2049)
    // GeneralizedTime: YYYYMMDDHHMMSSZ (for years outside 1950-2049)
    if (1950..2050).contains(&year) {
        let s = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            (year - 2000) as u8,
            month,
            day,
            hour,
            minute,
            second
        );
        let mut v = vec![0x17]; // UTCTime tag
        v.extend_from_slice(&der_len(s.len()));
        v.extend_from_slice(s.as_bytes());
        v
    } else {
        let s = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            year, month, day, hour, minute, second
        );
        let mut v = vec![0x18]; // GeneralizedTime tag
        v.extend_from_slice(&der_len(s.len()));
        v.extend_from_slice(s.as_bytes());
        v
    }
}

/// Encode a sqlx DateTime\<Utc> as UTCTime DER
fn utctime_from_datetime(dt: sqlx::types::chrono::DateTime<Utc>) -> Vec<u8> {
    use chrono::{Datelike, Timelike};
    let year = dt.year();
    let month = dt.month() as u8;
    let day = dt.day();
    let hour = dt.hour() as u8;
    let minute = dt.minute() as u8;
    let second = dt.second() as u8;

    if (1950..2050).contains(&year) {
        let s = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            (year - 2000) as u8,
            month,
            day,
            hour,
            minute,
            second
        );
        let mut v = vec![0x17];
        v.extend_from_slice(&der_len(s.len()));
        v.extend_from_slice(s.as_bytes());
        v
    } else {
        let s = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            year, month, day, hour, minute, second
        );
        let mut v = vec![0x18];
        v.extend_from_slice(&der_len(s.len()));
        v.extend_from_slice(s.as_bytes());
        v
    }
}

/// Algorithm-agnostic TBSCertificate builder (RFC 5280 §4.1):
///
///   TBSCertificate ::= SEQUENCE {
///     version         \[0\] EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     ...
///     extensions      \[3\] EXPLICIT Extensions OPTIONAL
///   }
///
/// `sig_alg_id` and `spki_alg_id` are pre-built DER-encoded
/// AlgorithmIdentifier values; `spki_pubkey_bitstring` is the BIT STRING
/// content (e.g. 65-byte uncompressed SM2 point, or PKCS#1 RSAPublicKey
/// DER for RSA). The SPKI is assembled here from those pieces so callers
/// don't have to duplicate that layout.
///
/// Nine arguments is over clippy's default threshold but the call sites
/// are confined to `CaSigner` (SM2) and `RsaCaSigner` (RSA); a builder
/// type would only obscure the DER layout.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_tbs_certificate(
    serial: &[u8],
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
    issuer_cn: &[u8],
    subject_der: &[u8],
    sig_alg_id: Vec<u8>,
    spki_alg_id: Vec<u8>,
    spki_pubkey_bitstring: Vec<u8>,
    extensions: Option<Vec<u8>>,
) -> Result<Vec<u8>, CaError> {
    // [0] EXPLICIT version v3
    let version_inner = der_integer_positive(&[0x03]);
    let version = der_explicit_context(0, &version_inner);

    // SerialNumber
    let serial_der = der_integer_positive(serial);

    // Issuer Name
    let issuer = der_name(issuer_cn);

    // Validity
    let validity = der_sequence(&[utctime(not_before), utctime(not_after)].concat());

    // Subject (use raw DER from CSR)
    let subject = subject_der.to_vec();

    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING(content) }
    let spki = der_sequence(&[spki_alg_id, der_bit_string(&spki_pubkey_bitstring)].concat());

    // Build TBSCertificate
    let mut tbs_parts: Vec<Vec<u8>> = vec![
        version, serial_der, sig_alg_id, issuer, validity, subject, spki,
    ];

    // Append [3] EXPLICIT Extensions if present
    if let Some(exts) = extensions {
        tbs_parts.push(der_explicit_context(3, &exts));
    }

    Ok(der_sequence_v(&tbs_parts))
}

/// Algorithm-agnostic Certificate wrapper (RFC 5280 §4.1):
///
///   Certificate ::= SEQUENCE {
///     tbsCertificate     TBSCertificate,
///     signatureAlgorithm AlgorithmIdentifier,
///     signatureValue     BIT STRING
///   }
///
/// `sig_alg_id` must match the AlgorithmIdentifier inside the TBS.
pub(crate) fn build_certificate_der(tbs: &[u8], sig_alg_id: Vec<u8>, signature: &[u8]) -> Vec<u8> {
    let sig_bits = der_bit_string(signature);
    der_sequence(&[tbs.to_vec(), sig_alg_id, sig_bits].concat())
}

// ============================================================================
// Tests — wire-format smoke checks for the new profile-aware extension
// emission (AKI, BasicConstraints CA:FALSE/CA:TRUE, KU keyCertSign|cRLSign).
//
// These tests round-trip the produced PEM through x509-parser to verify
// gm-tls / gm-tlcp will accept the certs.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS;
    use x509_parser::prelude::{FromDer, X509Certificate};

    const BASIC_CONSTRAINTS_OID_TEST: &[u8] = &[0x55, 0x1D, 0x13];
    const KEY_USAGE_OID_TEST: &[u8] = &[0x55, 0x1D, 0x0F];
    const SUBJECT_KEY_ID_OID_TEST: &[u8] = &[0x55, 0x1D, 0x0E];
    const AUTHORITY_KEY_ID_OID_TEST: &[u8] = &[0x55, 0x1D, 0x23];

    /// Helper: parse DER bytes into x509-parser's struct (borrows from input).
    fn parse_cert_der<'a>(der_bytes: &'a [u8]) -> X509Certificate<'a> {
        let (_, cert) = X509Certificate::from_der(der_bytes).expect("DER parse");
        cert
    }

    /// Helper: return the first extension matching OID, if any.
    fn find_ext<'a, 'b>(
        cert: &'a X509Certificate<'b>,
        oid: &[u8],
    ) -> Option<&'a x509_parser::extensions::X509Extension<'b>> {
        cert.extensions().iter().find(|e| e.oid.as_bytes() == oid)
    }

    #[test]
    fn root_ca_self_signed_has_bc_ca_true_and_aki() {
        let key = Sm2KeyPair::generate().expect("gen key");
        let ca_pub_65 = key.public_key_bytes_uncompressed();
        let signer = CaSigner::new(key, "Test Root CA");

        let pem_str = signer
            .self_sign_ca(365, &CertProfile::root_ca())
            .expect("self_sign_ca");

        let pem_obj = pem::parse(pem_str.as_bytes()).expect("PEM parse");
        let cert = parse_cert_der(pem_obj.contents());

        // BasicConstraints: CA:TRUE, critical, no pathLenConstraint
        let bc = find_ext(&cert, BASIC_CONSTRAINTS_OID_TEST).expect("BC present");
        assert!(
            bc.critical,
            "BC must be critical when CA:TRUE per RFC 5280 §4.2.1.9"
        );
        let parsed = bc.parsed_extension();
        match parsed {
            x509_parser::extensions::ParsedExtension::BasicConstraints(bc_inner) => {
                assert!(bc_inner.ca, "CA must be TRUE");
                assert!(
                    bc_inner.path_len_constraint.is_none(),
                    "no pathLenConstraint"
                );
            }
            other => panic!("expected BC, got {:?}", other),
        }
        // _ = OID registry alias reference (silences unused-import lint if needed)
        let _ = OID_X509_EXT_BASIC_CONSTRAINTS;

        // KeyUsage: keyCertSign(bit 5) | cRLSign(bit 6) only
        let ku = find_ext(&cert, KEY_USAGE_OID_TEST).expect("KU present");
        assert!(ku.critical, "KU should be critical per §4.2.1.3 SHOULD");
        // BIT STRING is MSB-first within the byte:
        //   bit 5 (keyCertSign) = 0x80 >> 5 = 0x04
        //   bit 6 (cRLSign)     = 0x80 >> 6 = 0x02
        //   combined            = 0x06
        // ku.value contains [unused_bits, byte0, ...]
        assert_eq!(ku.value[1], 0x06, "KU bits must be keyCertSign|cRLSign");

        // SKI: SM3(CA pubkey)[:20]
        let ski = find_ext(&cert, SUBJECT_KEY_ID_OID_TEST).expect("SKI present");
        let expected_ski = {
            let h = gm_crypto::sm3::Sm3Hasher::hash(&ca_pub_65).expect("SM3");
            h[..20].to_vec()
        };
        // ski.value is the full OCTET STRING TLV (tag 04 + length + body).
        // Skip the first 2 bytes to get the body.
        assert_eq!(&ski.value[2..], expected_ski.as_slice());

        // AKI: keyIdentifier = SM3(CA pubkey)[:20] (CA == subject, so AKI == SKI)
        let aki = find_ext(&cert, AUTHORITY_KEY_ID_OID_TEST).expect("AKI present");
        let aki_inner = aki.value;
        let mut found_key_id = false;
        for window in aki_inner.windows(20) {
            if window == expected_ski.as_slice() {
                found_key_id = true;
                break;
            }
        }
        assert!(
            found_key_id,
            "AKI keyIdentifier must equal SM3(CA pubkey)[:20]"
        );
    }

    #[test]
    fn end_entity_default_profile_has_bc_ca_false_and_aki() {
        let leaf_key = Sm2KeyPair::generate().expect("gen leaf key");
        let leaf_pub_65 = leaf_key.public_key_bytes_uncompressed();

        let ca_key = Sm2KeyPair::generate().expect("gen CA key");
        let ca_pub_65 = ca_key.public_key_bytes_uncompressed();
        let ca_signer = CaSigner::new(ca_key, "Test CA");

        // Build the CSR with CsrBuilder (replaces ~25 lines of naked DER
        // that lived here pre-Phase-3).
        let csr_pem = gm_crypto::x509::CsrBuilder::new_sm2("leaf.example.com", &leaf_pub_65)
            .expect("CsrBuilder::new_sm2")
            .build_pem(&leaf_key)
            .expect("CsrBuilder::build_pem");

        let (_, cert_pem) = ca_signer
            .sign_csr_with_profile(csr_pem.as_bytes(), 365, &CertProfile::default())
            .expect("sign_csr_with_profile");

        let pem_obj = pem::parse(cert_pem.as_bytes()).expect("PEM parse");
        let cert = parse_cert_der(pem_obj.contents());

        // BasicConstraints: CA:FALSE
        let bc = find_ext(&cert, BASIC_CONSTRAINTS_OID_TEST).expect("BC present");
        let parsed = bc.parsed_extension();
        match parsed {
            x509_parser::extensions::ParsedExtension::BasicConstraints(bc_inner) => {
                assert!(!bc_inner.ca, "CA must be FALSE for end-entity");
            }
            other => panic!("expected BC, got {:?}", other),
        }

        // KU: digitalSignature(0) | keyEncipherment(2)
        // bit 0 (digitalSig)   = 0x80 >> 0 = 0x80
        // bit 2 (keyEncipher)  = 0x80 >> 2 = 0x20
        // combined             = 0xA0
        let ku = find_ext(&cert, KEY_USAGE_OID_TEST).expect("KU present");
        assert_eq!(
            ku.value[1], 0xA0,
            "KU bits must be digitalSignature|keyEncipherment"
        );

        // AKI must key on the CA's pubkey (not the leaf's)
        let aki = find_ext(&cert, AUTHORITY_KEY_ID_OID_TEST).expect("AKI present");
        let expected_aki = {
            let h = gm_crypto::sm3::Sm3Hasher::hash(&ca_pub_65).expect("SM3");
            h[..20].to_vec()
        };
        let mut found_key_id = false;
        for window in aki.value.windows(20) {
            if window == expected_aki.as_slice() {
                found_key_id = true;
                break;
            }
        }
        assert!(
            found_key_id,
            "AKI keyIdentifier must equal SM3(CA pubkey)[:20] — NOT the subject's"
        );

        // SAN: a single DNS entry equal to subject CN
        let san = find_ext(&cert, SUBJECT_ALT_NAME_OID).expect("SAN present");
        let san_bytes = san.value;
        assert!(
            san_bytes.windows(16).any(|w| w == b"leaf.example.com"),
            "SAN must contain dNSName leaf.example.com"
        );
    }
}
