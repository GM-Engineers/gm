//! Certificate operations

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
#[allow(dead_code)]
const AUTHORITY_KEY_ID_OID: &[u8] = &[0x55, 0x1D, 0x23];
// SubjectAltName OID: 2.5.29.17
const SUBJECT_ALT_NAME_OID: &[u8] = &[0x55, 0x1D, 0x11];
// BasicConstraints OID: 2.5.29.19
#[allow(dead_code)]
const BASIC_CONSTRAINTS_OID: &[u8] = &[0x55, 0x1D, 0x19];

// ExtKeyUsage: serverAuth = 1.3.6.1.5.5.7.3.1
const SERVER_AUTH_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
// ExtKeyUsage: clientAuth = 1.3.6.1.5.5.7.3.2
const CLIENT_AUTH_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

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
}

impl CaSigner {
    pub fn new(key_pair: Sm2KeyPair, ca_subject_cn: &str) -> Self {
        Self {
            key_pair,
            ca_subject_cn: ca_subject_cn.to_string(),
        }
    }

    /// Get the CA subject CN used for issued certificates.
    pub fn ca_subject_cn(&self) -> &str {
        &self.ca_subject_cn
    }

    /// Sign a CSR and return the certificate PEM along with the serial number.
    ///
    /// Returns `(serial_hex, pem_str)` tuple where `serial_hex` is the hex-encoded
    /// serial number for database storage.
    pub fn sign_csr(
        &self,
        csr_input: &[u8],
        validity_days: i64,
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

        // Build end-entity extensions with SAN from CN
        let dns_name = extract_csr_subject_cn(csr_input).unwrap_or_default();
        let extensions = if !dns_name.is_empty() {
            Some(build_end_entity_extensions(spki_bytes, &dns_name))
        } else {
            None
        };

        // Build TBSCertificate DER
        let tbs_der = build_tbs_certificate(
            &serial_bytes,
            not_before,
            not_after,
            self.ca_subject_cn.as_bytes(),
            subject_der,
            spki_bytes,
            extensions,
        )?;

        // Sign TBSCertificate with CA key using GM/T standard distid
        let signer = Sm2Signer::new_with_distid(&self.key_pair, GM_TLS_DEFAULT_ID)
            .map_err(|e| CaError::SigningFailed(format!("failed to create signer: {}", e)))?;
        let signature = signer
            .sign(&tbs_der)
            .map_err(|e| CaError::SigningFailed(format!("signing failed: {}", e)))?;

        // Build full Certificate DER
        let cert_der = build_certificate_der(&tbs_der, &signature);

        // Encode as PEM
        let pem_obj = pem::Pem::new("CERTIFICATE", cert_der);
        let pem_str = pem::encode(&pem_obj);

        // Return serial number as hex string for database storage
        let serial_hex = hex::encode(serial_bytes);
        Ok((serial_hex, pem_str))
    }

    /// Renew an existing certificate: issue a new certificate with the same
    /// subject and public key but a new validity period and serial number.
    pub fn renew_certificate(
        &self,
        existing_cert_pem: &str,
        validity_days: i64,
    ) -> Result<String, CaError> {
        if validity_days <= 0 || validity_days > 3650 {
            return Err(CaError::InvalidArgument(format!(
                "validity_days must be 1-3650, got {}",
                validity_days
            )));
        }
        use gm_crypto::x509::parse_cert_pem;

        // Parse existing certificate once to extract subject DN, public key, and validity
        let cert_info = parse_cert_pem(existing_cert_pem)
            .map_err(|e| CaError::InvalidCertificate(format!("certificate parse failed: {}", e)))?;

        // Check if the existing certificate is expired
        let now = time::OffsetDateTime::now_utc();
        if now > cert_info.not_after {
            return Err(CaError::InvalidCertificate(
                "cannot renew an expired certificate".to_string(),
            ));
        }

        // Validity period
        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + std::time::Duration::from_secs(86400 * validity_days as u64);

        // Random 20-byte positive serial number
        let mut serial_bytes = [0u8; 20];
        rand::rng().fill_bytes(&mut serial_bytes);
        serial_bytes[0] &= 0x7F; // ensure positive

        // Build TBSCertificate with same subject and public key, new validity
        // Include extensions (KeyUsage, ExtKeyUsage, SubjectKeyIdentifier, SAN) if DNS name available
        let extensions = cert_info
            .san_dns_name
            .as_ref()
            .map(|dns_name| build_end_entity_extensions(&cert_info.spki_bytes, dns_name));

        let tbs_der = build_tbs_certificate(
            &serial_bytes,
            not_before,
            not_after,
            self.ca_subject_cn.as_bytes(),
            &cert_info.subject_der,
            &cert_info.spki_bytes,
            extensions,
        )?;

        // Sign with CA key using GM/T standard distid
        let signer = Sm2Signer::new_with_distid(&self.key_pair, GM_TLS_DEFAULT_ID)
            .map_err(|e| CaError::SigningFailed(format!("failed to create signer: {}", e)))?;
        let signature = signer
            .sign(&tbs_der)
            .map_err(|e| CaError::SigningFailed(format!("signing failed: {}", e)))?;

        // Build full Certificate DER
        let cert_der = build_certificate_der(&tbs_der, &signature);

        // Encode as PEM
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
        let tbs_sig_alg = der_algorithm_identifier();
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
        let crl = der_sequence(&[tbs_der, der_algorithm_identifier(), sig_bits].concat());

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

/// Build KeyUsage extension value:
/// KeyUsage ::= BIT STRING { digitalSignature(0), keyEncipherment(1), keyCertSign(5), cRLSign(6) }
fn build_key_usage(end_entity: bool) -> Vec<u8> {
    if end_entity {
        // digitalSignature(0) | keyEncipherment(1) = 0b00000011 = 0x03
        vec![0x03, 0x03, 0x00, 0x03]
    } else {
        // keyCertSign(5) | cRLSign(6) = 0b00000110 = 0x06
        vec![0x03, 0x02, 0x00, 0x06]
    }
}

/// Build ExtendedKeyUsage extension value:
/// ExtKeyUsage ::= SEQUENCE OF KeyPurposeId (OID)
/// Includes: serverAuth (1.3.6.1.5.5.7.3.1) and clientAuth (1.3.6.1.5.5.7.3.2)
fn build_ext_key_usage() -> Vec<u8> {
    let server_auth = encode_oid(SERVER_AUTH_OID);
    let client_auth = encode_oid(CLIENT_AUTH_OID);
    der_sequence(&[server_auth, client_auth].concat())
}

/// Build SubjectKeyIdentifier from SPKI bytes (SM3 hash, RFC 7093 Method 1).
/// RFC 5480: SubjectKeyIdentifier is SHA-1 of SPKI for compatibility,
/// but GM/TLS uses SM3 per GM/T specification.
fn build_subject_key_id(spki_bytes: &[u8]) -> Vec<u8> {
    use gm_crypto::sm3::Sm3Hasher;
    let hash = Sm3Hasher::hash(spki_bytes).expect("SM3 hash should not fail for bytes");
    // Only first 20 bytes for SubjectKeyIdentifier (RFC 5480 §4.2.1.2)
    der_octet_string(&hash[..20])
}

/// Build BasicConstraints extension value:
/// BasicConstraints ::= SEQUENCE { CA BOOLEAN }
#[allow(dead_code)]
fn build_basic_constraints(is_ca: bool) -> Vec<u8> {
    der_sequence_v(&[der_bool(is_ca)])
}

/// Build SubjectAlternativeName from a DNS name:
/// SubjectAltName ::= SEQUENCE OF GeneralName { dNSName }
fn build_subject_alt_name(dns_name: &str) -> Vec<u8> {
    // dNSName is a IA5String (ASCII DNS name)
    let mut name = vec![0x82]; // IA5String tag
    name.extend_from_slice(&der_len(dns_name.len()));
    name.extend_from_slice(dns_name.as_bytes());
    der_sequence_v(&[name])
}

/// Build a complete Extensions SEQUENCE for an end-entity certificate.
/// Includes: KeyUsage, ExtendedKeyUsage, SubjectKeyIdentifier, SubjectAlternativeName
fn build_end_entity_extensions(spki_bytes: &[u8], dns_name: &str) -> Vec<u8> {
    der_sequence_v(&[
        build_extension(KEY_USAGE_OID, true, &build_key_usage(true)),
        build_extension(EXT_KEY_USAGE_OID, false, &build_ext_key_usage()),
        build_extension(SUBJECT_KEY_ID_OID, false, &build_subject_key_id(spki_bytes)),
        build_extension(
            SUBJECT_ALT_NAME_OID,
            false,
            &build_subject_alt_name(dns_name),
        ),
    ])
}

fn der_algorithm_identifier() -> Vec<u8> {
    // SEQUENCE { OID, NULL } - uses SM2 signature OID
    let oid = encode_oid(SM2_SIG_OID);
    der_sequence(&[oid, vec![0x05, 0x00]].concat())
}

fn der_algorithm_identifier_for_spki() -> Vec<u8> {
    // SEQUENCE { OID, NULL } - uses SM2 public key OID for SPKI
    let oid = encode_oid(SM2_PK_OID);
    der_sequence(&[oid, vec![0x05, 0x00]].concat())
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

fn build_tbs_certificate(
    serial: &[u8],
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
    issuer_cn: &[u8],
    subject_der: &[u8],
    spki_bytes: &[u8],
    extensions: Option<Vec<u8>>,
) -> Result<Vec<u8>, CaError> {
    // [0] EXPLICIT version v3
    let version_inner = der_integer_positive(&[0x03]);
    let version = der_explicit_context(0, &version_inner);

    // SerialNumber
    let serial_der = der_integer_positive(serial);

    // Signature AlgorithmIdentifier
    let sig_alg = der_algorithm_identifier();

    // Issuer Name
    let issuer = der_name(issuer_cn);

    // Validity
    let validity = der_sequence(&[utctime(not_before), utctime(not_after)].concat());

    // Subject (use raw DER from CSR)
    let subject = subject_der.to_vec();

    // SubjectPublicKeyInfo - properly DER-encoded as SEQUENCE { AlgorithmIdentifier, BIT_STRING }
    let spki_alg = der_algorithm_identifier_for_spki();
    let spki_key = der_bit_string(spki_bytes);
    let spki = der_sequence(&[spki_alg, spki_key].concat());

    // Build TBSCertificate
    let mut tbs_parts: Vec<Vec<u8>> = vec![
        version, serial_der, sig_alg, issuer, validity, subject, spki,
    ];

    // Append [3] EXPLICIT Extensions if present
    if let Some(exts) = extensions {
        tbs_parts.push(der_explicit_context(3, &exts));
    }

    Ok(der_sequence_v(&tbs_parts))
}

fn build_certificate_der(tbs: &[u8], signature: &[u8]) -> Vec<u8> {
    let sig_alg = der_algorithm_identifier();
    let sig_bits = der_bit_string(signature);
    der_sequence(&[tbs.to_vec(), sig_alg, sig_bits].concat())
}
