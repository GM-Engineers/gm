//! X.509 Certificate parsing utilities

use crate::error::CryptoError;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

/// SubjectAlternativeName OID: 2.5.29.17
const SUBJECT_ALT_NAME_OID: &[u8] = &[0x55, 0x1D, 0x11];

/// Parsed certificate info for renewal / re-issuance
pub struct CertInfo {
    /// Raw DER bytes of the subject DN
    pub subject_der: Vec<u8>,
    /// Raw bytes of the SubjectPublicKeyInfo (SPKI) - used to embed the public key in new cert
    pub spki_bytes: Vec<u8>,
    /// Certificate expiration time (not_after) for renewal validation
    pub not_after: OffsetDateTime,
    /// DNS name from SubjectAlternativeName extension, if present
    pub san_dns_name: Option<String>,
    /// Serial number as lowercase hex string (e.g. "1a2b3c...")
    pub serial_hex: Option<String>,
}

/// Parse a PEM-encoded X.509 certificate and extract info needed for renewal.
///
/// Returns subject DER, public key bytes, and expiration time.
pub fn parse_cert_pem(cert_pem: &str) -> Result<CertInfo, CryptoError> {
    let (_, pem_obj) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| CryptoError::Sm2Error(format!("PEM parse failed: {}", e)))?;
    let (_, cert) = X509Certificate::from_der(&pem_obj.contents)
        .map_err(|e| CryptoError::Sm2Error(format!("certificate parse failed: {}", e)))?;
    let subject_der = cert.subject.as_raw().to_vec();
    let spki_bytes = cert.subject_pki.subject_public_key.data.to_vec();
    let not_after = cert.validity().not_after.to_datetime();

    // Extract SubjectAlternativeName DNS name if present for re-embedding in renewed cert
    let san_dns_name: Option<String> = {
        use x509_parser::extensions::GeneralName;
        cert.extensions()
            .iter()
            .find(|ext| ext.oid.as_bytes() == SUBJECT_ALT_NAME_OID)
            .and_then(|ext| {
                // ext.value is the raw bytes of the OCTET STRING for this extension
                // It contains a SEQUENCE OF GeneralName - parse it to find dNSName
                use x509_parser::prelude::FromDer;
                if let Ok((_, names)) = Vec::<GeneralName>::from_der(ext.value) {
                    for name in names {
                        if let GeneralName::DNSName(dns) = name {
                            return Some(dns.to_string());
                        }
                    }
                }
                None
            })
    };

    Ok(CertInfo {
        subject_der,
        spki_bytes,
        not_after,
        san_dns_name,
        serial_hex: Some(cert.serial.to_string()),
    })
}

/// Extract the raw SM2 public key bytes (65 bytes, uncompressed 0x04 || x || y)
/// from a DER-encoded X.509 certificate's SubjectPublicKeyInfo BIT STRING.
///
/// Returns the public-key bytes WITHOUT the BIT STRING tag/length/unused-bits
/// prefix, i.e. the exact bytes needed by `gm_crypto::sm2::Sm2Encryptor::new`
/// or `Sm2Verifier::new`.
pub fn extract_sm2_pubkey_from_der(cert_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| CryptoError::Sm2Error(format!("certificate DER parse failed: {}", e)))?;
    // x509-parser exposes BIT STRING content separately from the trailing-bits
    // count, so `raw.data` is already the point octets (no leading unused-bits
    // byte). DER rules require unused_bits==0, but gmSSL has historically
    // emitted SPKI BIT STRINGs with non-zero trailing-bits counts (e.g. 4 when
    // the high nibble of the last byte is zero). Mask those bits defensively
    // so downstream parsers see canonical bytes.
    let unused = cert.subject_pki.subject_public_key.unused_bits as usize;
    if unused > 7 {
        return Err(CryptoError::Sm2Error(format!(
            "BIT STRING unused-bits count {} exceeds 7",
            unused
        )));
    }
    let mut pk: Vec<u8> = cert.subject_pki.subject_public_key.data.to_vec();
    if unused > 0 {
        if let Some(last) = pk.last_mut() {
            *last &= !(0xFFu8 >> (8 - unused));
        }
    }
    if pk.len() != 65 || pk[0] != 0x04 {
        return Err(CryptoError::Sm2Error(format!(
            "SM2 public key must be 65-byte uncompressed point, got {} bytes starting with {:02x}",
            pk.len(),
            pk.first().copied().unwrap_or(0)
        )));
    }
    Ok(pk.to_vec())
}
