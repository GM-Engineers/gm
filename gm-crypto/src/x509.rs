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
