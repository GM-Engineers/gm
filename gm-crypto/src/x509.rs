//! X.509 Certificate parsing utilities + PKCS#10 CSR generation.

use crate::error::CryptoError;
use crate::sm2::{GM_TLS_DEFAULT_ID, Sm2KeyPair, Sm2Signer};
use gm_der::{der_bit_string, der_len, der_sequence, der_set, der_utf8_string, encode_oid};
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

// =============================================================================
// PKCS#10 CertificationRequest generation (RFC 2986)
//
// The CSRs produced here are wire-compatible with:
//   - gm-ca's `CaSigner::sign_csr_with_profile(csr_pem, days, &profile)`
//     (which round-trips through x509-parser before signing).
//   - GmSSL master `gmssl req` (the standard SM2 SPKI + sigAlg encoding).
//   - openHiTLS / Tongsuo TLCP / TLS 1.3 + SM cert chain tooling.
//
// We do NOT support RSA CSR signing here. RSA cert issuance lives in
// gm-ca's `rsa` feature flag (Phase 4+).
// =============================================================================

// SM2 signature OID: 1.2.156.10197.1.501 = 2A 8C D8 E3 65 6A 02 01 F5
const SM2_SIG_OID_CSR: &[u8] = &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x02, 0x01, 0xF5];
// SM2 public key OID: 1.2.156.10197.1.301 = 2A 8C D8 E3 65 6A 01 01
const SM2_PK_OID_CSR: &[u8] = &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x01, 0x01];
// CN OID: 2.5.4.3 = 55 04 03
const CN_OID_CSR: &[u8] = &[0x55, 0x04, 0x03];

/// PKCS#10 CertificationRequest builder (RFC 2986).
///
/// Builds an SM2-signed CSR with a single-CN subject DN. The signature
/// uses the GM/TLS standard distid (`"1234567812345678"`), matching
/// GmSSL / Tongsuo / openHiTLS conventions.
///
/// # Example
///
/// ```ignore
/// use gm_crypto::sm2::Sm2KeyPair;
/// use gm_crypto::x509::CsrBuilder;
///
/// let keypair = Sm2KeyPair::generate()?;
/// let pubkey_65 = keypair.public_key_bytes_uncompressed();
/// let csr_pem = CsrBuilder::new_sm2("server.example.com", &pubkey_65)?
///     .build_pem(&keypair)?;
/// // csr_pem can now be fed to gm-ca's `sign_csr_with_profile`,
/// // or saved to disk and presented to any RFC-2986-compliant CA.
/// # Ok::<(), gm_crypto::error::CryptoError>(())
/// ```
pub struct CsrBuilder {
    subject_cn: String,
    sm2_pubkey_65: Vec<u8>,
}

impl std::fmt::Debug for CsrBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsrBuilder")
            .field("subject_cn", &self.subject_cn)
            .field("sm2_pubkey_65_len", &self.sm2_pubkey_65.len())
            .finish()
    }
}

impl CsrBuilder {
    /// Build an SM2 CSR builder.
    ///
    /// `subject_cn` is the subject Common Name (UTF8String in the DN).
    /// `sm2_pubkey_65` is the 65-byte uncompressed SEC1 SM2 public key
    /// (`04 || x || y`) — what `extract_sm2_pubkey_from_der` returns,
    /// or `Sm2KeyPair::public_key_bytes_uncompressed()`.
    ///
    /// Validates the public key byte length and prefix at construction
    /// time so the first failure mode is the earliest possible call.
    pub fn new_sm2(
        subject_cn: impl Into<String>,
        sm2_pubkey_65: &[u8],
    ) -> Result<Self, CryptoError> {
        if sm2_pubkey_65.len() != 65 || sm2_pubkey_65[0] != 0x04 {
            return Err(CryptoError::Sm2Error(format!(
                "SM2 public key must be 65-byte uncompressed point (0x04 || x || y), got {} bytes starting with {:02x}",
                sm2_pubkey_65.len(),
                sm2_pubkey_65.first().copied().unwrap_or(0)
            )));
        }
        Ok(Self {
            subject_cn: subject_cn.into(),
            sm2_pubkey_65: sm2_pubkey_65.to_vec(),
        })
    }

    /// Get the subject CN (read-only).
    pub fn subject_cn(&self) -> &str {
        &self.subject_cn
    }

    /// Get the 65-byte uncompressed SM2 public key (read-only).
    pub fn sm2_pubkey(&self) -> &[u8] {
        &self.sm2_pubkey_65
    }

    /// Build the unsigned CertificationRequestInfo DER body.
    ///
    /// This is the bytes that get signed. Calling `build_cri_der` directly
    /// is only useful if you want to sign externally (e.g., with an HSM
    /// or for negative tests where you want to construct a CSR with a
    /// tampered signature).
    ///
    /// Layout per RFC 2986 §4.1:
    /// ```text
    /// CertificationRequestInfo ::= SEQUENCE {
    ///     version       INTEGER (0),
    ///     subject       Name,
    ///     subjectPKInfo SubjectPublicKeyInfo,
    ///     attributes    [0] IMPLICIT Attributes
    /// }
    /// ```
    /// The `attributes` field is always emitted as the empty SEQUENCE
    /// (`A0 00`). Extensions / challengePassword go in `[0] IMPLICIT
    /// SET OF Attribute` and are not currently supported by this builder.
    pub fn build_cri_der(&self) -> Vec<u8> {
        // Subject Name: SEQUENCE { SET { SEQUENCE { OID(CN=2.5.4.3), UTF8String } } }
        let atv = der_sequence(
            &[
                encode_oid(CN_OID_CSR),
                der_utf8_string(self.subject_cn.as_bytes()),
            ]
            .concat(),
        );
        let set = der_set(&[atv]);
        let subject = der_sequence(&[set].concat());

        // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        // AlgorithmIdentifier: SEQUENCE { OID(SM2_PK=1.2.156.10197.1.301), NULL }
        let alg_id = der_sequence(&[encode_oid(SM2_PK_OID_CSR), vec![0x05, 0x00]].concat());
        // BIT STRING { 0x00 unused-bits, <65-byte uncompressed point> }
        let bs = der_bit_string(&self.sm2_pubkey_65);
        let spki = der_sequence(&[alg_id, bs].concat());

        // CRI: SEQUENCE { version(INTEGER 0), subject, spki, [0] empty attrs }
        // INTEGER 0 = 02 01 00
        let version = vec![0x02, 0x01, 0x00];
        // [0] IMPLICIT empty attributes = A0 00
        let attrs = vec![0xA0, 0x00];

        der_sequence(&[version, subject, spki, attrs].concat())
    }

    /// Sign the CRI with `key_pair` and return the full CSR DER.
    ///
    /// Signature algorithm: SM3withSM2 (OID 1.2.156.10197.1.501) with
    /// the GM/TLS standard distid `"1234567812345678"`.
    ///
    /// Full CSR layout per RFC 2986 §4.2:
    /// ```text
    /// CertificationRequest ::= SEQUENCE {
    ///     certificationRequestInfo  CertificationRequestInfo,
    ///     signatureAlgorithm        AlgorithmIdentifier,
    ///     signature                 BIT STRING
    /// }
    /// ```
    pub fn sign(&self, key_pair: &Sm2KeyPair) -> Result<Vec<u8>, CryptoError> {
        let cri = self.build_cri_der();
        let signer = Sm2Signer::new_with_distid(key_pair, GM_TLS_DEFAULT_ID)?;
        let sig = signer.sign(&cri)?;

        // sigAlg: SEQUENCE { OID(SM2_SIG=1.2.156.10197.1.501), NULL }
        let sig_alg = der_sequence(&[encode_oid(SM2_SIG_OID_CSR), vec![0x05, 0x00]].concat());

        // sigValue: BIT STRING { 0x00 unused-bits, <64-byte SM2 signature> }
        let mut sig_value = vec![0x03];
        sig_value.extend_from_slice(&der_len(1 + sig.len()));
        sig_value.push(0x00);
        sig_value.extend_from_slice(&sig);

        // Full CSR: SEQUENCE { CRI, sigAlg, sigValue }
        Ok(der_sequence(&[cri, sig_alg, sig_value].concat()))
    }

    /// Sign and PEM-encode the CSR (`-----BEGIN CERTIFICATE REQUEST-----`).
    pub fn build_pem(&self, key_pair: &Sm2KeyPair) -> Result<String, CryptoError> {
        let der = self.sign(key_pair)?;
        Ok(pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", der)))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::certification_request::X509CertificationRequest;

    #[test]
    fn rejects_wrong_pubkey_length() {
        // 64 bytes (missing 0x04 prefix is fine, but length wrong)
        let too_short = vec![0x04; 64];
        let err = CsrBuilder::new_sm2("test", &too_short).unwrap_err();
        assert!(format!("{}", err).contains("65-byte"), "got: {}", err);

        // 66 bytes (too long)
        let too_long = vec![0x04; 66];
        let err = CsrBuilder::new_sm2("test", &too_long).unwrap_err();
        assert!(format!("{}", err).contains("65-byte"), "got: {}", err);

        // Empty
        let empty: &[u8] = &[];
        let err = CsrBuilder::new_sm2("test", empty).unwrap_err();
        assert!(format!("{}", err).contains("65-byte"), "got: {}", err);
    }

    #[test]
    fn rejects_wrong_pubkey_prefix() {
        // 65 bytes but not starting with 0x04 (e.g., compressed 33-byte form
        // would normally be 33 bytes — we're testing 65 bytes with 0x03)
        let wrong_prefix = vec![0x03; 65];
        let err = CsrBuilder::new_sm2("test", &wrong_prefix).unwrap_err();
        assert!(format!("{}", err).contains("uncompressed"), "got: {}", err);
    }

    #[test]
    fn accepts_valid_pubkey() {
        let pubkey = vec![0x04; 65];
        let builder = CsrBuilder::new_sm2("test.example.com", &pubkey).unwrap();
        assert_eq!(builder.subject_cn(), "test.example.com");
        assert_eq!(builder.sm2_pubkey(), pubkey.as_slice());
    }

    #[test]
    fn cri_der_round_trips_via_x509_parser() {
        let key = Sm2KeyPair::generate().expect("gen key");
        let pubkey_65 = key.public_key_bytes_uncompressed();

        let builder = CsrBuilder::new_sm2("server.test", &pubkey_65).unwrap();
        let cri = builder.build_cri_der();

        // x509-parser parses the CRI via X509CertificationRequestInfo.
        // We use X509CertificationRequest (which includes signature) —
        // to test CRI in isolation, prepend a fake sigAlg + sigValue.
        let sig_alg = der_sequence(&[encode_oid(SM2_SIG_OID_CSR), vec![0x05, 0x00]].concat());
        let mut sig_value = vec![0x03, 0x05, 0x00]; // BIT STRING len=5 unused=0, 4-byte placeholder sig
        sig_value.extend_from_slice(&[0u8; 4]);
        let csr_der = der_sequence(&[cri.clone(), sig_alg, sig_value].concat());

        let (_, csr) =
            X509CertificationRequest::from_der(&csr_der).expect("x509-parser should parse");
        // Subject CN must equal what we built
        let subject_str = csr.certification_request_info.subject.to_string();
        assert!(
            subject_str.contains("CN=server.test"),
            "subject string was: {}",
            subject_str
        );
        // SPKI algorithm must be the SM2 OID (1.2.156.10197.1.301)
        let spki_alg = &csr
            .certification_request_info
            .subject_pki
            .algorithm
            .algorithm;
        assert_eq!(spki_alg.as_bytes(), SM2_PK_OID_CSR);
        // SPKI public key bytes must equal our input
        assert_eq!(
            csr.certification_request_info
                .subject_pki
                .subject_public_key
                .data,
            pubkey_65.as_slice()
        );
    }

    #[test]
    fn sign_produces_valid_csr_pem() {
        let key = Sm2KeyPair::generate().expect("gen key");
        let pubkey_65 = key.public_key_bytes_uncompressed();

        let pem_str = CsrBuilder::new_sm2("client.test", &pubkey_65)
            .unwrap()
            .build_pem(&key)
            .expect("build_pem");

        // PEM structure
        assert!(pem_str.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(pem_str.contains("-----END CERTIFICATE REQUEST-----"));

        // Parse PEM with x509-parser
        let pem_obj = x509_parser::pem::parse_x509_pem(pem_str.as_bytes())
            .expect("PEM parse")
            .1;
        assert_eq!(pem_obj.label, "CERTIFICATE REQUEST");
        let csr_der = pem_obj.contents;
        let (_, csr) = X509CertificationRequest::from_der(&csr_der).expect("CSR DER parse");

        // Subject
        let subject_str = csr.certification_request_info.subject.to_string();
        assert!(subject_str.contains("CN=client.test"));

        // Signature algorithm: SM3withSM2
        let sig_alg = csr.signature_algorithm.algorithm;
        assert_eq!(sig_alg.as_bytes(), SM2_SIG_OID_CSR);

        // Verify the signature (x509-parser exposes signature_value.data
        // as the BIT STRING content minus the unused-bits byte).
        let sig_bytes = csr.signature_value.data.as_ref();
        let cri = csr.certification_request_info.raw;
        let verifier =
            crate::sm2::Sm2Verifier::new(&pubkey_65, GM_TLS_DEFAULT_ID).expect("verifier");
        verifier
            .verify(cri, sig_bytes)
            .expect("signature must verify");
    }
}
