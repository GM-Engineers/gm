//! TLCP dual certificate pair.
//!
//! GB/T 38636-2020 requires **two** certificates from the server:
//!
//! 1. A **signing** certificate (auth + CertificateVerify signature).
//! 2. An **encryption** certificate (key encapsulation for ECC mode).
//!
//! In ECDHE mode, the encryption cert's public key is used together
//! with the client's enc key + ephemeral to derive the SM2 ECDHE
//! pre-master secret (see `tlcp::pms::compute_tlcp_ecdhe_pms`). The Z
//! values used for the SKE signature verification are derived from
//! the SIGN cert's public key (configured via
//! [`crate::tlcp::TlcpConnector::with_server_sign_key`]).
//!
//! The wire format for the `Certificate` handshake message is the
//! dual-cert list
//! `[total_length(3) | sign_entry(3+N) | enc_entry(3+M)]` matching
//! GmSSL's `tls_send_certificate` byte layout.

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;

/// Certificate layout mode for a [`TlcpCertPair`].
///
/// GB/T 38636-2020 §6.4.5.5 specifies that the `Certificate` handshake
/// message contains **two** cert entries for static-ECC / ECDHE / SM9
/// suites (signing + encryption) but **one** cert entry for static-key
/// RSA suites. This enum tags which layout a `TlcpCertPair` instance
/// represents.
///
/// The mode is set by the constructors ([`TlcpCertPair::new`] /
/// `with_chains` produce `Dual`; [`TlcpCertPair::new_single`] produces
/// `Single`) and auto-detected by [`TlcpCertPair::from_certificate_message`]
/// based on the observed cert-entry count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertMode {
    /// Dual cert entries (sign + enc). Default for SM2 / SM9 suites.
    Dual,
    /// Single cert entry. Used for the 4 RSA suites per §6.4.5.5.
    Single,
}

/// TLCP certificate pair
///
/// GB/T 38636-2020 requires separate signing and encryption certificates
/// for static-ECC / ECDHE / SM9 suites, but only a single certificate for
/// static-key RSA suites (see the internal `CertMode` enum and §6.4.5.5).
///
/// The signing certificate is used for authentication (CertificateVerify),
/// and the encryption certificate is used for key encapsulation. Use
/// [`TlcpCertPair::is_single_cert`] to detect single-Cert layout (RSA
/// suites per §6.4.5.5).
#[derive(Debug, Clone)]
pub struct TlcpCertPair {
    /// Signing certificate (DER encoded). For the single-Cert layout (RSA
    /// suites per §6.4.5.5), this is the only certificate (the RSA cert).
    pub sign_cert: Vec<u8>,
    /// Encryption certificate (DER encoded). Empty (`b""`) in
    /// single-Cert mode — the second slot is omitted from the
    /// wire format per §6.4.5.5.
    pub enc_cert: Vec<u8>,
    /// Signing certificate chain (intermediate CAs)
    pub sign_chain: Vec<Vec<u8>>,
    /// Encryption certificate chain (intermediate CAs). Empty in
    /// single-Cert mode.
    pub enc_chain: Vec<Vec<u8>>,
    /// Layout mode (private; set by constructors / parser).
    mode: CertMode,
}

impl TlcpCertPair {
    /// Create a new dual certificate pair
    pub fn new(sign_cert: Vec<u8>, enc_cert: Vec<u8>) -> Self {
        Self {
            sign_cert,
            enc_cert,
            sign_chain: Vec::new(),
            enc_chain: Vec::new(),
            mode: CertMode::Dual,
        }
    }

    /// Create a new single-certificate pair for RSA suites
    /// (E019/E01C/E059/E05A, R-7).
    ///
    /// Per GB/T 38636-2020 §6.4.5.5, RSA suites use exactly one
    /// certificate entry in the `Certificate` handshake message. This
    /// constructor builds a [`TlcpCertPair`] that serializes to that
    /// single-entry layout (matches openHiTLS / Tongsuo convention).
    ///
    /// Wire format: `total_length(3) | sign_cert_length(3) | sign_cert`.
    /// The encryption slot is omitted.
    pub fn new_single(cert: Vec<u8>) -> Self {
        Self {
            sign_cert: cert,
            enc_cert: Vec::new(),
            sign_chain: Vec::new(),
            enc_chain: Vec::new(),
            mode: CertMode::Single,
        }
    }

    /// Create with certificate chains
    pub fn with_chains(
        sign_cert: Vec<u8>,
        enc_cert: Vec<u8>,
        sign_chain: Vec<Vec<u8>>,
        enc_chain: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            sign_cert,
            enc_cert,
            sign_chain,
            enc_chain,
            mode: CertMode::Dual,
        }
    }

    /// Returns true iff this pair represents the single-Cert layout
    /// used by RSA suites (GB/T 38636-2020 §6.4.5.5, R-7).
    pub fn is_single_cert(&self) -> bool {
        self.mode == CertMode::Single
    }

    /// Serialize as TLCP Certificate message
    ///
    /// Layout depends on the internal `CertMode` (see [`Self::is_single_cert`]):
    /// - Dual: `total_length(3) | sign_entry(3+N) | enc_entry(3+M)`
    /// - Single: `total_length(3) | sign_entry(3+N)` (RSA suites per
    ///   §6.4.5.5)
    pub fn to_certificate_message(&self) -> Vec<u8> {
        let mut body = Vec::new();

        let sign_entry_len = 3 + self.sign_cert.len();
        // R-7: cast to u32 for stable 4-byte to_be_bytes (matches the
        // original wire-format encoding; the field is logically bounded
        // by 16 MiB-2 which fits u32). Using usize here would give
        // 8-byte big-endian encoding on 64-bit platforms and break the
        // total_length field for any cert-list > 256 bytes.
        let total_len_u32: u32 = match self.mode {
            CertMode::Dual => (sign_entry_len + 3 + self.enc_cert.len()) as u32,
            CertMode::Single => sign_entry_len as u32,
        };

        body.extend_from_slice(&total_len_u32.to_be_bytes()[1..4]); // 3-byte length

        // Signing certificate (always present in both modes)
        let sign_cert_len = self.sign_cert.len() as u32;
        body.push((sign_cert_len >> 16) as u8);
        body.push((sign_cert_len >> 8) as u8);
        body.push(sign_cert_len as u8);
        body.extend_from_slice(&self.sign_cert);

        // Encryption certificate (only in Dual mode)
        if self.mode == CertMode::Dual {
            let enc_cert_len = self.enc_cert.len() as u32;
            body.push((enc_cert_len >> 16) as u8);
            body.push((enc_cert_len >> 8) as u8);
            body.push(enc_cert_len as u8);
            body.extend_from_slice(&self.enc_cert);
        }

        // Wrap in handshake message header
        let mut buf = Vec::with_capacity(4 + body.len());
        buf.push(HandshakeType::Certificate as u8);
        buf.push((body.len() >> 16) as u8);
        buf.push((body.len() >> 8) as u8);
        buf.push(body.len() as u8);
        buf.extend_from_slice(&body);
        buf
    }

    pub fn from_certificate_message(body: &[u8]) -> Result<Self, TlcpError> {
        if body.len() < 3 {
            return Err(TlcpError::InvalidMessage(
                "Certificate body too short".to_string(),
            ));
        }
        let _total_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize;
        // Inline cert entry parsing (avoids free-function scope issues)
        let mut p = 3;
        let mut certs = Vec::new();
        loop {
            if p >= body.len() {
                break;
            }
            if body.len() < p + 3 {
                break;
            }
            let len =
                ((body[p] as usize) << 16) | ((body[p + 1] as usize) << 8) | body[p + 2] as usize;
            p += 3;
            if body.len() < p + len {
                break;
            }
            certs.push(body[p..p + len].to_vec());
            p += len;
            // R-7: accept either 1 cert (RSA suites) or 2 certs (other
            // suites). Previously the parser hard-required 2 certs, which
            // blocked strict-spec RSA peers that send a single cert entry
            // per GB/T 38636-2020 §6.4.5.5.
            if certs.len() >= 2 {
                break;
            }
        }
        match certs.len() {
            1 => {
                // Single-Cert layout (RSA suites per §6.4.5.5).
                let sign_cert = certs.remove(0);
                Ok(Self {
                    sign_cert,
                    enc_cert: Vec::new(),
                    sign_chain: Vec::new(),
                    enc_chain: Vec::new(),
                    mode: CertMode::Single,
                })
            }
            2 => {
                // Dual-Cert layout (static-ECC / ECDHE / SM9 suites).
                let sign_cert = certs.remove(0);
                let enc_cert = certs.remove(0);
                Ok(Self {
                    sign_cert,
                    enc_cert,
                    sign_chain: Vec::new(),
                    enc_chain: Vec::new(),
                    mode: CertMode::Dual,
                })
            }
            n => Err(TlcpError::InvalidMessage(format!(
                "expected 1 (RSA) or 2 (SM2/SM9) certs, got {}",
                n
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_cert_roundtrip() {
        // R-7: TlcpCertPair::new_single(...) → to_certificate_message
        // → from_certificate_message preserves the single-cert layout.
        let cert = vec![0xAAu8; 256];
        let pair = TlcpCertPair::new_single(cert.clone());
        assert!(pair.is_single_cert());
        assert_eq!(pair.sign_cert, cert);
        assert!(pair.enc_cert.is_empty(), "enc_cert should be empty");

        let msg = pair.to_certificate_message();
        // First byte is the handshake type (Certificate = 0x0B).
        assert_eq!(msg[0], HandshakeType::Certificate as u8);

        // Parse the body (skip the 4-byte handshake header).
        let body = &msg[4..];
        let parsed = TlcpCertPair::from_certificate_message(body).expect("parse single-cert body");
        assert!(parsed.is_single_cert(), "parsed should be single-cert");
        assert_eq!(parsed.sign_cert, cert);
        assert!(
            parsed.enc_cert.is_empty(),
            "parsed enc_cert should be empty"
        );
    }

    #[test]
    fn dual_cert_roundtrip() {
        // R-7 regression guard: existing dual-cert behavior preserved.
        let sign = vec![0x01u8; 100];
        let enc = vec![0x02u8; 100];
        let pair = TlcpCertPair::new(sign.clone(), enc.clone());
        assert!(!pair.is_single_cert());

        let msg = pair.to_certificate_message();
        let body = &msg[4..];
        let parsed = TlcpCertPair::from_certificate_message(body).expect("parse dual-cert body");
        assert!(!parsed.is_single_cert(), "parsed should be dual-cert");
        assert_eq!(parsed.sign_cert, sign);
        assert_eq!(parsed.enc_cert, enc);
    }

    #[test]
    fn single_cert_wire_format_is_one_entry() {
        // R-7: GB/T 38636-2020 §6.4.5.5 specifies single-Cert for RSA
        // suites. Verify the wire bytes contain exactly ONE cert entry,
        // not two.
        let cert = vec![0xCCu8; 128];
        let cert_len = cert.len();
        let pair = TlcpCertPair::new_single(cert);
        let msg = pair.to_certificate_message();
        let body = &msg[4..];

        // Body layout: total_length (3B) | sign_cert_length (3B) | sign_cert
        let total_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | (body[2] as usize);
        assert_eq!(
            total_len,
            3 + cert_len,
            "total_length must cover exactly one cert entry"
        );

        // After the first entry, there should be no more bytes.
        assert_eq!(
            body.len(),
            3 + 3 + cert_len,
            "body should contain only the single-cert entry (no enc entry)"
        );
    }

    #[test]
    fn from_certificate_message_accepts_one_or_two_certs() {
        // R-7: parser must accept both layouts.
        let one_cert_body: Vec<u8> = {
            let cert = vec![0xDDu8; 50];
            let mut body = vec![0u8; 3]; // total_len placeholder
            body.push(0); // sign cert len high byte
            body.push(0);
            body.push(cert.len() as u8);
            body.extend_from_slice(&cert);
            let total_len = 3 + cert.len();
            body[0] = (total_len >> 16) as u8;
            body[1] = (total_len >> 8) as u8;
            body[2] = total_len as u8;
            body
        };
        let parsed_one = TlcpCertPair::from_certificate_message(&one_cert_body).expect("1 cert");
        assert!(parsed_one.is_single_cert());

        let two_cert_body: Vec<u8> = {
            let sign = vec![0x01u8; 30];
            let enc = vec![0x02u8; 40];
            let mut body = vec![0u8; 3];
            body.push(0);
            body.push(0);
            body.push(sign.len() as u8);
            body.extend_from_slice(&sign);
            body.push(0);
            body.push(0);
            body.push(enc.len() as u8);
            body.extend_from_slice(&enc);
            let total_len = 3 + sign.len() + 3 + enc.len();
            body[0] = (total_len >> 16) as u8;
            body[1] = (total_len >> 8) as u8;
            body[2] = total_len as u8;
            body
        };
        let parsed_two = TlcpCertPair::from_certificate_message(&two_cert_body).expect("2 certs");
        assert!(!parsed_two.is_single_cert());
    }

    #[test]
    fn from_certificate_message_rejects_empty_or_truncated_body() {
        // R-7: 0 certs (truncated body) must error.
        let empty_body = vec![0u8; 3];
        assert!(TlcpCertPair::from_certificate_message(&empty_body).is_err());

        // A body that claims a length larger than itself must also
        // error out (truncated).
        let mut body = vec![0xFFu8; 3]; // total_length = 0x00FFFFFF
        body.push(0);
        body.push(0);
        body.push(50); // sign_cert_length = 50, but we only have a few bytes
        assert!(TlcpCertPair::from_certificate_message(&body).is_err());
    }

    #[test]
    fn from_certificate_message_silently_truncates_after_two_certs() {
        // R-7: parser behavior preserved from pre-R-7. A peer sending 3+
        // cert entries is a protocol violation but the parser breaks
        // after the 2nd entry (existing behavior). New peers should
        // never send >2 certs; the leniency here is for wire-noise
        // tolerance only.
        let three_cert_body: Vec<u8> = {
            let cert = vec![0x03u8; 10];
            let mut body = vec![0u8; 3];
            for _ in 0..3 {
                body.push(0);
                body.push(0);
                body.push(cert.len() as u8);
                body.extend_from_slice(&cert);
            }
            let total_len_u32: u32 = (body.len() - 3) as u32;
            body[0] = (total_len_u32 >> 16) as u8;
            body[1] = (total_len_u32 >> 8) as u8;
            body[2] = total_len_u32 as u8;
            body
        };
        let parsed = TlcpCertPair::from_certificate_message(&three_cert_body)
            .expect("3-cert body parses as 2-cert (truncation leniency)");
        assert!(!parsed.is_single_cert(), "parsed should be dual-cert");
        assert_eq!(parsed.sign_cert.len(), 10);
        assert_eq!(parsed.enc_cert.len(), 10);
    }
}
