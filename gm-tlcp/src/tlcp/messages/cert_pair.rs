//! TLCP dual certificate pair.
//!
//! GB/T 38636-2020 requires **two** certificates from the server:
//!
//! 1. A **signing** certificate (auth + CertificateVerify signature).
//! 2. An **encryption** certificate (key encapsulation for ECC mode).
//!
//! In ECDHE mode, the encryption cert's public key is also used to
//! derive the SM2 Z value when verifying the ServerKeyExchange
//! signature, per GB/T 38636-2020 §6.4.1.5.
//!
//! The wire format for the `Certificate` handshake message is the
//! dual-cert list
//! `[total_length(3) | sign_entry(3+N) | enc_entry(3+M)]` matching
//! GmSSL's `tls_send_certificate` byte layout.

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;

/// TLCP dual certificate pair
///
/// GB/T 38636-2020 requires separate signing and encryption certificates.
/// The signing certificate is used for authentication (CertificateVerify),
/// and the encryption certificate is used for key encapsulation.
#[derive(Debug, Clone)]
pub struct TlcpCertPair {
    /// Signing certificate (DER encoded)
    pub sign_cert: Vec<u8>,
    /// Encryption certificate (DER encoded)
    pub enc_cert: Vec<u8>,
    /// Signing certificate chain (intermediate CAs)
    pub sign_chain: Vec<Vec<u8>>,
    /// Encryption certificate chain (intermediate CAs)
    pub enc_chain: Vec<Vec<u8>>,
}

impl TlcpCertPair {
    /// Create a new dual certificate pair
    pub fn new(sign_cert: Vec<u8>, enc_cert: Vec<u8>) -> Self {
        Self {
            sign_cert,
            enc_cert,
            sign_chain: Vec::new(),
            enc_chain: Vec::new(),
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
        }
    }

    /// Serialize as TLCP Certificate message
    ///
    /// Format: total_length | sign_cert_length | sign_cert | enc_cert_length | enc_cert
    pub fn to_certificate_message(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // Certificate list length (3 bytes)
        let sign_entry_len = 3 + self.sign_cert.len();
        let enc_entry_len = 3 + self.enc_cert.len();
        let total_len = sign_entry_len + enc_entry_len;

        body.extend_from_slice(&total_len.to_be_bytes()[1..4]); // 3-byte length

        // Signing certificate
        let sign_cert_len = self.sign_cert.len() as u32;
        body.push((sign_cert_len >> 16) as u8);
        body.push((sign_cert_len >> 8) as u8);
        body.push(sign_cert_len as u8);
        body.extend_from_slice(&self.sign_cert);

        // Encryption certificate
        let enc_cert_len = self.enc_cert.len() as u32;
        body.push((enc_cert_len >> 16) as u8);
        body.push((enc_cert_len >> 8) as u8);
        body.push(enc_cert_len as u8);
        body.extend_from_slice(&self.enc_cert);

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
            if certs.len() >= 2 {
                break;
            }
        }
        if certs.len() < 2 {
            return Err(TlcpError::InvalidMessage(format!(
                "need at least 2 certs (sign + enc), got {}",
                certs.len()
            )));
        }
        let sign_cert = certs.remove(0);
        let enc_cert = certs.remove(0);
        Ok(Self {
            sign_cert,
            enc_cert,
            sign_chain: Vec::new(),
            enc_chain: Vec::new(),
        })
    }
}
