//! TLCP `CertificateRequest` message (server -> client).
//!
//! GB/T 38636-2020 §6.4.5.5. The body has two variable-length vectors:
//!
//! ```text
//! struct {
//!     ClientCertificateType certificate_types<1..2^8-1>;
//!     DistinguishedName certificate_authorities<0..2^16-1>;
//! } CertificateRequest;
//! ```
//!
//! `ClientCertificateType` is the same enum as RFC 5246 §7.4.6:
//!
//! ```text
//! enum { rsa_sign(1), ecdsa_sign(64), ibc_params(80), (255) }
//! ```
//!
//! SM2 certificates (signing + encryption) are advertised via
//! `ecdsa_sign` because TLCP carries the certificate type code in the
//! outer certificate-type byte the same way GmSSL master and
//! Tongsuo 8.3.0 do. The `certificate_authorities` vector is empty
//! in this release; the cert chain is supplied directly via
//! `TlcpConnector::with_client_certs`, and verification of the
//! client's sign cert chain is delegated to the caller's CA store.

use crate::error::TlcpError;
use crate::tlcp::HandshakeType;

/// TLCP `CertificateRequest` (server -> client) per GB/T 38636-2020 §6.4.5.5.
///
/// We always advertise the same set of certificate types: SM2 dual
/// certs use the `ecdsa_sign(64)` code, which matches GmSSL master and
/// Tongsuo 8.3.0 byte-for-byte.
#[derive(Debug, Clone)]
pub struct TlcpCertificateRequest {
    /// Advertised client certificate types.
    pub cert_types: Vec<u8>,
}

impl Default for TlcpCertificateRequest {
    fn default() -> Self {
        Self {
            // GmSSL master advertises [rsa_sign, ecdsa_sign, ibc_params]
            // for ECDHE suites; we mirror that list for interop.
            cert_types: vec![1, 64, 80],
        }
    }
}

impl TlcpCertificateRequest {
    /// Build the standard CertificateRequest (offering all three
    /// certificate type codes).
    pub fn standard() -> Self {
        Self::default()
    }

    /// Serialize to a complete handshake-record body (i.e. the bytes
    /// **after** the 4-byte handshake header that
    /// `crate::tlcp::write_handshake_record` prepends; the caller is
    /// responsible for wrapping it with the handshake header).
    ///
    /// Layout per §6.4.5.5:
    /// ```text
    /// u8 cert_types_len
    /// u8 cert_types[cert_types_len]
    /// u16 cas_len (=0)
    /// ```
    pub fn body(&self) -> Result<Vec<u8>, TlcpError> {
        if self.cert_types.is_empty() || self.cert_types.len() > 0xFF {
            return Err(TlcpError::HandshakeFailed(format!(
                "CertificateRequest.cert_types must be 1..=255 bytes, got {}",
                self.cert_types.len()
            )));
        }
        let mut body = Vec::with_capacity(1 + self.cert_types.len() + 2);
        body.push(self.cert_types.len() as u8);
        body.extend_from_slice(&self.cert_types);
        body.extend_from_slice(&0u16.to_be_bytes()); // empty CA list
        Ok(body)
    }

    /// Serialize to the full handshake message bytes
    /// (`type=0x0D || 24-bit length || body`).
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlcpError> {
        let body = self.body()?;
        let mut buf = Vec::with_capacity(4 + body.len());
        buf.push(HandshakeType::CertificateRequest as u8);
        buf.push((body.len() >> 16) as u8);
        buf.push((body.len() >> 8) as u8);
        buf.push(body.len() as u8);
        buf.extend_from_slice(&body);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_body_roundtrip() {
        let cr = TlcpCertificateRequest::standard();
        let bytes = cr.to_bytes().unwrap();
        // Header: type(1) + length(3) + body
        assert_eq!(bytes[0], HandshakeType::CertificateRequest as u8);
        let body_len =
            ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        let body = &bytes[4..];
        assert_eq!(body.len(), body_len);
        // cert_types_len = 3
        assert_eq!(body[0], 3);
        assert_eq!(&body[1..4], &[1, 64, 80]);
        // cas_len = 0
        assert_eq!(&body[4..6], &[0, 0]);
    }

    #[test]
    fn empty_cert_types_is_rejected() {
        let cr = TlcpCertificateRequest { cert_types: vec![] };
        assert!(cr.body().is_err());
    }
}
