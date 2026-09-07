//! Verify and append a `CertificateVerify` (CV) message to the
//! server's transcript. The signature covers the transcript hash
//! *up to but excluding CV itself*; on success, the CV message bytes
//! are appended to `server_hs.transcript` so the subsequent
//! Finished-PRF sees the same hash as the client's.
//!
//! Returns `Ok(())` on success or a `TlcpError` describing the
//! failure (malformed body, wrong type, signature mismatch, missing
//! client cert, etc).
//!
//! Extracted as a free function so the calling code in
//! `accept_with_certs` can be expressed as a single
//! `if cv_present { ... } else { ... }` expression that yields
//! `Option<Vec<u8>>` for the post-CKE record without tripping
//! clippy's `needless_late_init` lint.

use crate::error::TlcpError;
use crate::tlcp::handshake_type::HandshakeType;

/// Local copy of `crate::tlcp::parse_handshake_message`.
///
/// The original is a private free function in `tlcp::mod` and not
/// re-exported. CV verification only needs the `type || body` shape;
/// the inlined copy keeps this helper module self-contained.
fn parse_handshake_message_local(
    payload: &[u8],
) -> Result<(HandshakeType, Vec<u8>, &[u8]), TlcpError> {
    if payload.len() < 4 {
        return Err(TlcpError::InvalidMessage(
            "Handshake message too short".to_string(),
        ));
    }
    let msg_type = HandshakeType::try_from(payload[0])?;
    let body_len =
        ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
    if payload.len() < 4 + body_len {
        return Err(TlcpError::InvalidMessage(format!(
            "Handshake body truncated: {} bytes available, {} needed",
            payload.len() - 4,
            body_len
        )));
    }
    Ok((
        msg_type,
        payload[4..4 + body_len].to_vec(),
        &payload[4 + body_len..],
    ))
}

#[cfg(feature = "tlcp-strict")]
pub(crate) fn process_certificate_verify(
    cv_probe_payload: &[u8],
    server_hs: &mut crate::tlcp::handshake::server::TlcpServerHandshake,
    client_sign_distid_override: Option<&str>,
) -> Result<(), TlcpError> {
    let (cv_type, cv_body, _rem) = parse_handshake_message_local(cv_probe_payload)?;
    if cv_type != HandshakeType::CertificateVerify {
        return Err(TlcpError::HandshakeFailed(format!(
            "Expected CertificateVerify, got {:?}",
            cv_type
        )));
    }
    if cv_body.len() < 2 {
        return Err(TlcpError::HandshakeFailed(
            "CertificateVerify body too short".to_string(),
        ));
    }
    let sig_len = ((cv_body[0] as usize) << 8) | cv_body[1] as usize;
    if cv_body.len() < 2 + sig_len {
        return Err(TlcpError::HandshakeFailed(format!(
            "CertificateVerify signature truncated: {} < {}",
            cv_body.len() - 2,
            sig_len
        )));
    }
    let sig_der = &cv_body[2..2 + sig_len];
    // The CV signature covers the transcript up to (but
    // excluding) CV itself; after verification the CV
    // message bytes are appended to the transcript for the
    // Finished-PRF.
    let raw_sig: [u8; 64] = if sig_der.len() == 64 {
        let mut a = [0u8; 64];
        a.copy_from_slice(sig_der);
        a
    } else {
        gm_crypto::sm2::sm2_signature_der_to_raw(sig_der)
            .map_err(|e| TlcpError::HandshakeFailed(format!("CV signature DER decode: {}", e)))?
    };
    let client_sign_cert_der = server_hs.client_certs.first().ok_or_else(|| {
        TlcpError::HandshakeFailed("server received CV but no client Certificate".to_string())
    })?;
    let client_sign_pub =
        crate::tlcp::crypto::verify::extract_sm2_pubkey_from_cert_der(client_sign_cert_der)
            .map_err(TlcpError::HandshakeFailed)?;
    let distid_default: String = "1234567812345678".to_string();
    let distid_str: &str = client_sign_distid_override.unwrap_or(&distid_default);
    let verifier = gm_crypto::sm2::Sm2Verifier::new(&client_sign_pub, distid_str)
        .map_err(|e| TlcpError::HandshakeFailed(format!("CV verifier: {}", e)))?;
    verifier
        .verify(&server_hs.transcript, &raw_sig)
        .map_err(|e| TlcpError::HandshakeFailed(format!("CV signature verify: {}", e)))?;
    server_hs.transcript.extend_from_slice(cv_probe_payload);
    Ok(())
}
