//! Signature verification helpers for the TLCP handshake.
//!
//! Houses the [`verify_ske_signature`] free function that handles both
//! the ECDHE and the ECC ServerKeyExchange signature paths, plus
//! [`extract_sm2_pubkey_from_cert_der`] for pulling the SM2 pubkey out
//! of an X.509 cert's SubjectPublicKeyInfo.

use crate::error::TlcpError;
use crate::tlcp::constants::TLCP_ECH_PARAMS_PREFIX;
use crate::tlcp::messages::TlcpServerKeyExchange;

/// Verify the ServerKeyExchange signature, branching on key-exchange mode.
///
/// - ECDHE mode: body = `1B pub_len || pub || 2B sig_len || sig`,
///   signature covers `client_random || server_random || ephemeral_pub`.
/// - ECC   mode: body = `2B sig_len || sig`,
///   signature covers `client_random || server_random || enc_cert_header || enc_cert`
///   where `enc_cert_header = 3-byte big-endian length(enc_cert_der)`.
pub(crate) fn verify_ske_signature(
    is_ecc_mode: bool,
    ske_body: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    enc_cert: &[u8],
    verifier: &gm_crypto::sm2::Sm2Verifier,
) -> Result<(), TlcpError> {
    if is_ecc_mode {
        // body = 2-byte sig length prefix + signature DER bytes.
        if ske_body.len() < 2 {
            return Err(TlcpError::InvalidMessage(
                "ECC SKE body too short".to_string(),
            ));
        }
        let sig_len = ((ske_body[0] as usize) << 8) | ske_body[1] as usize;
        if ske_body.len() < 2 + sig_len {
            return Err(TlcpError::InvalidMessage(format!(
                "ECC SKE signature truncated: {} < {}",
                ske_body.len() - 2,
                sig_len
            )));
        }
        let signature_der = &ske_body[2..2 + sig_len];
        // gmSSL emits SM2 signatures in DER (ASN.1) form; our sm2 crate verifier
        // wants the raw r||s concatenation (64 bytes), so convert first.
        let signature_raw =
            gm_crypto::sm2::sm2_signature_der_to_raw(signature_der).map_err(|e| {
                TlcpError::HandshakeFailed(format!("ECC SKE signature DER decode: {}", e))
            })?;
        // Build the message that was signed: cr || sr || enc_cert_header || enc_cert
        let mut msg = Vec::with_capacity(32 + 32 + 3 + enc_cert.len());
        msg.extend_from_slice(client_random);
        msg.extend_from_slice(server_random);
        let cert_len = enc_cert.len() as u32;
        msg.push((cert_len >> 16) as u8);
        msg.push((cert_len >> 8) as u8);
        msg.push(cert_len as u8);
        msg.extend_from_slice(enc_cert);
        verifier
            .verify(&msg, &signature_raw)
            .map_err(|e| TlcpError::HandshakeFailed(format!("ECC SKE signature verify: {}", e)))
    } else {
        // ECDHE path: parse Sm2EcdheParams. gmSSL emits DER signatures
        // too, so decode before passing to the raw-format verifier.
        let ske = TlcpServerKeyExchange::from_body(ske_body)?;
        let raw_sig = gm_crypto::sm2::sm2_signature_der_to_raw(&ske.ecdhe_params.signature)
            .map_err(|e| {
                TlcpError::HandshakeFailed(format!("ECDHE SKE signature DER decode: {}", e))
            })?;
        // Build signed message: cr || sr || server_ecdh_params (the full
        // RFC 4492 ECParameters blob on the wire, NOT just the raw 65-byte
        // public key). GmSSL 2026-06+ master signs the ECParameters
        // envelope, so we must reproduce those exact bytes when verifying.
        let mut msg = Vec::with_capacity(
            32 + 32 + TLCP_ECH_PARAMS_PREFIX.len() + 1 + ske.ecdhe_params.ephemeral_public.len(),
        );
        msg.extend_from_slice(client_random);
        msg.extend_from_slice(server_random);
        msg.extend_from_slice(&TLCP_ECH_PARAMS_PREFIX);
        msg.push(ske.ecdhe_params.ephemeral_public.len() as u8);
        msg.extend_from_slice(&ske.ecdhe_params.ephemeral_public);
        verifier
            .verify(&msg, &raw_sig)
            .map_err(|e| TlcpError::HandshakeFailed(format!("ECDHE SKE signature verify: {}", e)))
    }
}

/// Thin wrapper around `gm_crypto::x509::extract_sm2_pubkey_from_der`
/// that returns `String` (matches `connect_with_certs` error-mapping style).
#[allow(clippy::items_after_test_module)]
pub(crate) fn extract_sm2_pubkey_from_cert_der(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    gm_crypto::x509::extract_sm2_pubkey_from_der(cert_der)
        .map_err(|e| format!("SM2 pubkey extract: {}", e))
}
