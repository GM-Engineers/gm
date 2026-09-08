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
        // ECDHE path: parse Sm2EcdheParams. SM2 signatures come in two
        // wire formats depending on the producer:
        //   - GmSSL 2026-06+ master: raw r||s, 64 bytes (no DER framing).
        //   - GmSSL 3.x / Tongsuo 8.3.0 / our own `Sm2Signer::sign`:
        //     raw r||s, 64 bytes.
        //   - Some X.509 / CMS profiles: DER (`0x30 0x46 0x02 0x21 ...`).
        //
        // We accept both: if the signature is exactly 64 bytes we treat
        // it as raw r||s; otherwise we try to parse it as DER. This
        // matches the historical gmssl master behaviour and keeps us
        // compatible with peers that emit DER (e.g. openHiTLS, the
        // Tongsuo built-in verifier).
        let ske = TlcpServerKeyExchange::from_body(
            ske_body,
            crate::tlcp::cipher_suite::KeyExchangeMode::Ecdhe,
        )?;
        let ecdhe_params = ske.as_ecdhe().ok_or_else(|| {
            TlcpError::InvalidMessage(
                "ECDHE verify called on non-ECDHE ServerKeyExchange body".to_string(),
            )
        })?;
        let raw_sig: [u8; 64] = if ecdhe_params.signature.len() == 64 {
            let mut a = [0u8; 64];
            a.copy_from_slice(&ecdhe_params.signature);
            a
        } else {
            gm_crypto::sm2::sm2_signature_der_to_raw(&ecdhe_params.signature).map_err(|e| {
                TlcpError::HandshakeFailed(format!("ECDHE SKE signature DER decode: {}", e))
            })?
        };
        // Build signed message: cr || sr || server_ecdh_params (the full
        // RFC 4492 ECParameters blob on the wire, NOT just the raw 65-byte
        // public key). GmSSL 2026-06+ master signs the ECParameters
        // envelope, so we must reproduce those exact bytes when verifying.
        let mut msg = Vec::with_capacity(
            32 + 32 + TLCP_ECH_PARAMS_PREFIX.len() + 1 + ecdhe_params.ephemeral_public.len(),
        );
        msg.extend_from_slice(client_random);
        msg.extend_from_slice(server_random);
        msg.extend_from_slice(&TLCP_ECH_PARAMS_PREFIX);
        msg.push(ecdhe_params.ephemeral_public.len() as u8);
        msg.extend_from_slice(&ecdhe_params.ephemeral_public);
        verifier
            .verify(&msg, &raw_sig)
            .map_err(|e| TlcpError::HandshakeFailed(format!("ECDHE SKE signature verify: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_crypto::sm2::Sm2KeyPair;

    /// Build the standard signed-input byte string for the ECC SKE variant:
    ///   `cr ∥ sr ∥ (3-byte big-endian len(enc_cert_der)) ∥ enc_cert_der`.
    fn ecc_signed_input(cr: &[u8; 32], sr: &[u8; 32], enc_cert: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(32 + 32 + 3 + enc_cert.len());
        msg.extend_from_slice(cr);
        msg.extend_from_slice(sr);
        let cert_len = enc_cert.len() as u32;
        msg.push((cert_len >> 16) as u8);
        msg.push((cert_len >> 8) as u8);
        msg.push(cert_len as u8);
        msg.extend_from_slice(enc_cert);
        msg
    }

    /// Build the body bytes for the ECC SKE variant:
    ///   `uint16 sig_len ∥ sig_der`.
    fn ecc_ske_body(sig_der: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(2 + sig_der.len());
        body.extend_from_slice(&(sig_der.len() as u16).to_be_bytes());
        body.extend_from_slice(sig_der);
        body
    }

    #[test]
    fn verify_ske_signature_ecc_path_accepts_correct_sig() {
        // Generate a real sign keypair; sign the standard ECC SKE input.
        let sign_kp = Sm2KeyPair::generate().expect("sm2 keypair generate");
        let sign_signer = gm_crypto::sm2::Sm2Signer::new(&sign_kp).expect("signer");
        let distid = sign_kp.distid();
        let verifier = gm_crypto::sm2::Sm2Verifier::new(&sign_kp.public_key_bytes(), distid)
            .expect("verifier");

        let client_random = [0xAAu8; 32];
        let server_random = [0xBBu8; 32];
        // Use a fake but well-formed enc_cert (just bytes — the verifier
        // hashes them as part of the signed input but doesn't validate the
        // DER structure).
        let enc_cert: Vec<u8> = (0u8..=200).collect();

        let signed_input = ecc_signed_input(&client_random, &server_random, &enc_cert);
        // Sign produces raw r||s (64 bytes). The verify_ske_signature ECC
        // path expects DER; convert raw to DER.
        let raw_sig = sign_signer.sign(&signed_input).expect("sign");
        let raw_arr: [u8; 64] = raw_sig.as_slice().try_into().expect("64-byte raw sig");
        let sig_der = gm_crypto::sm2::sm2_signature_raw_to_der(&raw_arr);

        let body = ecc_ske_body(&sig_der);
        verify_ske_signature(
            true, /* is_ecc_mode */
            &body,
            &client_random,
            &server_random,
            &enc_cert,
            &verifier,
        )
        .expect("verification should succeed for correctly-signed ECC SKE");
    }

    #[test]
    fn verify_ske_signature_ecc_path_rejects_bad_sig() {
        let sign_kp = Sm2KeyPair::generate().expect("sm2 keypair generate");
        let sign_signer = gm_crypto::sm2::Sm2Signer::new(&sign_kp).expect("signer");
        let verifier =
            gm_crypto::sm2::Sm2Verifier::new(&sign_kp.public_key_bytes(), sign_kp.distid())
                .expect("verifier");

        let client_random = [0xAAu8; 32];
        let server_random = [0xBBu8; 32];
        let enc_cert: Vec<u8> = (0u8..=200).collect();

        // Sign the correct input then flip 1 byte in the signature.
        let signed_input = ecc_signed_input(&client_random, &server_random, &enc_cert);
        let raw_sig = sign_signer.sign(&signed_input).expect("sign");
        let raw_arr: [u8; 64] = raw_sig.as_slice().try_into().expect("64-byte raw sig");
        let mut sig_der = gm_crypto::sm2::sm2_signature_raw_to_der(&raw_arr);
        let last = sig_der.len() - 1;
        sig_der[last] ^= 0xFF;
        let body = ecc_ske_body(&sig_der);
        assert!(
            verify_ske_signature(
                true,
                &body,
                &client_random,
                &server_random,
                &enc_cert,
                &verifier
            )
            .is_err(),
            "ECC SKE with tampered signature byte must be rejected"
        );
    }

    #[test]
    fn verify_ske_signature_ecc_path_rejects_truncated_body() {
        let client_random = [0u8; 32];
        let server_random = [0u8; 32];
        let enc_cert = vec![0u8; 16];
        // Sign a dummy verifier just so the call doesn't fail at the
        // verifier-construction step. We test only the body-length guard.
        let sign_kp = Sm2KeyPair::generate().expect("sm2 keypair generate");
        let verifier =
            gm_crypto::sm2::Sm2Verifier::new(&sign_kp.public_key_bytes(), sign_kp.distid())
                .expect("verifier");

        // body = 1 byte (less than the 2-byte sig_len prefix)
        assert!(
            verify_ske_signature(
                true,
                &[0x00],
                &client_random,
                &server_random,
                &enc_cert,
                &verifier
            )
            .is_err(),
            "ECC SKE body shorter than 2 bytes must be rejected"
        );
        // body = uint16(10) || (no payload bytes)
        assert!(
            verify_ske_signature(
                true,
                &[0x00, 0x0A],
                &client_random,
                &server_random,
                &enc_cert,
                &verifier
            )
            .is_err(),
            "ECC SKE body whose declared sig_len exceeds actual length must be rejected"
        );
    }
}

/// Thin wrapper around `gm_crypto::x509::extract_sm2_pubkey_from_der`
/// that returns `String` (matches `connect_with_certs` error-mapping style).
#[allow(clippy::items_after_test_module)]
pub(crate) fn extract_sm2_pubkey_from_cert_der(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    gm_crypto::x509::extract_sm2_pubkey_from_der(cert_der)
        .map_err(|e| format!("SM2 pubkey extract: {}", e))
}
