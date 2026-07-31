//! Pure Rust GM TLS implementation (SM2 certificates / SM4-GCM sessions)
//!
//! This module serves as the orchestration layer for GM/TLS handshakes,
//! delegating to specialized modules for specific functionality:
//!
//! - `session_ticket`: Session ticket management (RFC 5077)
//! - `record_layer`: TLS record layer with SM4-GCM
//! - `handshake`: Handshake message types and builders
//! - `cert_verify`: Certificate and CRL verification
//! - `kdf`: Key derivation (HKDF-SM3)

// Re-export serialization from crate module for backward compatibility
pub(crate) mod serialization {
    // Keep these imports to avoid breaking other code that may use them
    #[allow(unused_imports)]
    pub use crate::serialization::{deserialize, serialize};
}

// ============== Re-exports from dedicated modules ==============

// Session ticket management
pub use crate::session_ticket::{
    SessionKeys, SessionTicket, TicketKey, TicketKeySet, create_session_state,
    decrypt_session_ticket, encrypt_session_ticket,
};

// Record layer
pub use crate::record_layer::{GmTlsStream, next_nonce};

// Handshake types and builders
pub use crate::handshake::{
    CertificateVerify, ClientCertificate, ClientHello, Finished, HandshakeOptions,
    HandshakeSecrets, NewSessionTicket, ServerHello, build_client_hello,
    build_client_hello_with_ticket, build_server_hello, compute_transcript_hash,
    compute_transcript_hash_multi, generate_sm2_ephemeral, select_alpn, sign_finished,
    verify_finished,
};

// Certificate and CRL verification
pub use crate::cert_verify::{
    CrlInfo, OwnedCert, validate_cert_pem, verify_cert_chain_sm2_chain, verify_cert_crl, verify_crl,
};
// Key derivation
pub use crate::kdf::{derive_session_keys_sm2, hkdf_sm3};

// ============== Imports for handshake orchestration ==============

use crate::cert_verify::extract_server_pubkey_for_cert_verify;
use crate::der;
use crate::error::TlsError;
use crate::handshake::{
    parse_sm2_pubkey, read_handshake_record, select_client_pubkey_for_finished,
    select_pubkey_for_finished, signer_from_pem_key, signer_from_scalar, write_handshake_record,
};
use crate::metrics::{HandshakeTimer, record_session_resumption};
use crate::session_store::{InMemorySessionStore, SessionStore};
use gm_crypto::sm2::{GM_TLS_DEFAULT_ID, Scalar, Sm2Verifier};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

// ============== Handshake Orchestration ==============

/// Establish GmRust client connection
pub async fn connect_gm_rust<S>(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    domain: Option<&str>,
    alpn: &[String],
    stream: S,
    opts: &HandshakeOptions,
) -> Result<GmTlsStream<S>, TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let domain_str = domain.unwrap_or("unknown");
    let result = connect_gm_rust_inner(cert_pem, key_pem, ca_pem, domain, alpn, stream, opts).await;
    match &result {
        Ok(_) => {
            crate::audit::AuditLogger::auth_success(domain_str, "outbound", "-");
        }
        Err(e) => {
            crate::audit::AuditLogger::auth_failure(domain_str, "outbound", &e.to_string());
        }
    }
    result
}

/// Accept TLS connection
pub async fn accept_gm_rust<S>(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    require_client_auth: bool,
    alpn: &[String],
    stream: S,
    opts: &HandshakeOptions,
) -> Result<GmTlsStream<S>, TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = accept_gm_rust_inner(
        cert_pem,
        key_pem,
        ca_pem,
        require_client_auth,
        alpn,
        stream,
        opts,
    )
    .await;
    match &result {
        Ok(_) => {
            crate::audit::AuditLogger::auth_success("client", "inbound", "-");
        }
        Err(e) => {
            crate::audit::AuditLogger::auth_failure("client", "inbound", &e.to_string());
        }
    }
    result
}

/// Accept TLS connection and return client certificate info
pub async fn accept_gm_rust_with_client_cert<S>(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    require_client_auth: bool,
    alpn: &[String],
    stream: S,
    opts: &HandshakeOptions,
) -> Result<(GmTlsStream<S>, Option<String>, Option<SessionTicket>), TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = accept_gm_rust_inner_with_cert(
        cert_pem,
        key_pem,
        ca_pem,
        require_client_auth,
        alpn,
        stream,
        opts,
    )
    .await;
    match &result {
        Ok((_, client_cn, _)) => {
            let identity = client_cn.as_deref().unwrap_or("client");
            crate::audit::AuditLogger::auth_success(identity, "inbound", "-");
        }
        Err(e) => {
            crate::audit::AuditLogger::auth_failure("client", "inbound", &e.to_string());
        }
    }
    result
}

async fn connect_gm_rust_inner<S>(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    domain: Option<&str>,
    alpn: &[String],
    mut stream: S,
    opts: &HandshakeOptions,
) -> Result<GmTlsStream<S>, TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let timer = HandshakeTimer::new("client");

    debug!(
        role = "client",
        domain = ?domain,
        alpn = ?alpn,
        "starting GM/TLS handshake"
    );

    // Build session store for replay protection
    let session_store: Arc<dyn SessionStore> = if let Some(ref config) = opts.session_store {
        config.build().await?
    } else {
        Arc::new(InMemorySessionStore::new())
    };

    // Attempt session resumption if ticket is provided and can be decrypted
    let (ch, sk_client, _sh_buf): (ClientHello, Scalar, Option<SessionTicket>) =
        if let Some(ref ticket) = opts.session_ticket {
            if let Some(ticket_key) = &opts.session_ticket_key {
                match decrypt_session_ticket(ticket, ticket_key, session_store.clone()).await {
                    Ok(mut state) => {
                        // Valid ticket — use abbreviated handshake (PSK mode).
                        let (ch, _sk) =
                            build_client_hello_with_ticket(alpn, domain, ticket.clone())?;
                        info!("Session ticket valid, attempting resumption");
                        let ch_bytes = ch
                            .to_bytes()
                            .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
                        write_handshake_record(&mut stream, &ch_bytes, &der::VERSION_TLS_1_3)
                            .await?;

                        debug!(
                            role = "client",
                            client_hello_size = ch_bytes.len(),
                            "ClientHello sent"
                        );

                        let sh_buf = read_handshake_record(&mut stream).await?;
                        let sh: ServerHello = ServerHello::from_bytes(&sh_buf)
                            .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;

                        debug!(
                            role = "client",
                            server_hello_size = sh_buf.len(),
                            alpn = ?sh.alpn,
                            require_client_auth = sh.require_client_auth,
                            "ServerHello received"
                        );

                        if sh.eph_pubkey.is_empty() {
                            // Server accepted resumption — use session keys from ticket.
                            record_session_resumption("success");
                            timer.finish("success");
                            // Extract fields from state before moving session_keys
                            let client_ts = state.client_traffic_secret.take();
                            let server_ts = state.server_traffic_secret.take();
                            let mut tls_stream = GmTlsStream::new(
                                stream,
                                state.session_keys.clone(),
                                true, // client
                                None,
                                sh.alpn.clone(),
                            );
                            // Restore traffic secrets for KeyUpdate support on resumed connections
                            if let (Some(cts), Some(sts)) = (client_ts, server_ts) {
                                tls_stream.set_traffic_secrets(cts, sts);
                            }
                            return Ok(tls_stream);
                        }
                        // Server rejected ticket — full handshake is being performed.
                        info!("Server rejected ticket, performing full handshake");
                        record_session_resumption("rejected");
                        let transcript = compute_transcript_hash(&ch_bytes, &sh_buf)?;
                        let server_pk = parse_sm2_pubkey(&sh.eph_pubkey)?;
                        let shared = server_pk * _sk;
                        let secrets = derive_session_keys_sm2(&shared)?;

                        let srv_finished_buf = read_handshake_record(&mut stream).await?;
                        let srv_finished: Finished = Finished::from_bytes(&srv_finished_buf)
                            .map_err(|e| {
                                TlsError::HandshakeFailed(format!("Finished parse failed: {}", e))
                            })?;
                        let srv_pubkey = select_pubkey_for_finished(&sh)?;
                        let verifier = Sm2Verifier::new(srv_pubkey.as_slice(), GM_TLS_DEFAULT_ID)
                            .map_err(|e| {
                            TlsError::HandshakeFailed(format!(
                                "SM2 verifier creation failed: {}",
                                e
                            ))
                        })?;
                        verify_finished(&verifier, &transcript, &srv_finished)?;

                        // In PSK mode, client sends certificate + Finished if required.
                        if !cert_pem.is_empty() {
                            let client_cert = ClientCertificate {
                                cert_chain_pem: cert_pem.to_vec(),
                            };
                            let cert_bytes = client_cert
                                .to_bytes()
                                .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
                            write_handshake_record(&mut stream, &cert_bytes, &der::VERSION_TLS_1_3)
                                .await?;

                            let signer = if !key_pem.is_empty() {
                                signer_from_pem_key(key_pem).map_err(|e| {
                                    TlsError::HandshakeFailed(format!(
                                        "client key parse failed: {}",
                                        e
                                    ))
                                })?
                            } else {
                                signer_from_scalar(&_sk)?
                            };
                            let cli_finished = sign_finished(&signer, &transcript)?;
                            let cli_finished_bytes = cli_finished
                                .to_bytes()
                                .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
                            write_handshake_record(
                                &mut stream,
                                &cli_finished_bytes,
                                &der::VERSION_TLS_1_3,
                            )
                            .await?;
                        }

                        timer.finish("success");
                        let mut tls_stream = GmTlsStream::new(
                            stream,
                            secrets.session_keys,
                            true, // client
                            Some(sh.cert_chain_pem.clone()),
                            sh.alpn.clone(),
                        );
                        tls_stream.set_traffic_secrets(
                            (*secrets.client_traffic_secret).clone(),
                            (*secrets.server_traffic_secret).clone(),
                        );
                        return Ok(tls_stream);
                    }
                    Err(e) => {
                        info!("Session ticket decryption failed ({})", e);
                        let (ch, sk_client) = build_client_hello(alpn, domain)?;
                        (ch, sk_client, None)
                    }
                }
            } else {
                let (ch, sk_client) = build_client_hello(alpn, domain)?;
                (ch, sk_client, None)
            }
        } else {
            let (ch, sk_client) = build_client_hello(alpn, domain)?;
            (ch, sk_client, None)
        };

    let ch_bytes = ch
        .to_bytes()
        .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
    write_handshake_record(&mut stream, &ch_bytes, &der::VERSION_TLS_1_3).await?;

    let sh_buf = read_handshake_record(&mut stream).await?;
    let sh: ServerHello =
        ServerHello::from_bytes(&sh_buf).map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;

    let transcript = compute_transcript_hash(&ch_bytes, &sh_buf)?;

    // If server sent a certificate chain, it must send CertificateVerify before Finished
    let srv_cert_buf = read_handshake_record(&mut stream).await?;
    let srv_cert: ClientCertificate =
        ClientCertificate::from_bytes(&srv_cert_buf).map_err(|e| {
            TlsError::HandshakeFailed(format!("Server Certificate parse failed: {}", e))
        })?;
    let transcript = compute_transcript_hash_multi(&[&transcript, &srv_cert_buf])?;

    if !ca_pem.is_empty() {
        if srv_cert.cert_chain_pem.is_empty() {
            timer.finish("error");
            return Err(TlsError::CertificateVerificationFailed(
                "server did not provide certificate chain".into(),
            ));
        }
        let leaf_chain = OwnedCert::chain_from_pem_concat(&srv_cert.cert_chain_pem)?;
        let trust = OwnedCert::chain_from_pem_concat(ca_pem)?;
        verify_cert_chain_sm2_chain(&leaf_chain, &trust, OffsetDateTime::now_utc(), domain)?;

        // Check CRL if provided
        if let Some(ref crl) = opts.crl_info {
            let leaf_cert = leaf_chain[0].as_x509()?;
            let cert_serial = leaf_cert.serial.to_bytes_be();
            verify_crl(
                &cert_serial,
                leaf_cert.issuer(),
                &trust[0].as_x509()?,
                crl,
                OffsetDateTime::now_utc(),
            )?;
        }
    }

    let cv_buf = read_handshake_record(&mut stream).await?;
    let cv: CertificateVerify = CertificateVerify::from_bytes(&cv_buf)
        .map_err(|e| TlsError::HandshakeFailed(format!("CertificateVerify parse failed: {}", e)))?;

    // Verify CertificateVerify using the server's certificate public key (not ephemeral)
    let srv_cert_pubkey = extract_server_pubkey_for_cert_verify(&srv_cert.cert_chain_pem)?;
    let verifier = Sm2Verifier::new(&srv_cert_pubkey, GM_TLS_DEFAULT_ID)
        .map_err(|e| TlsError::HandshakeFailed(format!("SM2 verifier creation failed: {}", e)))?;
    verifier.verify(&transcript, &cv.signature).map_err(|e| {
        TlsError::HandshakeFailed(format!("CertificateVerify verification error: {}", e))
    })?;

    // Update transcript to include CertificateVerify
    let transcript = compute_transcript_hash_multi(&[&transcript, &cv_buf])?;

    let server_pk = parse_sm2_pubkey(&sh.eph_pubkey)?;
    let shared = server_pk * sk_client;
    let secrets = derive_session_keys_sm2(&shared)?;

    let srv_finished_buf = read_handshake_record(&mut stream).await?;
    let srv_finished: Finished = Finished::from_bytes(&srv_finished_buf)
        .map_err(|e| TlsError::HandshakeFailed(format!("Finished parse failed: {}", e)))?;
    let srv_pubkey = select_pubkey_for_finished(&sh)?;
    let verifier = Sm2Verifier::new(srv_pubkey.as_slice(), GM_TLS_DEFAULT_ID)
        .map_err(|e| TlsError::HandshakeFailed(format!("SM2 verifier creation failed: {}", e)))?;
    verify_finished(&verifier, &transcript, &srv_finished)?;

    if !cert_pem.is_empty() {
        // Send client certificate after server authentication (TLS 1.3 style)
        let client_cert = ClientCertificate {
            cert_chain_pem: cert_pem.to_vec(),
        };
        let cert_bytes = client_cert
            .to_bytes()
            .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
        write_handshake_record(&mut stream, &cert_bytes, &der::VERSION_TLS_1_3).await?;

        // Send client Finished
        let signer = signer_from_scalar(&sk_client)?;
        let cli_finished = sign_finished(&signer, &transcript)?;
        let cli_finished_bytes = cli_finished
            .to_bytes()
            .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
        write_handshake_record(&mut stream, &cli_finished_bytes, &der::VERSION_TLS_1_3).await?;
    }

    timer.finish("success");
    let mut tls_stream = GmTlsStream::new(
        stream,
        secrets.session_keys,
        true, // client
        Some(srv_cert.cert_chain_pem.clone()),
        sh.alpn.clone(),
    );
    tls_stream.set_traffic_secrets(
        (*secrets.client_traffic_secret).clone(),
        (*secrets.server_traffic_secret).clone(),
    );
    Ok(tls_stream)
}

async fn accept_gm_rust_inner<S>(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    require_client_auth: bool,
    alpn: &[String],
    stream: S,
    opts: &HandshakeOptions,
) -> Result<GmTlsStream<S>, TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let timer = HandshakeTimer::new("server");
    let result = accept_gm_rust_inner_with_cert(
        cert_pem,
        key_pem,
        ca_pem,
        require_client_auth,
        alpn,
        stream,
        opts,
    )
    .await;
    match result {
        Ok((stream, _, _)) => {
            timer.finish("success");
            Ok(stream)
        }
        Err(e) => {
            timer.finish("error");
            Err(e)
        }
    }
}

async fn accept_gm_rust_inner_with_cert<S>(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    require_client_auth: bool,
    alpn: &[String],
    stream: S,
    opts: &HandshakeOptions,
) -> Result<(GmTlsStream<S>, Option<String>, Option<SessionTicket>), TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = stream;
    let ch_buf = read_handshake_record(&mut stream).await?;
    let ch: ClientHello =
        ClientHello::from_bytes(&ch_buf).map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;

    debug!(
        role = "server",
        client_hello_size = ch_buf.len(),
        alpn = ?ch.alpn,
        sni = ?ch.sni,
        has_session_ticket = ch.session_ticket.is_some(),
        "ClientHello received"
    );

    // Client certificate will be received later via ClientCertificate message
    // (after server authentication), not in ClientHello.
    let mut client_cert_pem: Option<String> = None;

    let (sh, sk_server) =
        build_server_hello(select_alpn(alpn, &ch.alpn), cert_pem, require_client_auth)?;

    // Derive session keys before sending ServerHello so we can create session ticket
    let client_pk = parse_sm2_pubkey(&ch.eph_pubkey)?;
    let shared = client_pk * sk_server;
    let secrets = derive_session_keys_sm2(&shared)?;

    // Create session ticket if ticket key is configured
    let session_ticket = if let Some(ticket_key) = &opts.session_ticket_key {
        let state = crate::session_ticket::create_session_state(
            (*secrets.master_secret).clone(),
            secrets.session_keys.clone(),
            Some((*secrets.client_traffic_secret).clone()),
            Some((*secrets.server_traffic_secret).clone()),
            sh.random,
            ch.random,
            sh.alpn.clone(),
            3600, // 1 hour
            require_client_auth,
        );
        match encrypt_session_ticket(&state, ticket_key) {
            Ok(ticket) => Some(ticket),
            Err(e) => {
                warn!("Failed to create session ticket: {}", e);
                None
            }
        }
    } else {
        None
    };

    let sh_bytes = sh
        .to_bytes()
        .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
    write_handshake_record(&mut stream, &sh_bytes, &der::VERSION_TLS_1_3).await?;

    // Build transcript: include ServerHello first
    let mut transcript = compute_transcript_hash(&ch_buf, &sh_bytes)?;

    // RFC 5077: Send NewSessionTicket after ServerHello, before Finished
    if let Some(ref ticket) = session_ticket {
        let nst = NewSessionTicket {
            ticket: ticket.clone(),
        };
        let nst_bytes = nst
            .to_bytes()
            .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
        write_handshake_record(&mut stream, &nst_bytes, &der::VERSION_TLS_1_3).await?;
        // Include NewSessionTicket in transcript for Finished
        transcript = compute_transcript_hash_multi(&[&transcript, &nst_bytes])?;
    }

    // Send Server Certificate
    if !cert_pem.is_empty() {
        let srv_cert = ClientCertificate {
            cert_chain_pem: cert_pem.to_vec(),
        };
        let srv_cert_bytes = srv_cert
            .to_bytes()
            .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
        write_handshake_record(&mut stream, &srv_cert_bytes, &der::VERSION_TLS_1_3).await?;
        transcript = compute_transcript_hash_multi(&[&transcript, &srv_cert_bytes])?;
    }

    // Send CertificateVerify signed with server's long-term certificate private key
    let cert_verify = {
        let signer = signer_from_pem_key(key_pem)
            .map_err(|e| TlsError::HandshakeFailed(format!("server key parse failed: {}", e)))?;
        let sig = signer.sign(&transcript).map_err(|e| {
            TlsError::HandshakeFailed(format!("CertificateVerify signing failed: {}", e))
        })?;
        let cv = CertificateVerify { signature: sig };
        let cv_bytes = cv
            .to_bytes()
            .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
        write_handshake_record(&mut stream, &cv_bytes, &der::VERSION_TLS_1_3).await?;
        cv_bytes
    };
    transcript = compute_transcript_hash_multi(&[&transcript, &cert_verify])?;

    let signer = signer_from_scalar(&sk_server)?;
    let srv_finished = sign_finished(&signer, &transcript)?;
    let srv_finished_bytes = srv_finished
        .to_bytes()
        .map_err(|e| TlsError::HandshakeFailed(e.to_string()))?;
    write_handshake_record(&mut stream, &srv_finished_bytes, &der::VERSION_TLS_1_3).await?;

    if require_client_auth {
        // Read client certificate (sent after server authentication, TLS 1.3 style)
        let cli_cert_buf = read_handshake_record(&mut stream).await?;
        let cli_cert: ClientCertificate =
            ClientCertificate::from_bytes(&cli_cert_buf).map_err(|e| {
                TlsError::HandshakeFailed(format!("ClientCertificate parse failed: {}", e))
            })?;

        if cli_cert.cert_chain_pem.is_empty() || ca_pem.is_empty() {
            return Err(TlsError::CertificateVerificationFailed(
                "client certificate required but certificate chain or CA is missing".into(),
            ));
        }
        let leaf_chain = OwnedCert::chain_from_pem_concat(&cli_cert.cert_chain_pem)?;
        let trust = OwnedCert::chain_from_pem_concat(ca_pem)?;
        verify_cert_chain_sm2_chain(&leaf_chain, &trust, OffsetDateTime::now_utc(), None)?;

        // Check CRL if provided
        if let Some(ref crl) = opts.crl_info {
            let leaf_cert = leaf_chain[0].as_x509()?;
            let cert_serial = leaf_cert.serial.to_bytes_be();
            verify_crl(
                &cert_serial,
                leaf_cert.issuer(),
                &trust[0].as_x509()?,
                crl,
                OffsetDateTime::now_utc(),
            )?;
        }

        client_cert_pem = Some(String::from_utf8_lossy(&cli_cert.cert_chain_pem).to_string());

        let cli_finished_buf = read_handshake_record(&mut stream).await?;
        let cli_finished: Finished = Finished::from_bytes(&cli_finished_buf).map_err(|e| {
            TlsError::HandshakeFailed(format!("Client Finished parse failed: {}", e))
        })?;
        let cli_pubkey = select_client_pubkey_for_finished(&ch)?;
        let verifier = Sm2Verifier::new(cli_pubkey.as_slice(), GM_TLS_DEFAULT_ID).map_err(|e| {
            TlsError::HandshakeFailed(format!(
                "SM2 verifier creation failed(client finished): {}",
                e
            ))
        })?;
        verify_finished(&verifier, &transcript, &cli_finished)?;
    }

    let mut tls_stream = GmTlsStream::new(
        stream,
        secrets.session_keys,
        false, // server
        Some(
            client_cert_pem
                .as_ref()
                .map(|_| Vec::new())
                .unwrap_or_default(),
        ),
        sh.alpn.clone(),
    );
    // Server: write_secret = server_traffic_secret, read_secret = client_traffic_secret
    tls_stream.set_traffic_secrets(
        (*secrets.server_traffic_secret).clone(),
        (*secrets.client_traffic_secret).clone(),
    );
    Ok((tls_stream, client_cert_pem, session_ticket))
}
