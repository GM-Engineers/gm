//! Client SM2 keys supplied as **encrypted PKCS#8 PEM**, and the
//! explicit-error contract for `TlcpConnector::connect()` without a
//! pinned server key.
//!
//! Previously `TlcpConnector` loaded the client sign / enc keys with
//! `Sm2KeyPair::from_private_key_pem` only, so an encrypted PEM always
//! failed the handshake even though the docs promised encrypted-PKCS#8
//! support with a `"P@ssw0rd"` default (the `client_sign_key_password`
//! field was dead code). These tests freeze the fixed behaviour:
//!
//! - an encrypted client sign/enc key (scrypt *and* PBKDF2) completes an
//!   ECDHE mTLS handshake;
//! - a wrong password still fails;
//! - `connect()` without `with_server_sign_key()` returns a clear error
//!   instead of silently using the no-verification legacy path.

#![cfg(feature = "tlcp-profiles")]

mod support;

use gm_crypto::sm2::{PbeKdf, Sm2KeyPair};
use gm_tlcp::tlcp::*;
use support::gmca_cert_setup::{DEFAULT_DISTID, GmcaCerts};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ECDHE_SM4_GCM: [u8; 2] = [0xE0, 0x51];
const PASSWORD: &str = "P@ssw0rd";

/// Re-encrypt a plaintext SEC1 PEM key into an encrypted PKCS#8 PEM with
/// the chosen KDF, so the test feeds the connector exactly what a real
/// operator would load from disk.
fn encrypt_key(plain_pem: &str, kdf: Option<&PbeKdf>) -> String {
    let kp = Sm2KeyPair::from_private_key_pem(plain_pem).expect("load plaintext client key");
    match kdf {
        None => kp.to_encrypted_pem(PASSWORD).expect("scrypt encrypt"),
        Some(k) => kp
            .to_encrypted_pem_with_kdf(PASSWORD, k)
            .expect("kdf encrypt"),
    }
}

async fn run_handshake(
    acceptor: TlcpAcceptor,
    connector: TlcpConnector,
) -> Result<
    (
        TlcpStream<tokio::io::DuplexStream>,
        TlcpStream<tokio::io::DuplexStream>,
    ),
    String,
> {
    let (client_io, server_io) = tokio::io::duplex(32768);
    let server_handle = tokio::spawn(async move { acceptor.accept_with_certs(server_io).await });
    let client_handle = tokio::spawn(async move { connector.connect_with_certs(client_io).await });
    let server = tokio::time::timeout(std::time::Duration::from_secs(30), server_handle)
        .await
        .expect("server task timed out")
        .expect("server task panicked");
    let client = tokio::time::timeout(std::time::Duration::from_secs(30), client_handle)
        .await
        .expect("client task timed out")
        .expect("client task panicked");
    match (server, client) {
        (Ok(s), Ok(c)) => Ok((s, c)),
        (_, Err(e)) => Err(format!("client: {e}")),
        (Err(e), Ok(_)) => Err(format!("server: {e}")),
    }
}

fn base_acceptor(certs: &GmcaCerts) -> TlcpAcceptor {
    let sign_kp = Sm2KeyPair::from_private_key_pem(&certs.server_sign_key_pem).expect("sign key");
    let enc_kp = Sm2KeyPair::from_private_key_pem(&certs.server_enc_key_pem).expect("enc key");
    TlcpAcceptor::new()
        .with_dual_certs(
            certs.server_sign_cert_der.clone(),
            certs.server_enc_cert_der.clone(),
            sign_kp,
            enc_kp,
        )
        // Require + verify a client cert chain against the test CA: this
        // forces the client to actually use its (encrypted) sign key in
        // CertificateVerify, so the handshake only succeeds if the
        // encrypted key loaded correctly.
        .with_client_ca_chain(vec![certs.ca_cert_der.clone()])
}

fn base_connector(certs: &GmcaCerts) -> TlcpConnector {
    TlcpConnector::new()
        .with_cipher_suites(vec![ECDHE_SM4_GCM])
        .with_server_sign_key(certs.server_sign_pub_65.clone(), DEFAULT_DISTID.to_string())
        .with_server_ca_chain(vec![certs.ca_cert_der.clone()])
}

/// Client sign + enc keys encrypted with the scrypt KDF.
///
/// Uses explicit low-cost scrypt parameters (`log_n = 12, r = 1, p = 1`)
/// rather than the deliberately expensive `to_encrypted_pem` default
/// (`log_n = 15, r = 8`). This still exercises the full scrypt code path
/// end-to-end — the PEM carries a scrypt PBES2 identifier, which the
/// connector must parse and decrypt inside the handshake — while keeping
/// the derivation fast enough to fit the handshake timeout on slower
/// shared CI runners. The expensive default cost profile is covered by
/// gm-crypto's own round-trip tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_with_scrypt_encrypted_client_keys_succeeds() {
    let certs = support::gmca_cert_setup::generate_gmca_test_certs(&std::path::PathBuf::from("."))
        .expect("gen certs");
    let kdf = PbeKdf::Scrypt {
        log_n: 12,
        r: 1,
        p: 1,
    };
    let sign_enc_pem = encrypt_key(&certs.client_sign_key_pem, Some(&kdf));
    let enc_enc_pem = encrypt_key(&certs.client_enc_key_pem, Some(&kdf));

    let connector = base_connector(&certs).with_client_certs(
        vec![
            certs.client_sign_cert_der.clone(),
            certs.client_enc_cert_der.clone(),
        ],
        sign_enc_pem,
        Some(enc_enc_pem),
        Some(PASSWORD.to_string()),
    );

    let (mut server_stream, mut client_stream) = run_handshake(base_acceptor(&certs), connector)
        .await
        .expect("scrypt-encrypted client keys must load and complete mTLS");

    client_stream.write_all(b"enc-ok").await.expect("write");
    client_stream.flush().await.expect("flush");
    let mut buf = vec![0u8; 16];
    let n = server_stream.read(&mut buf).await.expect("read");
    assert_eq!(&buf[..n], b"enc-ok");
}

/// Client sign + enc keys encrypted with the new PBKDF2 KDF path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_with_pbkdf2_encrypted_client_keys_succeeds() {
    let certs = support::gmca_cert_setup::generate_gmca_test_certs(&std::path::PathBuf::from("."))
        .expect("gen certs");
    let kdf = PbeKdf::Pbkdf2 { iterations: 4096 };
    let sign_enc_pem = encrypt_key(&certs.client_sign_key_pem, Some(&kdf));
    let enc_enc_pem = encrypt_key(&certs.client_enc_key_pem, Some(&kdf));

    let connector = base_connector(&certs).with_client_certs(
        vec![
            certs.client_sign_cert_der.clone(),
            certs.client_enc_cert_der.clone(),
        ],
        sign_enc_pem,
        Some(enc_enc_pem),
        Some(PASSWORD.to_string()),
    );

    run_handshake(base_acceptor(&certs), connector)
        .await
        .expect("pbkdf2-encrypted client keys must load and complete mTLS");
}

/// A wrong password must NOT decrypt the key, so the handshake fails
/// (rather than silently succeeding — proving the fallback actually
/// gates on the password).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_with_wrong_password_fails() {
    let certs = support::gmca_cert_setup::generate_gmca_test_certs(&std::path::PathBuf::from("."))
        .expect("gen certs");
    let kdf = PbeKdf::Pbkdf2 { iterations: 2048 };
    let sign_enc_pem = encrypt_key(&certs.client_sign_key_pem, Some(&kdf));
    let enc_enc_pem = encrypt_key(&certs.client_enc_key_pem, Some(&kdf));

    let connector = base_connector(&certs).with_client_certs(
        vec![
            certs.client_sign_cert_der.clone(),
            certs.client_enc_cert_der.clone(),
        ],
        sign_enc_pem,
        Some(enc_enc_pem),
        // Deliberately wrong password.
        Some("totally-wrong".to_string()),
    );

    let err = run_handshake(base_acceptor(&certs), connector)
        .await
        .err()
        .expect("wrong client key password must fail the handshake");
    assert!(
        err.contains("neither a plaintext PEM") || err.contains("client key load"),
        "expected the dual-cause key-load diagnostic, got: {err}"
    );
}

/// `connect()` without a pinned server signing key must return an
/// explicit error instead of degrading to the no-verification legacy
/// `connect_tlcp` path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_without_pinned_server_key_errors() {
    let (client_io, _server_io) = tokio::io::duplex(1024);
    let connector = TlcpConnector::new(); // no with_server_sign_key
    let err = connector
        .connect(client_io)
        .await
        .err()
        .expect("connect() without a pinned server key must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("with_server_sign_key") && msg.contains("connect_tlcp"),
        "error must name both the fix (with_server_sign_key) and the \
         explicit legacy escape hatch (connect_tlcp); got: {msg}"
    );
}
