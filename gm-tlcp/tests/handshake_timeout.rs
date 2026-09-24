//! PR-4.24 / P2-12: TLCP handshake timeout integration tests
//!
//! Validates that `TlcpConnector::with_handshake_timeout(Duration)`
//! and `TlcpAcceptor::with_handshake_timeout(Duration)` correctly
//! bound the wall-clock time of the TLCP handshake. Mirrors the
//! gm-tls PR-4.23 tests in `gm-tls/tests/handshake_timeout.rs`.
//!
//! Two scenarios:
//!
//! 1. **Slow peer (legit timeout trigger)**: a duplex client
//!    holds back its writes after the first byte so the
//!    server's `accept` blocks on `AsyncReadExt::read`. The
//!    server's `tokio::time::timeout` should fire and return
//!    `TlcpError::HandshakeFailed("handshake timeout after Ns ...")`
//!    after `handshake_timeout`.
//!
//! 2. **Disabled timeout (Duration::ZERO)**: a legitimate
//!    handshake succeeds even when the timeout is disabled
//!    end-to-end. Confirms the opt-out path.
//!
//! Reference: SPEC §3.2.
//!
//! End-to-end CRL/grace behavior is exercised separately by
//! `verify_crl` in gm-crypto and the TLCP revocation tests in
//! `gm_tlcp_loopback.rs`.

#![cfg(test)]
#![cfg(feature = "tlcp-profiles")]

mod support;
use support::gmca_cert_setup::{GmcaCerts, generate_gmca_test_certs};

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use gm_crypto::sm2::Sm2KeyPair;
use gm_tlcp::TlcpError;
use gm_tlcp::tlcp::{TlcpAcceptor, TlcpConnector};

/// Generate a GMCA-issued TLCP dual cert chain (sign + enc)
/// suitable for in-process loopback handshakes. Mirrors the
/// pattern used by `gm_tlcp_loopback.rs::run_loopback`.
fn gen_test_certs() -> GmcaCerts {
    let tmp = std::env::temp_dir().join(format!("gm-tlcp-pr424-test-{}", std::process::id()));
    generate_gmca_test_certs(&tmp).expect("generate_gmca_test_certs")
}

/// PR-4.24: a "slow" client that sends one byte of the
/// ClientHello (the leading TLS record-content-type byte)
/// and then stalls. This forces the server to block on
/// `AsyncReadExt::read` for the rest of the handshake,
/// exercising the `tokio::time::timeout` wrap added in this PR.
async fn slow_client_write(client_io: tokio::io::DuplexStream) {
    let mut io = client_io;
    if io.write_u8(0x16).await.is_err() {
        return;
    }
    loop {
        // Sleep longer than the test's timeout — guarantees
        // we never make progress.
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// PR-4.24: server-side timeout fires when the client
/// dribbles bytes. The server's `with_handshake_timeout`
/// wrap converts the elapsed future into a
/// `TlcpError::HandshakeFailed("handshake timeout after Ns (...)")`
/// error after `handshake_timeout`.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn pr424_accept_times_out_on_slow_client() {
    let certs = gen_test_certs();

    // Server has a 1-second handshake timeout. Long enough
    // for CI box startup jitter, short enough to keep the
    // test fast.
    let sign_kp = Sm2KeyPair::from_private_key_pem(&certs.server_sign_key_pem).expect("sign kp");
    let enc_kp = Sm2KeyPair::from_private_key_pem(&certs.server_enc_key_pem).expect("enc kp");
    let acceptor = TlcpAcceptor::new()
        .with_dual_certs(
            certs.server_sign_cert_der.clone(),
            certs.server_enc_cert_der.clone(),
            sign_kp,
            enc_kp,
        )
        .with_handshake_timeout(Duration::from_secs(1));

    let (client_io, server_io) = tokio::io::duplex(8192);

    let server_hdl = tokio::spawn(async move { acceptor.accept(server_io).await });

    // Client side: send exactly 1 byte (the leading 0x16
    // TLS record-content-type byte) and then stall. This
    // puts the server in a `read()` that never returns.
    let client_hdl = tokio::spawn(slow_client_write(client_io));

    // Wait for the server's timeout (1s) plus margin.
    let started = std::time::Instant::now();
    let err_tls = match tokio::time::timeout(Duration::from_secs(5), server_hdl)
        .await
        .expect("server future should resolve before our 5s outer timeout")
        .expect("server task should not panic")
    {
        Err(e) => e,
        Ok(_stream) => panic!("accept must fail when client stalls, got Ok"),
    };
    let elapsed = started.elapsed();

    let msg = format!("{err_tls}");
    assert!(
        msg.contains("handshake timeout"),
        "expected HandshakeFailed with timeout message, got: {msg}"
    );
    // Verify it really did fire at ~1s.
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(4),
        "timeout fired at {elapsed:?}, expected ~1s"
    );

    // Stop the slow client.
    client_hdl.abort();
}

/// PR-4.24: a *disabled* timeout (`Duration::ZERO`) does
/// NOT cause the handshake to fail. Pair this with a normal
/// fast client to make sure the
/// `if timeout.is_zero() { return inner.await; }` branch is
/// actually taken.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn pr424_zero_timeout_disables_check() {
    let certs = gen_test_certs();

    // Configure both sides with the real GMCA chain.
    let sign_kp = Sm2KeyPair::from_private_key_pem(&certs.server_sign_key_pem).expect("sign kp");
    let enc_kp = Sm2KeyPair::from_private_key_pem(&certs.server_enc_key_pem).expect("enc kp");
    let acceptor = TlcpAcceptor::new()
        .with_dual_certs(
            certs.server_sign_cert_der.clone(),
            certs.server_enc_cert_der.clone(),
            sign_kp,
            enc_kp,
        )
        // PR-4.24 explicit opt-out.
        .with_handshake_timeout(Duration::ZERO);

    let connector = TlcpConnector::new()
        .with_server_sign_key(
            certs.server_sign_pub_65.clone(),
            "1234567812345678".to_string(),
        )
        // mTLS: TLCP dual-cert servers expect a client cert chain
        // in reply to CertificateRequest. Feed the matching GMCA
        // client sign + enc certs and SEC1 keys (no PBES2 — the
        // helper emits unencrypted SEC1 PEMs).
        .with_client_certs(
            vec![
                certs.client_sign_cert_der.clone(),
                certs.client_enc_cert_der.clone(),
            ],
            certs.client_sign_key_pem.clone(),
            Some(certs.client_enc_key_pem.clone()),
            Some("P@ssw0rd".to_string()),
        )
        .with_handshake_timeout(Duration::ZERO);

    let (client_io, server_io) = tokio::io::duplex(16384);

    let payload = Arc::new(Mutex::new(Vec::<u8>::new()));
    let payload_writer = Arc::clone(&payload);

    let server_hdl = tokio::spawn(async move {
        let mut s = acceptor.accept(server_io).await?;
        let mut buf = [0u8; 5];
        let n = s.read_exact(&mut buf).await?;
        payload_writer.lock().await.extend_from_slice(&buf[..n]);
        s.write_all(b"pong").await?;
        Ok::<_, TlcpError>(())
    });

    let client_hdl = tokio::spawn(async move {
        let mut c = connector.connect(client_io).await?;
        c.write_all(b"hello").await?;
        let mut buf = [0u8; 4];
        let _ = c.read_exact(&mut buf).await?;
        Ok::<_, TlcpError>(())
    });

    let (sr, cr) = tokio::join!(server_hdl, client_hdl);
    sr.expect("server task panicked")
        .expect("handshake must succeed with disabled timeout");
    cr.expect("client task panicked")
        .expect("handshake must succeed with disabled timeout");
    assert_eq!(
        &*payload.lock().await,
        b"hello",
        "server must have received the client's payload"
    );
}
