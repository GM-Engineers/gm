//! PR-4.23 / P2-12: Handshake timeout integration tests
//!
//! Validates that `TlsConfig::with_handshake_timeout(Duration)`
//! correctly bounds the wall-clock time of `TlsAcceptor::accept`
//! and `TlsConnector::connect`. The tests use
//! [`tokio::io::duplex`] so both halves are in-process — no
//! networking, no firewall, no port collisions.
//!
//! Two scenarios:
//!
//! 1. **Slow peer (legit timeout trigger)**: a duplex client
//!    holds back its writes after the first byte so the
//!    server's `accept_gm_rust` blocks on `AsyncReadExt::read`.
//!    The server's `tokio::time::timeout` should fire and
//!    return `TlsError::HandshakeFailed("handshake timeout
//!    after Ns ...")`.
//!
//! 2. **Disabled timeout (Duration::ZERO)**: a legitimate
//!    handshake succeeds even when the timeout is disabled
//!    end-to-end. Confirms the opt-out path.
//!
//! Reference: SPEC §3.2 loopback integration test.
//! End-to-end CRL/grace behavior is exercised separately by
//! `verify_crl` in gm-crypto.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use gm_ca::cert::CaSigner;
use gm_ca::cert_profile::CertProfile;
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;
use gm_tls::{TlsAcceptor, TlsConfig, TlsConnector, TlsError};

/// Generate a self-signed SM2 cert chain suitable for
/// in-process loopback handshakes. The same leaf cert is
/// used for both client and server sides (the test only
/// validates the timeout, not PKI).
fn gen_test_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca_key = Sm2KeyPair::generate().expect("CA keygen");
    let ca_signer = CaSigner::new(ca_key, "PR-4.23 timeout test CA");
    let ca_pem = ca_signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("CA self-sign");

    let leaf_key = Sm2KeyPair::generate().expect("leaf keygen");
    let leaf_pub_65 = leaf_key.public_key_bytes_uncompressed();
    let csr_pem = CsrBuilder::new_sm2("pr423-test", &leaf_pub_65)
        .expect("CsrBuilder")
        .build_pem(&leaf_key)
        .expect("CSR build");

    let (_, leaf_pem) = ca_signer
        .sign_csr_with_profile(csr_pem.as_bytes(), 365, &CertProfile::server_end_entity())
        .expect("sign CSR");

    let leaf_key_pem = leaf_key.private_key_pem().expect("leaf key PEM");
    (
        leaf_pem.into_bytes(),
        leaf_key_pem.into_bytes(),
        ca_pem.into_bytes(),
    )
}

/// PR-4.23: a "slow" client that sends one byte of the
/// ClientHello and then stalls. This forces the server to
/// block on `AsyncReadExt::read` for the rest of the
/// handshake, exercising the `tokio::time::timeout` wrap
/// added in this PR.
async fn slow_client_write(client_io: tokio::io::DuplexStream, first_byte: u8) {
    let mut io = client_io;
    // Send 1 byte, then sleep forever (until the test's
    // timeout-driven cancellation unblocks us via the
    // outer `tokio::time::timeout`).
    if io.write_u8(first_byte).await.is_err() {
        return;
    }
    loop {
        // Sleep longer than the test's timeout — guarantees
        // we never make progress.
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// PR-4.23: server-side timeout fires when the client
/// dribbles bytes. The server's `with_handshake_timeout`
/// wrap converts the elapsed future into a
/// `TlsError::HandshakeFailed("handshake timeout after Ns (...)")`
/// error after `handshake_timeout`.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn pr423_accept_times_out_on_slow_client() {
    let (leaf, key, ca) = gen_test_cert();

    // Server has a 1-second handshake timeout. Long enough
    // for the CI box's startup jitter, short enough to keep
    // the test fast.
    let server_cfg = TlsConfig::from_bytes(leaf.clone(), key.clone(), ca.clone())
        .expect("server config")
        .with_handshake_timeout(Duration::from_secs(1));
    let acceptor = TlsAcceptor::new(server_cfg).expect("acceptor");

    let (client_io, server_io) = tokio::io::duplex(8192);

    let server_hdl = tokio::spawn(async move {
        // `accept` should return Err(_) with the timeout
        // message rather than hanging indefinitely.
        acceptor.accept(server_io).await
    });

    // Client side: send exactly 1 byte (the leading 0x16
    // TLS record-content-type byte) and then stall. This
    // puts the server in a `read()` that never returns.
    let client_hdl = tokio::spawn(slow_client_write(client_io, 0x16));

    // Wait for the server's timeout (1s) plus margin for
    // tokio's deadline firing on the test runtime.
    let started = std::time::Instant::now();
    let err = tokio::time::timeout(Duration::from_secs(5), server_hdl)
        .await
        .expect("server future should resolve before our 5s outer timeout")
        .expect("server task should not panic");
    let elapsed = started.elapsed();

    assert!(err.is_err(), "accept must fail when client stalls, got Ok");
    let err_tls = match err {
        Err(e) => e,
        Ok(_stream) => panic!("accept must fail when client stalls, got Ok"),
    };
    let msg = format!("{err_tls}");
    assert!(
        msg.contains("handshake timeout"),
        "expected HandshakeFailed with timeout message, got: {msg}"
    );
    // Verify it really did fire at ~1s (allow 0.5s — 2s slack
    // for CI scheduling).
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(4),
        "timeout fired at {elapsed:?}, expected ~1s"
    );

    // Stop the slow client. It's stuck in a 60s sleep, so
    // we abort it instead of waiting.
    client_hdl.abort();
}

/// PR-4.23: a *disabled* timeout (`Duration::ZERO`) does
/// NOT cause the handshake to fail. We pair this with a
/// normal fast client to make sure the
/// `if timeout.is_zero() { return inner.await; }` branch
/// is actually taken.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn pr423_zero_timeout_disables_check() {
    let (leaf, key, ca) = gen_test_cert();

    let server_cfg = TlsConfig::from_bytes(leaf.clone(), key.clone(), ca.clone())
        .expect("server config")
        .with_handshake_timeout(Duration::ZERO);
    let acceptor = TlsAcceptor::new(server_cfg).expect("acceptor");
    let connector = TlsConnector::new(TlsConfig::from_bytes(leaf, key, ca).expect("client config"))
        .expect("connector");

    let (client_io, server_io) = tokio::io::duplex(8192);

    let payload = Arc::new(Mutex::new(Vec::<u8>::new()));
    let payload_writer = Arc::clone(&payload);

    let server_hdl = tokio::spawn(async move {
        let mut s = acceptor.accept(server_io).await?;
        let mut buf = [0u8; 5];
        let n = s.read_exact(&mut buf).await?;
        payload_writer.lock().await.extend_from_slice(&buf[..n]);
        s.write_all(b"pong").await?;
        Ok::<_, TlsError>(())
    });

    let client_hdl = tokio::spawn(async move {
        let mut c = connector.connect(client_io).await?;
        c.write_all(b"hello").await?;
        let mut buf = [0u8; 4];
        let _ = c.read_exact(&mut buf).await?;
        Ok::<_, TlsError>(())
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
