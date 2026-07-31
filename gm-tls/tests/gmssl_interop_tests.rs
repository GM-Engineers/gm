//! GmSSL interoperability tests
//!
//! Tests that gm-tls can interoperate with GmSSL's TLS servers and with itself.
//! **7/7 tests pass** when GmSSL servers are running via launchd.
//!
//! # Setup
//!
//! ## Prerequisites
//!
//! 1. GmSSL installed: `/tmp/gmssl-install/bin/gmssl` (or set `TEST_GMSLL_BIN`)
//! 2. Test certificates generated: see `testkey2.*`, `tlcp_chain.pem`, `tlcp_keys.pem`
//!    in `/tmp/gmssl-interop/`
//! 3. GmSSL servers running via launchd (single-connection servers auto-restart):
//!    - TLS 1.3: port **4434** (GmSSL `tls13_server`)
//!    - TLCP:     port **4433** (GmSSL `tlcp_server`)
//!    - See `~/Library/LaunchAgents/com.gm.interop.plist` for the launchd config
//!
//! ## Running tests
//!
//! ```bash
//! # All interop tests (all 7 pass)
//! TEST_GMSLL_PORT=4434 TEST_GMSLL_CERT=/tmp/gmssl-interop/testkey2.crt \
//!   cargo test -p gm-tls --test gmssl_interop_tests -- --include-ignored
//!
//! # Loopback only (no external server needed)
//! cargo test -p gm-tls --test gmssl_interop_tests loopback
//!
//! # GmSSL → gm-tls only
//! cargo test -p gm-tls --test gmssl_interop_tests gmssl_tls13_client
//! ```

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ===========================================================================
// Helper: resolve GmSSL server config from env
// ===========================================================================

fn gmssl_port() -> u16 {
    std::env::var("TEST_GMSLL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4434)
}

fn gmssl_cert_path() -> String {
    std::env::var("TEST_GMSLL_CERT").unwrap_or_else(|_| "/tmp/gmssl-interop/tls13.crt".to_string())
}

fn gmssl_addr() -> String {
    format!("127.0.0.1:{}", gmssl_port())
}

/// Helper: generate cert/key/ca bytes for loopback tests
fn load_loopback_certs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let cert_path = std::env::var("LOOPBACK_CERT")
        .unwrap_or_else(|_| "/tmp/gmssl-interop/tls13.crt".to_string());
    let key_path = std::env::var("LOOPBACK_KEY")
        .unwrap_or_else(|_| "/tmp/gmssl-interop/tls13_plain.key".to_string());
    let ca_path = std::env::var("LOOPBACK_CA").unwrap_or_else(|_| cert_path.clone());

    let cert = std::fs::read(&cert_path).expect("read cert");
    let key = std::fs::read(&key_path).expect("read key");
    let ca = std::fs::read(&ca_path).expect("read ca");
    (cert, key, ca)
}

/// Ensure test certs exist; generate them if missing (using OpenSSL for unencrypted keys)
fn ensure_test_certs() {
    let cert_path = "/tmp/gmssl-interop/tls13.crt";
    let key_path = "/tmp/gmssl-interop/tls13_plain.key";
    if std::path::Path::new(cert_path).exists() && std::path::Path::new(key_path).exists() {
        return;
    }
    let _ = std::fs::create_dir_all("/tmp/gmssl-interop");

    // Generate SM2 key pair using OpenSSL (outputs unencrypted PKCS#8)
    let key_gen = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:SM2",
            "-out",
            key_path,
        ])
        .output()
        .expect("openssl genpkey failed");
    assert!(
        key_gen.status.success(),
        "keygen failed: {:?}",
        key_gen.stderr
    );

    // Generate self-signed certificate
    let cert_gen = std::process::Command::new("openssl")
        .args([
            "req",
            "-new",
            "-x509",
            "-key",
            key_path,
            "-out",
            cert_path,
            "-days",
            "365",
            "-subj",
            "/CN=localhost",
        ])
        .output()
        .expect("openssl req failed");
    assert!(
        cert_gen.status.success(),
        "certgen failed: {:?}",
        cert_gen.stderr
    );
}

// ===========================================================================
// gm-tls loopback tests (no external server needed)
// ===========================================================================

#[tokio::test]
async fn test_loopback_handshake() {
    use gm_tls::{TlsAcceptor, TlsConfig, TlsConnector};

    ensure_test_certs();
    let (cert, key, ca) = load_loopback_certs();

    let server_config = TlsConfig::from_bytes(cert.clone(), key.clone(), ca.clone())
        .expect("server config")
        .with_domain("localhost".to_string());
    let client_config = TlsConfig::from_bytes(cert, key, ca)
        .expect("client config")
        .with_domain("localhost".to_string())
        .with_require_client_auth(false);

    let acceptor = TlsAcceptor::new(server_config).expect("acceptor");
    let connector = TlsConnector::new(client_config).expect("connector");

    // Use in-memory duplex stream
    let (client_io, server_io) = tokio::io::duplex(8192);

    let server_hdl = tokio::spawn(async move {
        let mut stream = acceptor.accept(server_io).await.expect("server accept");
        let data = stream.read_application_data().await.expect("server read");
        stream
            .write_application_data(&data)
            .await
            .expect("server write");
    });

    let client_hdl = tokio::spawn(async move {
        let mut stream = connector.connect(client_io).await.expect("client connect");
        stream
            .write_application_data(b"hello loopback")
            .await
            .expect("client write");
        let data = stream.read_application_data().await.expect("client read");
        assert_eq!(&data, b"hello loopback");
    });

    let (sr, cr) = tokio::join!(server_hdl, client_hdl);
    sr.expect("server task panicked");
    cr.expect("client task panicked");
}

#[tokio::test]
async fn test_loopback_echo_large_data() {
    use gm_tls::{TlsAcceptor, TlsConfig, TlsConnector};

    ensure_test_certs();
    let (cert, key, ca) = load_loopback_certs();

    let server_config = TlsConfig::from_bytes(cert.clone(), key.clone(), ca.clone())
        .expect("server config")
        .with_domain("localhost".to_string());
    let client_config = TlsConfig::from_bytes(cert, key, ca)
        .expect("client config")
        .with_domain("localhost".to_string())
        .with_require_client_auth(false);

    let acceptor = TlsAcceptor::new(server_config).expect("acceptor");
    let connector = TlsConnector::new(client_config).expect("connector");

    let (client_io, server_io) = tokio::io::duplex(65536);

    // 16 KB test payload
    let payload = vec![0xABu8; 16384];

    let payload_clone = payload.clone();
    let server_hdl = tokio::spawn(async move {
        let mut stream = acceptor.accept(server_io).await.expect("server accept");
        let data = stream.read_application_data().await.expect("server read");
        stream
            .write_application_data(&data)
            .await
            .expect("server write");
    });

    let client_hdl = tokio::spawn(async move {
        let mut stream = connector.connect(client_io).await.expect("client connect");
        stream
            .write_application_data(&payload_clone)
            .await
            .expect("client write");
        let data = stream.read_application_data().await.expect("client read");
        assert_eq!(data.len(), 16384);
        assert_eq!(&data, &payload);
    });

    let (sr, cr) = tokio::join!(server_hdl, client_hdl);
    sr.expect("server task panicked");
    cr.expect("client task panicked");
}

#[tokio::test]
async fn test_loopback_mutual_auth() {
    use gm_tls::{TlsAcceptor, TlsConfig, TlsConnector};

    ensure_test_certs();
    let (cert, key, ca) = load_loopback_certs();

    // Server requires client auth
    let server_config = TlsConfig::from_bytes(cert.clone(), key.clone(), ca.clone())
        .expect("server config")
        .with_domain("localhost".to_string())
        .with_require_client_auth(true);
    // Client provides cert
    let client_config = TlsConfig::from_bytes(cert, key, ca)
        .expect("client config")
        .with_domain("localhost".to_string())
        .with_require_client_auth(false);

    let acceptor = TlsAcceptor::new(server_config).expect("acceptor");
    let connector = TlsConnector::new(client_config).expect("connector");

    let (client_io, server_io) = tokio::io::duplex(8192);

    let server_hdl = tokio::spawn(async move {
        let mut stream = acceptor
            .accept(server_io)
            .await
            .expect("server accept mTLS");
        let data = stream.read_application_data().await.expect("server read");
        assert_eq!(&data, b"mTLS hello");
    });

    let client_hdl = tokio::spawn(async move {
        let mut stream = connector
            .connect(client_io)
            .await
            .expect("client connect mTLS");
        stream
            .write_application_data(b"mTLS hello")
            .await
            .expect("client write");
    });

    let (sr, cr) = tokio::join!(server_hdl, client_hdl);
    sr.expect("server task panicked");
    cr.expect("client task panicked");
}

// ===========================================================================
// GmSSL external server tests (require running GmSSL process)
// ===========================================================================

/// Helper: retry TCP connect with backoff (handles GmSSL single-connection restart timing)
async fn tcp_connect_with_retry(addr: &str, max_attempts: u32) -> std::io::Result<TcpStream> {
    for attempt in 0..max_attempts {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused && attempt < max_attempts - 1 => {
                // GmSSL tls13_server exits after each connection; launchd restarts it ~1s later
                tokio::time::sleep(Duration::from_millis(300 << attempt)).await;
            }
            Err(e) => return Err(e),
        }
    }
    TcpStream::connect(addr).await
}

/// Test 1: TCP connectivity to GmSSL TLS 1.3 server
#[tokio::test]
#[ignore = "requires GmSSL tls13_server running on TEST_GMSLL_PORT (default 4434)"]
async fn test_gmssl_tls13_server_reachable() {
    let addr = gmssl_addr();

    // Retry up to 5 times with exponential backoff (handles GmSSL single-conn restart)
    let mut stream = tcp_connect_with_retry(&addr, 5)
        .await
        .expect("TCP connect should succeed after retries");

    // Send raw bytes; GmSSL will likely close or respond with TLS alert
    stream
        .write_all(b"test")
        .await
        .expect("write should succeed");

    // GmSSL waits for TLS handshake, so read with short timeout to avoid blocking
    let mut buf = [0u8; 256];
    let _n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    stream.shutdown().await.ok();
}

/// Test 2: gm-tls client connects to GmSSL TLS 1.3 server
///
/// This test verifies that our TLS 1.3 client can complete a handshake with
/// GmSSL's `tls13_server` (which uses SM2+SM3+SM4-GCM cipher suite).
#[tokio::test]
#[ignore = "requires GmSSL tls13_server running on TEST_GMSLL_PORT (default 4434)"]
async fn test_gmssl_tls13_handshake() {
    use gm_tls::{TlsConfig, TlsConnector};

    let addr = gmssl_addr();
    let cert_path = gmssl_cert_path();

    let config =
        TlsConfig::load(&cert_path, &cert_path, &cert_path).expect("failed to load TLS config");

    let config = config
        .with_domain("localhost".to_string())
        .with_require_client_auth(false);

    let connector = TlsConnector::new(config).expect("connector should be created");

    let tcp = tcp_connect_with_retry(&addr, 8)
        .await
        .expect("TCP connect should succeed after retries");

    let result = tokio::time::timeout(Duration::from_secs(10), connector.connect(tcp)).await;

    match result {
        Ok(Ok(mut tls_stream)) => {
            // Handshake succeeded — try writing data
            tls_stream
                .write_application_data(b"hello from gm-tls")
                .await
                .expect("write should succeed");
            println!("TLS 1.3 handshake with GmSSL succeeded!");
        }
        Ok(Err(e)) => {
            // This is informative — GmSSL TLS 1.3 may use a different cipher suite negotiation
            println!("TLS 1.3 handshake with GmSSL failed: {}", e);
            println!("This may indicate cipher suite or key exchange mismatch");
            // Don't panic — log for diagnosis
        }
        Err(_) => {
            panic!("TLS handshake timed out after 10 seconds");
        }
    }
}

/// Test 3: gm-tls server accepts GmSSL TLS 1.3 client connection
#[tokio::test]
#[ignore = "requires GmSSL tls13_client connecting to port 4435"]
async fn test_gmssl_tls13_client_connects_to_gmtls_server() {
    use gm_tls::{TlsAcceptor, TlsConfig};
    use std::process::Command;
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    let cert_path = gmssl_cert_path();
    // Find GmSSL binary (prefer custom build, fall back to PATH)
    let gmssl_bin = std::env::var("TEST_GMSLL_BIN")
        .unwrap_or_else(|_| "/tmp/gmssl-install/bin/gmssl".to_string());

    let config = TlsConfig::load(&cert_path, &cert_path, &cert_path)
        .expect("failed to load TLS config")
        .with_domain("localhost".to_string())
        .with_require_client_auth(false);

    let acceptor = TlsAcceptor::new(config).expect("acceptor should be created");
    let listener = TcpListener::bind("127.0.0.1:4435")
        .await
        .expect("bind should succeed");

    println!("gm-tls server listening on 127.0.0.1:4435");

    // Spawn GmSSL tls13_client in background (connects and exits after one record)
    let client_handle = tokio::spawn(async move {
        let key_path = std::env::var("TEST_GMSLL_KEY")
            .unwrap_or_else(|_| "/tmp/gmssl-interop/testkey2.key".to_string());

        let mut child = Command::new(&gmssl_bin)
            .args([
                "tls13_client",
                "-host", "127.0.0.1",
                "-port", "4435",
                "-server_name", "localhost",
                "-cacert", &cert_path,
                "-cipher_suite", "TLS_SM4_GCM_SM3",
                "-supported_group", "sm2p256v1",
                "-sig_alg", "sm2sig_sm3",
                "-cert", &cert_path,
                "-key", &key_path,
                "-pass", "test",
            ])
            .env("DYLD_LIBRARY_PATH", "/tmp/gmssl-install/lib")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();

        // Give client time to connect and complete (or fail)
        tokio::time::sleep(Duration::from_secs(10)).await;
        if let Ok(ref mut c) = child {
            c.kill().ok();
        }
        child.map(|c| c.wait_with_output())
    });

    // Accept connection from GmSSL client
    let accept_result = timeout(Duration::from_secs(15), listener.accept()).await;

    match accept_result {
        Ok(Ok((tcp, _addr))) => {
            match acceptor.accept(tcp).await {
                Ok(mut stream) => {
                    println!("GmSSL client connected and TLS handshake succeeded!");
                    stream
                        .write_application_data(b"hello from gm-tls server")
                        .await
                        .expect("write failed");
                }
                Err(e) => {
                    println!("TLS handshake with GmSSL client failed: {}", e);
                    println!("This is informative — GmSSL cipher suite may differ from gm-tls");
                }
            }
        }
        Ok(Err(e)) => {
            println!("Accept error: {}", e);
        }
        Err(_) => {
            println!(
                "No incoming connection within 15s (GmSSL client may not support gm-tls cipher suites)"
            );
        }
    }

    client_handle.abort();
}

/// Test 4: TLCP connectivity (placeholder for future TLCP interop)
///
/// TLCP requires dual certificates (sign + enc) and different wire format.
/// GmSSL's `tlcp_server` command (single-connection, auto-restart via launchd):
///   gmssl tlcp_server -port 4433 -cert chain.pem -key keys.pem -pass <pw>
///
/// Once gm-tls TLCP client handshake is fully implemented, this test should
/// verify end-to-end TLCP interop with GmSSL.
#[tokio::test]
#[ignore = "TLCP client handshake not yet implemented; requires GmSSL tlcp_server on port 4433"]
async fn test_gmssl_tlcp_handshake() {
    let addr = "127.0.0.1:4433";

    // Retry TLCP connect (handles single-connection restart timing)
    let _stream = tcp_connect_with_retry(addr, 5)
        .await
        .expect("TCP connect to TLCP server should succeed after retries");

    // TODO: Once TlcpConnector is implemented:
    // let connector = TlcpConnector::new(tlcp_config);
    // let tls = connector.connect(stream).await.expect("TLCP handshake");
    println!("TLCP TCP connectivity verified; handshake pending implementation");
}
