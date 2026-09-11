//! Full chain integration test: CSR → CA signing → TLS handshake
//!
//! This test creates certificates locally using CaSigner and tests the TLS handshake.
//! It does NOT require docker or the gm-ca-server to be running.

use gm_ca::cert::CaSigner;
use gm_ca::cert_profile::CertProfile;
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;
use gm_tls::gm::{HandshakeOptions, accept_gm_rust, connect_gm_rust};
use std::time::Duration;

/// Build a PKCS#10 CSR PEM for an SM2 keypair using
/// `gm_crypto::x509::CsrBuilder`. Replaces the ~120 lines of naked
/// DER + asn1-crate construction that lived here pre-Phase-3.
fn build_sm2_csr_pem(subject_cn: &str, pubkey_65: &[u8], signing_key: &Sm2KeyPair) -> String {
    CsrBuilder::new_sm2(subject_cn, pubkey_65)
        .expect("CsrBuilder::new_sm2")
        .build_pem(signing_key)
        .expect("CsrBuilder::build_pem")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "heavy end-to-end gRPC+TLS 1.3 + SM handshake; intermittently hangs on CI runners (likely a handshake scheduling deadlock in the in-development TLS stack). Run manually: cargo test -p gm-ca --test full_chain_test -- --ignored"]
async fn test_full_chain_grpc_ca_plus_tls_handshake() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Create test CA keypair
    let ca_keypair = Sm2KeyPair::generate().expect("failed to generate CA key");
    let _ca_key_pem = ca_keypair
        .private_key_pem()
        .expect("failed to get CA private key PEM");
    let ca_signer = CaSigner::new(ca_keypair.duplicate(), "Test GM CA");

    // 2. Generate server keypair + CSR
    let server_keypair = Sm2KeyPair::generate().expect("failed to generate server key");
    let server_pubkey_65 = server_keypair.public_key_bytes_uncompressed();
    let server_csr_pem = build_sm2_csr_pem("server.test", &server_pubkey_65, &server_keypair);

    // 3. Generate client keypair + CSR
    let client_keypair = Sm2KeyPair::generate().expect("failed to generate client key");
    let client_pubkey_65 = client_keypair.public_key_bytes_uncompressed();
    let client_csr_pem = build_sm2_csr_pem("client.test", &client_pubkey_65, &client_keypair);

    // 4. Sign both leaf certs with our test CA. Default profile reproduces
    // the v0.1.x wire-format extension set (digitalSignature +
    // keyEncipherment, serverAuth + clientAuth, SKI, SAN).
    // Server cert: signed by our test CA (ca_signer), not docker gm-ca-server
    let (_, server_cert_pem) = ca_signer
        .sign_csr_with_profile(server_csr_pem.as_bytes(), 365, &CertProfile::default())
        .expect("sign server cert failed");

    let (_, client_cert_pem) = ca_signer
        .sign_csr_with_profile(client_csr_pem.as_bytes(), 365, &CertProfile::default())
        .expect("sign client cert via CaSigner failed");

    // CA self-signed cert (trust anchor). Use self_sign_ca directly with
    // the root_ca profile — keyCertSign + cRLSign + BasicConstraints CA:TRUE
    // + AKI/SKI per GmSSL -gen_authority_key_id / -gen_subject_key_id
    // semantics. Avoids the intermediate CSR dance.
    let ca_cert_pem = ca_signer
        .self_sign_ca(3650, &CertProfile::root_ca())
        .expect("self-sign CA cert failed");

    // 5. Write to temp files
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let write = |name: &str, data: &str| {
        let path = temp_dir.path().join(name);
        std::fs::write(&path, data).expect("failed to write temp file");
        path
    };

    let _server_cert_path = write("server.pem", &server_cert_pem);
    let _server_key_path = write("server-key.pem", &server_keypair.private_key_pem().unwrap());
    let _client_cert_path = write("client.pem", &client_cert_pem);
    let _client_key_path = write("client-key.pem", &client_keypair.private_key_pem().unwrap());
    let _ca_cert_path = write("ca.pem", &ca_cert_pem);

    // 6. Spawn TLS server requiring client auth
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind TCP");
    let server_addr = listener.local_addr().expect("failed to get local addr");

    let server_cert_pem_clone = server_cert_pem.clone();
    let server_key_pem_clone = server_keypair.private_key_pem().unwrap();
    let ca_cert_pem_clone = ca_cert_pem.clone();

    let server_handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept failed");
        let mut tls = accept_gm_rust(
            server_cert_pem_clone.as_bytes(),
            server_key_pem_clone.as_bytes(),
            ca_cert_pem_clone.as_bytes(),
            true,
            &[],
            tcp,
            &HandshakeOptions::default(),
        )
        .await
        .expect("server TLS handshake failed");

        let data = tls
            .read_application_data()
            .await
            .expect("server read failed");
        tls.write_application_data(&data)
            .await
            .expect("server write failed");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 7. Client connects with mTLS
    let tcp = tokio::net::TcpStream::connect(server_addr)
        .await
        .expect("TCP connect failed");
    let client_cert_bytes = std::fs::read(&_client_cert_path).expect("failed to read client cert");
    let client_key_bytes = std::fs::read(&_client_key_path).expect("failed to read client key");
    let ca_cert_bytes = std::fs::read(&_ca_cert_path).expect("failed to read CA cert");
    let mut tls_client = connect_gm_rust(
        &client_cert_bytes,
        &client_key_bytes,
        &ca_cert_bytes,
        Some("server.test"),
        &[],
        tcp,
        &HandshakeOptions::default(),
    )
    .await
    .expect("client TLS handshake failed");

    // 8. mTLS echo test
    tls_client
        .write_application_data(b"Hello, TLS 1.3 + SM!")
        .await
        .expect("client write failed");
    let response = tls_client
        .read_application_data()
        .await
        .expect("client read failed");
    assert_eq!(&response, b"Hello, TLS 1.3 + SM!");

    server_handle.await.expect("server panicked");

    tracing::info!("Full chain test passed: CA-issued certs → mTLS handshake ✓");
}
