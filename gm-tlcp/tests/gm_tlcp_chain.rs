//! Intermediate-CA certificate chain transmission over the TLCP wire
//! (three-level PKI: root → intermediate → leaf).
//!
//! Before the chain-serialization fix, `TlcpCertPair` dropped
//! `sign_chain` / `enc_chain` on the wire and the receiver truncated
//! the cert list at two entries — so a peer trusting only the root CA
//! could never build a chain and the handshake failed with a
//! trust-anchor error. These tests freeze the fixed behaviour:
//!
//! - `server_chain_root_anchor_handshake_succeeds` — server sends
//!   `[sign_leaf, enc_leaf, intermediate]`, client anchors the root ⇒
//!   full ECDHE handshake + data round-trip.
//! - `server_without_chain_root_anchor_handshake_fails` — negative
//!   control pinning the pre-fix symptom (this test asserts the OLD
//!   failure mode still occurs when the chain is deliberately not
//!   configured, proving the anchor really requires the intermediate).
//! - `client_chain_root_anchor_handshake_succeeds` — mTLS direction:
//!   the client's `Certificate` reply carries an intermediate CA entry
//!   and the server (anchoring only the root) builds both leaf chains
//!   through it. Entries beyond the two leaves must NOT be re-validated
//!   as independent leaves.

#![cfg(feature = "tlcp-profiles")]

mod support;

use gm_ca::cert::CaSigner;
use gm_ca::cert_profile::CertProfile;
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;
use gm_tlcp::tlcp::*;
use support::gmca_cert_setup::DEFAULT_DISTID;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A three-level SM2 PKI: self-signed root → intermediate CA → the
/// usual TLCP dual-cert leaves (server sign/enc + client sign/enc).
struct ChainPki {
    root_cert_der: Vec<u8>,
    intermediate_cert_der: Vec<u8>,
    server_sign_cert_der: Vec<u8>,
    server_enc_cert_der: Vec<u8>,
    server_sign_key_pem: String,
    server_enc_key_pem: String,
    server_sign_pub_65: Vec<u8>,
    client_sign_cert_der: Vec<u8>,
    client_enc_cert_der: Vec<u8>,
    client_sign_key_pem: String,
    client_enc_key_pem: String,
}

fn pem_to_der(pem_str: &str) -> Vec<u8> {
    pem::parse(pem_str.as_bytes())
        .expect("PEM parse")
        .into_contents()
}

fn issue_leaf(signer: &CaSigner, cn: &str, profile: &CertProfile) -> (Sm2KeyPair, Vec<u8>, String) {
    let key = Sm2KeyPair::generate().expect("keygen");
    let pub65 = key.public_key_bytes_uncompressed();
    let csr = CsrBuilder::new_sm2(cn, &pub65)
        .expect("CSR builder")
        .build_pem(&key)
        .expect("CSR sign");
    let (_serial, cert_pem) = signer
        .sign_csr_with_profile(csr.as_bytes(), 365, profile)
        .expect("sign leaf CSR");
    let key_pem = key.private_key_pem().expect("SEC1 PEM");
    (key, pem_to_der(&cert_pem), key_pem)
}

fn generate_chain_pki() -> ChainPki {
    // ---- Root CA (self-signed) ----
    let root_key = Sm2KeyPair::generate().expect("root keygen");
    let root_signer = CaSigner::new(root_key, "chain-test Root CA");
    let root_pem = root_signer
        .self_sign_ca(3650, &CertProfile::root_ca())
        .expect("root self-sign");
    let root_cert_der = pem_to_der(&root_pem);

    // ---- Intermediate CA (signed by root, CA:TRUE pathLen=0) ----
    let inter_key = Sm2KeyPair::generate().expect("intermediate keygen");
    let inter_pub65 = inter_key.public_key_bytes_uncompressed();
    let inter_csr = CsrBuilder::new_sm2("chain-test Intermediate CA", &inter_pub65)
        .expect("intermediate CSR builder")
        .build_pem(&inter_key)
        .expect("intermediate CSR sign");
    let (_serial, inter_pem) = root_signer
        .sign_csr_with_profile(inter_csr.as_bytes(), 365, &CertProfile::intermediate_ca())
        .expect("sign intermediate");
    let intermediate_cert_der = pem_to_der(&inter_pem);
    let inter_signer = CaSigner::new(inter_key, "chain-test Intermediate CA");

    // ---- Leaves signed by the intermediate ----
    let (_, server_sign_cert_der, server_sign_key_pem) = issue_leaf(
        &inter_signer,
        "server-sign.local",
        &gm_ca::profiles::tlcp::tlcp_server_sign_ecc(),
    );
    let (_, server_enc_cert_der, server_enc_key_pem) = issue_leaf(
        &inter_signer,
        "server-enc.local",
        &gm_ca::profiles::tlcp::tlcp_server_enc_ecc(),
    );
    let (_, client_sign_cert_der, client_sign_key_pem) = issue_leaf(
        &inter_signer,
        "client-sign.local",
        &gm_ca::profiles::tlcp::tlcp_client_sign_ecc(),
    );
    let (_, client_enc_cert_der, client_enc_key_pem) = issue_leaf(
        &inter_signer,
        "client-enc.local",
        &gm_ca::profiles::tlcp::tlcp_client_enc_ecc(),
    );
    let server_sign_pub_65 = gm_crypto::x509::extract_sm2_pubkey_from_der(&server_sign_cert_der)
        .expect("extract server sign pubkey");

    ChainPki {
        root_cert_der,
        intermediate_cert_der,
        server_sign_cert_der,
        server_enc_cert_der,
        server_sign_key_pem,
        server_enc_key_pem,
        server_sign_pub_65,
        client_sign_cert_der,
        client_enc_cert_der,
        client_sign_key_pem,
        client_enc_key_pem,
    }
}

const ECDHE_SM4_GCM: [u8; 2] = [0xE0, 0x51];

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
    let server = tokio::time::timeout(std::time::Duration::from_secs(20), server_handle)
        .await
        .expect("server task timed out")
        .expect("server task panicked");
    let client = tokio::time::timeout(std::time::Duration::from_secs(20), client_handle)
        .await
        .expect("client task timed out")
        .expect("client task panicked");
    match (server, client) {
        (Ok(s), Ok(c)) => Ok((s, c)),
        (_, Err(e)) => Err(format!("client: {e}")),
        (Err(e), Ok(_)) => Err(format!("server: {e}")),
    }
}

fn base_acceptor(pki: &ChainPki) -> TlcpAcceptor {
    let sign_kp =
        Sm2KeyPair::from_private_key_pem(&pki.server_sign_key_pem).expect("server sign key");
    let enc_kp = Sm2KeyPair::from_private_key_pem(&pki.server_enc_key_pem).expect("server enc key");
    TlcpAcceptor::new().with_dual_certs(
        pki.server_sign_cert_der.clone(),
        pki.server_enc_cert_der.clone(),
        sign_kp,
        enc_kp,
    )
}

fn base_connector(pki: &ChainPki) -> TlcpConnector {
    // ECDHE-SM2 suites force a server `CertificateRequest` (spec-default
    // PMS path needs the client's enc cert for `Z_client`), so every
    // connector here must present a client dual-cert pair. Acceptors
    // that do not call `with_client_ca_chain` accept any non-empty
    // chain (legacy path), so these certs are inert unless a test
    // explicitly anchors them.
    TlcpConnector::new()
        .with_cipher_suites(vec![ECDHE_SM4_GCM])
        .with_server_sign_key(pki.server_sign_pub_65.clone(), DEFAULT_DISTID.to_string())
        .with_client_certs(
            vec![
                pki.client_sign_cert_der.clone(),
                pki.client_enc_cert_der.clone(),
            ],
            pki.client_sign_key_pem.clone(),
            Some(pki.client_enc_key_pem.clone()),
            None,
        )
}

/// Server transmits `[sign_leaf, enc_leaf, intermediate]`; the client
/// trusts only the ROOT. Pre-fix this failed with a trust-anchor error
/// because the intermediate never reached the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_chain_root_anchor_handshake_succeeds() {
    let pki = generate_chain_pki();
    let acceptor = base_acceptor(&pki)
        .with_sign_cert_chain(vec![pki.intermediate_cert_der.clone()])
        .with_enc_cert_chain(vec![pki.intermediate_cert_der.clone()]);
    let connector = base_connector(&pki).with_server_ca_chain(vec![pki.root_cert_der.clone()]);

    let (mut server_stream, mut client_stream) = run_handshake(acceptor, connector)
        .await
        .expect("handshake with transmitted chain must succeed against root-only anchor");

    // Record-layer keys must match on both sides (the chain fix must
    // not perturb the transcript / key derivation).
    let msg: &[u8] = b"chain-ok";
    client_stream.write_all(msg).await.expect("client write");
    client_stream.flush().await.expect("client flush");
    let mut buf = vec![0u8; 16];
    let n = server_stream.read(&mut buf).await.expect("server read");
    assert_eq!(&buf[..n], msg);
}

/// Negative control: same PKI, but the server does NOT configure its
/// chains. The root anchor alone cannot build leaf → root, so the
/// handshake must keep failing with the pre-fix symptom.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_without_chain_root_anchor_handshake_fails() {
    let pki = generate_chain_pki();
    let acceptor = base_acceptor(&pki); // no with_*_cert_chain
    let connector = base_connector(&pki).with_server_ca_chain(vec![pki.root_cert_der.clone()]);

    let err = match run_handshake(acceptor, connector).await {
        Err(e) => e,
        Ok(_) => panic!("root anchor without a transmitted chain must not verify the leaf"),
    };
    assert!(
        err.contains("trust-anchor validation"),
        "expected a trust-anchor validation failure, got: {err}"
    );
}

/// Anchor = intermediate directly: works even without chain
/// transmission (2-level view of the same hierarchy) — the historical
/// workaround from the integration report, kept as a compatibility
/// regression guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_intermediate_anchor_still_works() {
    let pki = generate_chain_pki();
    let acceptor = base_acceptor(&pki);
    let connector =
        base_connector(&pki).with_server_ca_chain(vec![pki.intermediate_cert_der.clone()]);

    run_handshake(acceptor, connector)
        .await
        .expect("intermediate anchor must keep working");
}

/// mTLS direction: the client's `Certificate` reply already may carry
/// CA entries after the two leaves (`with_client_certs`). The server
/// must treat them as chain material — verifying sign and enc leaves
/// through the intermediate toward a ROOT-only anchor — instead of
/// re-validating each extra entry as an independent leaf.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_chain_root_anchor_handshake_succeeds() {
    let pki = generate_chain_pki();
    let acceptor = base_acceptor(&pki)
        .with_sign_cert_chain(vec![pki.intermediate_cert_der.clone()])
        .with_enc_cert_chain(vec![pki.intermediate_cert_der.clone()])
        .with_client_ca_chain(vec![pki.root_cert_der.clone()]);
    let connector = base_connector(&pki)
        .with_server_ca_chain(vec![pki.root_cert_der.clone()])
        .with_client_certs(
            vec![
                pki.client_sign_cert_der.clone(),
                pki.client_enc_cert_der.clone(),
                pki.intermediate_cert_der.clone(),
            ],
            pki.client_sign_key_pem.clone(),
            Some(pki.client_enc_key_pem.clone()),
            None,
        );

    let (mut server_stream, mut client_stream) = run_handshake(acceptor, connector)
        .await
        .expect("client chain entries beyond the leaves must be chain material, not extra leaves");

    // Server must observe the client's sign leaf as entry 0.
    let peer = server_stream.client_certificates().to_vec();
    assert_eq!(peer[0], pki.client_sign_cert_der);

    let msg: &[u8] = b"mtls-chain-ok";
    client_stream.write_all(msg).await.expect("client write");
    client_stream.flush().await.expect("client flush");
    let mut buf = vec![0u8; 32];
    let n = server_stream.read(&mut buf).await.expect("server read");
    assert_eq!(&buf[..n], msg);
}
