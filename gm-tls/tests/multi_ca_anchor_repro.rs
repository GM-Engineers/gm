//! Multi-CA trust anchor regression tests for gm-tls.
//!
//! Pins that the chain verifier iterates the trust anchor pool
//! in both anchor orders: `[matching_ca, other_ca]` and
//! `[other_ca, matching_ca]`. The verifier must fall through to
//! the matching CA regardless of position; a `trust[0]`-only
//! lookup would silently break the second ordering.

use gm_ca::cert::CaSigner;
use gm_ca::cert_profile::{CertProfile, ExtendedKeyUsage, GeneralName, KeyUsageBits};
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;
use gm_tls::{TlsAcceptor, TlsConfig, TlsConnector, TlsError};

/// Issue a server leaf cert (signed by `ca`) carrying the SAN `localhost`.
fn issue_server_leaf(ca: &CaSigner, cn: &str) -> (Vec<u8>, Vec<u8>) {
    let leaf_key = Sm2KeyPair::generate().expect("leaf keygen");
    let leaf_pub_65 = leaf_key.public_key_bytes_uncompressed();
    let csr_pem = CsrBuilder::new_sm2(cn, &leaf_pub_65)
        .expect("CsrBuilder")
        .build_pem(&leaf_key)
        .expect("CSR build");

    let profile = CertProfile {
        sans: vec![GeneralName::DnsName("localhost".to_string())],
        key_usage: KeyUsageBits::digital_signature(),
        ext_key_usage: vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
        ..CertProfile::server_end_entity()
    };
    let (_, leaf_pem) = ca
        .sign_csr_with_profile(csr_pem.as_bytes(), 365, &profile)
        .expect("sign CSR");
    let leaf_key_pem = leaf_key.private_key_pem().expect("leaf key PEM");
    (leaf_pem.into_bytes(), leaf_key_pem.into_bytes())
}

/// Issue a root CA. Returns `(ca_pem, ca_signer)`.
fn issue_ca(name: &str) -> (Vec<u8>, CaSigner) {
    let key = Sm2KeyPair::generate().expect("CA keygen");
    let signer = CaSigner::new(key, name);
    let pem = signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("CA self-sign");
    (pem.into_bytes(), signer)
}

async fn run_handshake(server_cfg: TlsConfig, client_cfg: TlsConfig) -> Result<(), TlsError> {
    let acceptor = TlsAcceptor::new(server_cfg).expect("acceptor");
    let connector = TlsConnector::new(client_cfg).expect("connector");

    let (client_io, server_io) = tokio::io::duplex(8192);

    let server_hdl = tokio::spawn(async move {
        let mut stream = acceptor.accept(server_io).await?;
        let data = stream.read_application_data().await?;
        stream.write_application_data(&data).await?;
        Ok::<(), TlsError>(())
    });

    let client_hdl = tokio::spawn(async move {
        let mut stream = connector.connect(client_io).await?;
        stream.write_application_data(b"hello").await?;
        let _ = stream.read_application_data().await?;
        Ok::<(), TlsError>(())
    });

    let (sr, cr) = tokio::join!(server_hdl, client_hdl);
    match (sr, cr) {
        (Ok(Ok(())), Ok(Ok(()))) => Ok(()),
        (_, Ok(Err(e))) => Err(e),
        (Ok(Err(e)), _) => Err(e),
        (Err(e), _) | (_, Err(e)) => {
            Err(TlsError::HandshakeFailed(format!("task join error: {e}")))
        }
    }
}

/// Build a client trust anchor pool from a list of (ca_pem, name)
/// references, in the requested concatenation order. Newlines separate
/// each PEM block so PEM parsers that walk the buffer once will see
/// every block.
fn build_anchor_pool(ordered_pems: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (i, pem) in ordered_pems.iter().enumerate() {
        if i > 0 {
            buf.extend_from_slice(b"\n");
        }
        buf.extend_from_slice(pem);
    }
    buf
}

/// Reference scenario from the issue: client has `[ca_b, ca_a]` anchors
/// (correct CA first) and server is signed by ca_b. Must succeed.
#[tokio::test]
async fn multi_ca_anchor_first_match_succeeds() {
    let (ca_a_pem, _ca_a) = issue_ca("ca-a");
    let (ca_b_pem, ca_b) = issue_ca("ca-b");

    // Server: signed by ca_b. Trust anchor = ca_b (server's "client_ca_root").
    let (server_leaf, server_key) = issue_server_leaf(&ca_b, "server-b");
    let server_cfg =
        TlsConfig::from_bytes(server_leaf.clone(), server_key.clone(), ca_b_pem.clone())
            .expect("server cfg")
            .with_domain("localhost".to_string());

    // Client: signed by ca_b. Trust anchors = [ca_b, ca_a].
    let (client_leaf, client_key) = issue_server_leaf(&ca_b, "client-b");
    let anchors = build_anchor_pool(&[&ca_b_pem, &ca_a_pem]);
    let client_cfg = TlsConfig::from_bytes(client_leaf, client_key, anchors)
        .expect("client cfg")
        .with_domain("localhost".to_string());

    let result = run_handshake(server_cfg, client_cfg).await;
    assert!(
        result.is_ok(),
        "expected handshake to succeed when matching CA is first, got: {:?}",
        result.err()
    );
}

/// Bug scenario from the issue: client has `[ca_a, ca_b]` anchors
/// (wrong CA first, matching CA second). The verifier should fall
/// through to the second anchor and succeed. The reported bug says
/// the handshake fails with ConnectionReset instead.
#[tokio::test]
async fn multi_ca_anchor_wrong_first_right_second_falls_through() {
    let (ca_a_pem, _ca_a) = issue_ca("ca-a");
    let (ca_b_pem, ca_b) = issue_ca("ca-b");

    // Server: signed by ca_b.
    let (server_leaf, server_key) = issue_server_leaf(&ca_b, "server-b");
    let server_cfg =
        TlsConfig::from_bytes(server_leaf.clone(), server_key.clone(), ca_b_pem.clone())
            .expect("server cfg")
            .with_domain("localhost".to_string());

    // Client: signed by ca_b. Trust anchors = [ca_a, ca_b] — ca_a is
    // first; ca_a does NOT match the server's issuer.
    let (client_leaf, client_key) = issue_server_leaf(&ca_b, "client-b");
    let anchors = build_anchor_pool(&[&ca_a_pem, &ca_b_pem]);
    let client_cfg = TlsConfig::from_bytes(client_leaf, client_key, anchors)
        .expect("client cfg")
        .with_domain("localhost".to_string());

    let result = run_handshake(server_cfg, client_cfg).await;
    assert!(
        result.is_ok(),
        "expected handshake to fall through to the matching CA, got: {:?}",
        result.err()
    );
}

/// Single-anchor baseline: with only the wrong CA, the verifier must
/// return a clean `CertificateVerificationFailed` (not a transport
/// reset). This is what the issue describes as the "对照" reference.
#[tokio::test]
async fn single_wrong_ca_returns_clean_cert_error() {
    let (ca_a_pem, _ca_a) = issue_ca("ca-a");
    let (ca_b_pem, ca_b) = issue_ca("ca-b");

    // Server: signed by ca_b.
    let (server_leaf, server_key) = issue_server_leaf(&ca_b, "server-b");
    let server_cfg =
        TlsConfig::from_bytes(server_leaf.clone(), server_key.clone(), ca_b_pem.clone())
            .expect("server cfg")
            .with_domain("localhost".to_string());

    // Client: signed by ca_b, but only ca_a in trust anchors.
    let (client_leaf, client_key) = issue_server_leaf(&ca_b, "client-b");
    let client_cfg = TlsConfig::from_bytes(client_leaf, client_key, ca_a_pem)
        .expect("client cfg")
        .with_domain("localhost".to_string());

    let err = run_handshake(server_cfg, client_cfg)
        .await
        .expect_err("single wrong CA must fail the handshake");
    assert!(
        matches!(err, TlsError::CertificateVerificationFailed(_)),
        "expected TlsError::CertificateVerificationFailed, got: {err:?}"
    );
}
