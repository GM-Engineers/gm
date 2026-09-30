//! Multi-CA CRL issuer lookup regression test.
//!
//! `gm-tls` CRL verification must look up the CRL's issuer DN
//! across the entire trust anchor pool, not only at `trust[0]`.
//! Multi-CA trust pools (federation, dual-trust-domain gateways)
//! put multiple CA certs in the PEM concat; assuming the CRL
//! issuer is at index 0 breaks any deployment where that
//! assumption doesn't hold.

use gm_ca::cert::{CaSigner, CrlEntry};
use gm_ca::cert_profile::{CertProfile, ExtendedKeyUsage, GeneralName, KeyUsageBits};
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;
use gm_tls::{TlsAcceptor, TlsConfig, TlsConnector, TlsError};

fn issue_ca(name: &str) -> (Vec<u8>, CaSigner) {
    let key = Sm2KeyPair::generate().expect("CA keygen");
    let signer = CaSigner::new(key, name);
    let pem = signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("CA self-sign");
    (pem.into_bytes(), signer)
}

fn issue_leaf(ca: &CaSigner, cn: &str) -> (Vec<u8>, Vec<u8>) {
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

/// Empty CRL signed by `ca` (no revoked serials). The CRL's
/// issuer DN is the CA's CN.
fn issue_empty_crl(ca: &CaSigner) -> Vec<u8> {
    let entries: Vec<CrlEntry> = Vec::new();
    ca.generate_crl(&entries, 1).expect("CA generate_crl")
}

/// Build a client/server trust anchor pool from a list of
/// `(ca_pem, name)` PEM blocks, in the requested concatenation
/// order. Newlines separate each PEM block so PEM parsers that
/// walk the buffer once see every block.
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

/// Build a `CrlInfo` from DER bytes (gm-ca's `generate_crl`
/// emits DER, not PEM).
fn crl_info_from_der(der: &[u8]) -> gm_tls::gm::CrlInfo {
    use gm_tls::gm::CrlInfo;
    CrlInfo::from_der(der).expect("CRL DER parse")
}

async fn run_handshake(server_cfg: TlsConfig, client_cfg: TlsConfig) -> Result<(), TlsError> {
    let acceptor = TlsAcceptor::new(server_cfg).expect("acceptor");
    let connector = TlsConnector::new(client_cfg).expect("connector");

    let (client_io, server_io) = tokio::io::duplex(65536);

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

/// Two-CA fixture + a CRL signed by ca_b. Returns all the
/// parts the multi-CA CRL tests need:
/// `(ca_a_pem, ca_b_pem, leaf_b_pem, leaf_b_key, crl_b_der)`.
fn make_two_ca_with_crl() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (ca_a_pem, _ca_a) = issue_ca("ca-a");
    let (ca_b_pem, ca_b) = issue_ca("ca-b");

    // CRL signed by ca_b (issuer DN = "CN=ca-b").
    let crl_b_der = issue_empty_crl(&ca_b);

    // Leaf cert signed by ca_b.
    let (leaf_b_pem, leaf_b_key) = issue_leaf(&ca_b, "server-b");

    (ca_a_pem, ca_b_pem, leaf_b_pem, leaf_b_key, crl_b_der)
}

/// Trust anchor order `[ca_b, ca_a]` with CRL signed by ca_b:
/// baseline — the matching CA happens to be at index 0, so the
/// CRL check passes whether we iterate the pool or just use
/// `trust[0]`.
#[tokio::test]
async fn crl_match_first_succeeds() {
    let (ca_a_pem, ca_b_pem, leaf_b_pem, leaf_b_key, crl_b_der) = make_two_ca_with_crl();
    let crl_info = crl_info_from_der(&crl_b_der);

    let server_cfg =
        TlsConfig::from_bytes(leaf_b_pem.clone(), leaf_b_key.clone(), ca_b_pem.clone())
            .expect("server cfg")
            .with_domain("localhost".to_string());
    let anchors = build_anchor_pool(&[&ca_b_pem, &ca_a_pem]);
    let client_cfg = TlsConfig::from_bytes(leaf_b_pem, leaf_b_key, anchors)
        .expect("client cfg")
        .with_domain("localhost".to_string())
        .with_crl_info(crl_info);

    let result = run_handshake(server_cfg, client_cfg).await;
    assert!(
        result.is_ok(),
        "expected Ok with matching CA first, got: {:?}",
        result.err()
    );
}

/// Trust anchor order `[ca_a, ca_b]` with CRL signed by ca_b:
/// the matching CA is at index 1, so the CRL check must
/// iterate the pool to find it.
#[tokio::test]
async fn crl_match_second_succeeds() {
    let (ca_a_pem, ca_b_pem, leaf_b_pem, leaf_b_key, crl_b_der) = make_two_ca_with_crl();
    let crl_info = crl_info_from_der(&crl_b_der);

    let server_cfg =
        TlsConfig::from_bytes(leaf_b_pem.clone(), leaf_b_key.clone(), ca_b_pem.clone())
            .expect("server cfg")
            .with_domain("localhost".to_string());
    let anchors = build_anchor_pool(&[&ca_a_pem, &ca_b_pem]);
    let client_cfg = TlsConfig::from_bytes(leaf_b_pem, leaf_b_key, anchors)
        .expect("client cfg")
        .with_domain("localhost".to_string())
        .with_crl_info(crl_info);

    let result = run_handshake(server_cfg, client_cfg).await;
    assert!(
        result.is_ok(),
        "expected Ok with matching CA second, got: {:?}",
        result.err()
    );
}

/// Trust pool `[ca_a, ca_b]` but CRL signed by ca_c (NOT in
/// the trust pool). The chain check must pass (server cert is
/// signed by ca_b which IS in the pool); only then does the
/// CRL check run. The CRL check must surface the real cause
/// (`no trust anchor matches CRL issuer`) rather than the
/// misleading "CRL signature verification failed" that a
/// `trust[0]`-only lookup would produce.
#[tokio::test]
async fn crl_no_matching_anchor_clean_error() {
    // Two CAs in the trust pool.
    let (ca_a_pem, _ca_a) = issue_ca("ca-a");
    let (ca_b_pem, ca_b) = issue_ca("ca-b");
    // A third CA that signs the CRL but is NOT in the pool.
    let (_ca_c_pem, ca_c) = issue_ca("ca-c");

    let crl_c_der = issue_empty_crl(&ca_c);

    let (leaf_b_pem, leaf_b_key) = issue_leaf(&ca_b, "server-b");

    let server_cfg =
        TlsConfig::from_bytes(leaf_b_pem.clone(), leaf_b_key.clone(), ca_b_pem.clone())
            .expect("server cfg")
            .with_domain("localhost".to_string());
    let anchors = build_anchor_pool(&[&ca_a_pem, &ca_b_pem]);
    let crl_info = crl_info_from_der(&crl_c_der);
    let client_cfg = TlsConfig::from_bytes(leaf_b_pem, leaf_b_key, anchors)
        .expect("client cfg")
        .with_domain("localhost".to_string())
        .with_crl_info(crl_info);

    let err = run_handshake(server_cfg, client_cfg)
        .await
        .expect_err("CRL signed by an unknown CA must fail");
    assert!(
        matches!(err, TlsError::CrlVerificationFailed(_)),
        "expected TlsError::CrlVerificationFailed, got: {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("no trust anchor matches CRL issuer"),
        "expected explicit 'no trust anchor matches CRL issuer' message, got: {msg}"
    );
}
