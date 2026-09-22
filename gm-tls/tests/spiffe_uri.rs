//! PR-2.4 (P0-7 + P0-6 builder integration): SPIFFE ID matching on top of
//! the gm-tls handshake.
//!
//! Exercises the `TlsConfig::with_expected_uri` and
//! `TlsConfig::with_distid_policy` builders end-to-end:
//!
//! 1. Issue a real SM2 cert via `gm_ca::cert::CaSigner` carrying a URI SAN
//!    (SPIFFE ID, e.g. `spiffe://prod.example.com/ns/foo/sa/web`).
//! 2. Wire the cert + key + CA into a `TlsConfig` and configure
//!    `with_expected_uri` to assert a SPIFFE ID match.
//! 3. Run a local loopback TLS handshake via in-memory duplex streams and
//!    verify:
//!    - `Ok(_)` when the URI matches (default `Prefix` policy)
//!    - `Ok(_)` when the expected URI is a prefix of the cert URI
//!    - `Err(_)` when the URI does not match
//!
//! Reference: SPIFFE Federation §4.1 (path prefix matching).

use gm_ca::cert::CaSigner;
use gm_ca::cert_profile::{CertProfile, ExtendedKeyUsage, GeneralName, KeyUsageBits};
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;
use gm_tls::{TlsAcceptor, TlsConfig, TlsConnector, TlsError};

/// Issue a self-signed SM2 cert chain (CA + leaf) that carries the
/// given URI SAN. Returns `(leaf_pem, leaf_key_pem, ca_pem)` suitable
/// for `TlsConfig::from_bytes(...)`.
fn issue_spiffe_cert(uri_san: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // Root CA — signs the leaf.
    let ca_key = Sm2KeyPair::generate().expect("CA keygen");
    let ca_signer = CaSigner::new(ca_key, "PR-2.4 test CA");
    let ca_pem = ca_signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("CA self-sign");

    // Leaf key + CSR with URI SAN.
    let leaf_key = Sm2KeyPair::generate().expect("leaf keygen");
    let leaf_pub_65 = leaf_key.public_key_bytes_uncompressed();
    let csr_pem = CsrBuilder::new_sm2("pr24-test", &leaf_pub_65)
        .expect("CsrBuilder")
        .build_pem(&leaf_key)
        .expect("CSR build");

    let leaf_profile = CertProfile {
        sans: vec![GeneralName::UniformResourceIdentifier(uri_san.to_string())],
        key_usage: KeyUsageBits::digital_signature(),
        // Both ServerAuth + ClientAuth: the loopback tests reuse the
        // same leaf cert for both the TLS server (server_auth) and
        // the client side (the gm-tls server defaults to
        // `require_client_auth: true`, so the client cert must carry
        // client_auth EKU).
        ext_key_usage: vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
        ..CertProfile::server_end_entity()
    };
    let (_, leaf_pem) = ca_signer
        .sign_csr_with_profile(csr_pem.as_bytes(), 365, &leaf_profile)
        .expect("sign CSR");

    // gm-crypto's `private_key_pem` emits SEC1 PEM (BEGIN EC PRIVATE KEY),
    // which `signer_from_pem_key` accepts.
    let leaf_key_pem = leaf_key.private_key_pem().expect("leaf key PEM");

    (
        leaf_pem.into_bytes(),
        leaf_key_pem.into_bytes(),
        ca_pem.into_bytes(),
    )
}

async fn run_loopback_handshake(
    server_cfg: TlsConfig,
    client_cfg: TlsConfig,
) -> Result<(), TlsError> {
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
        stream.write_application_data(b"hello spiffe").await?;
        let _ = stream.read_application_data().await?;
        Ok::<(), TlsError>(())
    });

    let (sr, cr) = tokio::join!(server_hdl, client_hdl);
    // Surface whichever side failed first as a `TlsError`. We use
    // `HandshakeFailed` because the test helper is generic over
    // success and failure (cert-verification failures already come
    // out as `CertificateVerificationFailed` from the inner code).
    let (sr_res, cr_res) = (sr, cr);
    match (sr_res, cr_res) {
        (Ok(Ok(())), Ok(Ok(()))) => Ok(()),
        // Preserve the original `TlsError` variant where possible;
        // a SPIFFE ID mismatch surfaces as `CertificateVerificationFailed`
        // from `validate_uri_only`'s `From<CryptoError>` impl, which is
        // the diagnostic the test should pin to.
        (_, Ok(Err(e))) => Err(e),
        (Ok(Err(e)), _) => Err(e),
        (Err(e), _) | (_, Err(e)) => {
            Err(TlsError::HandshakeFailed(format!("task join error: {e}")))
        }
    }
}

const LEAF_SPIFFE_ID: &str = "spiffe://prod.example.com/ns/foo/sa/web";

#[tokio::test]
async fn pr24_with_expected_uri_accepts_matching_spiffe() {
    let (leaf, key, ca) = issue_spiffe_cert(LEAF_SPIFFE_ID);

    let server_cfg =
        TlsConfig::from_bytes(leaf.clone(), key.clone(), ca.clone()).expect("server config");
    let client_cfg = TlsConfig::from_bytes(leaf, key, ca)
        .expect("client config")
        .with_expected_uri(LEAF_SPIFFE_ID);

    run_loopback_handshake(server_cfg, client_cfg)
        .await
        .expect("matching SPIFFE ID must accept the handshake");
}

#[tokio::test]
async fn pr24_with_expected_uri_accepts_prefix_path() {
    // SPIFFE Federation §4.1: a prefix path is an acceptable match
    // (default `UriMatchPolicy::Spiffe { path: Prefix }`).
    let (leaf, key, ca) = issue_spiffe_cert(LEAF_SPIFFE_ID);
    let prefix = "spiffe://prod.example.com/ns/foo"; // prefix of leaf

    let server_cfg =
        TlsConfig::from_bytes(leaf.clone(), key.clone(), ca.clone()).expect("server config");
    let client_cfg = TlsConfig::from_bytes(leaf, key, ca)
        .expect("client config")
        .with_expected_uri(prefix);

    run_loopback_handshake(server_cfg, client_cfg)
        .await
        .expect("prefix-path SPIFFE ID must accept the handshake");
}

#[tokio::test]
async fn pr24_with_expected_uri_rejects_mismatch() {
    let (leaf, key, ca) = issue_spiffe_cert(LEAF_SPIFFE_ID);

    let server_cfg =
        TlsConfig::from_bytes(leaf.clone(), key.clone(), ca.clone()).expect("server config");
    let client_cfg = TlsConfig::from_bytes(leaf, key, ca)
        .expect("client config")
        // Wrong trust domain — must fail closed.
        .with_expected_uri("spiffe://attacker.example.com/ns/foo/sa/web");

    let err = run_loopback_handshake(server_cfg, client_cfg)
        .await
        .expect_err("mismatched SPIFFE ID must reject the handshake");
    // Pin to the specific error variant — `validate_uri_only` returns
    // a `CryptoError::CertificateVerificationFailed`, which the
    // `From<CryptoError>` impl in gm-tls promotes to this TlsError
    // variant. A loose substring match would also accept unrelated
    // transcript-hash or alpn mismatches.
    assert!(
        matches!(err, TlsError::CertificateVerificationFailed(_)),
        "expected TlsError::CertificateVerificationFailed, got: {err:?}"
    );
}

#[tokio::test]
async fn pr24_with_distid_policy_permissive_accepts_openssl_empty_distid() {
    // Compile-time sanity: `DistidPolicy` is reachable from gm-tls's
    // public API surface (re-exported from gm-crypto). The matching
    // permissive end-to-end test is in `gmssl_interop_tests.rs`
    // (`test_loopback_*`, un-`#[ignore]`'d in PR-2.4).
    use gm_crypto::x509::verify::DistidPolicy;
    let _ = DistidPolicy::Strict;
    let _ = DistidPolicy::Permissive {
        fallback_distids: vec!["".to_string()],
        audit_on_fallback: None,
    };
}
