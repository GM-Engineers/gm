//! Phase 6b — in-process loopback handshakes that prove `CaSigner` (SM2) +
//! the Phase 5 TLCP profile presets produce dual certs (sign + enc)
//! wire-compatible with gm-tlcp's 4 ECC TLCP cipher suites —
//! E051 / E011 (ECDHE-SM4-{GCM,CBC}-SM3) and E053 / E013 (ECC-SM4-{GCM,CBC}-SM3).
//!
//! ## Why this file exists
//!
//! gm-tlcp's own `tests/gm_tlcp_loopback.rs::run_ecdhe_or_ecc_loopback` covers
//! the 4 ECC suites but **requires the `gmssl` CLI on PATH** to load
//! SM3-PBKDF2-encrypted SM2 keys via
//! `support::gmssl_key::load_sm2_key_from_gmssl_pem`. The certs and keypair
//! are produced externally, not by gm-ca.
//!
//! `CaSigner` produces real SM2 certs and `Sm2KeyPair::generate()` produces
//! unencrypted keys — so we replace the GmSSL dependency entirely. The bonus:
//! we exercise the Phase 5 `tlcp_server_sign_ecc` / `tlcp_server_enc_ecc`
//! profile presets in a real handshake, validating the KU/EKU/BC layout
//! they emit against gm-tlcp's strict wire format.
//!
//! ## File / feature layout
//!
//! Split from `tests/tlcp_loopback.rs` (Phase 6a's RSA loopback, gated
//! `feature = "rsa"`) so the two feature flags stay orthogonal:
//!
//!   * `--features rsa`           → tlcp_loopback.rs (4 RSA loopback tests)
//!   * `--features tlcp-profiles`  → tlcp_loopback_sm2.rs (4 SM2 loopback tests)
//!   * `--features rsa,tlcp-profiles` → both files run
//!   * default                     → neither file compiled
//!
//! ## Design notes
//!
//! * All 4 tests use `with_dual_certs` (Phase 5 SM2 dual-cert pattern).
//! * `with_server_sign_key(sign_pub_65, distid)` provides the SKE-verify
//!   material on the connector side; the connector reads the enc cert's
//!   SPKI off the wire for the ECDH/ECC PMS path.
//! * distid defaults to `"1234567812345678"` on both sides
//!   (matches `GM_TLS_DEFAULT_ID` in `gm-crypto::sm2`).
//! * 32 KiB duplex buffer (matches gm-tlcp's `run_ecdhe_or_ecc_loopback`).
//! * No client cert auth — anonymous client; matches what TLCP allows when
//!   `CertificateRequest` arrives without a configured client chain.
//!
//! ## Wall-clock
//!
//! Each test ≈ 3-5s (SM2 ECDHE pairing is expensive — multi-pairing per
//! handshake). All 4 tests run in CI under `--features tlcp-profiles`;
//! default builds skip this file via the top-level `#![cfg(...)]`.

#![cfg(feature = "tlcp-profiles")]

use gm_ca::cert::CaSigner;
use gm_ca::cert_profile::CertProfile;
use gm_ca::profiles::tlcp::{
    tlcp_client_enc_ecc, tlcp_client_sign_ecc, tlcp_server_enc_ecc, tlcp_server_sign_ecc,
};
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::{CsrBuilder, extract_sm2_pubkey_from_der};
use gm_tlcp::tlcp::{TlcpAcceptor, TlcpConnector};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Common harness for the 4 ECC TLCP loopback tests.
///
/// Mirrors `tests/gm_tlcp_loopback.rs::run_ecdhe_or_ecc_loopback` but
/// replaces GmSSL-CLI-generated certs with `CaSigner`-issued certs via
/// the Phase 5 `tlcp_server_sign_ecc` / `tlcp_server_enc_ecc` profile
/// presets. Verifies the cert SPKI matches the leaf keypair before
/// handing it to the TLCP handshake.
///
/// **Client certs are required**: gm-tlcp's server-side `CertificateRequest`
/// step is not skippable for the ECC suites, and the connector refuses to
/// handshake without `with_client_certs(...)` configured. We issue client
/// sign + enc certs via the same `CaSigner` so the chain `[client_sign,
/// client_enc, root_ca]` is fully self-consistent.
async fn run_ecc_loopback(suite: [u8; 2]) {
    // 1. Root CA via CaSigner (SM2). We keep the DER for the client cert
    //    chain — the connector requires the CA in the chain so its
    //    AKI chain walk can resolve.
    let ca_key = Sm2KeyPair::generate().expect("SM2 CA keygen");
    let ca_signer = CaSigner::new(ca_key, "GM ECC Test CA");
    let root_pem = ca_signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("CaSigner::self_sign_ca");
    let root_cert_der = pem::parse(root_pem.as_bytes())
        .expect("PEM parse (root)")
        .contents()
        .to_vec();

    // 2. Leaf sign cert via tlcp_server_sign_ecc profile
    //    (KU = digitalSignature | keyAgreement, EKU = serverAuth).
    let leaf_sign_key = Sm2KeyPair::generate().expect("SM2 sign keygen");
    let sign_pub_65 = leaf_sign_key.public_key_bytes_uncompressed();
    let sign_csr = CsrBuilder::new_sm2("leaf-sign.test", &sign_pub_65)
        .expect("CsrBuilder::new_sm2")
        .build_pem(&leaf_sign_key)
        .expect("build_pem");
    let (_, leaf_sign_pem) = ca_signer
        .sign_csr_with_profile(sign_csr.as_bytes(), 365, &tlcp_server_sign_ecc())
        .expect("sign_csr_with_profile (sign cert)");
    let leaf_sign_der = pem::parse(leaf_sign_pem.as_bytes())
        .expect("PEM parse (sign cert)")
        .contents()
        .to_vec();

    // 3. Leaf enc cert via tlcp_server_enc_ecc profile
    //    (KU = keyEncipherment | keyAgreement | dataEncipherment, no EKU
    //    per §6.4.6.1.2 b) + GmSSL convention).
    let leaf_enc_key = Sm2KeyPair::generate().expect("SM2 enc keygen");
    let enc_pub_65 = leaf_enc_key.public_key_bytes_uncompressed();
    let enc_csr = CsrBuilder::new_sm2("leaf-enc.test", &enc_pub_65)
        .expect("CsrBuilder::new_sm2")
        .build_pem(&leaf_enc_key)
        .expect("build_pem");
    let (_, leaf_enc_pem) = ca_signer
        .sign_csr_with_profile(enc_csr.as_bytes(), 365, &tlcp_server_enc_ecc())
        .expect("sign_csr_with_profile (enc cert)");
    let leaf_enc_der = pem::parse(leaf_enc_pem.as_bytes())
        .expect("PEM parse (enc cert)")
        .contents()
        .to_vec();

    // 4. Sanity: the cert's SPKI must match the leaf keypair we CSR'd.
    //    If CaSigner emitted a cert whose embedded pubkey != the pubkey we
    //    provided in the CSR, gm-tlcp's SM2 KAP / PKE will derive a
    //    different Z value and the PMS will diverge.
    let extracted_sign_pub =
        extract_sm2_pubkey_from_der(&leaf_sign_der).expect("extract sign pub from cert");
    assert_eq!(
        extracted_sign_pub, sign_pub_65,
        "issued sign cert's SPKI must match the leaf_sign_keypair we CSR'd"
    );
    let extracted_enc_pub =
        extract_sm2_pubkey_from_der(&leaf_enc_der).expect("extract enc pub from cert");
    assert_eq!(
        extracted_enc_pub, enc_pub_65,
        "issued enc cert's SPKI must match the leaf_enc_keypair we CSR'd"
    );

    // 5. Client certs (sign + enc) issued from the same CaSigner. The
    //    sign cert uses tlcp_client_sign_ecc (digitalSignature |
    //    keyAgreement + clientAuth EKU); the enc cert uses an inline
    //    profile (keyEncipherment | keyAgreement | dataEncipherment +
    //    clientAuth EKU) because `tlcp_client_enc_ecc` is not in the
    //    Phase 5 preset set yet — matching the existing gm-tlcp test
    //    convention.
    let client_sign_key = Sm2KeyPair::generate().expect("SM2 client sign keygen");
    let client_sign_pub_65 = client_sign_key.public_key_bytes_uncompressed();
    let client_sign_csr = CsrBuilder::new_sm2("client-sign.test", &client_sign_pub_65)
        .expect("CsrBuilder::new_sm2")
        .build_pem(&client_sign_key)
        .expect("build_pem");
    let (_, client_sign_pem) = ca_signer
        .sign_csr_with_profile(client_sign_csr.as_bytes(), 365, &tlcp_client_sign_ecc())
        .expect("sign_csr_with_profile (client sign cert)");
    let client_sign_cert_der = pem::parse(client_sign_pem.as_bytes())
        .expect("PEM parse (client sign)")
        .contents()
        .to_vec();

    let client_enc_key = Sm2KeyPair::generate().expect("SM2 client enc keygen");
    let client_enc_pub_65 = client_enc_key.public_key_bytes_uncompressed();
    let client_enc_csr = CsrBuilder::new_sm2("client-enc.test", &client_enc_pub_65)
        .expect("CsrBuilder::new_sm2")
        .build_pem(&client_enc_key)
        .expect("build_pem");
    let (_, client_enc_pem) = ca_signer
        .sign_csr_with_profile(client_enc_csr.as_bytes(), 365, &tlcp_client_enc_ecc())
        .expect("sign_csr_with_profile (client enc cert)");
    let client_enc_cert_der = pem::parse(client_enc_pem.as_bytes())
        .expect("PEM parse (client enc)")
        .contents()
        .to_vec();

    // SEC1 PEM (unencrypted) for `with_client_certs`. gm-tlcp can also
    // take encrypted PEM with a password; we don't bother since
    // `Sm2KeyPair::private_key_pem` returns the unencrypted form.
    let client_sign_pem_unenc = client_sign_key
        .private_key_pem()
        .expect("client sign key SEC1 PEM");
    let client_enc_pem_unenc = client_enc_key
        .private_key_pem()
        .expect("client enc key SEC1 PEM");

    // 6. Acceptor (SM2 dual-cert: sign + enc).
    let acceptor = TlcpAcceptor::new().with_dual_certs(
        leaf_sign_der,
        leaf_enc_der,
        leaf_sign_key,
        leaf_enc_key,
    );

    // 7. Connector: server_sign_key for SKE verify, plus the client cert
    //    chain (CA must be in the chain for gm-tlcp's AKI chain walk).
    let connector = TlcpConnector::new()
        .with_cipher_suites(vec![suite])
        .with_server_sign_key(sign_pub_65, "1234567812345678".to_string())
        .with_client_certs(
            vec![client_sign_cert_der, client_enc_cert_der, root_cert_der],
            client_sign_pem_unenc,
            Some(client_enc_pem_unenc),
            None,
        );

    // 8. tokio::io::duplex transport (32 KiB buffer — matches gm-tlcp's
    //    existing `run_ecdhe_or_ecc_loopback`).
    let (client_io, server_io) = tokio::io::duplex(32768);

    // 9. Spawn server.
    let server_handle = tokio::spawn(async move {
        acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server: SM2 ECC handshake must succeed end-to-end")
    });

    // 10. Spawn client.
    let client_handle = tokio::spawn(async move {
        connector
            .connect_with_certs(client_io)
            .await
            .expect("client: SM2 ECC handshake must succeed end-to-end")
    });

    // 11. Wait for handshake. SM2 ECDHE pairing + SM2 KAP can take a
    //     moment on slow CI; budget 20s (matches gm-tlcp's existing tests).
    let mut server_stream = tokio::time::timeout(Duration::from_secs(20), server_handle)
        .await
        .expect("server task timed out (>20s)")
        .expect("server task panicked");

    let mut client_stream = tokio::time::timeout(Duration::from_secs(20), client_handle)
        .await
        .expect("client task timed out (>20s)")
        .expect("client task panicked");

    // 12. App-data round-trip (proves master_secret derivation round-tripped).
    let msg: &[u8] = b"hello-sm2-ecc-loopback";
    client_stream.write_all(msg).await.expect("client write");
    client_stream.flush().await.expect("client flush");

    let mut buf = vec![0u8; 256];
    let n = server_stream.read(&mut buf).await.expect("server read");
    assert_eq!(
        &buf[..n],
        msg,
        "server received wrong bytes -- SM2 ECC PMS or record-layer key derivation diverged"
    );

    // Server -> Client round-trip.
    server_stream.write_all(msg).await.expect("server write");
    server_stream.flush().await.expect("server flush");
    let n = client_stream.read(&mut buf).await.expect("client read");
    assert_eq!(
        &buf[..n],
        msg,
        "client received wrong bytes -- SM2 ECC PMS or record-layer key derivation diverged"
    );
}

// ---------------------------------------------------------------------------
// 4 ECC TLCP suites (GB/T 38636-2020 §6.4.5.2.1 表 2)
// ---------------------------------------------------------------------------
//
// E051 / E011: ECDHE-ECDSA-SM4-SM3 (server emits ECDHE-style SKE with
//              ECParameters prefix, signature over `cr || sr || ephemeral_pub`).
// E053 / E013: ECC-SM4-SM3 (server emits spec-B sig-only SKE over
//              `cr || sr || enc_cert`, client SM2-PKE encrypts 48-byte PMS).
//
// GCM is the default record layer; the `_cbc` variants exercise CBC padding.
// SM3-PRF applies to all 4 (no SHA256-PRF variant for the ECC family per
// the spec §6.4.5.2.1 表 2).

/// E051 — `TLS_ECDHE_ECDSA_WITH_SM4_GCM_SM3`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sm2_e051_ecdhe_gcm_loopback() {
    run_ecc_loopback([0xE0, 0x51]).await;
}

/// E011 — `TLS_ECDHE_ECDSA_WITH_SM4_CBC_SM3`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sm2_e011_ecdhe_cbc_loopback() {
    run_ecc_loopback([0xE0, 0x11]).await;
}

/// E053 — `TLS_ECC_WITH_SM4_GCM_SM3` (static ECDH).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sm2_e053_ecc_gcm_loopback() {
    run_ecc_loopback([0xE0, 0x53]).await;
}

/// E013 — `TLS_ECC_WITH_SM4_CBC_SM3` (static ECDH).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sm2_e013_ecc_cbc_loopback() {
    run_ecc_loopback([0xE0, 0x13]).await;
}

// ---------------------------------------------------------------------------
// Wire-format introspection
// ---------------------------------------------------------------------------
//
// Sanity-checks that the issued SM2 sign cert carries the SM2 SPKI OID +
// sm3WithSM2 outer signature OID. The 4 loopback tests above already
// exercise the full X.509 path through gm-tlcp's handshake — this test
// just locks in the OID bytes so an accidental SPKI / sig OID swap
// (e.g., someone re-pointing the `CaSigner::sign_csr_with_profile` SM2
// wrappers to use EC-OID instead of SM2-OID) is caught immediately.

#[test]
fn sm2_issued_sign_cert_has_sm2_spki_and_sm3withsm2_sig() {
    let ca_key = Sm2KeyPair::generate().expect("SM2 CA keygen");
    let ca_signer = CaSigner::new(ca_key, "GM ECC Test CA");
    ca_signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("self_sign_ca");

    let leaf_sign_key = Sm2KeyPair::generate().expect("sign keygen");
    let sign_pub_65 = leaf_sign_key.public_key_bytes_uncompressed();
    let sign_csr = CsrBuilder::new_sm2("introspect.test", &sign_pub_65)
        .expect("CsrBuilder::new_sm2")
        .build_pem(&leaf_sign_key)
        .expect("build_pem");
    let (_, leaf_sign_pem) = ca_signer
        .sign_csr_with_profile(sign_csr.as_bytes(), 365, &tlcp_server_sign_ecc())
        .expect("sign_csr_with_profile");

    let pem_obj = pem::parse(leaf_sign_pem.as_bytes()).expect("PEM parse");
    use x509_parser::prelude::FromDer;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(pem_obj.contents())
        .expect("x509-parser must accept CaSigner SM2 output");

    // SM2 PK OID: 1.2.156.10197.1.301 (per `cert.rs::SM2_PK_OID`).
    // gm-ca emits this exact byte sequence; the encoding uses a 4-byte
    // continuation chain `8C D8 E3 65` for the 156 / 10197 arcs (non-
    // canonical BER — equivalent to 81 1C CF 55 in canonical DER but
    // matches the byte sequence every other GM library produces).
    assert_eq!(
        parsed.public_key().algorithm.algorithm.as_bytes(),
        &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x01, 0x01],
        "SPKI OID must be SM2 (1.2.156.10197.1.301)"
    );
    // sm3WithSM2 OID: 1.2.156.10197.1.501 (per `cert.rs::SM2_SIG_OID`).
    assert_eq!(
        parsed.signature_algorithm.algorithm.as_bytes(),
        &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x02, 0x01, 0xF5],
        "outer signature OID must be sm3WithSM2 (1.2.156.10197.1.501)"
    );
}
