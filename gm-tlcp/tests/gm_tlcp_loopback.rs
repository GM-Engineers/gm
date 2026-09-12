//! PR-A regression test for audit C-3 (gm-tlcp server-side PMS).
//!
//! Validates that the SM2 Key Agreement Protocol (GB/T 38636-2020
//! §6.4.6.2 + GM/T 0003.3-2012 §6.1) produces the same pre-master
//! secret on both sides when the test's real SM2 keypairs are fed
//! in.
//!
//! This is a focused unit-level test that exercises the
//! `compute_tlcp_ecdhe_pms` path introduced by PR-A without going
//! through the full handshake state machine. The full in-process
//! loopback test was attempted but the gm-tlcp handshake state
//! machine has pre-existing wire-format bugs that are out of scope
//! for PR-A (see `AUDIT-2026-09-06-v2.md` for the full audit).
//!
//! Requires the `tlcp-profiles` feature so the
//! `support::gmca_cert_setup` helper can sign the cert hierarchy with
//! `gm-ca::CaSigner` in-process (no external `gmssl` binary needed).
//! The pre-Phase-12 build relied on the `gmssl` CLI; that dependency
//! was removed in Phase 12 / R-12.

#![cfg(test)]
#![cfg(feature = "tlcp-profiles")]

mod support;
use support::gmca_cert_setup::{GmcaCerts, generate_gmca_test_certs};

use gm_crypto::sm2::Sm2KeyPair;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_kap_pms_roundtrip_with_real_keys() {
    // Verify that the SM2 Key Agreement Protocol produces the same
    // pre-master secret on both sides when the test's real keypairs
    // are used as input. This exercises the server-side PMS code
    // path added by PR-A (audit C-3) without depending on the full
    // handshake state machine.
    //
    // Phase 12 (R-12): cert generation moved from the `gmssl` CLI to
    // the in-process `gmca_cert_setup` helper, so this test no longer
    // gates on `gmssl_present()`.

    let tmp = std::env::temp_dir().join(format!("gm-tlcp-kap-test-{}", std::process::id()));
    let certs: GmcaCerts = generate_gmca_test_certs(&tmp).expect("generate_gmca_test_certs");

    // SEC1 PEM keys come straight out of the helper — no PBES2
    // decryption needed.
    let server_enc_kp = Sm2KeyPair::from_private_key_pem(&certs.server_enc_key_pem)
        .expect("server enc SEC1 PEM parse");
    let client_enc_kp = Sm2KeyPair::from_private_key_pem(&certs.client_enc_key_pem)
        .expect("client enc SEC1 PEM parse");

    // Extract the 64-byte x||y SM2 pubkey from each enc cert so we
    // can feed it to `compute_tlcp_ecdhe_pms`. We use the
    // `gm_crypto::x509::extract_sm2_pubkey_from_der` free function
    // directly because the gm-tlcp-internal re-export is private.
    let client_enc_pub_sec1 =
        gm_crypto::x509::extract_sm2_pubkey_from_der(&certs.client_enc_cert_der)
            .expect("client enc pub");
    let mut client_enc_xy = [0u8; 64];
    client_enc_xy.copy_from_slice(&client_enc_pub_sec1[1..65]);

    // The server's own enc pubkey comes from the keypair itself.
    let server_enc_sec1 = server_enc_kp.public_key_bytes_uncompressed();
    let mut server_enc_xy = [0u8; 64];
    server_enc_xy.copy_from_slice(&server_enc_sec1[1..65]);

    // Generate matching ephemeral keypairs for both sides.
    use gm_crypto::sm2::Sm2EcdhKeypair;
    let server_ephemeral_kp = Sm2EcdhKeypair::generate().expect("server eph");
    let client_ephemeral_kp = Sm2EcdhKeypair::generate().expect("client eph");

    let server_ephemeral_sec1 = server_ephemeral_kp.public_key_bytes();
    let mut server_ephemeral_xy = [0u8; 64];
    server_ephemeral_xy.copy_from_slice(&server_ephemeral_sec1[1..65]);
    let server_ephemeral_priv: [u8; 32] = {
        let v = server_ephemeral_kp.private_key_bytes();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    };

    let client_ephemeral_sec1 = client_ephemeral_kp.public_key_bytes();
    let mut client_ephemeral_xy = [0u8; 64];
    client_ephemeral_xy.copy_from_slice(&client_ephemeral_sec1[1..65]);
    let client_ephemeral_priv: [u8; 32] = {
        let v = client_ephemeral_kp.private_key_bytes();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    };

    // Derive Z values using the same default distid the strict-mode
    // server uses.
    let server_enc_priv_bytes = server_enc_kp.private_key_bytes();
    let mut server_enc_priv = [0u8; 32];
    server_enc_priv.copy_from_slice(&server_enc_priv_bytes);
    let client_enc_priv_bytes = client_enc_kp.private_key_bytes();
    let mut client_enc_priv = [0u8; 32];
    client_enc_priv.copy_from_slice(&client_enc_priv_bytes);

    let distid: &[u8] = b"1234567812345678";
    let z_server = gm_tlcp::tlcp::pms::sm2_compute_z(&server_enc_xy, distid).expect("Z_server");
    let z_client = gm_tlcp::tlcp::pms::sm2_compute_z(&client_enc_xy, distid).expect("Z_client");

    // Compute PMS from server side (mirrors `accept_with_certs`
    // step 8 in the strict-mode branch).
    let pms_server = gm_tlcp::tlcp::pms::compute_tlcp_ecdhe_pms(
        &server_enc_xy,
        &server_enc_priv,
        &server_ephemeral_xy,
        &server_ephemeral_priv,
        &client_enc_xy,
        &client_ephemeral_xy,
        &z_server,
        &z_client,
        48,
    )
    .expect("server PMS");

    // Compute PMS from client side (mirrors the connector's call).
    let pms_client = gm_tlcp::tlcp::pms::compute_tlcp_ecdhe_pms(
        &client_enc_xy,
        &client_enc_priv,
        &client_ephemeral_xy,
        &client_ephemeral_priv,
        &server_enc_xy,
        &server_ephemeral_xy,
        &z_server,
        &z_client,
        48,
    )
    .expect("client PMS");

    assert_eq!(pms_server.len(), 48, "PMS must be 48 bytes");
    assert_eq!(
        pms_server, pms_client,
        "server and client PMS must match — \
         PR-A C-3 fix is broken"
    );
}
// Note: the R-2 spec-B SKE roundtrip tests live as unit tests in
// `src/tlcp/messages/ecdhe.rs::tests` and `src/tlcp/crypto/verify.rs::tests`
// because they require crate-private access to `verify_ske_signature`.

// ============================================================================
// RSA suites loopback regression tests (R-5, gm-tlcp 0.6.0)
// ============================================================================
//
// These are the regression gate for the 4 RSA cipher suites
// (E019/E01C/E059/E05A). They wire `TlcpAcceptor` + `TlcpConnector`
// through `tokio::io::duplex`, complete a full RSA handshake (GCM or
// CBC), and exchange a single app-data record round-trip to prove the
// record layer also works post-handshake.
//
// Pre-flight: the server must complete step 5 (RSA-PKCS1-v1_5-signed
// SKE) + step 8 (RSAES-PKCS1-v1_5-decrypted PMS) with the same 48-byte
// PMS the client encrypted in step 7.5. This exercises:
//   - the RSA-SKE signature verify (step 5) with SM3 PKCS#1 v1.5 DigestInfo
//   - the RSAES-PKCS1-v1_5 envelope encrypt/decrypt (steps 7.5 / 8)
//   - the master_secret derivation round-trip
//
// These tests do NOT require the `gmssl` CLI. The RSA keypair is
// generated locally via `rsa_helpers::RsaKeyPair::generate(2048)`
// (2048-bit modulus for speed; production should use 3072 or 4096).
// The "RSA cert" sent in the Certificate message is a dummy 100-byte
// DER blob: the connector step 5 SKE-verify path takes the cert bytes
// verbatim as part of the signature input, but it does NOT extract
// the RSA pubkey from the cert (the pubkey comes from
// `with_rsa_certs(server_rsa_pub)`). So the cert just needs to match
// the bytes the server signed over — which it does, by construction.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_rsa_loopback_with_real_keys_gcm() {
    run_rsa_loopback([0xE0, 0x59]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_rsa_loopback_with_real_keys_cbc() {
    run_rsa_loopback([0xE0, 0x19]).await;
}

async fn run_rsa_loopback(suite: [u8; 2]) {
    use gm_tlcp::tlcp::*;

    // 1. RSA keypair for the server. 2048-bit modulus keeps the test
    //    snappy (~1s for keygen + a few encrypt/decrypt/sign/verify).
    let rsa_kp = gm_tlcp::tlcp::rsa_helpers::RsaKeyPair::generate(2048).expect("rsa keypair gen");
    let rsa_pub = rsa_kp.to_public_key().expect("rsa public key");

    // 2. Configure both sides. RSA suites need no SM2 dual-certs; the
    //    connector only needs the RSA pubkey (for SKE verify + CKE
    //    encrypt); the acceptor only needs the RSA keypair + a dummy
    //    RSA cert blob.
    let rsa_cert_der: Vec<u8> = (0..100u8).collect(); // dummy DER blob
    let acceptor = TlcpAcceptor::new().with_rsa_certs(rsa_kp, rsa_cert_der);

    let connector = TlcpConnector::new()
        .with_cipher_suites(vec![suite])
        .with_rsa_certs(rsa_pub);

    // 3. tokio::io::duplex transport (same pattern as the SM9 loopback
    //    tests above; 16 KiB buffer is plenty for a 1-record exchange).
    let (client_io, server_io) = tokio::io::duplex(16384);

    // 4. Spawn server.
    let server_handle = tokio::spawn(async move {
        acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server: RSA handshake must succeed in 0.6.0")
    });

    // 5. Spawn client.
    let client_handle = tokio::spawn(async move {
        connector
            .connect_with_certs(client_io)
            .await
            .expect("client: RSA handshake must succeed in 0.6.0")
    });

    // 6. Wait for handshake to complete. RSA keygen + 1 encrypt is
    //    the dominant cost; budget 15s to be safe on slow CI.
    let mut server_stream = tokio::time::timeout(std::time::Duration::from_secs(15), server_handle)
        .await
        .expect("server task timed out (>15s)")
        .expect("server task panicked");

    let mut client_stream = tokio::time::timeout(std::time::Duration::from_secs(15), client_handle)
        .await
        .expect("client task timed out (>15s)")
        .expect("client task panicked");

    // 7. Exchange a single app-data record to prove the record layer
    //    works post-handshake (proves master_secret derivation was
    //    correct on both sides).
    let msg: &[u8] = b"hello-rsa";
    client_stream.write_all(msg).await.expect("client write");
    client_stream.flush().await.expect("client flush");

    let mut buf = vec![0u8; 256];
    let n = server_stream.read(&mut buf).await.expect("server read");
    assert_eq!(
        &buf[..n],
        msg,
        "server received wrong bytes -- RSA PMS derivation diverged"
    );

    // Server -> Client round-trip.
    server_stream.write_all(msg).await.expect("server write");
    server_stream.flush().await.expect("server flush");
    let n = client_stream.read(&mut buf).await.expect("client read");
    assert_eq!(
        &buf[..n],
        msg,
        "client received wrong bytes -- RSA PMS derivation diverged"
    );
}

// ============================================================================
// SM9 IBC loopback regression tests (R-4.1-hotfix, gm-tlcp 0.5.2)
// ============================================================================
//
// These are the regression gate for the R-4.1 wire-protocol gap documented
// in AUDIT-2026-09-06-v2.md v2-rev6 (Bug 1 + Bug 2). They wire
// `TlcpAcceptor` + `TlcpConnector` through `tokio::io::duplex`, complete a
// full SM9 IBC handshake (E057 or E017), and exchange a single app-data
// record round-trip to prove the record layer also works post-handshake.
//
// These tests do NOT require the `gmssl` CLI. The SM2 dual-certs are dummy
// DER blobs (the IBC path doesn't consume them — see Bug 3 below) and
// the SM9 keys are generated locally via `KgcMasterKey::generate()`.
//
// Bug 3 in this fix: the server must skip CertificateRequest emission
// (step 5.5) AND the Client Certificate read (step 7) for IBC suites,
// per GB/T 38636-2020 §6.4.5.4. Without these skips the connector
// would error out with "Server sent CertificateRequest but no client
// certificate was configured".

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_sm9_ibc_loopback_with_real_keys_gcm() {
    run_sm9_ibc_loopback([0xE0, 0x57]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_sm9_ibc_loopback_with_real_keys_cbc() {
    run_sm9_ibc_loopback([0xE0, 0x17]).await;
}

async fn run_sm9_ibc_loopback(suite: [u8; 2]) {
    use gm_tlcp::tlcp::*;

    // 1. SM9 KGC + identity.
    let kgc = gm_sm9_rs::key::KgcMasterKey::generate().expect("kgc master");
    let ppube = kgc.enc_master().ppube;
    let ppubs = kgc.sign_master().ppubs;
    let server_id = b"sm9-ibc-server@tlcp.local".to_vec();

    // 2. SM2 dual-cert keypairs for the acceptor's cert pair. The IBC
    //    path does not consume these (no SM2 PKE / no SM2 sig), but
    //    `accept_with_certs` requires them to be configured.
    let sign_kp = gm_crypto::sm2::Sm2KeyPair::generate().expect("sign kp");
    let enc_kp = gm_crypto::sm2::Sm2KeyPair::generate().expect("enc kp");

    // 3. Configure both sides.
    let acceptor = TlcpAcceptor::new()
        .with_dual_certs(
            vec![0x01; 100], // dummy sign cert DER
            vec![0x02; 100], // dummy enc cert DER
            sign_kp,
            enc_kp,
        )
        .with_sm9_certs(kgc, server_id.clone());

    let connector = TlcpConnector::new()
        .with_cipher_suites(vec![suite])
        .with_sm9_certs(ppube, ppubs, server_id);

    // 4. tokio::io::duplex transport.
    let (client_io, server_io) = tokio::io::duplex(16384);

    // 5. Spawn server.
    let server_handle = tokio::spawn(async move {
        acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server: SM9 IBC handshake must succeed in 0.5.2+")
    });

    // 6. Spawn client.
    let client_handle = tokio::spawn(async move {
        connector
            .connect_with_certs(client_io)
            .await
            .expect("client: SM9 IBC handshake must succeed in 0.5.2+")
    });

    // 7. Wait for handshake to complete.
    let mut server_stream = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle)
        .await
        .expect("server task timed out (>5s)")
        .expect("server task panicked");

    let mut client_stream = tokio::time::timeout(std::time::Duration::from_secs(5), client_handle)
        .await
        .expect("client task timed out (>5s)")
        .expect("client task panicked");

    // 8. Exchange a single app-data record to prove the record layer
    //    works post-handshake (proves master_secret derivation was
    //    correct on both sides).
    let msg: &[u8] = b"hello-ibc";
    client_stream.write_all(msg).await.expect("client write");
    client_stream.flush().await.expect("client flush");

    let mut buf = vec![0u8; 256];
    let n = server_stream.read(&mut buf).await.expect("server read");
    assert_eq!(
        &buf[..n],
        msg,
        "server received wrong bytes — IBC PMS derivation diverged"
    );

    // Server → Client round-trip.
    server_stream.write_all(msg).await.expect("server write");
    server_stream.flush().await.expect("server flush");
    let n = client_stream.read(&mut buf).await.expect("client read");
    assert_eq!(
        &buf[..n],
        msg,
        "client received wrong bytes — IBC PMS derivation diverged"
    );
}

// ============================================================================
// SM9 IBSDH loopback regression tests (R-4.2, gm-tlcp 0.5.3)
// ============================================================================
//
// These are the regression gate for the SM9 IBSDH wire-protocol path
// (audit C-5 IBSDH half). They wire `TlcpAcceptor` + `TlcpConnector`
// through `tokio::io::duplex`, complete a full SM9 IBSDH handshake
// (E055 or E015), and exchange a single app-data record round-trip
// to prove the record layer also works post-handshake.
//
// Pre-flight: the server must complete step 5 + step 8 with an
// identical SM9 IBSDH PMS as the client. This exercises:
//   - the deferred SKE emit pattern (server reads R_A in CKE before
//     emitting its SKE-IBSDH with (ra, rb, sb))
//   - the client's `initiator_finish` S_B verification
//   - the master_secret derivation round-trip
//
// These tests do NOT require the `gmssl` CLI. The SM2 dual-certs are
// dummy DER blobs (the IBSDH path doesn't consume them) and the SM9
// keys are generated locally via `KgcMasterKey::generate()`.
//
// Note: this v1 implementation uses the documented `client_id =
// server_id` shortcut (single SM9 identity). See CHANGELOG [0.5.3]
// and R-4.2 plan §2 for the tradeoffs.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_sm9_ibsdh_loopback_with_real_keys_gcm() {
    run_sm9_ibsdh_loopback([0xE0, 0x55]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_sm9_ibsdh_loopback_with_real_keys_cbc() {
    run_sm9_ibsdh_loopback([0xE0, 0x15]).await;
}

async fn run_sm9_ibsdh_loopback(suite: [u8; 2]) {
    use gm_tlcp::tlcp::*;

    // 1. SM9 KGC + identity.
    let kgc = gm_sm9_rs::key::KgcMasterKey::generate().expect("kgc master");
    let ppube = kgc.enc_master().ppube;
    let ppubs = kgc.sign_master().ppubs;
    let server_id = b"sm9-ibsdh-server@tlcp.local".to_vec();

    // 2. SM2 dual-cert keypairs for the acceptor's cert pair. The IBSDH
    //    path does not consume these (no SM2 PKE / no SM2 sig), but
    //    `accept_with_certs` requires them to be configured.
    let sign_kp = gm_crypto::sm2::Sm2KeyPair::generate().expect("sign kp");
    let enc_kp = gm_crypto::sm2::Sm2KeyPair::generate().expect("enc kp");

    // 3. Configure both sides.
    //
    // SM9 IBSDH requires both parties to derive their user keys from the
    // SAME KGC master — otherwise de_a and de_b produce different
    // shared secrets and the key confirmation S_B mismatches. The
    // acceptor takes ownership of the kgc in `with_sm9_certs`, so we
    // pre-extract the client's `de_a` from the SAME kgc before
    // handing the kgc to the acceptor.
    let de_a = kgc
        .enc_master()
        .extract_key_exchange(&server_id)
        .expect("de_a extract from shared kgc");

    let acceptor = TlcpAcceptor::new()
        .with_dual_certs(
            vec![0x01; 100], // dummy sign cert DER
            vec![0x02; 100], // dummy enc cert DER
            sign_kp,
            enc_kp,
        )
        .with_sm9_certs(kgc, server_id.clone());

    // v1 shortcut: client_id = server_id (single SM9 identity).
    let connector = TlcpConnector::new()
        .with_cipher_suites(vec![suite])
        .with_sm9_certs(ppube, ppubs, server_id.clone())
        .with_sm9_client_exchange_key(de_a, server_id);

    // 4. tokio::io::duplex transport.
    let (client_io, server_io) = tokio::io::duplex(16384);

    // 5. Spawn server.
    let server_handle = tokio::spawn(async move {
        acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server: SM9 IBSDH handshake must succeed in 0.5.3")
    });

    // 6. Spawn client.
    let client_handle = tokio::spawn(async move {
        connector
            .connect_with_certs(client_io)
            .await
            .expect("client: SM9 IBSDH handshake must succeed in 0.5.3")
    });

    // 7. Wait for handshake to complete. SM9 pairing is expensive, so
    //    we use a 10s timeout (vs. the 5s for IBC suites).
    let mut server_stream = tokio::time::timeout(std::time::Duration::from_secs(10), server_handle)
        .await
        .expect("server task timed out (>10s)")
        .expect("server task panicked");

    let mut client_stream = tokio::time::timeout(std::time::Duration::from_secs(10), client_handle)
        .await
        .expect("client task timed out (>10s)")
        .expect("client task panicked");

    // 8. Exchange a single app-data record to prove the record layer
    //    works post-handshake (proves master_secret derivation was
    //    correct on both sides).
    let msg: &[u8] = b"hello-ibsdh";
    client_stream.write_all(msg).await.expect("client write");
    client_stream.flush().await.expect("client flush");

    let mut buf = vec![0u8; 256];
    let n = server_stream.read(&mut buf).await.expect("server read");
    assert_eq!(
        &buf[..n],
        msg,
        "server received wrong bytes -- IBSDH PMS derivation diverged"
    );

    // Server -> Client round-trip.
    server_stream.write_all(msg).await.expect("server write");
    server_stream.flush().await.expect("server flush");
    let n = client_stream.read(&mut buf).await.expect("client read");
    assert_eq!(
        &buf[..n],
        msg,
        "client received wrong bytes -- IBSDH PMS derivation diverged"
    );
}

// ============================================================================
// RSA single-Cert loopback regression tests (R-7, gm-tlcp 0.6.2+)
// ============================================================================
//
// R-11 follow-up (gm-tlcp 0.6.4+) added single-Cert variants for the
// RSA-SHA256 suites as well; see the "RSA SHA-256-PRF suites" section
// above for the E05A / E01C coverage.
//
// These are the regression gate for the single-Certificate wire-format
// for the 4 RSA suites (E019/E01C/E059/E05A). Per GB/T 38636-2020
// §6.4.5.5, RSA suites use exactly one cert entry in the Certificate
// handshake message (matches openHiTLS / Tongsuo convention). The
// server-side emission is opt-in via `TlcpAcceptor::with_rsa_certs_single`
// (gm-tlcp 0.6.0 / 0.6.1 used a dual-cert workaround for compatibility
// with the existing serializer).
//
// These tests do NOT require the `gmssl` CLI. The RSA keypair is
// generated locally via `rsa_helpers::RsaKeyPair::generate(2048)` and
// the "RSA cert" sent in the Certificate message is a dummy 100-byte
// DER blob (same convention as the R-5 dual-cert tests).

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_rsa_single_cert_loopback_with_real_keys_gcm() {
    run_rsa_single_cert_loopback([0xE0, 0x59]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_rsa_single_cert_loopback_with_real_keys_cbc() {
    run_rsa_single_cert_loopback([0xE0, 0x19]).await;
}

async fn run_rsa_single_cert_loopback(suite: [u8; 2]) {
    use gm_tlcp::tlcp::*;

    // 1. RSA keypair for the server. 2048-bit modulus keeps the test
    //    snappy (~1s for keygen + a few encrypt/decrypt/sign/verify).
    let rsa_kp = gm_tlcp::tlcp::rsa_helpers::RsaKeyPair::generate(2048).expect("rsa keypair gen");
    let rsa_pub = rsa_kp.to_public_key().expect("rsa public key");

    // 2. Configure both sides. The key difference from the R-5 dual-cert
    //    test: the server uses `with_rsa_certs_single` (R-7), which
    //    enables single-Certificate emission per GB/T 38636-2020 §6.4.5.5.
    //    The connector uses `with_rsa_certs_single` (synonym for
    //    `with_rsa_certs` — see docs in src/tlcp/mod.rs) — layout-agnostic.
    let rsa_cert_der: Vec<u8> = (0..100u8).collect(); // dummy DER blob
    let acceptor = TlcpAcceptor::new().with_rsa_certs_single(rsa_kp, rsa_cert_der);

    let connector = TlcpConnector::new()
        .with_cipher_suites(vec![suite])
        .with_rsa_certs_single(rsa_pub);

    // 3. tokio::io::duplex transport.
    let (client_io, server_io) = tokio::io::duplex(16384);

    // 4. Spawn server.
    let server_handle = tokio::spawn(async move {
        acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server: RSA single-cert handshake must succeed in 0.6.2+")
    });

    // 5. Spawn client.
    let client_handle = tokio::spawn(async move {
        connector
            .connect_with_certs(client_io)
            .await
            .expect("client: RSA single-cert handshake must succeed in 0.6.2+")
    });

    // 6. Wait for handshake to complete. Same timeout as the R-5
    //    dual-cert tests (RSA keygen + 1 encrypt is the dominant cost).
    let mut server_stream = tokio::time::timeout(std::time::Duration::from_secs(15), server_handle)
        .await
        .expect("server task timed out (>15s)")
        .expect("server task panicked");

    let mut client_stream = tokio::time::timeout(std::time::Duration::from_secs(15), client_handle)
        .await
        .expect("client task timed out (>15s)")
        .expect("client task panicked");

    // 7. Exchange a single app-data record to prove the record layer
    //    works post-handshake (proves master_secret derivation was
    //    correct on both sides; the cert-layout change does not affect
    //    master_secret derivation).
    let msg: &[u8] = b"hello-rsa-single";
    client_stream.write_all(msg).await.expect("client write");
    client_stream.flush().await.expect("client flush");

    let mut buf = vec![0u8; 256];
    let n = server_stream.read(&mut buf).await.expect("server read");
    assert_eq!(
        &buf[..n],
        msg,
        "server received wrong bytes -- RSA single-cert PMS derivation diverged"
    );

    // Server -> Client round-trip.
    server_stream.write_all(msg).await.expect("server write");
    server_stream.flush().await.expect("server flush");
    let n = client_stream.read(&mut buf).await.expect("client read");
    assert_eq!(
        &buf[..n],
        msg,
        "client received wrong bytes -- RSA single-cert PMS derivation diverged"
    );
}

// ============================================================================
// RSA SHA-256-PRF suites loopback regression tests (R-11 follow-up, gm-tlcp
// 0.6.4+)
// ============================================================================
//
// These tests close the last 2-case gap on the R-5 RSA suite set:
// E05A (`TLS_RSA_SM4_GCM_SHA256`) and E01C (`TLS_RSA_SM4_CBC_SHA256`).
// Per GB/T 38636-2020 §6.3 the PRF for these two suites is SHA-256 in the
// strict reading, but the gm-tlcp 0.6.0 release (R-5 §2) treats all 12
// suites as SM3-PRF to match GmSSL master + openHiTLS convention — see
// CHANGELOG 0.6.0 "SHA-256 PRF for the two `_SHA256` suites" note. So the
// wire-level PRF discriminator is currently a no-op; we still want these
// two suites to round-trip end-to-end against themselves (gm-tlcp as both
// client AND server over `tokio::io::duplex`) to prove the suite-id dispatch
// (E01C / E05A) and the single-cert + dual-cert RSA emitters both work.
//
// These tests mirror the structure of the R-5 / R-7 RSA-SM3-PRF loopback
// tests above (`run_rsa_loopback` / `run_rsa_single_cert_loopback`); only
// the suite ID changes.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_rsa_loopback_with_real_keys_gcm_sha256() {
    run_rsa_loopback([0xE0, 0x5A]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_rsa_loopback_with_real_keys_cbc_sha256() {
    run_rsa_loopback([0xE0, 0x1C]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_rsa_single_cert_loopback_with_real_keys_gcm_sha256() {
    run_rsa_single_cert_loopback([0xE0, 0x5A]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_rsa_single_cert_loopback_with_real_keys_cbc_sha256() {
    run_rsa_single_cert_loopback([0xE0, 0x1C]).await;
}

// ============================================================================
// ECDHE / static-ECC suites loopback regression tests (R-11, gm-tlcp
// 0.6.4+)
// ============================================================================
//
// These four tests close the long-standing 4-case gap on the
// GB/T 38636-2020 §6.4.5.2.1 表 2 standard SM2 suites:
//   * E051 `TLS_ECDHE_SM4_GCM_SM3`
//   * E011 `TLS_ECDHE_SM4_CBC_SM3`
//   * E053 `TLS_ECC_SM4_GCM_SM3`
//   * E013 `TLS_ECC_SM4_CBC_SM3`
//
// The previous audit-trail note at the top of this file
// (line 8-13, "The full in-process loopback test was attempted but the
// gm-tlcp handshake state machine has pre-existing wire-format bugs")
// dates back to PR-A / gm-tlcp 0.2.1. The intervening releases have since
// closed the relevant Critical findings (C-1/C-2/C-3/C-4 in
// `interop/AUDIT-2026-09-06-v2.md`), so a true client+server loopback
// over `tokio::io::duplex` is now feasible.
//
// These tests use the same `support::cert_setup::generate_test_certs`
// helper that `tests/gmssl_interop.rs` uses for cross-impl interop:
// the helper requires `gmssl` on PATH and self-skips if absent. The
// real X.509 DER certs + SM3-PBKDF2-encrypted SM2 keys are produced by
// `gmssl certgen`/`reqsign`/`sm2keygen` and loaded via
// `support::gmssl_key::load_sm2_key_from_gmssl_pem` (pure-Rust SM3-PBKDF2
// + SM4-CBC walker).
//
// Pre-flight (per suite):
//   - ECDHE: server emits ECDHE-style SKE
//     (`ECParameters ‖ pub ‖ sig_len ‖ sig`) signed by the server's sign
//     key; client verifies, sends its own ephemeral pub in CKE; both sides
//     derive the SM2 KAP PMS per GB/T 32918.3-2016 §6.4 (48 bytes).
//   - Static-ECC: server emits spec-B sig-only SKE
//     (`u16 sig_len ‖ sig_der`) over `cr ‖ sr ‖ enc_cert`; client
//     SM2-encrypts a 48-byte PMS under the server's enc cert (R-3 / 0.4.0);
//     server SM2-decrypts.
//   - Both: GCM (default) or CBC (suite flag) record layer.
//
// Wire-format side-effects we exercise end-to-end:
//   - SKE shape auto-detection (ECParameters prefix vs sig-only)
//   - Server-side PMS derivation (SM2 KAP for ECDHE; SM2 PKE for ECC)
//   - Master secret + key block derivation round-trip
//   - GCM / CBC record-layer round-trip

async fn run_ecdhe_or_ecc_loopback(suite: [u8; 2]) {
    use gm_tlcp::tlcp::*;

    // These tests need real X.509 certs to feed the DER cert slot of
    // `with_dual_certs` AND to feed `with_client_certs` on the connector
    // side (the connector replies to CertificateRequest with a client
    // chain). Phase 12 (R-12): cert generation moved from the `gmssl`
    // CLI to the in-process `gmca_cert_setup` helper, so this test
    // no longer gates on `gmssl_present()` and the keys come out as
    // unencrypted SEC1 PEM (no PBES2 decryption needed).

    let tmp = std::env::temp_dir().join(format!(
        "gm-tlcp-ecdhe-ecc-{}-{:02x}{:02x}-{}",
        std::process::id(),
        suite[0],
        suite[1],
        if suite[0] == 0xE0 && (suite[1] == 0x53 || suite[1] == 0x13) {
            "ecc"
        } else {
            "ecdhe"
        }
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    let certs: GmcaCerts = generate_gmca_test_certs(&tmp).expect("generate_gmca_test_certs");

    // ---- Server-side key material -----------------------------------------
    // `with_dual_certs` takes DER-encoded sign + enc certs plus the two
    // SM2 private keys (as SEC1 PEM). All four are returned by
    // `gmca_cert_setup::generate_gmca_test_certs` in memory.
    let server_sign_kp =
        Sm2KeyPair::from_private_key_pem(&certs.server_sign_key_pem).expect("server sign SEC1 PEM");
    let server_enc_kp =
        Sm2KeyPair::from_private_key_pem(&certs.server_enc_key_pem).expect("server enc SEC1 PEM");

    let acceptor = TlcpAcceptor::new().with_dual_certs(
        certs.server_sign_cert_der.clone(),
        certs.server_enc_cert_der.clone(),
        server_sign_kp,
        server_enc_kp,
    );

    // ---- Client-side key material -----------------------------------------
    // The connector must:
    //   1. Know the server's sign pubkey + distid for SKE verification
    //      (`with_server_sign_key`). The 65-byte SEC1 pubkey is returned
    //      directly by `generate_gmca_test_certs` in
    //      `certs.server_sign_pub_65`.
    //   2. Reply to a server CertificateRequest with a client cert chain
    //      `[client_sign, client_enc, ca]`. We keep the same 3-element
    //      chain shape the GmSSL wire-interop test uses (see
    //      `build_gmssl_compatible_connector` in `gmssl_interop.rs`).
    //   3. Provide the client's signing key (for CertificateVerify) AND
    //      encryption key (for ECDHE Z_client / static-ECC client-side
    //      PMS encrypt). Both come back as unencrypted SEC1 PEM from
    //      `gmca_cert_setup`.
    let connector = TlcpConnector::new()
        .with_cipher_suites(vec![suite])
        .with_server_sign_key(
            certs.server_sign_pub_65.clone(),
            support::gmca_cert_setup::DEFAULT_DISTID.to_string(),
        )
        .with_client_certs(
            vec![
                certs.client_sign_cert_der.clone(),
                certs.client_enc_cert_der.clone(),
                certs.ca_cert_der.clone(),
            ],
            certs.client_sign_key_pem.clone(),
            Some(certs.client_enc_key_pem.clone()),
            None,
        );

    // ---- Wire up the duplex transport --------------------------------------
    let (client_io, server_io) = tokio::io::duplex(32768);

    // Spawn server.
    let server_handle = tokio::spawn(async move {
        acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server: ECDHE/ECC handshake must succeed end-to-end")
    });

    // Spawn client.
    let client_handle = tokio::spawn(async move {
        connector
            .connect_with_certs(client_io)
            .await
            .expect("client: ECDHE/ECC handshake must succeed end-to-end")
    });

    // Wait for handshake. SM2 ECDHE + keypair decrypt + SM2 KAP pairing
    // can take a moment on slow CI; budget 20s.
    let mut server_stream = tokio::time::timeout(std::time::Duration::from_secs(20), server_handle)
        .await
        .expect("server task timed out (>20s)")
        .expect("server task panicked");

    let mut client_stream = tokio::time::timeout(std::time::Duration::from_secs(20), client_handle)
        .await
        .expect("client task timed out (>20s)")
        .expect("client task panicked");

    // ---- App-data round-trip ----------------------------------------------
    // Use a non-empty payload that touches both directions to prove
    // record-layer keys match on both sides. A short ASCII payload is
    // enough — the test goal is master_secret derivation + Finished
    // verify, not throughput.
    let msg: &[u8] = b"hello-sm2-loopback";
    client_stream.write_all(msg).await.expect("client write");
    client_stream.flush().await.expect("client flush");

    let mut buf = vec![0u8; 256];
    let n = server_stream.read(&mut buf).await.expect("server read");
    assert_eq!(
        &buf[..n],
        msg,
        "server received wrong bytes -- ECDHE/ECC PMS or record-layer key derivation diverged"
    );

    // Server -> Client round-trip.
    server_stream.write_all(msg).await.expect("server write");
    server_stream.flush().await.expect("server flush");
    let n = client_stream.read(&mut buf).await.expect("client read");
    assert_eq!(
        &buf[..n],
        msg,
        "client received wrong bytes -- ECDHE/ECC PMS or record-layer key derivation diverged"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_ecdhe_loopback_with_real_keys_gcm() {
    run_ecdhe_or_ecc_loopback([0xE0, 0x51]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_ecdhe_loopback_with_real_keys_cbc() {
    run_ecdhe_or_ecc_loopback([0xE0, 0x11]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_ecc_loopback_with_real_keys_gcm() {
    run_ecdhe_or_ecc_loopback([0xE0, 0x53]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_ecc_loopback_with_real_keys_cbc() {
    run_ecdhe_or_ecc_loopback([0xE0, 0x13]).await;
}
