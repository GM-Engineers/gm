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
//! Requires the `gmssl` CLI on PATH so the `support::cert_setup`
//! helper can generate a real CA hierarchy. Skips silently if
//! `gmssl` is absent (same convention as `tests/gmssl_interop.rs`).

#![cfg(test)]

mod support;
use support::cert_setup::{generate_test_certs, gmssl_present};
use support::gmssl_key::load_sm2_key_from_gmssl_pem;

use base64::Engine as _;

const PASSWORD: &str = "P@ssw0rd";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gm_tlcp_kap_pms_roundtrip_with_real_keys() {
    // Verify that the SM2 Key Agreement Protocol produces the same
    // pre-master secret on both sides when the test's real keypairs
    // are used as input. This exercises the server-side PMS code
    // path added by PR-A (audit C-3) without depending on the full
    // handshake state machine.
    if !gmssl_present() {
        eprintln!("skipping: gmssl not on PATH");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("gm-tlcp-kap-test-{}", std::process::id()));
    let certs = match generate_test_certs(&tmp) {
        Ok(c) => c,
        Err(e) => panic!("generate_test_certs failed: {}", e),
    };
    let server_enc_kp =
        load_sm2_key_from_gmssl_pem(&certs.enc_key, PASSWORD).expect("server enc key");
    let client_enc_kp =
        load_sm2_key_from_gmssl_pem(&certs.client_enc_key, PASSWORD).expect("client enc key");

    // Re-read client.enc.crt PEM to get its DER bytes.
    let client_enc_pem_text =
        std::fs::read_to_string(&certs.client_enc_crt).expect("read client enc cert PEM");
    let mut b64 = String::new();
    for line in client_enc_pem_text.lines() {
        if line.starts_with("-----") || line.trim().is_empty() {
            continue;
        }
        b64.push_str(line);
    }
    let client_enc_cert_der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .expect("decode client enc cert b64");

    // Extract the 64-byte x||y SM2 pubkey from each enc cert so we
    // can feed it to `compute_tlcp_ecdhe_pms`. We use the
    // `gm_crypto::x509::extract_sm2_pubkey_from_der` free function
    // directly because the gm-tlcp-internal re-export is private.
    let client_enc_pub_sec1 =
        gm_crypto::x509::extract_sm2_pubkey_from_der(&client_enc_cert_der).expect("client enc pub");
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
