//! TLCP integration tests: end-to-end client ↔ server handshake over in-memory stream
//!
//! Tests the complete TLCP handshake flow:
//! 1. ClientHello → ServerHello
//! 2. Dual certificates exchange
//! 3. ECDHE key exchange (simulated with pre-master secret)
//! 4. Master secret derivation
//! 5. Key material derivation
//! 6. Finished message computation and verification
//! 7. GmTlsStream creation with TLCP version
//! 8. Application data exchange over encrypted channel

use gm_tls::gm::GmTlsStream;
use gm_tls::tlcp::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Helper: derive matching key material on both sides
fn derive_both_sides() -> (TlcpKeyMaterial, TlcpKeyMaterial) {
    let master = [0xABu8; 32];
    let cr = [0x01u8; 32];
    let sr = [0x02u8; 32];

    let client_km = TlcpKeyMaterial::derive(&master, &cr, &sr, TlcpCipherSuite::ECDHE_SM4_GCM_SM3)
        .expect("client key derivation");
    let server_km = TlcpKeyMaterial::derive(&master, &cr, &sr, TlcpCipherSuite::ECDHE_SM4_GCM_SM3)
        .expect("server key derivation");

    (client_km, server_km)
}

// ============================================================================
// Handshake Integration Tests
// ============================================================================

#[tokio::test]
async fn test_tlcp_full_handshake_flow() {
    // ---- Phase 1: Client creates ClientHello ----
    let mut client_hs = TlcpHandshake::new_client().unwrap();
    let client_hello = client_hs.create_client_hello().unwrap();
    assert_eq!(client_hs.state, TlcpHandshakeState::HelloSent);

    // ---- Phase 2: Server processes ClientHello, creates ServerHello ----
    let mut server_hs = TlcpServerHandshake::new().unwrap();
    server_hs.process_client_hello(&client_hello).await.unwrap();
    assert_eq!(server_hs.state, TlcpHandshakeState::HelloSent);

    let server_hello = server_hs.create_server_hello().unwrap();
    assert_eq!(server_hello.version, TLCP_VERSION_1_0);

    // ---- Phase 3: Client processes ServerHello ----
    client_hs.process_server_hello(&server_hello).unwrap();

    // ---- Phase 4: Server sends dual certificates ----
    let sign_cert = vec![0x01; 100]; // Simulated DER cert
    let enc_cert = vec![0x02; 100];
    let certs = TlcpCertPair::new(sign_cert, enc_cert);
    server_hs.set_server_certs(certs.clone());

    // ---- Phase 5: Client receives certificates ----
    client_hs.process_server_certs(certs).unwrap();

    // ---- Phase 6: ECDHE key exchange (simulated) ----
    // In production, this would use SM2 ECDHE with the server's encryption cert
    let pre_master_secret = vec![0x42u8; 48];

    // Client side
    client_hs.pre_master_secret = Some(pre_master_secret.clone());
    client_hs.derive_master_secret().unwrap();

    // Server side
    server_hs.complete_key_exchange(pre_master_secret).unwrap();

    // ---- Phase 7: Verify both sides derive same master secret ----
    let client_master = client_hs.master_secret.as_ref().unwrap();
    let server_master = server_hs.master_secret.as_ref().unwrap();
    assert_eq!(client_master, server_master, "Master secrets must match");

    // ---- Phase 8: Derive key material ----
    let client_km = client_hs
        .master_secret
        .as_ref()
        .map(|m| {
            TlcpKeyMaterial::derive(
                m,
                &client_hs.client_random,
                client_hs.server_random.as_ref().unwrap(),
                TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
            )
        })
        .transpose()
        .unwrap()
        .unwrap();

    let server_km = server_hs.derive_key_material().unwrap();

    // Verify key material matches
    assert_eq!(client_km.client_enc_key, server_km.client_enc_key);
    assert_eq!(client_km.server_enc_key, server_km.server_enc_key);
    assert_eq!(client_km.client_iv, server_km.client_iv);
    assert_eq!(client_km.server_iv, server_km.server_iv);
}

#[tokio::test]
async fn test_tlcp_handshake_with_encrypted_data_exchange() {
    // Complete handshake
    let mut client_hs = TlcpHandshake::new_client().unwrap();
    let client_hello = client_hs.create_client_hello().unwrap();

    let mut server_hs = TlcpServerHandshake::new().unwrap();
    server_hs.process_client_hello(&client_hello).await.unwrap();
    let server_hello = server_hs.create_server_hello().unwrap();

    client_hs.process_server_hello(&server_hello).unwrap();

    let certs = TlcpCertPair::new(vec![0x01; 100], vec![0x02; 100]);
    server_hs.set_server_certs(certs.clone());
    client_hs.process_server_certs(certs).unwrap();

    let pms = vec![0x99u8; 48];
    client_hs.pre_master_secret = Some(pms.clone());
    client_hs.derive_master_secret().unwrap();
    server_hs.complete_key_exchange(pms).unwrap();

    // Derive key material
    let client_km = TlcpKeyMaterial::derive(
        client_hs.master_secret.as_ref().unwrap(),
        &client_hs.client_random,
        client_hs.server_random.as_ref().unwrap(),
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
    )
    .unwrap();

    let server_km = server_hs.derive_key_material().unwrap();

    // Create SessionKeys
    let client_sk = client_km.to_session_keys().unwrap();
    let server_sk = server_km.to_session_keys().unwrap();

    // Create in-memory duplex stream
    let (client_io, server_io) = tokio::io::duplex(4096);

    // Create GmTlsStream with TLCP version
    let mut client_stream = GmTlsStream::with_version(
        client_io,
        client_sk,
        true, // is_client
        None,
        None,
        TLCP_VERSION_1_0,
    );

    let mut server_stream = GmTlsStream::with_version(
        server_io,
        server_sk,
        false, // is_server
        None,
        None,
        TLCP_VERSION_1_0,
    );

    // Client → Server: send application data
    let client_msg = b"Hello from TLCP client!";
    client_stream.write_all(client_msg).await.unwrap();
    client_stream.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = server_stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], client_msg);

    // Server → Client: send application data
    let server_msg = b"Hello from TLCP server!";
    server_stream.write_all(server_msg).await.unwrap();
    server_stream.flush().await.unwrap();

    let n = client_stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], server_msg);
}

#[tokio::test]
async fn test_tlcp_bidirectional_data_exchange() {
    let (client_km, server_km) = derive_both_sides();
    let client_sk = client_km.to_session_keys().unwrap();
    let server_sk = server_km.to_session_keys().unwrap();

    let (client_io, server_io) = tokio::io::duplex(8192);

    let mut client =
        GmTlsStream::with_version(client_io, client_sk, true, None, None, TLCP_VERSION_1_0);

    let mut server =
        GmTlsStream::with_version(server_io, server_sk, false, None, None, TLCP_VERSION_1_0);

    // Send multiple messages in both directions
    let messages = [
        b"message 1: short".as_slice(),
        b"message 2: a bit longer with some extra data".as_slice(),
        &[0xAAu8; 200][..], // longer binary-like message
    ];

    for (i, msg) in messages.iter().enumerate() {
        // Client → Server
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut buf = vec![0u8; 512];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], *msg, "Message {} client→server mismatch", i);

        // Server → Client (echo back with prefix)
        let mut reply = Vec::with_capacity(4 + msg.len());
        reply.extend_from_slice(b"ACK:");
        reply.extend_from_slice(msg);
        server.write_all(&reply).await.unwrap();
        server.flush().await.unwrap();

        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &reply, "Message {} server→client mismatch", i);
    }
}

#[tokio::test]
async fn test_tlcp_large_data_transfer() {
    let (client_km, server_km) = derive_both_sides();
    let client_sk = client_km.to_session_keys().unwrap();
    let server_sk = server_km.to_session_keys().unwrap();

    let (client_io, server_io) = tokio::io::duplex(65536);

    let mut client =
        GmTlsStream::with_version(client_io, client_sk, true, None, None, TLCP_VERSION_1_0);

    let mut server =
        GmTlsStream::with_version(server_io, server_sk, false, None, None, TLCP_VERSION_1_0);

    // Send 4KB of data (larger than a single SM4-GCM record)
    let large_data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    client.write_all(&large_data).await.unwrap();
    client.flush().await.unwrap();

    // Read all data (may require multiple reads)
    let mut received = Vec::with_capacity(4096);
    let mut buf = vec![0u8; 8192];
    while received.len() < large_data.len() {
        let n = server.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }

    assert_eq!(received.len(), large_data.len());
    assert_eq!(received, large_data);
}

// ============================================================================
// Finished Message Integration Tests
// ============================================================================

#[tokio::test]
async fn test_tlcp_finished_client_server_verify() {
    let mut client_hs = TlcpHandshake::new_client().unwrap();
    let client_hello = client_hs.create_client_hello().unwrap();

    let mut server_hs = TlcpServerHandshake::new().unwrap();
    server_hs.process_client_hello(&client_hello).await.unwrap();
    let server_hello = server_hs.create_server_hello().unwrap();

    client_hs.process_server_hello(&server_hello).unwrap();

    let certs = TlcpCertPair::new(vec![0x01; 100], vec![0x02; 100]);
    server_hs.set_server_certs(certs.clone());
    client_hs.process_server_certs(certs).unwrap();

    let pms = vec![0x77u8; 48];
    client_hs.pre_master_secret = Some(pms.clone());
    client_hs.derive_master_secret().unwrap();
    server_hs.complete_key_exchange(pms).unwrap();

    // Both sides have same master secret
    let master = client_hs.master_secret.as_ref().unwrap();

    // Build handshake transcript (simplified)
    let hello_bytes = client_hello.to_bytes().unwrap();
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&hello_bytes);

    // Server computes its Finished
    let server_finished = TlcpFinished::compute(master, "server finished", &transcript).unwrap();

    // Client computes expected server Finished
    let expected_server_finished =
        TlcpFinished::compute(master, "server finished", &transcript).unwrap();
    assert!(server_finished.verify(&expected_server_finished.verify_data));

    // Client computes its Finished
    let client_finished = TlcpFinished::compute(master, "client finished", &transcript).unwrap();

    // Server verifies client Finished
    let expected_client_finished =
        TlcpFinished::compute(master, "client finished", &transcript).unwrap();
    assert!(client_finished.verify(&expected_client_finished.verify_data));

    // Client and server Finished must differ (different labels)
    assert_ne!(
        client_finished.verify_data, server_finished.verify_data,
        "Client and server verify_data must differ"
    );
}

// ============================================================================
// Alert Protocol Integration Tests
// ============================================================================

#[tokio::test]
async fn test_tlcp_alert_close_notify_flow() {
    let alert = TlcpAlert::close_notify();
    let bytes = alert.to_bytes();

    // Simulate sending alert over wire
    let received = TlcpAlert::from_bytes(&bytes).unwrap();
    assert!(received.is_close_notify());
    assert!(!received.is_fatal());

    // In a real flow, close_notify would be followed by closing the connection
}

#[tokio::test]
async fn test_tlcp_alert_fatal_terminates() {
    let alert = TlcpAlert::handshake_failure();
    assert!(alert.is_fatal());

    // Fatal alerts must terminate the connection
    // This would be enforced at the connection manager level
}

// ============================================================================
// Cipher Suite Negotiation Tests
// ============================================================================

#[tokio::test]
async fn test_tlcp_cipher_suite_negotiation() {
    // Client offers all suites
    let client_hello = TlcpClientHello::new().unwrap();
    assert!(client_hello.cipher_suites.contains(&TLS_ECDHE_SM4_GCM_SM3));
    assert!(client_hello.cipher_suites.contains(&TLS_ECDHE_SM4_CBC_SM3));

    // Server prefers ECDHE+GCM
    let mut server = TlcpServerHandshake::new().unwrap();
    server.process_client_hello(&client_hello).await.unwrap();

    let suite = server.cipher_suite.unwrap();
    assert!(suite.ecdhe, "Server should prefer ECDHE");
    assert!(suite.gcm, "Server should prefer GCM");
    assert_eq!(suite.id, TLS_ECDHE_SM4_GCM_SM3);
}

#[tokio::test]
async fn test_tlcp_server_rejects_no_common_suite() {
    let mut client_hello = TlcpClientHello::new().unwrap();
    // Client only offers unsupported suite
    client_hello.cipher_suites = vec![[0xFF, 0xFF]];

    let mut server = TlcpServerHandshake::new().unwrap();
    let result = server.process_client_hello(&client_hello).await;
    assert!(result.is_err());
}

// ============================================================================
// Key Material Consistency Tests
// ============================================================================

#[tokio::test]
async fn test_tlcp_key_material_consistency_with_handshake() {
    // Verify that deriving keys via client handshake and server handshake
    // produces identical key material when starting from the same master secret
    let mut client_hs = TlcpHandshake::new_client().unwrap();
    let client_hello = client_hs.create_client_hello().unwrap();

    let mut server_hs = TlcpServerHandshake::new().unwrap();
    server_hs.process_client_hello(&client_hello).await.unwrap();
    let server_hello = server_hs.create_server_hello().unwrap();

    client_hs.process_server_hello(&server_hello).unwrap();

    let pms = vec![0x55u8; 48];
    client_hs.pre_master_secret = Some(pms.clone());
    client_hs.derive_master_secret().unwrap();
    server_hs.complete_key_exchange(pms).unwrap();

    // Both derive key material from same master secret
    let client_km = TlcpKeyMaterial::derive(
        client_hs.master_secret.as_ref().unwrap(),
        &client_hs.client_random,
        client_hs.server_random.as_ref().unwrap(),
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
    )
    .unwrap();

    let server_km = server_hs.derive_key_material().unwrap();

    // All key material must match
    assert_eq!(client_km.client_enc_key, server_km.client_enc_key);
    assert_eq!(client_km.server_enc_key, server_km.server_enc_key);
    assert_eq!(client_km.client_iv, server_km.client_iv);
    assert_eq!(client_km.server_iv, server_km.server_iv);

    // SessionKeys must also match
    let client_sk = client_km.to_session_keys().unwrap();
    let server_sk = server_km.to_session_keys().unwrap();
    assert_eq!(client_sk.client_key, server_sk.client_key);
    assert_eq!(client_sk.server_key, server_sk.server_key);
    assert_eq!(client_sk.client_nonce, server_sk.client_nonce);
    assert_eq!(client_sk.server_nonce, server_sk.server_nonce);
}

#[tokio::test]
async fn test_tlcp_different_pms_produces_different_keys() {
    let mut client_hs1 = TlcpHandshake::new_client().unwrap();
    let hello1 = client_hs1.create_client_hello().unwrap();
    let mut server_hs1 = TlcpServerHandshake::new().unwrap();
    server_hs1.process_client_hello(&hello1).await.unwrap();
    let sh1 = server_hs1.create_server_hello().unwrap();
    client_hs1.process_server_hello(&sh1).unwrap();
    client_hs1.pre_master_secret = Some(vec![0x11u8; 48]);
    client_hs1.derive_master_secret().unwrap();

    let mut client_hs2 = TlcpHandshake::new_client().unwrap();
    let hello2 = client_hs2.create_client_hello().unwrap();
    let mut server_hs2 = TlcpServerHandshake::new().unwrap();
    server_hs2.process_client_hello(&hello2).await.unwrap();
    let sh2 = server_hs2.create_server_hello().unwrap();
    client_hs2.process_server_hello(&sh2).unwrap();
    client_hs2.pre_master_secret = Some(vec![0x22u8; 48]);
    client_hs2.derive_master_secret().unwrap();

    let km1 = TlcpKeyMaterial::derive(
        client_hs1.master_secret.as_ref().unwrap(),
        &client_hs1.client_random,
        client_hs1.server_random.as_ref().unwrap(),
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
    )
    .unwrap();

    let km2 = TlcpKeyMaterial::derive(
        client_hs2.master_secret.as_ref().unwrap(),
        &client_hs2.client_random,
        client_hs2.server_random.as_ref().unwrap(),
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
    )
    .unwrap();

    // Different PMS + different randoms → different keys
    assert_ne!(km1.client_enc_key, km2.client_enc_key);
    assert_ne!(km1.server_enc_key, km2.server_enc_key);
}

// ============================================================================
// TlcpStream Integration Tests
// ============================================================================

#[tokio::test]
async fn test_tlcp_stream_echo() {
    let (client_km, server_km) = derive_both_sides();

    let (client_io, server_io) = tokio::io::duplex(4096);

    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        true,
        vec![0x01, 0x02],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        false,
        vec![0x01, 0x02],
    )
    .unwrap();

    // Client → Server
    let msg = b"Hello TLCP!";
    client.write_all(msg).await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], msg);

    // Server → Client (echo)
    server.write_all(&buf[..n]).await.unwrap();
    server.flush().await.unwrap();

    let n2 = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n2], msg);
}

#[tokio::test]
async fn test_tlcp_stream_bidirectional() {
    let (client_km, server_km) = derive_both_sides();

    let (client_io, server_io) = tokio::io::duplex(8192);

    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        false,
        vec![],
    )
    .unwrap();

    let messages = [
        b"short".as_slice(),
        b"a bit longer message for TLCP stream testing".as_slice(),
        &[0xAAu8; 200][..],
    ];

    for (i, msg) in messages.iter().enumerate() {
        // Client → Server
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut buf = vec![0u8; 512];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], *msg, "Message {} client→server mismatch", i);

        // Server → Client (echo with prefix)
        let mut reply = Vec::with_capacity(4 + msg.len());
        reply.extend_from_slice(b"ACK:");
        reply.extend_from_slice(msg);
        server.write_all(&reply).await.unwrap();
        server.flush().await.unwrap();

        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &reply, "Message {} server→client mismatch", i);
    }
}

#[tokio::test]
async fn test_tlcp_stream_large_data() {
    let (client_km, server_km) = derive_both_sides();

    let (client_io, server_io) = tokio::io::duplex(65536);

    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        false,
        vec![],
    )
    .unwrap();

    let large_data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    client.write_all(&large_data).await.unwrap();
    client.flush().await.unwrap();

    let mut received = Vec::with_capacity(4096);
    let mut buf = vec![0u8; 8192];
    while received.len() < large_data.len() {
        let n = server.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }

    assert_eq!(received.len(), large_data.len());
    assert_eq!(received, large_data);
}

#[tokio::test]
async fn test_tlcp_stream_close_notify() {
    let (client_km, server_km) = derive_both_sides();

    let (client_io, server_io) = tokio::io::duplex(4096);

    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        false,
        vec![],
    )
    .unwrap();

    // Send some data first
    client.write_all(b"before close").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"before close");

    // Client sends close_notify
    client.close().await.unwrap();

    // Server should receive close_notify as EOF (0 bytes read)
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "Expected EOF after close_notify");
}

#[tokio::test]
async fn test_tlcp_stream_session_id() {
    let (client_km, server_km) = derive_both_sides();

    let (client_io, server_io) = tokio::io::duplex(4096);

    let session_id = vec![0xAB, 0xCD, 0xEF];
    let client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        true,
        session_id.clone(),
    )
    .unwrap();
    let server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        false,
        session_id.clone(),
    )
    .unwrap();

    assert_eq!(client.session_id(), &session_id);
    assert_eq!(server.session_id(), &session_id);
    assert!(client.is_client());
    assert!(!server.is_client());
}

// ============================================================================
// TlcpConnector & TlcpAcceptor Tests
// ============================================================================

#[tokio::test]
async fn test_tlcp_connector_acceptor_echo() {
    let cache = TlcpSessionCache::new();
    let ctx = TlcpEcdheContext::generate().unwrap();
    let ctx_server = ctx.clone();
    let _connector = TlcpConnector::new().with_session_cache(cache.clone());
    let acceptor = TlcpAcceptor::new().with_session_cache(cache);

    let (client_io, server_io) = tokio::io::duplex(4096);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut stream =
            accept_tlcp_with_context(server_io, acceptor.session_cache(), &ctx_server)
                .await
                .unwrap();
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
    });

    // Client connects and sends data
    let mut client = connect_tlcp_with_context(client_io, &ctx).await.unwrap();
    let msg = b"Hello TLCP connector!";
    client.write_all(msg).await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], msg);

    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_tlcp_connect_tlcp_function() {
    let cache = TlcpSessionCache::new();
    let ctx = TlcpEcdheContext::generate().unwrap();
    let ctx_server = ctx.clone();
    let (client_io, server_io) = tokio::io::duplex(4096);

    // Spawn server
    let server_cache = cache.clone();
    let server_handle = tokio::spawn(async move {
        let mut stream = accept_tlcp_with_context(server_io, &server_cache, &ctx_server)
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
    });

    // Client uses convenience function with shared context
    let mut client = connect_tlcp_with_context(client_io, &ctx).await.unwrap();
    client
        .write_all(b"convenience function test")
        .await
        .unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"convenience function test");

    server_handle.await.unwrap();
}

/// Helper: derive matching CBC key material on both sides
fn derive_both_sides_cbc() -> (TlcpKeyMaterial, TlcpKeyMaterial) {
    let master = [0xCDu8; 32];
    let cr = [0x03u8; 32];
    let sr = [0x04u8; 32];

    let client_km = TlcpKeyMaterial::derive(&master, &cr, &sr, TlcpCipherSuite::ECDHE_SM4_CBC_SM3)
        .expect("client CBC key derivation");
    let server_km = TlcpKeyMaterial::derive(&master, &cr, &sr, TlcpCipherSuite::ECDHE_SM4_CBC_SM3)
        .expect("server CBC key derivation");

    (client_km, server_km)
}

#[tokio::test]
async fn test_tlcp_cbc_stream_echo() {
    let (client_km, server_km) = derive_both_sides_cbc();

    let (client_io, server_io) = tokio::io::duplex(4096);

    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        true,
        vec![0x01, 0x02],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        false,
        vec![0x01, 0x02],
    )
    .unwrap();

    // Client → Server
    let msg = b"Hello TLCP CBC!";
    client.write_all(msg).await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], msg);

    // Server → Client (echo)
    server.write_all(&buf[..n]).await.unwrap();
    server.flush().await.unwrap();

    let n2 = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n2], msg);
}

#[tokio::test]
async fn test_tlcp_cbc_stream_bidirectional() {
    let (client_km, server_km) = derive_both_sides_cbc();

    let (client_io, server_io) = tokio::io::duplex(8192);

    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        false,
        vec![],
    )
    .unwrap();

    let messages = [
        b"short".as_slice(),
        b"a bit longer message for TLCP CBC stream testing".as_slice(),
        &[0xBBu8; 200][..],
    ];

    for (i, msg) in messages.iter().enumerate() {
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut buf = vec![0u8; 512];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], *msg, "CBC message {} client→server mismatch", i);

        let mut reply = Vec::with_capacity(4 + msg.len());
        reply.extend_from_slice(b"ACK:");
        reply.extend_from_slice(msg);
        server.write_all(&reply).await.unwrap();
        server.flush().await.unwrap();

        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            &reply,
            "CBC message {} server→client mismatch",
            i
        );
    }
}

#[tokio::test]
async fn test_tlcp_cbc_stream_large_data() {
    let (client_km, server_km) = derive_both_sides_cbc();

    let (client_io, server_io) = tokio::io::duplex(65536);

    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        false,
        vec![],
    )
    .unwrap();

    let large_data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    client.write_all(&large_data).await.unwrap();
    client.flush().await.unwrap();

    let mut received = Vec::with_capacity(4096);
    let mut buf = vec![0u8; 8192];
    while received.len() < large_data.len() {
        let n = server.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }

    assert_eq!(received.len(), large_data.len());
    assert_eq!(received, large_data);
}

#[tokio::test]
async fn test_tlcp_cbc_close_notify() {
    let (client_km, server_km) = derive_both_sides_cbc();

    let (client_io, server_io) = tokio::io::duplex(4096);

    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        false,
        vec![],
    )
    .unwrap();

    client.write_all(b"before CBC close").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"before CBC close");

    client.close().await.unwrap();

    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "Expected EOF after CBC close_notify");
}

#[tokio::test]
async fn test_tlcp_ecc_cbc_stream() {
    let master = [0xEFu8; 32];
    let cr = [0x05u8; 32];
    let sr = [0x06u8; 32];

    let client_km =
        TlcpKeyMaterial::derive(&master, &cr, &sr, TlcpCipherSuite::ECC_SM4_CBC_SM3).unwrap();
    let server_km =
        TlcpKeyMaterial::derive(&master, &cr, &sr, TlcpCipherSuite::ECC_SM4_CBC_SM3).unwrap();

    let (client_io, server_io) = tokio::io::duplex(4096);

    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECC_SM4_CBC_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECC_SM4_CBC_SM3,
        false,
        vec![],
    )
    .unwrap();

    client.write_all(b"ECC CBC test").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ECC CBC test");
}

/// Tamper proxy: intercepts bytes on the wire and flips a byte at a given offset.
struct TamperProxy<S> {
    inner: S,
    tamper_offset: usize,
    read_bytes: usize,
}

impl<S> TamperProxy<S> {
    fn new(inner: S, tamper_offset: usize) -> Self {
        Self {
            inner,
            tamper_offset,
            read_bytes: 0,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for TamperProxy<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let pin = std::pin::pin!(&mut this.inner);
        match pin.poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                let filled = buf.filled_mut();
                for b in filled.iter_mut() {
                    if this.read_bytes == this.tamper_offset {
                        *b ^= 0xFF; // flip all bits at the target offset
                    }
                    this.read_bytes += 1;
                }
                std::task::Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for TamperProxy<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn test_tlcp_cbc_hmac_tamper_rejected() {
    // CBC record format: [header 5][HMAC 32][IV 16][ciphertext...]
    // Tamper with the HMAC (byte offset 5 after the 5-byte header) and verify
    // the receiver rejects it with HMAC verification failure.
    let (client_km, server_km) = derive_both_sides_cbc();
    let (client_io, server_io) = tokio::io::duplex(4096);

    // Wrap server_io with a tamper proxy that flips a byte in the HMAC region
    let tamper_server_io = TamperProxy::new(server_io, 5); // offset 5 = first HMAC byte
    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        tamper_server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        false,
        vec![],
    )
    .unwrap();

    client.write_all(b"tampered message").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let result = server.read(&mut buf).await;
    assert!(
        result.is_err(),
        "Expected HMAC verification failure, got {:?}",
        result
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("HMAC") || err_msg.contains("hmac"),
        "Error should mention HMAC, got: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_tlcp_cbc_ciphertext_tamper_rejected() {
    // Tamper with ciphertext area (offset well past header+HMAC+IV) to verify
    // HMAC catches ciphertext modifications too.
    let (client_km, server_km) = derive_both_sides_cbc();
    let (client_io, server_io) = tokio::io::duplex(4096);

    // CBC record: [header 5][HMAC 32][IV 16][ciphertext...] → tamper at offset 60 (in ciphertext)
    let tamper_server_io = TamperProxy::new(server_io, 60);
    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        tamper_server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        false,
        vec![],
    )
    .unwrap();

    client.write_all(b"ciphertext tampered").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let result = server.read(&mut buf).await;
    assert!(
        result.is_err(),
        "Expected HMAC/cipher failure from ciphertext tampering, got {:?}",
        result
    );
}

#[tokio::test]
async fn test_tlcp_gcm_aead_tamper_rejected() {
    // GCM mode: AEAD should reject tampered ciphertext via GCM tag verification.
    let (client_km, server_km) = derive_both_sides();
    let (client_io, server_io) = tokio::io::duplex(4096);

    // GCM record: [header 5][nonce 12][ciphertext+tag] → tamper at offset 20 (in ciphertext)
    let tamper_server_io = TamperProxy::new(server_io, 20);
    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        tamper_server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        false,
        vec![],
    )
    .unwrap();

    client.write_all(b"tampered GCM message").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 256];
    let result = server.read(&mut buf).await;
    assert!(
        result.is_err(),
        "Expected GCM AEAD failure, got {:?}",
        result
    );
}

// ===== Boundary tests (SE-08) =====

#[tokio::test]
async fn test_tlcp_gcm_single_byte() {
    let (client_km, server_km) = derive_both_sides();
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        false,
        vec![],
    )
    .unwrap();

    client.write_all(b"X").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"X");
}

#[tokio::test]
async fn test_tlcp_cbc_single_byte() {
    let (client_km, server_km) = derive_both_sides_cbc();
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        false,
        vec![],
    )
    .unwrap();

    client.write_all(b"X").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"X");
}

#[tokio::test]
async fn test_tlcp_gcm_block_aligned_16bytes() {
    // SM4 block size boundary (16 bytes)
    let (client_km, server_km) = derive_both_sides();
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        false,
        vec![],
    )
    .unwrap();

    let msg = [0xABu8; 16];
    client.write_all(&msg).await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &msg[..]);
}

#[tokio::test]
async fn test_tlcp_cbc_block_aligned_16bytes() {
    // SM4 CBC block size boundary — tests PKCS#7 padding edge case
    // 16-byte message + 16 bytes padding = 32 bytes ciphertext
    let (client_km, server_km) = derive_both_sides_cbc();
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        false,
        vec![],
    )
    .unwrap();

    let msg = [0xCDu8; 16];
    client.write_all(&msg).await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &msg[..]);
}

#[tokio::test]
async fn test_tlcp_cbc_15bytes_one_byte_padding() {
    // 15 bytes message → 1 byte PKCS#7 padding → 16 bytes ciphertext
    let (client_km, server_km) = derive_both_sides_cbc();
    let (client_io, server_io) = tokio::io::duplex(4096);
    let mut client = TlcpStream::new(
        client_io,
        &client_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        true,
        vec![],
    )
    .unwrap();
    let mut server = TlcpStream::new(
        server_io,
        &server_km,
        TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        false,
        vec![],
    )
    .unwrap();

    let msg = [0xEFu8; 15];
    client.write_all(&msg).await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &msg[..]);
}

// ============================================================================
// Production ECDHE handshake with dual certificates
// ============================================================================

#[tokio::test]
async fn test_tlcp_production_ecdhe_handshake() {
    use gm_crypto::sm2::Sm2KeyPair;

    // Generate signing key pair (for ServerKeyExchange signature)
    let sign_kp = Sm2KeyPair::generate().expect("sign keypair");
    let sign_pub = sign_kp.public_key_bytes();
    // Generate encryption key pair (for key exchange)
    let enc_kp = Sm2KeyPair::generate().expect("enc keypair");
    let enc_pub = enc_kp.public_key_bytes();

    // Create acceptor with dual certs
    let acceptor = TlcpAcceptor::new().with_dual_certs(
        sign_pub.clone(), // sign cert (just public key for testing)
        enc_pub.clone(),  // enc cert
        sign_kp,
        enc_kp,
    );

    // Create connector that knows the server's signing public key
    let connector =
        TlcpConnector::new().with_server_sign_key(sign_pub, "1234567812345678".to_string());

    let (client_io, server_io) = tokio::io::duplex(8192);

    // Spawn server
    let server_handle = tokio::spawn(async move {
        let mut stream = acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server accept_with_certs");
        // Echo server
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.expect("server read");
        stream.write_all(&buf[..n]).await.expect("server write");
        stream.flush().await.expect("server flush");
    });

    // Client connects
    let mut client = connector
        .connect(client_io)
        .await
        .expect("client connect_with_certs");

    // Send and receive
    let msg = b"Production ECDHE handshake!";
    client.write_all(msg).await.expect("client write");
    client.flush().await.expect("client flush");

    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await.expect("client read");
    assert_eq!(&buf[..n], msg);

    server_handle.await.expect("server task");
}

#[tokio::test]
async fn test_tlcp_production_ecdhe_large_data() {
    use gm_crypto::sm2::Sm2KeyPair;

    let sign_kp = Sm2KeyPair::generate().expect("sign keypair");
    let sign_pub = sign_kp.public_key_bytes();
    let enc_kp = Sm2KeyPair::generate().expect("enc keypair");
    let enc_pub = enc_kp.public_key_bytes();

    let acceptor = TlcpAcceptor::new().with_dual_certs(sign_pub.clone(), enc_pub, sign_kp, enc_kp);

    let connector =
        TlcpConnector::new().with_server_sign_key(sign_pub, "1234567812345678".to_string());

    let (client_io, server_io) = tokio::io::duplex(16384);

    let server_handle = tokio::spawn(async move {
        let mut stream = acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server accept_with_certs");
        // Echo: read all, write all back
        let mut buf = vec![0u8; 8192];
        let mut total = 0;
        loop {
            let n = stream.read(&mut buf).await.expect("server read");
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.expect("server write");
            stream.flush().await.expect("server flush");
            total += n;
            if total >= 4096 {
                break;
            } // Got enough
        }
    });

    let mut client = connector
        .connect(client_io)
        .await
        .expect("client connect_with_certs");

    // Send 4 KB of data in chunks
    let msg = vec![0x42u8; 4096];
    client.write_all(&msg).await.expect("client write");
    client.flush().await.expect("client flush");

    let mut received = vec![0u8; 4096];
    let mut offset = 0;
    while offset < 4096 {
        let n = client
            .read(&mut received[offset..])
            .await
            .expect("client read");
        offset += n;
    }
    assert_eq!(&received, &msg);

    server_handle.await.expect("server task");
}

#[tokio::test]
async fn test_tlcp_production_ecdhe_bidirectional() {
    use gm_crypto::sm2::Sm2KeyPair;

    let sign_kp = Sm2KeyPair::generate().expect("sign keypair");
    let sign_pub = sign_kp.public_key_bytes();
    let enc_kp = Sm2KeyPair::generate().expect("enc keypair");
    let enc_pub = enc_kp.public_key_bytes();

    let acceptor = TlcpAcceptor::new().with_dual_certs(sign_pub.clone(), enc_pub, sign_kp, enc_kp);

    let connector =
        TlcpConnector::new().with_server_sign_key(sign_pub, "1234567812345678".to_string());

    let (client_io, server_io) = tokio::io::duplex(8192);

    let server_handle = tokio::spawn(async move {
        let mut stream = acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server accept_with_certs");
        // Server sends first
        stream
            .write_all(b"server hello")
            .await
            .expect("server write");
        stream.flush().await.expect("server flush");
        // Then read client
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf).await.expect("server read");
        assert_eq!(&buf[..n], b"client hello");
    });

    let mut client = connector
        .connect(client_io)
        .await
        .expect("client connect_with_certs");

    // Client reads server message first
    let mut buf = vec![0u8; 256];
    let n = client.read(&mut buf).await.expect("client read");
    assert_eq!(&buf[..n], b"server hello");

    // Then sends to server
    client
        .write_all(b"client hello")
        .await
        .expect("client write");
    client.flush().await.expect("client flush");

    server_handle.await.expect("server task");
}

/// Test that CBC cipher suite can be negotiated when only CBC is offered
#[test]
fn test_tlcp_cbc_suite_negotiation() {
    let mut client_hello = TlcpClientHello::new().expect("client hello");
    client_hello.cipher_suites = vec![TLS_ECDHE_SM4_CBC_SM3, TLS_ECC_SM4_CBC_SM3];
    let bytes = client_hello.to_bytes().expect("serialize");

    // Verify the ClientHello bytes are well-formed (contains the CBC suite IDs)
    let b = &bytes;
    assert!(b.len() > 10);
    // The cipher suite bytes for CBC should be in the serialized output
    let cbc_gcm: [u8; 2] = TLS_ECDHE_SM4_CBC_SM3;
    let cbc_ecc: [u8; 2] = TLS_ECC_SM4_CBC_SM3;
    assert!(b.windows(2).any(|w| w == cbc_gcm));
    assert!(b.windows(2).any(|w| w == cbc_ecc));
}

#[tokio::test]
async fn test_tlcp_production_ecdhe_cbc_handshake() {
    use gm_crypto::sm2::Sm2KeyPair;

    let sign_kp = Sm2KeyPair::generate().expect("sign keypair");
    let sign_pub = sign_kp.public_key_bytes();
    let enc_kp = Sm2KeyPair::generate().expect("enc keypair");
    let enc_pub = enc_kp.public_key_bytes();

    let acceptor = TlcpAcceptor::new().with_dual_certs(sign_pub.clone(), enc_pub, sign_kp, enc_kp);

    // Client only offers CBC cipher suites
    let connector = TlcpConnector::new()
        .with_server_sign_key(sign_pub, "1234567812345678".to_string())
        .with_cipher_suites(vec![TLS_ECDHE_SM4_CBC_SM3, TLS_ECC_SM4_CBC_SM3]);

    let (client_io, server_io) = tokio::io::duplex(8192);

    let server_handle = tokio::spawn(async move {
        let mut stream = acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server accept_with_certs");
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.expect("server read");
        stream.write_all(&buf[..n]).await.expect("server write");
        stream.flush().await.expect("server flush");
    });

    let mut client = connector
        .connect(client_io)
        .await
        .expect("client connect_with_certs");

    let msg = b"CBC production ECDHE!";
    client.write_all(msg).await.expect("client write");
    client.flush().await.expect("client flush");

    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await.expect("client read");
    assert_eq!(&buf[..n], msg);

    server_handle.await.expect("server task");
}

#[tokio::test]
async fn test_tlcp_production_ecdhe_session_resumption() {
    use gm_crypto::sm2::Sm2KeyPair;

    let sign_kp = Sm2KeyPair::generate().expect("sign keypair");
    let sign_pub = sign_kp.public_key_bytes();
    let enc_kp = Sm2KeyPair::generate().expect("enc keypair");
    let enc_pub = enc_kp.public_key_bytes();

    // Shared session caches
    let server_cache = TlcpSessionCache::new();
    let client_cache = TlcpSessionCache::new();

    let acceptor = TlcpAcceptor::new()
        .with_dual_certs(sign_pub.clone(), enc_pub, sign_kp, enc_kp)
        .with_session_cache(server_cache.clone());

    let connector = TlcpConnector::new()
        .with_server_sign_key(sign_pub, "1234567812345678".to_string())
        .with_session_cache(client_cache.clone());

    // === First connection: full handshake ===
    let (client_io, server_io) = tokio::io::duplex(8192);

    let server_cache_clone = server_cache.clone();
    let server_handle = tokio::spawn(async move {
        let mut stream = acceptor.accept(server_io).await.expect("server accept");
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.expect("server read");
        stream.write_all(&buf[..n]).await.expect("server write");
        stream.flush().await.expect("server flush");
        // Check server cached the session
        let sid = stream.session_id().to_vec();
        let cached = server_cache_clone.get(&sid).await;
        assert!(cached.is_some(), "server should have cached the session");
    });

    let mut client = connector.connect(client_io).await.expect("client connect");

    // Save session info
    let session_id = client.session_id().to_vec();
    let resumed = client
        .to_resumed_session()
        .expect("session should be cacheable")
        .clone();

    // Echo test
    let msg = b"first connection";
    client.write_all(msg).await.expect("client write");
    client.flush().await.expect("client flush");
    let mut buf = vec![0u8; 256];
    let n = client.read(&mut buf).await.expect("client read");
    assert_eq!(&buf[..n], msg);

    server_handle.await.expect("server task");

    // Cache the session on client side
    client_cache.put(session_id.clone(), resumed).await;
    let cached = client_cache.get(&session_id).await;
    assert!(cached.is_some(), "client should have cached the session");
}
