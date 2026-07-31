//! Integration tests for TLS 1.3 KeyUpdate mechanism (RFC 8446 §4.6.3).
//!
//! Tests key rotation, auto-trigger, and bidirectional KeyUpdate
//! using in-memory duplex streams.

use gm_crypto::sm4::SM4_GCM_NONCE_LENGTH;
use gm_tls::gm::SessionKeys;
use gm_tls::key_update::{
    GCM_CONFIDENTIALITY_LIMIT, KEY_UPDATE_THRESHOLD, KeyUpdate, KeyUpdateRequest,
    derive_key_and_nonce, update_traffic_secret,
};
use gm_tls::record_layer::GmTlsStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Create a pair of connected GmTlsStream instances (client + server)
/// with traffic secrets set up for KeyUpdate testing.
fn create_connected_pair() -> (
    GmTlsStream<DuplexStream>,
    GmTlsStream<DuplexStream>,
    Vec<u8>, // client traffic secret
    Vec<u8>, // server traffic secret
) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let client_key = vec![0x01u8; 16];
    let server_key = vec![0x02u8; 16];
    let client_nonce = [0xAAu8; SM4_GCM_NONCE_LENGTH];
    let server_nonce = [0xBBu8; SM4_GCM_NONCE_LENGTH];

    let session_keys = SessionKeys {
        client_key: client_key.clone(),
        client_nonce,
        server_key: server_key.clone(),
        server_nonce,
    };

    // Use deterministic traffic secrets for testing
    let client_traffic_secret = vec![0xC1u8; 32];
    let server_traffic_secret = vec![0xD2u8; 32];

    let mut client = GmTlsStream::new(client_io, session_keys.clone(), true, None, None);
    let mut server = GmTlsStream::new(server_io, session_keys.clone(), false, None, None);

    // Client: write=client, read=server
    client.set_traffic_secrets(client_traffic_secret.clone(), server_traffic_secret.clone());
    // Server: write=server, read=client
    server.set_traffic_secrets(server_traffic_secret.clone(), client_traffic_secret.clone());

    (client, server, client_traffic_secret, server_traffic_secret)
}

#[tokio::test]
async fn test_key_update_basic_rotation() {
    let (mut client, mut server, _client_secret, _server_secret) = create_connected_pair();

    // 1. Client sends some data before KeyUpdate
    client.write_all(b"hello before key update").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello before key update");

    // 2. Client initiates KeyUpdate (without requesting peer update)
    client.send_key_update(false).await.unwrap();

    // 3. Client sends data with the NEW key
    client.write_all(b"hello after key update").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello after key update");

    // 4. Verify the client's write secret was updated
    // After KeyUpdate, client write count should be 1
    assert_eq!(client.key_update_count(), 1);
}

#[tokio::test]
async fn test_key_update_bidirectional() {
    let (mut client, mut server, _cs, _ss) = create_connected_pair();

    // Client sends KeyUpdate requesting peer to also update
    client.send_key_update(true).await.unwrap();

    // Server reads the KeyUpdate and processes it
    // We need to read the KeyUpdate message from the stream.
    // Since KeyUpdate is sent as an encrypted record, the server
    // will decrypt it as application data when reading.
    // For now, the server's read key is automatically rotated
    // when it processes the KeyUpdate.

    // The server should now have a pending key update request
    // Server reads some data (which will trigger the pending key update flush)
    client.write_all(b"test data").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"test data");

    // Both sides should have updated
    assert!(client.key_update_count() >= 1);
    assert!(server.key_update_count() >= 1);
}

#[tokio::test]
async fn test_key_update_multiple_rotations() {
    let (mut client, mut server, _cs, _ss) = create_connected_pair();

    // Perform 3 key rotations
    for i in 0..3 {
        client.send_key_update(false).await.unwrap();
        let msg = format!("after rotation {}", i);
        client.write_all(msg.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 128];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
    }

    assert_eq!(client.key_update_count(), 3);
}

#[tokio::test]
async fn test_key_update_server_initiated() {
    let (mut client, mut server, _cs, _ss) = create_connected_pair();

    // Server initiates KeyUpdate
    server.send_key_update(false).await.unwrap();

    server.write_all(b"server data with new key").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"server data with new key");

    assert_eq!(server.key_update_count(), 1);
}

#[tokio::test]
async fn test_key_update_without_traffic_secrets() {
    // Create streams WITHOUT traffic secrets — KeyUpdate should fail gracefully
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let session_keys = SessionKeys {
        client_key: vec![0x01u8; 16],
        client_nonce: [0xAAu8; SM4_GCM_NONCE_LENGTH],
        server_key: vec![0x02u8; 16],
        server_nonce: [0xBBu8; SM4_GCM_NONCE_LENGTH],
    };

    let mut client = GmTlsStream::new(client_io, session_keys.clone(), true, None, None);
    let mut server = GmTlsStream::new(server_io, session_keys.clone(), false, None, None);

    // Should still be able to send data without KeyUpdate
    client.write_all(b"no key update").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"no key update");

    // But KeyUpdate should fail
    let result = client.send_key_update(false).await;
    assert!(result.is_err());
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_key_update_threshold_sanity() {
    // KEY_UPDATE_THRESHOLD should be less than GCM_CONFIDENTIALITY_LIMIT
    assert!(KEY_UPDATE_THRESHOLD < GCM_CONFIDENTIALITY_LIMIT);
    // And should be a large number (billions)
    assert!(KEY_UPDATE_THRESHOLD > 1_000_000_000u64);
}

#[test]
fn test_key_derivation_chain() {
    // Verify that repeated key updates produce different keys
    let secret0 = vec![0x42u8; 32];
    let secret1 = update_traffic_secret(&secret0).unwrap();
    let secret2 = update_traffic_secret(&secret1).unwrap();
    let secret3 = update_traffic_secret(&secret2).unwrap();

    // All secrets should be different
    assert_ne!(secret0, secret1);
    assert_ne!(secret1, secret2);
    assert_ne!(secret2, secret3);
    assert_ne!(secret0, secret2);
    assert_ne!(secret1, secret3);

    // Derive keys from each secret — should all differ
    let (key0, nonce0) = derive_key_and_nonce(&secret0).unwrap();
    let (key1, nonce1) = derive_key_and_nonce(&secret1).unwrap();
    let (key2, nonce2) = derive_key_and_nonce(&secret2).unwrap();
    let (key3, nonce3) = derive_key_and_nonce(&secret3).unwrap();

    assert_ne!(key0, key1);
    assert_ne!(key1, key2);
    assert_ne!(key2, key3);
    assert_ne!(nonce0, nonce1);
    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce2, nonce3);
}

#[test]
fn test_key_update_message_roundtrip() {
    let ku_not_requested = KeyUpdate::new(KeyUpdateRequest::UpdateNotRequested);
    let bytes = ku_not_requested.to_bytes();
    let parsed = KeyUpdate::from_bytes(&bytes).unwrap();
    assert_eq!(ku_not_requested, parsed);
    assert_eq!(bytes, vec![0]);

    let ku_requested = KeyUpdate::new(KeyUpdateRequest::UpdateRequested);
    let bytes = ku_requested.to_bytes();
    let parsed = KeyUpdate::from_bytes(&bytes).unwrap();
    assert_eq!(ku_requested, parsed);
    assert_eq!(bytes, vec![1]);
}

#[tokio::test]
async fn test_key_update_large_data_transfer() {
    let (mut client, mut server, _cs, _ss) = create_connected_pair();

    // Send large data before KeyUpdate
    let data_before = vec![0xABu8; 4096];
    client.write_all(&data_before).await.unwrap();
    let mut buf = vec![0u8; 4096];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, data_before);

    // KeyUpdate
    client.send_key_update(false).await.unwrap();

    // Send large data after KeyUpdate
    let data_after = vec![0xCDu8; 4096];
    client.write_all(&data_after).await.unwrap();
    let mut buf = vec![0u8; 4096];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, data_after);
}
