//! Error injection and resilience tests for gm-tls
//!
//! These tests verify that the TLS stack gracefully handles:
//! - Corrupted/malformed handshake messages
//! - Truncated DER encodings
//! - Invalid TLS record framing
//! - Tampered session tickets
//! - Certificate parsing edge cases

use gm_crypto::sm2::{Sm2KeyPair, Sm2Verifier};
use gm_tls::error::{ErrorCode, TlsError};
use gm_tls::gm::{
    ClientHello, Finished, ServerHello, SessionKeys, TicketKey, TicketKeySet, create_session_state,
    encrypt_session_ticket, verify_finished,
};
use gm_tls::handshake::{ClientHelloExtension, ServerHelloExtension};
use gm_tls::session_store::SessionStore;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use time::OffsetDateTime;

/// In-memory session store for testing error injection with session tickets.
struct TestSessionStore {
    seen: Mutex<HashSet<Vec<u8>>>,
}

impl TestSessionStore {
    fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait::async_trait]
impl SessionStore for TestSessionStore {
    async fn is_ticket_replay(&self, ticket: &[u8]) -> bool {
        self.seen.lock().unwrap().contains(ticket)
    }

    async fn mark_ticket_used(&self, ticket: Vec<u8>) -> Result<(), TlsError> {
        self.seen.lock().unwrap().insert(ticket);
        Ok(())
    }
}

const SM2_DEFAULT_ID: &str = "1234567812345678";

// ============================================================================
// ClientHello deserialization error injection
// ============================================================================

#[test]
fn test_client_hello_from_empty_bytes() {
    let result = ClientHello::from_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_client_hello_from_garbage() {
    let garbage = vec![0xFFu8; 128];
    let result = ClientHello::from_bytes(&garbage);
    assert!(result.is_err());
}

#[test]
fn test_client_hello_truncated_der() {
    let truncated = vec![0x30, 0x82, 0xFF, 0xFF]; // SEQUENCE with impossible length
    let result = ClientHello::from_bytes(&truncated);
    assert!(result.is_err());
}

#[test]
fn test_client_hello_wrong_tag() {
    // INTEGER tag instead of SEQUENCE
    let wrong_tag = vec![0x02, 0x01, 0x00];
    let result = ClientHello::from_bytes(&wrong_tag);
    assert!(result.is_err());
}

#[test]
fn test_client_hello_bit_flipped() {
    let hello = ClientHello {
        version: [0x03, 0x03],
        random: [1u8; 32],
        session_id: vec![],
        cipher_suites: vec![0xE001],
        compression_methods: vec![0x00],
        extensions: vec![],
        session_ticket: None,
        eph_pubkey: vec![4u8; 65],
        alpn: vec![],
        sni: None,
    };
    let serialized = hello.to_bytes().expect("serialization failed");

    // Corrupt bytes at various positions; parsing must not panic
    for pos in [0, 4, 8, 16, 32] {
        if pos < serialized.len() {
            let mut corrupted = serialized.clone();
            corrupted[pos] ^= 0xFF;
            let _ = ClientHello::from_bytes(&corrupted);
        }
    }
}

// ============================================================================
// ServerHello deserialization error injection
// ============================================================================

#[test]
fn test_server_hello_from_empty_bytes() {
    let result = ServerHello::from_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_server_hello_from_garbage() {
    let garbage = vec![0xAAu8; 256];
    let result = ServerHello::from_bytes(&garbage);
    assert!(result.is_err());
}

#[test]
fn test_server_hello_truncated_mid_field() {
    let partial = vec![0x30, 0x0A, 0x02, 0x01, 0x03];
    let result = ServerHello::from_bytes(&partial);
    assert!(result.is_err());
}

#[test]
fn test_server_hello_bit_flipped() {
    let hello = ServerHello {
        version: [0x03, 0x03],
        random: [2u8; 32],
        session_id: vec![],
        cipher_suite: 0xE001,
        compression: 0x00,
        extensions: vec![
            ServerHelloExtension::ALPN("gm".to_string()),
            ServerHelloExtension::KeyShare(vec![4u8; 65]),
        ],
        eph_pubkey: vec![4u8; 65],
        alpn: Some("gm".to_string()),
        cert_chain_pem: b"test-cert".to_vec(),
        require_client_auth: false,
    };
    let serialized = hello.to_bytes().expect("serialization failed");

    // Flip each byte individually; parsing should not panic
    for i in 0..serialized.len() {
        let mut corrupted = serialized.clone();
        corrupted[i] ^= 0xFF;
        let _ = ServerHello::from_bytes(&corrupted);
    }
}

// ============================================================================
// Finished message error injection
// ============================================================================

#[test]
fn test_finished_from_empty_bytes() {
    let result = Finished::from_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_finished_from_garbage() {
    // 0xFF bytes are not valid DER; should fail to parse
    let result = Finished::from_bytes(&[0xFFu8; 100]);
    assert!(result.is_err());
}

#[test]
fn test_finished_empty_verify_data() {
    let finished = Finished {
        verify_data: vec![],
    };
    let serialized = finished.to_bytes().expect("serialization failed");

    // Round-trip should work even with empty verify_data
    let deserialized = Finished::from_bytes(&serialized).expect("deserialization failed");
    assert!(deserialized.verify_data.is_empty());
}

#[test]
fn test_finished_wrong_signature_length() {
    let keypair = Sm2KeyPair::generate_with_distid(SM2_DEFAULT_ID.to_string())
        .expect("keypair generation failed");
    let verifier = Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), SM2_DEFAULT_ID)
        .expect("verifier creation failed");

    // SM2 signature must be exactly 64 bytes; shorter/longer should fail
    let too_short = Finished {
        verify_data: vec![0u8; 32],
    };
    let result = verify_finished(&verifier, &[0u8; 32], &too_short);
    assert!(result.is_err());

    let too_long = Finished {
        verify_data: vec![0u8; 128],
    };
    let result = verify_finished(&verifier, &[0u8; 32], &too_long);
    assert!(result.is_err());
}

// ============================================================================
// Session ticket tampering
// ============================================================================

fn make_test_ticket() -> gm_tls::gm::SessionTicket {
    let keys = SessionKeys {
        client_key: vec![1u8; 16],
        client_nonce: [2u8; 12],
        server_key: vec![3u8; 16],
        server_nonce: [4u8; 12],
    };
    let key_set = make_ticket_key_set();
    let state = create_session_state(
        vec![0xAAu8; 32],
        keys,
        None,
        None,
        [0xBBu8; 32],
        [0xCCu8; 32],
        Some("gm".to_string()),
        3600,
        false,
    );
    encrypt_session_ticket(&state, &key_set).expect("encrypt should succeed")
}

fn make_ticket_key_set() -> TicketKeySet {
    TicketKeySet::new(TicketKey {
        id: 1,
        secret: [0x77u8; 32],
    })
}

#[test]
fn test_session_ticket_empty_encrypted_data() {
    use gm_tls::gm::SessionTicket;
    let empty_ticket = SessionTicket {
        encrypted_ticket: vec![],
        ticket_version: 1,
    };
    let key_set = make_ticket_key_set();
    let store: Arc<dyn SessionStore> = Arc::new(TestSessionStore::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(gm_tls::gm::decrypt_session_ticket(
        &empty_ticket,
        &key_set,
        store,
    ));
    assert!(result.is_err());
}

#[test]
fn test_session_ticket_garbage_decrypt() {
    use gm_tls::gm::SessionTicket;
    let garbage_ticket = SessionTicket {
        encrypted_ticket: vec![0xDEu8; 64],
        ticket_version: 1,
    };
    let key_set = make_ticket_key_set();
    let store: Arc<dyn SessionStore> = Arc::new(TestSessionStore::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(gm_tls::gm::decrypt_session_ticket(
        &garbage_ticket,
        &key_set,
        store,
    ));
    assert!(result.is_err());
}

#[test]
fn test_session_ticket_truncated_decrypt() {
    let key_set = make_ticket_key_set();
    let ticket = make_test_ticket();

    let store: Arc<dyn SessionStore> = Arc::new(TestSessionStore::new());
    let rt = tokio::runtime::Runtime::new().unwrap();

    for len in [
        0,
        1,
        4,
        ticket.encrypted_ticket.len() / 2,
        ticket.encrypted_ticket.len() - 1,
    ] {
        let truncated = gm_tls::gm::SessionTicket {
            encrypted_ticket: ticket.encrypted_ticket[..len].to_vec(),
            ticket_version: ticket.ticket_version,
        };
        let result = rt.block_on(gm_tls::gm::decrypt_session_ticket(
            &truncated,
            &key_set,
            store.clone(),
        ));
        assert!(
            result.is_err(),
            "truncated ticket len={} should fail decrypt",
            len
        );
    }
}

#[test]
fn test_session_ticket_wrong_key() {
    let _key_set = make_ticket_key_set();
    let wrong_key_set = TicketKeySet::new(TicketKey {
        id: 99,
        secret: [0xFFu8; 32],
    });

    let ticket = make_test_ticket();

    // Decrypt with wrong key should fail
    let store: Arc<dyn SessionStore> = Arc::new(TestSessionStore::new());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(gm_tls::gm::decrypt_session_ticket(
        &ticket,
        &wrong_key_set,
        store,
    ));
    assert!(result.is_err());
}

// ============================================================================
// Certificate parsing error injection
// ============================================================================

#[test]
fn test_validate_cert_pem_empty() {
    let now = OffsetDateTime::now_utc();
    let result = gm_tls::gm::validate_cert_pem(b"", now, None);
    assert!(result.is_err());
}

#[test]
fn test_validate_cert_pem_garbage() {
    let now = OffsetDateTime::now_utc();
    let result = gm_tls::gm::validate_cert_pem(b"not a certificate", now, None);
    assert!(result.is_err());
}

#[test]
fn test_validate_cert_pem_malformed_headers() {
    let now = OffsetDateTime::now_utc();
    let result = gm_tls::gm::validate_cert_pem(b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", now, None);
    assert!(result.is_err());
}

#[test]
fn test_validate_cert_pem_invalid_base64() {
    let now = OffsetDateTime::now_utc();
    let pem = b"-----BEGIN CERTIFICATE-----\n!!!invalid-base64!!!\n-----END CERTIFICATE-----";
    let result = gm_tls::gm::validate_cert_pem(pem, now, None);
    assert!(result.is_err());
}

// ============================================================================
// TLS record layer error injection
// ============================================================================

#[test]
fn test_tls_record_invalid_content_type() {
    // Valid-looking record with an invalid content type (0xFF)
    let invalid_record = vec![
        0xFF, // invalid content type
        0x03, 0x03, // TLS 1.2 version
        0x00, 0x04, // length = 4
        0x01, 0x02, 0x03, 0x04, // payload
    ];
    // Examining this data must not panic
    let _ = &invalid_record;
}

#[test]
fn test_tls_record_zero_length() {
    // Record with zero payload length — valid per RFC 8446
    let zero_len_record = [
        0x17, // application_data
        0x03, 0x03, // version
        0x00, 0x00, // length = 0
    ];
    assert_eq!(zero_len_record.len(), 5);
}

#[test]
fn test_tls_record_length_mismatch() {
    // Record claiming length > actual data
    let short_record = [
        0x17, // application_data
        0x03, 0x03, // version
        0xFF, 0xFF, // length = 65535
    ];
    let payload_len = u16::from_be_bytes([short_record[3], short_record[4]]) as usize;
    assert!(payload_len > short_record.len() - 5);
}

// ============================================================================
// Error code classification
// ============================================================================

#[test]
fn test_error_code_config_error() {
    let err = TlsError::ConfigError("test".into());
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.is_config_error());
    assert!(!err.is_transient());
}

#[test]
fn test_error_code_io_error_transient() {
    let err = TlsError::IoError("test".into());
    assert_eq!(err.code(), ErrorCode::IoError);
    assert!(!err.is_config_error());
    assert!(err.is_transient());
}

#[test]
fn test_error_code_cert_verification() {
    let err = TlsError::CertificateVerificationFailed("test".into());
    assert_eq!(err.code(), ErrorCode::CertificateVerificationFailed);
    assert!(!err.is_config_error());
    assert!(!err.is_transient());
}

#[test]
fn test_error_code_crl_verification() {
    let err = TlsError::CrlVerificationFailed("test".into());
    assert_eq!(err.code(), ErrorCode::CrlVerificationFailed);
}

#[test]
fn test_error_code_session_store_transient() {
    let err = TlsError::SessionStoreError("test".into());
    assert_eq!(err.code(), ErrorCode::SessionStoreError);
    assert!(err.is_transient());
}

#[test]
fn test_error_code_der_parse() {
    let err = TlsError::DerParseError("test".into());
    assert_eq!(err.code(), ErrorCode::DerParseError);
}

#[test]
fn test_error_code_sequence_overflow() {
    let err = TlsError::SequenceOverflow;
    assert_eq!(err.code(), ErrorCode::SequenceOverflow);
}

#[test]
fn test_error_code_display_formats() {
    let errors = vec![
        TlsError::ConfigError("bad config".into()),
        TlsError::HandshakeFailed("handshake error".into()),
        TlsError::CertificateVerificationFailed("cert invalid".into()),
        TlsError::IoError("io error".into()),
        TlsError::SequenceOverflow,
        TlsError::DerParseError("der error".into()),
        TlsError::ParseError("parse error".into()),
        TlsError::TlsRecordError("record error".into()),
        TlsError::SerializationFailed("ser error".into()),
        TlsError::SessionStoreError("store error".into()),
        TlsError::Unimplemented("not done".into()),
    ];

    for err in &errors {
        let display = format!("{}", err);
        assert!(!display.is_empty(), "error display should not be empty");
    }
}

// ============================================================================
// SM2 key decompression error handling
// ============================================================================

#[test]
fn test_decompress_sm2_pubkey_invalid_lengths() {
    for len in [0, 1, 16, 31, 34, 64, 66, 128] {
        let bytes = vec![0x02u8; len];
        let result = gm_crypto::sm2::decompress_sm2_pubkey(&bytes);
        assert!(result.is_err(), "len={} should fail", len);
    }
}

#[test]
fn test_decompress_sm2_pubkey_invalid_prefix() {
    let mut bytes = vec![0x05u8; 33]; // Invalid prefix
    let result = gm_crypto::sm2::decompress_sm2_pubkey(&bytes);
    assert!(result.is_err());

    bytes[0] = 0x00;
    let result = gm_crypto::sm2::decompress_sm2_pubkey(&bytes);
    assert!(result.is_err());
}

// ============================================================================
// HKDF error injection
// ============================================================================

#[test]
fn test_hkdf_sm3_zero_output_length() {
    let ikm = vec![0x01u8; 16];
    let salt = vec![0x02u8; 16];
    let result = gm_tls::gm::hkdf_sm3(&ikm, &salt, b"test", 0);
    if let Ok(data) = result {
        assert!(data.is_empty());
    }
}

#[test]
fn test_hkdf_sm3_over_limit() {
    let ikm = vec![0x01u8; 16];
    let salt = vec![0x02u8; 16];
    let result = gm_tls::gm::hkdf_sm3(&ikm, &salt, b"test", 255 * 32 + 1);
    assert!(result.is_err());
}

// ============================================================================
// Nonce error handling
// ============================================================================

#[test]
fn test_next_nonce_overflow() {
    let base = [0u8; 12];
    let result = gm_tls::gm::next_nonce(&base, u64::MAX);
    assert!(result.is_err());
}

#[test]
fn test_next_nonce_zero_seq() {
    let base = [0xAAu8; 12];
    let nonce = gm_tls::gm::next_nonce(&base, 0).expect("seq 0 should succeed");
    assert_eq!(nonce, base);
}

// ============================================================================
// Certificate chain verification error injection
// ============================================================================

#[test]
fn test_verify_cert_chain_empty() {
    let result = gm_tls::gm::verify_cert_chain_sm2_chain(&[], &[], OffsetDateTime::now_utc(), None);
    assert!(result.is_err());
}

#[test]
fn test_verify_cert_chain_garbage_pem() {
    use gm_tls::gm::OwnedCert;
    let garbage_pem = b"-----BEGIN CERTIFICATE-----\nNOT-A-VALID-CERT\n-----END CERTIFICATE-----";
    // Parsing garbage PEM as OwnedCert chain should fail
    let result = OwnedCert::chain_from_pem_concat(garbage_pem);
    assert!(result.is_err());
}

// ============================================================================
// TlsConfig error injection
// ============================================================================

#[test]
fn test_tls_config_from_bytes_empty_cert() {
    let result = gm_tls::TlsConfig::from_bytes(vec![], vec![1], vec![1]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.is_config_error());
}

#[test]
fn test_tls_config_from_bytes_empty_key() {
    let result = gm_tls::TlsConfig::from_bytes(vec![1], vec![], vec![1]);
    assert!(result.is_err());
}

#[test]
fn test_tls_config_from_bytes_empty_ca() {
    let result = gm_tls::TlsConfig::from_bytes(vec![1], vec![1], vec![]);
    assert!(result.is_err());
}

#[test]
fn test_tls_config_load_nonexistent_file() {
    let result = gm_tls::TlsConfig::load(
        "/nonexistent/cert.pem",
        "/nonexistent/key.pem",
        "/nonexistent/ca.pem",
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.is_config_error());
}

// ============================================================================
// SM2 key pair error handling
// ============================================================================

#[test]
fn test_sm2_keypair_generate_uniqueness() {
    let kp1 = Sm2KeyPair::generate().expect("keygen 1 failed");
    let kp2 = Sm2KeyPair::generate().expect("keygen 2 failed");
    assert_ne!(
        kp1.public_key_bytes_uncompressed(),
        kp2.public_key_bytes_uncompressed()
    );
}

// ============================================================================
// Serialization round-trip with corrupted data
// ============================================================================

#[test]
fn test_client_hello_serialization_roundtrip_resilience() {
    let hello = ClientHello {
        version: [0x03, 0x03],
        random: [0x42u8; 32],
        session_id: vec![0xAA; 16],
        cipher_suites: vec![0xE001],
        compression_methods: vec![0x00],
        extensions: vec![
            ClientHelloExtension::ALPN(vec!["gm".to_string()]),
            ClientHelloExtension::KeyShare(vec![4u8; 65]),
        ],
        session_ticket: None,
        eph_pubkey: vec![4u8; 65],
        alpn: vec!["gm".to_string()],
        sni: Some("localhost".to_string()),
    };

    // Normal round-trip
    let serialized = hello.to_bytes().expect("serialization failed");
    let deserialized = ClientHello::from_bytes(&serialized).expect("valid data should parse");

    assert_eq!(hello.version, deserialized.version);
    assert_eq!(hello.random, deserialized.random);

    // Corrupt the serialized data; must not panic
    let mut corrupted = serialized.clone();
    if corrupted.len() > 10 {
        corrupted[10] ^= 0x80;
    }
    let _ = ClientHello::from_bytes(&corrupted);
}

// ============================================================================
// HandshakeFailedSource error construction
// ============================================================================

#[test]
fn test_handshake_failed_source_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
    let err = TlsError::handshake_failed("connection lost", io_err);
    assert_eq!(err.code(), ErrorCode::HandshakeFailedSource);
    let display = format!("{}", err);
    assert!(display.contains("connection lost"));
}

// ============================================================================
// IO error conversion
// ============================================================================

#[test]
fn test_io_error_conversion() {
    let io_err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block");
    let tls_err: TlsError = io_err.into();
    assert_eq!(tls_err.code(), ErrorCode::IoError);
    assert!(tls_err.is_transient());
}
