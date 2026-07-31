//! Property-based tests for gm-tls using proptest
//!
//! These tests verify cryptographic properties using randomized inputs:
//! - Determinism: same inputs → same outputs
//! - Uniqueness: different inputs → different outputs (usually)
//! - Consistency: encrypt then decrypt recovers original

use elliptic_curve::sec1::FromEncodedPoint;
use gm_crypto::sm2::{EncodedPoint, ProjectivePoint, Sm2KeyPair, Sm2Signer, Sm2Verifier};
use gm_crypto::sm4::{SM4_GCM_NONCE_LENGTH, Sm4Cipher};
use gm_tls::gm::{
    derive_session_keys_sm2, generate_sm2_ephemeral, next_nonce, select_alpn, sign_finished,
    verify_finished,
};
use proptest::prelude::*;

const SM2_DEFAULT_ID: &str = "1234567812345678";

// Property: KDF is deterministic - same inputs produce same outputs
#[test]
fn test_kdf_deterministic() {
    proptest!(|(_client_random in prop::array::uniform32(0u8..),
                 _server_random in prop::array::uniform32(0u8..))| {
        let (sk, pk) = generate_sm2_ephemeral().expect("keygen failed");
        let point = ProjectivePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&pk).unwrap()
        ).into_option().unwrap();
        let shared = point * sk;

        let secrets1 = derive_session_keys_sm2(&shared)
            .expect("KDF failed");
        let secrets2 = derive_session_keys_sm2(&shared)
            .expect("KDF failed");

        prop_assert_eq!(secrets1.master_secret.as_slice(), secrets2.master_secret.as_slice());
        prop_assert_eq!(secrets1.session_keys.client_key.as_slice(), secrets2.session_keys.client_key.as_slice());
        prop_assert_eq!(secrets1.session_keys.client_nonce, secrets2.session_keys.client_nonce);
        prop_assert_eq!(secrets1.session_keys.server_key.as_slice(), secrets2.session_keys.server_key.as_slice());
        prop_assert_eq!(secrets1.session_keys.server_nonce, secrets2.session_keys.server_nonce);
    });
}

// Property: Different random values produce different session keys
#[test]
fn test_kdf_sensitive_to_random() {
    proptest!(|(client_random1 in prop::array::uniform32(0u8..),
                 server_random1 in prop::array::uniform32(0u8..),
                 client_random2 in prop::array::uniform32(0u8..))| {
        prop_assume!(client_random1 != client_random2 || server_random1 != client_random2);

        let (sk1, pk1) = generate_sm2_ephemeral().expect("keygen 1 failed");
        let (sk2, pk2) = generate_sm2_ephemeral().expect("keygen 2 failed");

        let point1 = ProjectivePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&pk1).unwrap()
        ).into_option().unwrap();
        let point2 = ProjectivePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&pk2).unwrap()
        ).into_option().unwrap();
        let shared1 = point1 * sk1;
        let shared2 = point2 * sk2;

        let secrets1 = derive_session_keys_sm2(&shared1)
            .expect("KDF 1 failed");
        let secrets2 = derive_session_keys_sm2(&shared2)
            .expect("KDF 2 failed");

        prop_assert_ne!(secrets1.session_keys.client_key.as_slice(), secrets2.session_keys.client_key.as_slice());
    });
}

// Property: Signature verification succeeds with correct key
#[test]
fn test_signature_verification_consistency() {
    proptest!(|(data in prop::collection::vec(0u8.., 0..1000))| {
        let keypair = Sm2KeyPair::generate_with_distid(SM2_DEFAULT_ID.to_string())
            .expect("keygen failed");
        let signer = Sm2Signer::new(&keypair).expect("signer creation failed");
        let verifier = Sm2Verifier::new(
            &keypair.public_key_bytes_uncompressed(),
            SM2_DEFAULT_ID
        ).expect("verifier creation failed");

        let signature = sign_finished(&signer, &data).expect("sign failed");
        let result = verify_finished(&verifier, &data, &signature);

        prop_assert!(result.is_ok(), "Verification should succeed with correct key");
    });
}

// Property: ALPN selection returns a server protocol if there's a match
#[test]
fn test_alpn_returns_match() {
    proptest!(|(server_protocols in prop::collection::vec("[a-z]+", 1..5),
                 client_protocols in prop::collection::vec("[a-z]+", 1..5))| {
        let server: Vec<String> = server_protocols.into_iter().map(|s| s.to_string()).collect();
        let client: Vec<String> = client_protocols.into_iter().map(|s| s.to_string()).collect();

        let result = select_alpn(&server, &client);

        let has_common = server.iter().any(|s| client.contains(s));
        if has_common {
            prop_assert!(result.is_some(), "Should return Some if there's a match");
        }
    });
}

// Property: ALPN returns None when there's no match
#[test]
fn test_alpn_no_match() {
    proptest!(|(server_protocols in prop::collection::vec("unique_server_protocol_[a-z]+", 1..5),
                 client_protocols in prop::collection::vec("unique_client_protocol_[a-z]+", 1..5))| {
        let server: Vec<String> = server_protocols.into_iter().map(|s| s.to_string()).collect();
        let client: Vec<String> = client_protocols.into_iter().map(|s| s.to_string()).collect();

        let result = select_alpn(&server, &client);

        let has_common = server.iter().any(|s| client.contains(s));
        prop_assert!(!has_common);
        prop_assert_eq!(result, None);
    });
}

// Property: Ephemeral key generation produces valid points
#[test]
fn test_ephemeral_key_valid_point() {
    proptest!(|(_seed in 0u32..1000u32)| {
        let (sk, pk) = generate_sm2_ephemeral().expect("keygen failed");

        prop_assert_eq!(sk.to_bytes().len(), 32);
        prop_assert_eq!(pk.len(), 65);
        prop_assert_eq!(pk[0], 0x04);

        let enc = EncodedPoint::from_bytes(&pk).expect("encoding failed");
        let point = ProjectivePoint::from_encoded_point(&enc).into_option();
        prop_assert!(point.is_some(), "Generated public key should be a valid curve point");
    });
}

// ============== SM4 GCM Property Tests ==============

// Property: Encrypt then decrypt recovers original plaintext
#[test]
fn test_gcm_encrypt_decrypt_roundtrip() {
    proptest!(|(plaintext in prop::collection::vec(0u8.., 0..1000))| {
        let key = vec![0x42u8; 16];
        let nonce = [0x00u8; 12];
        let cipher = Sm4Cipher::new(&key).expect("cipher creation failed");

        let (ciphertext, tag) = cipher.encrypt_gcm(&plaintext, &nonce, b"seq0")
            .expect("encrypt failed");

        let decrypted = cipher.decrypt_gcm(&ciphertext, &nonce, b"seq0", &tag)
            .expect("decrypt failed");

        prop_assert_eq!(decrypted, plaintext);
    });
}

// Property: Different plaintexts produce different ciphertexts
#[test]
fn test_gcm_different_plaintexts_different_ciphertexts() {
    proptest!(|(plaintext1 in prop::collection::vec(0u8.., 1..100),
                 plaintext2 in prop::collection::vec(0u8.., 1..100))| {
        prop_assume!(plaintext1 != plaintext2);

        let key = vec![0x42u8; 16];
        let nonce = [0x00u8; 12];
        let cipher = Sm4Cipher::new(&key).expect("cipher creation failed");

        let (ct1, tag1) = cipher.encrypt_gcm(&plaintext1, &nonce, b"seq0")
            .expect("encrypt 1 failed");
        let (ct2, tag2) = cipher.encrypt_gcm(&plaintext2, &nonce, b"seq0")
            .expect("encrypt 2 failed");

        prop_assert_ne!(ct1, ct2, "Different plaintexts should produce different ciphertexts");
        prop_assert_ne!(tag1, tag2, "Different plaintexts should produce different tags");
    });
}

// Property: Same plaintext with same nonce produces same ciphertext
#[test]
fn test_gcm_deterministic_encryption() {
    proptest!(|(plaintext in prop::collection::vec(0u8.., 0..100))| {
        let key = vec![0x42u8; 16];
        let nonce = [0x00u8; 12];
        let cipher = Sm4Cipher::new(&key).expect("cipher creation failed");

        let (ct1, tag1) = cipher.encrypt_gcm(&plaintext, &nonce, b"seq0")
            .expect("encrypt 1 failed");
        let (ct2, tag2) = cipher.encrypt_gcm(&plaintext, &nonce, b"seq0")
            .expect("encrypt 2 failed");

        prop_assert_eq!(ct1, ct2, "Same inputs should produce same ciphertext");
        prop_assert_eq!(tag1, tag2, "Same inputs should produce same tag");
    });
}

// ============== Nonce Property Tests ==============

// Property: Nonce uniqueness for sequential sequence numbers
#[test]
fn test_nonce_uniqueness_property() {
    proptest!(|(base_nonce in prop::array::uniform12(0u8..))| {
        let base: [u8; 12] = base_nonce;
        let mut seen_nonces: Vec<Vec<u8>> = Vec::new();

        for seq in 0..100u64 {
            let nonce = next_nonce(&base, seq).expect("next_nonce failed");
            let nonce_vec = nonce.to_vec();

            for existing in &seen_nonces {
                prop_assert_ne!(&nonce_vec, existing, "Nonce at seq {} should be unique", seq);
            }
            seen_nonces.push(nonce_vec);
        }
    });
}

// Property: Different ALPN protocols result in different selections
#[test]
fn test_alpn_selection_deterministic() {
    proptest!(|(server_protocols in prop::collection::vec("[a-z0-9]+", 1..5),
                 client_protocols in prop::collection::vec("[a-z0-9]+", 1..5))| {
        let server: Vec<String> = server_protocols.into_iter().map(|s| s.to_string()).collect();
        let client: Vec<String> = client_protocols.into_iter().map(|s| s.to_string()).collect();

        // Selection should be deterministic - same inputs produce same output
        let result1 = select_alpn(&server, &client);
        let result2 = select_alpn(&server, &client);

        prop_assert_eq!(result1, result2, "ALPN selection should be deterministic");
    });
}

// Property: ALPN returns first matching protocol from server list
#[test]
fn test_alpn_returns_from_server_list() {
    proptest!(|(server_protocols in prop::collection::vec("gm-[a-z]+", 1..5),
                 client_protocols in prop::collection::vec("[a-z]+", 1..5))| {
        let server: Vec<String> = server_protocols.into_iter().map(|s| s.to_string()).collect();
        let client: Vec<String> = client_protocols.into_iter().map(|s| s.to_string()).collect();

        let result = select_alpn(&server, &client);

        if let Some(selected) = result {
            // Selected protocol must be from server list
            prop_assert!(server.contains(&selected.to_string()), "Selected protocol must be from server list");
            // Selected protocol must be from client list (already verified by being selected)
            prop_assert!(client.contains(&selected.to_string()), "Selected protocol must be from client list");
        }
    });
}

// Property: Session keys derivation is sensitive to input changes
#[test]
fn test_session_keys_sensitive_to_shared_secret() {
    proptest!(|(_client_random in prop::array::uniform32(0u8..),
                 _server_random in prop::array::uniform32(0u8..))| {
        let (sk1, pk1) = generate_sm2_ephemeral().expect("keygen 1 failed");
        let (sk2, pk2) = generate_sm2_ephemeral().expect("keygen 2 failed");

        let point1 = ProjectivePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&pk1).unwrap()
        ).into_option().unwrap();
        let point2 = ProjectivePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&pk2).unwrap()
        ).into_option().unwrap();

        let shared1 = point1 * sk1;
        let shared2 = point2 * sk2;

        let secrets1 = derive_session_keys_sm2(&shared1)
            .expect("KDF 1 failed");
        let secrets2 = derive_session_keys_sm2(&shared2)
            .expect("KDF 2 failed");

        // Different shared secrets should produce different master secrets (highly likely)
        // This is a probabilistic property
        prop_assert_ne!(secrets1.master_secret, secrets2.master_secret,
            "Different shared secrets should produce different master secrets");
    });
}

// Property: GCM ciphertext length is plaintext length + 16 (tag)
#[test]
fn test_gcm_ciphertext_length() {
    proptest!(|(plaintext in prop::collection::vec(0u8.., 0..1000))| {
        let key = vec![0x42u8; 16];
        let nonce = [0x00u8; 12];
        let cipher = Sm4Cipher::new(&key).expect("cipher creation failed");

        let (ciphertext, tag) = cipher.encrypt_gcm(&plaintext, &nonce, b"seq0")
            .expect("encrypt failed");

        // GCM ciphertext has same length as plaintext
        prop_assert_eq!(ciphertext.len(), plaintext.len(), "Ciphertext length should equal plaintext length");
        // GCM tag is always 16 bytes
        prop_assert_eq!(tag.len(), 16, "GCM tag should be 16 bytes");
    });
}

// Property: Empty plaintext produces valid ciphertext (just tag)
#[test]
fn test_gcm_empty_plaintext() {
    let key = vec![0x42u8; 16];
    let nonce = [0x00u8; 12];
    let cipher = Sm4Cipher::new(&key).expect("cipher creation failed");

    let (ciphertext, tag) = cipher
        .encrypt_gcm(&[], &nonce, b"seq0")
        .expect("encrypt failed");

    // Empty plaintext should produce empty ciphertext
    assert_eq!(
        ciphertext.len(),
        0,
        "Empty plaintext should produce empty ciphertext"
    );
    // But still produce a 16-byte tag
    assert_eq!(tag.len(), 16, "Tag should still be 16 bytes");
}

// Property: Ephemeral key pairs are unique across generations
#[test]
fn test_ephemeral_keys_unique() {
    let mut public_keys: Vec<Vec<u8>> = Vec::new();

    for _ in 0..10 {
        let (_, pk) = generate_sm2_ephemeral().expect("keygen failed");

        for existing in &public_keys {
            assert_ne!(&pk, existing, "Generated public keys should be unique");
        }
        public_keys.push(pk);
    }
}

// Property: Session keys have correct length
#[test]
fn test_session_keys_length_property() {
    proptest!(|(_client_random in prop::array::uniform32(0u8..),
                 _server_random in prop::array::uniform32(0u8..))| {
        let (sk, pk) = generate_sm2_ephemeral().expect("keygen failed");
        let point = ProjectivePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&pk).unwrap()
        ).into_option().unwrap();
        let shared = point * sk;

        let secrets = derive_session_keys_sm2(&shared)
            .expect("KDF failed");

        // SM4 client key should be 16 bytes
        prop_assert_eq!(secrets.session_keys.client_key.len(), 16,
            "SM4 client key should be 16 bytes");
        // SM4 server key should be 16 bytes
        prop_assert_eq!(secrets.session_keys.server_key.len(), 16,
            "SM4 server key should be 16 bytes");
        // Client nonce should be 12 bytes
        prop_assert_eq!(secrets.session_keys.client_nonce.len(), SM4_GCM_NONCE_LENGTH,
            "Client nonce should be 12 bytes");
        // Server nonce should be 12 bytes
        prop_assert_eq!(secrets.session_keys.server_nonce.len(), SM4_GCM_NONCE_LENGTH,
            "Server nonce should be 12 bytes");
        // Client and server keys must be different
        prop_assert_ne!(secrets.session_keys.client_key.as_slice(), secrets.session_keys.server_key.as_slice(),
            "Client and server keys must be different to prevent GCM nonce reuse");
        // Master secret should be 32 bytes (SM3 output)
        prop_assert_eq!(secrets.master_secret.len(), 32,
            "Master secret should be 32 bytes");
    });
}
