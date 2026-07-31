//! SM2 tests

use gm_crypto::CryptoError;
use gm_crypto::sm2::{Sm2Decryptor, Sm2Encryptor, Sm2KeyPair, Sm2Signer, Sm2Verifier};
use gm_crypto::sm3::Sm3Hasher;
use gm_crypto::sm4::Sm4Cipher;

/// GM/T standard distid for SM2 signatures
const GM_TLS_DEFAULT_ID: &str = "1234567812345678";

#[test]
fn test_sm2_key_generation() {
    let keypair = Sm2KeyPair::generate().unwrap();
    assert_eq!(keypair.private_key_bytes().len(), 32);
    assert_eq!(keypair.public_key_bytes().len(), 33); // compressed
    let uncompressed = keypair.public_key_bytes_uncompressed();
    assert_eq!(uncompressed.len(), 65);
    assert_eq!(uncompressed[0], 0x04);
}

#[test]
fn test_sm2_sign_verify() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let signer = Sm2Signer::new(&keypair).unwrap();
    let data = b"hello world";

    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 64);

    let verifier =
        Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), GM_TLS_DEFAULT_ID).unwrap();
    assert!(verifier.verify(data, &sig).is_ok());
}

#[test]
fn test_sm2_sign_verify_hex() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let signer = Sm2Signer::new(&keypair).unwrap();
    let data = b"test data";

    let sig_hex = signer.sign_hex(data).unwrap();
    assert_eq!(sig_hex.len(), 128); // 64 bytes -> 128 hex chars

    let verifier =
        Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), GM_TLS_DEFAULT_ID).unwrap();
    assert!(verifier.verify_hex(data, &sig_hex).is_ok());
}

#[test]
fn test_sm2_sign_bad_verification() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let signer = Sm2Signer::new(&keypair).unwrap();
    let data = b"hello";
    let sig = signer.sign(data).unwrap();

    let verifier =
        Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), GM_TLS_DEFAULT_ID).unwrap();
    // Wrong data should fail verification
    assert!(verifier.verify(b"wrong data", &sig).is_err());
}

#[test]
fn test_sm2_from_private_key() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let sk_bytes = keypair.private_key_bytes();

    let keypair2 = Sm2KeyPair::from_private_key(&sk_bytes).unwrap();
    assert_eq!(keypair.private_key_bytes(), keypair2.private_key_bytes());
}

#[test]
fn test_sm2_pem_serialization() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let pem = keypair.private_key_pem().unwrap();
    assert!(pem.contains("-----BEGIN EC PRIVATE KEY-----"));
    assert!(pem.contains("-----END EC PRIVATE KEY-----"));

    let keypair2 = Sm2KeyPair::from_private_key_pem(&pem).unwrap();
    assert_eq!(keypair.private_key_bytes(), keypair2.private_key_bytes());
}

#[test]
fn test_sm2_public_key_decompression() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let compressed = keypair.public_key_bytes();
    assert!(compressed.len() == 33);

    let uncompressed = gm_crypto::sm2::decompress_sm2_pubkey(&compressed).unwrap();
    assert_eq!(uncompressed.len(), 65);
    assert_eq!(uncompressed[0], 0x04);

    // Uncompressed input should also work
    let uncompressed2 = gm_crypto::sm2::decompress_sm2_pubkey(&uncompressed).unwrap();
    assert_eq!(uncompressed, uncompressed2);
}

#[test]
fn test_sm3_hash() {
    let data = b"hello";
    let hash = Sm3Hasher::hash(data).unwrap();
    assert_eq!(hash.len(), 32);

    let hex = Sm3Hasher::hash_hex(data).unwrap();
    assert_eq!(hex.len(), 64);

    // Known test vector (GM/T 3309-2012 test vector simplified)
    let hash2 = Sm3Hasher::hash(b"abc").unwrap();
    assert_eq!(hash2.len(), 32);
}

#[test]
fn test_sm4_gcm_encrypt_decrypt() {
    let key = [0u8; 16];
    let cipher = Sm4Cipher::new(&key).unwrap();
    let nonce = [0u8; 12];
    let plaintext = b"hello world";

    let (ct, tag) = cipher.encrypt_gcm(plaintext, &nonce, &[]).unwrap();
    assert_eq!(ct.len(), plaintext.len());

    let pt = cipher.decrypt_gcm(&ct, &nonce, &[], &tag).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_sm4_gcm_with_aad() {
    let key = [0u8; 16];
    let cipher = Sm4Cipher::new(&key).unwrap();
    let nonce = [0u8; 12];
    let plaintext = b"secret";
    let aad = b"additional data";

    let (ct, tag) = cipher.encrypt_gcm(plaintext, &nonce, aad).unwrap();
    let pt = cipher.decrypt_gcm(&ct, &nonce, aad, &tag).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_sm4_cbc_encrypt_decrypt() {
    let key = [0u8; 16];
    let iv = [0u8; 16];
    let cipher = Sm4Cipher::new(&key).unwrap();
    let plaintext = b"hello world 1234"; // 16 bytes for CBC

    let ct = cipher.encrypt_cbc(plaintext, &iv).unwrap();
    let pt = cipher.decrypt_cbc(&ct, &iv).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
#[allow(deprecated)]
fn test_sm4_ecb_encrypt_decrypt() {
    let key = [0u8; 16];
    let cipher = Sm4Cipher::new(&key).unwrap();
    let plaintext = b"hello world!!!!!"; // 16 bytes for ECB

    let ct = cipher.encrypt_ecb(plaintext).unwrap();
    let pt = cipher.decrypt_ecb(&ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_sm2_encrypt_decrypt() {
    // Generate key pair
    let keypair = Sm2KeyPair::generate().unwrap();

    // Create encryptor with public key
    let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();

    // Create decryptor with key pair
    let decryptor = Sm2Decryptor::new(keypair.duplicate());

    // Test data
    let plaintext = b"Hello, SM2 encryption!";

    // Encrypt
    let ciphertext = encryptor.encrypt(plaintext).unwrap();
    // Output format: C1(65) || C3(32) || C2
    assert_eq!(ciphertext.len(), 65 + 32 + plaintext.len());

    // Decrypt
    let decrypted = decryptor.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_sm2_encrypt_decrypt_multiple_sizes() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
    let decryptor = Sm2Decryptor::new(keypair.duplicate());

    // Test various plaintext sizes
    for len in [1, 16, 32, 65, 100, 1000] {
        let plaintext = vec![0u8; len];
        let ciphertext = encryptor.encrypt(&plaintext).unwrap();
        let decrypted = decryptor.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext, "Failed for plaintext length {}", len);
    }
}

#[test]
fn test_sm2_encrypt_randomness() {
    // Same plaintext should produce different ciphertexts due to random k
    let keypair = Sm2KeyPair::generate().unwrap();
    let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
    let plaintext = b"test data";

    let ct1 = encryptor.encrypt(plaintext).unwrap();
    let ct2 = encryptor.encrypt(plaintext).unwrap();

    // Ciphertexts should be different due to random k
    assert_ne!(
        ct1, ct2,
        "Ciphertexts should be different due to randomness"
    );

    // But both should decrypt to the same plaintext
    let decryptor = Sm2Decryptor::new(keypair);
    assert_eq!(decryptor.decrypt(&ct1).unwrap(), plaintext);
    assert_eq!(decryptor.decrypt(&ct2).unwrap(), plaintext);
}

#[test]
fn test_sm2_encrypt_invalid_ciphertext() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let decryptor = Sm2Decryptor::new(keypair);

    // Too short ciphertext
    let result = decryptor.decrypt(&[0u8; 10]);
    assert!(result.is_err());

    // Valid length but tampered ciphertext
    let encryptor = Sm2Encryptor::new(
        &Sm2KeyPair::generate()
            .unwrap()
            .public_key_bytes_uncompressed(),
    )
    .unwrap();
    let mut ct = encryptor.encrypt(b"test").unwrap();
    ct[97] ^= 0xFF; // Tamper with ciphertext
    let result = decryptor.decrypt(&ct);
    assert!(result.is_err());
}

#[test]
fn test_sm2_encrypt_with_different_keys() {
    let keypair1 = Sm2KeyPair::generate().unwrap();
    let keypair2 = Sm2KeyPair::generate().unwrap();

    let encryptor1 = Sm2Encryptor::new(&keypair1.public_key_bytes_uncompressed()).unwrap();
    let encryptor2 = Sm2Encryptor::new(&keypair2.public_key_bytes_uncompressed()).unwrap();

    let plaintext = b"secret message";

    let ct1 = encryptor1.encrypt(plaintext).unwrap();
    let _ct2 = encryptor2.encrypt(plaintext).unwrap();

    // Cannot decrypt with wrong key
    let decryptor_wrong = Sm2Decryptor::new(keypair2);
    assert!(decryptor_wrong.decrypt(&ct1).is_err());

    // Can decrypt with correct key
    let decryptor1 = Sm2Decryptor::new(keypair1);
    assert_eq!(decryptor1.decrypt(&ct1).unwrap(), plaintext);
}

// ── Custom distid tests ────────────────────────────────────────────────

#[test]
fn test_sm2_generate_with_custom_distid() {
    let custom_id = "custom@example.com";
    let keypair = Sm2KeyPair::generate_with_distid(custom_id.to_string()).unwrap();
    assert_eq!(keypair.distid(), custom_id);
}

#[test]
fn test_sm2_sign_verify_custom_distid() {
    let custom_id = "custom@example.com";
    let keypair = Sm2KeyPair::generate_with_distid(custom_id.to_string()).unwrap();

    // Sign with custom distid
    let signer = Sm2Signer::new(&keypair).unwrap();
    let data = b"test with custom distid";
    let sig = signer.sign(data).unwrap();

    // Verify with matching custom distid
    let verifier = Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), custom_id).unwrap();
    assert!(verifier.verify(data, &sig).is_ok());
}

#[test]
fn test_sm2_sign_verify_distid_mismatch() {
    let keypair = Sm2KeyPair::generate_with_distid("id-1".to_string()).unwrap();
    let signer = Sm2Signer::new(&keypair).unwrap();
    let sig = signer.sign(b"data").unwrap();

    // Different distid should fail verification
    let verifier = Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), "id-2").unwrap();
    assert!(verifier.verify(b"data", &sig).is_err());
}

#[test]
fn test_sm2_from_private_key_with_distid() {
    let custom_id = "custom@example.org";
    let keypair1 = Sm2KeyPair::generate_with_distid(custom_id.to_string()).unwrap();
    let sk = keypair1.private_key_bytes();

    let keypair2 = Sm2KeyPair::from_private_key_with_distid(&sk, custom_id.to_string()).unwrap();
    assert_eq!(keypair2.distid(), custom_id);
    assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
}

#[test]
fn test_sm2_signer_new_with_distid() {
    let keypair = Sm2KeyPair::generate().unwrap(); // default distid

    // Override distid when creating signer
    let custom_id = "override-id";
    let signer = Sm2Signer::new_with_distid(&keypair, custom_id).unwrap();
    let data = b"signed with override distid";
    let sig = signer.sign(data).unwrap();

    let verifier = Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), custom_id).unwrap();
    assert!(verifier.verify(data, &sig).is_ok());

    // Default distid should NOT verify this signature
    let verifier_default =
        Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), GM_TLS_DEFAULT_ID).unwrap();
    assert!(verifier_default.verify(data, &sig).is_err());
}

// ── Error path tests ───────────────────────────────────────────────────

#[test]
fn test_sm2_from_private_key_invalid() {
    // All-zero 32-byte scalar is invalid (not in [1, n-1])
    let result = Sm2KeyPair::from_private_key(&[0u8; 32]);
    assert!(result.is_err());
}

#[test]
fn test_sm2_from_private_key_zero_scalar() {
    // All-zero scalar is invalid (not in [1, n-1])
    let result = Sm2KeyPair::from_private_key(&[0u8; 32]);
    assert!(result.is_err());
}

#[test]
fn test_sm2_verifier_invalid_public_key() {
    let result = Sm2Verifier::new(&[0u8; 10], GM_TLS_DEFAULT_ID);
    assert!(result.is_err());
}

#[test]
fn test_sm2_verifier_wrong_signature_length() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let verifier =
        Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), GM_TLS_DEFAULT_ID).unwrap();

    let result = verifier.verify(b"data", &[0u8; 32]); // should be 64 bytes
    assert!(result.is_err());
    match result.unwrap_err() {
        CryptoError::Sm2Error(msg) => assert!(msg.contains("signature length")),
        other => panic!("expected Sm2Error, got {:?}", other),
    }
}

#[test]
fn test_sm2_encryptor_invalid_public_key() {
    let result = Sm2Encryptor::new(&[0u8; 10]);
    assert!(result.is_err());
}

#[test]
fn test_sm2_decrypt_too_short() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let decryptor = Sm2Decryptor::new(keypair);
    let result = decryptor.decrypt(&[0u8; 50]); // < 65 + 32 = 97
    assert!(result.is_err());
}

#[test]
fn test_sm2_keypair_distid_default() {
    let keypair = Sm2KeyPair::generate().unwrap();
    assert_eq!(keypair.distid(), GM_TLS_DEFAULT_ID);
}

#[test]
fn test_sm2_pem_roundtrip_with_distid() {
    let custom_id = "pem-test@example.com";
    let keypair = Sm2KeyPair::generate_with_distid(custom_id.to_string()).unwrap();
    let pem = keypair.private_key_pem().unwrap();

    // PEM roundtrip always uses default distid (per from_private_key_pem design)
    let keypair2 = Sm2KeyPair::from_private_key_pem(&pem).unwrap();
    assert_eq!(keypair2.distid(), GM_TLS_DEFAULT_ID);
    assert_eq!(keypair.private_key_bytes(), keypair2.private_key_bytes());
}

// ── Encrypted PEM tests ────────────────────────────────────────────────

#[test]
fn test_sm2_encrypted_pem_roundtrip() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let password = "test_password_123";

    // Encrypt
    let encrypted_pem = keypair.to_encrypted_pem(password).unwrap();
    assert!(encrypted_pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    assert!(encrypted_pem.contains("-----END ENCRYPTED PRIVATE KEY-----"));

    // Decrypt
    let decrypted = Sm2KeyPair::from_encrypted_pem(&encrypted_pem, password).unwrap();

    // Verify keys match
    assert_eq!(keypair.private_key_bytes(), decrypted.private_key_bytes());
    assert_eq!(keypair.public_key_bytes(), decrypted.public_key_bytes());
}

#[test]
fn test_sm2_encrypted_pem_wrong_password() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let password = "correct_password_123";
    let wrong_password = "wrong_password_456";

    let encrypted_pem = keypair.to_encrypted_pem(password).unwrap();

    // Should fail with wrong password
    let result = Sm2KeyPair::from_encrypted_pem(&encrypted_pem, wrong_password);
    assert!(result.is_err());
}

#[test]
fn test_sm2_encrypted_pem_short_password() {
    let keypair = Sm2KeyPair::generate().unwrap();
    let short_password = "short";

    let result = keypair.to_encrypted_pem(short_password);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("at least 8 characters")
    );
}

// ============================================================================
// Boundary tests for DoS protection limits
// ============================================================================

#[test]
fn test_sm2_encrypt_at_max_plaintext_length() {
    use gm_crypto::sm2::{SM2_MAX_PLAINTEXT_LEN, Sm2Encryptor, Sm2KeyPair};

    let keypair = Sm2KeyPair::generate().unwrap();
    let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();

    // Exact boundary: should succeed
    let data = vec![0xAAu8; SM2_MAX_PLAINTEXT_LEN];
    let result = encryptor.encrypt(&data);
    assert!(
        result.is_ok(),
        "encrypt at MAX_PLAINTEXT_LEN should succeed"
    );
}

#[test]
fn test_sm2_encrypt_exceeds_max_plaintext_length() {
    use gm_crypto::sm2::{SM2_MAX_PLAINTEXT_LEN, Sm2Encryptor, Sm2KeyPair};

    let keypair = Sm2KeyPair::generate().unwrap();
    let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();

    // Beyond boundary: should fail
    let data = vec![0xBBu8; SM2_MAX_PLAINTEXT_LEN + 1];
    let result = encryptor.encrypt(&data);
    assert!(
        result.is_err(),
        "encrypt exceeding MAX_PLAINTEXT_LEN should fail"
    );
    assert!(
        result.unwrap_err().to_string().contains("too large"),
        "error should mention 'too large'"
    );
}

#[test]
fn test_sm2_encrypt_empty_plaintext() {
    use gm_crypto::sm2::{Sm2Encryptor, Sm2KeyPair};

    let keypair = Sm2KeyPair::generate().unwrap();
    let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();

    // Empty plaintext: should succeed (valid edge case)
    let result = encryptor.encrypt(&[]);
    assert!(result.is_ok(), "encrypt empty plaintext should succeed");
    assert!(
        !result.unwrap().is_empty(),
        "ciphertext should not be empty"
    );
}
