//! SM4 cipher tests — error paths, known-answer vectors, edge cases

use gm_crypto::sm4::Sm4Cipher;
use gm_crypto::sm4::{SM4_BLOCK_SIZE, SM4_GCM_NONCE_LENGTH, SM4_GCM_TAG_LENGTH, SM4_KEY_LENGTH};

// ── Known-answer test vectors (GM/T 0002-2012) ────────────────────────

#[test]
#[allow(deprecated)]
fn test_sm4_ecb_known_vector() {
    // GM/T 0002-2012: key=0123456789ABCDEFFEDCBA9876543210, plaintext=0123456789ABCDEFFEDCBA9876543210
    let key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();
    let pt = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();
    let expected_ct = hex::decode("681EDF34D206965E86B3E94F536E4246").unwrap();

    let cipher = Sm4Cipher::new(&key).unwrap();
    let ct = cipher.encrypt_ecb(&pt).unwrap();
    assert_eq!(ct, expected_ct);

    let decrypted = cipher.decrypt_ecb(&ct).unwrap();
    assert_eq!(decrypted, pt);
}

// ── Key creation error paths ───────────────────────────────────────────

#[test]
fn test_sm4_new_key_too_short() {
    let result = Sm4Cipher::new(&[0u8; 15]);
    assert!(result.is_err());
    match result.err().unwrap() {
        gm_crypto::CryptoError::InvalidKeyLength { expected, actual } => {
            assert_eq!(expected, SM4_KEY_LENGTH);
            assert_eq!(actual, 15);
        }
        other => panic!("expected InvalidKeyLength, got {:?}", other),
    }
}

#[test]
fn test_sm4_new_key_too_long() {
    let result = Sm4Cipher::new(&[0u8; 17]);
    assert!(result.is_err());
}

#[test]
fn test_sm4_from_hex_valid() {
    let hex_key = "0123456789abcdef0123456789abcdef";
    let cipher = Sm4Cipher::from_hex(hex_key);
    assert!(cipher.is_ok());
}

#[test]
fn test_sm4_from_hex_invalid() {
    let result = Sm4Cipher::from_hex("not_hex_at_all!!");
    assert!(result.is_err());
    match result.err().unwrap() {
        gm_crypto::CryptoError::InvalidHex(_) => {}
        other => panic!("expected InvalidHex, got {:?}", other),
    }
}

#[test]
fn test_sm4_from_hex_wrong_length() {
    // Valid hex but only 8 bytes (16 hex chars) instead of 16 bytes
    let result = Sm4Cipher::from_hex("0123456789abcdef");
    assert!(result.is_err());
}

// ── ECB error paths ────────────────────────────────────────────────────

#[test]
#[allow(deprecated)]
fn test_sm4_ecb_encrypt_not_block_aligned() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let result = cipher.encrypt_ecb(b"not 16 bytes");
    assert!(result.is_err());
    match result.unwrap_err() {
        gm_crypto::CryptoError::InvalidDataLength(msg) => {
            assert!(msg.contains("multiple of"));
        }
        other => panic!("expected InvalidDataLength, got {:?}", other),
    }
}

#[test]
#[allow(deprecated)]
fn test_sm4_ecb_decrypt_not_block_aligned() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let result = cipher.decrypt_ecb(&[0u8; 20]);
    assert!(result.is_err());
}

#[test]
#[allow(deprecated)]
fn test_sm4_ecb_empty_data() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let ct = cipher.encrypt_ecb(&[]).unwrap();
    assert!(ct.is_empty());
    let pt = cipher.decrypt_ecb(&[]).unwrap();
    assert!(pt.is_empty());
}

// ── CBC error paths and padding ────────────────────────────────────────

#[test]
fn test_sm4_cbc_wrong_iv_length() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let result = cipher.encrypt_cbc(b"data", &[0u8; 10]);
    assert!(result.is_err());
    match result.unwrap_err() {
        gm_crypto::CryptoError::InvalidDataLength(msg) => {
            assert!(msg.contains("IV length"));
        }
        other => panic!("expected InvalidDataLength, got {:?}", other),
    }
}

#[test]
fn test_sm4_cbc_decrypt_wrong_iv_length() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let result = cipher.decrypt_cbc(&[0u8; 16], &[0u8; 10]);
    assert!(result.is_err());
}

#[test]
fn test_sm4_cbc_decrypt_not_block_aligned() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let result = cipher.decrypt_cbc(&[0u8; 20], &[0u8; 16]);
    assert!(result.is_err());
}

#[test]
fn test_sm4_cbc_pkcs7_padding_roundtrip() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let iv = [0u8; 16];

    // Plaintext not aligned to block size → PKCS#7 padding should be applied
    for len in [1, 5, 15, 16, 17, 31, 32, 33] {
        let pt = vec![0xABu8; len];
        let ct = cipher.encrypt_cbc(&pt, &iv).unwrap();
        // Ciphertext should always be a multiple of block size
        assert!(ct.len().is_multiple_of(SM4_BLOCK_SIZE), "len={}", len);
        let decrypted = cipher.decrypt_cbc(&ct, &iv).unwrap();
        assert_eq!(decrypted, pt, "CBC roundtrip failed for len={}", len);
    }
}

#[test]
fn test_sm4_cbc_empty_data() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let iv = [0u8; 16];
    // Empty plaintext: PKCS#7 adds a full 16-byte padding block
    let ct = cipher.encrypt_cbc(&[], &iv).unwrap();
    assert_eq!(
        ct.len(),
        16,
        "Empty plaintext should produce 16-byte ciphertext (full padding block)"
    );
    let pt = cipher.decrypt_cbc(&ct, &iv).unwrap();
    assert!(
        pt.is_empty(),
        "Decrypting and removing padding should recover empty plaintext"
    );
}

// ── GCM error paths ────────────────────────────────────────────────────

#[test]
fn test_sm4_gcm_encrypt_wrong_nonce_length() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let result = cipher.encrypt_gcm(b"data", &[0u8; 16], &[]);
    assert!(result.is_err());
    match result.unwrap_err() {
        gm_crypto::CryptoError::InvalidDataLength(msg) => {
            assert!(msg.contains("Nonce length"));
        }
        other => panic!("expected InvalidDataLength, got {:?}", other),
    }
}

#[test]
fn test_sm4_gcm_decrypt_wrong_nonce_length() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let result = cipher.decrypt_gcm(&[0u8; 16], &[0u8; 16], &[], &[0u8; 16]);
    assert!(result.is_err());
}

#[test]
fn test_sm4_gcm_decrypt_wrong_tag_length() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let nonce = [0u8; SM4_GCM_NONCE_LENGTH];
    let result = cipher.decrypt_gcm(&[0u8; 16], &nonce, &[], &[0u8; 8]);
    assert!(result.is_err());
    match result.unwrap_err() {
        gm_crypto::CryptoError::InvalidDataLength(msg) => {
            assert!(msg.contains("Tag length"));
        }
        other => panic!("expected InvalidDataLength, got {:?}", other),
    }
}

#[test]
fn test_sm4_gcm_authentication_failure() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let nonce = [0u8; SM4_GCM_NONCE_LENGTH];

    let (ct, mut tag) = cipher.encrypt_gcm(b"secret", &nonce, b"aad").unwrap();
    // Tamper with tag
    tag[0] ^= 0xFF;

    let result = cipher.decrypt_gcm(&ct, &nonce, b"aad", &tag);
    assert!(result.is_err());
    match result.unwrap_err() {
        gm_crypto::CryptoError::Sm4Error(msg) => {
            assert!(msg.contains("authentication failed"));
        }
        other => panic!("expected Sm4Error, got {:?}", other),
    }
}

#[test]
fn test_sm4_gcm_tampered_ciphertext() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let nonce = [0u8; SM4_GCM_NONCE_LENGTH];
    let aad = b"header";

    let (mut ct, tag) = cipher.encrypt_gcm(b"secret data", &nonce, aad).unwrap();
    ct[0] ^= 0xFF; // tamper with ciphertext

    let result = cipher.decrypt_gcm(&ct, &nonce, aad, &tag);
    assert!(result.is_err());
}

#[test]
fn test_sm4_gcm_tampered_aad() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let nonce = [0u8; SM4_GCM_NONCE_LENGTH];

    let (ct, tag) = cipher
        .encrypt_gcm(b"secret", &nonce, b"original-aad")
        .unwrap();
    let result = cipher.decrypt_gcm(&ct, &nonce, b"tampered-aad", &tag);
    assert!(result.is_err());
}

#[test]
fn test_sm4_gcm_empty_plaintext() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let nonce = [0u8; SM4_GCM_NONCE_LENGTH];

    let (ct, tag) = cipher.encrypt_gcm(&[], &nonce, b"aad").unwrap();
    assert!(ct.is_empty());
    assert_eq!(tag.len(), SM4_GCM_TAG_LENGTH);

    let pt = cipher.decrypt_gcm(&ct, &nonce, b"aad", &tag).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn test_sm4_gcm_no_aad() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let nonce = [0u8; SM4_GCM_NONCE_LENGTH];
    let plaintext = b"hello world";

    let (ct, tag) = cipher.encrypt_gcm(plaintext, &nonce, &[]).unwrap();
    let pt = cipher.decrypt_gcm(&ct, &nonce, &[], &tag).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_sm4_gcm_large_plaintext() {
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let nonce = [0u8; SM4_GCM_NONCE_LENGTH];
    let plaintext = vec![0x42u8; 4096];

    let (ct, tag) = cipher.encrypt_gcm(&plaintext, &nonce, b"aad").unwrap();
    assert_eq!(ct.len(), plaintext.len());

    let pt = cipher.decrypt_gcm(&ct, &nonce, b"aad", &tag).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_sm4_gcm_nonce_reuse_produces_same_keystream() {
    // Demonstrates why nonce reuse is dangerous: same nonce + key → same keystream
    let cipher = Sm4Cipher::new(&[0u8; 16]).unwrap();
    let nonce = [0u8; SM4_GCM_NONCE_LENGTH];

    let (ct1, _) = cipher.encrypt_gcm(b"AAAA", &nonce, &[]).unwrap();
    let (ct2, _) = cipher.encrypt_gcm(b"BBBB", &nonce, &[]).unwrap();

    // XOR of ciphertexts should equal XOR of plaintexts when nonce is reused
    let xor_ct: Vec<u8> = ct1.iter().zip(&ct2).map(|(a, b)| a ^ b).collect();
    let xor_pt: Vec<u8> = b"AAAA".iter().zip(b"BBBB").map(|(a, b)| a ^ b).collect();
    assert_eq!(xor_ct, xor_pt);
}

// ── Constant definitions ───────────────────────────────────────────────

#[test]
fn test_sm4_constants() {
    assert_eq!(SM4_KEY_LENGTH, 16);
    assert_eq!(SM4_BLOCK_SIZE, 16);
    assert_eq!(SM4_GCM_TAG_LENGTH, 16);
    assert_eq!(SM4_GCM_NONCE_LENGTH, 12);
}

// ============================================================================
// Boundary and edge case tests
// ============================================================================

#[test]
fn test_sm4_gcm_decrypt_tag_wrong_length() {
    use gm_crypto::sm4::Sm4Cipher;

    let key = [0xabu8; 16];
    let nonce = [0x01u8; 12];
    let cipher = Sm4Cipher::new(&key).unwrap();
    let (ct, _tag) = cipher.encrypt_gcm(b"hello", &nonce, &[]).unwrap();

    // Tag with wrong length should fail (GCM requires 16-byte tag)
    let short_tag = [0u8; 8];
    let result = cipher.decrypt_gcm(&ct, &nonce, &[], &short_tag);
    assert!(result.is_err(), "decrypt with 8-byte tag should fail");
}

#[test]
fn test_sm4_gcm_decrypt_without_ciphertext() {
    use gm_crypto::sm4::Sm4Cipher;

    let key = [0xabu8; 16];
    let nonce = [0x01u8; 12];
    let cipher = Sm4Cipher::new(&key).unwrap();

    // Decrypt empty ciphertext with valid tag should decrypt to empty
    let (ct, tag) = cipher.encrypt_gcm(&[], &nonce, &[]).unwrap();
    assert!(ct.is_empty());
    let decrypted = cipher.decrypt_gcm(&ct, &nonce, &[], &tag).unwrap();
    assert!(decrypted.is_empty(), "decrypt empty should produce empty");
}

#[test]
fn test_sm4_gcm_encrypt_zero_length_with_aad() {
    use gm_crypto::sm4::Sm4Cipher;

    let key = [0x42u8; 16];
    let nonce = [0x11u8; 12];
    let aad = b"authenticated but not encrypted";
    let cipher = Sm4Cipher::new(&key).unwrap();

    // Empty plaintext with AAD: used for close_notify
    let (ct, tag) = cipher.encrypt_gcm(&[], &nonce, aad).unwrap();
    assert!(
        ct.is_empty(),
        "ciphertext for empty plaintext should be empty"
    );
    assert_eq!(tag.len(), 16, "tag should be 16 bytes");

    // Verify decryption works
    let decrypted = cipher.decrypt_gcm(&ct, &nonce, aad, &tag).unwrap();
    assert!(decrypted.is_empty(), "decrypted should be empty");
}

#[test]
fn test_sm4_gcm_boundary_nonce_sequence() {
    use gm_crypto::sm4::{SM4_GCM_NONCE_LENGTH, Sm4Cipher};

    let key = [0x77u8; 16];
    let cipher = Sm4Cipher::new(&key).unwrap();
    let plaintext = b"sequence boundary test";

    // Test with maximum sequence number in last 8 bytes of nonce
    let mut nonce = [0u8; SM4_GCM_NONCE_LENGTH];
    nonce[4..].copy_from_slice(&u64::MAX.to_be_bytes());

    let (ct, tag) = cipher.encrypt_gcm(plaintext, &nonce, &[]).unwrap();
    let decrypted = cipher.decrypt_gcm(&ct, &nonce, &[], &tag).unwrap();
    assert_eq!(decrypted, plaintext);
}
