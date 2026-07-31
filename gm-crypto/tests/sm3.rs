//! SM3 hash and HMAC tests

use gm_crypto::sm3::{Sm3Hasher, Sm3Hmac};

// ── Known-answer test vectors (GM/T 0003-2012 / SM3 standard) ──────────

#[test]
fn test_sm3_empty_string() {
    // SM3("") per GM/T 0003-2012
    let hash = Sm3Hasher::hash(&[]).unwrap();
    let hex = Sm3Hasher::hash_hex(&[]).unwrap();
    assert_eq!(
        hex,
        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
    );
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_sm3_abc() {
    // SM3("abc") per GM/T 0003-2012
    let hex = Sm3Hasher::hash_hex(b"abc").unwrap();
    assert_eq!(
        hex,
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    );
}

#[test]
fn test_sm3_hash_deterministic() {
    let h1 = Sm3Hasher::hash(b"hello world").unwrap();
    let h2 = Sm3Hasher::hash(b"hello world").unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn test_sm3_different_inputs_different_hashes() {
    let h1 = Sm3Hasher::hash(b"hello").unwrap();
    let h2 = Sm3Hasher::hash(b"world").unwrap();
    assert_ne!(h1, h2);
}

#[test]
fn test_sm3_hash_base64() {
    let hash = Sm3Hasher::hash(b"abc").unwrap();
    let b64 = Sm3Hasher::hash_base64(b"abc").unwrap();
    // Verify round-trip: base64 decode should match hash bytes
    let decoded = base64_to_bytes_helper(&b64);
    assert_eq!(decoded, hash);
}

fn base64_to_bytes_helper(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

// ── Sm3Hmac tests ──────────────────────────────────────────────────────

#[test]
fn test_hmac_compute_and_verify() {
    let key = b"test-key-12345678";
    let hmac = Sm3Hmac::new(key);
    let data = b"hello world";

    let tag = hmac.compute(data).unwrap();
    assert_eq!(tag.len(), 32); // SM3 output = 32 bytes

    // Verify with correct tag
    assert!(hmac.verify(data, &tag).unwrap());

    // Verify with wrong tag should fail
    let mut bad_tag = tag.clone();
    bad_tag[0] ^= 0xFF;
    assert!(!hmac.verify(data, &bad_tag).unwrap());
}

#[test]
fn test_hmac_compute_hex() {
    let key = b"test-key";
    let hmac = Sm3Hmac::new(key);
    let data = b"data";

    let hex = hmac.compute_hex(data).unwrap();
    assert_eq!(hex.len(), 64); // 32 bytes -> 64 hex chars

    // hex should be valid hex
    let bytes = hex::decode(&hex).unwrap();
    assert_eq!(bytes.len(), 32);
}

#[test]
fn test_hmac_different_keys_different_tags() {
    let data = b"same data";
    let hmac1 = Sm3Hmac::new(b"key-one-12345678");
    let hmac2 = Sm3Hmac::new(b"key-two-12345678");

    let tag1 = hmac1.compute(data).unwrap();
    let tag2 = hmac2.compute(data).unwrap();
    assert_ne!(tag1, tag2);
}

#[test]
fn test_hmac_different_data_different_tags() {
    let key = b"same-key";
    let hmac = Sm3Hmac::new(key);

    let tag1 = hmac.compute(b"message-a").unwrap();
    let tag2 = hmac.compute(b"message-b").unwrap();
    assert_ne!(tag1, tag2);
}

#[test]
fn test_hmac_verify_wrong_length() {
    let hmac = Sm3Hmac::new(b"key");
    let tag = hmac.compute(b"data").unwrap();

    // Tag with different length should return false
    let short_tag = &tag[..16];
    assert!(!hmac.verify(b"data", short_tag).unwrap());
}

#[test]
fn test_hmac_long_key() {
    // Key longer than block size (64 bytes) should be hashed first
    let key = [0xABu8; 100]; // 100 bytes > 64 byte block size
    let hmac = Sm3Hmac::new(&key);
    let data = b"test data with long key";

    let tag = hmac.compute(data).unwrap();
    assert_eq!(tag.len(), 32);
    assert!(hmac.verify(data, &tag).unwrap());
}

#[test]
fn test_hmac_empty_data() {
    let hmac = Sm3Hmac::new(b"key");
    let tag = hmac.compute(&[]).unwrap();
    assert_eq!(tag.len(), 32);
    assert!(hmac.verify(&[], &tag).unwrap());
}

#[test]
fn test_hmac_empty_key() {
    let hmac = Sm3Hmac::new(&[]);
    let tag = hmac.compute(b"data").unwrap();
    assert_eq!(tag.len(), 32);
    assert!(hmac.verify(b"data", &tag).unwrap());
}

#[test]
fn test_hmac_deterministic() {
    let key = b"consistent-key";
    let hmac = Sm3Hmac::new(key);
    let data = b"consistent-data";

    let tag1 = hmac.compute(data).unwrap();
    let tag2 = hmac.compute(data).unwrap();
    assert_eq!(tag1, tag2);
}
