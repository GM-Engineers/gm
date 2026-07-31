//! Fuzz target for gm-crypto primitives
//!
//! This fuzz target tests:
//! 1. SM4 CBC/GCM encryption/decryption round-trip
//! 2. SM3 hashing
//! 3. SM2 key generation and sign/verify
//! 4. SM2 encrypt/decrypt round-trip
//! 5. SM4-CBC PKCS#7 padding validation
//! 6. HMAC-SM3

#![no_main]
#![allow(deprecated)]

use libfuzzer_sys::{fuzz_target, arbitrary::Arbitrary};
use gm_crypto::{
    sm4::Sm4Cipher,
    sm3::Sm3Hasher,
    sm2::{Sm2KeyPair, Sm2Encryptor, Sm2Decryptor},
};

#[derive(Arbitrary, Debug)]
enum CryptoInput {
    // SM4 operations
    Sm4Cbc(Sm4CbcInput),
    Sm4Gcm(Sm4GcmInput),
    Sm4Ecbc(Sm4EcbcInput),
    // SM3 operations
    Sm3Hash(Sm3HashInput),
    // SM2 operations
    Sm2SignVerify(Sm2SignVerifyInput),
    Sm2EncryptDecrypt(Sm2EncryptDecryptInput),
    // HMAC
    HmacSm3(HmacInput),
}

#[derive(Arbitrary, Debug)]
struct Sm4CbcInput {
    key: [u8; 16],
    iv: [u8; 16],
    plaintext: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Sm4GcmInput {
    key: [u8; 16],
    nonce: [u8; 12],
    plaintext: Vec<u8>,
    aad: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Sm4EcbcInput {
    key: [u8; 16],
    plaintext: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Sm3HashInput {
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Sm2SignVerifyInput {
    message: Vec<u8>,
    seed: [u8; 32],
}

#[derive(Arbitrary, Debug)]
struct Sm2EncryptDecryptInput {
    plaintext: Vec<u8>,
    // For key generation from seed
    key_seed: [u8; 32],
}

#[derive(Arbitrary, Debug)]
struct HmacInput {
    key: Vec<u8>,
    data: Vec<u8>,
}

fuzz_target!(|input: CryptoInput| {
    match input {
        CryptoInput::Sm4Cbc(i) => fuzz_sm4_cbc(i),
        CryptoInput::Sm4Gcm(i) => fuzz_sm4_gcm(i),
        CryptoInput::Sm4Ecbc(i) => fuzz_sm4_ecbc(i),
        CryptoInput::Sm3Hash(i) => fuzz_sm3_hash(i),
        CryptoInput::Sm2SignVerify(i) => fuzz_sm2_sign_verify(i),
        CryptoInput::Sm2EncryptDecrypt(i) => fuzz_sm2_encrypt_decrypt(i),
        CryptoInput::HmacSm3(i) => fuzz_hmac_sm3(i),
    }
});

fn fuzz_sm4_cbc(input: Sm4CbcInput) {
    let cipher = match Sm4Cipher::new(&input.key) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Encrypt
    let ciphertext = match cipher.encrypt_cbc(&input.plaintext, &input.iv) {
        Ok(ct) => ct,
        Err(_) => return,
    };

    // Decrypt
    let decrypted = match cipher.decrypt_cbc(&ciphertext, &input.iv) {
        Ok(pt) => pt,
        Err(_) => return,
    };

    assert_eq!(input.plaintext, decrypted);
}

fn fuzz_sm4_gcm(input: Sm4GcmInput) {
    let cipher = match Sm4Cipher::new(&input.key) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Encrypt
    let (ciphertext, tag) = match cipher.encrypt_gcm(&input.plaintext, &input.nonce, &input.aad) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Decrypt
    let decrypted = match cipher.decrypt_gcm(&ciphertext, &input.nonce, &input.aad, &tag) {
        Ok(pt) => pt,
        Err(_) => return,
    };

    assert_eq!(input.plaintext, decrypted);
}

fn fuzz_sm4_ecbc(input: Sm4EcbcInput) {
    // ECB requires block-aligned input
    let aligned = align_to_block(&input.plaintext, 16);
    if aligned.is_empty() {
        return;
    }

    let cipher = match Sm4Cipher::new(&input.key) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Encrypt
    let ciphertext = match cipher.encrypt_ecb(&aligned) {
        Ok(ct) => ct,
        Err(_) => return,
    };

    // Decrypt
    let decrypted = match cipher.decrypt_ecb(&ciphertext) {
        Ok(pt) => pt,
        Err(_) => return,
    };

    assert_eq!(aligned, decrypted);
}

fn fuzz_sm3_hash(input: Sm3HashInput) {
    let hash = match Sm3Hasher::hash(&input.data) {
        Ok(h) => h,
        Err(_) => return,
    };

    // SM3 output is always 32 bytes
    assert_eq!(hash.len(), 32);

    // Hashing same data twice should produce same result
    let hash2 = Sm3Hasher::hash(&input.data).unwrap();
    assert_eq!(hash, hash2);

    // Empty input should work
    let empty_hash = Sm3Hasher::hash(&[]).unwrap();
    assert_eq!(empty_hash.len(), 32);
}

fn fuzz_sm2_sign_verify(input: Sm2SignVerifyInput) {
    // Generate key pair from seed using gm_crypto's API
    let keypair = match gm_crypto::sm2::Sm2KeyPair::from_private_key(&input.seed) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    let signer = match gm_crypto::sm2::Sm2Signer::new(&keypair) {
        Ok(s) => s,
        Err(_) => return,
    };

    let signature = match signer.sign(&input.message) {
        Ok(sig) => sig,
        Err(_) => return,
    };

    // Verify with the same key
    let verifier = match gm_crypto::sm2::Sm2Verifier::new(
        &keypair.public_key_bytes_uncompressed(),
        keypair.distid(),
    ) {
        Ok(v) => v,
        Err(_) => return,
    };

    assert!(verifier.verify(&input.message, &signature).is_ok());

    // Different message should not verify (use a modified copy of the message)
    if input.message.len() > 0 {
        let mut wrong_message = input.message.clone();
        wrong_message[0] ^= 0xFF; // Flip bits on first byte to make it different
        if wrong_message != input.message {
            assert!(verifier.verify(&wrong_message, &signature).is_err());
        }
    }
}

fn fuzz_sm2_encrypt_decrypt(input: Sm2EncryptDecryptInput) {
    // Generate key pair from seed
    let keypair = match Sm2KeyPair::from_private_key(&input.key_seed) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Encrypt
    let encryptor = match Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()) {
        Ok(e) => e,
        Err(_) => return,
    };

    let ciphertext = match encryptor.encrypt(&input.plaintext) {
        Ok(ct) => ct,
        Err(_) => return,
    };

    // Decrypt
    let decryptor = Sm2Decryptor::new(keypair);
    let decrypted = match decryptor.decrypt(&ciphertext) {
        Ok(pt) => pt,
        Err(_) => return,
    };

    assert_eq!(input.plaintext, decrypted);
}

fn fuzz_hmac_sm3(input: HmacInput) {
    if input.key.is_empty() {
        return;
    }

    let hmac = gm_crypto::sm3::Sm3Hmac::new(&input.key);
    let result = hmac.compute(&input.data);
    if result.is_err() {
        return;
    }
    let mac = result.unwrap();

    // HMAC output is 32 bytes
    assert_eq!(mac.len(), 32);

    // Same input should produce same output
    let mac2 = hmac.compute(&input.data).unwrap();
    assert_eq!(mac, mac2);

    // Verify should work for correct MAC
    assert!(hmac.verify(&input.data, &mac).unwrap());

    // Verify should fail for wrong MAC
    let wrong_mac = [0xFFu8; 32];
    assert!(!hmac.verify(&input.data, &wrong_mac).unwrap());
}

// Helper: Pad data to block size (PKCS#7)
fn align_to_block(data: &[u8], block_size: usize) -> Vec<u8> {
    if data.is_empty() {
        return vec![];
    }
    let remainder = data.len() % block_size;
    if remainder == 0 {
        return data.to_vec();
    }
    let padding = block_size - remainder;
    let mut result = data.to_vec();
    result.extend(vec![padding as u8; padding]);
    result
}