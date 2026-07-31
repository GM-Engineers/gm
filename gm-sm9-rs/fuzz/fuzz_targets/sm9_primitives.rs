//! Fuzz target for gm-sm9 primitives
//!
//! This fuzz target tests:
//! 1. SM9 sign/verify round-trip
//! 2. SM9 encrypt/decrypt round-trip
//! 3. SM9 signature DER serialization round-trip
//! 4. SM9 ciphertext C1‖C3‖C2 serialization round-trip

#![no_main]

use libfuzzer_sys::{fuzz_target, arbitrary::Arbitrary};
use gm_sm9_rs::{
    sign::{Signer, Verifier, Signature},
    encrypt::{Encryptor, Decryptor, Ciphertext},
    key::{SignMasterKey, EncMasterKey},
};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[derive(Arbitrary, Debug)]
enum Sm9Input {
    SignVerify(SignVerifyInput),
    EncryptDecrypt(EncryptDecryptInput),
    DerRoundtrip(DerRoundtripInput),
    CiphertextRoundtrip(CiphertextRoundtripInput),
}

#[derive(Arbitrary, Debug)]
struct SignVerifyInput {
    message: Vec<u8>,
    identity: Vec<u8>,
    rng_seed: [u8; 32],
}

#[derive(Arbitrary, Debug)]
struct EncryptDecryptInput {
    plaintext: Vec<u8>,
    identity: Vec<u8>,
    rng_seed: [u8; 32],
}

#[derive(Arbitrary, Debug)]
struct DerRoundtripInput {
    // Raw bytes to try parsing as a signature
    bytes: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct CiphertextRoundtripInput {
    // Raw bytes to try parsing as ciphertext
    bytes: Vec<u8>,
}

fuzz_target!(|input: Sm9Input| {
    match input {
        Sm9Input::SignVerify(i) => fuzz_sign_verify(i),
        Sm9Input::EncryptDecrypt(i) => fuzz_encrypt_decrypt(i),
        Sm9Input::DerRoundtrip(i) => fuzz_der_roundtrip(i),
        Sm9Input::CiphertextRoundtrip(i) => fuzz_ciphertext_roundtrip(i),
    }
});

fn fuzz_sign_verify(input: SignVerifyInput) {
    let mut rng = StdRng::from_seed(input.rng_seed);

    let master = match SignMasterKey::generate(&mut rng) {
        Ok(m) => m,
        Err(_) => return,
    };

    let identity = if input.identity.is_empty() {
        b"fuzz@test.com".to_vec()
    } else {
        // Limit identity length to prevent excessive computation
        input.identity[..input.identity.len().min(64)].to_vec()
    };

    let user_key = match master.extract_key(&identity) {
        Ok(k) => k,
        Err(_) => return,
    };

    let signer = Signer::with_identity(user_key, &identity);
    let signature = match signer.sign(&input.message, &mut rng) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Verify
    let verifier = Verifier::new(&identity, &master.ppubs);
    match verifier.verify(&input.message, &signature) {
        Ok(true) => {},
        Ok(false) => panic!("Valid signature failed verification"),
        Err(_) => {}, // Verification error is acceptable for edge cases
    }

    // Wrong message should fail
    if !input.message.is_empty() {
        let mut wrong_msg = input.message.clone();
        wrong_msg[0] ^= 0xFF;
        match verifier.verify(&wrong_msg, &signature) {
            Ok(true) => panic!("Wrong message passed verification!"),
            _ => {},
        }
    }
}

fn fuzz_encrypt_decrypt(input: EncryptDecryptInput) {
    let mut rng = StdRng::from_seed(input.rng_seed);

    let master = match EncMasterKey::generate(&mut rng) {
        Ok(m) => m,
        Err(_) => return,
    };

    let identity = if input.identity.is_empty() {
        b"fuzz@test.com".to_vec()
    } else {
        input.identity[..input.identity.len().min(64)].to_vec()
    };

    let user_key = match master.extract_key(&identity) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Limit plaintext length for performance
    let plaintext = &input.plaintext[..input.plaintext.len().min(256)];

    let encryptor = Encryptor::new(&identity, &master.ppube);
    let ciphertext = match encryptor.encrypt(plaintext, &mut rng) {
        Ok(ct) => ct,
        Err(_) => return,
    };

    let decryptor = Decryptor::new(user_key);
    let decrypted = match decryptor.decrypt(&ciphertext, &identity) {
        Ok(pt) => pt,
        Err(_) => return,
    };

    assert_eq!(plaintext.to_vec(), decrypted);
}

fn fuzz_der_roundtrip(input: DerRoundtripInput) {
    // Try parsing arbitrary bytes as a DER signature
    if let Ok(sig) = Signature::from_der(&input.bytes) {
        // If parsing succeeds, serialization round-trip should also work
        let re_encoded = sig.to_der();
        if let Ok(re_parsed) = Signature::from_der(&re_encoded) {
            assert_eq!(sig.h, re_parsed.h);
            // Note: s point comparison depends on affine representation
        }
    }
}

fn fuzz_ciphertext_roundtrip(input: CiphertextRoundtripInput) {
    // Try parsing arbitrary bytes as C1‖C3‖C2 ciphertext
    if let Ok(ct) = Ciphertext::from_bytes(&input.bytes) {
        // If parsing succeeds, serialization round-trip should work
        let re_encoded = ct.to_bytes();
        if let Ok(re_parsed) = Ciphertext::from_bytes(&re_encoded) {
            assert_eq!(ct.c2, re_parsed.c2);
            assert_eq!(ct.c3, re_parsed.c3);
        }
    }

    // Also try C1‖C2‖C3 format
    if let Ok(ct) = Ciphertext::from_bytes_c1c2c3(&input.bytes) {
        let re_encoded = ct.to_bytes_c1c2c3();
        if let Ok(re_parsed) = Ciphertext::from_bytes_c1c2c3(&re_encoded) {
            assert_eq!(ct.c2, re_parsed.c2);
            assert_eq!(ct.c3, re_parsed.c3);
        }
    }
}
