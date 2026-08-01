//! Fuzz target for key exchange and session key derivation
//!
//! This fuzz target tests:
//! 1. Real ECDH key exchange with valid SM2 curve points
//! 2. Session key derivation from ECDH shared secrets
//! 3. Ephemeral key generation uniqueness

#![no_main]
// `Scalar::from_bytes` requires `&GenericArray<u8, U32>` from the pinned
// `generic-array` 0.14 / `sm2` 0.13 stack; both crates are deprecated upstream
// in favour of `generic-array` 1.x. Silence until the dependency is upgraded.
#![allow(deprecated)]

use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use gm_tls::gm::{derive_session_keys_sm2, generate_sm2_ephemeral};
use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};
use sm2::EncodedPoint;
use sm2::ProjectivePoint;
use sm2::Scalar;

#[derive(Arbitrary, Debug)]
enum KeyExchangeInput {
    // Test 1: Real ECDH key exchange with valid SM2 curve points
    KeyExchange(KeyExchangeFuzzInput),
    // Test 2: Ephemeral key generation uniqueness
    KeyGen(KeyGenInput),
    // Test 3: Scalar uniqueness (different scalars -> different points)
    Uniqueness(UniquenessInput),
}

#[derive(Arbitrary, Debug)]
#[allow(dead_code)] // fuzz-only fields kept for input diversity
struct KeyExchangeFuzzInput {
    client_random: [u8; 32],
    server_random: [u8; 32],
    client_eph_pubkey: Vec<u8>,
    server_eph_pubkey: Vec<u8>,
    client_scalar: [u8; 32],
    server_scalar: [u8; 32],
}

#[derive(Arbitrary, Debug)]
struct KeyGenInput {
    count: usize,
}

#[derive(Arbitrary, Debug)]
struct UniquenessInput {
    scalar1: [u8; 32],
    scalar2: [u8; 32],
}

fuzz_target!(|input: KeyExchangeInput| {
    match input {
        KeyExchangeInput::KeyExchange(kex) => fuzz_key_exchange(kex),
        KeyExchangeInput::KeyGen(kg) => fuzz_key_gen(kg),
        KeyExchangeInput::Uniqueness(u) => fuzz_uniqueness(u),
    }
});

fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    use generic_array::GenericArray;
    let ct_option = Scalar::from_bytes(GenericArray::from_slice(bytes));
    if ct_option.is_some().into() {
        Some(ct_option.unwrap())
    } else {
        None
    }
}

fn fuzz_key_exchange(input: KeyExchangeFuzzInput) {
    // Parse client public key
    let client_enc = match EncodedPoint::from_bytes(&input.client_eph_pubkey) {
        Ok(enc) => enc,
        Err(_) => return,
    };
    let client_point = match ProjectivePoint::from_encoded_point(&client_enc).into_option() {
        Some(pt) => pt,
        None => return,
    };

    // Parse server public key
    let server_enc = match EncodedPoint::from_bytes(&input.server_eph_pubkey) {
        Ok(enc) => enc,
        Err(_) => return,
    };
    let server_point = match ProjectivePoint::from_encoded_point(&server_enc).into_option() {
        Some(pt) => pt,
        None => return,
    };

    let client_sk = match scalar_from_bytes(&input.client_scalar) {
        Some(s) => s,
        None => return,
    };
    let server_sk = match scalar_from_bytes(&input.server_scalar) {
        Some(s) => s,
        None => return,
    };

    // Real ECDH: client computes shared = server_pubkey * client_sk
    // Real ECDH: server computes shared = client_pubkey * server_sk
    let shared_client = server_point * client_sk;
    let shared_server = client_point * server_sk;

    // Verify commutativity
    let client_enc_result = shared_client.to_affine().to_encoded_point(false);
    let server_enc_result = shared_server.to_affine().to_encoded_point(false);
    assert_eq!(client_enc_result.as_bytes(), server_enc_result.as_bytes());

    // Derive session keys from the real shared secret
    let result = derive_session_keys_sm2(&shared_client);
    if let Ok(secrets) = result {
        assert_eq!(secrets.session_keys.client_key.len(), 16);
        assert_eq!(secrets.session_keys.server_key.len(), 16);
        assert_eq!(secrets.master_secret.len(), 32);
    }
}

fn fuzz_key_gen(input: KeyGenInput) {
    let count = input.count.min(100);

    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(count);
    for _ in 0..count {
        if let Ok((_, pk)) = generate_sm2_ephemeral() {
            keys.push(pk);
        }
    }

    for (i, key1) in keys.iter().enumerate() {
        for key2 in keys.iter().skip(i + 1) {
            assert_ne!(key1.as_slice(), key2.as_slice());
        }
    }
}

fn fuzz_uniqueness(input: UniquenessInput) {
    let scalar1 = match scalar_from_bytes(&input.scalar1) {
        Some(s) => s,
        None => return,
    };
    let scalar2 = match scalar_from_bytes(&input.scalar2) {
        Some(s) => s,
        None => return,
    };

    if scalar1 == scalar2 {
        return;
    }

    let generator = ProjectivePoint::GENERATOR;
    let shared1 = generator * scalar1;
    let shared2 = generator * scalar2;

    let enc1 = shared1.to_affine().to_encoded_point(false);
    let enc2 = shared2.to_affine().to_encoded_point(false);

    assert_ne!(enc1.as_bytes(), enc2.as_bytes());
}
