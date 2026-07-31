//! Performance benchmarks for gm-tls cryptographic operations
//!
//! Run with: cargo bench

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use elliptic_curve::sec1::FromEncodedPoint;
use gm_crypto::sm2::EncodedPoint;
use gm_crypto::sm2::ProjectivePoint;
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier};
use gm_crypto::sm4::{SM4_GCM_NONCE_LENGTH, Sm4Cipher};
use gm_tls::gm::{
    build_client_hello, build_server_hello, derive_session_keys_sm2, generate_sm2_ephemeral,
    select_alpn, sign_finished, verify_finished,
};

const SM2_DEFAULT_ID: &str = "1234567812345678";

fn criterion_benchmark(c: &mut Criterion) {
    // SM2 Key Generation
    c.bench_function("sm2_ephemeral_keygen", |b| {
        b.iter(|| {
            let _ = generate_sm2_ephemeral();
        });
    });

    // SM2 Key Pair Generation
    c.bench_function("sm2_keypair_generate", |b| {
        b.iter(|| {
            let _ = Sm2KeyPair::generate_with_distid(SM2_DEFAULT_ID.to_string());
        });
    });

    // SM2 Signing
    c.bench_function("sm2_sign", |b| {
        let keypair =
            Sm2KeyPair::generate_with_distid(SM2_DEFAULT_ID.to_string()).expect("keygen failed");
        let signer = Sm2Signer::new(&keypair).expect("signer creation failed");
        let data = black_box(b"test data to sign".to_vec());

        b.iter(|| {
            let _ = sign_finished(&signer, &data);
        });
    });

    // SM2 Verification
    c.bench_function("sm2_verify", |b| {
        let keypair =
            Sm2KeyPair::generate_with_distid(SM2_DEFAULT_ID.to_string()).expect("keygen failed");
        let signer = Sm2Signer::new(&keypair).expect("signer creation failed");
        let verifier = Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), SM2_DEFAULT_ID)
            .expect("verifier creation failed");
        let data = b"test data to sign".to_vec();
        let signature = sign_finished(&signer, &data).expect("sign failed");

        b.iter(|| {
            let _ = verify_finished(&verifier, &data, &signature);
        });
    });

    // KDF (Key Derivation Function)
    c.bench_function("kdf_derive_session_keys", |b| {
        let (sk, pk) = generate_sm2_ephemeral().expect("keygen failed");
        let point = ProjectivePoint::from_encoded_point(&EncodedPoint::from_bytes(&pk).unwrap())
            .into_option()
            .unwrap();
        let shared = point * sk;

        b.iter(|| {
            let _ = derive_session_keys_sm2(&shared);
        });
    });

    // SM4-GCM Encryption
    c.bench_function("sm4_gcm_encrypt", |b| {
        let key = vec![0x42u8; 16];
        let nonce = [0x00u8; SM4_GCM_NONCE_LENGTH];
        let cipher = Sm4Cipher::new(&key).expect("cipher creation failed");
        let plaintext = black_box(b"Hello, GM/TLS!".to_vec());

        b.iter(|| {
            let _ = cipher.encrypt_gcm(&plaintext, &nonce, b"seq0");
        });
    });

    // SM4-GCM Decryption
    c.bench_function("sm4_gcm_decrypt", |b| {
        let key = vec![0x42u8; 16];
        let nonce = [0x00u8; SM4_GCM_NONCE_LENGTH];
        let cipher = Sm4Cipher::new(&key).expect("cipher creation failed");
        let plaintext = b"Hello, GM/TLS!".to_vec();
        let (ciphertext, tag) = cipher
            .encrypt_gcm(&plaintext, &nonce, b"seq0")
            .expect("encrypt failed");

        b.iter(|| {
            let _ = cipher.decrypt_gcm(&ciphertext, &nonce, b"seq0", &tag);
        });
    });

    // Client Hello Build
    c.bench_function("build_client_hello", |b| {
        let alpn = vec!["http/1.1".to_string()];
        let sni = Some("example.com");

        b.iter(|| {
            let _ = build_client_hello(black_box(&alpn), sni);
        });
    });

    // Server Hello Build
    c.bench_function("build_server_hello", |b| {
        let alpn = Some("http/1.1");
        let cert_pem = b"cert_pem_data";
        let require_client_auth = false;

        b.iter(|| {
            let _ = build_server_hello(black_box(alpn), cert_pem, require_client_auth);
        });
    });

    // ALPN Selection
    c.bench_function("select_alpn", |b| {
        let server = vec!["http/1.1".to_string(), "h2".to_string()];
        let client = vec!["h2".to_string(), "http/1.1".to_string()];

        b.iter(|| {
            let _ = select_alpn(black_box(&server), &client);
        });
    });

    // Session Keys Clone
    c.bench_function("session_keys_clone", |b| {
        use gm_tls::gm::SessionKeys;
        let keys = SessionKeys {
            client_key: vec![0x42u8; 16],
            client_nonce: [0x00u8; SM4_GCM_NONCE_LENGTH],
            server_key: vec![0x43u8; 16],
            server_nonce: [0x01u8; SM4_GCM_NONCE_LENGTH],
        };

        b.iter(|| {
            let _ = keys.clone();
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = criterion_benchmark
);
criterion_main!(benches);
