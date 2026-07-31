//! Criterion benchmarks for gm-crypto cryptographic operations.
//!
//! Run with: `cargo bench -p gm-crypto`
//! Open report: `open target/criterion/report/index.html`

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gm_crypto::sm2::{Sm2Decryptor, Sm2Encryptor, Sm2KeyPair, Sm2Signer, Sm2Verifier};
use gm_crypto::sm3::Sm3Hasher;
use gm_crypto::sm4::Sm4Cipher;

// ============================================================================
// SM2 benchmarks
// ============================================================================

fn bench_sm2_key_generation(c: &mut Criterion) {
    c.bench_function("sm2_key_generation", |b| {
        b.iter(|| {
            Sm2KeyPair::generate().unwrap();
        });
    });
}

fn bench_sm2_sign(c: &mut Criterion) {
    let keypair = Sm2KeyPair::generate().unwrap();
    let signer = Sm2Signer::new(&keypair).unwrap();
    let message = [0x42u8; 256];

    c.bench_function("sm2_sign_256b", |b| {
        b.iter(|| {
            signer.sign(black_box(&message)).unwrap();
        });
    });
}

fn bench_sm2_verify(c: &mut Criterion) {
    let keypair = Sm2KeyPair::generate().unwrap();
    let signer = Sm2Signer::new(&keypair).unwrap();
    let message = [0x42u8; 256];
    let signature = signer.sign(&message).unwrap();
    let verifier =
        Sm2Verifier::new(&keypair.public_key_bytes_uncompressed(), "1234567812345678").unwrap();

    c.bench_function("sm2_verify_256b", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(&message), black_box(&signature))
                .unwrap();
        });
    });
}

fn bench_sm2_encrypt(c: &mut Criterion) {
    let keypair = Sm2KeyPair::generate().unwrap();
    let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
    let plaintext = vec![0xAAu8; 1024];

    c.bench_function("sm2_encrypt_1k", |b| {
        b.iter(|| {
            encryptor.encrypt(black_box(&plaintext)).unwrap();
        });
    });
}

fn bench_sm2_decrypt(c: &mut Criterion) {
    let keypair = Sm2KeyPair::generate().unwrap();
    let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
    let decryptor = Sm2Decryptor::new(keypair);
    let plaintext = vec![0xBBu8; 1024];
    let ciphertext = encryptor.encrypt(&plaintext).unwrap();

    c.bench_function("sm2_decrypt_1k", |b| {
        b.iter(|| {
            decryptor.decrypt(black_box(&ciphertext)).unwrap();
        });
    });
}

// ============================================================================
// SM3 benchmarks
// ============================================================================

fn bench_sm3_hash_small(c: &mut Criterion) {
    let data = [0x42u8; 64];

    c.bench_function("sm3_hash_64b", |b| {
        b.iter(|| {
            Sm3Hasher::hash(black_box(&data)).unwrap();
        });
    });
}

fn bench_sm3_hash_large(c: &mut Criterion) {
    let data = vec![0x42u8; 65536]; // 64 KiB

    c.bench_function("sm3_hash_64k", |b| {
        b.iter(|| {
            Sm3Hasher::hash(black_box(&data)).unwrap();
        });
    });
}

// ============================================================================
// SM4-GCM benchmarks
// ============================================================================

fn bench_sm4_gcm_encrypt_1k(c: &mut Criterion) {
    let key = [0x77u8; 16];
    let nonce = [0x01u8; 12];
    let plaintext = vec![0xAAu8; 1024];
    let cipher = Sm4Cipher::new(&key).unwrap();

    c.bench_function("sm4_gcm_encrypt_1k", |b| {
        b.iter(|| {
            cipher
                .encrypt_gcm(black_box(&plaintext), black_box(&nonce), black_box(&[]))
                .unwrap();
        });
    });
}

fn bench_sm4_gcm_decrypt_1k(c: &mut Criterion) {
    let key = [0x77u8; 16];
    let nonce = [0x01u8; 12];
    let plaintext = vec![0xAAu8; 1024];
    let cipher = Sm4Cipher::new(&key).unwrap();
    let (ct, tag) = cipher.encrypt_gcm(&plaintext, &nonce, &[]).unwrap();

    c.bench_function("sm4_gcm_decrypt_1k", |b| {
        b.iter(|| {
            cipher
                .decrypt_gcm(
                    black_box(&ct),
                    black_box(&nonce),
                    black_box(&[]),
                    black_box(&tag),
                )
                .unwrap();
        });
    });
}

fn bench_sm4_gcm_encrypt_64k(c: &mut Criterion) {
    let key = [0x77u8; 16];
    let nonce = [0x01u8; 12];
    let plaintext = vec![0xAAu8; 65536];
    let cipher = Sm4Cipher::new(&key).unwrap();

    c.bench_function("sm4_gcm_encrypt_64k", |b| {
        b.iter(|| {
            cipher
                .encrypt_gcm(black_box(&plaintext), black_box(&nonce), black_box(&[]))
                .unwrap();
        });
    });
}

fn bench_sm4_gcm_decrypt_64k(c: &mut Criterion) {
    let key = [0x77u8; 16];
    let nonce = [0x01u8; 12];
    let plaintext = vec![0xAAu8; 65536];
    let cipher = Sm4Cipher::new(&key).unwrap();
    let (ct, tag) = cipher.encrypt_gcm(&plaintext, &nonce, &[]).unwrap();

    c.bench_function("sm4_gcm_decrypt_64k", |b| {
        b.iter(|| {
            cipher
                .decrypt_gcm(
                    black_box(&ct),
                    black_box(&nonce),
                    black_box(&[]),
                    black_box(&tag),
                )
                .unwrap();
        });
    });
}

criterion_group!(
    sm2_benches,
    bench_sm2_key_generation,
    bench_sm2_sign,
    bench_sm2_verify,
    bench_sm2_encrypt,
    bench_sm2_decrypt,
);
criterion_group!(sm3_benches, bench_sm3_hash_small, bench_sm3_hash_large,);
criterion_group!(
    sm4_benches,
    bench_sm4_gcm_encrypt_1k,
    bench_sm4_gcm_decrypt_1k,
    bench_sm4_gcm_encrypt_64k,
    bench_sm4_gcm_decrypt_64k,
);
criterion_main!(sm2_benches, sm3_benches, sm4_benches);
