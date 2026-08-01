# gm-sm9-rs: SM9 Identity-Based Cryptography (Chinese national standard GM/T 0044-2016)

## Features

This module implements the SM9 identity-based cryptographic algorithm defined in GM/T 0044-2016, including:

- **Pure Rust implementation** (default): uses the standard SM9 curve parameters and SM3 hash
- **GmSSL FFI backend**: calls the GmSSL 3.1.1 implementation

## Architecture

```
gm-sm9-rs/
├── src/
│   ├── lib.rs           # Library entry
│   ├── params.rs        # SM9 standard curve parameters (GM/T 0044-2016)
│   ├── z256/            # 256-bit integer arithmetic
│   ├── field/           # Finite fields (Fp, Fp2, Fp4, Fp12)
│   ├── curve/           # Elliptic curve points (G1, G2)
│   ├── pairing/         # Bilinear pairing (R-ate)
│   ├── hash/            # SM3 Hash1/Hash2
│   ├── key/             # Key generation and extraction
│   ├── sign.rs          # Signature algorithm
│   ├── encrypt.rs       # Encryption algorithm
│   ├── ffi.rs           # GmSSL FFI bindings
│   └── gmssl_backend.rs # GmSSL backend implementation
├── tests/
│   └── cross_validation.rs  # Cross-validation tests
├── Cargo.toml
└── README.md
```

## Dependencies

- `sm3` - SM3 national hash algorithm
- `subtle` - constant-time operations
- `zeroize` - secure memory wiping
- `rand` - random number generation
- `libc` - GmSSL FFI (gmssl feature)

## API Usage

```rust
use gm_sm9_rs::{Signer, Verifier, Encryptor, Decryptor, SignMasterKey, EncMasterKey};
use rand::thread_rng;

// Generate the signing master key
let sign_master = SignMasterKey::generate(&mut thread_rng())?;

// Derive a user signing key
let sign_key = sign_master.extract_key(b"user@example.com")?;

// Sign
let signer = Signer::new(sign_key);
let signature = signer.sign(b"message", &mut thread_rng())?;

// Verify
let verifier = Verifier::new(b"user@example.com", &sign_master.ppubs);
assert!(verifier.verify(b"message", &signature).unwrap());

// Encrypt
let enc_master = EncMasterKey::generate(&mut thread_rng())?;
let encryptor = Encryptor::new(b"recipient@example.com", &enc_master.ppube);
let ciphertext = encryptor.encrypt(b"secret message", &mut thread_rng())?;

// Decrypt
let dec_key = enc_master.extract_key(b"recipient@example.com")?;
let decryptor = Decryptor::new(dec_key);
let plaintext = decryptor.decrypt(&ciphertext, b"recipient@example.com")?;
```

## Cross-Validation

Cross-validation is performed between the GmSSL backend and the pure Rust backend:

```bash
# Pure Rust backend
cargo test --no-default-features --test cross_validation

# GmSSL backend (requires GmSSL 3.1.1)
cargo test --features gmssl --test cross_validation
```

All 17 cross-validation tests pass:
- GmSSL signs → pure Rust verifies
- Pure Rust signs → GmSSL verifies
- Pairing computation consistency
- Key derivation consistency
