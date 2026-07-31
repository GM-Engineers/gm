# gm-crypto

**GM Cryptography Library** — Pure Rust implementation of SM2/SM3/SM4 cryptographic primitives.

**[中文版](./README.md)**

## Algorithms

| Algorithm | Type | Description |
|-----------|------|-------------|
| SM2 | Asymmetric | Elliptic curve signature and key exchange, based on GF(p) curve |
| SM3 | Hash | National hash algorithm, 256-bit output |
| SM4 | Symmetric | Block cipher, supports ECB/CBC/GCM modes (⚠️ ECB is deprecated, use GCM for new projects) |

## Security Features

- SM4 keys are automatically zeroized on `Drop` (`ZeroizeOnDrop`)
- HMAC verification uses constant-time comparison (prevents timing attacks)
- All random numbers use `OsRng` (OS CSPRNG)

## Quick Start

```toml
[dependencies]
gm-crypto = "0.1"
```

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer};
use gm_crypto::sm3::Sm3Hasher;
use gm_crypto::sm4::Sm4Cipher;

// SM2 signing
let key_pair = Sm2KeyPair::generate().unwrap();  // generate() returns Result
let signer = Sm2Signer::new(&key_pair)?;
let sig = signer.sign(b"message")?;

// SM3 hash
let hash = Sm3Hasher::hash(b"data")?;

// SM4-GCM encryption
let cipher = Sm4Cipher::new(b"0123456789abcdef".as_slice())?;
let (ct, tag) = cipher.encrypt_gcm(b"plaintext", b"0123456789ab", b"")?;
```

## License

MIT OR Apache-2.0 — See [../LICENSE](../LICENSE)
