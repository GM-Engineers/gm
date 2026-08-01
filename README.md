# Chinese National Cryptography (GM) Algorithms & GM/TLS (TLCP)

Pure Rust implementation of Chinese national cryptography (GM/T) algorithms and the GM/TLS (TLCP) protocol stack, with full SM2/SM3/SM4 support.

**[中文版](./README.zh-CN.md)**

## Documentation

| Document | Contents |
|----------|----------|
| [Getting Started](./docs/getting-started.md) | Prerequisites, adding dependencies, first working example |
| [gm-crypto Guide](./docs/gm-crypto.md) | Complete API reference for SM2/SM3/SM4 |
| [gm-tls Guide](./docs/gm-tls.md) | GM/TLS client/server development, session stores |
| [gm-ca Guide](./docs/gm-ca.md) | CA service deployment, gRPC API usage |
| [gm-http-client Guide](./docs/gm-http-client.md) | HTTPS client, connection pooling, SSRF protection |
| [Certificate Guide](./docs/certificate-howto.md) | Certificate generation, format, OpenSSL/GmSSL integration |
| [Deployment Guide](./docs/deployment.md) | docker-compose production deployment, operations |

## Overview

```
gm/                          # Workspace root
├── gm-crypto/               # Cryptographic primitives (SM2/SM3/SM4)
├── gm-tls/                  # GM/TLS protocol implementation
├── gm-ca/                   # gRPC CA service (issue/revoke/query)
├── gm-sm9-rs/                  # SM9 identity-based cryptography (sign/encrypt)
├── gm-der/                  # DER/ASN.1 encoding/decoding (shared utility)
├── gm-http-client/          # HTTPS client
├── docs/                    # Detailed usage guides (this directory)
└── docker/                  # Docker deployment configuration
```

## Crate Overview

| Crate | Type | Description |
|-------|------|-------------|
| `gm-crypto` | Library | Cryptographic primitives, no binaries |
| `gm-tls` | Library | GM/TLS protocol; optional `grpc` feature for gRPC over GM/TLS |
| `gm-ca` | Library + Service | Provides `gm-ca-server` binary, gRPC interface |
| `gm-sm9-rs` | Library | SM9 identity-based sign/encrypt; dual backend (pure Rust + GmSSL FFI) |
| `gm-der` | Library | Shared DER/ASN.1 encoding/decoding utilities |
| `gm-http-client` | Library | HTTPS client based on gm-tls |

## Quick Example

```toml
[dependencies]
gm-crypto = "0.1"
gm-sm9-rs = "0.1"
```

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer};
use gm_crypto::sm3::Sm3Hasher;
use gm_crypto::sm4::Sm4Cipher;
use gm_sm9_rs::{SignMasterKey, Signer, Verifier, EncMasterKey, Encryptor, Decryptor};

// SM2/SM3/SM4 (SM2 includes key exchange)
let key_pair = Sm2KeyPair::generate().unwrap();
let signer = Sm2Signer::new(&key_pair).unwrap();
let sig = signer.sign(b"Hello, GM!").unwrap();

let hash = Sm3Hasher::hash(b"data").unwrap();

let cipher = Sm4Cipher::new(b"0123456789abcdef").unwrap();
let (ct, tag) = cipher.encrypt_gcm(b"secret", b"0123456789ab", b"").unwrap();

// SM9 identity-based signature
let mut rng = rand::thread_rng();
let master = SignMasterKey::generate(&mut rng)?;
let user_key = master.extract_key(b"alice@example.com")?;
let signer = Signer::new(user_key);
let sig = signer.sign(b"message")?;
let verifier = Verifier::new(b"alice@example.com", &master.ppubs);
assert!(verifier.verify(b"message", &sig)?);
```

## Third-Party Components

This project wraps existing community implementations and ports external code:

- **SM2 / SM3 / SM4** (`gm-crypto`) are thin wrappers around the community Rust crates [`sm2`](https://crates.io/crates/sm2), [`sm3`](https://crates.io/crates/sm3), and [`sm4`](https://crates.io/crates/sm4) — not independent reimplementations.
- **SM9** (`gm-sm9-rs`) is a Rust port derived from [GmSSL](https://github.com/guanzhi/GmSSL) (Apache-2.0). See [NOTICE](./NOTICE) for attribution and license details.

## License

MIT OR Apache-2.0 — See [LICENSE](./LICENSE)

> To report security vulnerabilities, see [SECURITY.md](./SECURITY.md)
