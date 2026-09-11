# GM (国密) Cryptographic Algorithms & Protocol Stacks

Pure Rust implementation of Chinese national cryptography (GM/T) algorithms, the TLS 1.3 + SM stack, and the TLCP (GB/T 38636-2020) protocol, with full SM2/SM3/SM4 support.

**[中文版](./README.zh-CN.md)**

## Documentation

| Document | Contents |
|----------|----------|
| [Getting Started](./docs/getting-started.en.md) | Prerequisites, adding dependencies, first working example |
| [gm-crypto Guide](./docs/gm-crypto.en.md) | Complete API reference for SM2/SM3/SM4 |
| [gm-tls Guide](./docs/gm-tls.en.md) | TLS 1.3 + SM client/server development, session stores |
| [gm-tlcp Guide](./docs/gm-tlcp.en.md) | TLCP (GB/T 38636-2020) protocol, dual-certificate PKI, GmSSL interop |
| [gm-ca Guide](./docs/gm-ca.en.md) | CA service deployment, gRPC API usage |
| [gm-http-client Guide](./docs/gm-http-client.en.md) | HTTPS client, connection pooling, SSRF protection |
| [Certificate Guide](./docs/certificate-howto.en.md) | Certificate generation, format, OpenSSL/GmSSL integration |
| [Deployment Guide](./docs/deployment.en.md) | docker-compose production deployment, operations |

## Overview

```
gm/                          # Workspace root
├── gm-crypto/               # Cryptographic primitives (SM2/SM3/SM4)
├── gm-tls/                  # TLS 1.3 + SM algorithms (TLCP has moved to gm-tlcp)
├── gm-tlcp/                 # TLCP (GB/T 38636-2020) protocol stack — standalone crate
├── gm-ca/                   # gRPC CA service (issue/revoke/query)
├── gm-sm9-rs/               # SM9 identity-based cryptography (sign/encrypt)
├── gm-der/                  # DER/ASN.1 encoding/decoding (shared utility)
├── gm-http-client/          # HTTPS client
├── docs/                    # Detailed usage guides (this directory)
└── docker/                  # Docker deployment configuration
```

## Crate Overview

| Crate | Type | Description |
|-------|------|-------------|
| `gm-crypto` | Library | Cryptographic primitives (SM2/SM3/SM4), no binaries. v0.2+ |
| `gm-tls` | Library | TLS 1.3 + SM algorithms only. TLCP moved to standalone `gm-tlcp`. Optional `grpc` feature for gRPC over TLS 1.3 + SM |
| `gm-tlcp` | Library | TLCP (GB/T 38636-2020) protocol — standalone, depends on `gm-crypto >= 0.2` |
| `gm-ca` | Library + Service | Provides `gm-ca-server` binary, gRPC interface |
| `gm-sm9-rs` | Library | SM9 identity-based sign/encrypt; dual backend (pure Rust + GmSSL FFI) |
| `gm-der` | Library | Shared DER/ASN.1 encoding/decoding utilities |
| `gm-http-client` | Library | HTTPS client based on gm-tls |

## Quick Example

```toml
[dependencies]
gm-crypto = "0.3"
gm-tlcp   = "0.6"
gm-sm9-rs = "0.1"
```

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer};
use gm_crypto::sm3::Sm3Hasher;
use gm_crypto::sm4::Sm4Cipher;
use gm_sm9_rs::{SignMasterKey, Signer, Verifier};
use gm_tlcp::{TlcpAcceptor, TlcpConnector, TLS_ECDHE_SM4_GCM_SM3};
use rand::rng;

// SM2/SM3/SM4 (SM2 includes key exchange)
let key_pair = Sm2KeyPair::generate().unwrap();
let signer = Sm2Signer::new(&key_pair).unwrap();
let sig = signer.sign(b"Hello, GM!").unwrap();

let hash = Sm3Hasher::hash(b"data").unwrap();

let cipher = Sm4Cipher::new(b"0123456789abcdef").unwrap();
let (ct, tag) = cipher.encrypt_gcm(b"secret", b"0123456789ab", b"").unwrap();

// SM9 identity-based signature (rand 0.10: `thread_rng` was renamed to `rng`)
let mut rng = rand::rng();
let master = SignMasterKey::generate(&mut rng)?;
let user_key = master.extract_key(b"alice@example.com")?;
let signer = Signer::new(user_key);
let sig = signer.sign(b"message", &mut rng)?;
let verifier = Verifier::new(b"alice@example.com", &master.ppubs);
assert!(verifier.verify(b"message", &sig)?);

// TLCP handshake (server side — see gm-tlcp docs for the full example)
// `with_dual_certs` takes 4 args: 2 certs (DER) + 2 SM2 key pairs.
// `with_cipher_suites` lives on TlcpConnector (not on TlcpAcceptor).
// let sign_key = Sm2KeyPair::from_private_key_pem(&sign_pem)?;
// let enc_key  = Sm2KeyPair::from_private_key_pem(&enc_pem)?;
// let acceptor = TlcpAcceptor::new()
//     .with_dual_certs(sign_cert_der, enc_cert_der, sign_key, enc_key);
// let connector = TlcpConnector::new()
//     .with_cipher_suites(vec![TLS_ECDHE_SM4_GCM_SM3]);
```

## Third-Party Components

This project wraps community implementations and ports external code where
appropriate, but also includes substantial original code:

- **SM2** (`gm-crypto/src/sm2.rs`) wraps the community crate
  [`sm2`](https://crates.io/crates/sm2) and adds a higher-level
  `Sm2Signer` / `Sm2Verifier` / `Sm2Encryptor` API on top.
- **SM3** (`gm-crypto/src/sm3.rs`) wraps [`sm3`](https://crates.io/crates/sm3).
- **SM4** (`gm-crypto/src/sm4.rs`) wraps [`sm4`](https://crates.io/crates/sm4)
  **and** adds hand-rolled raw-CBC primitives
  (`Sm4Cipher::encrypt_cbc_raw` / `decrypt_cbc_raw`) for MAC-then-Encrypt
  protocols (TLCP, TLS 1.1 CBC) where the protocol layer manages
  padding itself and the standard PKCS#7-padded `encrypt_cbc` would
  corrupt the wire format.
- **X.509 SM2 public-key extraction**
  (`gm-crypto/src/x509.rs::extract_sm2_pubkey_from_der`) is a from-scratch
  implementation, not a wrapper. It exists to work around a quirk in
  GmSSL-emitted SPKI BIT STRINGs that have a non-zero unused-bits
  count; off-the-shelf `x509-parser` doesn't strip those, which
  causes downstream SM2 encryption/verifier constructors to reject the
  key.
- **SM9** (`gm-sm9-rs`) is a Rust port derived from
  [GmSSL](https://github.com/guanzhi/GmSSL) (Apache-2.0). See
  [NOTICE](./NOTICE) for attribution and license details.
- **TLCP** (`gm-tlcp`) is a from-scratch Rust implementation of
  GB/T 38636-2020. The protocol layer is original work; cryptographic
  primitives delegate to `gm-crypto`.

## License

MIT OR Apache-2.0 — See [LICENSE](./LICENSE)

> To report security vulnerabilities, see [SECURITY.md](./SECURITY.md)
