# gm-tlcp Guide

`gm-tlcp` is the standalone Rust implementation of **TLCP (Transport Layer Cryptographic Protocol, GB/T 38636-2020)**, the Chinese national standard for cryptographic transport-layer security.

This page is a quick-start. Full rustdoc with every API is on [docs.rs/gm-tlcp](https://docs.rs/gm-tlcp).

## What is TLCP?

TLCP is structurally similar to TLS 1.3 but **not interoperable with it**:

- Uses **SM2** (signature + encryption + key exchange), **SM3** (hash), **SM4** (block cipher)
- Requires **dual certificates** (sign cert + enc cert) per peer, unlike TLS 1.3's single-cert model
- Protocol version byte is `[0x01, 0x01]` (TLCP), not `[0x03, 0x03]` (TLS 1.3)
- Defines 4 cipher suites:

| ID | Name | Notes |
|----|------|-------|
| `0xE051` | `TLS_ECDHE_SM4_GCM_SM3` | ECDHE + SM4-GCM + SM3 — **preferred** |
| `0xE011` | `TLS_ECDHE_SM4_CBC_SM3` | ECDHE + SM4-CBC + HMAC-SM3 |
| `0xE053` | `TLS_ECC_SM4_GCM_SM3`  | Static key + SM4-GCM + SM3 — no ECDHE |
| `0xE013` | `TLS_ECC_SM4_CBC_SM3`  | Static key + SM4-CBC + HMAC-SM3 — no ECDHE |

## Relationship with `gm-tls`

`gm-tls` is a **separate crate** that implements **TLS 1.3 with SM algorithms**. The TLCP support that used to live inside `gm-tls` was extracted into the standalone `gm-tlcp` crate (commit `28fbca1`) so the two protocol stacks can evolve independently. Pick the crate based on the protocol your peer speaks:

- **Peer speaks TLS 1.3** (with or without SM cipher suites) → use `gm-tls`
- **Peer speaks TLCP** (GB/T 38636-2020) → use `gm-tlcp`

## Quick Example

Add to `Cargo.toml`:

```toml
[dependencies]
gm-crypto = "0.2"
gm-tlcp = "0.1"
tokio = { version = "1", features = ["full"] }
```

### Server (TLCP acceptor)

```rust
use gm_tlcp::{TlcpAcceptor, TlcpCipherSuite, TlcpKeyMaterial};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sign_cert = std::fs::read("server-sign.crt")?;     // DER, signing cert
    let enc_cert  = std::fs::read("server-enc.crt")?;      // DER, encryption cert
    let sign_key  = std::fs::read("server-sign.key.pem")?; // SEC1 PEM
    let sign_pub_65 = /* 65-byte uncompressed SM2 SEC1 pubkey */;

    let acceptor = TlcpAcceptor::new()
        .with_dual_certs(sign_cert, enc_cert, sign_pub_65)
        .with_server_sign_key(sign_key, None)
        .with_cipher_suites(vec![TlcpCipherSuite::TLS_ECDHE_SM4_GCM_SM3]);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8443").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(mut tlcp) = acceptor.accept(stream).await {
                tlcp.write_all(b"HTTP/1.1 200 OK\r\n\r\nHello TLCP!").await.ok();
            }
        });
    }
}
```

### Client (TLCP connector)

```rust
use gm_tlcp::{TlcpConnector, TlcpCipherSuite};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_sign_pub_65 = /* 65-byte uncompressed SM2 SEC1 pubkey from server */;

    let connector = TlcpConnector::new()
        .with_server_sign_key(server_sign_pub_65.to_vec(), b"1234567812345678".to_vec());

    let stream = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
    let mut tlcp = connector.connect(stream).await?;

    tlcp.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
    let mut buf = vec![0u8; 4096];
    let n = tlcp.read(&mut buf).await?;
    println!("{}", String::from_utf8_lossy(&buf[..n]));
    Ok(())
}
```

## Dual Certificate PKI

TLCP requires **two separate SM2 certificates per peer**:

1. **Signing certificate** — used for `CertificateVerify` and ServerKeyExchange signatures. Public key is shared with the peer for signature verification.
2. **Encryption certificate** — used for SM2 ECDH key agreement. Private key is needed locally; public key is shared with the peer.

Both certificates must chain to a trusted CA, and both must be SM2 (1.2.156.10197.1.301) with the curve OID `1.2.156.10197.1.301`.

For step-by-step instructions on generating a test PKI with `gmssl sm2keygen` and `gmssl certgen`, see [Certificate Guide](./certificate-howto.en.md).

## Interoperability

`gm-tlcp` has been verified byte-for-byte against GmSSL:

- **GmSSL 3.2.0** (released) — all 4 cipher suites, full handshake + APP_DATA round-trip
- **GmSSL 3.3.0-dev master** (commit `1183+`) — same, plus the new client-certificate-mandatory path that master enforces

To run the GmSSL interop tests locally you need `gmssl` on `PATH`:

```bash
cargo test --test gmssl_interop
cargo test --test gmssl_interop -- --ignored --nocapture  # full suite
```

Tongsuo 8.3.0 interop is **not** currently passing — Tongsuo's NTLS state machine rejects the TLCP version byte `0x0101`. Investigation is tracked in [`gm-tlcp/interop/tongsuo/upstream/`](https://github.com/GM-Engineers/gm/tree/main/gm/gm-tlcp/interop/tongsuo/upstream/).

## Security

- 4-pass independent security audit performed pre-release — see commit `7b274ad`
- All sensitive types (`SessionKeys`, `TlcpKeyMaterial`, `TlcpHandshake`, `TlcpEcdheContext`, `TlcpResumedSession`) implement `Drop` zeroization
- Constant-time comparison used for signature / MAC / HMAC / Finished verification
- GCM nonce-reuse is detected and surfaces as a fatal `TlcpError::NonceReuse` (which `Drop`s the connection)

See [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## License

MIT OR Apache-2.0 — see [LICENSE](../LICENSE).
