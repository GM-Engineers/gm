# gm-tls

GM/TLS Core Library — Pure Rust implementation supporting SM2/SM3/SM4 algorithms.

**[中文版](./README.md)**

## Overview

gm-tls is a Rust library for GM/TLS protocol implementation, providing:

- **SM2** elliptic curve key generation, signing, and verification
- **SM3** hash algorithm and KDF key derivation
- **SM4-GCM** symmetric encryption (with authentication)
- **mTLS** mutual authentication handshake flow

## Documentation

- [Quick Start Guide](./README.md) (this file)
- [Architecture Documentation](./ARCHITECTURE.md) - Component structure and design
- [Security Guide](./SECURITY.md) - Security best practices

### Test Coverage

```bash
cargo test --workspace
cargo tarpaulin --out Html --workspace --tests  # requires cargo-tarpaulin
```

## Quick Start

```rust
use gm_tls::gm::{connect_gm_rust, HandshakeOptions};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = std::fs::read("client.pem")?;
    let key_pem = std::fs::read("client-key.pem")?;
    let ca_pem = std::fs::read("ca.pem")?;

    let stream = TcpStream::connect("127.0.0.1:8443").await?;
    let tls_stream = connect_gm_rust(
        &cert_pem,
        &key_pem,
        &ca_pem,
        Some("example.com"),
        &["http/1.1".to_string()],
        stream,
        &HandshakeOptions::default(),
    ).await?;

    tls_stream.write_application_data(b"Hello").await?;
    let response = tls_stream.read_application_data().await?;
    println!("Received: {:?}", response);

    Ok(())
}
```

## Security Usage Guide

### 1. Key Management

- **Private Key Protection**: Ensure private key file permissions are 600, readable only by owner
- **Key Rotation**: Regularly rotate session keys, recommended period not exceeding 90 days
- **CSPRNG**: Always use system-provided secure random number generator, do not use predictable random numbers

### 2. Certificate Verification

- **Full Chain Verification**: Always verify the complete certificate chain, do not skip intermediate CAs
- **Domain Matching**: Always pass the expected domain when using `validate_cert_pem`
- **Validity Check**: Certificates that are expired or not yet valid will be rejected
- **Self-Signed Restrictions**: Production environments should configure CA certificates, do not accept self-signed certificates

### 3. Session Security

- **Nonce Uniqueness**: Each encryption must use a unique sequence number, do not reuse nonces
- **Sequence Number Management**: Read and write sequence numbers are managed independently, do not mix them
- **Record Size Limit**: Single records should not exceed 64KB

### 4. Error Handling

- **Do Not Ignore Errors**: Immediately terminate session when signature verification or authentication fails
- **Logging**: Record errors for security audits, but do not leak sensitive information

## API Stability

This library follows semantic versioning, with API stability maintained between major versions.

Current version: v0.1.0

### Stable API

The following API will not introduce breaking changes within the v0.x range:

**Low-level API (gm module):**
- `gm_tls::gm::connect_gm_rust`
- `gm_tls::gm::accept_gm_rust`
- `gm_tls::gm::GmTlsStream`
- `gm_tls::gm::HandshakeOptions`
- `gm_tls::gm::SessionKeys`
- `gm_tls::gm::validate_cert_pem`

**High-level API:**
- `gm_tls::TlsConfig`
- `gm_tls::TlsConnector`
- `gm_tls::TlsAcceptor`

### Experimental API

The following APIs are marked as experimental and may change:

- Internal handshake state machine functions
- Undocumented protocol details

## Performance Characteristics

| Operation | Average Latency |
|-----------|-----------------|
| SM2 Ephemeral Key Generation | ~95 µs |
| SM2 Signing | ~100 µs |
| SM2 Verification | ~80 µs |
| SM4-GCM Encrypt/Decrypt | ~5 µs/KB |
| ClientHello Construction | ~94 µs |
| ALPN Selection | ~2.8 ns |

## Testing

```bash
# Run all tests
cargo test

# Run benchmarks
cargo bench

# Run fuzzing tests
cargo fuzz run tls_record_parse
```

## Dependencies and License

All dependencies in this project use MIT/Apache-2.0/BSD licenses, with no GPL/LGPL copyleft restrictions.

See [deny.toml](./deny.toml) for details.

## Security Reporting

If security vulnerabilities are found, please report through GitHub Security Advisories. Do not discuss in public issues.

---

**Note**: This library is a fundamental component and does not include business logic. Please follow the security guidelines above when using it.
