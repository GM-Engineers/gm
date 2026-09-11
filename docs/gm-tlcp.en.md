# gm-tlcp Guide

`gm-tlcp` is the standalone Rust implementation of **TLCP (Transport Layer Cryptographic Protocol, GB/T 38636-2020)**, the Chinese national standard for cryptographic transport-layer security.

This page is a quick-start. Full rustdoc with every API is on [docs.rs/gm-tlcp](https://docs.rs/gm-tlcp).

## What is TLCP?

TLCP is structurally similar to TLS 1.3 but **not interoperable with it**:

- Uses **SM2** (signature + encryption + key exchange), **SM3** (hash), **SM4** (block cipher)
- SM2/SM9 suites require **dual certificates** (sign cert + enc cert); RSA suites follow GB/T 38636-2020 §6.4.5.5 single-cert layout (a dual-cert compat mode is retained)
- Protocol version byte is `[0x01, 0x01]` (TLCP), not `[0x03, 0x03]` (TLS 1.3)
- Defines **12 cipher suites** (GB/T 38636-2020 §6.4.5.2.1 表 2), all 12 implemented by gm-tlcp with end-to-end in-process loopback regression coverage (`tests/gm_tlcp_loopback.rs` 21 tests where gm-tlcp plays both client and server through `tokio::io::duplex`)

| ID | Name | Key Exchange | Notes |
|----|------|--------------|-------|
| `0xE051` | `TLS_ECDHE_SM4_GCM_SM3` | SM2 ECDHE | SM4-GCM + SM3 — **preferred** for production |
| `0xE011` | `TLS_ECDHE_SM4_CBC_SM3` | SM2 ECDHE | SM4-CBC + HMAC-SM3 |
| `0xE053` | `TLS_ECC_SM4_GCM_SM3`  | SM2 static | SM4-GCM + SM3 — no ECDHE, for performance-sensitive paths |
| `0xE013` | `TLS_ECC_SM4_CBC_SM3`  | SM2 static | SM4-CBC + HMAC-SM3 — no ECDHE |
| `0xE057` | `TLS_IBC_SM4_GCM_SM3`  | SM9 IBC (static) | SM4-GCM + SM3 |
| `0xE017` | `TLS_IBC_SM4_CBC_SM3`  | SM9 IBC (static) | SM4-CBC + HMAC-SM3 |
| `0xE055` | `TLS_IBSDH_SM4_GCM_SM3` | SM9 IBSDH (dynamic) | SM4-GCM + SM3 — 2-round KEX |
| `0xE015` | `TLS_IBSDH_SM4_CBC_SM3` | SM9 IBSDH (dynamic) | SM4-CBC + HMAC-SM3 — 2-round KEX |
| `0xE059` | `TLS_RSA_SM4_GCM_SM3` | RSA | SM4-GCM + SM3 — dual-cert compat layout / single-cert spec layout |
| `0xE019` | `TLS_RSA_SM4_CBC_SM3` | RSA | SM4-CBC + HMAC-SM3 — same as above |
| `0xE05A` | `TLS_RSA_SM4_GCM_SHA256` | RSA | SM4-GCM + SHA-256 identifier; **PRF still runs SM3** (spec ambiguity, matches GmSSL + openHiTLS), see CHANGELOG known limitations |
| `0xE01C` | `TLS_RSA_SM4_CBC_SHA256` | RSA | SM4-CBC + SHA-256 identifier; **PRF still runs SM3**, same as above |

## Relationship with `gm-tls`

`gm-tls` is a **separate crate** that implements **TLS 1.3 with SM algorithms**. The TLCP support that used to live inside `gm-tls` was extracted into the standalone `gm-tlcp` crate (commit `28fbca1`) so the two protocol stacks can evolve independently. Pick the crate based on the protocol your peer speaks:

- **Peer speaks TLS 1.3** (with or without SM cipher suites) → use `gm-tls`
- **Peer speaks TLCP** (GB/T 38636-2020) → use `gm-tlcp`

## Quick Example

Add to `Cargo.toml`:

```toml
[dependencies]
gm-crypto = "0.3"
gm-tlcp = "0.6"
tokio = { version = "1", features = ["full"] }
```

### Server (TLCP acceptor)

```rust
use gm_tlcp::{TlcpAcceptor, TlcpError};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Load dual certificates (DER-encoded X.509) and dual private keys (PEM-encoded SM2)
    let sign_cert = std::fs::read("server-sign.crt")?;
    let enc_cert  = std::fs::read("server-enc.crt")?;
    let sign_pem  = std::fs::read_to_string("server-sign.key.pem")?;
    let enc_pem   = std::fs::read_to_string("server-enc.key.pem")?;

    // 2. Build SM2 key pairs
    let sign_key = gm_crypto::sm2::Sm2KeyPair::from_private_key_pem(&sign_pem)?;
    let enc_key  = gm_crypto::sm2::Sm2KeyPair::from_private_key_pem(&enc_pem)?;

    // 3. Build the acceptor and configure dual certs
    let acceptor = TlcpAcceptor::new()
        .with_dual_certs(sign_cert, enc_cert, sign_key, enc_key);

    // 4. Bind and echo loop
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8443").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let mut tlcp = acceptor.accept_with_certs(stream).await?;
            tlcp.write_application_data(b"HTTP/1.1 200 OK\r\n\r\nHello TLCP!").await.ok();
            Ok::<(), TlcpError>(())
        });
    }
}
```

> **RSA / SM9 suite server configuration**: substitute `with_dual_certs(...)` with `TlcpAcceptor::with_rsa_certs_single(...)` / `TlcpAcceptor::with_sm9_certs(...)`. See the [docs.rs/gm-tlcp](https://docs.rs/gm-tlcp) builder API list.

### Client (TLCP connector)

```rust
use gm_tlcp::TlcpConnector;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // The default connector offers 10 cipher suites (4 SM2 ECDHE/ECC + 2 SM9 IBC
    // + 4 RSA GCM/CBC × SM3/SHA256 PRF); the SM9 IBSDH suites (E055/E015)
    // are NOT in the default list and need explicit
    // `with_cipher_suites(...)` to add. The SM3 distid defaults to
    // "1234567812345678" (the GmSSL / Tongsuo convention).
    let connector = TlcpConnector::new();

    let stream = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
    let mut tlcp = connector.connect_with_certs(stream).await?;

    tlcp.write_application_data(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
    let response = tlcp.read_application_data().await?;
    println!("{}", String::from_utf8_lossy(&response));
    Ok(())
}
```

> **Production deployment note**: an ECDHE handshake needs the connector to be configured with the server's signing public key for `ServerKeyExchange` signature verification:
> ```rust
> // DER-encoded SM2 public key (65-byte uncompressed SEC1 point) + distid
> connector.with_server_sign_key(server_sign_pub_der, "1234567812345678".to_string())
> ```
> Mutual auth (when the peer issues `CertificateRequest`) needs `connector.with_client_certs(chain, sign_key_pem, enc_key_pem, password)`. SM9 IBSDH suites need explicit `with_cipher_suites(vec![TLS_IBSDH_SM4_GCM_SM3, TLS_IBSDH_SM4_CBC_SM3])`.

## Dual Certificate PKI

TLCP SM2/SM9 suites require **two separate SM2 certificates per peer**:

1. **Signing certificate** — used for `CertificateVerify` and `ServerKeyExchange` signatures. Public key is shared with the peer for signature verification.
2. **Encryption certificate** — used for SM2 ECDH key agreement. Private key is needed locally; public key is shared with the peer.

Both certificates must chain to the same trusted CA, and both must be SM2 (OID `1.2.156.10197.1.301`).

For step-by-step instructions on generating a test PKI with `gmssl sm2keygen` and `gmssl certgen`, see [Certificate Guide](./certificate-howto.en.md).

## Feature flags

| Feature | Status | Description |
|---|---|---|
| `default` | enabled | **GB/T 38636-2020 spec behaviour**. ECDHE `ClientKeyExchange` has no `uint16` length prefix; static-ECC skips SKE per RFC 5246 §7.4.3; ECDHE PMS uses SM2 KAP (48-byte KDF). Matches openHiTLS / Tongsuo standard mode. |
| `tlcp-gmssl-compat` | opt-in (default off) | Restores the GmSSL 2026-06+ master wire-format deviations. Enable only when talking to GmSSL master. |
| `tlcp-strict` | **DEPRECATED** (no-op) | Retained for 0.2.x callers' `Cargo.toml` — no behavioural effect. |

## Interoperability

`gm-tlcp` has been verified at varying depth against four TLCP implementations:

| Peer | Status | Verified scope |
|---|---|---|
| **in-process loopback** | ✅ all 12 suites | `tests/gm_tlcp_loopback.rs` 21 tests total: 16 where gm-tlcp plays both client and server through `tokio::io::duplex` for the full handshake + app-data round-trip (covering all 12 cipher suites + 4 RSA single-cert variants), 1 PMS-only KAT (`gm_tlcp_kap_pms_roundtrip_with_real_keys`), and 4 support-module tests |
| **GmSSL 3.3.0-dev master** | ✅ handshake / ❌ APP_DATA | All 9 handshake messages byte-for-byte verified (`tlcp-gmssl-compat` mode, R-8). F4 = record-layer deadlock (External-Upstream-Blocker, filed upstream as [gmssl #1920](https://github.com/guanzhi/GmSSL/issues/1920)) |
| **openHiTLS `s_server -tlcp`** | ✅ ECDHE up-to-Finished | Server-side handshake passes; `Decrypt Error (51)` after client Finished is a known open issue (ECDHE x̂ transform disagreement, tracked separately) |
| **Tongsuo 8.3.0** | ❌ state-machine rejects 0x0101 | NTLS state machine does not accept the TLCP version byte; [Tongsuo #836](https://github.com/Tongsuo-Project/Tongsuo/issues/836) submitted by EricZHANG1688, maintainer confirmed root cause and opened sub-issues [#840](https://github.com/Tongsuo-Project/Tongsuo/issues/840) + [#841](https://github.com/Tongsuo-Project/Tongsuo/issues/841) |

To run the GmSSL interop tests locally you need `gmssl` on `PATH`:

```bash
cargo test --test gmssl_interop
cargo test --test gmssl_interop -- --ignored --nocapture  # full suite (7 #[ignore]d tests)
```

## Security

- `interop/AUDIT-2026-09-06-v2.md` **v2-rev14** (2026-09-11, gm-tlcp 0.6.4 release baseline): 0 Critical / 0 Major / 0 Minor / 0 Doc still blocked; 1 External-Upstream-Blocker (F4). All 9 historical findings (M-1/M-2/M-3 + m-2..m-6 + D-1) RESOLVED.
- All sensitive types (`SessionKeys`, `TlcpKeyMaterial`, `TlcpHandshake`, `TlcpEcdheContext`, `TlcpResumedSession`) implement `Drop` zeroization (`zeroize` crate)
- Constant-time comparison (`subtle::ConstantTimeEq`) used for signature / MAC / HMAC / Finished verification
- GCM nonce-reuse is detected and surfaces as a fatal `TlcpError::NonceReuse` (which `Drop`s the connection)

See [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## License

MIT OR Apache-2.0 — see [LICENSE](../LICENSE).