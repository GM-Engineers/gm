# gm-tls Guide

> Last Updated:2026-06-30


## Adding Dependencies

```toml
[dependencies]
gm-tls = { path = "gm-tls" }

# For Prometheus metrics
metrics-exporter-prometheus = "0.16"
```

---

## Two API Styles

gm-tls provides two sets of APIs:


| Style | API | Use Case |
| ------- | ----- | ---------- |
| High-level (recommended) | `TlsConfig` + `TlsConnector` / `TlsAcceptor` | Most applications, simple and easy to use |
| Low-level | `connect_gm_rust` / `accept_gm_rust` | Need fine-grained control over handshake process |

---

## High-level API: GM/TLS Client

```rust
use gm_tls::{TlsConfig, TlsConnector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load(
        "certs/client.pem",       // Client certificate (PEM)
        "certs/client-key.pem",    // Client private key (PEM)
        "certs/ca.pem",            // CA certificate (verifies server cert)
    )?
    .with_domain("example.com".to_string())  // Validate server domain
    .with_alpn(vec!["http/1.1".to_string()]);

    let connector = TlsConnector::new(config)?; // Auto-runs GM/T 0028 KAT self-test

    let tcp = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
    let mut tls = connector.connect(tcp).await?;

    // GmTlsStream implements AsyncRead + AsyncWrite
    tls.write_application_data(b"GET /api HTTP/1.0\r\n\r\n").await?;
    let response = tls.read_application_data().await?;
    println!("Received: {:?}", response);

    Ok(())
}
```

`GmTlsStream<S>` implements `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`, usable as a regular tokio stream.


---

## High-level API: GM/TLS Server

```rust
use gm_tls::{TlsConfig, TlsAcceptor};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load(
        "certs/server.pem",
        "certs/server-key.pem",
        "certs/ca.pem",
    )?
    .with_require_client_auth(true)  // Enable mTLS
    .with_alpn(vec!["http/1.1".to_string()]);

    let acceptor = TlsAcceptor::new(config)?; // Auto-runs GM/T 0028 KAT self-test

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    loop {
        let (tcp, addr) = listener.accept().await?;
        println!("Connection from {}", addr);

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let data = tls.read_application_data().await.unwrap_or_default();
                    let _ = tls.write_application_data(&data).await;
                }
                Err(e) => eprintln!("Handshake failed: {}", e),
            }
        });
    }
}
```

To retrieve client certificate info after handshake:


```rust
// accept_with_client_cert returns (GmTlsStream, Option<client_CN>, Option<SessionTicket>)
let (tls, client_cn, ticket) = acceptor.accept_with_client_cert(tcp).await?;
if let Some(cn) = client_cn {
    println!("Client CN: {}", cn);
}
```

---

## TlsConfig Options

```rust
use gm_tls::{TlsConfig, HandshakeOptions, SessionStoreConfig, TlsConnector, TlsAcceptor};

// Basic configuration (auto-runs GM/T 0028 KAT self-test)
let config = TlsConfig::load("cert.pem", "key.pem", "ca.pem")?;

// Load from memory (for secret managers)
let config = TlsConfig::from_bytes(cert_pem, key_pem, ca_pem)?;

// Validate server domain (skip if not set)
let config = config.with_domain("example.com".to_string());

// ALPN protocol list
let config = config.with_alpn(vec!["http/1.1".to_string()]);

// Require client certificate (default: true)
let config = config.with_require_client_auth(true);

// Session resumption, CRL checking, and other advanced options (see below)
let config = config.with_handshake_options(opts);
```

---

## Session Resumption and Session Stores

Session resumption allows clients to reuse an established session in subsequent connections, reducing handshake time.


### Client: Sending a Session Ticket

```rust
use gm_tls::{TlsConfig, TlsConnector, HandshakeOptions, SessionTicket};

let config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?
    .with_domain("example.com".to_string())
    .with_handshake_options(HandshakeOptions {
        session_ticket: Some(your_saved_ticket), // Ticket received in a previous connection
        ..Default::default()
    });

let connector = TlsConnector::new(config)?;
let mut tls = connector.connect(tcp).await?;
// If server accepts ticket resumption, full handshake is skipped
```

### Server: Configure Session Ticket Keys

```rust
use gm_tls::{TlsConfig, TlsAcceptor, HandshakeOptions, TicketKey, TicketKeySet};

let current_key = TicketKey { id: 1, secret: generate_32_bytes() };
let key_set = TicketKeySet::new(current_key);

let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?
    .with_handshake_options(HandshakeOptions {
        session_ticket_key: Some(key_set),
        ..Default::default()
    });
```

### Session Storage Backends (Replay Protection)

Session resumption requires storing used tickets to prevent replay attacks. Four backends are supported:


```rust
use gm_tls::SessionStoreConfig;

// In-memory (default, single instance, no persistence, always fail-closed)
let config = SessionStoreConfig::InMemory;

// SQLite (local persistence, single instance)
let config = SessionStoreConfig::Sqlite {
    path: "/tmp/sessions.db".to_string(),
    fail_closed: true,  // Reject tickets on store error (secure default)
};

// PostgreSQL (multi-instance deployment)
let config = SessionStoreConfig::Postgres {
    url: "postgres://user:password@localhost:5432/gm_ca".to_string(),
    fail_closed: true,
    use_tls: true,  // Enable TLS in production
};

// Redis (high-performance caching)
let config = SessionStoreConfig::Redis {
    url: "redis://:password@localhost:6379".to_string(),
    fail_closed: true,
    use_tls: true,  // Enable TLS in production
};
```

Enable on server side:


```rust
let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?
    .with_handshake_options(HandshakeOptions {
        session_ticket_key: Some(key_set),
        session_store: Some(SessionStoreConfig::Redis {
            url: "redis://:password@localhost:6379".to_string(),
            fail_closed: true,
            use_tls: true,
        }),
        ..Default::default()
    });
```

---

## CRL Certificate Revocation Checking

Verify that peer certificates have not been revoked during handshake:


```rust
use gm_tls::{TlsConfig, HandshakeOptions, CrlInfo};
use std::fs;

// Load CRL (PEM format)
// Corresponding code: gm-tls/src/cert_verify.rs
let crl_pem = fs::read("crl.pem")?;
let crl_info = CrlInfo::from_pem(&crl_pem)?;

// Or DER format:
// let crl_der = fs::read("crl.der")?;
// let crl_info = CrlInfo::from_der(&crl_der)?;

let config = TlsConfig::load("cert.pem", "key.pem", "ca.pem")?
    .with_handshake_options(HandshakeOptions {
        crl_info: Some(crl_info),
        ..Default::default()
    });
```

---

## Prometheus Metrics

gm-tls exposes metrics via the `metrics` crate:


| Metric | Type | Labels | Description |
| ------------------- | ----------- | ----------------- | ------------------ |
| `gmtls_handshakes_total` | Counter | `role`, `result` | Total TLS handshakes |
| `gmtls_handshake_duration_seconds` | Histogram | `role` | TLS handshake duration |
| `gmtls_session_resumptions_total` | Counter | `result` | Session resumption attempts |
| `gmtls_bytes_transferred_total` | Counter | `role`, `dir` | Bytes sent/received |
| `gmtls_cert_verification_errors_total` | Counter | `reason` | Certificate verification errors |

Usage:


```rust
use gm_tls::describe_metrics;
use metrics_exporter_prometheus::PrometheusBuilder;

describe_metrics();
PrometheusBuilder::new().install().unwrap();
```

---

## Low-level API

For scenarios requiring fine-grained control over the handshake:


```rust
use gm_tls::gm::{connect_gm_rust, accept_gm_rust, HandshakeOptions};

let tls_stream = connect_gm_rust(
    &cert_pem,
    &key_pem,
    &ca_pem,
    Some("example.com"),           // Domain
    &["http/1.1".to_string()],    // ALPN
    tcp_stream,
    &HandshakeOptions::default(),
).await?;
```

---

## Security Notes

| Rule | Description |
| --------------- | ------------------ |
| Private key file permissions | Set to 600, readable only by owner |
| Certificate chain verification | Always verify the full chain in production |
| Domain validation | Clients should use `.with_domain()` to validate server domain |
| Nonce uniqueness | Use unique sequence numbers for each encryption; never reuse |
| Session ticket key rotation | Rotate regularly, recommended interval ≤ 24 hours |
| KAT self-test | `TlsConnector::new()` |
| Error codes | Use `TlsError::code()` to get structured `ErrorCode` |

---

## GmSSL Interoperability Testing

gm-tls verifies full bidirectional interoperability with GmSSL via `tests/gmssl_interop_tests.rs`. Currently **7/7 tests pass**.


### Test Coverage

| Test | Direction | Description |
| ------ | ----------- | ------------- |
| `test_gmssl_tls13_server_reachable` | → GmSSL | TCP connect to GmSSL TLS 1.3 server (port 4434) |
| `test_gmssl_tls13_handshake` | → GmSSL | gm-tls client → GmSSL TLS 1.3 server handshake |
| `test_gmssl_tls13_client_connects_to_gmtls_server` | ← GmSSL | GmSSL `tls13_client` subprocess → gm-tls server (port 4435) |
| `test_gmssl_tlcp_handshake` | → GmSSL | TCP connect to GmSSL TLCP server (port 4433) |
| `test_loopback_handshake` | self | TLS 1.3 self-handshake (no external service) |
| `test_loopback_mutual_auth` | self | TLS 1.3 mutual authentication |
| `test_loopback_echo_large_data` | self | TLS 1.3 large message (64KB) roundtrip |

### GmSSL Server Architecture

GmSSL's `tls13_server` and `tlcp_server` are **single-connection servers** that exit after handling one connection. A `launchd` plist restarts them automatically:


```xml
<!-- ~/Library/LaunchAgents/com.gm.interop.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"...">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.gm.interop</string>
  <key>ProgramArguments</key>
  <array>
    <string>/tmp/gmssl-interop-daemon.sh</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict/>
</dict>
</plist>
```

The daemon script starts two servers:
- TLS 1.3 server: `gmssl tls13_server -port 4434 ...` (binary: `/tmp/gmssl-install/bin/gmssl`)
- TLCP server: `gmssl tlcp_server -port 4433 ...`

### Running Tests

```bash
# Prerequisites:
# 1. GmSSL installed (path /tmp/gmssl-install/bin/gmssl)
# 2. launchd plist loaded (launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.gm.interop.plist)
# 3. Server processes running (ports 4433, 4434 listening)

# Run all interop tests
TEST_GMSLL_PORT=4434 \
TEST_GMSLL_CERT=/tmp/gmssl-interop/testkey2.crt \
TEST_GMSLL_KEY=/tmp/gmssl-interop/testkey2.key \
cargo test -p gm-tls --test gmssl_interop_tests -- --include-ignored

# Environment variables:
# TEST_GMSLL_PORT   GmSSL TLS 1.3 server port (default 4434)
# TEST_GMSLL_CERT    Certificate PEM path (default /tmp/gmssl-interop/testkey2.crt)
# TEST_GMSLL_KEY     Private key path (default /tmp/gmssl-interop/testkey2.key)
# TEST_GMSLL_BIN     GmSSL binary path (default /tmp/gmssl-install/bin/gmssl)
```

### TLCP Dual-Certificate Configuration

TLCP requires dual certificates (sign cert + enc cert), in chain PEM format `sign_cert + enc_cert + ca_cert`:


```bash
# Start TLCP server (launchd auto-restarts)
/tmp/gmssl-install/bin/gmssl tlcp_server \
  -port 4433 \
  -cert /tmp/gmssl-interop/tlcp_chain.pem \
  -key /tmp/gmssl-interop/tlcp_keys.pem \
  -pass tlcp999 \
  -cipher_suite TLS_ECDHE_SM4_CBC_SM3
```
