# gm-http-client Guide

> Last Updated:2026-06-29

HTTPS client based on gm-tls with GM/TLS encryption, built-in SSRF protection, connection pooling, and response size limits.


## Adding Dependencies

```toml
[dependencies]
gm-http-client = { path = "gm-http-client" }
```

---

## Basic Usage

```rust
use gm_http_client::{GmHttpClient, TlsConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load(
        "certs/client.pem",
        "certs/client-key.pem",
        "certs/ca.pem",
    )?
    .with_domain("example.com");

    let client = GmHttpClient::new(config)?;

    // GET request
    let response = client.get("https://example.com/api").await?;
    println!("Status: {}", response.status);
    println!("Body: {:?}", String::from_utf8_lossy(&response.body));

    // POST request
    let response = client.post("https://example.com/api/data", b"hello world").await?;
    println!("Status: {}", response.status);

    Ok(())
}
```

`Response` structure:

```rust
pub struct Response {
    pub status: u16,   // HTTP status code
    pub body: Vec<u8>, // Response body (raw bytes)
}
```

---

## Connection Pool

For high-frequency HTTPS request scenarios, use `ConnectionPool` to reuse GM/TLS connections and avoid a full TLS handshake on every request.


```rust
use gm_http_client::{GmHttpClient, TlsConfig, ConnectionPool, PooledHttpClient};
use gm_tls::gm::GmTlsStream;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load(
        "certs/client.pem",
        "certs/client-key.pem",
        "certs/ca.pem",
    )?
    .with_domain("example.com");

    let client = GmHttpClient::new(config)?;
    let pool = ConnectionPool::<GmTlsStream<TcpStream>>::new(10); // max 10 connections per host
    let pooled_client = PooledHttpClient::new(client, pool);

    // Requests reuse existing connections from the pool
    let response = pooled_client.get("https://example.com/api").await?;

    // Start background cleanup task to remove idle connections automatically
    let handle = pooled_client.start_cleanup_task();

    // Cancel cleanup after some time (example)
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    handle.abort();

    Ok(())
}
```

### Connection Pool API

```rust
// Create pool with specified max connections per host
let max_per_host: usize = 10;
let pool = ConnectionPool::<GmTlsStream<TcpStream>>::new(max_per_host);

// Get connection (currently managed internally by PooledHttpClient)
// Directly using PooledHttpClient is more convenient

// Start background cleanup task (periodically removes idle connections)
let handle = pooled_client.start_cleanup_task(); // -> JoinHandle<()>
```

---

## SSRF Protection

The client includes SSRF (Server-Side Request Forgery) protection that validates the resolved IP address after DNS lookup, rejecting connections to private IPs, loopback, and link-local addresses.


**Blocked address types**:

| Type | Examples |
| ------ | ------------------- |
| Loopback | `127.0.0.1`, `::1` |
| Private ranges | `10.x.x.x`, `172.16.x.x–31.x.x`, `192.168.x.x` |
| Link-local | `169.254.x.x`, `fe80::/10` |
| ULA | `fc00::/7` |
| Blocked hostnames | `localhost`, `*.local`, `*.internal` |

> **Note**:
> - Protection applies after DNS resolution
> - `validate_address_for_ssrf()` returns a verified `SocketAddr` used directly for connection, eliminating the TOCTOU window
> - DNS rebinding attacks (where DNS resolves to a public IP but the actual server is internal) are not protected in the current version

**Response Limits**:
- Maximum response body:10 MB
- Maximum response headers:64 KB

---

## Security Notes

| Rule | Description |
| ------ | ------------------ |
| HTTPS enforced | Only `https://` URLs are accepted; HTTP is rejected |
| Certificate verification | Must configure a valid CA certificate to verify server identity |
| SSRF protection | Private IPs and loopback are blocked by default |
| DNS rebinding | Not protected in current version; add application-layer protection as needed |
| TOCTOU | Fixed: validation and connection use the same resolved address |
