# gm-http-client

HTTP Client with GM/TLS Support — Secure HTTP client based on gm-tls.

**[中文版](./README.md)**

## Features

- **GM/TLS Encryption**: Secure communication using National Cryptography TLS protocol
- **Simple API**: Convenient `get()` and `post()` methods
- **Async Support**: Built on tokio async runtime
- **SSRF Protection**: Blocks requests to private IPs, localhost, and other internal resources by default
- **Connection Pool**: `ConnectionPool` for connection reuse to improve performance

## Quick Start

```toml
[dependencies]
gm-http-client = "0.1"
```

```rust
use gm_http_client::{GmHttpClient, TlsConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?
        .with_domain("example.com".to_string());

    let client = GmHttpClient::new(config)?;

    // GET request
    let response = client.get("https://example.com/api").await?;
    println!("Status: {}", response.status);
    println!("Body: {:?}", response.body);

    // POST request
    let response = client.post("https://example.com/api/data", b"hello").await?;
    println!("Status: {}", response.status);

    Ok(())
}
```

## Connection Pool

Use `ConnectionPool` to reuse GM/TLS connections and reduce handshake overhead:

```rust
use gm_http_client::{GmHttpClient, TlsConfig, ConnectionPool, PooledHttpClient};
use gm_tls::gm::GmTlsStream;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?
        .with_domain("example.com".to_string());

    let client = GmHttpClient::new(config)?;
    let pool = ConnectionPool::<GmTlsStream<TcpStream>>::new(10); // max 10 connections per host
    let pooled_client = PooledHttpClient::new(client, pool);

    // Requests reuse connections from the pool
    let response = pooled_client.get("https://example.com/api").await?;

    // Start background cleanup task to remove idle connections
    let handle = pooled_client.start_cleanup_task();

    Ok(())
}
```

**Connection pool parameters:**
- `ConnectionPool::new(max_per_host)` — maximum concurrent connections per host
- `start_cleanup_task()` — starts a background task that automatically cleans up idle connections

## API Reference

### `GmHttpClient`

- `new(tls_config)` - Create client instance
- `get(url)` - Send GET request
- `post(url, body)` - Send POST request

### `ConnectionPool<S>`

- `new(max_per_host)` - Create pool with the specified max connections per host
- `get_connection(host, port)` - Get a connection from the pool (returns None if none available)
- `return_connection(host, port, stream)` - Return a connection to the pool
- `cleanup()` - Manually trigger cleanup of idle connections
- `len()` / `is_empty()` - Query pool status

### `PooledHttpClient`

- `new(client, pool)` - Create an HTTP client wrapped with a connection pool
- `get(url)` - Send GET request via the pool
- `post(url, body)` - Send POST request via the pool
- `start_cleanup_task()` - Start a background cleanup task, returns `JoinHandle`

### `Response`

- `status` - HTTP status code
- `body` - Response body (byte array)

## Security Notes

- Client verifies server certificate by default
- Must configure valid CA certificate
- Domain validation is recommended
- **SSRF Protection**: Blocks private IPs, reserved addresses, and localhost requests by default; to disable, refer to the `is_private_ip()` implementation in the source
- **Response Limits**: Maximum body size 10 MB, maximum header size 64 KB

## License

MIT OR Apache-2.0 — See [../LICENSE](../LICENSE)
