# Getting Started

> Last Updated: 2026-06-29

**[中文版本](./getting-started.md)**

This guide helps you get started from scratch and run the core functionality of this project in 10 minutes.

## Prerequisites

| Condition | Description | Required |
|-----------|-------------|----------|
| Rust 1.85+ | Recommended install via [rustup](https://rustup.rs/) | ✅ |
| PostgreSQL 17+ | Only needed when using gm-ca | ❌ |
| Redis 7+ | Only needed when using Redis session storage | ❌ |
| Docker + docker compose | Optional, for running gm-ca service | ❌ |

## Add Dependencies

This project is a Rust workspace. Library crates can be added as dependencies to your project; gm-ca is a binary, run via `cargo run`:

```toml
# Cryptographic primitives only (SM2/SM3/SM4)
gm-crypto = { path = "gm-crypto" }

# Use GM/TLS protocol
gm-tls = { path = "gm-tls" }

# Use HTTPS client
gm-http-client = { path = "gm-http-client" }
```

gm-ca is a binary, run via `cargo run -p gm-ca-server`; no need to add it to `Cargo.toml` dependencies.

## Example 1: SM2 Sign and Verify

Complete issuance flow: Generate key → Sign → Verify.

```toml
[dependencies]
gm-crypto = { path = "gm-crypto" }
tokio = { version = "1", features = ["full"] }
```

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier};

fn main() {
    // 1. Generate SM2 key pair
    let key_pair = Sm2KeyPair::generate().unwrap();

    // 2. Create signer
    let signer = Sm2Signer::new(&key_pair).unwrap();

    // 3. Sign message
    let message = b"Hello, GM TLS!";
    let signature = signer.sign(message).unwrap();
    println!("Signature (hex): {:x}", signature);

    // 4. Verify signature
    let public_key = key_pair.public_key_bytes();
    let verifier = Sm2Verifier::new(&public_key, "DEV").unwrap();
    verifier.verify(message, &signature).unwrap();
    println!("Signature verified OK!");
}
```

Run:

```bash
cargo run --example sm2_sign
```

## Example 2: GM/TLS Client

Connect to GM/TLS server and complete mutual authentication handshake.

```toml
[dependencies]
gm-tls = { path = "gm-tls" }
tokio = { version = "1", features = ["full"] }
```

```rust
use gm_tls::{TlsConfig, TlsConnector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load certificate config (auto-executes GM/T 0028 KAT self-test)
    let config = TlsConfig::load(
        "certs/client.pem",      // Client certificate
        "certs/client-key.pem",   // Client private key
        "certs/ca.pem",           // CA certificate (for verifying server cert)
    )?
    .with_domain("example.com".to_string());  // Verify server domain

    let connector = TlsConnector::new(config)?;

    // Connect to server
    let tcp = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
    let mut tls = connector.connect(tcp).await?;

    // Send application data
    tls.write_application_data(b"Hello").await?;
    let response = tls.read_application_data().await?;
    println!("Received: {:?}", response);

    Ok(())
}
```

## Example 3: GM/TLS Server

Start a GM/TLS server with mTLS support.

```toml
[dependencies]
gm-tls = { path = "gm-tls" }
tokio = { version = "1", features = ["full"] }
```

```rust
use gm_tls::{TlsConfig, TlsAcceptor};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load(
        "certs/server.pem",
        "certs/server-key.pem",
        "certs/ca.pem",
    )?
    .with_require_client_auth(true); // Enable mutual auth (mTLS)

    let acceptor = TlsAcceptor::new(config)?; // Auto-execute KAT self-test

    // Listen on TCP port
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    println!("Server listening on 0.0.0.0:8443");

    loop {
        let (tcp, addr) = listener.accept().await?;
        println!("Connection from {}", addr);

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    // Read client request
                    if let Ok(data) = tls.read_application_data().await {
                        // Echo back
                        let _ = tls.write_application_data(&data).await;
                    }
                }
                Err(e) => eprintln!("Handshake failed: {}", e),
            }
        });
    }
}
```

## Example 4: Issue Certificates via gm-ca

Issue certificates via gRPC after starting CA service.

### Step 1: Start CA Service

```bash
# Set up database
export DATABASE_URL="postgres://postgres:test_password@localhost:5432/gm_ca"
export CA_AUTH_TOKEN="$(openssl rand -hex 32)"

# Start service (default listen [::1]:50051)
cargo run -p gm-ca-server
```

### Step 2: Issue Certificate via gRPC

```bash
# Use grpcurl (install first: brew install grpcurl)
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
    "validity_days": 365
  }' \
  localhost:50051 gm.ca.v1.CaService/SignCertificate
```

## Example 5: SM9 Identity-Based Signature

SM9 allows using identity (e.g., email) directly as public key, no certificate management needed:

```toml
[dependencies]
gm-sm9-rs = "0.1"
rand = "0.8"
```

```rust
use gm_sm9_rs::{SignMasterKey, Signer, Verifier};

// 1. KGC generates master key
let mut rng = rand::thread_rng();
let master = SignMasterKey::generate(&mut rng)?;

// 2. Derive user private key (use identity instead of certificate)
let user_key = master.extract_key(b"alice@example.com")?;

// 3. Sign
let signer = Signer::new(user_key);
let sig = signer.sign(b"important message", &mut rng)?;

// 4. Verify (anyone with master public key can verify)
let verifier = Verifier::new(b"alice@example.com", &master.ppubs);
assert!(verifier.verify(b"important message", &sig)?);
```

SM9 also supports identity-based encryption (`EncMasterKey`/`Encryptor`/`Decryptor`), see source code in `gm-sm9-rs/` directory.

## Directory Structure Reference

```
your-project/
├── Cargo.toml
├── certs/
│   ├── ca.pem           # CA certificate
│   ├── server.pem       # Server certificate
│   ├── server-key.pem   # Server private key (permission 600)
│   ├── client.pem       # Client certificate
│   └── client-key.pem   # Client private key (permission 600)
└── src/
    └── main.rs
```

For certificate generation, see [Certificate Operations Guide](./certificate-howto.md).

## Next Steps

| Need | Documentation |
|------|---------------|
| Learn more about cryptographic API | [gm-crypto Guide](./gm-crypto.md) |
| Need custom TLS behavior | [gm-tls Guide](./gm-tls.md) |
| Want to deploy CA service | [gm-ca Deployment Guide](./gm-ca.md) |
| Need HTTPS client | [gm-http-client Guide](./gm-http-client.md) |
| Need SM9 identity-based cryptography | `gm-sm9-rs` crate (Sign/encrypt, dual backend) |
