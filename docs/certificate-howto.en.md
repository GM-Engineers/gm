# Certificate Operations Guide

> Last Updated: 2026-06-29

This document describes how to use the project suite to generate, verify, and manage SM2 certificates.

**[中文版本](./certificate-howto.md)**

---

## Certificate Format

gm-tls expects PEM-formatted certificates and private keys.

### Certificate (PEM)

```
-----BEGIN CERTIFICATE-----
<base64-encoded DER content>
-----END CERTIFICATE-----
```

### Private Key (SEC1 or PKCS#8)

```
-----BEGIN EC PRIVATE KEY-----
<base64-encoded SEC1 content>
-----END EC PRIVATE KEY-----

# Or PKCS#8 (encrypted or unencrypted):
-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----
```

> **Important**: In production, private key file permissions must be set to `600` (owner read/write only).

---

## Method 1: Generate Test Certificates with GmSSL CLI (No gm-ca Required)

Suitable for local development and testing, no services need to be running.

> ⚠️ GmSSL 3.x CLI is incompatible with OpenSSL CLI; `openssl ecparam`, `openssl req`, and other subcommands are not supported. Please use the `gmssl` command instead.

### Install GmSSL

```bash
# macOS
brew install gmssl

# Linux (Build from source)
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL
./config && make && sudo make install
```

### Generate SM2 Key Pair

```bash
# Generate SM2 key pair (outputs PEM format private key)
gmssl sm2keygen -out ca-key.pem

# View public key
gmssl sm2sign -help  # View signing command help
```

> **Note**: GmSSL 3.x CLI has limited functionality and does not directly support certificate issuance (`req`/`x509` subcommands). For complete certificate management, use Method 2 (gm-ca service) or GmSSL 2.x (supports OpenSSL-compatible CLI).

---

## Method 2: Issue Certificates via gm-ca Service

Suitable for production environments, supports centralized certificate management and CRL issuance.

### Prerequisites

| Condition | Description |
|-----------|-------------|
| PostgreSQL database | Start database service |
| gm-ca-server | Run CA service (see [gm-ca Deployment Guide](./gm-ca.md)) |
| CSR file | Certificate Signing Request in PEM format |

### Issue via gRPC

#### Step 1: Generate CSR

Use gm-crypto to generate key pair and create CSR:

```rust
// Generate key pair
let key_pair = Sm2KeyPair::generate().unwrap();

// Note: gm-crypto does not provide CSR generation API
// CSR needs to be manually constructed as ASN.1 DER structure or use third-party crate (e.g., x509-cert)
// You can also pass the key pair directly to gm-ca's SignCertificate gRPC interface
```

#### Step 2: Call gRPC to Issue Certificate

```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d "{
    \"csr_pem\": \"$(cat client.csr | tr '\n' '\\n')\",
    \"validity_days\": 365
  }" \
  localhost:50051 gm.ca.v1.CaService/SignCertificate
```

The `certificate_pem` in the response is the issued certificate.

#### Step 3: Verify Certificate

```bash
# Use standard OpenSSL to view certificate content (verification and viewing don't involve GM algorithms, OpenSSL can be used)
openssl x509 -in client-cert.pem -noout -text
```

---

## Method 3: Issue Certificates with gm-ca CaSigner

gm-ca's `CaSigner` can directly sign CSRs:

```rust
use gm_ca::cert::CaSigner;
use gm_crypto::sm2::Sm2KeyPair;

let ca_key = Sm2KeyPair::generate().unwrap();
let signer = CaSigner::new(ca_key, "GM CA");

// Sign CSR (returns serial number and certificate PEM)
let (serial_hex, cert_pem) = signer.sign_csr(&csr_pem_bytes, 365).unwrap();
```

> **Note**: `CaSigner` does not provide a `generate_ca_cert` method. For self-signed CA certificates, construct manually or use the gRPC API via gm-ca service.

---

## Verify Certificate Chain

### Using OpenSSL

```bash
# Verify full chain (server cert → intermediate CA → root CA)
openssl verify -CAfile ca-cert.pem -partial_chain server-cert.pem

# Export and view certificate chain
openssl storeutl -noout -text -certfile server-cert.pem
```

### Using gm-tls to Verify

```rust
use gm_tls::cert_verify::validate_cert_pem;
use time::OffsetDateTime;

let result = validate_cert_pem(
    &server_cert_pem,             // Certificate PEM bytes
    OffsetDateTime::now_utc(),    // Current time
    Some("server.example.com"),   // Optional: expected domain
);
assert!(result.is_ok());
```

> **Note**: `validate_cert_pem` is a synchronous function with signature `(cert_pem: &[u8], now: OffsetDateTime, expected_domain: Option<&str>)`, it does NOT verify CA chain (only verifies single certificate validity and domain).

---

## View Certificate Information

```bash
# Standard OpenSSL can view SM2 certificate basic info (doesn't involve signature verification)
openssl x509 -in cert.pem -noout -subject -issuer -dates
openssl x509 -in cert.pem -noout -serial

# Convert PEM → DER
openssl x509 -in cert.pem -outform DER -out cert.der

# Convert DER → PEM
openssl x509 -in cert.der -inform DER -out cert.pem
```

> ⚠️ `openssl x509 -fingerprint -sm3` is not available in standard OpenSSL; SM3 fingerprint needs to be calculated using GmSSL or gm-crypto.

---

## Private Key Format Conversion

```bash
# SEC1 -> PKCS#8
openssl pkcs8 -topk8 -nocrypt -in ca-key.pem -out ca-key-pkcs8.pem

# PKCS#8 -> SEC1
openssl ec -in ca-key-pkcs8.pem -out ca-key.pem

# View private key info (without exposing private key content)
openssl ec -in ca-key.pem -text -noout
```

> ⚠️ Standard OpenSSL's `pkcs8 -v2 sm4` does not support SM4 encryption. For private key encryption, use gm-crypto's PBES2 implementation.
