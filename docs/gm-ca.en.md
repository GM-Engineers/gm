# gm-ca Deployment Guide

> Last Updated:2026-06-29

gm-ca provides an SM2 Certificate Authority service via gRPC, offering certificate issuance, renewal, revocation, querying, and CRL (Certificate Revocation List) management.


## Starting the Service

gm-ca is configured **exclusively through environment variables** — no command-line arguments.


### Environment Variables

| Variable | Required | Default | Description |
| ---------- | ---------- | --------- | ------------- |
| `DATABASE_URL` | Yes | — | Database connection string: `postgres://user:pass@host:5432/gm_ca` or `sqlite:gm_ca.db` |
| `CA_AUTH_TOKEN` | Yes | — | Bearer Token; **minimum 32 bytes (256 bits)**, generate with `openssl rand -hex 32` |
| `CA_KEY_PATH` | No | `ca_key.pem` | CA private key file path (SEC1, PKCS#8, or encrypted PKCS#8 PEM) |
| `CA_SUBJECT_CN` | No | `GM CA` | CA certificate's Common Name field |
| `GRPC_LISTEN_ADDR` | No | `[::1]:50051` | gRPC listen address (**default: IPv6 localhost only**) |
| `METRICS_ADDR` | No | `[::1]:9000` | Prometheus metrics listen address |
| `GRPC_TLS_CERT` | No | — | Enable GM/TLS transport: client certificate path |
| `GRPC_TLS_KEY` | No | — | Enable GM/TLS transport: server private key path |
| `GRPC_TLS_CA` | No | — | Enable GM/TLS transport: CA certificate path |

> **Important**: By default `GRPC_LISTEN_ADDR=[::1]:50051` only accepts connections from the local host via IPv6. Set to `0.0.0.0:50051` before deploying if external access is needed.


### Starting the Server

```bash
# Set required environment variables
export DATABASE_URL="postgres://postgres:test_password@localhost:5432/gm_ca"
export CA_AUTH_TOKEN="$(openssl rand -hex 32)"

# Start the CA service
cargo run -p gm-ca-server
```

### Enabling GM/TLS Transport (Optional)

Set all three variables simultaneously to use GM/TLS encryption for gRPC traffic (instead of plaintext TCP):


```bash
export DATABASE_URL="postgres://postgres:test_password@localhost:5432/gm_ca"
export CA_AUTH_TOKEN="$(openssl rand -hex 32)"
export GRPC_TLS_CERT="/path/to/grpc-server.pem"
export GRPC_TLS_KEY="/path/to/grpc-server-key.pem"
export GRPC_TLS_CA="/path/to/ca.pem"   # CA for client certificates

cargo run -p gm-ca-server
```

---

## gRPC API

Proto package: `gm.ca.v1`. All requests require `Authorization: Bearer <CA_AUTH_TOKEN>` header.


### 1. Sign Certificate (SignCertificate)

Issue a new end-entity certificate (requires a pre-generated CSR):


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIICIT...",
    "validity_days": 365
  }' \
  localhost:50051 gm.ca.v1.CaService/SignCertificate
```

**Success response**:
```json
{
  "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIICEjCC...",
  "error_code": "",
  "error_message": ""
}
```

### 2. Renew Certificate (RenewCertificate)

Renew an existing certificate (uses the original public key with extended validity):


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "serial_number": "00:AA:BB:CC:DD:EE:FF:00:01",
    "validity_days": 365
  }' \
  localhost:50051 gm.ca.v1.CaService/RenewCertificate
```

### 3. Revoke Certificate (RevokeCertificate)

Revoke an issued certificate:


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "serial_number": "00:AA:BB:CC:DD:EE:FF:00:01",
    "reason": 1
  }' \
  localhost:50051 gm.ca.v1.CaService/RevokeCertificate
```

`reason` is an integer (RFC 5280 CRL reason code): `0`=unspecified, `1`=keyCompromise, `2`=cACompromise, `3`=affiliationChanged, `4`=superseded, `5`=cessationOfOperation, `6`=certificateHold, `9`=privilegeWithdrawn, `10`=aACompromise.


**Success response**:
```json
{
  "success": true,
  "error_code": "",
  "error_message": ""
}
```

### 4. Get Certificate (GetCertificate)

Query certificate info by serial number:


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "serial_number": "00:AA:BB:CC:DD:EE:FF:00:01"
  }' \
  localhost:50051 gm.ca.v1.CaService/GetCertificate
```

**Response**:
```json
{
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "issuer": "GM CA",
  "not_before": "2024-01-01T00:00:00Z",
  "not_after": "2025-01-01T00:00:00Z",
  "status": "valid",
  "error_code": "",
  "error_message": ""
}
```

`status` values: `valid`, `revoked`, `expired`.


### 5. Get CRL (GetCrl)

Retrieve the CRL for a given CA (in DER format):


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "issuer_cn": "GM CA"
  }' \
  localhost:50051 gm.ca.v1.CaService/GetCrl
```

Returns `crl_der` (binary DER). To view with OpenSSL:


```bash
# Save and view CRL contents
openssl crl -inform DER -in crl.der -text -noout
```

---

## Health Check

gm-ca includes a built-in gRPC Health Checking Protocol service for Kubernetes/container orchestration:


```bash
grpcurl -plaintext localhost:50051 /grpc.health.v1.Health/Check
```

Response `{"status":"SERVING"}` means healthy.


---

## Calling from Rust Code

```rust
use gm_ca::ca::v1::ca_service_client::CaServiceClient;
use tonic::transport::Channel;

let channel = Channel::from_static("http://[::1]:50051")
    .connect()
    .await?;

let mut client = CaServiceClient::with_interceptor(channel, |mut req| {
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", std::env::var("CA_AUTH_TOKEN")?).parse()?,
    );
    Ok(req)
});

let response = client
    .sign_certificate(tonic::Request::new(SignCertificateRequest {
        csr_pem: csr_pem.clone(),
        validity_days: 365,
    }))
    .await?;
```

---

## Database Requirements

gm-ca supports **PostgreSQL** and **SQLite** dual backends, configured via the `DATABASE_URL` environment variable:


- PostgreSQL: `postgres://user:password@host:5432/gm_ca` (recommended for production, supports PG 14+)
- SQLite: `sqlite:gm_ca.db` (for dev/testing, supports both file mode and in-memory `sqlite::memory:` mode)

The database schema is auto-created by the service on first startup (`store.init_schema().await?`). Ensure the connecting user has permissions to create tables and indexes.


> **Security note**: CA private key file permissions should be set to `600` (readable/writable by owner only). If the key does not exist, set `ALLOW_CA_KEY_GENERATION=true` to auto-generate.
