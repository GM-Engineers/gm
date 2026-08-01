# gm Project Deployment Guide

> Last Updated: 2026-06-29
> Version: 1.0 | Applicable to: gm-tls / gm-kms v0.1.0

**[中文版本](./deployment.md)**

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Environment Variables](#2-environment-variables)
3. [TLS Certificate Configuration](#3-tls-certificate-configuration)
4. [Database Connection](#4-database-connection)
5. [Key Management](#5-key-management)
6. [Security Hardening](#6-security-hardening)
7. [Monitoring and Audit](#7-monitoring-and-audit)
8. [Docker Deployment](#8-docker-deployment)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. System Requirements

### Software Dependencies

| Dependency | Min Version | Description |
|------------|-------------|-------------|
| Rust | 1.85+ | Build toolchain |
| GmSSL | 3.1.1 | FFI backend (optional, enabled with `gmssl` feature) |
| PostgreSQL | 14+ | Key storage backend |
| Redis | 7+ | Cache and rate limiting |

### Hardware Requirements

| Environment | CPU | Memory | Disk |
|-------------|-----|--------|------|
| Development | 2 cores | 4GB | 20GB |
| Production | 4+ cores | 8GB+ | 100GB+ SSD |

### Operating Systems

- Linux (x86_64, aarch64) ✅
- macOS (aarch64, Development/Testing) ✅
- Windows (Experimental, requires WSL2) ⚠️

---

## 2. Environment Variables

### Core Configuration

```bash
# Required
export DATABASE_URL="postgres://kms:password@localhost:5432/kms"
export KMS_KEK="your-key-encryption-key-base64"  # At least 32 bytes

# Redis (optional but recommended)
export REDIS_URL="redis://localhost:6379"

# Development mode (development environment only!)
export KMS_DEV_MODE=1  # Enable development API Key
```

### TLS Configuration

```bash
# Database connection TLS
export KMS_DB_TLS_MODE="verify_ca"    # disabled | verify_ca | no_verify
export KMS_DB_TLS_CA_CERT="/etc/ssl/ca.pem"
export KMS_DB_TLS_CLIENT_CERT="/etc/ssl/client.pem"  # mTLS
export KMS_DB_TLS_CLIENT_KEY="/etc/ssl/client.key"    # mTLS
```

### Audit Log

```bash
# Audit log integrity protection (strongly recommended for production)
export AUDIT_SIGNING_KEY="your-hmac-key-at-least-32-bytes"
```

### Security Configuration

```bash
# Do NOT use in production
# KMS_DEV_MODE=1  # NEVER set in production!
```

---

## 3. TLS Certificate Configuration

### 3.1 GM TLS Certificates

Use `gm-ca` to generate GM TLS certificates:

```bash
# 1. Generate CA key and certificate
gm-ca ca-init --cn "GM Root CA" --days 3650

# 2. Issue server certificate
gm-ca sign --cn "server.example.com" \
  --san "DNS:server.example.com" \
  --days 365 \
  --out server.pem

# 3. Issue client certificate (mTLS)
gm-ca sign --cn "client@example.com" \
  --days 365 \
  --client \
  --out client.pem
```

### 3.2 Certificate Format Requirements

| Requirement | Description |
|-------------|-------------|
| Key format | PKCS#8 (plaintext) or SEC1 (both supported by `gm-crypto`) |
| Signature format | DER encoded (auto-converted to 64-byte raw format) |
| SM2 signature ID | Default `1234567812345678` (GM/T standard), auto-fallback to empty ID (OpenSSL compatible) |

### 3.3 TLS Versions

| Protocol | Version | Support |
|----------|---------|---------|
| GM/TLS 1.1 | 0x0101 | ✅ TLCP |
| TLS 1.3 | 0x0303 | ✅ |

---

## 4. Database Connection

### 4.1 PostgreSQL

```bash
# Basic connection
DATABASE_URL="postgres://user:pass@host:5432/kms"

# With TLS
DATABASE_URL="postgres://user:pass@host:5432/kms?sslmode=verify-ca&sslrootcert=/etc/ssl/ca.pem"
```

Or use `BackendTlsConfig`:

```bash
export DATABASE_URL="postgres://user:pass@host:5432/kms"
export KMS_DB_TLS_MODE="verify_ca"
export KMS_DB_TLS_CA_CERT="/etc/ssl/ca.pem"
```

### 4.2 Redis

```bash
# Plaintext connection
REDIS_URL="redis://localhost:6379"

# TLS connection (use rediss:// protocol)
REDIS_URL="rediss://localhost:6380"
```

### 4.3 Connection Pool Configuration

| Parameter | Default | Recommended Production |
|-----------|---------|----------------------|
| PG max_connections | 10 | 20-50 |
| PG min_connections | - | 5 |
| PG connect_timeout | 30s | 10s |
| Redis connection_timeout | - | 5s |

---

## 5. Key Management

### 5.1 KEK (Key Encryption Key)

KEK is used to encrypt key material stored in the database:

```bash
# Generate KEK (32 bytes, Base64 encoded)
openssl rand -base64 32
export KMS_KEK="<generated-key>"
```

⚠️ **Security Requirements**:
- KEK must be at least 32 bytes
- Do not load directly from files or environment variables in production (use HSM)
- When `KMS_KEK` is not set, `KMS_DEV_MODE=1` allows plaintext fallback (development only)

### 5.2 SM9 Master Key

SM9 master key pairs are managed via `Sm9MasterKeyStore`:

| Store Backend | Description |
|--------------|-------------|
| `EnvVarKekStore` | Load KEK from environment variable |
| `MemoryKekStore` | In-memory storage (for testing) |

### 5.3 Key Rotation

```rust
// Execute via key_rotation module
use gm_sm9_rs::key_rotation::KeyRotationManager;
```

Current key rotation supports versioned rotation of SM9 sign/encrypt key pairs.

---

## 6. Security Hardening

### 6.1 Network Security

| Measure | Status |
|---------|--------|
| Enable database TLS (`KMS_DB_TLS_MODE=verify_ca`) | ✅ |
| Enable Redis TLS (`rediss://`) | ✅ |
| Use mTLS for inter-service authentication | ✅ |
| Disable database port from public network | ⚠️ |
| Use firewall to restrict KMS service port access | ⚠️ |

### 6.2 Cryptographic Security

| Measure | Status |
|---------|--------|
| GCM nonce reuse runtime detection | ✅ |
| Constant-time scalar multiplication (G1/G2) | ✅ |
| Constant-time `pow_mod` (Fermat's little theorem) | ✅ |
| KAT self-test (SM2/SM3/SM4/SM9) | ✅ |
| Traffic key ZeroizeOnDrop | ✅ |
| Audit log HMAC-SM3 integrity protection | ✅ |

### 6.3 Access Control

| Measure | Status |
|---------|--------|
| gRPC authentication (API Key / mTLS) | ✅ |
| Multi-tenant isolation | ✅ |
| Key export approval workflow | ✅ |
| MFA TOTP support | ✅ |
| TOTP secret envelope encryption | ✅ |
| Disable `KMS_DEV_MODE` in production | ⚠️ |

### 6.4 Known Limitations

| Item | Status | Risk Level |
|------|--------|------------|
| `rand` 0.8.5 unsound | Upgraded to 0.10 | Low |
| `rsa` Marvin Attack | Waiting for upstream sqlx update | Medium |
| `atomic-polyfill` unmaintained | Transitive dependency | Low |
| SM9 `modinv` large number limit | Returns None, sufficient for current scenarios | Low |

---

## 7. Monitoring and Audit

### 7.1 Audit Log

Audit logs output to `tracing` framework, containing structured JSON:

```json
{
  "seq": 42,
  "timestamp": "2026-06-14T01:23:45Z",
  "event_type": "AuthSuccess",
  "severity": "Info",
  "actor": "client.cn=admin:client",
  "action": "TLS authentication completed successfully",
  "result": "SUCCESS",
  "integrity_hash": "a1b2c3..."
}
```

### 7.2 Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|----------------|
| `gmtls_handshake_total` | TLS handshake count | - |
| `gmtls_handshake_errors` | Handshake failure count | > 5/min |
| `gmtls_active_sessions` | Active TLS sessions | > 10000 |
| `kms_key_operations` | Key operation count | - |
| `kms_auth_failures` | Authentication failure count | > 10/min |

### 7.3 Log Integrity Verification

When `AUDIT_SIGNING_KEY` is configured, use `AuditEvent::verify_integrity()` to verify logs haven't been tampered with.

---

## 8. Docker Deployment

### 8.1 Build

```dockerfile
FROM rust:1.85-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p kms

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/kms /usr/local/bin/
EXPOSE 8443
ENTRYPOINT ["kms"]
```

### 8.2 Docker Compose

```yaml
version: '3.8'
services:
  kms:
    build: .
    ports:
      - "8443:8443"
    environment:
      - DATABASE_URL=postgres://kms:password@postgres:5432/kms
      - REDIS_URL=redis://redis:6379
      - KMS_KEK=${KMS_KEK}
      - KMS_DB_TLS_MODE=verify_ca
      - KMS_DB_TLS_CA_CERT=/etc/ssl/ca.pem
      - AUDIT_SIGNING_KEY=${AUDIT_SIGNING_KEY}
    volumes:
      - ./certs:/etc/ssl:ro
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16
    environment:
      - POSTGRES_DB=kms
      - POSTGRES_USER=kms
      - POSTGRES_PASSWORD=password
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redisdata:/data

volumes:
  pgdata:
  redisdata:
```

---

## 9. Troubleshooting

### 9.1 Common Issues

| Symptom | Cause | Solution |
|---------|-------|---------|
| `PoolTimedOut` | PostgreSQL not started or network unreachable | Check PG service and connection string |
| `KMS_KEK not set` | Key encryption key not configured | Set `KMS_KEK` or `KMS_DEV_MODE=1` |
| SM2 signature verification failed | Signature ID mismatch | System auto-fallback to empty ID, check certificates |
| GmSSL FFI load failed | GmSSL library not installed | Install GmSSL 3.1.1 or use `pure-rust` |
| Redis connection timeout | Redis not started | Check Redis service |

### 9.2 Log Levels

```bash
RUST_LOG=gm_tls=info,kms=info    # Production
RUST_LOG=gm_tls=debug,kms=debug  # Debug
RUST_LOG=gm_tls=trace             # Verbose debug
```

### 9.3 Health Check

```bash
curl -s http://localhost:8443/health | jq .
```

---

## Appendix A: Cipher Suites

| Suite | Value | Protocol |
|-------|-------|----------|
| TLS_AES_128_GCM_SHA256 | 0x1301 | TLS 1.3 |
| ECC_SM4_GCM_SM3 | 0xE001 | TLCP |
| ECDHE_SM4_GCM_SM3 | 0xE011 | TLCP |
| ECC_SM4_CBC_SM3 | 0xE002 | TLCP |
| ECDHE_SM4_CBC_SM3 | 0xE012 | TLCP |

## Appendix B: Standard References

| Standard | Description |
|----------|-------------|
| GM/T 0028-2014 | Cryptographic Module Security Technical Requirements |
| GB/T 32905-2016 | SM3 Cryptographic Hash Algorithm |
| GB/T 32907-2016 | SM4 Block Cipher Algorithm |
| GB/T 32918-2016 | SM2 Elliptic Curve Public Key Cryptographic Algorithm |
| GB/T 38636-2020 | TLCP Transport Layer Cryptography Protocol |
| GB/T 39786-2021 | Cryptography Application Requirements for Information Systems |
| GM/T 0044-2016 | SM9 Identity-Based Cryptography Algorithm |
| GM/T 0080-2020 | SM9 Cryptographic Algorithm Usage Specification |
