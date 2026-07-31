# GM/TLS Production Deployment Guide

> Last Updated: 2026-06-29

This guide covers production deployment of `gm-tls` services using SM2/SM3/SM4
cryptographic algorithms (GM/T 0003/0004/0005-2012). It addresses the security
requirements defined in GM/T 0028-2014 and GB/T 39786-2021.

**[中文版本](./deployment-guide.md)**

## Table of Contents

- [Security Model](#security-model)
- [File Permissions](#file-permissions)
- [Network Isolation](#network-isolation)
- [Certificate Management](#certificate-management)
- [Key Rotation](#key-rotation)
- [Session Store Configuration](#session-store-configuration)
- [Docker Deployment](#docker-deployment)
- [Systemd Service](#systemd-service)
- [Health Checks and Monitoring](#health-checks-and-monitoring)
- [Audit Logging](#audit-logging)
- [Incident Response](#incident-response)

---

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Private key compromise | File permissions, hardware-bound keys, key rotation |
| Man-in-the-middle | SM2 certificate chain verification, domain validation |
| Replay attack | Session ticket replay detection, monotonic nonce counters |
| Downgrade attack | Fixed cipher suite (SM4-GCM only), no version negotiation |
| Side-channel (timing) | Constant-time SM2 operations via `elliptic-curve` crate |
| Denial of service | Connection limits, input size validation, timeouts |

### Cryptographic Module Self-Test (GM/T 0028-2014)

The library automatically executes Known Answer Tests (KAT) on first
`TlsConnector::new()` or `TlsAcceptor::new()` call. This verifies:

| Test Item | Description |
|-----------|-------------|
| SM2 key generation/sign/verify/encrypt/decrypt | Complete SM2 algorithm test |
| SM3 hash | Hash function test |
| SM4 ECB encrypt/decrypt | Block cipher test |
| SM4 GCM encrypt/decrypt | AEAD test |
| SM2 key exchange (KEX) | Shared secret derivation test |
| Pair-wise consistency test | Sign/verify round-trip test |
| Software integrity check | Code segment SM3 hash verification |
| Critical function test | Key loading test |

If the self-test fails, initialization returns an error and the service must
not start. This satisfies GM/T 0028-2014 §7.2.4.1.

---

## File Permissions

### Certificate and Key Files

Private keys **must** have restricted permissions. Certificates may be
world-readable.

```bash
# Private keys: owner read-only (no group/other access)
chmod 400 /etc/gmtls/private/key.pem
chown root:root /etc/gmtls/private/key.pem

# Certificates: owner read, group read if needed
chmod 444 /etc/gmtls/certs/server.pem
chmod 444 /etc/gmtls/certs/ca.pem

# Directory: owner-only access for private material
chmod 700 /etc/gmtls/private
chmod 755 /etc/gmtls/certs
```

### Configuration Files

Configuration files may contain database credentials. Restrict access:

```bash
chmod 600 /etc/gmtls/config.toml
chown root:root /etc/gmtls/config.toml
```

### Runtime User

Run the service as a dedicated unprivileged user, not as root:

```bash
useradd --system --no-create-home --shell /sbin/nologin gmtls
```

---

## Network Isolation

### Firewall Rules (iptables)

```bash
# Allow incoming TLS connections on port 8443 from trusted networks
iptables -A INPUT -p tcp --dport 8443 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -s 172.16.0.0/12 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP

# Rate limit new connections (prevent SYN flood)
iptables -A INPUT -p tcp --dport 8443 --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 --syn -j DROP
```

### TLS for Backend Connections

Session store connections to PostgreSQL and Redis should use TLS in production:

```rust
use gm_tls::SessionStoreConfig;

// PostgreSQL with TLS (fail-closed by default)
let pg_config = SessionStoreConfig::Postgres {
    url: "postgres://user:pass@host:5432/gm_ca".to_string(),
    fail_closed: true,   // Reject tickets on store error
    use_tls: true,       // Enables PgSslMode::VerifyFull
};

// Redis with TLS (fail-closed by default)
let redis_config = SessionStoreConfig::Redis {
    url: "redis://:password@host:6379".to_string(),
    fail_closed: true,   // Reject tickets on store error
    use_tls: true,       // Uses rediss:// scheme
};

// SQLite for local development
let sqlite_config = SessionStoreConfig::Sqlite {
    path: "/tmp/sessions.db".to_string(),
    fail_closed: true,
};
```

### Container Network Policies

When deploying with Docker, isolate the TLS service from other containers:

```yaml
# docker-compose.yml
networks:
  frontend:
    # Internet-facing
  backend:
    internal: true  # No external access
    # Database and Redis only
```

---

## Certificate Management

### Certificate Lifecycle

| Phase | Action |
|-------|--------|
| Generation | Use GM/T-compliant CA (e.g., gm-ca) to issue SM2 certificates |
| Distribution | Deploy certificates via configuration management or secrets manager |
| Monitoring | Track expiration dates; alert at 30/14/7/1 days before expiry |
| Rotation | Rotate before expiry; maintain overlap period with old certificate |

### Certificate Validation

The library performs certificate chain verification during each TLS handshake:

- SM2 signature verification on each certificate in the chain
- Expiration date check
- Optional CRL revocation check (enable with `with_crl_info()`)

```rust
use gm_tls::{TlsConfig, HandshakeOptions, CrlInfo};
use std::fs;

let crl_pem = fs::read("/etc/gmtls/crl.pem")?;
let crl_info = CrlInfo::from_pem(&crl_pem)?;

let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?
    .with_crl_info(crl_info)
    .with_domain("service.example.com".to_string());
```

### Secrets Management

Prefer loading certificates from a secrets manager or environment rather than filesystem files:

```rust
use gm_tls::TlsConfig;
use std::env;

let cert_pem = env::var("GMTLS_CERT_PEM")?.into_bytes();
let key_pem = env::var("GMTLS_KEY_PEM")?.into_bytes();
let ca_pem = env::var("GMTLS_CA_PEM")?.into_bytes();

let config = TlsConfig::from_bytes(cert_pem, key_pem, ca_pem)?;
assert!(config.is_from_bytes());
```

Recommended production secrets managers:

| Platform | Solution |
|----------|----------|
| HashiCorp Vault | Use `vault` crate or REST API |
| AWS Secrets Manager | Use `aws-sdk-secretsmanager` |
| Kubernetes Secrets | Mount as environment variables |

---

## Key Rotation

### Session Ticket Keys

Rotate session ticket keys regularly (recommended: every 24 hours). The
`TicketKeySet` supports smooth rotation with multiple active keys:

```rust
use gm_tls::gm::{TicketKey, TicketKeySet};
use rand::RngCore;

// Generate a new key
let mut secret = [0u8; 32];
rand::thread_rng().fill_bytes(&mut secret);
let new_key = TicketKey {
    id: 42,  // Unique u8 identifier (first byte of ticket)
    secret,
};

// Add new key alongside old one for zero-downtime rotation
let key_set = TicketKeySet::new(new_key)
    .with_key(previous_key);  // Keep for decryption

// After migration period (e.g., 2x ticket lifetime), remove old key:
let mut key_set = key_set;
key_set.remove_key(old_id);
```

### Certificate Rotation

1. Generate new certificate 30 days before expiry
2. Deploy new certificate alongside existing one
3. Update DNS/load balancer configuration
4. Verify new certificate works (health check)
5. Remove old certificate after all connections drain

### Key Destruction

When keys are no longer needed, the library uses `Zeroizing` (from the `zeroize`
crate) to clear key material from memory on drop. No additional action is
needed for in-memory keys. For filesystem keys:

```bash
# Secure deletion: overwrite before unlinking
shred -u /etc/gmtls/private/old-key.pem
```

---

## Session Store Configuration

### PostgreSQL

```sql
-- Auto-created by gm-tls on first connection
CREATE TABLE IF NOT EXISTS session_tickets (
    id BIGSERIAL PRIMARY KEY,
    ticket_hash VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tickets_hash ON session_tickets(ticket_hash);
CREATE INDEX IF NOT EXISTS idx_tickets_created ON session_tickets(created_at);
```

Connection string (with TLS):

```
postgres://user:password@db-host:5432/gm_tls_sessions?sslmode=verify-full
```

Run periodic cleanup (cron or application-side):

```sql
DELETE FROM session_tickets WHERE created_at < NOW() - INTERVAL '24 hours';
```

### Redis

Redis sessions auto-expire via TTL. No manual cleanup needed.

Connection string (with TLS):

```
rediss://:password@redis-host:6379
```

### Suggested Session Store Lifetime

| Use Case | Session Ticket Lifetime |
|----------|------------------------|
| API Gateway | 1 hour |
| Web Application | 8 hours |
| Internal Service Mesh | 24 hours |
| IoT / Long-lived | 7 days (with rotation) |

---

## Docker Deployment

### Dockerfile (Multi-Stage Build)

```dockerfile
FROM rust:1.85-slim-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p gm-tls

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --shell /sbin/nologin gmtls

COPY --from=builder /app/target/release/your-service /usr/local/bin/
USER gmtls
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/your-service"]
```

### Docker Compose

```yaml
version: "3.9"
services:
  gmtls:
    build: .
    ports:
      - "8443:8443"
    environment:
      - DATABASE_URL=postgres://user:pass@postgres:5432/gm_tls_sessions?sslmode=verify-full
      - REDIS_URL=rediss://:pass@redis:6379
      - RUST_LOG=info,gm_tls=debug
    volumes:
      - /etc/gmtls:/etc/gmtls:ro  # Read-only cert mount
    networks:
      - backend
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp

  postgres:
    image: postgres:17
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks:
      - backend
    restart: unless-stopped

  redis:
    image: redis:7
    command: redis-server --requirepass ${REDIS_PASSWORD} --tls-port 6379
    volumes:
      - redisdata:/data
    networks:
      - backend
    restart: unless-stopped

networks:
  backend:
    internal: true

volumes:
  pgdata:
  redisdata:
```

---

## Systemd Service

```ini
# /etc/systemd/system/gmtls.service
[Unit]
Description=GM/TLS Service
Documentation=https://github.com/GM-Engineers/gm
After=network-online.target postgresql.service redis.service
Wants=network-online.target
Requires=postgresql.service redis.service

[Service]
Type=simple
User=gmtls
Group=gmtls
ExecStart=/usr/local/bin/gmtls-service
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/gmtls
ReadOnlyPaths=/etc/gmtls
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

# Environment
Environment=RUST_LOG=info,gm_tls=debug
EnvironmentFile=-/etc/gmtls/environment

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
systemctl daemon-reload
systemctl enable gmtls
systemctl start gmtls
```

---

## Health Checks and Monitoring

### Application Health Endpoint

Implement a health check endpoint that verifies certificate validity and optionally tests session store connectivity:

```rust
use gm_tls::TlsConfig;

async fn health_check() -> Result<(), Box<dyn std::error::Error>> {
    // Verify certificate is loaded and not expiring soon (within 30 days)
    let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?;
    // Application-level checks (e.g., session store cleanup) can be added here
    Ok(())
}
```

### Prometheus Metrics

The `gm-tls` library emits metrics via the `metrics` crate. Install a Prometheus exporter:

```rust
use metrics_exporter_prometheus::PrometheusBuilder;
use gm_tls::describe_metrics;

// Register metric descriptions
describe_metrics();

// Install Prometheus recorder
PrometheusBuilder::new()
    .install_recorder()
    .expect("failed to install Prometheus recorder");
```

### Key Metrics to Monitor

| Metric | Alert Threshold | Severity |
|--------|----------------|----------|
| TLS handshake failures / min | > 5% of total | Warning |
| TLS handshake failures / min | > 10% of total | Critical |
| Certificate days to expiry | < 30 days | Warning |
| Certificate days to expiry | < 7 days | Critical |
| Session store connection errors | > 0 | Warning |
| Connection rate | > 80% of limit | Warning |
| Audit events with CRITICAL severity | > 0 | Immediate |
| KAT self-test failures | > 0 | Critical |

### Logging Configuration

Configure structured logging with `RUST_LOG`:

```bash
# Production: info level, debug for TLS operations
RUST_LOG=info,gm_tls=debug

# Debugging: trace level
RUST_LOG=debug,gm_tls=trace

# Silence noisy dependencies
RUST_LOG=info,gm_tls=debug,sqlx=warn,tokio=warn
```

### Docker Health Check

```dockerfile
# Health check endpoint is application-specific;
# gm-tls does not provide an HTTP server.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1
```

---

## Audit Logging

### Configuration

Configure audit logging minimum severity:

```rust
use gm_tls::audit::{AuditConfig, Severity, configure};

configure(AuditConfig {
    min_severity: Severity::Warning,  // Log warnings and critical events
    include_location: true,
    service_id: "gmtls-production".to_string(),
});
```

### Log Collection

Forward audit logs to a centralized log collection system (ELK, Loki, Splunk).
Audit events are emitted via the `tracing` crate at `info`, `warn`, or `error`
level depending on severity.

Each audit event includes a monotonic sequence number. Monitor the sequence
for gaps to detect log tampering or loss.

### Required Audit Events

Per GM/T 0028-2014, ensure these events are logged:

| Event | Description |
|-------|-------------|
| Authentication success/failure | who, when, source IP |
| Session creation/resumption/expiry | Session lifecycle events |
| Key generation/loading/destruction | Key management events |
| Certificate verification results | Verification result details |
| Configuration changes | Before/after state |
| Security events | Downgrade attempts, invalid signatures, etc. |

---

## Incident Response

### Private Key Compromise

1. **Revoke** the certificate via CRL immediately
2. **Rotate** all session ticket keys
3. **Investigate** access logs for unauthorized use
4. **Notify** affected parties per your security policy
5. **Audit** all systems that had access to the compromised key

### Suspected Downgrade Attack

1. Check audit logs for `DowngradeAttempt` events
2. Verify the service only accepts the expected cipher suite (SM4-GCM)
3. Review network captures for protocol version manipulation
4. Block source IP if attack is confirmed

### Certificate Expiry Emergency

1. Deploy emergency certificate (pre-generated, stored offline)
2. Restart affected services
3. Verify health checks pass
4. Schedule root cause analysis

---

## Checklist

- [ ] Private key files: `chmod 400`, owned by root
- [ ] Service runs as unprivileged user
- [ ] Network firewall restricts access to trusted networks
- [ ] PostgreSQL/Redis use TLS in production
- [ ] Certificates monitored for expiry (30-day alert)
- [ ] Session ticket keys configured for rotation
- [ ] Health check endpoint implemented
- [ ] Prometheus metrics exported
- [ ] Audit logging configured at Warning severity or higher
- [ ] Systemd service hardening applied
- [ ] Docker containers run with `no-new-privileges` and `read_only: true`
- [ ] Incident response plan documented
- [ ] KAT self-test runs on service startup
- [ ] Session store has automatic cleanup configured (prune_expired)
- [ ] Certificate revocation checking enabled (if required)
- [ ] Session store configured with fail_closed for security
- [ ] TLS for backend connections (PostgreSQL/Redis) enabled

---

## References

| Standard | Description |
|----------|-------------|
| GM/T 0003-2012 | SM2 Public Key Cryptographic Algorithm |
| GM/T 0004-2012 | SM3 Cryptographic Hash Algorithm |
| GM/T 0005-2012 | SM4 Block Cipher Algorithm |
| GM/T 0028-2014 | Security Requirements for Cryptographic Modules |
| GB/T 38636-2020 | Transport Layer Cryptography Protocol (TLCP) |
| GB/T 39786-2021 | Information Security Technology — Cryptography Application Requirements |
| RFC 5077 | Transport Layer Security Session Resumption without Server-Side State |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) |
| RFC 8446 | The Transport Layer Security (TLS) Protocol Version 1.3 |
