# Security Considerations

**[中文版](./SECURITY.zh-CN.md)**

## Memory Management

### Key Zeroization

This library implements automatic zeroization for sensitive key material:

- **Sm2KeyPair**: The private key is automatically zeroized when the `Sm2KeyPair` is dropped, thanks to the `ZeroizeOnDrop` derive.
- **SessionState**: Master secret and session keys are zeroized in the `Drop` implementation when a session state is dropped.
- **SessionKeys**: The SM4 session key is zeroized when `SessionKeys` is dropped.

**Important**: When cloning `SessionKeys`, the original will still be zeroized on drop, but the clone will need to be explicitly zeroized if needed.

### Key Material Handling

```rust
// Keys are zeroized on drop automatically
let keypair = Sm2KeyPair::generate()?;
let signer = Sm2Signer::new(&keypair)?;
// When 'keypair' and 'signer' go out of scope,
// their sensitive data is automatically overwritten with zeros
```

## Key Lifetime

### Session Keys

- Session keys are derived from SM2 ephemeral key exchange
- Maximum session duration: 24 hours (hardcoded limit for session tickets)
- Session keys are stored in `SessionKeys` and zeroized on drop

### Ticket Encryption Keys

- Ticket keys (`TicketKey`) must be rotated periodically
- Use `TicketKeySet::remove_key()` to remove old keys after rotation
- Each ticket key can encrypt unlimited tickets, but rotation is recommended every 90 days

## Certificate Validation

### Chain Verification

The library performs full certificate chain verification:

1. Each certificate's signature is verified using the issuer's public key
2. Validity periods (not_before, not_after) are checked
3. BasicConstraints CA:true is verified for intermediate CAs
4. Domain name matching via SAN or CN fallback

### CRL Support

- CRL verification is supported via `verify_cert_crl()`
- If no CRL is provided, revocation checking is skipped
- CRLs have a maximum validity period; expired CRLs cause verification failure

### Certificate Renewal

- Only non-expired certificates can be renewed
- The renewed certificate has a new serial number but preserves the subject and public key
- Original certificate must not be revoked before renewal

## TLS Handshake Security

### Session Resumption (RFC 5077)

- Session tickets are encrypted with SM4-GCM
- Tickets include a 24-hour maximum lifetime
- Sessions requiring client authentication cannot be resumed (security policy)
- Session store backends (in-memory, SQLite, PostgreSQL, Redis) track issued ticket nonces and reject duplicate tickets (replay protection)

### CertificateVerify

- The server signs the transcript hash with its certificate private key
- This proves the server owns the corresponding private key
- Binds the certificate to the specific handshake

### ALPN

- Application-Layer Protocol Negotiation is supported
- Server preference is respected (server chooses from client's list)

### Ticket Replay

Server-side replay protection is implemented via session store backends. When a session ticket is used for resumption, the server checks whether that ticket nonce was already issued — if so, the resumption is rejected. Different backends behave differently on error:

- **In-memory**: Reject resumption on any error (fail-closed)
- **SQLite/PostgreSQL/Redis**: By default, replay checks fail-open (errors allow resumption). For fail-closed behavior, configure the store with `fail_closed: true`

### GCM Counter

The internal GCM counter is 32 bits within the nonce construction. While the outer sequence number is 64 bits and checked for overflow, in practice:
- Maximum 2^32 encrypted records per session
- For most applications, this limit is never reached

### SM2 ID

The default SM2 ID ("1234567812345678") is used for signing. For production, ensure your ID complies with GM/T 0003 requirements.

## TLCP Protocol

### Dual-Certificate System

TLCP (GB/T 38636-2020) uses a dual-certificate system:
- **Signing certificate**: Used for authentication and handshake signatures
- **Encryption certificate**: Used for key exchange (SM2 ECDHE)

Both certificates must be provided for TLCP server operations.

### Record Layer Differences from TLS 1.3

TLCP uses protocol version 0x0101 and does NOT implement:
- Inner content type encapsulation (RFC 8446 §5.4)
- KeyUpdate mechanism
- 0-RTT data

`close_notify` is encrypted as an APPLICATION_DATA record and recognized as EOF on the receiving side.

### Session Resumption

TLCP session resumption uses session IDs (not session tickets as in TLS 1.3).
Session cache uses LRU eviction with configurable capacity (default: 1024 sessions)
and 24-hour TTL.

## Traffic Secret Protection

Application traffic secrets (`write_traffic_secret`, `read_traffic_secret`)
are wrapped in `Zeroizing<Vec<u8>>` to ensure key material is zeroized on drop.
This prevents potential secret leakage through memory inspection or core dumps.

## Best Practices

1. **Use short session lifetimes**: Configure ticket lifetimes appropriately for your security requirements
2. **Rotate ticket keys regularly**: Use `TicketKeySet::remove_key()` to remove old keys after rotation
3. **Validate certificates fully**: Always provide CA certificates and enable domain validation
4. **Use client authentication for sensitive applications**: Enable `require_client_auth` for mTLS
5. **Monitor for expired CRLs**: Ensure CRLs are refreshed before expiration

## Reporting Security Issues

We take security vulnerabilities seriously. We appreciate your efforts to
responsibly disclose your findings.

### Disclosure Process

1. **Do not open a public issue.** Security vulnerabilities should not be
   discussed in public GitHub issues.

2. **Report via GitHub Security Advisory.** Use the
   [Private vulnerability reporting](https://github.com/GM-Engineers/gm/security/advisories/new)
   feature on GitHub. This ensures encrypted communication with maintainers.

3. **Provide details.** Include:
   - Description of the vulnerability and its impact
   - Steps to reproduce (proof-of-concept code if available)
   - Affected versions / components
   - Any suggested fixes

### What to Expect

| Phase | Timeline |
|-------|----------|
| Acknowledgment | Within 3 business days |
| Initial assessment | Within 5 business days |
| Patch release for critical issues | Within 14 days |
| Patch release for high-severity issues | Within 30 days |
| Public disclosure (CVE) | Coordinated with reporter, typically after patch release |

### Scope

The following are in scope for our security program:

- **gm-der**: ASN.1 DER encoding/decoding for certificates and keys
- **gm-crypto**: SM2/SM3/SM4 cryptographic implementations, KAT self-tests
- **gm-sm9-rs**: SM9 identity-based cryptography — signatures, encryption,
  key exchange (pure-Rust + GmSSL FFI dual backend)
- **gm-tls**: TLS handshake protocol, record layer, session ticket handling,
  certificate verification, CRL checking
- **gm-ca**: Certificate authority operations
- **gm-http-client**: HTTP client with GM/TLS support

### Out of Scope

- Issues requiring physical access to the running process
- Denial of service caused by unbounded resource allocation in
  non-default configurations
- Issues in dependencies that are not exploitable through our API
- Theoretical attacks that are not practically exploitable

### Recognition

We will acknowledge reporters in the advisory and release notes (unless you
prefer to remain anonymous). We do not currently offer a bug bounty program.

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Only the latest release receives security patches.
