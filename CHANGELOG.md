# Changelog

All notable changes to the GM cryptographic library suite.

## [Unreleased] - 2026-06-30

### Added

#### GmSSL Interoperability (gm-tls)
- **7/7 GmSSL interop tests passing**: TLS 1.3 handshake, TLCP connectivity, bidirectional client/server, loopback self-tests
- **GmSSL server daemons**: launchd plist (`com.gm.interop.plist`) auto-restarts GmSSL single-connection servers:
  - TLS 1.3 server: port **4434** (`gmssl tls13_server`)
  - TLCP server: port **4433** (`gmssl tlcp_server` with dual-cert PKI chain)
- **GmSSL client→gm-tls**: GmSSL `tls13_client` subprocess spawned from test, connects to gm-tls server (port 4435)
- **TLCP dual-cert PKI**: proper `sign_cert + enc_cert + ca_cert` chain format for GmSSL `tlcp_server`
- **Retry + timeout helpers**: `tcp_connect_with_retry()` (5x, exponential backoff), 2s read timeout
- Test env vars: `TEST_GMSLL_PORT`, `TEST_GMSLL_CERT`, `TEST_GMSLL_KEY`, `TEST_GMSLL_BIN`

## [0.2.0] - 2026-06-13

### Added

#### TLCP Protocol (GB/T 38636-2020)
- **TlcpStream<S>**: Full async record layer with SM4-GCM encryption, `AsyncRead + AsyncWrite` impl
- **TlcpHandshake**: Client-side handshake with session resumption support
- **TlcpServerHandshake**: Server-side handshake with session cache
- **TlcpConnector / TlcpAcceptor**: High-level connection API (mirrors TLS 1.3 `TlsConnector`/`TlsAcceptor`)
- **connect_tlcp() / accept_tlcp()**: Convenience functions for quick TLCP connections
- **TlcpSessionCache**: LRU-based session cache (default 1024 entries, 24h TTL)
- **TlcpResumedSession**: Abbreviated handshake state for session resumption
- TLCP cipher suites: `ECDHE_SM4_GCM_SM3`, `ECC_SM4_GCM_SM3`, `ECDHE_SM4_CBC_SM3`, `ECC_SM4_CBC_SM3`
- TLCP alert protocol with proper error handling
- 16+ integration tests (loopback, bidirectional data, close_notify, session resumption)

#### TLS 1.3 Improvements
- **Inner content type** (RFC 8446 §5.4): Encryption now prepends inner content type, decryption strips it
- **KeyUpdate mechanism**: Automatic key rotation when sequence numbers approach 2^32
- **KeyUpdate auto-trigger**: `flush_pending_key_update()` called on next write after receiving `update_requested`

#### SM9
- **KAT self-test module** (`gm-sm9-rs/src/kat.rs`): 8 test vectors per GM/T 0028-2014 §7.2.4
- **Key rotation**: `key_rotation.rs` with master key → user key re-extraction
- **Fuzz testing**: `gm-sm9-rs-fuzz` target for signature/verification

#### SM2
- **DER ↔ Raw signature conversion**: `sm2_signature_der_to_raw()` / `sm2_signature_raw_to_der()`
- **OpenSSL cross-validation**: KAT test using IETF draft-shen-sm2-ecdsa-02 vectors
- **Certificate verify fallback**: Try standard ID `1234567812345678` first, then OpenSSL empty string ID
- **PKCS#8 + SEC1 key support**: `from_private_key_pem()` handles both formats

#### SM4
- **GB/T standard KAT vectors**: SM3/SM4 KAT replaced from self-consistency to GB/T standard test vectors
- **Million-iteration SM4 KAT**: Verified against OpenSSL output

#### Crypto Traits
- **gm-crypto/src/traits.rs**: `HashToField`, `Signer`/`Verifier`, `BlockCipher`, `AeadEncryptor`, `Kdf`

#### gm-ca
- **gRPC service**: Certificate visibility, renewal, revocation, CRL generation

#### Infrastructure
- **CI/CD pipeline** (`.github/workflows/ci.yml`): fmt, clippy, test, fuzz-build, security-audit, gmssl-interop, doc
- **SBOM generation**: CycloneDX via cargo-cyclonedx in CI
- **LICENSE**: Added to all crates
- **MSRV**: `rust-version = "1.85"` in all Cargo.toml
- **rand 0.10 migration**: All crates migrated from rand 0.8/0.9 to 0.10

### Changed

- **SM9 ciphertext format**: Default changed to C1‖C3‖C2; `from_bytes()` auto-detects format
- **SM9 modinv**: Now constant-time (Fermat's little theorem + constant-time `pow_mod`)
- **G1/G2 scalar_mul**: Windowed NAF (w=4) for performance; `double-and-add-always` for constant-time
- **Session store**: All backends implement `prune_expired()` with 24h TTL
- **SM3 KAT vector 2**: Replaced GB/T standard value (transcription error) with OpenSSL-verified value

### Security

- **Traffic secrets zeroized**: `write_traffic_secret`/`read_traffic_secret` wrapped in `Zeroizing<Vec<u8>>`
- **SM9 keys ZeroizeOnDrop**: All SM9 key types derive `ZeroizeOnDrop`
- **Constant-time scalar_mul**: G1/G2 use `conditional_select` + delinearization
- **Constant-time pow_mod**: Square-and-multiply-always with `Z256::conditional_select`
- **TlsConfig bug fix**: `is_from_bytes()` checks all three fields (cert, key, ca) are `Some`
- **GmSSL version check**: Runtime FFI version verification (expects 3.1.1 = 0x7595)
- **Cert verify ID fallback**: Prevents handshake failure when server uses non-standard SM2 ID
- **Internal modules `#[doc(hidden)]`**: cert_verify, der, gm, handshake, key_update, record_layer, session_ticket

### Fixed

- Conformance test temp dir race condition (unique paths per test)
- CSR DER length encoding bug
- `build_sm2_public_key_der` deprecation warning
- Clippy warnings across all crates (zero code-level warnings)
- gm-kms Redis/PostgreSQL tests marked `#[ignore]` (require running infrastructure)
- 151 commits total across both repositories

---

## [0.1.0] - 2026-05-10

### Added

- **gm-crypto**: SM2/SM3/SM4/SM9 cryptographic primitives
- **gm-sm9-rs**: SM9 signature/encryption with dual backend (pure Rust + GmSSL FFI)
- **gm-tls**: GM/TLS 1.3 implementation with SM4-GCM record layer
- **gm-ca**: Certificate authority with SM2 certificate issuance
- **gm-der**: DER encoding/decoding utilities
- **gm-http-client**: HTTP client with GM/TLS support
- **gm-kms**: Key management service with gRPC API, MFA, multi-tenant isolation
- KAT self-tests for SM2, SM3, SM4, SM4-GCM, RNG
- Session stores: in-memory, SQLite, PostgreSQL, Redis
- 85 tests passing (gm workspace)
- Security assessment: 91-item evaluation completed

### Known Issues

- GmSSL interop tests require external server (marked `#[ignore]`)
- SM2 ZA calculation uses default ID (may differ from GB/T standard in some scenarios)
- `rand 0.8.5` unsound (fixed in 0.2.0 with migration to 0.10)
- `atomic-polyfill` unmaintained transitive dependency
- `rsa` crate Marvin Attack (awaiting upstream sqlx update)
