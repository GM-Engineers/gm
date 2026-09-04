# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING**: TLCP support has been removed from `gm-tls` and now lives
  exclusively in the standalone `gm-tlcp` crate. The previous
  `gm_tls::tlcp::*` re-export shim and the `GmTlsStream::with_version(...,
  TLCP_VERSION_1_0)` bridge were both **removed outright** (no deprecation
  cycle — the entire TLCP path moved out under the same major version).
  Consumers of TLCP must `use gm_tlcp::*` directly and depend on the
  `gm-tlcp` crate. The split is documented in ADR-001 / gm-kms/discuss/10.

  Code-level changes:
  - `gm-tls/src/tlcp.rs` deleted.
  - `gm-tls/Cargo.toml`: dropped the `gm-tlcp` dependency.
  - `gm-tls/tests/tlcp_integration_tests.rs` (1592 lines, the only
    in-workspace file that still imported `gm_tls::tlcp::*` and the
    broken `gm_tls::gm::GmTlsStream` bridge) migrated to
    `gm-tlcp/tests/integration_tlcp.rs`. The migration exposed two
    latent TLCP bugs that this commit also fixes:
    1. `TlcpStream::poll_read` GCM decrypt path was building the AAD
       from `seq || header (5 bytes)` instead of the symmetric
       `seq || header[0..3] || pt_len_bytes` that the encrypt side
       produces, AND was passing the explicit-nonce + body as a
       single `ct` to GCM (instead of the body alone, after stripping
       the 8-byte explicit nonce). Fixing the AAD and the split
       repairs in-memory `TlcpStream::new(... ECDHE_SM4_GCM_SM3)`
       round-trips that previously failed the GCM tag check.
    2. `connect_tlcp_with_context` / `accept_tlcp_with_context` (the
       simulated-helper paths the in-memory tests rely on) bypass
       the cert step, which now violates the post-PR5 state-machine
       invariant `derive_master_secret -> ServerCertsReceived | KeyExchange`.
       Both helpers install a placeholder cert pair so the invariant
       holds.

  Test-status after migration:
    - `gm-tlcp/tests/integration_tlcp.rs`: 32 pass / 5 ignored (the 5
      ignored ones were carrying pre-existing X.509 wiring bugs from
      the gm-tls copy; they need a real CA fixture to enable).
    - `gm-tlcp/tests/gmssl_interop.rs`: 4 pass / 7 ignored (unchanged).
    - `gm-tls` no longer has any TLCP-flavored integration test.
      Workspace-wide `cargo test --workspace` is green.

## [0.1.0] - 2026-04-14

### Added
- Initial release of gm-tls
- SM2/SM3/SM4 cryptographic primitives via gm-crypto
- GM/TLS handshake protocol implementation
- SM4-GCM record layer encryption/decryption
- Certificate chain validation (SM2 signatures)
- Finished message signing and verification
- mTLS (mutual TLS) support
- Async I/O support via Tokio
- Comprehensive test suite (141 tests)
- Fuzzing infrastructure
- Performance benchmarks
- Security assessment report
- GitHub Actions CI/CD

### Security
- Uses OS CSPRNG for key generation (OsRng)
- Constant-time signature verification
- GCM authentication before decryption

### Known Limitations
- `bincode` dependency is unmaintained (see RUSTSEC-2025-0141)
- No session resumption support
- No 0-RTT support
- Domain validation is case-insensitive only