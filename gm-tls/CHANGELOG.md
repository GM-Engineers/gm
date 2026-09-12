# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- README / README.en.md: documentation accuracy pass.
  - API Stability section now honestly states the crate is `< 1.0` and
    carries **no SemVer compatibility promise**; replaces the prior
    "will not introduce breaking changes within v0.x" claim that was
    false under SemVer semantics.
  - Performance Characteristics section removes the unreproducible
    µs / ns latency table; readers are pointed at `cargo bench --bench
    crypto_bench` instead, with the file's coverage area listed.
  - Added `accept_gm_rust_with_client_cert` to the public API listing
    (was missing from the README even though it shipped in 0.2.x).
  - Version string synced to `v0.2.1` (Cargo.toml).

## [0.2.1] - 2026-09-07

### Changed

- **Dependency bump**: `gm-crypto` requirement relaxed from `0.2.0`
  to `0.3` (caret range). No public API change in this crate.
  Required because `gm-crypto 0.3.0` adds the
  `Sm2EcdhKeypair::private_key_bytes()` method, which downstream
  callers (notably `gm-tlcp 0.2.2`'s `tlcp-strict` mode) need.

## [0.2.0] - 2026-09-05

**Headline change**: TLCP (GB/T 38636-2020) has been **extracted out of
`gm-tls`** into the standalone `gm-tlcp` crate. This is a **BREAKING
CHANGE** for any consumer that used `gm_tls::tlcp::*` or
`GmTlsStream::with_version(_, TLCP_VERSION_1_0)`. Under SemVer 0.x,
breaking changes bump the minor position, hence `0.1.0` → `0.2.0`.

Consumers of TLCP must now depend on the `gm-tlcp` crate directly:
```toml
[dependencies]
gm-tls = "0.2"
gm-tlcp = "0.1"
```

### Removed

- **BREAKING: TLCP support extracted out of `gm-tls`** into the
  standalone `gm-tlcp` crate (commit `28fbca1`). The TLCP protocol
  stack (handshake, record layer, dual-cert handling, session
  resumption, alert protocol) is no longer part in this crate. Code
  removals:
  - `gm-tls/src/tlcp.rs` deleted (~1600 LOC of pre-extraction TLCP
    code).
  - `gm-tls/Cargo.toml`: dropped the (now-circular) `gm-tlcp`
    dependency.
  - `gm-tls/tests/tlcp_integration_tests.rs` (1592 lines, the only
    in-workspace file that still imported `gm_tls::tlcp::*` and the
    broken `gm_tls::gm::GmTlsStream` bridge) migrated to
    `gm-tlcp/tests/integration_tlcp.rs`.
  - `gm_tls::tlcp::*` re-export shim removed outright (no deprecation
    cycle — the entire TLCP path moved out under the same major
    version).
  - `GmTlsStream::with_version(_, TLCP_VERSION_1_0)` bridge removed.

  Two **latent** TLCP bugs were exposed by the migration and fixed in
  the same commit:
  1. `TlcpStream::poll_read` GCM decrypt path was building the AAD
     from `seq || header (5 bytes)` instead of of the symmetric
     `seq || header[0..3] || pt_len_bytes` that the encrypt side
     produces, AND was passing the explicit-nonce + body as a
     single `ct` to GCM (instead of the body alone, after stripping
     the 8-byte explicit nonce). Fixing the AAD and the split
     repairs in-memory `TlcpStream::new(... ECDHE_SM4_GCM_SM3)`
     round-trips that previously failed the GCM tag check.
  2. `connect_tlcp_with_context` / `accept_tlcp_with_context` (the
     simulated-helper paths the in-memory tests rely on) bypass
     the cert step, which now violates the post-PR5 state-machine
     invariant `derive_master_secret -> ServerCertsReceived |
     KeyExchange`. Both helpers install a placeholder cert pair
     so the invariant holds.

  **Note on inert surface**: two non-functional references to
  TLCP remain in `gm-tls/src/der.rs`:
  - `pub const VERSION_TLCP_1_0: [u8; 2] = [0x01, 0x01];`
  - `pub enum ProtocolVersion { ..., TLCP1_0 }`
  These are **inert type declarations** with no protocol code
  behind them. They are intentionally retained for protocol
  detection use cases (network monitoring, log analysis) that
  need to distinguish TLS 1.3 records from TLCP records without
  depending on the full TLCP stack. Removing them would be an
  additional breaking change for those users, with no functional
  benefit.

- **`bincode` dependency** (was flagged unmaintained, see
  [RUSTSEC-2025-0141](https://rustsec.org/advisories/RUSTSEC-2025-0141)).
  Replaced by [`postcard`](https://crates.io/crates/postcard) for
  in-process session-ticket serialization. No public API change;
  the swap is transparent to consumers.

### Changed

- **Cargo.toml `description`**: updated from
  `"GM/TLS (国密TLS) core library with SM2/SM3/SM4 support"` to
  `"TLS 1.3 core library with SM (国密) cipher suites — SM2/SM3/SM4,
  optional gRPC integration. TLCP (GB/T 38636-2020) lives in the
  standalone gm-tlcp crate."`. The old string implied TLCP was
  still in this crate.
- **Cargo.toml `keywords`**: updated from
  `["tls", "gmtls", "gm", "sm2", "cryptography"]` to
  `["tls13", "sm2", "sm3", "sm4", "cryptography"]`
  (5 entries, the crates.io maximum). The `"gmtls"` term was
  ambiguous post-split; `"tls"` alone was too generic; `"tls13"`
  and `"tls1.3"` were redundant (kept the more-searchable
  `"tls13"`).
- **Dependency requirement**: `gm-crypto` bumped from `0.1` → `0.2`
  in `gm-tls/Cargo.toml`. gm-crypto 0.2.0 is fully
  backwards-compatible per SemVer, so this is not a breaking
  change.

### Dependencies

- `gm-ca` and `gm-http-client` (workspace members that depend on
  this crate) have had their `gm-tls = "..."` version requirement
  bumped from `"0.1.0"` to `"0.2.0"` in their local Cargo.toml.
  No published version of `gm-ca` or `gm-http-client` is being
  released alongside this — only the workspace-local source is
  updated, so they will pick up gm-tls 0.2.0 on their next
  release.

### Test status (gm-tls 0.2.0)

- 14 lib unit tests pass
- 6 integration test files: 159 pass / 12 ignored (sqlite + property
  fixtures require running infrastructure)
- 5 doctests pass / 3 ignored
- Total: **175 pass / 0 fail / 15 ignored**
- `cargo +nightly clippy --all-targets`: clean (no warnings)
- `cargo build --release`: clean
- `cargo doc --no-deps`: clean

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
[Unreleased]: https://github.com/GM-Engineers/gm/compare/main...HEAD
[0.2.1]: https://github.com/GM-Engineers/gm/compare/gm-tls-v0.2.0...gm-tls-v0.2.1
[0.2.0]: https://github.com/GM-Engineers/gm/releases/tag/gm-tls-v0.2.0
