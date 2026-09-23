# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`GmTlsConnector` URI host+port resolution** (PR-4.9 / P2-2 + P2-5):
  the connector now (a) rejects URIs without an explicit port when
  no `default_port` was configured (closing the silent-fallback-to-50051
  hole) instead of erroring out only after a 30-second connect
  timeout; (b) handles IPv6 literal hostnames (`http://[::1]:8080/`)
  by re-bracketing before building the connect string (the prior
  code's `format!("{}:{}", host, port)` produced an unparseable
  `::1:8080` for IPv6 hosts, hanging the connect attempt). Added
  `GmTlsConnector::with_default_port(u16)` builder for opt-in
  fallback; existing callers that always pass an explicit port
  see no behavior change. Added 13 unit tests in
  `pr49_uri_resolve_tests` covering IPv4 / IPv6 / hostname paths,
  default-port fallback, port-override-default precedence, and the
  silent-fallback regression guard. Bumps gm-tls to 0.2.5 (patch;
  the silent-fallback removal is a fail-fast improvement, not a
  breaking API change).

- **`GmTlsIncoming::local_addr()` no longer returns
  `Err(AddrNotAvailable)`** (PR-4.6 / P1-6): the implementation
  previously was a stub ("We need to reconstruct this - just return
  error for now"). tonic middleware depending on
  `ConnectInfo.local_addr` (rate limiting by local port, audit
  logging, Prometheus labels keyed on listener address) had no
  usable API. PR-4.6 captures the bound address at construction
  time (before the listener is moved into the inner stream) and
  returns it from `local_addr()`. Returns
  `Err(AddrNotAvailable)` only in the rare case where
  `TcpListener::local_addr()` itself failed at construction.
  Added `tests/gmssl_interop_tests.rs::pr46_local_addr_returns_bound_address`
  and `pr46_local_addr_consistent_across_calls` integration tests
  (bind 127.0.0.1:0, build `GmTlsIncoming`, verify
  `local_addr()` returns the bound address and is stable across
  multiple calls).

### Added

- **`TlsConfig::with_expected_uri(String)`** (PR-2.4): pins the peer
  cert's URI SAN (SPIFFE ID) per [`gm_crypto::x509::verify::validate_uri_only`].
  The check runs after the chain verification step and is orthogonal to
  the existing DNS-hostname `with_domain` builder — operators can pin
  both a hostname and a SPIFFE ID on the same peer (mTLS-to-SPIRE-SVID
  deployments).
- **`TlsConfig::with_distid_policy(DistidPolicy)`** (PR-2.4): overrides
  the SM2 signature distid policy (gm-crypto 0.3.5+). Default
  `None` retains `Strict` (only the GM/T standard distid
  `"1234567812345678"` is accepted). Pass
  `DistidPolicy::Permissive { fallback_distids: vec![""] }` for
  OpenSSL 3.x interop (which defaults to the empty SM2 distid).
- **`tests/spiffe_uri.rs`** (PR-2.4): end-to-end loopback handshake
  tests for the new builders — 4 tests covering exact-match,
  prefix-match, mismatch rejection, and policy-type surface.

### Changed

- **gm-tls now depends on `gm-crypto 0.3.6`** (was 0.3.3); this picks
  up the URI/SPIFFE ID parsing surface (`SpiffeId`, `UriMatchPolicy`,
  `validate_uri_only`) and the `DistidPolicy` enum used by the new
  builder. `gm-crypto` remains a path dep, so the workspace stays
  buildable offline.

### Fixed

- **Loopback tests re-enabled** (`tests/gmssl_interop_tests.rs`): the
  three `#[ignore]`'d PR-2.2 follow-ups (`test_loopback_handshake`,
  `test_loopback_echo_large_data`, `test_loopback_mutual_auth`) now
  run by default, opting into `DistidPolicy::Permissive{..}` for the
  OpenSSL-issued fixture (empty distid).

## [0.2.2] - 2026-09-18

### Fixed

- **SM2 signature / public-key OID byte sequences corrected
  to canonical DER** (1.2.156.10197.1.501 / 1.2.156.10197.1.301).
  The `der::SM2_SIG_OID` and `der::SM2_PK_OID` constants carried
  byte sequences that encoded a different OID (`1.2.26620389.*`)
  with a dangling continuation byte — a malformed OID per X.690.
  Fixed to the canonical GM/T 38636-2020 §6.4.6 encoding so the
  handshake emits `SignatureScheme: sm2withsm3` with a parsable
  AlgorithmIdentifier OID.

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
