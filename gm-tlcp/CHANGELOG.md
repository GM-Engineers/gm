# Changelog

All notable changes to the `gm-tlcp` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-04

First standalone release of `gm-tlcp`, extracted from `gm-tls`.
See commit [`28fbca1`](https://github.com/GM-Engineers/gm/commit/28fbca1)
for the extraction itself and the public API baseline.

### Added

#### Crate structure
- **`gm-tlcp` standalone crate**: TLCP (GB/T 38636-2020) implementation in pure
  Rust with zero dependency on `gm-tls`. The previous `gm_tls::tlcp::*`
  re-export shim and `GmTlsStream::with_version(..., TLCP_VERSION_1_0)` bridge
  in `gm-tls` have been removed outright (no deprecation cycle — the entire
  TLCP path moved out under the same major version of `gm-tls`).

#### TLCP handshake (GB/T 38636-2020)
- Full client + server handshake state machine covering all 9 handshake
  message types: `ClientHello`, `ServerHello`, `ServerKeyExchange`,
  `ServerHelloDone`, `Certificate`, `ClientKeyExchange`, `CertificateVerify`,
  `Finished`, `CertificateRequest`.
- SM2 ECDHE key agreement per GB/T 32918.3-2016 §6.4.2
  (`compute_tlcp_ecdhe_pms`).
- SM3-based PRF per RFC 5246 §5 P_hash (adapted for SM3).
- Dual-certificate handling: separate SM2 signing and encryption
  certificate chains (a TLCP requirement distinct from TLS 1.3's single
  certificate).
- ECDHE and static ECC suites both supported.

#### TLCP record layer
- SM4-GCM and SM4-CBC + HMAC-SM3 record-layer encryption and authentication.
- Correct CBC padding per RFC 5246 §6.2.3.2 / GB/T 38636-2020 §6.2.3.2
  (verified against `gmssl tlcp_server` master byte-for-byte — see
  `GmSSL-fixed-bugs-summary.md` in `interop/tongsuo/upstream/`).
- Async `AsyncRead + AsyncWrite` via `tokio` I/O traits
  (`TlcpStream<S>` is generic over the transport).

#### Session resumption
- `TlcpSessionCache` with FIFO eviction (default 1024 sessions, 24 h TTL)
  and per-entry `TlcpResumedSession` state. `TlcpResumeResult` enum
  distinguishes `Resumed`, `New`, and `Rejected` outcomes.

#### Errors & alerts
- `TlcpError` enum with `#[non_exhaustive]` attribute. Variants cover
  handshake failures, I/O errors, sequence overflow, parse errors, GCM
  nonce reuse (the catastrophic-failure variant), record-layer errors,
  invalid handshake types / messages, and invalid state transitions.
- `TlsError` type alias preserved for source-level compatibility with
  pre-split `gm-tls` consumers.
- `TlcpAlert` / `TlcpAlertLevel` / `TlcpAlertDescription` model the
  alert protocol messages.

#### Examples & docs
- `examples/simple_client.rs` / `simple_server.rs` — minimal end-to-end
  TLCP request/response.
- `examples/interop_client.rs` — interoperability CLI driven by env vars.
- `examples/interop_proxy.rs` — middleware-style proxy harness.
- `examples/pms_kat.rs` — Known-Answer Test for the PMS derivation
  (marked ⚠️ TEST ONLY).
- `PUBLISHING.md` — maintainer-facing notes on `cargo package` /
  crates.io publish mechanics.

### Interop verified

- **GmSSL 3.2.0** (released) — handshake + APP_DATA byte-for-byte
  round-trip verified for all 4 cipher suites.
- **GmSSL 3.3.0-dev master (`1183+`)** — same as above, plus
  double-signed CertificateVerify path (`client_certificate_verify = 1`
  enforced by master per 2026-06 server-side change).
- **Tongsuo 8.3.0** — open investigation in `interop/tongsuo/upstream/`
  (Tongsuo-side NTLS state-machine rejects the TLCP version byte
  `0x0101`; tracked separately).

### Testing

- 58 lib unit tests
- 32 integration tests (`tests/integration_tlcp.rs`)
- 4 default GmSSL interop tests, with 7 more `#[ignore]`-gated that
  require `gmssl` on `PATH` and run with `cargo test -- --ignored`
- 8 doctests
- 4 fuzz harnesses (`cargo +nightly fuzz run <target>`)

### Security

- 4-pass independent security audit performed pre-release (see commit
  `7b274ad`). Audit covered:
  1. PMS / master-secret / key-material lifecycle (zeroize-on-Drop)
  2. Constant-time comparison for signature / MAC / HMAC / Finished
  3. Record-layer framing edge cases (CBC padding off-by-one regression
     tests now in `cbc_record_roundtrip_various_plaintext_lengths`)
  4. Transcript ordering, CertificateVerify SM2 hash binding, and
     interop-correctness vs gmssl
- All four audit passes passed without findings requiring code changes
  beyond the bug fixes documented under `Bug fixes` below.

### Bug fixes (carried over from the gm-tls → gm-tlcp migration)

- `TlcpStream::poll_read` GCM decrypt path was building the AAD from a
  stale ciphertext slice — corrected.
- CBC explicit-IV copy-in was reading 17 bytes instead of 16 in some
  handshake paths — corrected.
- `TlcpFinished::verify_data` was not being reset across session
  resumption; now re-derived per handshake.

[Unreleased]: https://github.com/GM-Engineers/gm/compare/main...HEAD
[0.1.0]: https://github.com/GM-Engineers/gm/releases/tag/gm-tlcp-v0.1.0
