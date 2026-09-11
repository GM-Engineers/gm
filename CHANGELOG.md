# Changelog

All notable changes to the GM cryptographic library suite.

## [Unreleased]

### Changed

- **Dependabot (`ci(dependabot): ignore major bumps`)** — added
  `ignore:` entries in `.github/dependabot.yml` for `redis >= 0.27`,
  `deadpool-redis >= 0.18`, and `rand_core >= 0.7`. The bumps cross
  more than one minor and touch either cryptographic RNG paths
  (`rand_core`, used in `gm-crypto` / `gm-tls` / `gm-tlcp` for
  handshake random, SM2 ephemeral keygen, IVs / nonces, PMS) or the
  `redis-rs` API surface (`redis` 0.27 was a major break). Each is
  bumped manually in a dedicated PR with KAT / interop regression
  evidence. PRs #24 / #25 / #26 (the weekly Dependabot bumps that
  failed CI for these reasons) are auto-closed by Dependabot when
  this change reaches `main`.

### Added

#### `gm-ca` 0.2.0

- **`CertProfile`** (in `gm_ca::cert_profile`) — declarative spec
  for what extensions a cert should carry. Presets:
  `CertProfile::default`, `server_end_entity`, `client_end_entity`,
  `intermediate_ca`, `root_ca`.
- **`CaSigner::sign_csr_with_profile(csr, days, &profile)`** —
  replaces the v0.1.x `sign_csr(csr, days)`. Default profile
  reproduces the v0.1.x wire-format extension set.
- **`CaSigner::renew_certificate_with_profile(cert_pem, days, &profile)`**
  — replaces the v0.1.x `renew_certificate(cert_pem, days)`.
- **`CaSigner::self_sign_ca(days, &profile)`** — new method for
  self-signing the CA cert (trust anchor). Default profile is
  `CertProfile::root_ca()` (`keyCertSign | cRLSign` +
  `BasicConstraints CA:TRUE`).
- **AuthorityKeyIdentifier** emitted by default on every cert —
  `keyIdentifier = SM3(CA pubkey)[:20]` per RFC 7093 Method 1.
  Required by GmSSL master for TLCP chain walks.
- **BasicConstraints emitted by default** — `CA:FALSE` for end-entity
  certs, `CA:TRUE` (with optional `pathLenConstraint`) for CA certs.

### Breaking

- **`gm-ca` 0.2.0** — `CaSigner::sign_csr` removed (use
  `sign_csr_with_profile`), `CaSigner::renew_certificate` removed
  (use `renew_certificate_with_profile`). Old methods are removed,
  not deprecated.

## [0.3.0] - 2026-09-05

**Headline change**: TLCP (GB/T 38636-2020) has been **extracted out of
`gm-tls`** into its own standalone `gm-tlcp` crate. The `gm-crypto` crate
shipped a patch release (0.2.0) with three new building-block APIs that
`gm-tlcp` depends on. The workspace also received comprehensive docs,
a CI rewrite of the GmSSL interop setup, and 20 commits.

### Added

#### Standalone `gm-tlcp` crate (0.1.0)

- **New crate at `gm/gm-tlcp/`**, published to crates.io as
  `gm-tlcp = 0.1.0`. Depends on `gm-crypto >= 0.2`.
- Full TLCP handshake state machine (client + server, 9 message
  types: `ClientHello`, `ServerHello`, `ServerKeyExchange`,
  `ServerHelloDone`, `CertificateVerify`, `ClientKeyExchange`,
  `Certificate`, `Finished`, `ServerFinished`).
- All four cipher suites:
  `TLS_ECDHE_SM4_GCM_SM3` (`0xE051`),
  `TLS_ECDHE_SM4_CBC_SM3` (`0xE011`),
  `TLS_ECC_SM4_GCM_SM3` (`0xE053`),
  `TLS_ECC_SM4_CBC_SM3` (`0xE013`).
- SM2 ECDHE key agreement per GB/T 32918.3-2016.
- SM3-based PRF (RFC 5246 §5 `P_hash`, SM3 replacing the SHA-256
  family used in TLS 1.3).
- SM4-GCM and SM4-CBC + HMAC-SM3 record-layer encryption.
- Mandatory **dual-certificate** model (sign cert + enc cert).
- Session resumption: `TlcpSessionCache` + `TlcpResumedSession`.
- Alert protocol: `TlcpAlert` / `TlcpAlertLevel` / `TlcpAlertDescription`.
- High-level API: `TlcpConnector::new().connect(...)`,
  `TlcpAcceptor::new().accept(...)` mirroring the `rustls` API.
- Async `AsyncRead + AsyncWrite` via `tokio` traits.
- 58 lib unit tests + 32 integration tests + 4 default GmSSL
  interop tests (7 more `#[ignore]`-gated, run with `--ignored`
  when `gmssl` is on `PATH`) + 8 doctests + 4 fuzz harnesses.
- Comprehensive rustdoc, bilingual quickstart guide
  (`docs/gm-tlcp.md` + `docs/gm-tlcp.en.md`).
- README + README.en.md (English translation added).

#### `gm-crypto` 0.2.0

- **`Sm4Cipher::encrypt_cbc_raw` / `decrypt_cbc_raw`** — SM4 CBC
  mode **without PKCS#7 padding**, for protocols that manage
  padding themselves (TLCP MAC-then-Encrypt, TLS 1.1 CBC). The
  standard `encrypt_cbc` is left untouched for users who want
  PKCS#7 padding.
- **`x509::extract_sm2_pubkey_from_der`** — extract the raw SM2
  public key bytes (65 bytes SEC1) from a DER-encoded X.509
  certificate. From-scratch implementation, defensive against the
  GmSSL-emitted SPKI BIT STRING quirk (non-zero trailing-bits
  count) that causes off-the-shelf `x509-parser` to emit key
  bytes that the SM2 key constructors reject.

#### GmSSL Interoperability (gm-tls)

Carried over from the previous `[Unreleased]` section:

- **7/7 GmSSL interop tests passing**: TLS 1.3 handshake, TLCP
  connectivity, bidirectional client/server, loopback self-tests.
- **GmSSL server daemons**: launchd plist
  (`com.gm.interop.plist`) auto-restarts GmSSL single-connection
  servers:
  - TLS 1.3 server: port **4434** (`gmssl tls13_server`)
  - TLCP server: port **4433** (`gmssl tlcp_server` with
    dual-cert PKI chain)
- **GmSSL client→gm-tls**: GmSSL `tls13_client` subprocess
  spawned from test, connects to gm-tls server (port 4435).
- **TLCP dual-cert PKI**: proper `sign_cert + enc_cert + ca_cert`
  chain format for GmSSL `tlcp_server`.
- **Retry + timeout helpers**: `tcp_connect_with_retry()`
  (5x, exponential backoff), 2s read timeout.
- Test env vars: `TEST_GMSLL_PORT`, `TEST_GMSLL_CERT`,
  `TEST_GMSLL_KEY`, `TEST_GMSLL_BIN`.

#### Project governance

- `.github/ISSUE_TEMPLATE/{bug_report,security,feature_request}.yml`
- `.github/PULL_REQUEST_TEMPLATE.md` (8-section checklist)
- `CHANGELOG.md` at the workspace root.

### Changed

#### Breaking — `gm-tls` TLCP support removed

- `gm-tls/src/tlcp.rs` deleted. The TLCP code is in
  `gm-tlcp/src/tlcp/` (under commit `28fbca1`).
- `gm-tls/Cargo.toml`: dropped the (now-circular) `gm-tlcp`
  dependency.
- `gm-tls/tests/tlcp_integration_tests.rs` (1592 lines) migrated
  to `gm-tlcp/tests/integration_tlcp.rs`. Two latent TLCP bugs
  fixed in the migration:
  1. `TlcpStream::poll_read` GCM decrypt path was building the
     AAD from `seq || header (5 bytes)` instead of the symmetric
     `seq || header[0..3] || pt_len_bytes`. Also was passing the
     explicit nonce + body as a single `ct` to GCM instead of the
     body alone. Fixing the AAD and the split repairs in-memory
     `TlcpStream::new(... ECDHE_SM4_GCM_SM3)` round-trips that
     previously failed the GCM tag check.
  2. `connect_tlcp_with_context` / `accept_tlcp_with_context`
     bypassed the cert step, which violated the post-PR5
     state-machine invariant
     `derive_master_secret -> ServerCertsReceived | KeyExchange`.
     Both helpers now install a placeholder cert pair so the
     invariant holds.

#### `gm-tls` Cargo.toml metadata

- `description` updated from
  `"GM/TLS (国密TLS) core library with SM2/SM3/SM4 support"` to
  `"TLS 1.3 core library with SM (国密) cipher suites —
  SM2/SM3/SM4, optional gRPC integration. TLCP (GB/T 38636-2020)
  lives in the standalone gm-tlcp crate."` — the old string
  implied TLCP was still in this crate.
- `keywords` updated from
  `["tls", "gmtls", "gm", "sm2", "cryptography"]` to
  `["tls13", "tls1.3", "sm2", "sm3", "sm4", "cryptography"]`.
  The `"gmtls"` term was ambiguous post-split; `"tls"` alone was
  too generic.

#### Workspace docs

- Top-level `README.md` (English) and `README.zh-CN.md`
  (Chinese) rewritten to:
  - Include `gm-tlcp` in the directory tree, crate overview
    table, and documentation nav table.
  - Switch 7 documentation-table links to the `.en.md` variants
    (the plain `.md` files are Chinese; this convention is the
    same as every other crate in the workspace).
  - Bump the `Cargo.toml` example from `gm-crypto = "0.1"` to
    `gm-crypto = "0.2"`, add `gm-tlcp = "0.1"`.
  - Update the **Third-Party Components** section to enumerate
    which files in `gm-crypto` are wrappers vs hand-rolled (the
    old text claimed it was all "thin wrappers" which is no
    longer true).
- `SECURITY.md` / `SECURITY.zh-CN.md`: `LRU` → `FIFO` typo
  fixed (the actual cache strategy in `gm-tls` is FIFO, the
  doc claimed LRU).
- `gm-tls/CHANGELOG.md` cross-link to ADR-001 fixed.

### Removed

- **`bincode` dependency from `gm-tls`** (was flagged unmaintained,
  [RUSTSEC-2025-0141](https://rustsec.org/advisories/RUSTSEC-2025-0141)).
  Replaced by [`postcard`](https://crates.io/crates/postcard) for
  in-process session-ticket serialization. No public API change.

### Security

#### `gm-tlcp` independent audit

- 4-pass independent security audit pre-release, recorded in
  commit `7b274ad`:
  1. Pre-master-secret secret-zeroize on disconnect (Drop impl).
  2. Constant-time signature / MAC / HMAC / Finished comparison
     (`subtle::ConstantTimeEq`).
  3. GCM nonce-reuse detection — emits fatal
     `TlcpError::NonceReuse` and zeroizes the connection.
  4. Transcript-boundary cross-check: every `Finished`
     computation re-hashes the full transcript to detect
     message-order tampering.
- All sensitive types implement `Drop` zeroization
  (`SessionKeys`, `TlcpKeyMaterial`, `TlcpHandshake`,
  `TlcpEcdheContext`, `TlcpResumedSession`).
- PMS was leaked to `stderr` via `eprintln!` in a debug call
  site; removed (commit `56dd223`).
- CV self-verify now returns `Err` on signature mismatch
  (previously `Ok(())`).

#### Interop verification

- **GmSSL 3.2.0** — all 4 cipher suites byte-for-byte round-trip.
- **GmSSL 3.3.0-dev master** (`1183+`) — same, plus the new
  client-certificate-mandatory path.
- **Tongsuo 8.3.0** — not yet passing. Tongsuo's NTLS state
  machine rejects the TLCP version byte `0x0101`. Tracked under
  `gm-tlcp/interop/tongsuo/upstream/`.

### Fixed

#### CI — GmSSL install step rewrite

The `gmssl` install step in `.github/workflows/ci.yml` was
unreliable across the CI runners (Docker symlink handling,
permission race, etc). Replaced over a 5-attempt fix sequence:

1. `d97b94c` — `sudo mv` of `docker cp` output.
2. `5a968c2` — `docker run cat | sudo tee` to dodge symlink
   mishandling in `docker cp`.
3. `a121113` — `apt-get install gmssl` first, Docker tarball
   extraction as fallback.
4. `b460df9` — wrapper script that `exec`s `docker run`.
   Introduced a YAML heredoc indentation bug that surfaced as
   a 0-jobs visible workflow (`2cfb1ef`).
5. `3ddbdf3` — wrapper script + `continue-on-error: true`
   for the `gmssl` step. **Final form**; all 7 CI jobs green.

#### Nightly clippy

- 12 nightly-clippy warnings auto-fixed via
  `cargo +nightly clippy --fix`. 1 manually added
  `#[allow(dead_code)]` for symmetric struct fields. CI now
  passes `cargo +nightly clippy --workspace --all-targets`.

#### Source-tree hygiene

- `docs/gm-tlcp.md` and `docs/gm-tlcp.en.md` **new** (bilingual
  quickstart guide).
- `gm-tlcp/README.en.md` **new** (English translation).
- `gm-tlcp/CHANGELOG.md` **new** (Keep-a-Changelog format).

### Dependencies

- `gm-crypto` dependency bumped from `0.1` → `0.2` across
  `gm-ca`, `gm-sm9-rs`, `gm-tlcp`, `gm-tls` (no actual API
  change for any of them — the bump only matters for crates
  that consume the new 0.2 APIs, which is just `gm-tlcp`).

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
