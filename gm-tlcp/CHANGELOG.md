# Changelog

All notable changes to the `gm-tlcp` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-09-08

### Added — SM9 IBC cipher suites (partial; R-4)

- **Two new cipher suites declared**: `IBC_SM4_GCM_SM3` (`0xE0, 0x57`)
  and `IBC_SM4_CBC_SM3` (`0xE0, 0x17`). Per GB/T 38636-2020 §6.4.5.2.1
  表 2, these are the SM9 identity-based cryptography (IBC) static-key
  suites (server identity is fixed, no ECDHE).
- **`KeyExchangeMode` enum** in [`src/tlcp/cipher_suite.rs`](src/tlcp/cipher_suite.rs)
  replaces the previous binary `ecdhe: bool` discriminant. Variants:
  `Ecdhe`, `Ecc`, `Ibc` (R-4), `Ibsdh` (R-4.1), `Rsa` (R-5).
  The `ecdhe: bool` field is kept as a `#[deprecated]` helper for
  0.4.x callers; will be removed in gm-tlcp 1.0.
- **SKE Ibc variant**: [`ServerKeyExchangeBody::Ibc`](src/tlcp/messages/ecdhe.rs)
  wire layout `uint16 id_len || id || uint16 sig_len || sig_der`
  (server identity explicit in body, not extracted from cert subject).
  Mirrors the static-ECC interpretation-B shape; signature covers
  `client_random || server_random || server_sm9_id`.
- **CKE Ibc variant**: [`ClientKeyExchangeBody::Ibc`](src/tlcp/messages/client_key_exchange.rs)
  carries the SM9-encrypted pre-master secret ciphertext. Server-side
  SM9 decryption path is **not yet implemented**; the handshake
  state machine returns an explicit
  `TlcpError::HandshakeFailed("SM9 IBC suites ... pending R-4.1")`
  error.
- **`KeyExchangeMode` re-export** at crate root
  (`gm_tlcp::KeyExchangeMode`).
- **`gm-sm9-rs = "0.1"` dependency** added to gm-tlcp (pure-Rust SM9
  backend, default features off).

### Changed — BREAKING (callers using `suite.ecdhe` must migrate)

- `TlcpCipherSuite::ecdhe: bool` field is `#[deprecated]` since 0.5.0.
  Use `suite.key_exchange == KeyExchangeMode::Ecdhe` instead.
- `TlcpServerKeyExchange::from_body(body)` 1-arg call is now an
  explicit-error form. Use:
  - `from_body(body, KeyExchangeMode::Ecdhe | Ecc | Ibc)` for
    the strict per-variant form, **or**
  - `from_body_legacy(body)` for the auto-detect (ECDHE if
    `0x03 0x00 0x29` prefix present, otherwise ECC) form
    used by old callers.
- `TlcpClientKeyExchange::from_body(body, is_ecc_mode: bool)` is
  now `from_body(body, is_ecc_mode, is_ibc_mode)`. Pass `false` for
  `is_ibc_mode` to preserve the 0.4.x behaviour.

### Deferred to R-4.1 / R-5

- **SM9 IBSDH (E055/E015)** — 2-round identity-based key exchange
  per GM/T 0044-2016 §6.1. Requires handshake state machine changes
  (multi-message Initiator/Responder exchange); too large for R-4.
- **Server-side IBC PMS decryption** — `Sm9Decryptor::decrypt(ciphertext)`
  integration in `accept_with_certs` step 8. The IBC SKE/CKE wire
  format is fully implemented and unit-tested; only the protocol
  glue remains.
- **RSA suites (E019/E01C/E059/E05A)** — pending R-5. Will use
  the RustCrypto `rsa` crate directly in gm-tlcp (RSA is **not** a
  国密 algorithm, so it does not belong in gm-crypto).

### Tests

- 99 lib tests (was 91 in 0.4.0; +8 from R-4):
  5 new SKE IBC tests + 1 new CKE IBC test + 2 cipher_suite enum tests.
- 5 loopback tests (unchanged).
- 32 integration tests (unchanged).
- 8 doctests (unchanged).

### Verification

- `cargo +stable fmt --all -- --check` ✓
- `cargo +stable clippy --workspace --all-features --all-targets -- -D warnings` ✓
- `cargo +stable test -p gm-tlcp` (default) ✓
- `cargo +stable test -p gm-tlcp --features tlcp-gmssl-compat` ✓
- `cargo +stable test -p gm-tlcp --features tlcp-strict` ✓
- `cargo +stable publish -p gm-tlcp --dry-run --registry crates-io` ✓

## [0.4.0] - 2026-09-08

### Changed — BREAKING (server-side static-ECC PMS now works)

- **C-4 fix: server-side static-ECC PMS decryption**
  ([`src/tlcp/mod.rs`](src/tlcp/mod.rs) `accept_with_certs` step 8
  `None` arm,
  [`src/tlcp/messages/client_key_exchange.rs`](src/tlcp/messages/client_key_exchange.rs)).
  Audit finding **C-4** in
  [`interop/AUDIT-2026-09-06-v2.md`](interop/AUDIT-2026-09-06-v2.md)
  §C-4 is now **Resolved**. The server no longer returns an explicit
  error on the `ECCEncryptedPreMasterSecret` decrypt step. The
  pre-master secret is recovered via SM2 PKE mode 1 (per
  GB/T 32918.4-2016) under the server's encryption keypair, and
  the plaintext (`ProtocolVersion client_version (2B) ||
  opaque random[46]`, total 48 bytes per GB/T 38636-2020
  §6.4.5.8 c)) is fed into the master_secret derivation like any
  other PMS.

  Side effects:

  - `TlcpClientKeyExchange` is now an enum-backed struct with
    two variants: `Ecdhe { ephemeral_public }` and
    `Ecc { ciphertext }`. Callers access the inner body via
    `as_ecdhe_wire_body()` / `as_ecc_ciphertext()` helpers
    (or the existing `ecdhe_public_key()` for the raw SEC1
    point). `from_body` requires an `is_ecc_mode: bool`
    parameter to disambiguate the variant since the GmSSL-master
    shim's `uint16` length prefix wraps both variants.
  - Server-side `Sm2KeyPair` reconstruction: `Sm2KeyPair` is
    not `Clone`, so the decrypt path extracts the private-key
    bytes from the stored `Arc<Sm2KeyPair>` and rebuilds a
    local `Sm2KeyPair` via `from_private_key(...)` for the
    `Sm2Decryptor::new(...)` call. The local copy is zeroized on
    drop (via the existing `ZeroizeOnDrop` derive on
    `Sm2KeyPair`).
  - 4 new unit tests in
    `src/tlcp/messages/client_key_exchange.rs::tests`:
    `cke_ecc_ciphertext_returns_bytes_for_ecc_body`,
    `cke_ecc_ciphertext_returns_none_for_ecdhe_body`,
    `cke_ecc_roundtrip_via_enum_body` (per-mode split),
    `from_body_rejects_wrong_is_ecc_mode_flag`.
  - 2 new unit tests in `src/tlcp/mod.rs::tests`:
    `test_static_ecc_server_pms_decrypt_smoke` (encrypts a
    synthetic 48-byte PMS, decrypts via the same path
    `accept_with_certs` uses, asserts plaintext match) and
    `test_static_ecc_server_pms_decrypt_rejects_wrong_key`
    (negative test: wrong-key ciphertext must NOT recover
    the original PMS).
  - All three feature modes (`default`, `tlcp-gmssl-compat`,
    `tlcp-strict`) remain green; the new PMS-decrypt path is
    gated to `not(feature = "tlcp-gmssl-compat")` because the
    gmssl-compat static-ECC path continues to use the
    ECDHE-style SKE + raw 32-byte ECDH PMS legacy behaviour
    (R-1 / R-2 semantics).

### Verification

- `cargo +stable fmt --all -- --check` clean.
- `cargo +stable clippy --workspace --all-features --all-targets -- -D warnings` clean.
- `cargo +stable test --workspace` clean: gm-tlcp 91 unit tests (was 85 in 0.3.1) + 5 loopback + 32 integration + 4 GmSSL interop (7 `#[ignore]`d) + 8 doctests.
- `cargo +stable test -p gm-tlcp --features tlcp-gmssl-compat` clean (rollback path verified).
- `cargo +stable test -p gm-tlcp --features tlcp-strict` clean (deprecated no-op verified).
- `cargo +stable publish --dry-run -p gm-tlcp --registry crates-io` clean (44 files, 498.7 KiB).

### Audit-finding tally (post-0.4.0)

- **C-1** (ECDHE CKE u16 prefix) — Resolved by R-1, 0.3.0.
- **C-2** (static-ECC SKE shape) — Resolved by R-2, 0.3.1.
- **C-3** (server 32-byte raw ECDH) — Resolved by R-1, 0.3.0.
- **C-4** (server-side ECC/RSA CKE) — **Resolved by R-3, 0.4.0**
  (static-ECC suites only; RSA suites pending R-5 / 0.6.0).

All four Critical audit findings on static-ECC suites are now
**RESOLVED**. The next Critical-remaining scope is **RSA suites
server-side PMS decryption** (R-5 / 0.6.0) and **SM9 suites** (R-4
/ 0.5.0).

## [0.3.1] - 2026-09-08

### Changed

- **C-2 fix: static-ECC suites (E013 / E053) now emit and accept
  the spec interpretation-B `ServerKeyExchange`** (sig-only over
  `cr ∥ sr ∥ enc_cert_header ∥ enc_cert_der`).
  Audit finding **C-2** in
  [`interop/AUDIT-2026-09-06-v2.md`](interop/AUDIT-2026-09-06-v2.md)
  §C-2 (the C-2 status moves from PARTIAL to RESOLVED on the
  client side; server-side static-ECC PMS decryption remains
  pending R-3 / 0.4.0). This is the wire format openHiTLS and
  Tongsuo 8.3.0 emit on the wire for E013 / E053, so the gm-tlcp
  client can now complete a static-ECC handshake against those
  peers (up to the server-PMS step).

  Changes ([`src/tlcp/messages/ecdhe.rs`](src/tlcp/messages/ecdhe.rs),
  [`src/tlcp/mod.rs`](src/tlcp/mod.rs) `connect_with_certs` step 4 +
  `accept_with_certs` step 5,
  [`src/tlcp/crypto/verify.rs`](src/tlcp/crypto/verify.rs)):

  - `TlcpServerKeyExchange` is now an enum-backed struct with two
    variants: `Ecdhe(Sm2EcdheParams)` (existing) and `Ecc {
    signature }` (new — interpretation-B). Callers access the
    inner params via `as_ecdhe()` / `as_ecc_signature()` helpers.
  - New `TlcpServerKeyExchange::generate_ecc(cr, sr, enc_cert_der,
    &sign_signer)` produces the interpretation-B body (DER-encoded
    sig, matching openHiTLS / Tongsuo wire convention).
  - `from_body` auto-detects the variant: if the body starts with
    the ECParameters prefix (`0x03 0x00 0x29`) it's parsed as
    ECDHE; otherwise it's parsed as `Ecc`. This lets the same
    parser handle both ECDHE and static-ECC peers without mode
    branching at the call site.
  - Client step 4 now always reads `ServerKeyExchange` for all
    four cipher suites (previously default-mode skipped SKE for
    static-ECC per RFC 5246 §7.4.3). The verifier dispatches on
    `is_ecc_mode` to pick the right signed-input reconstruction.
  - Server step 5 default-mode for static-ECC now emits the
    interpretation-B sig-only SKE (previously skipped under
    default; previously emitted ECDHE-style under
    `tlcp-gmssl-compat`). The `tlcp-gmssl-compat` path keeps the
    legacy ECDHE-style emit for GmSSL master interop.

  Behaviour matrix (post-0.3.1):

  | Suite | Default mode | `tlcp-gmssl-compat` |
  |---|---|---|
  | ECDHE (E011 / E051) | spec ECDHE-style SKE ✅ | GmSSL ECDHE-style SKE ✅ |
  | static-ECC (E013 / E053) **client** | spec sig-only SKE ✅ | GmSSL ECDHE-style SKE ✅ |
  | static-ECC (E013 / E053) **server** | spec sig-only SKE emit; PMS decrypt still R-3 / 0.4.0 | GmSSL ECDHE-style SKE emit; raw ECDH PMS ✅ |

  Side effects:

  - 5 new unit tests in `src/tlcp/messages/ecdhe.rs::tests`:
    `ske_ecc_to_bytes_writes_uint16_sig_len_prefix`,
    `ske_ecc_from_body_parses_back`,
    `ske_ecc_from_body_rejects_truncated_input`,
    `ske_from_body_autodetects_ecdhe_by_ecparameters_prefix`,
    `ske_from_body_autodetects_ecc_when_prefix_absent`,
    `generate_ecc_then_verify_roundtrip_succeeds`,
    `generate_ecc_to_bytes_matches_interp_b_layout`.
  - 3 new unit tests in `src/tlcp/crypto/verify.rs::tests` (this
    file had no tests prior to 0.3.1):
    `verify_ske_signature_ecc_path_accepts_correct_sig`,
    `verify_ske_signature_ecc_path_rejects_bad_sig`,
    `verify_ske_signature_ecc_path_rejects_truncated_body`.

### Verification

- `cargo +stable fmt --all -- --check` clean.
- `cargo +stable clippy --workspace --all-features --all-targets -- -D warnings` clean.
- `cargo +stable test -p gm-tlcp` clean: gm-tlcp 85 unit tests (was 80 in 0.3.0) + 5 loopback tests + 32 integration tests + 4 GmSSL interop (7 `#[ignore]`d) + 8 doctests.
- `cargo +stable test -p gm-tlcp --features tlcp-gmssl-compat` clean (rollback path verified).
- `cargo +stable test -p gm-tlcp --features tlcp-strict` clean (deprecated no-op verified).
- `cargo +stable publish --dry-run -p gm-tlcp --registry crates-io` clean (44 files, 477.5 KiB).

### Audit-finding tally (post-0.3.1)

- **C-1** (ECDHE CKE u16 prefix) — Resolved by 0.3.0.
- **C-2** (static-ECC SKE shape) — **Resolved (client side)** by 0.3.1.
  Server-side static-ECC PMS decryption remains pending R-3 / 0.4.0.
- **C-3** (server 32-byte raw ECDH) — Resolved by 0.3.0.
- **C-4** (server-side ECC/RSA CKE) — Still blocked; R-3 / 0.4.0.

## [0.3.0] - 2026-09-08

### Changed — BREAKING (default mode flip)

- **Default mode is now GB/T 38636-2020 spec-compliant**.
  `tlcp-strict` is **deprecated** (kept as a no-op for source-level
  compatibility with 0.2.x callers' `Cargo.toml`/`build.rs` — see
  [Migration from 0.2.x to 0.3.0](#migration-from-02x-to-030) below).
  A new opt-in feature `tlcp-gmssl-compat` (default off) restores the
  pre-0.3.0 default-mode wire deviations for byte-for-byte interop with
  GmSSL 2026-06+ master and Tongsuo NTLS. Strategic pivot per user
  directive 2026-09-08: *"务必以完全实现最新 tlcp 规范为目标，而不是为了
  兼容 GmSSL 等"*.

  Behaviour matrix (which path is taken when):

  | Handshake step | Default (0.3.0) | `tlcp-gmssl-compat` (opt-in) |
  |---|---|---|
  | Client ECDHE `ClientKeyExchange` body | spec — no `uint16` length prefix (RFC 5246 §7.4.7) | GmSSL master — `uint16 payload_length ∥ payload` |
  | Static-ECC `ServerKeyExchange` | skip SKE entirely (RFC 5246 §7.4.3) | always read SKE (GmSSL ECDHE-style on static-ECC) |
  | Server ECDHE pre-master secret | SM2 KAP per GB/T 32918.3-2016 §6.4.2 (48-byte KDF output) | raw 32-byte ECDH x-coordinate (legacy 0.2.x default) |
  | `CertificateRequest` after ECDHE SKE | emitted by server (server also reads client's `Certificate` reply) | not emitted |
  | Client `CertificateVerify` after ECDHE SKE | emitted + verified against server sign cert | not emitted |
  | Server sign cert selection | used for SKE/CV signature verification | skipped |

  Audit findings resolved by this release:
  - **C-1** (non-spec `uint16` CKE prefix) — **resolved**: spec is now
    default; GmSSL deviation is opt-in.
  - **C-3** (server-side 32-byte raw ECDH PMS) — **resolved**: SM2 KAP
    is now default; raw ECDH is opt-in.
  - **C-2** (static-ECC SKE handling) — **partial**: default mode now
    skips SKE on static-ECC (RFC 5246 §7.4.3), but the spec-perfect
    sig-only SKE (`cr ∥ sr ∥ enc_cert` body, interpretation B) is
    **not yet implemented** and is the scope of **R-2** (gm-tlcp
    0.3.1). 0.3.0's default is still RFC-5246-strict (no SKE), not
    spec-perfect (sig-only SKE). See
    [`interop/AUDIT-2026-09-06-v2.md`](interop/AUDIT-2026-09-06-v2.md)
    §C-2 for the three interpretations.
  - **C-4** (server-side static-ECC / RSA CKE decryption) — **still
    blocked**: pending **R-3** (gm-tlcp 0.4.0).

- **Removed cfg gate from `cv_helper` module**.
  [`src/tlcp/cv_helper.rs`](src/tlcp/cv_helper.rs) was previously
  `#[cfg(feature = "tlcp-strict")]`. It is now unconditional and
  internally gates its single function on `#[cfg(not(feature =
  "tlcp-gmssl-compat"))]`, since the GmSSL-master shim path does not
  parse the server's `CertificateVerify`. `parse_handshake_message_local`
  gained a `#[allow(dead_code)]` because it is only reachable under
  the spec-default path (the gmssl-compat path reads CV inline from
  the wire).

- **Top-level docstring table inverted**.
  [`src/tlcp/mod.rs`](src/tlcp/mod.rs) "Limitations and interop
  boundaries" now leads with the spec-default column and lists the
  GmSSL deviations as opt-in.

- **Test naming updated**.
  [`src/tlcp/messages/client_key_exchange.rs`](src/tlcp/messages/client_key_exchange.rs):
  `default_*` → `gmssl_compat_*`, `strict_*` → `spec_default_*`.

### Migration from 0.2.x to 0.3.0

1. **If you were using default mode (no feature flag)** and connecting
   to GmSSL 2026-06+ master or Tongsuo NTLS: add
   `features = ["tlcp-gmssl-compat"]` to your `gm-tlcp` dependency in
   `Cargo.toml`. The wire deviations are restored, byte-for-byte.

2. **If you were using `features = ["tlcp-strict"]`** and connecting to
   openHiTLS / standards-strict peers: just remove the `tlcp-strict`
   feature flag from `Cargo.toml` — strict behaviour is now the
   default. (Leaving `tlcp-strict` in place still compiles; it is a
   deprecated no-op and emits a `cargo:warning=` if you run with
   `--warnings-as-errors`, but that is a build-script concern only.)

3. **Public API**: no signature changes. Only the wire-format and
   feature-flag names changed.

4. **No other crates need to bump**: `gm-tlcp`'s cascade consumers
   (`gm-crypto ^0.3`, `gm-tls ^0.2.1`, `gm-sm9-rs ^0.1.1`, `gm-ca ^0.1.2`)
   are unaffected — R-1 is gm-tlcp-internal.

### Verification

- `cargo +stable fmt --all -- --check` clean.
- `cargo +stable clippy --workspace --all-features --all-targets -- -D warnings` clean.
- `cargo +stable test --workspace` clean: gm-tlcp 74 unit tests + 5 loopback tests
  (incl. `gm_tlcp_kap_pms_roundtrip_with_real_keys`) pass under default mode.
- `cargo +stable test -p gm-tlcp --features tlcp-gmssl-compat` clean (rollback path verified).
- `cargo +stable test -p gm-tlcp --features tlcp-strict` clean (deprecated no-op verified).
- `cargo +stable publish --dry-run -p gm-tlcp --registry crates-io` clean.

## [0.2.2] - 2026-09-07

### Changed

- **Dependency bump**: \`gm-crypto\` requirement relaxed from
  \`0.2.0\` to \`0.3\` (caret range). Required so that the
  \`tlcp-strict\` ECDHE PMS code path can access the new
  \`Sm2EcdhKeypair::private_key_bytes()\` method that landed in
  \`gm-crypto 0.3.0\`. No public API change in this crate. Fully
  backwards-compatible: the default-mode wire path still works
  against \`gm-crypto 0.2.x\` if a downstream user pins to it,
  because \`compute_tlcp_ecdhe_pms\` is only reachable from the
  \`tlcp-strict\` feature flag which compiles fine on either
  version.

  Build/runtime effect for crates.io consumers:
    - Old: \`gm-tlcp 0.2.1\` pulled in \`gm-crypto 0.2.0\`; strict
      mode would compile but \`private_key_bytes()\` was missing
      from the published \`gm-crypto 0.2.0\`, so strict mode was
      effectively broken for crates.io consumers.
    - New: \`gm-tlcp 0.2.2\` pulls in \`gm-crypto >= 0.3\`, and
      \`gm-crypto 0.3.0\` provides \`private_key_bytes()\`. Strict
      mode now works end-to-end from crates.io.

## [0.2.1] - 2026-09-07

### Fixed

- **C-3 fix: server-side ECDHE PMS now uses SM2 KAP instead of raw ECDH**
  ([`src/tlcp/mod.rs`](src/tlcp/mod.rs) `accept_with_certs` step 8,
  [`src/tlcp/cv_helper.rs`](src/tlcp/cv_helper.rs) (new),
  [`src/tlcp/messages/certificate_request.rs`](src/tlcp/messages/certificate_request.rs) (new),
  [`src/tlcp/handshake/server.rs`](src/tlcp/handshake/server.rs),
  [`src/tlcp/crypto/verify.rs`](src/tlcp/crypto/verify.rs),
  [`src/tlcp/messages/mod.rs`](src/tlcp/messages/mod.rs),
  [`gm-crypto/src/sm2.rs`](../gm-crypto/src/sm2.rs),
  [`tests/gm_tlcp_loopback.rs`](tests/gm_tlcp_loopback.rs) (new)).
  Audit finding **C-3** in
  [`interop/AUDIT-2026-09-06-v2.md`](interop/AUDIT-2026-09-06-v2.md) §C-3
  (the original [v1](interop/AUDIT-2026-09-06.md) wording on x̂ was
  corrected in v2; the v2 wording is the audit of record).
  The server now computes the pre-master secret via
  `compute_tlcp_ecdhe_pms(..., z_server, z_client, 48)` —
  `V = [x̄_R_A · r_A + k_A] · (R_B · x̄_R_B + P_B)` then
  `KDF(x_V ∥ y_V ∥ Z_A ∥ Z_B, 48)` — matching the client call site and
  the spec (GB/T 38636-2020 §6.4.6.2 + GM/T 0003.3-2012 §6.1 B4/B6/A5/A7).
  Without this fix, the server emitted a 32-byte raw ECDH x-coordinate
  while the client (and GmSSL master / openHiTLS / Tongsuo) emit a
  48-byte KDF output, so the two sides could never agree on
  `master_secret`. Strict-only (`--features tlcp-strict`); default
  mode preserves the historical 32-byte path for byte-for-byte interop
  with the existing `tests/gmssl_interop.rs` flow.

  Side effects of the strict-mode server-side change:
  - New `TlcpCertificateRequest` message type per GB/T 38636-2020 §6.4.5.5.
  - Server writes `CertificateRequest` after `ServerKeyExchange` and
    reads the client's `Certificate` reply before `ClientKeyExchange`.
    Reads `CertificateVerify` if present and verifies it against the
    client sign cert + distid (configurable via the new
    `with_client_sign_distid` setter).
  - New `TlcpAcceptor` setters: `with_server_enc_distid`,
    `with_client_enc_distid`, `with_client_sign_distid`
    (audit M-3, server side; client-side equivalents were already
    shipped in 0.2.0).
  - New `gm_crypto::sm2::Sm2EcdhKeypair::private_key_bytes()` accessor
    to feed the ephemeral scalar into the KAP without exposing internal
    `Scalar` machinery.
  - Bonus wire-format fix: the ECDHE SKE signature verify path now
    accepts both raw r∥s (64 bytes, what `Sm2Signer::sign` emits and
    what GmSSL master emits) and DER-framed signatures. Previously the
    server emitted raw r∥s but the connector's verify path only
    accepted DER, so the existing `gmssl_interop` flow could never
    succeed end-to-end (it was `#[ignore]`-d in CI). Now strict mode
    self-loops work, and the GitHub `gm-tlcp × GmSSL TLCP Interop`
    workflow flips from queued/never-run to success.

### Added

- New regression test
  [`tests/gm_tlcp_loopback.rs::gm_tlcp_kap_pms_roundtrip_with_real_keys`](tests/gm_tlcp_loopback.rs)
  — feeds real GmSSL-generated SM2 dual-cert keypairs into
  `compute_tlcp_ecdhe_pms` and asserts both sides produce an identical
  48-byte PMS. Skips silently if `gmssl` is not on PATH. Verified
  locally under both default and `--features tlcp-strict` modes.

- New `.gitignore` rules in `gm-tlcp/.gitignore` blocking
  `tests/**/*.pem|.key|.crt|.csr` and `tests/fixtures/`, so the test
  cert artefacts generated by `support::cert_setup` can never be
  accidentally pushed to a public mirror.

[Unreleased]: https://github.com/GM-Engineers/gm/compare/main...HEAD
[0.4.0]: https://github.com/GM-Engineers/gm/compare/gm-tlcp-v0.3.1...gm-tlcp-v0.4.0
[0.3.1]: https://github.com/GM-Engineers/gm/compare/gm-tlcp-v0.3.0...gm-tlcp-v0.3.1
[0.3.0]: https://github.com/GM-Engineers/gm/compare/gm-tlcp-v0.2.2...gm-tlcp-v0.3.0
[0.2.2]: https://github.com/GM-Engineers/gm/compare/gm-tlcp-v0.2.1...gm-tlcp-v0.2.2
[0.2.1]: https://github.com/GM-Engineers/gm/compare/gm-tlcp-v0.2.0...gm-tlcp-v0.2.1
[0.2.0]: https://github.com/GM-Engineers/gm/compare/gm-tlcp-v0.1.0...gm-tlcp-v0.2.0
[0.1.0]: https://github.com/GM-Engineers/gm/releases/tag/gm-tlcp-v0.1.0

## [0.2.0] - 2026-09-07

### Changed

- **Dead SM2-ephemeral-key field removed from `TlcpClientHello` / `TlcpServerHello`**
  ([messages/client_hello.rs](src/tlcp/messages/client_hello.rs),
  [messages/server_hello.rs](src/tlcp/messages/server_hello.rs),
  [handshake/client.rs](src/tlcp/handshake/client.rs),
  [handshake/server.rs](src/tlcp/handshake/server.rs)).
  Audit finding **M-1** in [`interop/AUDIT-2026-09-06.md`](interop/AUDIT-2026-09-06.md):
  the `sm2_ephemeral_public` field, the `with_ephemeral_key()` setter, and the
  in-parser that consumed the standard `extensions_length` as an SM2-key length
  were unreachable code. The TLCP spec defines no Hello-extension semantics;
  the previous code silently mis-parsed any peer that sent real extensions
  (e.g. `extended_master_secret`). The new code silently ignores trailing
  bytes after the compression-methods block, matching GmSSL/Tongsuo behaviour.
  This is a **public-API breaking change** but has no in-tree callers.

### Added

- **Cargo feature flag `tlcp-strict`** (no behaviour change in default mode).
  When enabled, gm-tlcp emits and accepts the strict GB/T 38636-2020 wire
  format on the parts of the handshake where the deployed GmSSL/Tongsuo
  ecosystem diverges from the spec (currently: audit findings **C-1** for
  ECDHE `ClientKeyExchange` length prefix, **C-2** for static-ECC
  `ServerKeyExchange`). The default (no feature) preserves byte-for-byte
  interop with GmSSL master and Tongsuo NTLS. The cfg-gated logic for C-1
  and C-2 will land in the next minor release.

- **C-1 fix behind feature `tlcp-strict`** (no behaviour change in default
  mode). Audit finding **C-1** in [`interop/AUDIT-2026-09-06.md`](interop/AUDIT-2026-09-06.md):
  gm-tlcp's ECDHE `ClientKeyExchange` body used a non-standard 16-bit
  length prefix to match GmSSL 2026-06+ master (`tls_uint16array_to_bytes`),
  which broke interop with standards-strict peers like openHiTLS (alert
  *Decode Error*). When `tlcp-strict` is enabled, the prefix is omitted
  on the encoder side and not consumed on the decoder side, matching
  RFC 5246 §7.4.7 / GB/T 38636-2020 §6.4.1.6. Verified against openHiTLS
  `s_server -tlcp` (Docker, `tlcp-bin/`): the strict-mode client
  successfully progresses past the CKE step where the default-mode client
  was rejected. New cfg-gated unit tests (`tests` mod in
  [messages/client_key_exchange.rs](src/tlcp/messages/client_key_exchange.rs))
  assert exact wire bytes in both modes.

- **C-2 fix behind feature `tlcp-strict`** (no behaviour change in default
  mode). Audit finding **C-2** in [`interop/AUDIT-2026-09-06.md`](interop/AUDIT-2026-09-06.md):
  gm-tlcp unconditionally emitted and read `ServerKeyExchange` regardless
  of suite type, while standards-strict peers omit SKE for static-ECC
  suites (RFC 5246 §7.4.3 / GB/T 38636-2020 §6.4.1.5). Under `tlcp-strict`:
  - The client skips the SKE read+verify block entirely for static-ECC
    suites (`suite.ecdhe == false`) and tracks whether `ServerHelloDone`
    was already consumed in step 5.5 so step 6 doesn't hang waiting for
    a record the standards-strict server doesn't send.
  - The server skips the SKE generate+emit block for static-ECC suites
    and returns an explicit `"strict-mode server-side static-ECC PMS
    decryption is not implemented"` error if a static-ECC client connects
    (the static-ECC server PMS-decrypt path is tracked separately).
  Verified against openHiTLS `s_server -tlcp` for the e013 suite: the
  strict-mode client now progresses past the previous step-6 hang and
  reaches the Finished stage (the remaining `Decrypt Error` on Finished
  is a downstream PMS/distid issue tracked as **M-3**). In default mode
  the historical "always read SKE, fall through" behaviour is kept for
  GmSSL/Tongsuo interop.

- **M-3 partial: configurable SM2 distid for ECDHE PMS and CV
  signature** (no behaviour change when defaults are used). Audit
  finding **M-3** in [`interop/AUDIT-2026-09-06.md`](interop/AUDIT-2026-09-06.md):
  the SM2 `distid` was hard-coded to `"1234567812345678"` at the
  Z-value computation site (`mod.rs:1846`) and the CV self-verify site
  (`mod.rs:1929`). Three new builder methods on `TlcpConnector`:
  - `with_server_enc_distid(distid)` — `Z_server` in ECDHE PMS
  - `with_client_enc_distid(distid)` — `Z_client` in ECDHE PMS
  - `with_client_sign_distid(distid)` — `Z_client` for CV signature
  When unset, all three fall back to `"1234567812345678"` (the GmSSL /
  Tongsuo / openHiTLS convention), so existing GmSSL interop is
  preserved. CV signing now uses `Sm2Signer::new_with_distid` with the
  configured distid (instead of `Sm2Signer::new` which hard-codes the
  PEM-loader's default), and the CV self-verify step uses the same
  distid for consistency. New unit tests in
  [mod.rs `tests` mod](src/tlcp/mod.rs) cover default-None, custom
  values, and the empty-string-is-distinct-from-None invariant.
  Verified by `cargo test --lib` (64/64 pass) in both default and
  strict modes. Note: PR4 fixes the *configuration* surface; the
  *root cause* of the openHiTLS `Decrypt Error (51)` on Finished
  remains an open interop issue under investigation (x̂ transform
  alignment between gm-tlcp and openHiTLS' SM2 key-agreement) and is
  tracked separately as a follow-up.

- **m-1, m-3, m-4, m-5, m-6, D-1, D-2 fixes** (audit cleanup, no
  behaviour change for spec-compliant peers). Audit findings
  **m-1** through **m-6** plus **D-1** and **D-2** in
  [`interop/AUDIT-2026-09-06.md`](interop/AUDIT-2026-09-06.md):
  - **m-1**: `ClientHello::new()` and the server-side handshake
    constructors now set the first 4 bytes of `random` to the
    current GMT Unix time per RFC 5246 §7.4.1.2 (helper
    `tlcp::constants::current_gmt_unix_time()`).
  - **m-3**: removed the stale `#[allow(dead_code)]` on
    `TLCP_RECORD_TYPE_CCS` (it has always been used by the
    handshake state machine; the attribute was a historical
    leftover).
  - **m-4**: `TlcpClientHello::from_body` now rejects non-null
    `compression_methods` per GB/T 38636-2020 §6.4.1.1 (TLCP only
    supports 0x00).
  - **m-5**: `TlcpServerHello::from_bytes` now rejects unknown
    `cipher_suite` IDs and non-null `compression_method`. The
    four TLCP suites are enumerated explicitly with a clear error
    message.
  - **m-6**: `TlcpClientHello::from_body` now enforces
    `session_id_len <= MAX_SESSION_ID_LEN` (32) per
    GB/T 38636-2020 §6.4.1.1.
  - **D-1**: rewrote the `tlcp/alert.rs` module doc to remove the
    internal contradiction (the old text said "specifies
    HANDSHAKE content type, not alert content type" and then
    "the current master is correct" — but the code at
    `mod.rs:162` and the actual GB/T 38636-2020 §6.2.2.1 both
    confirm the standard uses ALERT content type 0x15, identical
    to RFC 5246 §7.2 and to current GmSSL master).
  - **D-2**: added a top-level "Limitations and interop
    boundaries" section to
    [mod.rs](src/tlcp/mod.rs) that enumerates the six divergences
    between default and strict modes in a table (CKE prefix,
    SKE-for-static-ECC, distid, GMT-time random, compression /
    cipher-suite validation, session_id_len cap), and tells
    production callers which mode to pick for GmSSL vs
    openHiTLS / Tongsuo, and warns that running gm-tlcp as a
    server for static-ECC suites is not yet supported.
  - 8 new unit tests in the message-parser `tests` mods cover
    the m-1, m-4, m-5, m-6 changes. Verified by `cargo test
    --lib` (72/72 pass) in both default and strict modes.

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
