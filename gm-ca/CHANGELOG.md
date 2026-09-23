# Changelog

All notable changes to the `gm-ca` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Configurable mTLS (PR-4.2 / P1-1)**. New env var
  `GRPC_TLS_REQUIRE_CLIENT_AUTH` enables client-certificate
  authentication on the gRPC listener (mTLS + Bearer Token
  dual-factor). Accepted values: `1` / `true` / `yes` / `on`
  (case-insensitive) enable mTLS; everything else (including
  unset, empty string, `0`, `garbage`) disables it. Default
  `false` preserves pre-PR-4.2 behavior. Client cert chain
  validation reuses `gm_tls::TlsConfig::with_require_client_auth`,
  which internally calls `verify_cert_chain_sm2_chain`.

- **`gm-ca-server` binary**: new `parse_bool_env` helper (file
  scope) for the above. 9 new unit tests cover the env-var
  parsing semantics exhaustively.

- **gm-ca 0.4.0**: version bump (minor; new opt-in public env var).

- **`gm-crypto` / `gm-tlcp` dev-deps**: cascade-bump gm-ca
  constraint from `^0.3` to `^0.4` to follow the workspace.

### Added (PR-3.1)

- **`SignCertificateRequest` / `RenewCertificateRequest` (proto v0.3.0, PR-3.1)** gain two additive fields for SPIRE Workload API support:
  - `validity_seconds` (int64, field 3): sub-day TTL. When > 0,
    takes precedence over the legacy `validity_days` field. Range
    `1..=31_536_000` (1s .. 365d). SPIRE SVID rotation typically
    issues 1h~24h SVIDs — structurally incompatible with the
    pre-3.0 integer-day granularity.
  - `profile_json` (string, field 4): JSON-encoded `CertProfile`
    (see `gm_ca::cert_profile::CertProfile` for the schema). Empty
    string = fall back to `CertProfile::default()` (v0.1.x /
    v0.2.x wire format). Used by SPIRE Server to pass URI SANs
    (`spiffe://trust.domain/ns/.../sa/...`) + the appropriate
    KU/EKU layout per SVID type.
- **`CaSigner::sign_csr_with_profile_and_seconds` /
  `RsaCaSigner::sign_csr_with_profile_and_seconds` /
  `CaSigner::renew_certificate_with_profile_and_seconds`** — direct
  signer entry points accepting `validity_seconds: i64`. The pre-3.0
  `_with_profile` methods are preserved as thin wrappers that
  convert days to seconds.
- **`CertProfile` (and nested `KeyUsageBits`, `ExtendedKeyUsage`,
  `GeneralName`) gains `serde::Serialize` / `Deserialize`** —
  required for the new `profile_json` gRPC field. JSON
  representation uses snake_case field names; the SAN enum is
  internally tagged (`{"type":"uri","value":"..."}`).
- **`tests/sign_certificate_v3.rs`** (PR-3.1, new file, 11 tests)
  exercises backward compatibility (pre-v0.3.0 clients using only
  `validity_days`), sub-day TTL (1h / 5min SVID scenarios),
  profile_json URI SAN passthrough (verifying the SPIFFE-ID URI
  appears in the issued cert's SAN extension), precedence
  (seconds beats days), and validation (invalid JSON / out-of-range
  seconds).

### Changed

- **`CertProfile` carries `#[serde(default)]`** at the struct level
  (and `KeyUsageBits` likewise), so callers can pass partial JSON
  profiles; missing fields default to `false` / `Default::default()`.
- **gm-ca bumped to 0.3.0** (from 0.2.2): proto wire-format addition
  (additive, backward-compatible) + new public API methods
  (`sign_csr_with_profile_and_seconds` et al.) + new dependencies
  (`serde`, `serde_json`) constitute a minor-version bump per SemVer.
  Downstream dev-deps `gm-crypto` (`^0.2` → `^0.3`) and `gm-tlcp`
  (`^0.2` → `^0.3`) track accordingly.

### Fixed

- **`notBefore` is now back-dated by 5 minutes when issuing a new
  certificate**, so freshly-issued certs do not trigger
  `"certificate has expired or is not yet valid"` on a verifier
  whose clock is modestly behind the CA's. The back-date is
  applied via a new `now_utc_for_x509()` helper (constant
  `NOT_BEFORE_CLOCK_SKEW_TOLERANCE = 300 s`). Combined with
  `utctime()`'s sub-second truncation, this also stabilises
  back-to-back sign-then-verify test loops near the second
  boundary. See R2 in
  `2026-09-18-gm-tlcp-fix-verification-v2.md` and
  RFC 5280 §4.1.2.5.

## [0.2.2] - 2026-09-18

### Fixed

- **SM2 signature / public-key / CRL Number OID byte sequences
  corrected to canonical DER.** The constants
  `SM2_SIG_OID` (1.2.156.10197.1.501 / sm3WithSM2),
  `SM2_PK_OID` (1.2.156.10197.1.301), and `CRL_NUM_OID`
  (1.2.156.10197.1.106) carried byte sequences whose base-128
  sub-component encoding for the `156` and `10197` arcs was
  non-canonical. The bytes produced a numeric OID of
  `1.2.26620389.106.*.*` (private arc) plus a dangling
  continuation byte at the end, which made the OID invalid
  per X.690. As a result, openssl rejected every certificate
  gm-ca emitted with "BAD OBJECT" / "unsupported". The bytes
  are now the canonical GM/T 38636-2020 §6.4.6 encoding
  (`2A 81 1C CF 55 01 ...`), and openssl parses gm-ca-issued
  certs as `Signature Algorithm: SM2-with-SM3` /
  `Public Key Algorithm: sm2`. A regression test
  (`cert::tests::sm2_oid_byte_sequences_match_gm_t_standard`)
  decodes the bytes back to the documented OID strings and
  fails if any future change drifts away from the standard.

- **KeyUsage extension now carries the proper BIT STRING TLV**
  (the wire form required by x509-parser 0.16 + RFC 5280
  §4.2.1.3). `KeyUsageBits::to_der_bytes()` returns the BIT
  STRING content (unused-bits prefix + payload); the caller
  in `build_extensions` now wraps it with the BIT STRING
  tag + length before passing it to `build_extension`.
  Without this wrapper x509-parser's KU parser returns
  `ParseError`, which previously caused every KU/EKU role
  assertion in `verify_cert_role` to silently no-op. The
  RSA signer unit tests were also updated from raw-byte
  position assertions (`ku.value[1] == 0x06`) to parsed
  `KeyUsage` checks so the tests stay valid against any
  future BIT STRING header layout change.

## [0.2.1] - 2026-09-18

### Added

- **`CaSigner::key_pair()`** — read-only getter for the CA's
  underlying `Sm2KeyPair`. Provided as a convenience for test
  fixtures that need to sign custom-encoded artifacts (e.g. CRLs
  that bypass the built-in `generate_crl` path). Production code
  should NOT depend on this getter — use `sign_csr_with_profile`
  or `generate_crl` instead.

### Changed

- **`CaSigner::generate_crl`** now produces CRLs that conform to
  RFC 5280 §5.1 / §5.2.3 (see "Fixed" below). The encoded bytes
  change; dependents producing invalid CRLs would benefit, while
  anyone hardcoding the prior (broken) bytes would break.

### Fixed

- **`CaSigner::generate_crl`: `tbs_version` was doubly-wrapped**
  (was `a0 05 02 03 02 01 01`). Per RFC 5280 §5.1 the version
  field in TBSCertList is a PLAIN INTEGER — `02 01 01` for v2.
- **`CaSigner::generate_crl`: CRL Number extension missing OCTET
  STRING wrapper.** The extension value is now emitted via
  `build_extension(CRL_NUM_OID, false, &integer)`, which wraps
  the INTEGER in the OCTET STRING `extnValue` required by RFC
  5280 §5.2.3. Both bugs caused the produced CRL to be rejected
  by `x509-parser` 0.16 with `Eof`, and would have been rejected
  by any RFC-strict CRL reader.

## [0.2.0] - 2026-09-11

### Breaking Changes

- **`CaSigner::sign_csr` removed.** Use
  `CaSigner::sign_csr_with_profile(csr, days, &profile)`. The default
  `CertProfile::default()` (or `CertProfile::server_end_entity()`)
  reproduces the v0.1.x wire-format extension set
  (`digitalSignature | keyEncipherment`, `serverAuth | clientAuth`,
  SKI, SAN, plus a new explicit `BasicConstraints CA:FALSE`).
- **`CaSigner::renew_certificate` removed.** Use
  `CaSigner::renew_certificate_with_profile(cert_pem, days, &profile)`.

### Added

- **`CertProfile`** (in `gm_ca::cert_profile`) — declarative spec for
  the extension set + flags a cert should carry. Presets:
  `CertProfile::default`, `server_end_entity`, `client_end_entity`,
  `intermediate_ca`, `root_ca`.
- **`CaSigner::self_sign_ca(days, &profile)`** — self-sign the CA
  certificate (the trust anchor for chains `sign_csr_with_profile`
  issues). Default profile `CertProfile::root_ca()` produces a
  `keyCertSign | cRLSign` + `BasicConstraints CA:TRUE` root with
  matching SKI / AKI per RFC 7093 Method 1.
- **AuthorityKeyIdentifier extension** emitted by default on every
  certificate — `keyIdentifier = SM3(CA pubkey)[:20]` per RFC 7093
  §2 Method 1. Required by GmSSL master for TLCP chain walks.
- **BasicConstraints emitted by default** — `CA:FALSE` for end-entity
  certs, `CA:TRUE` (with optional `pathLenConstraint`) for CA certs.
- **`RsaCaSigner` (feature `rsa`, Phase 4)** — X.509 CA signer backed
  by an RSA private key, mirror of `CaSigner` for the SM2 path.
  Produces certs with `rsaEncryption` (1.2.840.113549.1.1.1) SPKI and
  `sha256WithRSAEncryption` (1.2.840.113549.1.1.11) signatures — the
  surface expected by general-purpose X.509 verifiers (GmSSL master,
  openHiTLS, OpenSSL) for the TLCP RSA suites
  ([GB/T 38636-2020] §6.4.5.2.1 表 2 — E019/E01C/E059/E05A). SKI/AKI
  key-ids use SHA-1 per RFC 7093 §2 Method 1 (interop with global PKI;
  SM3 is reserved for SM2 certs). Methods: `self_sign_ca`,
  `sign_csr_with_profile` (CSR must use `rsaEncryption`; SM2-signed
  CSRs are rejected up front), `renew_certificate_with_profile`,
  `from_pkcs8_pem`. RSA CSRs are signature-verified with
  sha256WithRSAEncryption before issuing.
- **`rsa` Cargo feature** (off by default, Phase 4) — enables
  `RsaCaSigner` and pulls `rsa = "0.9"` + `sha2 = "0.10"` +
  `sha1 = "0.10"` (versions synced with gm-tlcp 0.6.x). Default build
  stays strictly SM2 + 国密; the SM2 path is the canonical CA signer.
- **`tlcp-profiles` Cargo feature** (off by default, Phase 5) —
  enables the `gm_ca::profiles::tlcp` submodule exposing 6 TLCP
  end-entity `CertProfile` preset constructors matching the KU/EKU
  layout [GB/T 38636-2020] §6.4.6 / GmSSL master / openHiTLS expect:

  | Preset | KU bits | EKU | Algorithm |
  |---|---|---|---|
  | `tlcp_server_sign_ecc` | digitalSignature \| keyAgreement | serverAuth | SM2 |
  | `tlcp_server_enc_ecc` | keyEncipherment \| keyAgreement \| dataEncipherment | (none — GmSSL convention) | SM2 |
  | `tlcp_client_sign_ecc` | digitalSignature \| keyAgreement | clientAuth | SM2 |
  | `tlcp_client_enc_ecc` (Phase 9) | keyEncipherment \| keyAgreement \| dataEncipherment | clientAuth | SM2 |
  | `tlcp_server_rsa` (gated `rsa`) | digitalSignature \| keyEncipherment | serverAuth | RSA |
  | `tlcp_client_rsa` (gated `rsa`) | digitalSignature \| keyEncipherment | clientAuth | RSA |

  The enc cert preset (`tlcp_server_enc_ecc`) deliberately has **no
  EKU** because GB/T 38636 §6.4.6.1.2 b) marks EKU as optional and
  GmSSL/openHiTLS both emit none — matching that keeps TLCP enc certs
  GmSSL-chain-walkable. The client-side enc preset
  (`tlcp_client_enc_ecc`, Phase 9) does carry `clientAuth` EKU because
  §6.4.6.2.2 b) marks it as "应包括" (should include) for the client
  side, contrasting with the server's "可包括" (may include). Presets
  leave `sans` empty so callers push their own `GeneralName::DnsName` /
  `IpAddress` entries before passing the profile to
  `CaSigner`/`RsaCaSigner`.
- **`tests/tlcp_loopback.rs` (Phase 6a / Phase 4g close-out)** —
  5 in-process loopback tests proving `RsaCaSigner`-issued X.509
  certs round-trip through gm-tlcp's 4 RSA cipher suites
  ([GB/T 38636-2020] §6.4.5.2.1 表 2 — E019/E01C/E059/E05A) plus a
  wire-format introspection test (rsaEncryption SPKI +
  sha256WithRSAEncryption outer signature). Replaces the dummy 100-byte
  DER blob `gm-tlcp`'s own loopback tests use with a real RSA cert
  signed via `RsaCaSigner::sign_csr_with_profile` and
  `with_rsa_certs_single` (R-7 / GB/T §6.4.5.5 single-Cert emission).
  File is gated behind `#[cfg(feature = "rsa")]` so default builds
  stay SM2-only and slim; `cargo test --features rsa` runs them
  (≈40s wall-clock, RSA-2048 keygen dominates). Dev-dep
  `gm-tlcp = { version = "0.6", default-features = false }` added
  under `[dev-dependencies]`.
- **`tests/tlcp_loopback_sm2.rs` (Phase 6b close-out)** — 5 in-process
  loopback tests proving `CaSigner` (SM2) + the Phase 5
  `tlcp_server_sign_ecc` / `tlcp_server_enc_ecc` profile presets
  produce dual certs (sign + enc) wire-compatible with gm-tlcp's 4
  ECC TLCP cipher suites ([GB/T 38636-2020] §6.4.5.2.1 表 2 —
  E051/E011/E053/E013) plus a wire-format introspection test (SM2
  SPKI OID + sm3WithSM2 outer signature OID). Mirrors Phase 6a's RSA
  loopback but replaces the GmSSL-CLI dependency of
  `tests/gm_tlcp_loopback.rs::run_ecdhe_or_ecc_loopback` with
  `CaSigner`-issued certs issued from the same root SM2 CA. Client
  cert chain `[client_sign, client_enc, root_ca]` is also issued by
  `CaSigner` (server `CertificateRequest` step is non-skippable for
  ECC suites per the `with_client_certs` hard requirement). File is
  gated behind `#[cfg(feature = "tlcp-profiles")]`; `cargo test
  --features tlcp-profiles` runs them (≈0.3s wall-clock).

### Internal

- **`cert::build_tbs_certificate`, `cert::build_certificate_der`,
  `cert::build_extensions` refactored to be algorithm-agnostic**
  (Phase 4). They now take pre-built `sig_alg_id`, `spki_alg_id`,
  and 20-byte `subject_key_id` / `ca_key_id` values instead of
  SM2-specific pubkey bytes. The SM2 `CaSigner` path uses thin SM2
  wrappers (`sm2_sig_alg_id`, `sm2_spki_alg_id`, `sm3_key_id`) and
  the new `RsaCaSigner` path uses RSA wrappers (`rsa_sig_alg_id`,
  `rsa_spki_alg_id`, `sha1_key_id`). No behavior change to existing
  SM2 callers.

### Changed

- Default end-entity extension set now includes an explicit
  `BasicConstraints CA:FALSE` extension (previously omitted).
  `gm-tls` / `gm-tlcp` both accept it unchanged.

## [0.1.2] - 2026-09-07

### Changed

- **Dependency bump**: `gm-crypto` requirement relaxed from `0.2.0`
  to `0.3` (caret range). No public API change in this crate.
  Required because `gm-crypto 0.3.0` adds the
  `Sm2EcdhKeypair::private_key_bytes()` method, which downstream
  callers (notably `gm-tlcp 0.2.2`'s `tlcp-strict` mode) need.

## [0.1.1] - 2026-09-05

### Added

- TLS gRPC integration via `gm-tls = { features = ["grpc"] }` and
  Tonic health endpoints.
- Generic CA service for SM2 certificate management.

[Unreleased]: https://github.com/GM-Engineers/gm/compare/main...HEAD
[0.2.1]: https://github.com/GM-Engineers/gm/compare/gm-ca-v0.2.0...gm-ca-v0.2.1
[0.2.0]: https://github.com/GM-Engineers/gm/compare/gm-ca-v0.1.2...gm-ca-v0.2.0
[0.1.2]: https://github.com/GM-Engineers/gm/compare/gm-ca-v0.1.1...gm-ca-v0.1.2
[0.1.1]: https://github.com/GM-Engineers/gm/releases/tag/gm-ca-v0.1.1
