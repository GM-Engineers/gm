# Changelog

All notable changes to the `gm-crypto` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Standards references: `GM/T 0028-2014` → `GM/T 0028-2024`** in `src/kat.rs`
  doc-comments (9 locations: module-level, `kat_sm3`, `kat_sm4`, `self_test`,
  `self_test_with_options`, `kat_sm2_pairwise`, `kat_critical_functions`,
  `verify_software_integrity`, plus the `# GM/T 0028-2024 Compliance`
  section heading). `GM/T 0028-2024` 《密码模块安全要求》 was published
  2024-12-27 and became effective 2025-07-01, replacing `GM/T 0028-2014`
  per 全国标准信息公共服务平台 (hbba.sacinfo.org.cn). Status: 现行,
  制修订=修订, 代替标准=GM/T 0028-2014. Section-number references
  (§7.2.4.1–7.2.4.5) follow the 2014 structure; the 2024 PDF is
  currently viewable on hbba.sacinfo.org.cn but requires auth to download,
  so section-number preservation across the 2014→2024 revision will be
  re-verified in a follow-up patch when the PDF is publicly released.

  The 3 KAT sign-input bytes containing the literal `b"GM/T 0028 ..."`
  (lines 424/518/595 of `src/kat.rs`) are KAT input data — SM2 sign
  payload, SM4-GCM plaintext, and SM3 software-integrity canary — and
  are preserved unchanged to keep existing KAT signatures stable. No
  behavior change.

### Added

- **SM4-GCM standard KAT vectors in `kat_sm4_gcm`** (`src/kat.rs`): asserts
  against three official standard-issued SM4-GCM test vectors, in addition
  to the existing self-consistency round-trip and tampered-input checks.
  These guard against silent SM4-GCM regressions that the previous
  self-consistency tests could not detect.

  Three new assertions added, each independently pinpointed by its error:

  - **GB/T 36624-2018 附录 C.5 v1** (K=∅, IV=∅(12B), AAD=∅, PT=∅):
    expected tag = `232f0cfe308b49ea6fc88229b5dc858d` (no ciphertext).
    This is the empty-payload case of the "可鉴别的加密机制 5" (GCM with SM4)
    section of the GB/T 36624-2018 national standard, verified via
    macOS Vision OCR of the PDF (page 18, PDF page 24).

  - **GB/T 36624-2018 附录 C.5 v2** (K=∅, IV=∅(12B), AAD=∅, PT=∅(16B)):
    expected ct = `7de2aa7f1110188218063be1bfeb6d89`,
    tag = `b851b5f39493752be508f1bb4482c557`.

  - **RFC 8998 附录 A.1** (K=`0123…3210`, IV=`00001234567800000000abcd`,
    AAD=`feedfacedeadbeeffeedfacedeadbeefabaddad2` (20B),
    PT=AAAA…AAAA (64B)):
    expected ct = `17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d`,
    tag = `83de3541e4c2b58177e065a9bf7b62ec`.
    Cross-verified against the IETF RFC text at `rfc-editor.org/rfc/rfc8998.txt`.

  All three vectors were independently verified before this change against
  the current gm-crypto implementation AND against `gmssl 3.1.1` CLI on the
  same inputs (see `/tmp/sm4_gcm_verify`). The implementation already
  produces byte-for-byte matches, and this PR hardcodes the expected values
  as regression guards. SemVer: PATCH (additive KAT only).

- **Wycheproof SM4-GCM 65 vectors** in new `tests/wycheproof_sm4_gcm.rs`
  integration test, sourced from C2SP Wycheproof `testvectors_v1/sm4_gcm_test.json`
  via `gmssl-master/tests/sm4_gcmtest.h` (Apache-2.0). Embeds the 65 of 104
  Wycheproof vectors that fit gm-crypto's 12-byte nonce constraint:

  - **38 valid vectors** (1 `Ktv` + 35 `Pseudorandom` + 2 `SpecialCase`):
    expected to encrypt byte-for-byte to the documented ct/tag and round-trip
    decrypt to msg.
  - **27 invalid `ModifiedTag` vectors** (bit-flip and all-zero / all-one tag
    variants per Wycheproof): expected to be rejected by `decrypt_gcm`.

  Plus one positive API-contract test
  `wycheproof_sm4_gcm_rejects_non_12b_iv` asserting that `encrypt_gcm` rejects
  IVs of length 0/1/8/11/13/16/32/64/128/257 (gm-crypto's
  `SM4_GCM_NONCE_LENGTH = 12` constraint). Regression guard against silent
  relaxation of the IV-length check.

  The other 39 Wycheproof vectors (12 `SmallIv` + 2 `ZeroLengthIv` + 25
  `LongIv`/`CounterWrap`/`SpecialCase`) require GHASH-keyed IV derivation
  per NIST SP 800-38D §5.2.1.1 — outside gm-crypto's current API contract.
  If a future PR adds that capability, this test file is the place to
  re-enable them. SemVer: PATCH (additive test-only).

- **SM4-GCM live GmSSL 3.1.1 CLI interop test** in
  `tests/conformance_test.rs`: the new `sm4_tests::gcm_vs_gmssl_cli`
  test shells out to `gmssl sm4 -gcm` and verifies byte-for-byte parity
  against gm-crypto's `encrypt_gcm` / `decrypt_gcm` for both an
  empty-AAD case and an `AAD = "additional data"` case. 4 round-trip
  assertions (encrypt + decrypt, both AAD variants) — all pass against
  GmSSL 3.1.1 (Homebrew build 20250911-5311). When `gmssl` is not on
  PATH the test skips gracefully, matching the existing interop-test
  pattern (e.g. `sm2_e2e_cross::gmssl_encrypt_rust_decrypt`).

  The pre-existing `gcm_vs_gmssl` test is preserved as
  `gcm_vs_gmssl_known_values` (hardcoded reference hex against
  `8b985a9c…f1bed` / `8b985a9c…bcf44`), serving as a
  `gmssl`-PATH-independent regression guard. Both tests coexist.

  Key design choice: the new test uses `-aad ""` (the ASCII-string form,
  NOT `-aad_hex ""`) for empty AAD. Although GmSSL 3.1.1 happens to
  produce identical output for all three empty-AAD invocation forms
  (no-flag / `-aad ""` / `-aad_hex ""`, sha256 = `9c8da069…3de6`),
  future versions of `hex_to_bytes("", 0, …)` may reject empty input,
  making `-aad_hex ""` version-sensitive. `-aad ""` is the
  cross-version-stable form. Verified empirically on 2026-10-01 — full
  results in
  `interop/INTEROP-2026-10-01-sm4-gcm-verification.md`. SemVer: PATCH
  (additive test-only).

- **`README.md` SM4 compliance row + `合规与基准` section** — the SM4
  algorithm table row now explicitly enumerates **GM/T 0028-2024**,
  **GB/T 32907-2016**, **GB/T 36624-2018**, **RFC 8998**, the
  Wycheproof SM4-GCM 65/104 vectors, and the GmSSL 3.1.1 CLI
  live-interop. A new `合规与基准` (Compliance & Benchmark) section
  below the table maps each standard/benchmark to its gm-crypto test
  surface (KAT function or integration test) with checkmark status.
  Closes the README-level compliance-declaration gap noted in
  `AUDIT-2026-09-10-gm-crypto-v1.md` I-2 ("referenced in doc-comment
  but not in README").

- **`interop/INTEROP-2026-10-01-sm4-gcm-verification.md`** — new
  interop report documenting the full third-party-report response:
  (1) the trigger; (2) the PR-1 → PR-4 audit trail; (3) empirical
  byte-for-byte equivalence between gm-crypto and GmSSL 3.1.1 CLI for
  4 test cases; (4) the `-aad` / `-aad_hex` flag semantics verified on
  2026-10-01; (5) the standards coverage matrix; (6) the coverage gap
  (NIST SP 800-38D §5.2.1.1 GHASH-keyed IV, out of API scope); (7)
  conclusion explicitly rebutting the third-party report's
  "OpenSSL 3.6.3 as independent judge" claim (OpenSSL has no SM4-GCM).
  No behavior change. SemVer: PATCH (documentation only).

### Fixed

- **CRL signature BIT STRING walker** (PR-4.29 companion fix):
  `find_bitstring_in_outer` in `gm-crypto/src/x509/verify.rs`
  jumped past the declared length of any BIT STRING candidate
  whose content didn't match the target. On any CRL whose TBS
  contained an OID of length 3 (every standard CRL — `commonName`
  2.5.4.3 = `06 03 55 04 03`, `CRL Number` 2.5.29.20 =
  `06 03 55 1d 14`) the walker treated the `06 03 ...` byte
  sequence as a fake BIT STRING of length 85, jumped 87 bytes
  forward, and sailed past the real signatureValue BIT STRING at
  the end of the DER. Result: every CRL signature verification
  with a real-world CRL failed with "CRL signature BIT STRING
  data not found in outer DER". Fixed by falling back to
  byte-by-byte scanning (`pos += 1`) on a candidate mismatch
  instead of jumping past the candidate's declared length. No
  public API change.

- **RFC 5280 §4.2 unknown critical extension rejection** (PR-4.8 / P2-1):
  added `KNOWN_X509_EXTENSIONS` constant + `check_unknown_critical_extensions`
  helper in `gm_crypto::x509::verify`. The helper is wired into every
  verification entry point (`validate_cert_pem`, `validate_hostname_only`,
  `validate_uri_only`, `verify_cert_chain_sm2_chain_with_distid_policy`,
  plus its delegates `verify_against_anchors` and
  `verify_cert_chain_sm2_chain`). Certificates that carry a
  `critical = TRUE` extension whose OID is not in the known set are
  rejected with a clear diagnostic naming the offending OID. Pre-PR-4.8
  the verifier ignored all unknown critical extensions, violating
  RFC 5280 §4.2 ("SHOULD reject"). Added 7 integration tests in
  `tests/x509_unknown_critical_ext.rs` covering the rejection path,
  the non-critical pass-through, the OID-named error message, and
  the static invariant that all RFC 5280 §4.2 baseline OIDs are in
  `KNOWN_X509_EXTENSIONS`. `nameConstraints` and `policyConstraints`
  are accepted (pass the "is recognized" gate) but their semantic
  enforcement is deferred to a follow-up PR per master plan P2-1
  路线图项. PR-4.8 also bumps the version to 0.3.8 (patch; new
  pub API is additive).

### Added

- **`OwnedCert::der_bytes(&self) -> &[u8]`** (PR-2.4): borrow the raw
  DER bytes backing an `OwnedCert`. Returned for callers that need
  to re-feed the cert into a verification helper (e.g.
  `validate_uri_only` for SPIFFE ID matching after the chain walk
  succeeds). Closes the loop on the URI-SAN path — the PR-2.3
  `validate_uri_only` entry point needs the leaf DER, which was
  previously only available via the private `der` field.

## [0.3.7] - 2026-09-23

### Added

- **Explicit deterministic / randomized SM2 signature APIs (PR-4.3 / P1-2)**.
  Audit found that `Sm2Signer::sign` already uses RFC 6979-style
  deterministic k derivation (via the sm2 crate's
  `sign_prehash_rfc6979`, which combines HMAC-SM3 DRBG with the
  private key + e), but the determinism was undocumented and the
  API didn't expose an opt-in randomized path.

  New methods (both wire-format compatible with `sign()`):

  - `Sm2Signer::deterministic_sign(data)` — explicit RFC 6979
    deterministic signature. Byte-identical to `sign()` output
    (they share the same internal path). For CA / KMS / long-term
    archival signing where reproducibility matters.
  - `Sm2Signer::randomized_sign(data, &mut rng)` — caller-supplied
    RNG drives the `additional_data` slot of the RFC 6979
    HMAC-SM3 DRBG; two invocations over the same (key, data)
    produce different signatures. Use when the caller wants
    explicit control over the randomness source (HSM RNG,
    deterministic test RNG, etc.).

  The pre-existing `Sm2Signer::sign(data)` continues to use the
  deterministic RFC 6979 path (default behavior preserved for
  backward compatibility; reproducibility-by-default for CA/KMS).

### Removed

- **Heuristic dummy scalar multiplication in `Sm2Signer::sign`**.
  The pre-PR-4.3 implementation had a `Scalar::random` + dummy
  `r*G` computation claiming to provide timing-side-channel
  noise. The actual signature path already used RFC 6979 (so the
  dummy had no security effect on k, only on CPU noise that was
  already dominated by the real signing operation). Removed to
  avoid misleading future readers into thinking the dummy was
  doing useful work.

### Added (regression test surface)

- **9 new PR-4.3 unit tests** (`gm-crypto/src/sm2.rs::pr43_deterministic_sign_tests`):
  - `pr43_kat_deterministic_sm3_standard_distid`: same (key, msg)
    → byte-identical signature.
  - `pr43_kat_deterministic_custom_distid`: same with non-default
    distid.
  - `pr43_kat_deterministic_empty_message`: empty input edge case.
  - `pr43_kat_deterministic_long_message`: 1 MiB input still
    RFC 6979-deterministic.
  - `pr43_kat_cross_process_invariant`: two independent signers
    over the same key produce identical signatures.
  - `pr43_kat_different_message_different_signature`: changing
    one byte of input flips the signature (k-reuse impossible).
  - `pr43_sign_equals_deterministic_sign`: `sign()` and
    `deterministic_sign()` output is byte-identical (locked
    invariant).
  - `pr43_deterministic_sign_then_verify_round_trip`: end-to-end
    sign + verifier round trip.
  - `pr43_randomized_sign_differs_across_calls`: with OsRng,
    randomized_sign produces three distinct signatures over the
    same input, all verifying.

## [0.3.1] - 2026-09-11

### Added

- **`x509::CsrBuilder`** (in [`src/x509.rs`](src/x509.rs)) — PKCS#10
  CertificationRequest (RFC 2986) builder for SM2. The CSR produced here
  is wire-compatible with:
    - `gm_ca::cert::CaSigner::sign_csr_with_profile(csr_pem, days, &profile)`
      (which round-trips through x509-parser before signing).
    - GmSSL master `gmssl req` (standard SM2 SPKI + sigAlg encoding).
    - openHiTLS / Tongsuo TLCP / TLS 1.3 + SM cert chain tooling.

  Public API:
  ```rust
  use gm_crypto::x509::CsrBuilder;
  use gm_crypto::sm2::Sm2KeyPair;

  let keypair = Sm2KeyPair::generate()?;
  let pubkey_65 = keypair.public_key_bytes_uncompressed();
  let csr_pem = CsrBuilder::new_sm2("server.example.com", &pubkey_65)?
      .build_pem(&keypair)?;
  ```

  - `new_sm2(cn, pubkey_65)` — validate 65-byte uncompressed SEC1 pubkey.
  - `build_cri_der()` — unsigned CRI body (RFC 2986 §4.1).
  - `sign(key_pair)` — full CSR DER (RFC 2986 §4.2) using SM3withSM2
    (OID 1.2.156.10197.1.501) with the GM/TLS standard distid.
  - `build_pem(key_pair)` — `build_pem` shortcut.
  - `subject_cn()` / `sm2_pubkey()` — read-only accessors.

  RSA CSR signing is NOT supported here. RSA cert issuance lives in
  gm-ca's `rsa` feature flag (Phase 4+).

  Five unit tests cover:
    - input validation (length + 0x04 prefix)
    - CRI round-trip via x509-parser
    - CSR PEM round-trip + signature verification via `Sm2Verifier`.

### Changed

- `x509` module: doc comment expanded to mention PKCS#10 CSR generation
  alongside the existing cert parsing helpers.

## [0.3.6] - 2026-09-22

### Added

- **`x509::verify::validate_uri_only(leaf_der, expected_uri, now, policy)`**
  — new leaf-only entry point that matches an X.509 cert's
  `uniformResourceIdentifier` SAN (RFC 5280 §4.2.1.6) against an
  expected URI per a caller-selected policy. Closes the SPIFFE /
  SPIRE SVID verification gap: gm-ca could already issue URI SANs
  (`gm-ca/src/cert_profile.rs:256` `UniformResourceIdentifier`
  variant) but gm-crypto's verifier silently ignored every
  `GeneralName::URI` entry — SPIFFE deployments could not be
  validated end-to-end through `verify_against_anchors`.

  Migration: callers wanting SPIFFE validation route the leaf
  cert's DER through `validate_uri_only` with a
  `UriMatchPolicy::Spiffe { path }` argument. The default path
  policy is `Prefix` per SPIFFE Federation §4.1.

- **`x509::verify::SpiffeId<'a>`** — borrowed-string parser for
  `spiffe://<trust-domain>/<workload-path>` (SPIFFE-ID §2.1):
  - rejects missing `spiffe://` scheme, empty / uppercase /
    non-DNS trust domain, empty / non-`/`-prefixed / non-normalised
    path, and total length > 2048 bytes (SPIFFE-ID §2.1.3);
  - trust-domain matching is case-sensitive (per spec);
  - exposes `trust_domain()` / `path()` accessors.

- **`x509::verify::UriMatchPolicy`** — public enum:
  - `Spiffe { path: SpiffePathPolicy }` (default — SPIFFE-aware);
  - `Literal` (raw string equality, no SPIFFE parsing).
- **`x509::verify::SpiffePathPolicy`** — `Prefix` (default, per
  SPIFFE Federation §4.1) / `Exact` (high-assurance).

- **20 new tests** in `tests/x509_uri_san.rs` exercising the full
  URI-matching surface (well-formed / malformed SPIFFE ID
  parsing, exact / prefix / exact-only path policies, mismatched
  trust domain, no URI SAN, non-SPIFFE URI SAN skipped under
  Spiffe policy, literal policy exact match / substring rejection,
  end-to-end cert issuance via gm-ca with a real URI SAN).

### Out of Scope

- The gm-tls / gm-tlcp `with_expected_uri(String)` builder that
  wires `validate_uri_only` into the handshake flow (PR-2.4+).
  The new function is fully usable from any caller today via the
  DER byte slice returned by `TlcpStream::peer_certificates()` etc.

## [0.3.5] - 2026-09-22

### Security

- **`x509::verify::verify_against_anchors` and
  `verify_cert_chain_sm2_chain` now default to fail-closed SM2
  distid semantics (only accept the GM/T standard
  `"1234567812345678"`).** Previously (gm-crypto ≤ 0.3.4) both
  helpers silently fell back to the empty distid `""` (OpenSSL 3.x
  default) after the GM/T standard distid failed. This created an
  asymmetric weakness: the gm-ca signer always uses the GM/T
  standard distid (`gm-ca/src/cert.rs:366` etc.), but the verifier
  would accept both — an attacker who obtained a cert signed with
  the empty distid (any tool using OpenSSL 3.x defaults) could
  bypass the stronger standard-distid requirement without leaving
  an audit trail.

  Migration:

  - **Default callers** (`verify_against_anchors(..)`,
    `verify_cert_chain_sm2_chain(..)`) automatically get the new
    strict behaviour. Audit the leaf-cert issuance path before
    upgrading if any peer signer is known to use the empty distid
    (OpenSSL 3.x without an explicit `distid` override).

  - **Operators that need OpenSSL 3.x interop** must opt in
    explicitly via the new
    [`verify_against_anchors_with_distid_policy(.., DistidPolicy::Permissive{..})`]
    entry point (or the PEM-path equivalent
    `verify_cert_chain_sm2_chain_with_distid_policy`). The
    permissive variant accepts the GM/T standard distid first, then
    tries a caller-provided list of fallback distids (typically
    `[""]` for OpenSSL 3.x); each successful fallback fires an
    audit callback with the accepted distid so operators can log,
    metric, or alert.

  - **CRL signatures** also use the strict default; the
    policy-aware `verify_crl_signature_with_distid` exists for
    parity but CRLs from a GmSSL-standard CA are always
    strict-compatible, so `Permissive` is rarely useful there.

### Added

- **`x509::verify::DistidPolicy`** — public enum with two
  variants (`Strict` default, `Permissive { fallback_distids,
  audit_on_fallback }`). `#[derive(Default)]` puts `Strict` behind
  any `..Default::default()` use.
- **`x509::verify::GM_TLS_DISTID`** — public constant for the
  GM/T standard distid `"1234567812345678"` (re-export of the
  internal string for callers that need it).
- **`x509::verify::verify_against_anchors_with_distid_policy(.., DistidPolicy)`**
  — policy-aware variant of `verify_against_anchors`.
- **`x509::verify::verify_cert_chain_sm2_chain_with_distid_policy(.., DistidPolicy)`**
  — policy-aware variant of `verify_cert_chain_sm2_chain`.
- **Four new unit tests** in [`src/x509/verify.rs`](src/x509/verify.rs)
  covering: default policy, STRICT rejects empty-distid signatures,
  PERMISSIVE accepts and fires the audit callback exactly once,
  PERMISSIVE silent when the audit callback is `None`.

## [0.3.4] - 2026-09-22

### Security

- **`x509::verify::check_revocations` now defaults to fail-closed CRL
  semantics (RFC 5280 §6.3 strict).** Previously (v0.3.2 / v0.3.3),
  `check_revocations` silently skipped malformed CRLs and CRLs whose
  issuer did not match any chain cert — fail-open behaviour that
  contradicted RFC 5280 §6.3 and GB/T 25056-2018 §7.4. A malformed
  CRL in such a deployment would be indistinguishable from "no CRL
  configured", silently disabling revocation checking for that hand-
  shake. This is now corrected.

  Migration:

  - **Default callers** (`check_revocations(chain, crls, now)`) automatically
    get the new strict behaviour. If a CRL in `crls` fails to parse, has
    an unparseable issuer DN, references a CA that is not in `chain`, or
    is otherwise unusable, the function returns
    [`CryptoError::CrlVerificationFailed`] instead of silently continuing.
    If your deployment relied on the silent-skip behaviour (e.g. a stale
    CRL cache where some entries may be corrupt), audit your CRL feed
    before upgrading.

  - **Operators that need v0.2.x / v0.3.0–v0.3.3 fail-open behaviour**
    must opt in explicitly via the new
    `check_revocations_with_policy(chain, crls, now, CrlVerifyPolicy::Permissive)`
    entry point. `Permissive` skips CRL processing errors (parse,
    issuer match, chain-entry parse) but still rejects invalid
    signatures, expired CRLs, and any serial present in a valid CRL's
    `revokedCertificates` list — the cryptographic revocation decision
    itself is never relaxed.

  - **`check_revocations` is now a one-line forwarder to
    `check_revocations_with_policy(.., CrlVerifyPolicy::Strict)`,** so
    the type signature is unchanged and downstream code continues to
    compile.

### Added

- **`x509::verify::CrlVerifyPolicy`** — public enum with two variants
  (`Strict`, `Permissive`). `#[derive(Default)]` defaults `Strict` so
  any caller using `..default()` or `..Default::default()` picks up the
  secure behaviour.
- **`x509::verify::check_revocations_with_policy(chain, crls, now, policy)`**
  — new entry point that takes the explicit [`CrlVerifyPolicy`]
  argument. Documented policy table in the rustdoc spells out which
  failure sources are policy-controlled (parse / issuer / chain-entry)
  and which always fail closed (signature / freshness / revoked-list).
- **Five new unit tests** in [`src/x509/verify.rs`](src/x509/verify.rs)
  covering:
  - `CrlVerifyPolicy::default() == Strict`
  - `Strict` rejects a malformed CRL; `Permissive` skips it.
  - Legacy `check_revocations` entry point defaults to `Strict`.
  - Empty `crls` list is a no-op under both policies (regression
    coverage for the early-return guard).
  - `Strict` rejection diagnostic includes the CRL parse-failure
    reason (operator-triage signal).

## [0.3.3] - 2026-09-18

### Fixed

- **SM2 signature / public-key OID byte sequences corrected
  to canonical DER** (1.2.156.10197.1.501 / 1.2.156.10197.1.301).
  The constants `SM2_SIG_OID_CSR` and `SM2_PK_OID_CSR` carried
  byte sequences that encoded a different OID (`1.2.26620389.*`)
  with a dangling continuation byte — a malformed OID per X.690.
  Fixed to the canonical GM/T 38636-2020 §6.4.6 encoding so
  the CSRs and certs `CsrBuilder` produces are interoperable
  with openssl.

- **`x509::verify::verify_against_anchors` no longer hardcodes
  `CertRole::Ca` on a single-element chain.** Previously, when
  the caller passed `chain = [leaf]` (the connector/acceptor
  call shape, distinct from the documented leaf-first full-chain
  shape `[leaf, intermediate, root]`), the root-branch always
  enforced `CertRole::Ca` — rejecting any legitimate TLCP leaf
  certificate (which carries `digitalSignature` and not
  `keyCertSign`). The closure `role_for_idx` now returns
  `Option<CertRole>` (None = skip role enforcement, the
  enc-cert path); the else-branch reads the caller's `role`
  option when the chain has length 1 and falls back to
  `CertRole::Ca` only when the chain has more entries
  (i.e. this really is the root).

- **`verify_against_anchors` doc comments now reflect actual
  semantics.** The previous docs recommended passing
  `[leaf, ca]` (a multi-element chain), but the function routes
  the first element through the "intermediate CA" branch —
  demanding `BasicConstraints CA:TRUE`, a condition leaf certs
  by definition do not satisfy. Docs now explicitly say
  callers should pass `[leaf]` (with the CA in `anchors_der`)
  or `[leaf, root]` (with an optional root in `anchors_der`).
  See R1 in `2026-09-18-gm-tlcp-fix-verification-v2.md`.

## [0.3.2] - 2026-09-18

### Added

- **`x509::verify::check_revocations`** — RFC 5280 §5 CRL revocation
  check helper for `verify_against_anchors`. Walks the validated
  chain (leaf + intermediates + root) and, for each cert whose
  issuer matches a CRL's issuer, checks whether the cert's serial
  appears in that CRL's `revokedCertificates` list. The CRL's
  signature is verified against the chain cert whose subject equals
  the CRL's issuer. CRLs with no matching issuer in the chain are
  silently skipped (operators are expected to provide CRLs that
  match their configured anchors). Malformed CRLs are also silently
  skipped (one bad CRL does not invalidate the whole handshake).
- **`OwnedCert::from_der`** — accept a single DER certificate
  (raw bytes that are NOT a PEM envelope). Used by callers like
  `gm-tlcp` that receive certs from the TLCP wire-format (DER).
- **`OwnedCert::from_pem_or_der`** — convenience that detects
  PEM-vs-DER by header bytes and dispatches to the matching
  parser. Useful for unit-test fixtures that sometimes ship as
  one form, sometimes the other.

### Fixed

- **`x509::verify::extract_crl_signature`** (private helper used by
  `verify_crl_signature`) — the hand-rolled DER walker was computing
  "end of outer CRL content" rather than "end of TBSCertList",
  which produced the wrong offset whenever the outer CRL SEQUENCE
  used the long-form length (e.g. `30 81 c9`). Replaced with a
  call that borrows the BIT STRING's raw slice from the parsed
  `CertificateRevocationList`, so the signature range is always
  correct regardless of the outer length encoding.

## [0.3.0] - 2026-09-07

### Added

- **`Sm2EcdhKeypair::private_key_bytes()`** —
  ([`src/sm2.rs`](src/sm2.rs)).
  Returns the 32-byte big-endian scalar of the raw ECDH keypair's
  private key as `Vec<u8>`. This is the input that the SM2 Key
  Agreement Protocol (GB/T 32918.3-2016 §6.1 B4 / GM/T 0003.3-2012 §6.1)
  needs when computing the per-ephemeral `k_A` (initiator) /
  `k_B` (responder) term in the `V = k_A · R_B` step. The new method
  exposes the scalar without dragging in any of the internal `Scalar`
  machinery, keeping the public API stable for callers that just need
  the bytes to feed into a KAP call.

  Required by the `tlcp-strict` server-side ECDHE PMS fix in
  `gm-tlcp 0.2.2` (audit C-3, originally landed in `gm-tlcp 0.2.1`
  but only now consumable from crates.io because of the matching
  `gm-crypto` version bump).

### Compatibility

This release adds new APIs only; no existing API has been changed or
removed. Fully backwards-compatible with the 0.2.x series.

## [0.2.0] - 2026-09-04

### Added

#### SM4 raw CBC primitives (no PKCS#7 padding)

- **`Sm4Cipher::encrypt_cbc_raw`** — CBC mode encryption that operates
  on the input bytes verbatim without applying PKCS#7 padding. The
  caller is responsible for any padding the protocol layer requires.
  This is the right primitive when the protocol layer (e.g. TLCP
  record-layer MAC-then-Encrypt, TLS 1.1 CBC suites) already manages
  its own padding — using the regular `encrypt_cbc` in that
  situation would add a *second* layer of padding and corrupt the
  wire format.

- **`Sm4Cipher::decrypt_cbc_raw`** — symmetric counterpart of
  `encrypt_cbc_raw`. Decrypts raw ciphertext blocks without removing
  any padding. Callers that need PKCS#7 stripping should call this
  and then run their own `unpad_pkcs7` logic.

These two functions are the foundation for the new `gm-tlcp`
crate's MAC-then-Encrypt CBC record-layer framing.

#### X.509 SM2 public key extraction

- **`x509::extract_sm2_pubkey_from_der`** — given a DER-encoded X.509
  certificate, returns the raw SM2 public key as 65 bytes in
  uncompressed SEC1 form (`0x04 || x || y`). The function defensively
  masks the BIT STRING trailing-bits count because GmSSL has
  historically emitted SPKI BIT STRINGs with non-zero unused-bits
  values (e.g. `4` when the high nibble of the last byte is `0`),
  which would otherwise leak into downstream SM2 encryption/verifier
  constructors and cause them to reject the public key.

  This function is what `gm-tlcp`'s certificate verification path uses
  to extract the server's static encryption pubkey from the enc cert
  and the client's static encryption pubkey from the client enc cert
  before driving SM2 ECDHE key agreement per GB/T 32918.3-2016.

### Compatibility

This release adds new APIs only; no existing API has been changed or
removed. The crate's public surface is fully backwards-compatible with
the 0.1.x series.

[Unreleased]: https://github.com/GM-Engineers/gm/compare/main...HEAD
[0.3.6]: https://github.com/GM-Engineers/gm/compare/gm-crypto-v0.3.5...gm-crypto-v0.3.6
[0.3.5]: https://github.com/GM-Engineers/gm/compare/gm-crypto-v0.3.4...gm-crypto-v0.3.5
[0.3.4]: https://github.com/GM-Engineers/gm/compare/gm-crypto-v0.3.3...gm-crypto-v0.3.4
[0.3.2]: https://github.com/GM-Engineers/gm/compare/gm-crypto-v0.3.1...gm-crypto-v0.3.2
[0.3.1]: https://github.com/GM-Engineers/gm/compare/gm-crypto-v0.3.0...gm-crypto-v0.3.1
[0.3.0]: https://github.com/GM-Engineers/gm/compare/gm-crypto-v0.2.0...gm-crypto-v0.3.0
[0.2.0]: https://github.com/GM-Engineers/gm/releases/tag/gm-crypto-v0.2.0
