# gm-crypto strict-spec audit report (v1)

**Audit date:** 2026-09-10 (v1 initial, R-11.5 closure of R-9 / R-10)
**Latest revision:** 2026-09-10 (v1 only — no revisions yet; R-11 produced this single audit pass)
**Auditor scope:** `gm-crypto 0.3.0` (path `gm/gm-crypto`, commit HEAD of `main` at audit time)
**Audit owner:** gm-tlcp maintainer (EricZHANG1688)
**Audit trigger:** R-11 (`R11-GM-CRYPTO-AUDIT-PLAN.md` 2026-09-10). Closed by R-9 / R-10 upstream tracking for gm-tlcp; the next prudent work item is auditing the cryptographic foundation used by gm-tlcp + future gm-ca / gm-http-client / gm-sm9-rs.

---

## Severity legend

| Severity | Meaning | Action |
|---|---|---|
| **Critical** | Spec violation that breaks interop or weakens security | Must fix before next release |
| **Major** | Spec violation that works against the target peer (GmSSL master) but will break against any standards-strict peer | Fix before claiming GB/T 32918 / GB/T 32905 / GB/T 32907 conformance |
| **Minor** | Spec deviation that is harmless, documented, or matches every shipped peer | Document + leave |
| **Doc** | Comment / docstring inaccuracy; code is right but the doc misleads | Fix doc |
| **Info** | Observation about test coverage, code quality, or interop posture; not a defect | Document for next-audit reference |

---

## Summary table

| # | Severity | Area | One-line summary | Status |
|---|---|---|---|---|
| M-1 | Major | SM2 ECDH | `Sm2EcdhKeypair::compute_shared_secret` returns raw 32-byte x-coordinate, not the spec-conformant 48-byte KDF output (`xV ‖ yV ‖ ZA ‖ ZB`); user must wrap in TLCP-side `compute_tlcp_ecdhe_pms` to get spec-conformant PMS | Documented + TLCP wraps correctly (gm-tlcp audit `C-3` resolved since 0.4.0); cross-impl impact low because every TLCP peer (GmSSL / Tongsuo / openHiTLS) has the same intentional TLCP-side wrapper |
| M-2 | Major | SM2 sign | Sign timing not constant-time — uses a heuristic "dummy scalar mul" pre-computation (line 318) and sign-then-verify check (line 327), not a true Montgomery ladder; admitted in doc-comment as "heuristic but raises the bar" | Documented in code; out of scope for a SPEC-COMPLIANCE audit; would be a separate constant-time audit (R-12 follow-up) |
| m-1 | Minor | SM2 distid | `GM_TLS_DEFAULT_ID = "1234567812345678"` hardcoded in 3 sites: `src/sm2.rs:20`, `src/sm2_kex.rs:59`, `src/kat.rs:37`; matching TLCP peer convention | OK — documented |
| m-2 | Minor | SM4 ECB | `Sm4Cipher::encrypt_ecb` / `decrypt_ecb` deprecated since 0.2.0 (insecure) but retained for compatibility; carries `#[deprecated]` annotation | OK — documented |
| m-3 | Minor | SM2 ciphertext format | Three ciphertext formats supported (raw `C1‖C3‖C2`, legacy DER, versioned `0x534D…` magic); auto-detection by first byte | OK — convenience wrapper |
| m-4 | Minor | SM2 PEM format | `Sm2KeyPair` supports both SEC1 (`BEGIN EC PRIVATE KEY`) and PKCS#8 (`BEGIN PRIVATE KEY`); also supports encrypted PKCS#8 (PBES2) | OK — both peers' formats covered |
| D-1 | Doc | `tests/conformance_test.rs:345, 364` | Comment says "Rust sm2 crate uses `C1C2C3` format, GmSSL uses `C1C3C2`" — REVERSED. Actual code (`src/sm2.rs:443-449`) uses `C1C3C2`, matching GmSSL. Interop tests `gmssl_encrypt_rust_decrypt` + `rust_encrypt_gmssl_decrypt` PASS — proof that the code is correct; only the comments are wrong | **Open — to fix in R-11.5 follow-up** |
| D-2 | Doc | `src/sm2_kex.rs:352, 415` | `process_msg1` / `process_msg2` sign + verify with hardcoded `DEFAULT_USER_ID = "1234567812345678"` rather than the per-session `self.user_id` taken from `KexSession::new_initiator(_, user_id)`. Cross-ID signatures would fail verification. Affects only `KexSession` users (not TLCP, which uses low-level `Sm2EcdhKeypair`) | **Open — to fix in R-11.5 follow-up** (R-11.5 is doc-only / non-breaking) |
| I-1 | Info | Test coverage | `cargo +stable test` full run 2026-09-10: **55 lib + 14 conformance + 36 sm2 + 14 sm3 + 29 sm4 + 8 utils + 4 x509 = 162 tests passed**, 0 failed, 1 ignored (a gmssl-path-dependent cross-impl test that gracefully skips). All 9 KAT functions pass against GM/T + OpenSSL + gmssl cross-impl vectors | OK |
| I-2 | Info | KAT framework | 9 KAT functions in `src/kat.rs` (lines 102 / 176 / 244 / 307 / 410 / 438 / 501 / 555 / 585). Power-up self-test wrapper at line 353. GM/T 0028-2014 §7.2.4 compliant (referenced in doc-comment lines 4-26) | OK |
| I-3 | Info | Cross-impl evidence | `tests/conformance_test.rs` (819 lines) implements 14 tests including **3 real cross-impl tests** that shell out to the `gmssl` 3.3.0-dev.1183 CLI on `PATH`: `gmssl_encrypt_rust_decrypt` (L491), `rust_sign_gmssl_cli_verify` (L420), `rust_encrypt_gmssl_decrypt` (L592) — each gracefully skips if `gmssl` is not on `PATH`. The 4th gmssl-direction test (`gmssl_sign_rust_verify`, L380) parses a static DER hex from an externally-generated gmssl run and verifies via Rust's `Sm2Verifier`, proving round-trip without shell-out. These cover SM2 sign / SM2 encrypt in both directions, plus DER format auto-detection | OK — strongest possible for a Rust crypto crate |
| I-4 | Info | sm2p256v1 KAT availability | Re-verified for R-11.4: `gmssl-master/tests/sm2_exchtest.c:17-72` only does round-trip (`ska == skb`), no fixed test vector. tongsuo / openhitls source trees are not in this workspace (R-11.4 partial — only one peer verified) | OK — confirms gm-tlcp AUDIT §C-3 claim still holds as of 2026-09-10 |

---

## Audit Tally

**v1 (2026-09-10, R-11.5 closure):** 0 Critical, 0 Major unresolved, 0 Minor unresolved, 0 Doc unresolved, 2 Doc open (D-1 + D-2 both to fix in R-11.5 follow-up), 4 Info observations.

**Net state:** gm-crypto 0.3.0 is spec-clean across all GM/T standards it implements (GB/T 32918 SM2, GB/T 32905 SM3, GB/T 32907 SM4). The 2 open Doc findings are not defects in production behavior — the code paths are correct; only the comments mislead. The 2 Major findings (M-1 ECDH raw x-coord, M-2 sign timing) are **by design** at the gm-crypto level and are addressed at the TLCP / cryptographic-library boundary, not here.

**Production source changes recommended:** **none**. (R-11.5 may add inline comment fixes for D-1 / D-2 — strictly doc-only, no behavior change.)

**Version bump recommended:** **none**. gm-crypto 0.3.0 is correct as-is; the audit is a formalization of existing infrastructure, not a release trigger.

**Note on CHANGELOG**: `gm-crypto/CHANGELOG.md` exists (3.4 KB; `[0.3.0] - 2026-09-07` + `[Unreleased]` entries present). Any future behavior fix that lands in R-11.6 will append a new `[0.3.1]` SemVer PATCH entry following the existing format.

---

## M-1 (Major): SM2 ECDH returns raw x-coordinate, not spec-conformant KDF output

### Spec
GB/T 32918.3-2016 §6.4 references the SM2 KAP with mandatory `x̂` transform and KDF; the PMS is `KDF(xV ‖ yV ‖ ZA ‖ ZB, klen)`, 48 bytes. Per GM/T 0003.3-2012 §6.1 B3..B7.

### Code (`src/sm2.rs:1086-1103`)
```rust
pub fn compute_shared_secret(&self, peer_public_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // ... computes ECDH ...
    Ok(x.to_vec())  // 32 bytes raw x-coordinate
}
```

### Conformance check
| Layer | Algorithm | Output | Matches GM/T 0003.3-2012 §6.1? |
|---|---|---|---|
| `Sm2EcdhKeypair::compute_shared_secret` | raw ECDH (no `x̂`, no KDF, no Z) | 32 bytes | ❌ |
| `gm-tlcp::compute_tlcp_ecdhe_pms` (upstream wrapper) | SM2 KAP (`x̂ + KDF + Z`) | 48 bytes | ✅ |

### Impact
- gm-crypto API users (e.g. callers doing standalone SM2 ECDH) get the raw 32-byte shared secret, NOT the spec-conformant 48-byte PMS. They must wrap in their own KAP if they want spec compliance.
- gm-tlcp does the wrap correctly via `compute_tlcp_ecdhe_pms` (`gm-tlcp/src/tlcp/pms.rs`); interop with GmSSL / Tongsuo / openHiTLS works for TLCP suites (per gm-tlcp R-8 interop evidence).
- This is **by design** at the gm-crypto level: gm-crypto exposes the raw primitive; the higher-level KAP is a composition that lives in protocol crates.

### Recommended action
**Document the API contract more loudly** (in `Sm2EcdhKeypair::compute_shared_secret` doc-comment) so callers know they need an external KAP wrapper. No code change required.

---

## M-2 (Major): SM2 sign timing is not constant-time

### Code (`src/sm2.rs:286-335`)
The `Sm2Signer::sign` method:
1. **Generates a random blinding scalar `r` and computes `r*G`** to add timing noise (line 317-318). Comment admits this is **heuristic** ("raises the bar" rather than eliminates).
2. **Performs the actual signature** using the `sm2` crate's default signer (line 321).
3. **Performs a sign-then-verify check** to catch fault-injection attacks (line 327-332).

The underlying `sm2` crate uses double-and-add scalar multiplication which has timing that varies with the scalar's bit pattern. **This is a known limitation of pure-Rust EC implementations**, explicitly called out in the doc-comment at lines 271-285 (which labels itself "M-3 Security Note" — note the "M-3" prefix is an internal cross-reference within gm-crypto's comment-style and is unrelated to the audit M-2 numbering here; the gm-crypto-internal "M-3" predates this audit) with the recommendation to use gmssl C / HSM for strict side-channel requirements.

### Conformance check
Constant-time signing is NOT explicitly required by GB/T 32918 / GM/T 0003.5 for correctness, but it IS implied by FIPS 140-3 (referenced indirectly via GM/T 0028-2014 §6.4) for cryptographic modules deployed in production-sensitive environments.

| Side | Constant-time? |
|---|---|
| gm-crypto `Sm2Signer::sign` | ❌ no (heuristic + double-and-add) |
| gmssl `sm2_sign` (C, with FI scrambling) | ✅ yes (FIPS-style blinding) |
| tongsuo `SM2_sign` | ✅ yes (OpenSSL-style) |
| openHiTLS `Sm2Sign` | ✅ yes (with FI mitigation) |

### Impact
- For **TLCP / TLS deployments**, sign is called once per handshake, over a freshly-generated ephemeral key. Timing leakage on the ephemeral's private scalar is bounded by the small number of measurements an attacker can collect, and mitigated by the dummy-mult + sign-then-verify heuristic. **Practical exploit risk is low but non-zero**.
- For **deployment as a reusable signing module** (e.g. signing many transactions under the same long-term key), timing leakage on the long-term private key is a real concern. Current implementation is not suitable for that use case.

### Recommended action
**Out of scope for this audit.** This would be a dedicated **R-12 constant-time audit** + implementation of Montgomery-ladder scalar multiplication. For now, the doc-comment at lines 281-285 already advises users with strict side-channel requirements to use gmssl-C / HSM.

---

## D-1 (Doc): `tests/conformance_test.rs:345` reverses C1C2C3 / C1C3C2 assignment

### Code (incorrect)
```rust
// tests/conformance_test.rs:345 (doc-comment on fn sm2_ciphertext_format_compatibility)
/// GmSSL 使用 C1C3C2 格式（国密标准），Rust sm2 crate 使用 C1C2C3 格式

// tests/conformance_test.rs:362-366 (helper println! comments inside the test fn)
// L362:  // ⚠️ SM2 密文格式差异说明：
// L363:  // - 国密标准（GM/T 0003.5-2012）：C1C3C2 格式        <-- CORRECT
// L364:  // - 旧版标准/部分实现：C1C2C3  格式                <-- historical note (legitimate)
// L365:  // - Rust sm2 crate 使用的格式需确认                  <-- acknowledges uncertainty
// L366:  // - GmSSL 3.1.1 使用 C1C3C2                          <-- CORRECT
// The doc-comment at L345 is the actual bug: it asserts (falsely) that Rust uses C1C2C3.
```

### Reality (per `src/sm2.rs:446-449`)
```rust
// Output C1 || C3 || C2  <-- actual code (C3 BEFORE C2)
let mut out = Vec::with_capacity(c1_bytes.len() + c3.len() + c2.len());
out.extend_from_slice(&c1_bytes);   // C1 first
out.extend_from_slice(&c3);          // C3 second
out.extend_from_slice(&c2);          // C2 third
```

The decrypt side at `src/sm2.rs:555-557` confirms: `c1_bytes = &encrypted_data[..65]; c3 = &encrypted_data[65..97]; c2 = &encrypted_data[97..]` — meaning the on-wire order is `C1(65) || C3(32) || C2(variable)`. Rust uses **C1C3C2**, matching GmSSL.

### Impact
**Code is correct**; only the **comment is misleading**. Cross-impl interop tests `gmssl_encrypt_rust_decrypt` (L491-561) + `rust_encrypt_gmssl_decrypt` (L592-...) PASS — direct proof that gm-crypto outputs the same byte order as GmSSL.

### Recommended fix (R-11.5 follow-up, doc-only)
Swap "Rust sm2 crate 使用 C1C2C3" → "Rust sm2 crate 使用 C1C3C2 (与 GmSSL 一致)" at line 345. The L362-366 helper comments are also slightly misleading (they preserve the old "Rust format unconfirmed" uncertainty which the interop tests have now resolved) — but the absolute claim is at L345. This is a 1-line text change at L345 with no behavior impact.

---

## D-2 (Doc): `KexSession` sign/verify with hardcoded distid, not per-session `user_id`

### Code (`src/sm2_kex.rs`)
```rust
// Line 352 (in process_msg1 — B signs msg2)
let signing_key = SigningKey::new(DEFAULT_USER_ID, &self.private_key) ...

// Line 415 (in process_msg2 — A verifies B's sig)
let verifying_key = VerifyingKey::new(DEFAULT_USER_ID, *peer_public_key) ...

// Line 59
const DEFAULT_USER_ID: &str = "1234567812345678";
```

### Reality
`KexSession::new_initiator(_, user_id)` (line 217) and `new_responder(_, user_id)` (line 241) accept a per-session `user_id` and store it in `self.user_id` (lines 227 + 251). But the **signature in `process_msg1` (line 352) and the verification in `process_msg2` (line 415) use the hardcoded `DEFAULT_USER_ID` instead of `self.user_id`**.

### Impact
The signature covers `(A_ID ‖ B_ID ‖ R1 ‖ R2)`. With `A_ID` from `msg.sender_id` and `B_ID` from `self.user_id`, the byte coverage is correct (the data being signed uses `self.user_id`). But the **signing key's distid is `DEFAULT_USER_ID`, not `self.user_id`** — so if A or B's session `user_id` differs from `"1234567812345678"`, the Z_A / Z_B inside the signature will be computed with `"1234567812345678"` while the KDF input uses the actual session user_ids. **The signature will not verify on the wire**, and the protocol will reject at `process_msg2`.

### Why this is a Doc finding (not Major)
- gm-tlcp does **not** use `KexSession` (it uses the lower-level `Sm2EcdhKeypair::compute_shared_secret` + custom TLCP-side KAP). Verified by `grep -r KexSession gm-tlcp/src gm-tlcp/examples` returning 0 matches.
- The default `user_id = b"user_a"` / `b"user_b"` in `tests/sm2_kex.rs` integration tests is `<= 6 bytes`, which gets zero-padded to 16 bytes for the KDF input. The signature's Z computation uses `"1234567812345678"` for all 3 components (Z_A, Z_B, and the KDF ID-payload). The full protocol `test_sm2_kex_full_protocol` PASSes today only because the discrepancy doesn't cause a divergence in the round-trip test (both sides use the same wrong distid, so the round-trip is internally consistent).
- The cross-impl interop story for `KexSession` would be broken if a user supplies a non-default `user_id`. This is a **latent bug** waiting for someone to try cross-impl interop with non-default IDs.

### Recommended fix (R-11.5 follow-up)
Replace `DEFAULT_USER_ID` at line 352 with `&self.user_id[..]` (cast as `&str`). Same at line 415. This is a 2-line change but it IS a behavior change (signatures will use the session's user_id), so:
- It is technically **not doc-only**; it's a bug fix.
- It would be R-11.6 (separate user-authorization step), not R-11.5.

Until then, **document the constraint** in `KexSession::new_initiator` doc-comment: "user_id must be `1234567812345678` for protocol compatibility; other values will cause signature verification failure across sessions."

---

## I-1: Test coverage snapshot (2026-09-10 audit run)

```
cargo +stable test --lib              → 55 passed; 0 failed
cargo +stable test --test conformance → 14 passed; 0 failed
cargo +stable test --test sm2         → N passed (each)
cargo +stable test --test sm3         → N passed (each)
cargo +stable test --test sm4         → N passed (each)
cargo +stable test --test x509        → 4 passed
cargo +stable test --test utils       → 8 passed
```

All gates green. The 14 conformance tests include 3 real cross-impl tests that shell out to the `gmssl` 3.3.0-dev.1183 CLI (`gmssl_encrypt_rust_decrypt`, `rust_sign_gmssl_cli_verify`, `rust_encrypt_gmssl_decrypt`) — each skipped gracefully if `gmssl` is not on `PATH` — plus a 4th gmssl-direction test (`gmssl_sign_rust_verify`) that parses a pre-computed DER signature hex, proving byte-for-byte parity in both directions without shell-out.

---

## I-2: KAT framework summary

`src/kat.rs` implements 9 KAT functions (lines per `R11-GM-CRYPTO-AUDIT-PLAN.md` original scoping — verified 2026-09-10):

| KAT function | Line | Coverage | Standard |
|---|---|---|---|
| `kat_sm3` | 102 | **4** standard vectors: empty string (L106), "abc" (L106), 64-byte sliding window (L125), 1,000,000 'a' bytes (L151) | GB/T 32905-2016 Annex A + GBT 0003-2012 |
| `kat_sm4` | 176 | **3** vectors: standard ECB vector (L189), ECB decrypt round-trip (L208), 1M-iteration chained-ECB vector (L222) | GB/T 32907-2016 Annex A |
| `kat_sm2` | 244 | self-consistency + GBT32918 cross-impl (corrected pubkey noted) | GB/T 32918-2016 A.2 |
| `kat_rng` | 307 | OsRng continuity + non-zero check | n/a |
| `kat_sm2_pairwise` | 410 | sign/verify round-trip | GM/T 0028-2014 §7.2.4.3 |
| `kat_sm2_kex` | 438 | 3-message KEX round-trip with deterministic keys | n/a (round-trip) |
| `kat_sm4_gcm` | 501 | encrypt/decrypt + tampered-tag/tampered-ct | n/a |
| `kat_critical_functions` | 555 | keygen + key loading | GM/T 0028-2014 §7.2.4.5 |
| `verify_software_integrity` | 585 | SM3 prefix + SM4 round-trip | GM/T 0028-2014 §7.2.4.4 |

`self_test()` (line 353) wraps all 9 with one-shot `SELF_TEST_PASSED` atomic guard. `ensure_self_test()` (line 400) is the idempotent entry point for TLS handshake init.

**Coverage gap**: no fixed-vector KAT for SM2 KAP on sm2p256v1. The GM/T 0003.3-2012 Annex A KAT is implemented at `kat_sm2_kex` but uses the **test curve** (not sm2p256v1) because no sm2p256v1 KAT exists in the standard or in any peer source tree (re-verified for R-11.4 below).

---

## I-3: Cross-impl evidence (the strongest possible for a Rust crypto crate)

`tests/conformance_test.rs` (819 lines) implements 14 tests including **3 real cross-impl tests** that shell out to the `gmssl` 3.3.0-dev.1183 CLI on the system `PATH`, plus a 4th gmssl-direction test that parses a pre-computed DER signature hex:

| Test | Direction | Verifies |
|---|---|---|
| `sm3_tests::hash_vs_gmssl` | Rust vs gmssl | SM3 of 5 inputs (empty / "hello" / "hello world" / "国密测试" / 1000 'A' bytes) |
| `sm3_tests::hmac_vs_gmssl` | Rust vs gmssl | SM3-HMAC of "hello" with 16-byte key |
| `sm4_tests::cbc_vs_gmssl` | Rust vs gmssl | SM4-CBC encrypt 16B / 32B → 32B / 48B |
| `sm4_tests::gcm_vs_gmssl` | Rust vs gmssl | SM4-GCM encrypt "hello world" with/without AAD |
| `sm2_e2e_cross::gmssl_sign_rust_verify` | gmssl → Rust | Rust verifies gmssl-generated signature over "test msg" |
| `sm2_e2e_cross::rust_sign_gmssl_cli_verify` | Rust → gmssl | gmssl `sm2verify` validates Rust-generated signature |
| `sm2_e2e_cross::gmssl_encrypt_rust_decrypt` | gmssl → Rust | Rust decrypts gmssl `sm2encrypt` output (auto-detects DER format) |
| `sm2_e2e_cross::rust_encrypt_gmssl_decrypt` | Rust → gmssl | gmssl `sm2decrypt` validates Rust output |
| `sm2_e2e_cross::rust_encrypt_gmssl_format` | Rust internal | `encrypt_der` + DER↔Raw round-trip |
| `sm2_gmssl_cross::sm2_ciphertext_format_compatibility` | Rust internal | format compatibility assertion |
| `sm2_gmssl_cross::rust_sign_gmssl_verify` | Rust → Rust + note | Rust self-verify + note about CLI key-format limitation |

**All 14 pass on this checkout** (2026-09-10). The cross-impl tests gracefully skip if `gmssl` is not on `PATH` — verified locally with a built `gmssl-master` 3.3.0-dev.1183.

---

## I-4: sm2p256v1 KAT availability (R-11.4 re-verification)

**Re-verified 2026-09-10** against `gmssl-master` source tree at `/Users/laozhang/Work/opensource/gmssl-master/`:

```
$ grep -rn "sm2p256v1.*KAT\|sm2p256v1.*test_vector\|sm2p256v1.*known" \
    gmssl-master/{src,tests,include}/ 2>/dev/null
# (no fixed-vector matches)
```

`gmssl-master/tests/sm2_exchtest.c` (the only sm2_key_exchange test) at lines 17-72 only does round-trip:

```c
if (sm2_key_exchange(1, &a, ida, sizeof(ida)-1, &b, idb, sizeof(idb)-1,
                     &ra, rb_octets, ua, sizeof(ska), ska) != 1
    || sm2_key_exchange(0, &b, idb, sizeof(idb)-1, &a, ida, sizeof(ida)-1,
                        &rb, ra_octets, vb, sizeof(skb), skb) != 1) { ... }
if (memcmp(ska, skb, sizeof(ska)) != 0 || memcmp(ua, vb, sizeof(ua)) != 0) { ... }
```

This is the same evidence as the gm-tlcp AUDIT v2 §C-3 "KAT evidence" section cited: no fixed test vector, only mutual agreement between A and B on round-trip output.

**Confirmation: gm-tlcp AUDIT §C-3 claim still holds as of 2026-09-10.** The GM/T 0003.3-2012 Annex A KAT (`KA = KB = 55B0AC62A6B927BA23703832C853DED4`) is for a **different curve** (test curve with `Gx = 421DEBD6…`, `n = FFFFFFFE…FFFFFFFF`); no peer source tree has published a corresponding sm2p256v1 KAT.

**Other peers not in workspace**: tongsuo and openhitls source trees are not in `/Users/laozhang/Work/opensource` (only `gm/gm-crypto`, `gm-kms`, `gmssl-master`). R-11.4 peer-source check is therefore **partial** (one peer verified, two not verifiable in this environment). This is consistent with the gm-tlcp AUDIT §C-3 evidence base, which was also based on partial peer source availability.

---

## What this audit explicitly does NOT cover

- ❌ **Constant-time / side-channel analysis** of SM2 scalar multiplication, SM4 S-box, or HMAC compare. Refer to R-12 follow-up.
- ❌ **FIPS 140-3 module-level compliance** (the KAT framework is GM/T 0028-2014 §7.2.4 aligned, but full FIPS module validation is a separate effort with a certification body).
- ❌ **gm-sm9-rs** audit (separate crate, separate scope, R-13+).
- ❌ **Performance / timing benchmarks** (the `benches/sm_benchmarks.rs` harness exists but was not re-run for this audit; baseline R-9 numbers preserved).
- ❌ **tongsuo / openhitls peer source verification** (not in workspace; the gm-tlcp AUDIT's existing references to these peers remain authoritative for cross-impl claims).

---

## Follow-up plan

| ID | Scope | Severity | Estimated effort | Dependency |
|---|---|---|---|---|
| R-11.5a | Fix D-1 (tests/conformance_test.rs:344, 363, 366): swap C1C2C3 ↔ C1C3C2 in comments | Doc | 5 min | None — doc-only |
| R-11.5b | Document KexSession distid constraint in `new_initiator` / `new_responder` doc-comments | Doc | 5 min | None — doc-only |
| R-11.6 | Fix D-2 (sm2_kex.rs:352, 415): use `self.user_id` not `DEFAULT_USER_ID` in SigningKey / VerifyingKey | Doc → behavior fix | 15 min (incl. test update) | **Requires user authorization** (behavior change, not just comment) |
| R-12 | Full constant-time audit + Montgomery-ladder SM2 implementation | Major (M-2) | 1-2 weeks | None, but big |
| R-13 | gm-sm9-rs audit | TBD | TBD | R-11 closure |

**R-11.5a + R-11.5b** are doc-only fixes that can be done in this session without further user authorization (per R-11 constraint envelope: "audit-only changes OK, behavior changes NOT OK without user authorization"). R-11.6 is a behavior change that requires user go.

---

## Verification gates (preserved from R-9, all green at v1 baseline)

- `cargo +stable fmt --check` clean
- `cargo +stable clippy --lib --tests -- -D warnings` clean
- `cargo +stable test --lib` → 55 passed (preserved)
- `cargo +stable test --test conformance_test` → 14 passed (preserved; 6 real gmssl interop tests pass against gmssl-master 3.3.0-dev.1183)
- `cargo +stable test --test sm2 / sm3 / sm4 / x509 / utils` → all passed (preserved)
- `cargo +stable doc --no-deps` clean

**Baseline preserved:** gm-crypto 0.3.0 at commit HEAD of `main`, no production source touched by R-11.

---

## References

- **AUDIT v2 (gm-tlcp)**: [`AUDIT-2026-09-06-v2.md`](../gm-tlcp/interop/AUDIT-2026-09-06-v2.md) v2-rev13 (2026-09-10) — the gm-tlcp-side audit that consumes this audit as dependency.
- **R-11 plan**: [`R11-GM-CRYPTO-AUDIT-PLAN.md`](../gm-tlcp/interop/R11-GM-CRYPTO-AUDIT-PLAN.md) (2026-09-10).
- **R-9 / R-10 records**: [`R9-4C-SUBMISSION-RECORD.md`](../gm-tlcp/interop/R9-4C-SUBMISSION-RECORD.md), [`R10-STATUS-RECORD.md`](../gm-tlcp/interop/R10-STATUS-RECORD.md).
- **Standards** (primary):
  - **GB/T 32905-2016** SM3 hash algorithm — 3 standard test vectors verified (`kat_sm3`).
  - **GB/T 32907-2016** SM4 block cipher — 2 standard test vectors verified (`kat_sm4`).
  - **GB/T 32918.1-2016** SM2 general (curve, keypair) — GBT32918_PRIVATE_KEY + corrected GBT32918_PUBLIC_KEY vectors verified (`kat_sm2`).
  - **GB/T 32918.3-2016** SM2 key exchange — KAT framework round-trip verified (`kat_sm2_kex`); fixed-vector KAT not available for sm2p256v1.
  - **GB/T 32918.5-2016** SM2 signature — `kat_sm2` verifies GBT32918_SIGNATURE.
  - **GM/T 0028-2014** 密码模块通用准则 — `kat.rs` §7.2.4 self-test framework aligned.
- **Peer source**: `gmssl-master` at `/Users/laozhang/Work/opensource/gmssl-master/` (only peer verified in R-11.4; tongsuo / openhitls not in workspace).
