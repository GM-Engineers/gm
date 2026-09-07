# M-2 Root Cause Analysis: SM2 ECDHE x̂ Transform Direction

Status: investigation complete, awaiting user approval before any code change.

## TL;DR

`gm-tlcp/src/tlcp/pms.rs:117,123` applies the SM2 x̂ transform to the
**wrong** x-coordinate relative to the spec. The implementation is
self-consistent (gm-tlcp ↔ gm-tlcp roundtrip test passes) but disagrees
with every spec-conformant peer (openHiTLS, Tongsuo, GmSSL master). The
PR4 strict-mode interop test reproduces this: CKE/CV/CCS all accepted,
then `Decrypt Error (51)` on Finished because the master_secret derived
from the wrong PMS.

## Spec reference

GB/T 32918.3-2016 §6.4.2 (key agreement with key confirmation, the
basis for TLCP ECDHE per GB/T 38636-2020 §6.4.6.2 / GmSSL's
`tlcp_send_client_key_exchange`):

For **user A (initiator)**, given:
- static priv `d_A`, static pub `P_A = d_A · G`
- ephemeral priv `r_A`, ephemeral pub `R_A = r_A · G`
- peer's ephemeral `R_B` and static `P_B`

```
x_1 = x-coordinate of R_B              (peer's ephemeral)
x_2 = x-coordinate of R_A              (own ephemeral)
t_A = 2^127 + (x_1 mod 2^127) · r_A + d_A   (mod n)   ← x̂ applied to PEER's x
V   = t_A · ( (2^127 + (x_2 mod 2^127)) · R_B  +  P_B )  ← x̂ applied to OWN x
```

For **user B (responder)**, swap A↔B.

## Current gm-tlcp implementation (`pms.rs:91-143`)

```rust
let (local_ephemeral_x, _) = point_xy_bytes(&local_ephemeral_point)?;  // = x-coord of R_A
let local_x_hat = scalar_from_x_hat(&local_ephemeral_x)?;              // = x̂(R_A.x)
let t = local_x_hat * local_ephemeral_scalar + local_static_scalar;     // = x̂(R_A.x)·r_A + d_A

let (peer_ephemeral_x, _) = point_xy_bytes(&peer_ephemeral_point)?;    // = x-coord of R_B
let peer_x_hat = scalar_from_x_hat(&peer_ephemeral_x)?;                // = x̂(R_B.x)
let shared_point = peer_ephemeral_point * peer_x_hat + peer_static_point;  // = R_B·x̂(R_B.x) + P_B

let v = shared_point * t;
```

Both `t` and `shared_point` use x̂ on the **same** x-coordinate (own
ephemeral in `t`, peer ephemeral in `shared_point`), but in the
**opposite** order from the spec.

The spec says:
- `t` should use `x̂(peer_ephemeral_x)` = `x̂(R_B.x)`
- `shared_point` should use `x̂(own_ephemeral_x)` = `x̂(R_A.x)` on `R_B`

## Why the in-tree roundtrip test passes anyway

Let `a_hat = x̂(R_A.x)`, `b_hat = x̂(R_B.x)`.

Initiator (A) computes:
```
V_A = (a_hat·r_A + d_A) · (b_hat·R_B + P_B)
    = (a_hat·r_A + d_A) · (b_hat·r_B + d_B) · G
```

Responder (B) computes:
```
V_B = (b_hat·r_B + d_B) · (a_hat·R_A + P_A)
    = (b_hat·r_B + d_B) · (a_hat·r_A + d_A) · G
```

The scalar products `(a_hat·r_A + d_A)·(b_hat·r_B + d_B)` and
`(b_hat·r_B + d_B)·(a_hat·r_A + d_A)` are equal by commutativity of
multiplication. So V_A == V_B as EC points.

This is the only reason the existing roundtrip test passes — the
algorithm is *symmetrically wrong*, so two gm-tlcp instances agree
with each other, but neither agrees with a spec-conformant peer.

## What a spec-conformant peer computes

openHiTLS (and Tongsuo, and GmSSL master) presumably implements the
spec formula. Their V is:

```
V_spec_A = (b_hat·r_A + d_A) · (a_hat·R_B + P_B)
         = (b_hat·r_A + d_A) · (a_hat·r_B + d_B) · G

V_spec_B = (a_hat·r_B + d_B) · (b_hat·R_A + P_A)
         = (a_hat·r_B + d_B) · (b_hat·r_A + d_A) · G
```

These are equal to each other (same commutativity argument), but
`V_spec != V_gm_tlcp` in general — the scalar products
`(a_hat·r_A + d_A)·(b_hat·r_B + d_B)` and
`(b_hat·r_A + d_A)·(a_hat·r_B + d_B)` differ.

## Confirmation: PR4 wire trace

`interop/openhitls/wire-traces/e011-ecdhe-mutualauth-strict-pr4.pcap`
shows the strict-mode client successfully sending:
- CKE (PR3-1 fix, no uint16 prefix)
- CV (PR4 fix, default distid)
- CCS
- Encrypted Finished

…then receiving `Alert Fatal Decrypt Error (51)`. The server
processed CV successfully (signature verified) before trying to
decrypt Finished — so the Z values match (PR4 fix is correct), the
transcripts match, and the only divergence is the ECDHE shared
secret V, which traces back to the x̂ transform direction.

## Open verification: find an authoritative KAT

To prove the diagnosis beyond doubt and to validate any future fix, I
need a Known-Answer Test vector. Possibilities:

1. **National standard test vectors**: GB/T 32918.3-2016 Annex
   (informative) is the canonical source. I don't have a copy of the
   PDF in the local tree; would need to find it online or via a
   standards database.

2. **openHiTLS test vectors**: the openHiTLS source tree at
   `openhitls/testcode/testdata/tls/` may have TLCP ECDHE vectors we
   can extract. The current local checkout (`openhitls/`) is just the
   main source, not the full testdata.

3. **Tongsuo vectors**: Tongsuo's `testdata/` has ECDHE test vectors
   for various cipher suites; TLCP may or may not be there.

4. **Cross-implementation parity**: spin up a peer (e.g. gm-crypto's
   `sm2_kex` module which has its own x̂-correct algorithm) and
   verify the *fixed* gm-tlcp matches.

5. **Back-of-envelope proof**: the spec formula is short enough to
   re-derive algebraically and confirm via the roundtrip structure.
   This is what I did above but it's not a KAT.

**Risk**: without a KAT, a fix that I implement might still be wrong
in some edge case (e.g. all-zero x, x near n, specific curve params).
The roundtrip test only proves the fix is self-consistent, not that
it matches the spec.

## Proposed fix plan (cfg-gated, additive, low-risk)

1. **Add a `tlcp-strict` cfg-gated code path** in
   `pms.rs:compute_tlcp_ecdhe_pms` that applies the spec formula.
   Default mode keeps the current (GmSSL-master-compatible) formula.
2. **Update the KAT-style roundtrip test** in
   `pms.rs:tests::compute_tlcp_ecdhe_pms_roundtrip` to compare both
   implementations and assert they give different V (as they should
   per the analysis).
3. **Add a hex-constant KAT** test: pick one of A/B, hard-code V_x,
   V_y, z_a, z_b, ephemeral/static scalars, and assert
   `compute_tlcp_ecdhe_pms` produces a specific PMS bytes. **This
   requires a KAT source.**
4. **Re-run the openHiTLS strict-mode e011 test** with the fix. The
   expected outcome is that the strict-mode client now reaches
   `AppData` exchange instead of `Decrypt Error (51)`.
5. **Smoke-test default mode** (GmSSL master interop CI job) — must
   remain green. The default-mode formula is unchanged, so this
   should be a no-op.

## Risk assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Spec interpretation is wrong | medium | fix doesn't actually match openHiTLS | KAT vector before merging |
| openHiTLS has its own non-spec quirk | low | fix matches spec but still interop-fails | look at openHiTLS source |
| Default-mode regression | low | GmSSL master CI job breaks | only cfg-gate the change; default untouched |
| x̂ edge case (e.g. x near 0) | very low | crash in production | unit tests with edge-case x |
| Subtle byte-order or endianness bug | low | wrong PMS even with correct formula | KAT vector covers this |

## Recommended order of operations

1. **Find one authoritative KAT** (GB/T 32918.3-2016 Annex, or a
   Tongsuo/openHiTLS testdata vector). This is a 30-60 min search
   task. Without it, **do not implement**.
2. Once KAT is found, add a hex-constant test that locks the spec
   formula. This is the safety net.
3. Implement the spec-correct formula as a separate function
   `compute_tlcp_ecdhe_pms_spec(...)` next to the existing
   `compute_tlcp_ecdhe_pms(...)`. Both should be in `pms.rs`.
4. Wire the strict mode to call `compute_tlcp_ecdhe_pms_spec` and
   default mode to call `compute_tlcp_ecdhe_pms` (unchanged).
5. Run the full PR6 test matrix: in-tree roundtrip, GmSSL interop CI
   (default mode), openHiTLS interop (strict mode).
6. Update CHANGELOG with the fix and a credit to the openHiTLS wire
   trace for the empirical evidence.

## What this PR6 does NOT do

- Does not investigate the static-ECC server PMS-decrypt path
  (separate future PR; PR3-2's explicit error stays).
- Does not change the GmSSL-targeted default mode.
- Does not add a SM2 Z-value KAT (separate concern, can be added
  later if needed for the distid PR4 follow-up).
- Does not bump the version. The fix is additive behind the
  `tlcp-strict` feature, so per SemVer 0.x it's a MINOR bump at
  most. Recommend holding the version at 0.2.0 and bumping to 0.3.0
  in a single commit that includes both M-2 fix and any M-3
  follow-up that surfaces during the fix.

## Current state (unchanged from PR5)

- gm-tlcp 0.2.0 on `main` (commit `c389392`)
- github / gitee / gitcode all in sync
- CI 10/10 green
- default-mode GmSSL interop verified by CI
- strict-mode openHiTLS interop: reaches Finished, then
  `Decrypt Error (51)` (the M-2 bug)
