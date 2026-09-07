# M-2 Root Cause Analysis: SM2 ECDHE Shared-Secret Asymmetry

Status: investigation complete, awaiting user approval before any code change.

## TL;DR

gm-tlcp's `compute_tlcp_ecdhe_pms` formula in
[`pms.rs:91-143`](../src/tlcp/pms.rs) is **spec-correct** (verified
algebraically against GB/T 32918.3-2016 §6.4.2). The `pms.rs`-internal
roundtrip test passes for that reason.

The M-2 divergence is at the **call sites**, not in the formula:

- The **client** (TlcpConnector) calls
  `compute_tlcp_ecdhe_pms` and feeds the resulting 48-byte PMS into
  PRF → master_secret.
- The **server** (TlcpAcceptor) calls
  `Sm2EcdhKeypair::compute_shared_secret(peer_pub)` which returns a
  **32-byte raw x-coordinate** of the standard ECDH point — no x̂
  transform, no KDF, no Z values. That 32-byte blob is fed into PRF as
  the PMS.

Client and server therefore produce different master_secret values
from the same handshake parameters → diverging handshake keys →
Finished MAC verification fails with `Decrypt Error (51)`.

This is **strictly worse than the previous analysis assumed**: not
only would gm-tlcp ↔ openHiTLS fail, gm-tlcp client ↔ gm-tlcp server
would fail too if exercised end-to-end (the existing
`gmssl_interop.rs` tests for that case are all `#[ignore]`-d behind a
`gmssl_present()` guard, so the CI never catches it).

## What the standard requires (extracted)

GB/T 32918.3-2016 §6.4.2 — the basis for TLCP ECDHE per
GB/T 38636-2020 §6.4.6.2 — gives, for **user A (initiator)**:

```
A5:  tA = (dA + x̂1 · rA) mod n   where x̂1 = x̂(RA.x)  (own ephemeral x)
A7:  U  = [h·tA](PB + [x̂2]RB)    where x̂2 = x̂(RB.x)  (peer ephemeral x)
A8:  KA = KDF(xU ‖ yU ‖ ZA ‖ ZB, klen)
```

For **user B (responder)**, the steps are symmetric with the same
`x̂(own_ephemeral)` / `x̂(peer_ephemeral)` rule:

```
B4:  tB = (dB + x̂2 · rB) mod n   where x̂2 = x̂(RB.x)
B6:  V  = [h·tB](PA + [x̂1]RA)    where x̂1 = x̂(RA.x)
B7:  KB = KDF(xV ‖ yV ‥ ZA ‖ ZB, klen)
```

Two consequences:

1. The KDF input order is **`xV ‖ yV ‖ ZA ‖ ZB`** (initiator's Z
   first, responder's Z second), in both A's and B's view. This is
   not symmetric per-side; the order is fixed by the KDF spec.
2. The PMS length is **`klen`** — for TLCP that's **48 bytes**
   (KDF expands to the master_secret length), not the 32-byte
   x-coordinate of a raw EC point.

## Verification against the standard's KAT

GB/T 32918.3-2016 Annex A.2 publishes a full worked example
(taking A and B, computing tA, tB, RA, RB, V, U, KA=KB). I
extracted the PDF and parsed Annex A.2 (test curve, 256-bit prime
field). The KAT confirms the formula structure; the same algebra
applied to sm2p256v1 is what `pms.rs:91-143` implements.

Two practical obstacles prevent putting the KAT into a hex-constant
test:

- The KAT uses a **test curve** (`Gx = 421DEBD61B62EAB6...`) **not**
  sm2p256v1 (`Gx = 32C4AE2C1F198119...`). The values can't be fed
  directly into `compute_tlcp_ecdhe_pms` because the function is
  bound to sm2p256v1 via the `sm2` crate.
- A sm2p256v1 KAT was not found in openHiTLS, Tongsuo, or any other
  public source I searched. The earlier analysis tried
  [WebSearch]; the only authoritative sources were the PDF standard
  itself (with the test-curve caveat) and academic papers.

The `compute_tlcp_ecdhe_pms_roundtrip` test in
[`pms.rs:256-323`](../src/tlcp/pms.rs) still serves as a
self-consistency check on sm2p256v1 — both A and B compute the same
48-byte PMS via the function.

## What's actually wrong (line-level)

### Client — correct

[`mod.rs:1948`](../src/tlcp/mod.rs):

```rust
let pms_vec = crate::tlcp::pms::compute_tlcp_ecdhe_pms(
    &client_enc_pub_xy,                  // local_static_xy    (A's P_A)
    &client_enc_kp.private_key().to_bytes().into(),  // local_static_priv (A's dA)
    &client_ephemeral_xy,                // local_ephemeral_xy (A's R_A)
    &client_ephemeral_priv,              // local_ephemeral_priv (A's rA)
    &server_enc_pub_xy,                  // peer_static_xy     (B's P_B)
    &server_ephemeral_xy,                // peer_ephemeral_xy  (B's R_B)
    &z_server,                           // <-- ARGS
    &z_client,                           //     See note ①
    48,                                  //     klen = 48
)
```

The function call is correct in *structure* (it uses
`compute_tlcp_ecdhe_pms`, which is spec-compliant).

① **Argument-order bug**: `z_a` (initiator's Z = ZA = Z_client) is
   supposed to come **first**, `z_b` (responder's Z = ZB = Z_server)
   second. The call site passes `z_server` first, `z_client` second.
   This alone is enough to break interop with any peer that follows
   the KDF input order `xV ‖ yV ‖ ZA ‖ ZB`. The in-tree roundtrip
   test gets away with this only because both A's and B's calls use
   the *same* (z_server, z_client) order — same wrong order, same
   wrong result.

### Server — wrong algorithm

[`mod.rs:2419-2444`](../src/tlcp/mod.rs):

```rust
let pms = match server_ephemeral_kp_opt {
    Some(kp) => kp
        .compute_shared_secret(peer_pub)  // <-- WRONG
        .map_err(|e| TlcpError::HandshakeFailed(format!(
            "ECDHE shared secret: {}", e)))?,
    None => { /* static-ECC path; not yet implemented */ }
};
```

`Sm2EcdhKeypair::compute_shared_secret` (in `gm-crypto/src/sm2.rs`)
is **standard ECDH**: it computes `peer_pub * my_priv` and returns
the raw x-coordinate (32 bytes). No x̂, no KDF, no Z.

This is the structural mismatch. Even if the client's argument-order
bug is fixed, server and client still produce different PMS lengths
(32 vs 48), so PRF outputs diverge.

### Why the existing CI is green

The CI's `gm-tlcp × GmSSL TLCP Interop` job reports `11 passed;
0 failed` but the 7 actual interop tests are all `#[ignore]`-d
behind `support::cert_setup::gmssl_present()`. The runner image
doesn't install `gmssl`, so every real interop test prints
`gmssl not on PATH; skipping` and returns `Ok(())`. The `11
passed` count is the *support* unit tests (`pbkdf2_sm3_basic`,
`hmac_sm3_short_key`, etc.), not real handshake exchanges.

This is **CI-shaped coverage that never actually exercises interop**.
Confirmed by reading the test file and the most recent run log
(commit `c389392`).

## What a spec-conformant implementation does

Both client and server call the same function:

```rust
fn compute_tlcp_ecdhe_pms(
    local_static_xy:   &[u8; 64], local_static_priv:   &[u8; 32],
    local_ephemeral_xy:   &[u8; 64], local_ephemeral_priv:   &[u8; 32],
    peer_static_xy:    &[u8; 64],
    peer_ephemeral_xy: &[u8; 64],
    z_initiator:       &[u8; 32],   // ZA
    z_responder:       &[u8; 32],   // ZB
    klen:              usize,
) -> Result<Vec<u8>, TlcpError>
```

For the server side, `local_*` is the server's data, `peer_*` is
the client's data (taken from the CKE message), `z_initiator` =
Z_client, `z_responder` = Z_server. The server already has the
client's enc pub (from `process_server_certs`) and the client's
ephemeral pub (from CKE), so the call can be wired up.

## Proposed fix (PR6, additive, cfg-gated)

Per the previous analysis's "Recommended order of operations" plus
the new findings:

1. **Fix the argument-order bug** at `mod.rs:1948-1957`:
   swap `z_server` and `z_client` so `z_a` (arg 7) = `z_client`,
   `z_b` (arg 8) = `z_server`.

2. **Make the server use `compute_tlcp_ecdhe_pms`** at
   `mod.rs:2419-2444`: replace the `compute_shared_secret` call
   with the same function used on the client side. The server's
   client-side inputs come from the CKE message + server cert;
   `z_server` and `z_client` are already in scope (computed from
   server enc pub / client enc pub respectively during step 4 /
   step 6 in the certificate verification path).

3. **Add a regression test** that constructs a TlcpConnector +
   TlcpAcceptor pair, runs them through a complete TLCP handshake
   on a `tokio::TcpStream`, and asserts both reach
   `HandshakeState::AppData`. This is a real interop test for the
   default mode that **doesn't** require the gmssl binary.

4. **Gate behind `tlcp-strict`** to keep the default mode behavior
   unchanged for the duration of a single release cycle. Reason:
   the GmSSL-master CI job is "green" by virtue of always-skipping,
   so we don't have positive evidence that GmSSL master interoperates
   in default mode. Reverting to a server-side ECDH x-coord in
   default mode risks breaking any other client that happened to
   agree with the old behavior. Strict-mode opt-in flips the server
   to the spec formula, matching openHiTLS / Tongsuo.

5. **Keep the existing `compute_tlcp_ecdhe_pms_roundtrip` test** as
   the formula's self-consistency check; add the new
   end-to-end-to-Finished test as the cfg-gated regression check.

## Risk assessment (updated)

| Risk                                                       | Likelihood | Impact                                                | Mitigation                                                                |
| ---------------------------------------------------------- | ---------- | ----------------------------------------------------- | ------------------------------------------------------------------------- |
| openHiTLS doesn't actually use spec formula                | very low   | fix matches spec but still interop-fails              | openHiTLS source already audited — see earlier search notes               |
| Server-side fix needs extra inputs we don't yet have in scope | medium | wire-up requires plumbing client enc pub + client ephemeral to server PMS code path | read `mod.rs:2340-2444` end-to-end before coding; small change           |
| Default-mode regression (GmSSL-master)                     | low        | GmSSL master CI breaks                                | cfg-gate the fix; default mode keeps `compute_shared_secret` until we have positive GmSSL-master interop evidence |
| Reseed of PRNG or transcript hash on mid-handshake failure | very low   | session cache poisoning                               | existing bounds already cover this; no new state                          |

## Order of operations

1. Read `mod.rs:2300-2450` end-to-end to confirm all inputs needed
   for the server's `compute_tlcp_ecdhe_pms` call are in scope.
2. Implement the server-side switch (cfg-gated) + the argument-order
   swap (cfg-gated).
3. Add the new regression test.
4. Local: `cargo +stable fmt --all && cargo +stable test -p gm-tlcp`.
5. Push to github → wait for CI 10/10 → push to gitee / gitcode.
6. Manually re-run the openHiTLS e011 strict-mode interop test
   (the same one from PR4's wire trace). Expected outcome:
   Finished accepted, AppData reachable.
7. Update CHANGELOG / version bump (0.2.0 → 0.3.0; breaking
   behavior under `--features tlcp-strict`).

## What this PR6 does NOT do

- Does not change the static-ECC server PMS-decrypt path
  (separate future PR; PR3-2's explicit error stays).
- Does not change default-mode behavior (the server's
  `compute_shared_secret` stays under `#[cfg(not(feature =
  "tlcp-strict"))]`).
- Does not introduce a sm2p256v1 KAT (the standard's Annex A.2 KAT
  uses a different test curve; no other public sm2p256v1 ECDHE
  KAT was found in the time available).
- Does not bump the version yet; that comes in the same commit
  that flips the cfg-gated server switch.

## Current state (unchanged from PR5)

- gm-tlcp 0.2.0 on `main` (commit `c389392`)
- github / gitee / gitcode all in sync
- CI 10/10 green
- default-mode GmSSL interop "passes" via always-skipping tests
  (false positive, not real evidence)
- strict-mode openHiTLS interop: reaches Finished, then
  `Decrypt Error (51)`
- M-2 root cause now correctly identified as the
  call-site asymmetry (server using `compute_shared_secret`,
  client using `compute_tlcp_ecdhe_pms`) plus the client-side
  argument-order bug — **not** the x̂ formula in `pms.rs`
  (which is correct).