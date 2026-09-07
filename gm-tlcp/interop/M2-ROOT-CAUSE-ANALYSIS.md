# M-2 Root Cause Analysis: SM2 ECDHE Shared-Secret Asymmetry

Status: investigation complete, awaiting user approval before any code change.

## TL;DR

gm-tlcp's `compute_tlcp_ecdhe_pms` formula in
[`pms.rs:91-143`](../src/tlcp/pms.rs) is **spec-correct** (verified
algebraically against GM/T 0003.3-2012 §6.1 / GB/T 32918.3-2016 (SM2 key-agreement protocol,
content-equivalent). The `pms.rs`-internal
roundtrip test passes for that reason.

The M-2 divergence is at the **server call site only**; the client
call site is already spec-conformant:

- The **client** (TlcpConnector) calls
  `compute_tlcp_ecdhe_pms` with `(z_server, z_client)` as the Z arguments
  and feeds the resulting 48-byte PMS into PRF → master_secret.
- The **server** (TlcpAcceptor) calls
  `Sm2EcdhKeypair::compute_shared_secret(peer_pub)` which returns a
  **32-byte raw x-coordinate** of the standard ECDH point — no x̂
  transform, no KDF, no Z values. That 32-byte blob is fed into PRF as
  the PMS.

Client and server therefore produce different master_secret values
from the same handshake parameters → diverging handshake keys →
Finished MAC verification fails with `Decrypt Error (51)`.

Concretely, gm-tlcp client ↔ gm-tlcp server would also fail if
exercised end-to-end (the existing `gmssl_interop.rs` tests for that
case are all `#[ignore]`-d behind a `gmssl_present()` guard, so the CI
never catches it).

## What the standard requires (extracted)

GB/T 38636-2020 §6.4.6.2 references the SM2 key-agreement protocol. The
canonical step text used here is from GM/T 0003.3-2012 §6.1 (which is the
text-equivalent of GB/T 32918.3-2016 §6.4; the 2016 text was not directly
read in this audit). For **user A (initiator)**:

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

1. In TLCP the server sends ServerKeyExchange first, so the server is
   user A (initiator) and the client is user B (responder).
2. The KDF input order is **`xV ‖ yV ‖ ZA ‖ ZB`** — initiator's Z
   first, responder's Z second — on **both** sides. There is no
   "swap for the responder" in the spec.
3. The PMS length is **`klen`** — for TLCP that's **48 bytes**
   (KDF expands to the master_secret length), not the 32-byte
   x-coordinate of a raw EC point.

## Verification against the standard's KAT

GM/T 0003.3-2012 Annex A publishes a full worked example
(taking A and B, computing tA, tB, RA, RB, V, U, KA=KB). I
extracted the PDF and parsed Annex A.2 (test curve, 256-bit prime
field). The KAT confirms the formula structure; the same algebra
applied to sm2p256v1 is what `pms.rs:91-143` implements.

Two practical obstacles prevent putting the KAT into a hex-constant
test:

- The KAT uses a **test curve** (`Gx = 421DEBD61B62EAB6...`) **not**
  sm2p256v1 (`Gx = 32C4AE2C1F198119...`). The values can't be fed
  directly into `compute_tlcp_ecdhe_pms` because the function is
  bound to sm2p256v1 via the `sm2` crate. (We cite the KAT from the
  2012 text; the GB/T 32918.3-2016 Annex A.2 is not directly verified
  in this audit, but the formula and KAT are widely accepted as the
  same.)
- A sm2p256v1 KAT was not found in openHiTLS, Tongsuo, or any other
  public source I searched. The earlier analysis tried
  [WebSearch]; the only authoritative sources were the PDF standard
  itself (with the test-curve caveat) and academic papers.

The `compute_tlcp_ecdhe_pms_roundtrip` test in
[`pms.rs:256-323`](../src/tlcp/pms.rs) still serves as a
self-consistency check on sm2p256v1 — both A and B compute the same
48-byte PMS via the function.

## What's actually wrong (line-level)

### Client — spec-conformant (no client-side Z-order bug)

[`mod.rs:1948`](../src/tlcp/mod.rs):

```rust
let pms_vec = crate::tlcp::pms::compute_tlcp_ecdhe_pms(
    &client_enc_pub_xy,                  // local_static_xy    (B's P_B)
    &client_enc_kp.private_key().to_bytes().into(),  // local_static_priv (B's dB)
    &client_ephemeral_xy,                // local_ephemeral_xy (B's R_B)
    &client_ephemeral_priv,              // local_ephemeral_priv (B's rB)
    &server_enc_pub_xy,                  // peer_static_xy     (A's P_A)
    &server_ephemeral_xy,                // peer_ephemeral_xy  (A's R_A)
    &z_server,                           // peer ZA (server Z = A)
    &z_client,                           // self  ZB (client Z = B)
    48,                                  // klen = 48
)
```

In TLCP the server is the SM2 key-agreement initiator (A): it sends
ServerKeyExchange first, so the standard's `A` corresponds to the
server, and `B` to the client. Therefore the client's call's `local_*`
slots are the client's (B's), and `peer_*` slots are the server's
(A's). The Z arguments are `z_server` (which is `Z_A`) first and
`z_client` (which is `Z_B`) second. `compute_tlcp_ecdhe_pms` appends
`z_a` then `z_b` to the KDF input, so the resulting KDF input is
`xV ∥ yV ∥ ZA ∥ ZB` — the spec-conformant KDF input. The in-tree
roundtrip test passes because both sides use the *same* `(z_server,
z_client)` order, which produces the same `ZA ∥ ZB` on both sides. There
is **no** client Z-order bug.

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

This is the structural mismatch. Server and client therefore produce
PMSes of different lengths (32 vs 48 bytes) and different content, so
PRF outputs diverge regardless of any client-side consideration.

### Why the existing CI is green

The CI's `gm-tlcp × GmSSL TLCP Interop` job reports `11 passed;
0 failed`, but all 7 actual handshake tests in
`gm-tlcp/tests/gmssl_interop.rs` are `#[ignore]`-d and self-skip
behind `support::cert_setup::gmssl_present()`. The runner image does
not install the `gmssl` binary, so every real handshake test prints
`"gmssl not on PATH; skipping"` and returns `Ok(())`. The `11 passed`
count is from the *support* unit tests (`pbkdf2_sm3_basic`,
`hmac_sm3_short_key`, etc.), not from real handshake exchanges. In other
words, the CI green is **structurally uninformative** about GmSSL
interoperability.

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

The M-2 root cause is the server algorithm. Recommended change:

1. **No client-side change** is required: the client call site
   already passes `(z_server, z_client)` = (ZA, ZB) and is spec-conformant.

2. **Make the server use `compute_tlcp_ecdhe_pms`** at
   `mod.rs:2419-2444`: replace the `compute_shared_secret` call
   with the same function used on the client side. The server's
   client-side inputs come from the CKE message + server cert;
   `z_server` and `z_client` are already in scope (computed from
   server enc pub / client enc pub respectively during step 4 /
   step 6 in the certificate verification path). The server's
   `local_*` slots are the server's, the `peer_*` slots are the
   client's (from CKE), and the Z argument order must be
   `(z_server, z_client)` to match the client and produce the
   spec-conformant `ZA ‖ ZB` KDF input.

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
   to the spec formula, matching GmSSL / openHiTLS / Tongsuo.

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
  call-site asymmetry (server using `compute_shared_secret` instead
  of `compute_tlcp_ecdhe_pms`) — **not** the x̂ formula in `pms.rs`
  (which is correct) and **not** the client-side argument order (which
  is also correct).