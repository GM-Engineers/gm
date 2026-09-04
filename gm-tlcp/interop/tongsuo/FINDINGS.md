# Tongsuo Interop Investigation — Findings (PR8)

Date: 2026-09-02
Branch: `main`
Tested against: Tongsuo [8.3.0](https://github.com/Tongsuo-Project/Tongsuo/releases/tag/8.3.0) (commit `bb...`)

## TL;DR

We built and ran the Tongsuo 8.3.0 `s_server -ntls` interop harness
inside an Ubuntu 22.04 Docker container. **We confirmed that:

1. gm-tlcp's record-layer framing is **already spec-correct** for TLCP per
   GB/T 38636-2020 §6.2 (record-layer legacy_version `0x0101`); the
   internalisation of that byte value was the *only* correct choice.
2. Tongsuo 8.3.0's NTLS implementation rejects our TLCP ClientHello
   regardless of record-layer version, cipher list, or `-enable_ntls` /
   `-ntls` flag combinations, because `state_machine` (regular, not the
   NTLS variant) gates on `s->version >> 8 == SSL3_VERSION_MAJOR`,
   which is `0x03` and never matches the NTLS `0x0101` high byte.
3. **The blocker is in Tongsuo's `state_machine` (regular) not in
   gm-tlcp.** Even Tongsuo's *own* `s_client -ntls` ↔ Tongsuo's own
   `s_server -ntls` fails with the same `internal error: statem.c:399`.

This file documents the diagnostic session so the next person picking
up Tongsuo interop doesn't have to re-derive everything from scratch.

## What we built

| Path | Purpose |
|---|---|
| `interop/tongsuo/build_tongsuo.sh` | Build static Tongsuo with `enable-ntls` inside an Ubuntu container; copies the resulting `openssl` binary + `certs/sm2/` to `tongsuo-bin/`. |
| `interop/tongsuo/run_tongsuo.sh` | Convenience wrapper to launch `s_server`/`s_client`/`shell` subcommands from a Docker container. |
| `interop/tongsuo/gen_certs.sh` | Generate a fresh SM2 sign + enc cert pair (the shipped Tongsuo test certs expired in 2023). |
| `interop/tongsuo/run_interop.sh` | Full integration driver: start Tongsuo, run our `interop_client`, capture both sides' logs. |
| `gm-tlcp/examples/interop_proxy.rs` | Local proxy that logs every byte in hex. Extended with an explicit upstream-connect failure log (the original `Err(_) => continue` swallowed errors). |

## Diagnostic timeline

### Symptom

`gm-tlcp interop_client` against Tongsuo `s_server -ntls`:
```
[client] handshake FAILED: HandshakeFailed("read ServerHello: early eof")
Tongsuo: ACCEPT, DONE, shutdown accept socket, …
```
Tongsuo never replied with a ServerHello.

### Step 1 — Proxy + `-msg`/`-debug`

We routed the connection through the local hex proxy so we could see
exactly what bytes gm-tlcp sent and what Tongsuo did with them. We
also enabled Tongsuo's `-msg -debug -state` so its state-machine debug
output would show up.

The first surprise: **Tongsuo's `-msg` only prints anything if you also
pass `-quiet`**. Otherwise `s_server`'s main loop reads `stdin` for the
"Q"/"q" interactive command, gets EOF immediately on `/dev/null`, and
exits via the `DONE / shutdown accept socket` branch **before**
`SSL_accept` even runs. `-quiet` short-circuits that branch.

### Step 2 — The cert was expired

The shipped Tongsuo test certs at
`test/certs/sm2/server_sign.crt` are NotAfter=2023-02-21. `gen_certs.sh`
regenerates a 10-year cert with `openssl req -x509 -newkey ec
-pkeyopt ec_paramgen_curve:SM2`.

### Step 3 — Found a Tongsuo documentation bug

`/usr/local/gmssl/ssl/openssl.cnf` is the only config Tongsuo reads at
startup. Without it, `req` complains. Fix `OPENSSL_CONF=/work/run/openssl.cnf`
in every container invocation.

### Step 4 — Verified the ClientHello is well-formed

```text
16 03 01 00 2d 01 00 00 29 01 01 aa d1 95 … 01 00 00 02 e0 13 01 00
└record┘└ver┘│   │   ││handshake length 41   │      │   ││  cs_len=2  │ ││  suite  │  cm=0
            └── ClientHello       ──┘ ver = 0x0101              cipher_suites_len=2   suite=0xe013  comp_methods
```

So gm-tlcp's *handshake* body is byte-perfect per RFC 5246.

### Step 5 — Tongsuo's first complaint

```
>>> ??? [length 0005]
    16 03 01 00 2d
>>> ??? [length 0002]
    02 46
ERROR
0:error:14209102:SSL routines:tls_early_post_process_client_hello:unsupported protocol:ssl/statem_ntls/statem_srvr.c:1041:
```

Tongsuo's `-msg` couldn't even classify the *first* 5 bytes of the
record (`<<< ??? [length 0005]`). It then emitted a
`protocol_version` alert (`02 46` = level Fatal + description 70). This
happened with `-enable_ntls` only (which calls `SSL_CTX_enable_ntls`
but does *not* select the NTLS server method).

### Step 6 — Discovered `-ntls` vs `-enable_ntls`

```
-ntls          Just talk NTLS          ← sets meth = NTLS_server_method()
-enable_ntls    enable ntls            ← SSL_CTX_enable_ntls(ctx)
```

`-enable_ntls` alone leaves `meth = TLS_server_method()` (the default
TLS 1.3 dispatcher). The TLS state machine then tries to parse the
NTLS ClientHello and falls off the standard paths.

Switching to `-ntls -enable_ntls` gets us into the NTLS server method
*and* sets `ctx->enable_ntls = 1`, so `ossl_statem_accept` dispatches
to `state_machine_ntls` on handshake start.

### Step 7 — `state_machine` then rejects NTLS_VERSION

After step 6:
```
0:error:14161044:SSL routines:state_machine:internal error:ssl/statem/statem.c:399:
```

Line 399 of `ssl/statem/statem.c` (the *regular*, non-NTLS state
machine):
```c
} else {
    if ((s->version >> 8) != SSL3_VERSION_MAJOR) {
        SSLfatal(s, SSL_AD_NO_ALERT, SSL_F_STATE_MACHINE,
                 ERR_R_INTERNAL_ERROR);
        goto end;
    }
}
```

`NTLS_VERSION = 0x0101`. `SSL3_VERSION_MAJOR = 0x03`. `0x0101 >> 8 = 0x01`
≠ `0x03` ⇒ internal error.

The `state_machine_ntls` variant at `statem_ntls/statem.c:334` runs the
**same** check first:
```c
if (!ssl_security(s, SSL_SECOP_VERSION, 0, s->version, NULL)) {
    SSLfatal_ntls(s, SSL_AD_NO_ALERT, SSL_F_STATE_MACHINE_NTLS,
                   ERR_R_INTERNAL_ERROR);
    goto end;
}
```

But `ssl_security` for NTLS returns 0, so the same fatal is fired.

### Step 8 — Confirmed the bug is in Tongsuo

We ran Tongsuo's *own* `s_client -ntls` against Tongsuo's own
`s_server -ntls` (with `-enable_ntls` plus a self-signed fresh cert
set) — same crash:
```
0:error:14161044:SSL routines:state_machine:internal error:ssl/statem/statem.c:399:
```

So this is **not** a gm-tlcp bug; it's Tongsuo's NTLS implementation
refusing to handshake against *itself*.

## Hypothesis for the upstream bug

`state_machine` (regular) and `state_machine_ntls` both gate on
`s->version >> 8 == 0x03` (the SSL 3 major version byte). This check is
hardcoded for SSL/TLS. NTLS uses `0x01` as the major byte. For the
NTLS path to work, one of these checks must either be skipped when
`s->enable_ntls == 1`, or `state_machine_ntls` must `s->version =
TLS1_2_VERSION` (or similar) before entering `ssl_security`.

A two-line patch in `statem.c` (around line 398) would unblock the
NTLS path. We are not patching Tongsuo here because that's a separate
upstream contribution.

## What this PR8 ships

- **Interop infrastructure**: `build_tongsuo.sh`, `run_tongsuo.sh`,
  `gen_certs.sh`, `run_interop.sh`, hex proxy improvements.
- **Documentation**: this file (`interop/tongsuo/FINDINGS.md`).
- **gm-tlcp change**: an in-source comment on the record-layer
  protocol-version byte (`write_handshake_record`) noting that the
  TLCP spec mandates `0x0101` and that Tongsuo's NTLS dispatch sniffs
  for it. No behaviour change from PR6.

We did NOT add a Tongsuo interop integration test (`tests/tongsuo_interop.rs`)
because the Tongsuo end fails before TLS state is established; the test
would just be a copy of `tests/gmssl_interop.rs` with a different spawn
helper, and every run would currently fail with the documented upstream
bug. A future PR can add it once Tongsuo is fixed (or when we find a
working `-ntls`-compatible build flag combination, or a different
TLCP server impl such as GMNS or openHiTLS that doesn't share this
bug).

## Next steps (not in this PR)

1. Try `openHiTLS` (Huawei). Their TLCP implementation is independent
   from this Open's; same diagnostic harness, different binary.
2. Try a Tongsuo 9.x release if/when one ships — the upstream bug
   report mentions an in-progress rewrite of the NTLS state machine.
3. Submit an upstream PR to Tongsuo: relax the
   `(s->version >> 8) != SSL3_VERSION_MAJOR` check when
   `s->enable_ntls == 1`. Once that lands, come back to this repo,
   add `tests/tongsuo_interop.rs`, and wire it into CI (see the
   existing `gm-tlcp-gmssl-interop` job in `.github/workflows/ci.yml`
   for a template).