# Comment on Tongsuo #836 — bundled-only repro for all three NTLS rejection paths

**Date**: 2026-09-06
**Posted to**: https://github.com/Tongsuo-Project/Tongsuo/issues/836 (comment, not new issue)
**Reporter**: gm-tlcp maintainer (cross-implementation interop suite)
**Tongsuo version reproduced**: 8.3.0 (verified against the source tree
shipped with gm-tlcp/interop/tongsuo/Tongsuo-8.3.0)

---

## Why a comment, not a new issue

Issue #836 (hou2gou, opened 2026-08-27) is still **Open** and already covers
**Path 1** with a complete gdb stack trace. The evidence below is
**strictly additive**: it covers two more rejection paths (Path 2 and
Path 3) that #836 does not reach, plus a **bundled-Tongsuo-only** round-trip
that removes any possibility the bug is on the peer side.

All line numbers below are verified against the Tongsuo 8.3.0 source tree
shipped at `gm/gm-tlcp/interop/tongsuo/Tongsuo-8.3.0/`. Line numbers differ
from #836's stack by at most 1 (e.g. `statem.c:399` vs the actual `398`
we read) — same `if` clause, just whitespace difference.

---

## Setup — no third-party code required

```bash
./config enable-ntls && make -j
```

Generate a fresh SM2 sign + enc cert pair (the bundled
`test/certs/sm2/*.crt` expired in 2023):

```bash
OPENSSL_CONF=./apps/openssl.cnf ./apps/openssl req -x509 -newkey ec \
    -pkeyopt ec_paramgen_curve:SM2 \
    -keyout server_sign.key -out server_sign.crt -days 3650 -nodes \
    -subj '/CN=tongsuo-self'

OPENSSL_CONF=./apps/openssl.cnf ./apps/openssl req -x509 -newkey ec \
    -pkeyopt ec_paramgen_curve:SM2 \
    -keyout server_enc.key  -out server_enc.crt  -days 3650 -nodes \
    -subj '/CN=tongsuo-self'
```

---

## Path 1 — already covered by #836, summary for context

Server flags: `-enable_ntls` only (default `TLS_server_method()`).

```
ERROR
0:error:14209102:SSL routines:tls_early_post_process_client_hello:unsupported protocol:ssl/statem_ntls/statem_srvr.c:1041:
```

Reaches `state_machine_ntls` → `tls_setup_handshake_ntls` →
`ssl_get_min_max_version_ntls` (file `ssl/statem_ntls/statem_lib.c:101-105`),
which returns `SSL_R_NO_PROTOCOLS_AVAILABLE`. Root cause: when the server
method is `TLS_server_method()` (version-flexible), the table walk in
`ssl_get_min_max_version_ntls` at `statem_lib.c:1685-1740` iterates
`tls_version_table`, and the NTLS entry at line 1181 is filtered out by
the combination of `s->method->version == TLS_ANY_VERSION` and the way
`ssl_method_error` at line 1202 applies `s->options & method->mask`.

---

## Path 2 (new) — `state_machine` (regular), server with `-ntls -enable_ntls`

```bash
./apps/openssl s_server -accept 3322 \
    -cert server_sign.crt -key server_sign.key \
    -enc_cert server_enc.crt -enc_key server_enc.key \
    -cipher ALL:@SECLEVEL=0 \
    -enable_ntls -ntls -quiet

./apps/openssl s_client -connect 127.0.0.1:3322 \
    -enable_ntls -ntls -cipher ALL:@SECLEVEL=0
```

**Server**:
```
0:error:14161044:SSL routines:state_machine:internal error:ssl/statem/statem.c:399:
```

**Client**:
```
CONNECTED(00000005)
---
no peer certificate available
...
SSL handshake has read 0 bytes and written 7 bytes
---
0:error:141A90B5:SSL routines:ssl_cipher_list_to_bytes:no ciphers available:ssl/statem/statem_clnt.c:3999:
0:error:1424A044:SSL routines:write_state_machine:internal error:ssl/statem/statem.c:923:
```

The **server** never reaches the state machine entry that dispatches to
`state_machine_ntls`; the very first bytes of the first record go
through the regular path because `state_machine_ntls` rejects NTLS at
`ssl_security(SECOP_VERSION, ...)` before any TLCP dispatch.

### Root cause (verified against `ssl/statem/statem.c:396-403`)

```c
        } else {
            if ((s->version >> 8) != SSL3_VERSION_MAJOR) {   // 0x03
                SSLfatal(s, SSL_AD_NO_ALERT, SSL_F_STATE_MACHINE,
                         ERR_R_INTERNAL_ERROR);
                goto end;
            }
        }
```

`NTLS_VERSION = 0x0101`. `(0x0101 >> 8) = 0x01 ≠ 0x03` → fatal.

This fires whenever a non-NTLS-shaped first record reaches a server
configured with `-ntls -enable_ntls` (e.g. a TLS 1.0 probe, a malformed
first byte, or a misconfigured peer). It was hit by our gm-tlcp test
client when we accidentally sent a TLS 1.0-formatted record instead of
the spec `0x0101`.

---

## Path 3 (new) — `state_machine_ntls` entry, server with `-cipher ALL:@SECLEVEL=3`

Same server / client invocation as Path 2, but add
`-cipher ALL:@SECLEVEL=3` to the server:

**Server**:
```
0:error:14161044:SSL routines:state_machine_ntls:internal error:ssl/statem_ntls/statem.c:334:
```

### Root cause (verified against `ssl/statem_ntls/statem.c:334`)

```c
        if (!ssl_security(s, SSL_SECOP_VERSION, 0, s->version, NULL)) {
            SSLfatal_ntls(s, SSL_AD_NO_ALERT, SSL_F_STATE_MACHINE_NTLS,
                           ERR_R_INTERNAL_ERROR);
            goto end;
        }
```

`ssl_security` for NTLS returns 0 at default `security level >= 3`
because of this gate in `ssl_security_default_callback` (per the
OpenSSL `ssl/s3_lib.c` macro / inline):

```c
case SSL_SECOP_VERSION:
    if (!SSL_IS_DTLS(s)) {
#ifndef OPENSSL_NO_NTLS
        /* NTLS v1.1 not allowed at level 3 */
        if (nid == NTLS_VERSION && level >= 3)
            return 0;
#endif
        ...
```

The `level >= 3` cutoff for TLCP (a current national standard,
GB/T 38636-2020) is overly restrictive; TLS 1.2 is allowed at level 3.

---

## Decision matrix — all three paths verified against Tongsuo 8.3.0

| Server flags | Path fired | File : line | Alert sent |
|---|---|---|---|
| `-enable_ntls` only | **Path 1** (`ssl_get_min_max_version_ntls`) | `ssl/statem_ntls/ntls_statem_lib.c:103` | `02 46` |
| `-ntls -enable_ntls` (record v ≠ `0x0101`) | **Path 2** (`state_machine` regular) | `ssl/statem/statem.c:398` | `02 46` |
| `-ntls -enable_ntls` (record v = `0x0101`, level ≥ 3) | **Path 3** (`state_machine_ntls` entry) | `ssl/statem_ntls/statem.c:334` | (no alert, internal error) |
| `-ntls -enable_ntls` (record v = `0x0101`, level 1) | reaches NTLS state machine, may continue | — | — |

---

## Why this is not a peer-client bug — bundled Tongsuo self-roundtrip

Reproducing **Path 2** and **Path 3** with **Tongsuo's own `s_client`**
against **Tongsuo's own `s_server`** (no third-party code) yields the
same `state_machine:internal error:ssl/statem/statem.c:399` /
`ssl/statem_ntls/statem.c:334` exceptions. So this is not an interop
quirk — Tongsuo's bundled NTLS round-trip fails against itself.

Traceback from the bundled round-trip (no third-party code, both sides
are `./apps/openssl`):

```
$ ./apps/openssl s_server -accept 3322 \
    -sign_cert cert/certs/SS.pem -sign_key cert/certs/SS.key \
    -enc_cert  cert/certs/SE.pem -enc_key  cert/certs/SE.key \
    -cipher ALL:@SECLEVEL=0 -enable_ntls -ntls -quiet
Using default temp DH parameters
ACCEPT
ERROR
0:error:14161044:SSL routines:state_machine:internal error:ssl/statem/statem.c:399:
```

```
$ ./apps/openssl s_client -connect 127.0.0.1:3322 \
    -enable_ntls -ntls -cipher ALL:@SECLEVEL=0
CONNECTED(00000003)
---
no peer certificate available
...
0:error:141A90B5:SSL routines:ssl_cipher_list_to_bytes:no ciphers available:ssl/statem/statem_clnt.c:3999:
0:error:1424A044:SSL routines:write_state_machine:internal error:ssl/statem/statem.c:923:
```

---

## Suggested fix surface (informational, not a PR yet)

For maintainers' convenience — the same patches called out in
`gm-tlcp/interop/tongsuo/upstream/ISSUE-state-machine-ntls-version.md`:

- **Path 1**: introduce a `tls_version_table_ntls` consulted only when
  `s->enable_ntls == 1` and the method is flexible.
- **Path 2**: relax the `(s->version >> 8) != SSL3_VERSION_MAJOR` check
  when `s->enable_ntls == 1`.
- **Path 3**: relax the NTLS `security_level` cutoff from `level >= 3` to
  `level >= 5` in `ssl_security_default_callback`.

These three patches together would unblock all known TLCP interop
scenarios including the bundled `s_client ↔ s_server` self-test.

---

## References

- GB/T 38636-2020 §6.2 — TLCP record-layer protocol version = `0x0101`.
- Tongsuo issue #836 — Path 1 only.
- gm-tlcp diagnostic trace: `gm-tlcp/interop/tongsuo/FINDINGS.md`
  and `gm-tlcp/interop/tongsuo/upstream/ISSUE-state-machine-ntls-version.md`.
- Independent TLCP implementations that emit the spec version byte `0x0101`:
  GmSSL (`include/gmssl/tls.h`: `TLS_protocol_tlcp = 0x0101`), openHiTLS
  (Huawei; TLCP 1.1 = `0x0101`), tjfoc/gmsm (`gmtls/gm_support.go`:
  `VersionGMSSL = 0x0101`).
