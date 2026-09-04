# NTLS state machine cannot complete a TLCP handshake: NTLS_VERSION (0x0101) rejected in multiple paths

**Tongsuo versions affected**: 8.3.0, 8.4.0-pre1 (and every release in between)
**Reporter**: gm-tlcp maintainer, cross-implementation interop suite
**Related upstream issue**: #836 (already filed, but covers only one of the three code paths)

## TL;DR

Tongsuo's NTLS handshake cannot complete a TLCP handshake. Three independent code paths reject `NTLS_VERSION` (0x0101) — the version byte defined by GB/T 38636-2020 §6.2 for the TLCP record-layer protocol. All three paths are reached in practice, including Tongsuo's bundled `s_client ↔ s_server` round-trip against itself with documented flags.

This issue lists all three paths. They are ordered by what actually fires for a spec-compliant TLCP peer.

## Path 1 — `ssl_get_min_max_version_ntls` (issue #836 territory)

This is the path that **fires for a spec-compliant TLCP client when the server is started with `-enable_ntls` but without `-ntls`**. Reproduction matches issue #836 exactly:

```bash
./apps/openssl s_server -accept 3322 \
    -cipher ALL:@SECLEVEL=0 \
    -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2 -no_tls1_3 \
    -enable_ntls -quiet
```

Server stack trace (matches #836):
```
#1 tls_setup_handshake_ntls at ssl/statem_ntls/ntls_statem_lib.c:103
#2 state_machine_ntls at ssl/statem_ntls/statem.c:391
#3 ossl_statem_accept at ssl/statem/statem.c:296
```

Error: `error:...:SSL routines:tls_setup_handshake_ntls:no protocols available:ssl/statem_ntls/ntls_statem_lib.c:103`

### Root cause

`s_server -enable_ntls` without `-ntls` keeps `meth = TLS_server_method()` (the version-flexible method, `version == TLS_ANY_VERSION`). `ossl_statem_accept` dispatches into `state_machine_ntls` because of the `-enable_ntls` flag plus a successful `SSL_connection_is_ntls` peek.

Inside `tls_setup_handshake_ntls`, `ssl_get_min_max_version_ntls` is called. Because `s->method->version == TLS_ANY_VERSION`, it falls into the `case TLS_ANY_VERSION:` branch and iterates `tls_version_table` (which *does* include NTLS — see `ssl/statem_ntls/statem_lib.c:1181`). For every iteration:

- The standard TLS methods are filtered out by the user's `-no_tls*` flags (`s->options & method->mask` check in `ssl_method_error` returns non-zero, which sets `hole = 1`).
- For NTLS, `ssl_method_error` *should* succeed: `ssl_security(SSL_SECOP_VERSION, NTLS_VERSION, level=1)` returns 1 (allowed at default level; see Path 3 for the level≥3 case), and `s->options & SSL_OP_NO_NTLS == 0` since the user did not pass `-no_ntls`.

Despite this, the test consistently returns `SSL_R_NO_PROTOCOLS_AVAILABLE`, indicating `version == 0` after the table walk. The exact mechanism by which NTLS gets filtered in this branch is still under investigation (the static analysis suggests it should pass); the proposed fix is to add a dedicated `tls_version_table_ntls` and dispatch from `ssl_get_min_max_version_ntls` only when `s->enable_ntls == 1` and the method is flexible.

## Path 2 — `state_machine` (regular, NOT NTLS) at `ssl/statem/statem.c` line 398

This path fires when `SSL_connection_is_ntls` returns 0 (i.e., the very first record does NOT look like NTLS) but `s->version` has already been initialized to `NTLS_VERSION` by the `NTLS_server_method()`. The trigger is a non-NTLS-shaped record reaching a server configured with `-ntls -enable_ntls`.

```c
} else {
    if ((s->version >> 8) != SSL3_VERSION_MAJOR) {   // 0x03
        SSLfatal(s, SSL_AD_NO_ALERT, SSL_F_STATE_MACHINE,
                 ERR_R_INTERNAL_ERROR);
        goto end;
    }
}
```

For `NTLS_VERSION = 0x0101`, `(0x0101 >> 8) = 0x01 ≠ 0x03` → fatal.

This is **not** reached for a spec-compliant TLCP peer (which sends record `0x0101` and is correctly dispatched into `state_machine_ntls`). It is reached for any non-NTLS record reaching an NTLS-configured server (e.g., a TLS 1.0 probe, a malformed first byte, or a misconfigured peer). This was the bug hit by our gm-tlcp test client when we accidentally sent a TLS 1.0-formatted record instead of the spec `0x0101`.

## Path 3 — `state_machine_ntls` at `ssl/statem_ntls/statem.c` line 334

```c
if (!ssl_security(s, SSL_SECOP_VERSION, 0, s->version, NULL)) {
    SSLfatal_ntls(s, SSL_AD_NO_ALERT, SSL_F_STATE_MACHINE_NTLS,
                   ERR_R_INTERNAL_ERROR);
    goto end;
}
```

This fires only when the user has configured the security level to 3 or higher (`-cipher ...@SECLEVEL=3` or `SSL_CTX_set_security_level(ctx, 3+)`), because `ssl_security_default_callback` blocks NTLS at `level >= 3`:

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

For a spec-compliant TLCP peer at default level 1 (no `-cipher @SECLEVEL=3`), this path is **not** reached — Path 1's `tls_setup_handshake_ntls` fires first.

## Reproduction (no third-party code required)

```bash
# Build
./config enable-ntls && make -j

# Server (use Tongsuo's bundled certs and a self-signed pair for NTLS)
./apps/openssl s_server -accept 3322 \
    -sign_cert cert/certs/SS.pem -sign_key cert/certs/SS.key \
    -enc_cert  cert/certs/SE.pem -enc_key  cert/certs/SE.key \
    -cipher ALL:@SECLEVEL=0 \
    -no_ssl3 -no_tls1 -no_tls1_1 -no_tls1_2 -no_tls1_3 \
    -enable_ntls -ntls -quiet

# Client (bundled Tongsuo s_client)
./apps/openssl s_client -connect 127.0.0.1:3322 \
    -sign_cert cert/certs/CS.pem -sign_key cert/certs/CS.key \
    -enc_cert  cert/certs/CE.pem -enc_key  cert/certs/CE.key \
    -cipher ALL:@SECLEVEL=0 \
    -enable_ntls -ntls
```

| Server flag combination | Error path fired | Stack frame |
|---|---|---|
| `-enable_ntls` only | **Path 1** (ssl_get_min_max_version_ntls) | `ntls_statem_lib.c:103` |
| `-ntls -enable_ntls` (record v=0x0301 or other non-NTLS) | **Path 2** (state_machine regular) | `statem/statem.c:398` |
| `-ntls -enable_ntls` (record v=0x0101, level ≥ 3) | **Path 3** (state_machine_ntls entry) | `statem_ntls/statem.c:334` |

The peer receives a `protocol_version` alert (`02 46` = alert 70) in every case.

## Proposed fix

### Path 1 (most impactful — affects spec-compliant clients)

The cleanest fix is a dedicated `tls_version_table_ntls` that's consulted only when `s->enable_ntls == 1` and the method is flexible:

```c
/* ssl/statem_ntls/statem_lib.c, around line 1658 */
int ssl_get_min_max_version_ntls(const SSL *s, int *min_version, int *max_version,
                            int *real_max)
{
    ...
    if (s->enable_ntls == 1) {
        /* Use a dedicated NTLS table */
        table = tls_version_table_ntls;
    } else {
        switch (s->method->version) {
        default:
            *min_version = *max_version = s->version;
            return 0;
        case TLS_ANY_VERSION:
            table = tls_version_table;
            break;
        }
    }
    ...
}
```

### Path 2 (defensive — affects non-spec peers)

```c
/* ssl/statem/statem.c, around line 398 */
} else {
# ifndef OPENSSL_NO_NTLS
    if (!s->enable_ntls && (s->version >> 8) != SSL3_VERSION_MAJOR) {
# else
    if ((s->version >> 8) != SSL3_VERSION_MAJOR) {
# endif
        SSLfatal(...);
        goto end;
    }
}
```

### Path 3 (high-security contexts)

Make NTLS' security-level gating explicit in `ssl_security_default_callback`:

```c
case SSL_SECOP_VERSION:
    if (!SSL_IS_DTLS(s)) {
#ifndef OPENSSL_NO_NTLS
        /* NTLS v1.1 not allowed at level 5+ (not 3 — see note below) */
        if (nid == NTLS_VERSION && level >= 5)
            return 0;
#endif
        ...
```

(Note: the existing `level >= 3` cutoff for NTLS is overly restrictive. TLCP is a current national standard, GB/T 38636-2020, and should be allowed at security level 3 like TLS 1.2.)

## Why this matters

This is not a tooling quirk. **Tongsuo's bundled `s_client ↔ s_server` round-trip fails against itself** when both sides are configured with the documented `-enable_ntls -ntls` flag set, and any third-party TLCP peer following GB/T 38636-2020 hits Path 1 by default. The interop problem blocks any TLCP deployment on Tongsuo until at least Path 1 is fixed.

## References

- GB/T 38636-2020 §6.2 — TLCP record-layer protocol version = `0x0101`
- GM/T 0024-2014 §6.2 — predecessor standard with the same `0x0101` version
- Tongsuo issue #836 — covers Path 1 only: https://github.com/Tongsuo-Project/Tongsuo/issues/836
- gm-tlcp's recorded diagnostic trace: `gm-tlcp/interop/tongsuo/FINDINGS.md`
- Independent TLCP implementations that emit the spec version byte `0x0101`:
  - GmSSL: `TLS_protocol_tlcp = 0x0101` in `include/gmssl/tls.h`
  - gm-tlcp (record-layer framing per GB/T 38636-2020)
  - openHiTLS, GMNS, tjfoc/gmsm
