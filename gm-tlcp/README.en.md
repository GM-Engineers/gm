# gm-tlcp

TLCP (GB/T 38636-2020) core library in pure Rust — SM2/SM3/SM4 algorithms.

## Protocol Overview

TLCP (Transport Layer Cryptographic Protocol) is the Chinese national
standard defined in GB/T 38636-2020. It is structurally similar to
TLS 1.3 but:

- Uses the Chinese national cipher suite: SM2 (signature / encryption / key exchange), SM3 (hash), SM4 (block cipher)
- Requires **dual certificates** (sign cert + enc cert)
- Protocol version byte is `[0x01, 0x01]` (vs TLS 1.3's `[0x03, 0x03]`)
- **Not interoperable with TLS 1.3**

### 12 Cipher Suites (full GB/T 38636-2020 §6.4.5.2.1 表 2)

| ID | Name | Notes |
|----|------|-------|
| `0xE051` | `TLS_ECDHE_SM4_GCM_SM3` | ECDHE + SM4-GCM + SM3 — **preferred**, recommended for production |
| `0xE011` | `TLS_ECDHE_SM4_CBC_SM3` | ECDHE + SM4-CBC + HMAC-SM3 |
| `0xE053` | `TLS_ECC_SM4_GCM_SM3`  | Static key + SM4-GCM + SM3 — no ECDHE, for performance-critical scenarios |
| `0xE013` | `TLS_ECC_SM4_CBC_SM3`  | Static key + SM4-CBC + HMAC-SM3 — no ECDHE |
| `0xE057` | `TLS_IBC_SM4_GCM_SM3`  | SM9-IBC + SM4-GCM + SM3 (static) |
| `0xE017` | `TLS_IBC_SM4_CBC_SM3`  | SM9-IBC + SM4-CBC + HMAC-SM3 (static) |
| `0xE055` | `TLS_IBSDH_SM4_GCM_SM3` | SM9-IBSDH + SM4-GCM + SM3 (dynamic) |
| `0xE015` | `TLS_IBSDH_SM4_CBC_SM3` | SM9-IBSDH + SM4-CBC + HMAC-SM3 (dynamic) |
| `0xE059` | `TLS_RSA_SM4_GCM_SM3`   | RSA + SM4-GCM + SM3 (static) |
| `0xE019` | `TLS_RSA_SM4_CBC_SM3`   | RSA + SM4-CBC + HMAC-SM3 (static) |
| `0xE05A` | `TLS_RSA_SM4_GCM_SHA256` | RSA + SM4-GCM + SHA-256 (static) — PRF dispatcher still SM3 in gm-tlcp 0.6.4 (no SHA-256 PRF dispatch wired) |
| `0xE01C` | `TLS_RSA_SM4_CBC_SHA256` | RSA + SM4-CBC + SHA-256 (static) — PRF dispatcher still SM3 in gm-tlcp 0.6.4 (no SHA-256 PRF dispatch wired) |

## Implementation Status

- ✅ Full TLCP handshake state machine (client + server, 9 handshake message types)
- ✅ Dual-certificate handling (sign cert + enc cert)
- ✅ SM2 ECDHE key exchange + SM3-based PRF
- ✅ SM4-GCM and SM4-CBC + HMAC-SM3 record-layer encryption
- ✅ Session resumption via session IDs (`TlcpSessionCache`)
- ✅ Alert protocol (`TlcpAlert` / `TlcpAlertDescription`)
- ✅ All 12 cipher suites
- ✅ **End-to-end in-process loopback regression gate for all 12 cipher suites** (`tests/gm_tlcp_loopback.rs`): gm-tlcp acts as both client AND server over `tokio::io::duplex`, runs the full handshake, and exchanges a single app-data round-trip to prove record-layer keys match on both sides. Coverage: 16 handshake-loopback tests (ECDHE/ECC/IBC/IBSDH/RSA × {GCM,CBC} = 8 base + 4 RSA-SHA256 + 4 RSA-single-cert variants) + 4 support-module tests + 1 PMS-only KAT test = 21 total.
- ✅ 125 lib tests + 21 loopback + 32 integration tests
- ✅ GmSSL 3.3.0-dev (`master`) handshake verified end-to-end for `TLS_ECDHE_SM4_GCM_SM3` (E051) with `--features tlcp-gmssl-compat` (R-8 F3, **first positive cross-impl interop evidence**)
- ⚠️ GmSSL 3.3.0-dev app-data exchange hangs after successful handshake — gmssl-master `tools/tlcp_server.c::do_send_select` state-machine deadlock (R-9 F4, reclassified as External-Upstream-Blocker; gm-tlcp production source is **not** at fault; see `interop/AUDIT-2026-09-06-v2.md` v2-rev12 + `interop/F4-DIAGNOSTIC-2026-09-09.md`)
- ✅ R-10 / external upstream tracking filed + verified (2026-09-10, audit v2-rev13). GmSSL upstream issue [#1920](https://github.com/guanzhi/GmSSL/issues/1920) submitted by EricZHANG1688 (F4 deadlock against `tools/tlcp_server.c::do_send_select`; body trimmed + edited clean via `gh issue create` + `gh issue edit`, final 185-line body verified via WebFetch). Tongsuo [#836](https://github.com/Tongsuo-Project/Tongsuo/issues/836) comment (id 5557341448) verified via GitHub REST API as already submitted by EricZHANG1688 on 2026-09-06 (the 239-line bundled-only repro draft); Tongsuo maintainer pr000000f replied on 2026-09-09 acknowledging the NTLS root cause and committed a fix + sub-issues [#840](https://github.com/Tongsuo-Project/Tongsuo/issues/840) (Path 2) + [#841](https://github.com/Tongsuo-Project/Tongsuo/issues/841) (both currently empty placeholders); gm-tlcp will NOT populate these unsolicited. R-9 + R-10 were doc-only at the time of writing; they were bundled into 0.6.4 together with R-11 (the actual code change). See `interop/R9-4C-SUBMISSION-RECORD.md` + `interop/R10-STATUS-RECORD.md` + `AUDIT-2026-09-06-v2.md` v2-rev13 + `CHANGELOG.md [0.6.4]`.
- ❌ Tongsuo 8.3.0 round-trip — Tongsuo-side NTLS state-machine rejects `0x0101`, investigation tracked in `interop/tongsuo/upstream/` (see R-10: #836 + #840 + #841 are now filed upstream)

## Documentation

- Module API index: top-level `//!` doc in `src/tlcp/mod.rs`
- Publishing / package manifest: `PUBLISHING.md`
- Tongsuo interop investigation: `interop/tongsuo/upstream/`

## License

MIT OR Apache-2.0
