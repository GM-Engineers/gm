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

### 4 Cipher Suites

| ID | Name | Notes |
|----|------|-------|
| `0xE051` | `TLS_ECDHE_SM4_GCM_SM3` | ECDHE + SM4-GCM + SM3 — **preferred**, recommended for production |
| `0xE011` | `TLS_ECDHE_SM4_CBC_SM3` | ECDHE + SM4-CBC + HMAC-SM3 |
| `0xE053` | `TLS_ECC_SM4_GCM_SM3`  | Static key + SM4-GCM + SM3 — no ECDHE, for performance-critical scenarios |
| `0xE013` | `TLS_ECC_SM4_CBC_SM3`  | Static key + SM4-CBC + HMAC-SM3 — no ECDHE |

## Implementation Status

- ✅ Full TLCP handshake state machine (client + server, 9 handshake message types)
- ✅ Dual-certificate handling (sign cert + enc cert)
- ✅ SM2 ECDHE key exchange + SM3-based PRF
- ✅ SM4-GCM and SM4-CBC + HMAC-SM3 record-layer encryption
- ✅ Session resumption via session IDs (`TlcpSessionCache`)
- ✅ Alert protocol (`TlcpAlert` / `TlcpAlertDescription`)
- ✅ All 4 cipher suites
- ✅ 125 lib tests + 13 loopback + 32 integration tests (preserved from 0.6.3 baseline)
- ✅ GmSSL 3.3.0-dev (`master`) handshake verified end-to-end for `TLS_ECDHE_SM4_GCM_SM3` (E051) with `--features tlcp-gmssl-compat` (R-8 F3, **first positive cross-impl interop evidence**)
- ⚠️ GmSSL 3.3.0-dev app-data exchange hangs after successful handshake — gmssl-master `tools/tlcp_server.c::do_send_select` state-machine deadlock (R-9 F4, reclassified as External-Upstream-Blocker; gm-tlcp production source is **not** at fault; see `interop/AUDIT-2026-09-06-v2.md` v2-rev12 + `interop/F4-DIAGNOSTIC-2026-09-09.md`)
- ✅ R-10 / external upstream tracking filed + verified (2026-09-10, audit v2-rev13). GmSSL upstream issue [#1920](https://github.com/guanzhi/GmSSL/issues/1920) submitted by EricZHANG1688 (F4 deadlock against `tools/tlcp_server.c::do_send_select`; body trimmed + edited clean via `gh issue create` + `gh issue edit`, final 185-line body verified via WebFetch). Tongsuo [#836](https://github.com/Tongsuo-Project/Tongsuo/issues/836) comment (id 5557341448) verified via GitHub REST API as already submitted by EricZHANG1688 on 2026-09-06 (the 239-line bundled-only repro draft); Tongsuo maintainer pr000000f replied on 2026-09-09 acknowledging the NTLS root cause and committed a fix + sub-issues [#840](https://github.com/Tongsuo-Project/Tongsuo/issues/840) (Path 2) + [#841](https://github.com/Tongsuo-Project/Tongsuo/issues/841) (both currently empty placeholders); gm-tlcp will NOT populate these unsolicited. gm-tlcp production source unchanged; no 0.6.4 release. See `interop/R9-4C-SUBMISSION-RECORD.md` + `interop/R10-STATUS-RECORD.md` + `AUDIT-2026-09-06-v2.md` v2-rev13 + `CHANGELOG.md [Unreleased]`.
- ❌ Tongsuo 8.3.0 round-trip — Tongsuo-side NTLS state-machine rejects `0x0101`, investigation tracked in `interop/tongsuo/upstream/` (see R-10: #836 + #840 + #841 are now filed upstream)

## Documentation

- Module API index: top-level `//!` doc in `src/tlcp/mod.rs`
- Publishing / package manifest: `PUBLISHING.md`
- Tongsuo interop investigation: `interop/tongsuo/upstream/`

## License

MIT OR Apache-2.0
