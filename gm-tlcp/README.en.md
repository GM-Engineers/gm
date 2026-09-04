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
- ✅ 58 lib tests + 32 integration tests (`tests/integration_tlcp.rs`) + 4 default gmssl interop tests (7 more `#[ignore]`-gated, run with `--ignored` when `gmssl` is on `PATH`)
- ✅ GmSSL 3.3.0-dev (`master`) handshake + APP_DATA byte-for-byte interoperability verified
- ❌ Tongsuo 8.3.0 round-trip — Tongsuo-side NTLS state-machine rejects `0x0101`, investigation tracked in `interop/tongsuo/upstream/`

## Documentation

- Module API index: top-level `//!` doc in `src/tlcp/mod.rs`
- Publishing / package manifest: `PUBLISHING.md`
- Tongsuo interop investigation: `interop/tongsuo/upstream/`

## License

MIT OR Apache-2.0
