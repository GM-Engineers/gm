# gm-tlcp

TLCP (GB/T 38636-2020) core library in pure Rust — 国密 SM2/SM3/SM4 算法.

## 协议简介

TLCP（Transport Layer Cryptographic Protocol，传输层密码协议）是 GB/T 38636-2020
定义的国家标准。它在结构上类似 TLS 1.3，但：

- 使用国密 SM2（签名/加密/密钥交换）、SM3（哈希）、SM4（对称加密）
- 采用**双证书**系统：签名证书 + 加密证书
- 协议版本字节 `[0x01, 0x01]`（不同于 TLS 1.3 的 `[0x03, 0x03]`）
- **与 TLS 1.3 不兼容**——不能互操作

### 4 套密码套件

| ID | 名称 | 说明 |
|----|------|------|
| `0xE051` | `TLS_ECDHE_SM4_GCM_SM3` | ECDHE + SM4-GCM + SM3 — **首选**，生产推荐 |
| `0xE011` | `TLS_ECDHE_SM4_CBC_SM3` | ECDHE + SM4-CBC + HMAC-SM3 |
| `0xE053` | `TLS_ECC_SM4_GCM_SM3` | 静态密钥 + SM4-GCM + SM3 — 无 ECDHE，性能优化场景 |
| `0xE013` | `TLS_ECC_SM4_CBC_SM3` | 静态密钥 + SM4-CBC + HMAC-SM3 — 无 ECDHE |

## 实现状态

- ✅ 完整 TLCP 握手状态机（client + server，9 个 handshake 消息类型）
- ✅ 双证书处理（sign cert + enc cert）
- ✅ SM2 ECDHE 密钥交换 + SM3-based PRF
- ✅ SM4-GCM 和 SM4-CBC + HMAC-SM3 record-layer 加密
- ✅ Session resumption via session IDs (`TlcpSessionCache`)
- ✅ Alert 协议（`TlcpAlert` / `TlcpAlertDescription`）
- ✅ 全部 4 个密码套件
- ✅ 85 lib tests + 5 loopback tests（`tests/gm_tlcp_loopback.rs`，包含 `gm_tlcp_kap_pms_roundtrip_with_real_keys`）+ 32 integration tests (`tests/integration_tlcp.rs`) + 4 default gmssl interop tests (7 more `#[ignore]`d, run with `--ignored` when `gmssl` is on `PATH`)
- ✅ GmSSL 3.3.0-dev (`master`) handshake + APP_DATA byte-for-byte 互操作验证（需 `tlcp-gmssl-compat`）
- ✅ openHiTLS `s_server -tlcp` 互操作验证：ECDHE（默认模式）+ static-ECC SKE round-trip（默认模式 sig-only body）
- ❌ Tongsuo 8.3.0 round-trip — Tongsuo-side NTLS state-machine 拒绝 `0x0101`， 调查见 `interop/tongsuo/upstream/`

## 特性开关 (Feature flags)

| Feature | 状态 | 说明 |
|---|---|---|
| `default` | enabled | **GB/T 38636-2020 spec 行为**（0.3.0+ 默认）。ECDHE `ClientKeyExchange` 不带 `uint16` 前缀；静态-ECC 不发/读 `ServerKeyExchange`；ECDHE PMS 走 SM2 KAP (48-byte KDF)。与 openHiTLS / Tongsuo 标准模式一致。 |
| `tlcp-strict` | **DEPRECATED**（0.3.0+ no-op） | 为 0.2.x 调用者的 `Cargo.toml` 保留——不再影响行为。请迁移到下条。 |
| `tlcp-gmssl-compat` | opt-in（默认 off） | **回滚到 0.2.x default 的 wire 偏离**，与 GmSSL 2026-06+ master / Tongsuo NTLS byte-for-byte 互操作。仅当你需要连 GmSSL master时才打开。 |

### 从 0.2.x 迁到 0.3.0

| 0.2.x 配置 | 目标 peer | 0.3.0 配置 |
|---|---|---|
| default mode（无 flag） | GmSSL master / Tongsuo NTLS | 加 `features = ["tlcp-gmssl-compat"]` |
| `features = ["tlcp-strict"]` | openHiTLS / standards-strict | 删除 `tlcp-strict` 即可（默认就是 spec 行为） |

公共 API 未变；仅 feature flag 名变了。详见 `CHANGELOG.md [0.3.0]`。

## 文档

- 模块 API 索引：`src/tlcp/mod.rs` 顶部 `//!` doc
- 发布/打包清单：`PUBLISHING.md`
- Tongsuo 互操作调查：`interop/tongsuo/upstream/`

## 许可证

MIT OR Apache-2.0
