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
- ✅ 58 lib tests + 32 integration tests (`tests/integration_tlcp.rs`) + 4 default gmssl interop tests (7 more `#[ignore]`d, run with `--ignored` when `gmssl` is on `PATH`)
- ✅ GmSSL 3.3.0-dev (`master`) handshake + APP_DATA byte-for-byte 互操作验证
- ❌ Tongsuo 8.3.0 round-trip — Tongsuo-side NTLS state-machine 拒绝 `0x0101`，调查见 `interop/tongsuo/upstream/`

## 文档

- 模块 API 索引：`src/tlcp/mod.rs` 顶部 `//!` doc
- 发布/打包清单：`PUBLISHING.md`
- Tongsuo 互操作调查：`interop/tongsuo/upstream/`

## 许可证

MIT OR Apache-2.0
