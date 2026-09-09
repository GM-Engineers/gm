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

### 12 套密码套件（GB/T 38636-2020 完整集）

| ID | 名称 | 状态 |
|----|------|------|
| `0xE057` | `TLS_IBC_SM4_GCM_SM3` | ⚠️ 0.5.1 broken / ✅ 0.5.2 fixed (R-4.1 / R-4.1-hotfix)：SM9 IBC + SM4-GCM + SM3 |
| `0xE017` | `TLS_IBC_SM4_CBC_SM3` | ⚠️ 0.5.1 broken / ✅ 0.5.2 fixed (R-4.1 / R-4.1-hotfix)：SM9 IBC + SM4-CBC + HMAC-SM3 |
| `0xE055` | `TLS_IBSDH_SM4_GCM_SM3` | ✅ 0.5.3 (R-4.2)：SM9 IBSDH 2-round KEX + SM4-GCM + SM3 |
| `0xE015` | `TLS_IBSDH_SM4_CBC_SM3` | ✅ 0.5.3 (R-4.2)：SM9 IBSDH 2-round KEX + SM4-CBC + HMAC-SM3 |
| `0xE059` | `TLS_RSA_SM4_GCM_SM3` | ✅ 0.6.0 (R-5)：RSA + SM4-GCM + SM3 |
| `0xE019` | `TLS_RSA_SM4_CBC_SM3` | ✅ 0.6.0 (R-5)：RSA + SM4-CBC + HMAC-SM3 |
| `0xE05A` | `TLS_RSA_SM4_GCM_SHA256` | ✅ 0.6.0 (R-5)：RSA + SM4-GCM + SHA-256（PRF 仍走 SM3，详见 CHANGELOG 已知限制） |
| `0xE01C` | `TLS_RSA_SM4_CBC_SHA256` | ✅ 0.6.0 (R-5)：RSA + SM4-CBC + SHA-256（PRF 仍走 SM3，详见 CHANGELOG 已知限制） |

## 实现状态

- ✅ 完整 TLCP 握手状态机（client + server，9 个 handshake 消息类型）
- ✅ 双证书处理（sign cert + enc cert）
- ✅ SM2 ECDHE 密钥交换 + SM3-based PRF
- ✅ SM4-GCM 和 SM4-CBC + HMAC-SM3 record-layer 加密
- ✅ Session resumption via session IDs (`TlcpSessionCache`)
- ✅ Alert 协议（`TlcpAlert` / `TlcpAlertDescription`）
- ✅ 全部 12 个密码套件（4 SM2 + 4 SM9 + 4 RSA）
- ✅ **审计全清**（R-6 / gm-tlcp 0.6.1）：`interop/AUDIT-2026-09-06-v2.md` v2-rev9：0 Critical / 0 Major / 0 Minor / 0 Doc still blocked。9 项历史遗留 (M-1/M-2/M-3 + m-2..m-6 + D-1) 全部 RESOLVED。
- ✅ 119 lib tests (R-5 +6：rsa_helpers 单元测试) + 11 loopback tests（R-5 +2：2 个 `gm_tlcp_rsa_loopback_with_real_keys_{gcm,cbc}`） + 32 integration tests (`tests/integration_tlcp.rs`) + 4 default gmssl interop tests (7 more `#[ignore]`d, run with `--ignored` when `gmssl` is on `PATH`)
- ✅ GmSSL 3.3.0-dev (`master`) handshake + APP_DATA byte-for-byte 互操作验证（需 `tlcp-gmssl-compat`）
- ✅ openHiTLS `s_server -tlcp` 互操作验证：ECDHE（默认模式）+ static-ECC SKE + static-ECC PMS decrypt（默认模式，server 侧 R-3 已实现）
- ✅ R-4 / gm-tlcp 0.5.0: SM9 IBC 静态套件 (E057/E017) cipher_suite registry 已声明，SKE/CKE wire format 完整实现 + 单元测试覆盖。
- ✅ R-4.1 / gm-tlcp 0.5.2: SM9 IBC 握手 step 5 (server SKE 用 SM9 IBC 签名) + step 7.5 (client CKE 用 SM9 PKE 加密 PMS) + step 8 (server SM9 decrypt 恢复 PMS) 全部接通。`TlcpAcceptor::with_sm9_certs(...)` / `TlcpConnector::with_sm9_certs(...)` 为新增构造器。2 个 loopback 回归门禁（`gm_tlcp_sm9_ibc_loopback_with_real_keys_{gcm,cbc}`）在 `tests/gm_tlcp_loopback.rs` 。C-5 IBC half 已 RESOLVED。
- ⚠️ R-4.1 (0.5.1)发布 版本: SM9 IBC wire path 实际上坏（server 早返 + ServerHello parse 白名单漏 IBC + server 对 IBC 发 CR）—— 请跳过 0.5.1 使用 0.5.2。ECDHE/ECC 路径不受影响。
- ✅ R-4.2 / gm-tlcp 0.5.3: SM9 IBSDH ephemeral 套件 (E055/E015) — 2 轮 initiator/responder 握手。2 个 loopback 回归门禁新增（`gm_tlcp_sm9_ibsdh_loopback_with_real_keys_{gcm,cbc}`）。C-5 IBSDH half 已 RESOLVED。Known limitation: v1 使用 `client_id = server_id` 简捷做法（同身份部署）；后续 PR 可扩展 `with_sm9_certs_client_id(...)` 支持非对称身份。
- ✅ R-5 / gm-tlcp 0.6.0: RSA 套件 (E019/E01C/E059/E05A) — RustCrypto `rsa = 0.9` 直集成（RSA 不属于国密，故不放在 gm-crypto）。`TlcpAcceptor::with_rsa_certs(rsa_keypair, rsa_cert_der)` + `TlcpConnector::with_rsa_certs(server_rsa_pub)` 为新增构造器。2 个 loopback 回归门禁新增（`gm_tlcp_rsa_loopback_with_real_keys_{gcm,cbc}`）。C-5 RSA half 已 RESOLVED；C-5 整体在 0.6.0 完整 RESOLVED（4 SM2 + 4 SM9 + 4 RSA = 全部 12 套）。
- ⚠️ R-5 已知限制（保留作向后兼容路径）：(a) 两个 `_SHA256` 套件 (E01C/E05A) 的 PRF 仍走 SM3（spec 模糊，与 GmSSL + openHiTLS 一致）；(b) `TlcpAcceptor::with_rsa_certs(...)`（dual-cert layout） 仍保留，给需要双-cert 互操作的部署使用。新部署建议改用 `with_rsa_certs_single(...)`（R-7 0.6.2 走 GB/T 38636-2020 §6.4.5.5 单证书 layout；openHiTLS / Tongsuo 互操作同样走单证书）。
- ✅ R-6 / gm-tlcp 0.6.1: 审计 close-out（无 wire / API 变动）。新加 `TlcpAcceptor::with_server_sign_distid(distid)` 与 connector 侧 4 个 `with_*_distid` 对齐 ；`pms.rs` 顶注的 “GmSSL-specific `x̂` transform” 表述改为 GM/T 0003.3-2012 §6.1 ；其余 m-2..m-6 + D-1 状态由 `git grep` / `cargo +stable test --lib` 现网走话验 证。详细见 `CHANGELOG.md [0.6.1]` + `interop/AUDIT-2026-09-06-v2.md` v2-rev9。
- ✅ R-7 / gm-tlcp 0.6.2: RSA 套件单证书 wire format（GB/T 38636-2020 §6.4.5.5）— 新增 `TlcpAcceptor::with_rsa_certs_single(...)` 与 `TlcpConnector::with_rsa_certs_single(...)`（后者为 `with_rsa_certs` 同义别名）。`TlcpCertPair::from_certificate_message` 现在同时接受 1-cert（RSA）与 2-cert（SM2/SM9）两种 layout，server 侧 suite-aware 后置校验仅拒绝 “non-RSA 套件的单证书” （spe c 违规）。原 `with_rsa_certs` 保留作向后兼容路径（仍发 dual-cert）。2 个 loopback 回归门禁新增 `gm_tlcp_rsa_single_cert_loopback_with_real_keys_{gcm,cbc}`。详细见 `CHANGELOG.md [0.6.2]`。
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
