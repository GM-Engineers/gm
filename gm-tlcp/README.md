# gm-tlcp

TLCP（GB/T 38636-2020）纯 Rust 实现 — 国密 SM2/SM3/SM4 算法。

**[English Version](./README.en.md)** (待补)

## ⚠️ 当前状态：骨架（Phase 1 第一批）

本 crate 正在从 [`gm-tls`](../gm-tls) 的 `tlcp` 子模块拆分中。
**完整 TLCP 实现（4502 行 + 1592 行集成测试）目前仍在 `gm-tls/src/tlcp.rs`**，
本 crate 暂为空骨架。

### 拆分计划

| 阶段 | 内容 | 状态 |
|------|------|------|
| Phase 1 第一批 | 本骨架（workspace 注册 + 空 crate） | **进行中** |
| Phase 1 主体 | 搬 4502 行 tlcp.rs + 1592 行测试 + ~565 行工具代码 | 待 |
| Phase 1 收尾 | gm-tls 旧路径加 `#[deprecated]` re-export | 待 |
| Phase 2 | 硬切换：gm-tls 移除 TLCP、major bump、写 MIGRATION.md | 待 |

详见：
- [讨论稿 §5.2 / §10 / §11](../../gm-kms/discuss/00-tlcp-implementation-status.md)
- [ADR-001](../../gm-kms/discuss/10-adr-gm-tlcp-split.md)
- [战略决策](../../gm-kms/discuss/02-tlcp-strategy.md)

## 协议简介

TLCP（Transport Layer Cryptographic Protocol，传输层密码协议）是 GB/T 38636-2020
定义的国家标准。它在结构上类似 TLS 1.3，但：

- 使用国密 SM2（签名/加密/密钥交换）、SM3（哈希）、SM4（对称加密）
- 采用**双证书**系统：签名证书 + 加密证书
- 协议版本字节 `[0x01, 0x01]`（不同于 TLS 1.3 的 `[0x03, 0x03]`）
- **与 TLS 1.3 不兼容**——不能互操作

### 4 套密码套件

| ID | 名称 |
|----|------|
| `0xE011` | ECDHE + SM4-GCM + SM3 |
| `0xE013` | ECDHE + SM4-CBC + SM3 |
| `0xE001` | ECC + SM4-GCM + SM3（无 ECDHE） |
| `0xE003` | ECC + SM4-CBC + SM3（无 ECDHE） |

## 文档

- 协议架构文档（待补）
- 实现状态：[gm-kms/discuss/00-tlcp-implementation-status.md](../../gm-kms/discuss/00-tlcp-implementation-status.md)
- 拆分 ADR：[gm-kms/discuss/10-adr-gm-tlcp-split.md](../../gm-kms/discuss/10-adr-gm-tlcp-split.md)

## 许可证

MIT OR Apache-2.0
