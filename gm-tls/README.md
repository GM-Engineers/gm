# gm-tls

国密 TLS (GM/TLS) 核心库 - 纯 Rust 实现，支持 SM2/SM3/SM4 算法。

**[English Version](./README.en.md)**

## 概述

gm-tls 是一个用于 GM/TLS 协议实现的 Rust 库，提供了：

- **SM2** 椭圆曲线密钥生成、签名、验签
- **SM3** 哈希算法和 KDF 密钥派生
- **SM4-GCM** 对称加密（带认证）
- **mTLS** 双向认证握手流程

## 文档

- [快速开始指南](./README.md)（本文档）
- [架构文档](./ARCHITECTURE.md) - 组件结构和设计
- [安全指南](./SECURITY.md) - 安全最佳实践

### 测试覆盖率

```bash
cargo test --workspace
cargo tarpaulin --out Html --workspace --tests  # 需要 cargo-tarpaulin
```

## 快速开始

```rust
use gm_tls::gm::{connect_gm_rust, HandshakeOptions};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = std::fs::read("client.pem")?;
    let key_pem = std::fs::read("client-key.pem")?;
    let ca_pem = std::fs::read("ca.pem")?;

    let stream = TcpStream::connect("127.0.0.1:8443").await?;
    let tls_stream = connect_gm_rust(
        &cert_pem,
        &key_pem,
        &ca_pem,
        Some("example.com"),
        &["http/1.1".to_string()],
        stream,
        &HandshakeOptions::default(),
    ).await?;

    tls_stream.write_application_data(b"Hello").await?;
    let response = tls_stream.read_application_data().await?;
    println!("Received: {:?}", response);

    Ok(())
}
```

## 安全使用指南

### 1. 密钥管理

- **私钥保护**: 确保私钥文件权限为 600，且仅 owner 可读
- **密钥轮换**: 建议定期更换会话密钥，建议周期不超过 90 天
- **CSPRNG**: 始终使用系统提供的安全随机数生成器，不要使用可预测的随机数

### 2. 证书验证

- **完整链验证**: 始终验证完整证书链，不要跳过中间 CA
- **域名匹配**: 使用 `validate_cert_pem` 时务必传入期望的域名
- **有效期检查**: 证书过期或未生效都会被拒绝
- **自签名限制**: 生产环境应配置 CA 证书，不接受自签名证书

### 3. 会话安全

- **Nonce 唯一性**: 每次加密必须使用唯一的序列号，不要重复使用 nonce
- **序列号管理**: 读写序列号独立管理，不要混淆
- **记录大小限制**: 单条记录建议不超过 64KB

### 4. 错误处理

- **不要忽略错误**: 验签失败、认证失败时应立即终止会话
- **日志记录**: 记录错误用于安全审计，但不要泄漏敏感信息

## API 稳定性

本库遵循语义化版本控制，API 在主要版本间保持稳定。

当前版本：v0.1.0

### 稳定 API

以下 API 在 v0.x 范围内不会引入破坏性变更：

**低层 API（gm 模块）：**
- `gm_tls::gm::connect_gm_rust`
- `gm_tls::gm::accept_gm_rust`
- `gm_tls::gm::GmTlsStream`
- `gm_tls::gm::HandshakeOptions`
- `gm_tls::gm::SessionKeys`
- `gm_tls::gm::validate_cert_pem`

**高层 API：**
- `gm_tls::TlsConfig`
- `gm_tls::TlsConnector`
- `gm_tls::TlsAcceptor`

### 实验性 API

以下 API 标记为实验性，可能会变更：

- 内部握手状态机函数
- 未公开的协议细节

## 性能特征

| 操作 | 平均延迟 |
|------|----------|
| SM2 临时密钥生成 | ~95 µs |
| SM2 签名 | ~100 µs |
| SM2 验签 | ~80 µs |
| SM4-GCM 加密/解密 | ~5 µs/KB |
| ClientHello 构建 | ~94 µs |
| ALPN 选择 | ~2.8 ns |

## 测试

```bash
cargo test --workspace
cargo test --workspace -- --test-threads=1  # 串行运行（如需）
```

## 依赖与许可证

本项目所有依赖均为 MIT/Apache-2.0/BSD 许可证，无 GPL/LGPL 等 copyleft 限制。

## 安全报告

如发现安全漏洞，请通过 GitHub Security Advisories 报告，不要在公开 issue 中讨论。

---

**注意**: 本库是基础组件，不包含业务逻辑。使用时请遵循上述安全指南。
