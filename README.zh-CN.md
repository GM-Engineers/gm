# GM 密码学与 TLS

纯 Rust 实现的国密（GM/T）密码学算法和 TLS 协议栈，完整支持 SM2/SM3/SM4。

**[English Version](./README.md)**

## 文档导航

| 文档 | 内容 |
|------|------|
| [快速入门](./docs/getting-started.md) | 环境准备、依赖添加、第一个可运行例子 |
| [gm-crypto 使用指南](./docs/gm-crypto.md) | SM2 签名、SM3 哈希、SM4 加密的完整 API 说明 |
| [gm-tls 使用指南](./docs/gm-tls.md) | GM/TLS 客户端/服务器开发、会话存储配置 |
| [gm-ca 部署指南](./docs/gm-ca.md) | CA 服务部署、gRPC API 调用方式 |
| [gm-http-client 使用指南](./docs/gm-http-client.md) | HTTPS 客户端、连接池、SSRF 防护 |
| [证书操作指南](./docs/certificate-howto.md) | 证书生成、格式说明、与 OpenSSL/GmSSL 集成 |
| [Docker 部署指南](./docs/deployment.md) | docker-compose 生产部署、运维 |

## 概览

```
gm/                          # 工作空间
├── gm-crypto/               # 密码学原语（SM2/SM3/SM4）
├── gm-tls/                  # GM/TLS 协议实现
├── gm-ca/                   # gRPC CA 服务（证书签发/吊销/查询）
├── gm-sm9-rs/                  # SM9 基于身份的密码（签名/加密）
├── gm-der/                  # DER/ASN.1 编解码（共享工具）
├── gm-http-client/          # HTTPS 客户端
├── docs/                    # 详细使用文档（本目录）
└── docker/                  # Docker 部署配置
```

## Crate 概览

| Crate | 类型 | 说明 |
|-------|------|------|
| `gm-crypto` | 库 | 密码学原语，无二进制 |
| `gm-tls` | 库 | GM/TLS 协议，可选 `grpc` feature 支持 gRPC over GM/TLS |
| `gm-ca` | 库 + 服务 | 提供 `gm-ca-server` 二进制，gRPC 接口 |
| `gm-sm9-rs` | 库 | SM9 基于身份的签名/加密；双后端（纯 Rust + GmSSL FFI） |
| `gm-der` | 库 | 共享 DER/ASN.1 编解码工具 |
| `gm-http-client` | 库 | 基于 gm-tls 的 HTTPS 客户端 |

## 快速示例

```toml
[dependencies]
gm-crypto = "0.1"
gm-sm9-rs = "0.1"
```

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer};
use gm_crypto::sm3::Sm3Hasher;
use gm_crypto::sm4::Sm4Cipher;
use gm_sm9_rs::{SignMasterKey, Signer, Verifier};

// SM2/SM3/SM4
let key_pair = Sm2KeyPair::generate().unwrap();
let signer = Sm2Signer::new(&key_pair).unwrap();
let sig = signer.sign(b"Hello, GM!").unwrap();

let hash = Sm3Hasher::hash(b"data").unwrap();

let cipher = Sm4Cipher::new(b"0123456789abcdef").unwrap();
let (ct, tag) = cipher.encrypt_gcm(b"secret", b"0123456789ab", b"").unwrap();

// SM9 基于身份的签名
let mut rng = rand::thread_rng();
let master = SignMasterKey::generate(&mut rng)?;
let user_key = master.extract_key(b"alice@example.com")?;
let signer = Signer::new(user_key);
let sig = signer.sign(b"message")?;
let verifier = Verifier::new(b"alice@example.com", &master.ppubs);
assert!(verifier.verify(b"message", &sig)?);
```

## 第三方组件

本项目封装了社区已有实现，并移植了外部代码：

- **SM2 / SM3 / SM4**（`gm-crypto`）是对社区 Rust crate [`sm2`](https://crates.io/crates/sm2)、[`sm3`](https://crates.io/crates/sm3)、[`sm4`](https://crates.io/crates/sm4) 的轻量封装，并非从零自研。
- **SM9**（`gm-sm9-rs`）是 [GmSSL](https://github.com/guanzhi/GmSSL)（Apache-2.0）的 Rust 移植。署名与许可详情见 [NOTICE](./NOTICE)。

## 许可

MIT OR Apache-2.0 — 详见 [LICENSE](./LICENSE)

> 报告安全漏洞：[SECURITY.md](./SECURITY.md)
