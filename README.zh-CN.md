# 国密（GM）算法与协议栈实现

纯 Rust 实现的国密（GM/T）密码算法、TLS 1.3 + SM 算法栈，以及 TLCP（GB/T 38636-2020）协议，完整支持 SM2/SM3/SM4。

**[English Version](./README.md)**

## 文档导航

| 文档 | 内容 |
|------|------|
| [快速入门](./docs/getting-started.md) | 环境准备、依赖添加、第一个可运行例子 |
| [gm-crypto 使用指南](./docs/gm-crypto.md) | SM2 签名、SM3 哈希、SM4 加密的完整 API 说明 |
| [gm-tls 使用指南](./docs/gm-tls.md) | TLS 1.3 + SM 客户端/服务器开发、会话存储配置 |
| [gm-tlcp 使用指南](./docs/gm-tlcp.md) | TLCP（GB/T 38636-2020）协议、双证书 PKI、与 GmSSL 互操作 |
| [gm-ca 部署指南](./docs/gm-ca.md) | CA 服务部署、gRPC API 调用方式 |
| [gm-http-client 使用指南](./docs/gm-http-client.md) | HTTPS 客户端、连接池、SSRF 防护 |
| [证书操作指南](./docs/certificate-howto.md) | 证书生成、格式说明、与 OpenSSL/GmSSL 集成 |
| [Docker 部署指南](./docs/deployment.md) | docker-compose 生产部署、运维 |

## 概览

```
gm/                          # 工作空间
├── gm-crypto/               # 密码学原语（SM2/SM3/SM4）
├── gm-tls/                  # TLS 1.3 + SM 算法（TLCP 已拆分至 gm-tlcp）
├── gm-tlcp/                 # TLCP（GB/T 38636-2020）协议栈 — 独立 crate
├── gm-ca/                   # gRPC CA 服务（证书签发/吊销/查询）
├── gm-sm9-rs/               # SM9 基于身份的密码（签名/加密）
├── gm-der/                  # DER/ASN.1 编解码（共享工具）
├── gm-http-client/          # HTTPS 客户端
├── docs/                    # 详细使用文档（本目录）
└── docker/                  # Docker 部署配置
```

## Crate 概览

| Crate | 类型 | 说明 |
|-------|------|------|
| `gm-crypto` | 库 | 密码学原语（SM2/SM3/SM4），无二进制。v0.2+ |
| `gm-tls` | 库 | 仅 TLS 1.3 + SM 算法。TLCP 已拆分至独立 `gm-tlcp` crate。可选 `grpc` feature 支持 gRPC over TLS 1.3 + SM |
| `gm-tlcp` | 库 | TLCP（GB/T 38636-2020）协议 — 独立 crate，依赖 `gm-crypto >= 0.2` |
| `gm-ca` | 库 + 服务 | 提供 `gm-ca-server` 二进制，gRPC 接口 |
| `gm-sm9-rs` | 库 | SM9 基于身份的签名/加密；双后端（纯 Rust + GmSSL FFI） |
| `gm-der` | 库 | 共享 DER/ASN.1 编解码工具 |
| `gm-http-client` | 库 | 基于 gm-tls 的 HTTPS 客户端 |

## 快速示例

```toml
[dependencies]
gm-crypto = "0.2"
gm-tlcp   = "0.1"
gm-sm9-rs = "0.1"
```

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer};
use gm_crypto::sm3::Sm3Hasher;
use gm_crypto::sm4::Sm4Cipher;
use gm_sm9_rs::{SignMasterKey, Signer, Verifier};
use gm_tlcp::{TlcpAcceptor, TlcpConnector, TlcpCipherSuite};

// SM2/SM3/SM4（SM2 含密钥交换）
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

// TLCP 握手（服务端示例 — 完整代码见 gm-tlcp 文档）
// let acceptor = TlcpAcceptor::new()
//     .with_dual_certs(sign_cert_der, enc_cert_der, sign_pub_65)
//     .with_cipher_suites(vec![TlcpCipherSuite::TLS_ECDHE_SM4_GCM_SM3]);
```

## 第三方组件

本项目在合适的地方封装社区实现、移植外部代码，同时包含大量原创实现：

- **SM2**（`gm-crypto/src/sm2.rs`）封装社区 crate
  [`sm2`](https://crates.io/crates/sm2)，在其之上提供更高级的
  `Sm2Signer` / `Sm2Verifier` / `Sm2Encryptor` API。
- **SM3**（`gm-crypto/src/sm3.rs`）封装 [`sm3`](https://crates.io/crates/sm3)。
- **SM4**（`gm-crypto/src/sm4.rs`）封装 [`sm4`](https://crates.io/crates/sm4)，
  **同时**新增手写的无 padding CBC 原语
  （`Sm4Cipher::encrypt_cbc_raw` / `decrypt_cbc_raw`），用于 MAC-then-Encrypt
  协议（TLCP、TLS 1.1 CBC）—— 在这些场景下协议层自行管理填充，
  标准带 PKCS#7 填充的 `encrypt_cbc` 会破坏 wire 格式。
- **X.509 SM2 公钥提取**
  （`gm-crypto/src/x509.rs::extract_sm2_pubkey_from_der`）是自研实现，
  非封装。用于绕过 GmSSL 生成的 SPKI BIT STRING 残留位非零的 quirk；
  现成的 `x509-parser` 不会去掉这些位，会导致下游 SM2 加密/验签构造器拒绝该密钥。
- **SM9**（`gm-sm9-rs`）是 [GmSSL](https://github.com/guanzhi/GmSSL)（Apache-2.0）的 Rust 移植。署名与许可详情见 [NOTICE](./NOTICE)。
- **TLCP**（`gm-tlcp`）是 GB/T 38636-2020 的从零 Rust 实现。协议层是原创工作；密码原语委托给 `gm-crypto`。

## 许可

MIT OR Apache-2.0 — 详见 [LICENSE](./LICENSE)

> 报告安全漏洞：[SECURITY.md](./SECURITY.md)
