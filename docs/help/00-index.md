# GM 国密项目技术文档索引 / GM Cryptography Project Technical Documentation Index

> 上次更新 / Last Updated: 2026-06-29
> 文档版本 / Doc Version: 2026-05-21
> 项目路径 / Project Path: `gm`
> 阅读对象 / Target Audience: 项目维护者、核心开发者 / Project maintainers, core developers

---

## 项目架构速览 / Project Architecture Overview

```
gm/                          # Workspace root
├── gm-crypto/               # 密码原语库: SM2/SM3/SM4 / Cryptographic primitives: SM2/SM3/SM4
├── gm-tls/                  # GM/TLS 协议栈 / GM/TLS protocol stack
├── gm-ca/                   # CA 服务 (gRPC) / CA service (gRPC)
├── gm-http-client/          # HTTPS 客户端 / HTTPS client
└── gm-sm9-rs/                  # SM9 标识密码算法 / SM9 identity-based cryptography
```

## 文档列表 / Document List

| 编号 No. | 文档 Document | 内容 Content | 篇幅 Size |
|---------|--------------|-------------|----------|
| 01 | [项目架构总览 / Project Architecture Overview](01-architecture-overview.md) | 模块关系、依赖图、密钥生命周期、安全设计 / Module relationships, dependency graph, key lifecycle, security design | 中 / Medium |
| 02 | [GM 算法原语详解 / GM Algorithm Primitives](02-gm-crypto-primitives.md) | SM2/SM3/SM4 算法原理、API、安全机制 / SM2/SM3/SM4 algorithm principles, API, security mechanisms | 大 / Large |
| 03 | [gm-tls 协议实现 / gm-tls Protocol Implementation](03-gm-tls-protocol.md) | TLS 握手、记录层、密钥派生、证书验证 / TLS handshake, record layer, key derivation, certificate verification | 大 / Large |
| 05 | [gm-ca 证书服务 / gm-ca Certificate Service](05-gm-ca-service.md) | CA 服务、证书签发/吊销、gRPC API / CA service, certificate issuance/revocation, gRPC API | 中 / Medium |
| 06 | [gm-http-client](06-gm-http-client.md) | HTTPS 客户端、连接池、SSRF 防护 / HTTPS client, connection pool, SSRF protection | 小 / Small |
| 08 | [测试与 KAT / Testing and KAT](08-testing-kat.md) | 测试策略、KAT 自测试、属性测试 / Test strategy, KAT self-test, property testing | 中 / Medium |
| 09 | [构建与部署 / Build and Deployment](09-build-deployment.md) | 构建配置、Docker 部署、监控 / Build configuration, Docker deployment, monitoring | 中 / Medium |

## 快速导航 / Quick Navigation

| 角色 Role | 推荐阅读 Recommended Reading | 关键关注点 Key Focus Areas |
|----------|---------------------------|--------------------------|
| **新加入开发者 / New Contributors** | 01 → 09 → 03 | 项目架构、构建流程、TLS 握手基本流程 / Project architecture, build process, TLS handshake basics |
| **密码学实现者 / Cryptography Implementers** | 02 → 08 | SM2/SM3/SM4/SM9 算法原理、KAT 测试向量 / SM2/SM3/SM4/SM9 algorithm principles, KAT test vectors |
| **TLS 协议开发者 / TLS Protocol Developers** | 03 → 06 → 08 | 握手状态机、记录层 nonce 管理 / Handshake state machine, record layer nonce management |
| **运维/DevOps** | 09 → 05 | Docker 部署、数据库连接配置 / Docker deployment, database connection configuration |

## 关键文件路径 / Key File Paths

```
gm/
├── gm-crypto/src/
│   ├── lib.rs                    # 模块导出 / Module exports
│   ├── sm2.rs                    # SM2 签名/加密 / SM2 sign/encrypt
│   ├── sm2_kex.rs                # SM2 密钥交换 / SM2 key exchange
│   ├── sm3.rs                    # SM3 哈希 / SM3 hash
│   ├── sm4.rs                    # SM4 对称加密 / SM4 symmetric encryption
│   └── kat.rs                    # KAT 自测试 / KAT self-test
│
├── gm-tls/src/
│   ├── lib.rs                    # 公共 API / Public API
│   ├── gm.rs                     # 握手编排 / Handshake orchestration
│   ├── handshake.rs              # 握手消息 / Handshake messages
│   ├── record_layer.rs           # 记录层 / Record layer
│   └── session_store.rs          # 会话存储 / Session store
│
├── gm-sm9-rs/src/
│   ├── lib.rs                    # 库入口 / Library entry
│   ├── params.rs                 # SM9 标准曲线参数 / SM9 standard curve parameters
│   ├── z256/                     # 256位整数运算 / 256-bit integer arithmetic
│   ├── field/                    # 有限域 (Fp, Fp2, Fp4, Fp12) / Finite fields (Fp, Fp2, Fp4, Fp12)
│   ├── curve/                    # 椭圆曲线点 (G1, G2) / Elliptic curve points (G1, G2)
│   ├── pairing/                  # 双线性配对 / Bilinear pairing
│   ├── hash/                     # SM3 Hash1/Hash2
│   ├── key/                      # 密钥生成与提取 / Key generation and extraction
│   ├── sign.rs                   # 签名算法 / Signature algorithm
│   ├── encrypt.rs                # 加密算法 / Encryption algorithm
│   ├── ffi.rs                    # GmSSL FFI 绑定 / GmSSL FFI bindings
│   └── gmssl_backend.rs          # GmSSL 后端 / GmSSL backend
│
├── gm-ca/src/
│   └── ...
│
└── gm-http-client/src/
    └── ...
```

## 术语表 / Glossary

| 术语 Chinese Term | 英文 English | 说明 Description |
|-----------------|-------------|-----------------|
| GM/T | GuoMi/Tongyong | 中国国家密码管理局标准 / China National Cryptography Administration Standard |
| TLCP | Transport Layer Cryptography Protocol | 传输层密码协议 / Transport layer cryptography protocol |
| IBC | Identity-Based Cryptography | 基于身份的密码学 / Identity-based cryptography |
| KGC | Key Generation Center | 密钥生成中心 / Key generation center |
| KAT | Known Answer Test | 已知答案测试 / Known answer test |
| KDF | Key Derivation Function | 密钥派生函数 / Key derivation function |
| AEAD | Authenticated Encryption with Associated Data | 认证加密 / Authenticated encryption |
| mTLS | Mutual TLS | 双向 TLS / Mutual TLS |

---

## 更新记录 / Changelog

| 日期 Date | 版本 Version | 变更 Changes |
|----------|-------------|-------------|
| 2026-06-29 | 1.3 | ✅ 已双语化 / Bilingual completed |
| 2026-05-24 | 1.2 | 更新密码学实现者导航包含 SM9 / Updated cryptography navigator to include SM9 |
| 2026-05-21 | 1.1 | 删除过时文档 (01, 02, 04, 07)，更新 gm-sm9-rs 文件结构 / Removed obsolete docs (01, 02, 04, 07), updated gm-sm9-rs file structure |
| 2026-05-02 | 1.0 | 初始版本 / Initial version |
