# gm 项目架构总览 / gm Project Architecture Overview

> 上次更新 / Last Updated: 2026-06-29
> 文档版本 / Doc Version: 2026-05-21
> 项目路径 / Project Path: `gm`
> 阅读对象 / Target Audience: 开发者、维护者 / Developers, maintainers

---

## 1. 项目组成 / Project Components

```
gm/                          # Workspace root
├── gm-crypto/               # 密码原语库: SM2/SM3/SM4 / Cryptographic primitives: SM2/SM3/SM4
├── gm-der/                  # DER/ASN.1 编解码（共享工具）/ DER/ASN.1 codec (shared utility)
├── gm-tls/                  # GM/TLS 协议栈 / GM/TLS protocol stack
├── gm-ca/                   # CA 服务 (gRPC) / CA service (gRPC)
├── gm-http-client/          # HTTPS 客户端 / HTTPS client
└── gm-sm9-rs/                  # SM9 标识密码算法 / SM9 identity-based cryptography
```

| 模块 Module | 职责 Responsibility | 依赖 Dependencies |
|-----------|-------------------|------------------|
| **gm-crypto** | SM2/SM3/SM4 原语实现 / SM2/SM3/SM4 primitive implementation | sm2 crate, sm3 crate, sm4 crate |
| **gm-tls** | TLS 握手、记录层、会话存储 / TLS handshake, record layer, session store | gm-crypto |
| **gm-ca** | 证书签发/吊销 gRPC 服务 / Certificate issuance/revocation gRPC service | gm-crypto, gm-tls |
| **gm-http-client** | HTTPS 客户端、连接池 / HTTPS client, connection pool | gm-tls |
| **gm-sm9-rs** | SM9 配对签名/加密 / SM9 pairing sign/encrypt | sm3 crate (独立 / independent) |

---

## 2. 模块依赖关系 / Module Dependencies

```
                    ┌─────────────┐
                    │  gm-crypto  │  ← 底层依赖，无上游 / Base layer, no upstream
                    │ SM2/SM3/SM4 │
                    └──────┬──────┘
                           │
               ┌───────────┴───────────┐
               │                       │
               ▼                       ▼
        ┌─────────────┐          ┌─────────────┐
        │   gm-tls    │          │    gm-ca    │
        │  TLS 协议栈 │◄─────────┤  CA 服务   │
        └──────┬──────┘          └─────────────┘
               │
               ▼
        ┌─────────────┐   ┌─────────────┐
        │gm-http-client│   │   gm-sm9-rs    │
        │ HTTPS 客户端│   │IBC 配对密码│  ← 独立，无 gm-crypto 依赖 / Independent, no gm-crypto dependency
        └─────────────┘   └─────────────┘
```

---

## 3. 核心模块详解 / Core Module Details

### 3.1 gm-crypto —— 密码原语库 / Cryptographic Primitives Library

**模块结构 / Module Structure:**

```
gm-crypto/src/
├── lib.rs           # 统一导出接口 / Unified export interface
├── error.rs         # CryptoError 错误类型 / Error types
├── sm2.rs           # SM2 签名/验签/加密/解密 / SM2 sign/verify/encrypt/decrypt
├── sm2_kex.rs       # SM2 密钥交换协议 (KEX) / SM2 key exchange protocol
├── sm3.rs           # SM3 哈希 + HMAC
├── sm4.rs           # SM4 对称加密 (ECB/CBC/GCM)
├── utils.rs         # 工具函数 (hex/base64) / Utility functions
├── x509.rs          # X.509 证书解析 / Certificate parsing
└── kat.rs           # KAT 自测试 / KAT self-test
```

**设计原则 / Design Principles:**

| 原则 Principle | 说明 Description |
|--------------|-----------------|
| 密钥内存保护 / Key memory protection | 密钥类型实现 `ZeroizeOnDrop`，确保内存释放时清零 / Key types implement `ZeroizeOnDrop`, ensuring memory zeroing on drop |
| 密钥不复制 / No key cloning | 密钥类型不实现 `Clone`，防止意外复制 / Key types don't implement `Clone`, preventing accidental copies |
| 时序攻击防护 / Timing attack protection | 椭圆曲线操作使用 `subtle` 常数时间比较 / Elliptic curve operations use `subtle` constant-time comparison |
| HMAC 安全比较 / HMAC secure comparison | HMAC 计算使用 `ConstantTimeEq` 比较结果 / HMAC computation uses `ConstantTimeEq` for result comparison |

**关键类型 / Key Types:**

| 类型 Type | 用途 Usage | 安全特性 Security Features |
|----------|----------|-------------------------|
| `Sm2KeyPair` | SM2 密钥对 / SM2 key pair | `ZeroizeOnDrop`，无 `Clone` / `ZeroizeOnDrop`, no `Clone` |
| `Sm2Signer/Sm2Verifier` | SM2 签名/验签 / SM2 sign/verify | - |
| `Sm4Cipher` | SM4 加密器 / SM4 cipher | `ZeroizeOnDrop` 保护密钥 / `ZeroizeOnDrop` protects key |
| `Sm3Hasher/Sm3Hmac` | SM3 哈希/HMAC | - |

---

### 3.2 gm-tls —— GM/TLS 协议栈 / GM/TLS Protocol Stack

**模块结构 / Module Structure:**

```
gm-tls/src/
├── lib.rs           # 公共 API: TlsConfig, TlsConnector, TlsAcceptor / Public API
├── gm.rs            # 握手编排: connect/accept 状态机 / Handshake orchestration
├── handshake.rs     # 握手消息 / Handshake messages
├── record_layer.rs  # 记录层: SM4-GCM 加密/解密流 / Record layer
├── cert_verify.rs   # 证书验证: 链验证、CRL、OCSP / Certificate verification
├── session_store.rs # 会话存储: 内存/数据库/Redis / Session store
├── session_ticket.rs# 会话票证: RFC 5077 / Session tickets
├── kdf.rs           # 密钥派生: HKDF-SM3 / Key derivation
├── crypto_traits.rs # 加密特征定义 / Cryptographic trait definitions
├── der.rs           # DER 编解码 / DER encoding/decoding
├── grpc.rs          # gRPC 传输层 / gRPC transport
├── serialization.rs # 序列化工具 / Serialization utilities
├── audit.rs         # 审计日志 / Audit logging
├── metrics.rs       # Prometheus 指标 / Metrics
└── error.rs         # 错误类型 / Error types
```

**协议标准 / Protocol Standards:**

| 标准 Standard | 说明 Description |
|-------------|-----------------|
| GB/T 38636-2020 | TLCP 传输层密码协议 / TLCP transport layer cryptography protocol |
| RFC 8446 | TLS 1.3 协议 / TLS 1.3 protocol |

**核心流程 / Core Flow:**

```
TCP 连接 / TCP connection
    │
    ▼
┌─────────────┐
│ Handshake   │ ← SM2 密钥交换 + 签名 / SM2 key exchange + signing
│ 握手阶段    │
└──────┬──────┘
       │ 完成时派生会话密钥 (HKDF-SM3) / Derive session keys on completion (HKDF-SM3)
       ▼
┌─────────────┐
│ Record Layer│ ← SM4-GCM AEAD 加密 / SM4-GCM AEAD encryption
│ 记录层      │
└──────┬──────┘
       │
       ▼
 Application Data (加密传输 / Encrypted transmission)
```

---

### 3.3 gm-ca —— CA 证书服务 / CA Certificate Service

**模块结构 / Module Structure:**

```
gm-ca/src/
├── main.rs          # 入口: gRPC 服务器启动 / Entry: gRPC server startup
├── lib.rs           # 库导出 / Library exports
├── auth.rs          # 认证 / Authentication
├── cert.rs          # 证书管理 / Certificate management
├── db.rs            # 数据库 (PostgreSQL/SQLite) / Database
├── error.rs         # 错误类型 / Error types
├── metrics.rs       # 指标 / Metrics
└── service.rs       # gRPC 服务实现 / gRPC service implementation
```

**服务类型 / Service Type:** gRPC (tonic)，proto 文件定义在 `ca/v1` / gRPC (tonic), proto files defined in `ca/v1`

---

### 3.4 gm-http-client —— HTTPS 客户端 / HTTPS Client

**模块结构 / Module Structure:**

```
gm-http-client/src/
├── client.rs       # HTTP 客户端 / HTTP client
├── error.rs        # 错误类型 / Error types
└── pool.rs         # 连接池 / Connection pool
```

**特性 / Features:**

| 特性 Feature | 说明 Description |
|------------|-----------------|
| GM/TLS 支持 / GM/TLS support | 基于 `gm-tls` 的 GM/TLS 支持 / GM/TLS support based on `gm-tls` |
| 连接池管理 / Connection pool management | 连接池管理 / Connection pool management |
| SSRF 防护 / SSRF protection | SSRF 防护 / SSRF protection |

---

### 3.5 gm-sm9-rs —— SM9 标识密码 / SM9 Identity-Based Cryptography

**模块结构 / Module Structure:**

```
gm-sm9-rs/src/
├── lib.rs           # 库入口 / Library entry
├── params.rs        # GM/T 0044-2016 曲线参数 / Curve parameters
├── z256/             # 256位整数运算 / 256-bit integer arithmetic
├── field/            # 有限域 (Fp, Fp2, Fp4, Fp12) / Finite fields
├── curve/            # 椭圆曲线点 (G1, G2) / Elliptic curve points
├── pairing/          # 双线性配对 (R-ate) / Bilinear pairing
├── hash/             # SM3 Hash1/Hash2
├── key/              # 密钥生成与提取 / Key generation and extraction
├── sign.rs           # 签名算法 / Signature algorithm
├── encrypt.rs        # 加密算法 / Encryption algorithm
├── ffi.rs            # GmSSL FFI 绑定 / GmSSL FFI bindings
└── gmssl_backend.rs  # GmSSL 后端实现 / GmSSL backend implementation
```

**实现方式 / Implementation:**

| 后端 Backend | 说明 Description |
|------------|-----------------|
| **纯 Rust** (默认 / Default) | 使用标准 SM9 曲线参数和 SM3 哈希 / Uses standard SM9 curve parameters and SM3 hash |
| **GmSSL FFI** (可选 / Optional) | 调用 GmSSL 3.1.1 实现 / Calls GmSSL 3.1.1 implementation |

**两种后端交叉验证测试 / Cross-backend validation testing:**

| 测试项 Test | 说明 Description |
|-----------|-----------------|
| GmSSL 签名 → 纯 Rust 验签 / GmSSL sign → pure Rust verify | 签名兼容性验证 / Signature compatibility verification |
| 纯 Rust 签名 → GmSSL 验签 / Pure Rust sign → GmSSL verify | 签名兼容性验证 / Signature compatibility verification |
| 配对计算一致性 / Pairing computation consistency | 配对结果一致性 / Pairing result consistency |
| 密钥派生一致性 / Key derivation consistency | 密钥派生结果一致性 / Key derivation consistency |

---

## 4. 密钥生命周期 / Key Lifecycle

```
┌──────────────────────────────────────────────────────────┐
│                    密钥生命周期                          │
│                    Key Lifecycle                         │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  生成 ──→ 存储 ──→ 使用 ──→ 轮换 ──→ 销毁             │
│  Gen     Store    Use    Rotate    Destroy              │
│    │        │        │        │        │                │
│    ▼        ▼        ▼        ▼        ▼                │
│  随机数   加密存储  加密运算  新密钥   安全擦除           │
│  KRNG     Keystore  Cipher   (双密钥)  Zeroize           │
│  Random   Encrypted  Encrypted  (Dual  Secure           │
│  source   storage    ops      keys)  erasure             │
│                                                          │
│  注意: 本项目主要使用 SM2 密钥进行签名与密钥交换；       │
│        SM2 公钥加密仅用于密钥封装（key encapsulation），  │
│        不直接加密业务数据                                 │
│  Note: In this project, SM2 keys are mainly used for     │
│        signing and key exchange; SM2 public-key          │
│        encryption is only used for key encapsulation,     │
│        not for encrypting application data directly       │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 5. 标准对应 / Standard Mapping

| 算法 Algorithm | 标准 Standard | 实现位置 Implementation Location |
|--------------|-------------|-------------------------------|
| SM2 签名 / SM2 signature | GM/T 0006-2012 | gm-crypto/sm2.rs |
| SM2 密钥交换 / SM2 key exchange | GM/T 002-2012 | gm-crypto/sm2_kex.rs |
| SM3 哈希 / SM3 hash | GM/T 0004-2012 | gm-crypto/sm3.rs |
| SM4 对称加密 / SM4 symmetric encryption | GM/T 0002-2012 | gm-crypto/sm4.rs |
| SM9 标识密码 / SM9 identity-based crypto | GM/T 0044-2016 | gm-sm9-rs/ |
| TLCP/TLS | GB/T 38636-2020 | gm-tls/ |

---

## 6. 安全设计要点 / Security Design Highlights

| 要点 Security Aspect | 实现 Implementation |
|---------------------|-------------------|
| 密钥内存保护 / Key memory protection | `ZeroizeOnDrop` 自动清零 / Auto zero on drop |
| 时序攻击防护 / Timing attack protection | `subtle::ConstantTimeEq` 常数时间比较 / Constant-time comparison |
| 密钥不复制 / No key cloning | 类型不实现 `Clone` / Types don't implement `Clone` |
| 密钥交换认证 / Key exchange authentication | SM2 签名验证 / SM2 signature verification |
| 传输加密 / Transport encryption | SM4-GCM AEAD |
| 会话密钥派生 / Session key derivation | HKDF-SM3 |

---

## 更新记录 / Changelog

| 日期 Date | 版本 Version | 变更 Changes |
|----------|-------------|-------------|
| 2026-06-29 | 1.1 | ✅ 已双语化 / Bilingual completed |
| 2026-05-21 | 1.0 | 初始版本（重写）/ Initial version (rewrite) |
