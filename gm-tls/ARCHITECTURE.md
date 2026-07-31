# gm-tls 架构文档

## 组件结构

```
gm-tls/
├── src/
│   ├── lib.rs              # 库入口，公开 API
│   ├── gm.rs               # 核心握手和消息处理 (~550 行)
│   ├── record_layer.rs     # TLS 记录层，SM4-GCM 加密/解密
│   ├── handshake.rs        # 握手状态机和选项
│   ├── session_ticket.rs   # RFC 5077 会话票证
│   ├── session_store.rs    # 会话存储抽象 (多后端)
│   ├── cert_verify.rs      # 证书链验证 + CRL
│   ├── kdf.rs              # HKDF-SM3 密钥派生
│   ├── crypto_traits.rs    # 密码学抽象 trait
│   ├── metrics.rs          # Prometheus 指标
│   ├── error.rs            # 错误类型定义
│   └── serialization.rs    # ASN.1 DER 序列化（RFC 8446 / GB/T 38636-2020）
├── tests/                  # 测试套件
│   ├── gm_tls_tests.rs         # 单元测试 (61)
│   ├── property_tests.rs        # 属性测试 (17)
│   └── session_store_tests.rs   # 会话存储测试 (23，含 SQLite/PostgreSQL/Redis)
└── fuzz/                   # 模糊测试
    └── fuzz_targets/
        ├── tls_record_parse.rs    # TLS 记录解析
        ├── cert_parse.rs          # 证书解析
        ├── key_exchange.rs        # 密钥交换
        └── handshake_parse.rs     # 握手协议
```

## 核心模块

### gm.rs

**GmTlsStream<TcpStream>** 
- 包装任意 AsyncRead + AsyncWrite 的流
- 实现 SM4-GCM 加密/解密
- 管理读写序列号
- 实现 AsyncRead/AsyncWrite trait

**握手流程**

```
Client                                          Server
  |                                               |
  |--- ClientHello (eph_pubkey, cert) --------->|
  |<-- ServerHello (eph_pubkey, cert) ----------|
  |                                               |
  |     [ECDH 密钥交换]                           |
  |     shared = client_sk * server_pk           |
  |     derive session keys                       |
  |                                               |
  |--- ClientCertificate (if mutual auth) ------>|
  |<-- ServerCertificateRequest (if client auth) -|
  |--- ClientFinished (signature) -------------->|
  |<-- ServerFinished (signature) ---------------|
  |                                               |
  |====== 加密通道建立 ======|
```

**关键函数**

| 函数 | 说明 |
|------|------|
| `generate_sm2_ephemeral()` | 生成临时 SM2 密钥对 |
| `build_client_hello()` | 构建客户端问候 |
| `build_server_hello()` | 构建服务端问候 |
| `derive_session_keys_sm2()` | 派生会话密钥 |
| `sign_finished()` / `verify_finished()` | Finished 消息签名/验签 |
| `connect()` | 发起 TLS 连接 |
| `accept()` | 接受 TLS 连接 |

### record_layer.rs

TLS 记录层，处理加密解密：

- `GmTlsStream<S>` 实现 `AsyncRead`/`AsyncWrite`
- `Sm4Cipher` 缓存避免重复创建
- 序列号管理防止重放

### session_ticket.rs

RFC 5077 会话票证支持：

- `TicketKeySet` 支持零停机密钥轮换
- `SessionKeys` 包含 client/server key 和 nonce
- 自动清理过期票证

### session_store.rs

多后端会话存储：

- `InMemorySessionStore` - 内存存储，IndexMap 实现 FIFO；**始终 fail-closed**（操作永不失败）
- `SqliteSessionStore` - SQLite 本地持久化；默认 fail-open
- `PostgresSessionStore` - PostgreSQL 分布式存储；可配置 fail-closed/open
- `RedisSessionStore` - Redis 缓存存储；默认 fail-open

**注意**: InMemory 存储在单进程内通过 mutex 提供原子性；多实例部署应使用共享数据库存储以实现正确的重放保护。

## 密码学实现

### SM2 签名

使用 `sm2::dsa::SigningKey` 和 `VerifyingKey`：

```rust
// 签名者创建
let signing_key = SigningKey::new(distid, &secret_key);
let signature: Signature = signing_key.sign(transcript_hash);

// 验签
let verifying_key = VerifyingKey::from_sec1_bytes(distid, pubkey)?;
verifying_key.verify(transcript_hash, &signature)?;
```

### HKDF-SM3

RFC 5869 合规的密钥派生：

```rust
fn hkdf_sm3(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    // Extract: PRK = SM3(salt, ikm)
    // Expand: OKM = SM3(PRK || info || counter) 循环
}
```

### SM4-GCM

对称加密 + 认证：

```rust
// 加密: ciphertext + tag
let (ciphertext, tag) = cipher.encrypt_gcm(plaintext, nonce, aad)?;

// 解密: 先认证后解密
let plaintext = cipher.decrypt_gcm(ciphertext, nonce, aad, tag)?;
```

## 安全特性

1. **CSPRNG**: 使用 `OsRng` 生成密钥
2. **恒定时间**: 签名验签使用库实现，无时间侧信道
3. **认证加密**: GCM 模式提供加密和认证
4. **序列号管理**: 独立读写序列号，防止重放攻击
5. **长度检查**: 最小 16 字节记录，限制最大 24KB
6. **ZeroizeOnDrop**: 密钥材料自动清零

## 错误处理

使用 `thiserror` 定义错误类型：

```rust
pub enum TlsError {
    HandshakeFailed(String),
    CertificateVerificationFailed(String),
    IoError(String),
    // ...
}
```

## 性能考虑

- `Sm4Cipher` 缓存避免重复创建
- 序列号使用 `wrapping_add` 防止溢出
- 预分配缓冲区减少内存分配
- 连接池支持减少握手开销

## 扩展方向

1. **0-RTT**: 支持早期数据（需评估安全风险）
2. **异步证书验证**: 不阻塞事件循环
3. **OCSP 支持**: 证书吊销检查
