# gm-tls 协议实现详解 / gm-tls Protocol Implementation Deep Dive

> 上次更新 / Last Updated: 2026-06-29
> 文档版本 / Doc Version: 2026-05-02
> 对应代码 / Corresponding Code: `gm-tls/src/` (~6,163 LOC)
> 阅读对象 / Target Audience: TLS 协议栈维护者 / TLS protocol stack maintainers
> 标准 / Standards: GB/T 38636-2020 (TLCP), RFC 8446 (TLS 1.3)

---

## 1. 架构概览 / Architecture Overview

`gm-tls` 实现了基于国密算法的 TLS 协议栈（GM/TLS），核心设计：

`gm-tls` implements a TLS protocol stack based on national cryptography algorithms (GM/TLS), with core design:

| 特性 Feature | 说明 Description |
|------------|-----------------|
| 分层架构 / Layered architecture | 握手层 → 记录层 → 传输层 / Handshake → Record → Transport |
| 异步设计 / Async design | 基于 `tokio::io::AsyncRead/AsyncWrite` / Based on tokio async I/O |
| 零拷贝优化 / Zero-copy optimization | 记录层直接操作底层流 / Record layer operates directly on underlying stream |
| 可插拔存储 / Pluggable storage | 支持内存/SQLite/PostgreSQL/Redis 会话存储 / Memory/SQLite/PostgreSQL/Redis session stores |

### 1.1 模块职责 / Module Responsibilities

```
gm-tls/src/
├── lib.rs           # 公共 API: TlsConfig, TlsConnector, TlsAcceptor / Public API
├── gm.rs            # 握手编排: connect/accept 状态机 / Handshake orchestration
├── handshake.rs     # 握手消息 / Handshake messages
├── record_layer.rs  # 记录层: SM4-GCM 加密/解密流 / Record layer
├── cert_verify.rs   # 证书验证: 链验证、CRL、OCSP / Certificate verification
├── session_store.rs # 会话存储 / Session store
├── session_ticket.rs# 会话票证: RFC 5077 / Session tickets
├── kdf.rs           # 密钥派生: HKDF-SM3 / Key derivation
├── crypto_traits.rs # 加密特征定义 / Cryptographic traits
├── grpc.rs          # gRPC 支持: tonic 集成 / gRPC support
├── der.rs           # DER 编解码 / DER encoding
├── serialization.rs # 序列化工具 / Serialization utilities
├── audit.rs         # 审计日志 / Audit logging
├── metrics.rs       # 可观测性: Prometheus 指标 / Metrics
└── error.rs         # 错误类型 / Error types
```

---

## 2. 公共 API 设计 / Public API Design

### 2.1 配置层 / Configuration Layer

```rust
/// TLS 配置 (不可变，构建器模式) / TLS config (immutable, builder pattern)
pub struct TlsConfig {
    cert_path: PathBuf,       // 证书路径 / Certificate path
    key_path: PathBuf,        // 私钥路径 / Private key path
    ca_path: PathBuf,         // CA 路径 / CA path
    cert_bytes: Option<Vec<u8>>,  // 内存加载 / In-memory loading
    key_bytes: Option<Vec<u8>>,
    ca_bytes: Option<Vec<u8>>,
    domain: Option<String>,   // SNI 域名验证 / SNI domain validation
    alpn: Vec<String>,        // ALPN 协议列表 / ALPN protocol list
    require_client_auth: bool,// 是否要求客户端证书 / Require client certificate
    backend: TlsBackend,      // 后端类型 / Backend type
    handshake_opts: Option<HandshakeOptions>,
}
```

**两种构造方式 / Two Construction Methods:**

```rust
// 1. 文件系统加载 (常规场景) / File system loading (normal scenarios)
let config = TlsConfig::load("cert.pem", "key.pem", "ca.pem")?
    .with_domain("example.com".to_string())
    .with_alpn(vec!["h2".to_string(), "http/1.1".to_string()])
    .with_require_client_auth(true)
    .with_handshake_options(opts);

// 2. 内存加载 (密钥管理系统/嵌入式场景) / In-memory loading (KMS/embedded)
let config = TlsConfig::from_bytes(cert_pem, key_pem, ca_pem)?
    .with_domain("example.com".to_string());
```

### 2.2 连接器/接收器 / Connector/Acceptor

```rust
// 客户端 / Client
let connector = TlsConnector::new(config)?;
let tls_stream = connector.connect(tcp_stream).await?;

// 服务端 / Server
let acceptor = TlsAcceptor::new(config)?;
let tls_stream = acceptor.accept(tcp_stream).await?;

// mTLS 获取客户端证书 / mTLS get client certificate
let (tls_stream, client_cert, ticket) = acceptor.accept_with_client_cert(tcp_stream).await?;
```

**初始化时的 KAT 自测试 / KAT Self-Test at Initialization:**

```rust
impl TlsConnector {
    pub fn new(cfg: TlsConfig) -> Result<Self, TlsError> {
        // GM/T 0028-2014 §7.2.4.1: 上电自测试 / Power-on self-test
        kat::ensure_self_test()
            .map_err(|e| TlsError::HandshakeFailed(format!("KAT self-test failed: {}", e)))?;
        // ...
    }
}
```

---

## 3. 握手协议实现 / Handshake Protocol Implementation

### 3.1 握手消息格式 / Handshake Message Format

**重大整改**: 2026-05-01 将握手消息从 ASN.1 DER 重构为**标准 TLS 1.3 二进制格式**。

**Major change**: 2026-05-01 refactored handshake messages from ASN.1 DER to **standard TLS 1.3 binary format**.

#### ClientHello 结构 (RFC 8446 §4.1.2) / ClientHello Structure

```rust
pub struct ClientHello {
    pub version: [u8; 2],              // ProtocolVersion (0x0303 = TLS 1.3, 0x0101 = TLCP)
    pub random: [u8; 32],              // Random
    pub session_id: Vec<u8>,           // opaque<0..32>
    pub cipher_suites: Vec<u16>,       // CipherSuite<2..2^16-2>
    pub compression_methods: Vec<u8>,  // CompressionMethod<1..2^8-1>
    pub extensions: Vec<ClientHelloExtension>,
    pub session_ticket: Option<SessionTicket>,
    pub eph_pubkey: Vec<u8>,           // SM2 临时公钥 / SM2 ephemeral public key (65 bytes)
    pub alpn: Vec<String>,
    pub sni: Option<String>,
}
```

**Wire 格式 / Wire Format:**

```
[version: 2B][random: 32B]
[session_id_len: 1B][session_id: variable]
[cipher_suites_len: 2B][cipher_suites: variable]
[compression_methods_len: 1B][compression_methods: variable]
[extensions_len: 2B][extensions: variable]
```

#### 扩展格式 (标准 IANA / Standard IANA) / Extension Format

| 扩展 Extension | 扩展类型值 Extension Type | 说明 Description |
|--------------|----------------------|-----------------|
| `ALPN` | 0x0010 | 应用层协议协商 / Application-Layer Protocol Negotiation |
| `SNI` | 0x0000 | 服务器名称指示 / Server Name Indication |
| `KeyShare` | 0x0033 | 密钥共享 / Key Share |
| `SessionTicket` | 0x0023 | 会话票据 / Session Ticket |
| `SupportedVersions` | 0x002B | 支持的版本 / Supported Versions |
| `SignatureAlgorithms` | 0x000D | 签名算法 / Signature Algorithms |

### 3.2 握手状态机 / Handshake State Machine

**文件 / File**: `gm-tls/src/gm.rs` (598 LOC)

#### 客户端握手流程 / Client Handshake Flow

```rust
async fn connect_gm_rust_inner<S>(...) -> Result<GmTlsStream<S>, TlsError> {
    // 1. 生成 SM2 临时密钥对 / Generate SM2 ephemeral key pair
    let (eph_sk, eph_pk) = generate_sm2_ephemeral()?;
    
    // 2. 构建 ClientHello
    let client_hello = build_client_hello(&eph_pk, domain, alpn, opts)?;
    
    // 3. 发送 ClientHello / Send ClientHello
    write_handshake_record(&mut stream, &client_hello.to_bytes()?).await?;
    
    // 4. 读取 ServerHello / Read ServerHello
    let server_hello = read_handshake_record(&mut stream).await?;
    let server_hello = ServerHello::from_bytes(&server_hello)?;
    
    // 5. 读取 Certificate / Read Certificate
    let cert_data = read_handshake_record(&mut stream).await?;
    let certs = parse_certificates(&cert_data)?;
    
    // 6. 验证证书链 / Verify certificate chain
    verify_cert_chain_sm2_chain(&certs, ca_pem, domain)?;
    
    // 7. 读取 CertificateVerify / Read CertificateVerify
    let cv_data = read_handshake_record(&mut stream).await?;
    let cv = CertificateVerify::from_bytes(&cv_data)?;
    
    // 8. 验证签名 / Verify signature
    let transcript = compute_transcript_hash(&client_hello, &server_hello)?;
    verify_finished(&transcript, &cv.signature, &server_pubkey)?;
    
    // 9. 计算共享密钥 / Compute shared secret
    let shared_secret = sm2_kex(&eph_sk, &server_hello.eph_pubkey)?;
    
    // 10. 派生会话密钥 / Derive session keys
    let secrets = derive_session_keys_sm2(&shared_secret, &transcript)?;
    
    // 11. [mTLS] 发送客户端证书 / Send client certificate
    if server_hello.require_client_auth {
        send_client_certificate(&mut stream, cert_pem).await?;
        let transcript = compute_transcript_hash_multi(&transcript, &client_cert_data)?;
        let client_cv = sign_finished(&transcript, key_pem)?;
        write_handshake_record(&mut stream, &client_cv.to_bytes()?).await?;
    }
    
    // 12. 发送 Finished / Send Finished
    let finished = sign_finished(&transcript, key_pem)?;
    write_handshake_record(&mut stream, &finished.to_bytes()?).await?;
    
    // 13. 读取 Server Finished / Read Server Finished
    let server_finished = read_handshake_record(&mut stream).await?;
    let server_finished = Finished::from_bytes(&server_finished)?;
    verify_finished(&transcript, &server_finished.verify_data, &server_pubkey)?;
    
    // 14. 创建记录层流 / Create record layer stream
    Ok(GmTlsStream::new(stream, secrets, peer_cert, alpn))
}
```

#### 服务端握手流程 / Server Handshake Flow

```rust
async fn accept_gm_rust_inner<S>(...) -> Result<GmTlsStream<S>, TlsError> {
    // 1. 读取 ClientHello / Read ClientHello
    let ch_data = read_handshake_record(&mut stream).await?;
    let client_hello = ClientHello::from_bytes(&ch_data)?;
    
    // 2. 生成 SM2 临时密钥对 / Generate SM2 ephemeral key pair
    let (eph_sk, eph_pk) = generate_sm2_ephemeral()?;
    
    // 3. 选择 ALPN / Select ALPN
    let selected_alpn = select_alpn(&client_hello.alpn, alpn)?;
    
    // 4. 构建 ServerHello / Build ServerHello
    let server_hello = build_server_hello(&eph_pk, selected_alpn, require_client_auth)?;
    
    // 5. 发送 ServerHello / Send ServerHello
    write_handshake_record(&mut stream, &server_hello.to_bytes()?).await?;
    
    // 6. 发送 Certificate / Send Certificate
    send_certificate(&mut stream, cert_pem).await?;
    
    // 7. 计算 transcript / Compute transcript
    let transcript = compute_transcript_hash(&client_hello, &server_hello)?;
    
    // 8. 发送 CertificateVerify / Send CertificateVerify
    let cv = sign_finished(&transcript, key_pem)?;
    write_handshake_record(&mut stream, &cv.to_bytes()?).await?;
    
    // 9. 计算共享密钥 / Compute shared secret
    let shared_secret = sm2_kex(&eph_sk, &client_hello.eph_pubkey)?;
    let secrets = derive_session_keys_sm2(&shared_secret, &transcript)?;
    
    // 10. [mTLS] 验证客户端证书 / Verify client certificate
    if require_client_auth {
        let client_cert = read_handshake_record(&mut stream).await?;
        let client_cv = read_handshake_record(&mut stream).await?;
        verify_client_certificate(&client_cert, &client_cv, ca_pem)?;
        let transcript = compute_transcript_hash_multi(&transcript, &client_cert)?;
    }
    
    // 11. 发送 Finished / Send Finished
    let finished = sign_finished(&transcript, key_pem)?;
    write_handshake_record(&mut stream, &finished.to_bytes()?).await?;
    
    // 12. 读取 Client Finished / Read Client Finished
    let client_finished = read_handshake_record(&mut stream).await?;
    let client_finished = Finished::from_bytes(&client_finished)?;
    verify_finished(&transcript, &client_finished.verify_data, &client_pubkey)?;
    
    // 13. 创建记录层流 / Create record layer stream
    Ok(GmTlsStream::new(stream, secrets, peer_cert, selected_alpn))
}
```

### 3.3 记录层数据流 / Record Layer Data Flow

| 阶段 Stage | 发送端 Sending Side | 接收端 Receiving Side |
|---------|------------------|-------------------|
| 1 | 明文数据 / Plaintext data | 解析记录头 / Parse record header |
| 2 | 序列号管理 / Sequence number management | 序列号验证 / Sequence number verification |
| 3 | Nonce 生成 (seq XOR base_iv) / Nonce generation | Nonce 重构 / Nonce reconstruction |
| 4 | SM4-GCM 加密 / SM4-GCM encryption | SM4-GCM 解密 / SM4-GCM decryption |
| 5 | 认证 Tag / Auth tag | Tag 验证 / Tag verification |
| 6 | 记录头 (type + version + len) / Record header | 明文输出 / Plaintext output |

### 3.4 降级防护 / Downgrade Protection

**整改新增 / New fix**: ServerHello 包含降级 sentinel：

**New fix**: ServerHello includes downgrade sentinel:

```rust
pub fn build_server_hello(...) -> Result<ServerHello, TlsError> {
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    
    // 最后 8 字节设置为降级 sentinel (RFC 8446 §4.1.3)
    // Set last 8 bytes to downgrade sentinel (RFC 8446 §4.1.3)
    random[24..32].copy_from_slice(b"DOWNGRD1"); // 或 / or "DOWNGRD2"
    
    Ok(ServerHello { random, ... })
}
```

客户端验证 / Client verification:

```rust
if server_hello.random[24..32] == b"DOWNGRD1"[..] 
    || server_hello.random[24..32] == b"DOWNGRD2"[..] {
    // 检查是否实际降级，若是则拒绝 / Check if actually downgraded, reject if so
}
```

---

## 4. 密钥派生 / Key Derivation

**文件 / File**: `gm-tls/src/kdf.rs` (131 LOC)

### 4.1 HKDF-SM3

```rust
/// 派生会话密钥 / Derive session keys
pub fn derive_session_keys_sm2(
    shared_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<SessionKeys, TlsError> {
    // HKDF-Extract: PRK = HKDF-Extract(salt=0, IKM=shared_secret)
    let prk = hkdf_extract(&[0u8; 32], shared_secret)?;
    
    // HKDF-Expand: 派生密钥材料 / Derive key material
    let okm = hkdf_expand(&prk, b"gm-tls-session-keys", 80)?; // 5 * 16 bytes
    
    Ok(SessionKeys {
        client_write_key: okm[0..16].to_vec(),
        server_write_key: okm[16..32].to_vec(),
        client_write_iv: okm[32..44].try_into().unwrap(),
        server_write_iv: okm[44..56].try_into().unwrap(),
        // ...
    })
}
```

### 4.2 密钥材料布局 / Key Material Layout

| 字段 Field | 偏移 Offset | 长度 Length | 用途 Usage |
|----------|-----------|-----------|---------|
| `client_write_key` | 0 | 16 bytes | 客户端写入密钥 / Client write key |
| `server_write_key` | 16 | 16 bytes | 服务端写入密钥 / Server write key |
| `client_write_iv` | 32 | 12 bytes | 客户端写入 IV / Client write IV |
| `server_write_iv` | 44 | 12 bytes | 服务端写入 IV / Server write IV |
| `client_finished_key` | 56 | 16 bytes | 客户端 Finished 密钥 / Client finished key |
| `server_finished_key` | 72 | 16 bytes | 服务端 Finished 密钥 / Server finished key |

---

## 5. 证书验证 / Certificate Verification

**文件 / File**: `gm-tls/src/cert_verify.rs` (804 LOC)

### 5.1 证书链验证 / Certificate Chain Verification

```rust
pub fn verify_cert_chain_sm2_chain(
    certs: &[OwnedCert],      // 证书链 (叶子 → 中间 → 根) / Certificate chain (leaf → intermediate → root)
    ca_pem: &[u8],            // 信任锚 / Trust anchor
    domain: Option<&str>,     // SNI 域名验证 / SNI domain validation
) -> Result<(), TlsError>
```

**验证步骤 / Verification Steps:**

| 步骤 Step | 说明 Description |
|---------|-----------------|
| 1 | 解析证书链 / Parse certificate chain |
| 2 | 验证每个证书的 SM2 签名 / Verify SM2 signature on each certificate |
| 3 | 验证有效期 / Verify validity period |
| 4 | 验证域名匹配（如果提供 domain）/ Verify domain match (if domain provided) |
| 5 | 检查 CRL（如果配置）/ Check CRL (if configured) |

### 5.2 CRL 检查 / CRL Checking

```rust
/// CRL 信息（DER 编码，字段私有）
/// CRL info (DER-encoded, private fields)
/// 对应代码: gm-tls/src/cert_verify.rs
/// Corresponding code: gm-tls/src/cert_verify.rs
pub struct CrlInfo {
    der: Vec<u8>,
}

impl CrlInfo {
    /// 从 PEM 格式解析 CRL / Parse CRL from PEM format
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, TlsError>;
    
    /// 从 DER 格式解析 CRL / Parse CRL from DER format
    pub fn from_der(der: &[u8]) -> Result<Self, TlsError>;
    
    /// 检查证书序列号是否被吊销 / Check if certificate serial is revoked
    pub fn is_cert_revoked(&self, serial_bytes: &[u8]) -> bool;
    
    /// 获取 CRL 签发者名称（字符串） / Get CRL issuer name (string)
    pub fn issuer_str(&self) -> Result<String, TlsError>;
    
    /// 获取 CRL 签发者名称（DER 字节，用于精确比对）/ Get issuer name in DER bytes (for exact match)
    pub fn issuer_der(&self) -> Result<Vec<u8>, TlsError>;
    
    /// 检查 CRL 是否在有效期内 / Check if CRL is within validity period
    pub fn is_valid(&self, now: OffsetDateTime) -> bool;
}

/// 验证证书未被 CRL 吊销
/// Verify certificate is not revoked in CRL
/// 返回 Ok(()) 表示未吊销；Err 表示已吊销或 CRL 无效
/// Returns Ok(()) if not revoked; Err if revoked or CRL invalid
pub fn verify_crl(
    cert_serial: &[u8],
    issuer: &x509_parser::x509::X509Name,
    ca_cert: &X509Certificate<'_>,
    crl: &CrlInfo,
    now: OffsetDateTime,
) -> Result<(), TlsError>
```

---

## 6. 会话管理 / Session Management

### 6.1 会话存储 / Session Store

**文件 / File**: `gm-tls/src/session_store.rs` (649 LOC)

支持多种后端 / Supports multiple backends:

```rust
pub enum SessionStoreConfig {
    InMemory,                           // 内存 (开发/测试 / Development/testing)
    Sqlite { path: String },            // SQLite
    Postgres { url: String },           // PostgreSQL
    Redis { url: String },              // Redis
}
```

**整改 / Fix**: 默认从 fail-open 改为 fail-closed：

**Fix**: Changed default from fail-open to fail-closed:

```rust
impl SessionStore {
    /// 默认配置: 连接失败时返回错误 (fail-closed)
    /// Default config: Return error on connection failure (fail-closed)
    pub fn default_config() -> SessionStoreConfig {
        SessionStoreConfig::InMemory
    }
}
```

### 6.2 会话票证 / Session Tickets

**文件 / File**: `gm-tls/src/session_ticket.rs` (350 LOC)

RFC 5077 实现 / RFC 5077 implementation:

```rust
pub struct SessionTicket {
    pub ticket: Vec<u8>,       // 加密票证 / Encrypted ticket
    pub lifetime_hint: u32,    // 有效期提示 (秒) / Lifetime hint (seconds)
}

pub struct TicketKeySet {
    pub current: TicketKey,    // 当前加密密钥 / Current encryption key
    pub previous: Option<TicketKey>, // 旧密钥 (轮换期) / Old key (rotation period)
}
```

**密钥轮换 / Key Rotation:**

| 参数 Parameter | 默认值 Default | 说明 Description |
|--------------|-------------|-----------------|
| 轮换周期 / Rotation period | 24 小时 / 24 hours | 默认轮换间隔 / Default rotation interval |
| 旧密钥保留 / Old key retention | 48 小时 / 48 hours | 允许会话恢复 / Allow session resumption |
| 票证加密 / Ticket encryption | AES-256-GCM | 加密算法 / Encryption algorithm |

---

## 7. 审计与可观测性 / Audit and Observability

### 7.1 审计日志 / Audit Logging

**文件 / File**: `gm-tls/src/audit.rs` (560 LOC)

| 事件类型 Event Type | 说明 Description |
|------------------|-----------------|
| `HandshakeStarted` | 握手开始 / Handshake started |
| `HandshakeCompleted` | 握手完成 / Handshake completed |
| `HandshakeFailed` | 握手失败 / Handshake failed |
| `CertificateVerified` | 证书验证通过 / Certificate verified |
| `CertificateRejected` | 证书被拒绝 / Certificate rejected |
| `SessionResumed` | 会话恢复 / Session resumed |
| `ConnectionClosed` | 连接关闭 / Connection closed |
| `AlertReceived` | 收到警报 / Alert received |

### 7.2 指标 / Metrics

**文件 / File**: `gm-tls/src/metrics.rs` (111 LOC)

| 指标 Metric | 类型 Type | 说明 Description |
|----------|---------|-----------------|
| `gm_tls_handshake_total` | Counter | TLS 握手总次数 / Total TLS handshakes |
| `gm_tls_handshake_failed` | Counter | 握手失败次数 / Failed handshakes |
| `gm_tls_handshake_duration` | Histogram | 握手耗时 / Handshake duration |
| `gm_tls_session_resumed` | Counter | 会话恢复次数 / Session resumptions |
| `gm_tls_active_connections` | Gauge | 活跃连接数 / Active connections |

---

## 8. gRPC 支持 / gRPC Support

**文件 / File**: `gm-tls/src/grpc.rs` (274 LOC)

```rust
use gm_tls::grpc::GmTlsChannel;

let channel = GmTlsChannel::new("https://example.com:443")
    .with_tls_config(tls_config)
    .connect()
    .await?;
```

---

## 9. 安全整改记录 / Security Fix Log

| 整改项 Fix Item | 状态 Status | 文件 File | 详情 Details |
|--------------|-----------|---------|-------------|
| close_notify AAD 统一 / close_notify AAD unified | ✅ | `record_layer.rs` | 三路 AAD 构造一致 / Three-way AAD construction consistent |
| TLS 降级 sentinel / TLS downgrade sentinel | ✅ | `handshake.rs` | ServerHello 填充 / ServerHello padding |
| 会话存储 fail-closed / Session store fail-closed | ✅ | `session_store.rs` | 默认安全 / Secure by default |
| SSRF 修复 / SSRF fix | ✅ | `client.rs` | TOCTOU 窗口消除 / TOCTOU window eliminated |
| 握手格式标准化 / Handshake format standardized | ✅ | `handshake.rs` | DER → TLS 1.3 二进制 / DER → TLS 1.3 binary |

---

## 10. 调试技巧 / Debug Tips

### 启用详细日志 / Enable Detailed Logging

```bash
RUST_LOG=gm_tls=debug,gm_crypto=debug cargo run
```

### 握手抓包分析 / Handshake Packet Capture Analysis

```bash
# 设置密钥日志 (类似 SSLKEYLOGFILE) / Set key log (like SSLKEYLOGFILE)
export GM_TLS_KEYLOG=keylog.txt

# 使用 Wireshark 分析 / Use Wireshark analysis
# Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
```

### 测试工具 / Test Tools

```bash
# 运行所有 TLS 测试 / Run all TLS tests
cargo test -p gm-tls

# 互操作性测试 (需要 GmSSL) / Interoperability tests (requires GmSSL)
cargo test -p gm-tls --test gmssl_interop_tests

# 属性测试 / Property tests
cargo test -p gm-tls --test property_tests
```

---

## 更新记录 / Changelog

| 日期 Date | 版本 Version | 变更 Changes |
|----------|-------------|-------------|
| 2026-06-29 | 1.1 | ✅ 已双语化 / Bilingual completed |
| 2026-05-02 | 1.0 | 初始版本 / Initial version |
