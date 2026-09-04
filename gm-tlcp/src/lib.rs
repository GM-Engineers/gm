//! TLCP (Transport Layer Cryptographic Protocol) — GB/T 38636-2020.
//!
//! TLCP 是中国国家标准化管理委员会发布的国家标准 GB/T 38636-2020《信息安全技术
//! 传输层密码协议》定义的一种传输层密码协议。它在结构上类似 TLS 1.3，但使用
//! 国密 SM2 / SM3 / SM4 算法族，且与 TLS 1.3（RFC 8446）协议层不兼容。
//!
//! # Phase 1 主体状态：代码已迁入，本 crate 可以独立使用
//!
//! 本 crate 在 Phase 1 主体 PR 中接收了从 `gm-tls/src/tlcp.rs` 迁出的 4501 行代码，
//! 含完整握手状态机、4 套密码套件、双证书（sign + enc）支持、记录层、Stream 封装、
//! Connector/Acceptor。集成测试（1592 行）暂保留在 `gm-tls/tests/tlcp_integration_tests.rs`，
//! 待 Phase 1 收尾时同步迁移。
//!
//! 按 ADR-001，gm-tls 内的旧 TLCP 路径在 Phase 1 主体完成后标记为 `#[deprecated]`。
//! 正在按 [ADR-001](https://github.com/GM-Engineers/gm-kms/blob/main/discuss/10-adr-gm-tlcp-split.md)
//! 拆分到本 crate。本骨架不包含任何业务代码，仅声明依赖与 crate 元数据。
//!
//! ## 与 TLS 1.3 的关键差异（决定本 crate 必须独立）
//!
//! - **协议版本字节**：`[0x01, 0x01]`（TLS 1.3 用 `0x03, 0x03` + ext）
//! - **证书系统**：双证书——签名证书（sign）+ 加密证书（enc），TLS 1.3 仅单证
//! - **密钥交换消息**：使用 `ServerKeyExchange` / `ClientKeyExchange`（TLS 1.2 风），
//!   不是 TLS 1.3 的 `key_share` 扩展
//! - **会话恢复**：使用 `session_id`（TLS 1.2 风），不是 session ticket（RFC 5077）
//! - **密码套件 ID**：`0xE0xx`（IANA 私有空间），TLS 1.3 用 `0x13xx`
//! - **PRF**：SM3 迭代式（TLS 1.2 PRF 风），不是 TLS 1.3 的 HKDF
//! - **监管口径**：GB/T 38636-2020 国标，TLS 1.3 是 IETF RFC 8446
//!
//! ## 不支持的功能
//!
//! - 0-RTT / Early Data（TLCP 标准未规定）
//! - PSK 预共享密钥模式
//! - KeyUpdate（TLS 1.3 §4.6.3，TLCP 无对应消息）
//!
//! # 设计目标
//!
//! - **纯 Rust**：无系统库依赖（不依赖 OpenSSL / GmSSL C 库）
//! - **国密合规**：严格遵循 GB/T 38636-2020 各章节定义
//! - **可互操作**：与 GmSSL 3.x、华为 iMaster、Tongsuo 等 TLCP 实现互通
//! - **可审计**：清晰模块边界 + 关键路径 KAT（Known Answer Tests）向量
//!
//! # 模块规划（拆分完成后）
//!
//! ```text
//! gm_tlcp
//! ├── version            // TLCP_VERSION_1_0 = [0x01, 0x01]
//! ├── cipher_suite      // 4 套密码套件（TLS_ECDHE_SM4_GCM_SM3 等）
//! ├── config            // TlcpConfig::load / from_bytes
//! ├── connector         // TlcpConnector / TlcpAcceptor (高层 API)
//! ├── stream            // TlcpStream<S>（薄封装 GmTlsStream）
//! ├── session           // 会话恢复（session_id 机制）
//! ├── alert             // 告警协议
//! ├── handshake/
//! │   ├── mod.rs        // 状态机入口
//! │   ├── client.rs      // 客户端握手驱动
//! │   ├── server.rs      // 服务端握手驱动
//! │   ├── messages.rs    // 11 种握手消息类型
//! │   ├── transcript.rs  // 握手摘要维护
//! │   └── kdf.rs         // master_secret / key_block 派生
//! └── record            // TLCP 专属记录层（不复用 GmTlsStream，避免 KeyUpdate 耦合）
//! ```
//!
//! # 许可证
//!
//! MIT OR Apache-2.0

// =============================================================================
// Module declarations
// =============================================================================

/// TLCP error types.
pub mod error;

/// TLCP metrics module (Prometheus-compatible).
pub mod metrics;

/// TLCP record layer helpers (currently `next_nonce`).
pub mod record;

/// TLCP session keys (per-direction SM4 key + GCM nonce).
pub mod session_keys;

/// TLCP protocol implementation (4501 lines).
pub mod tlcp;

// =============================================================================
// Re-exports for crate-level convenience
// =============================================================================

pub use error::{TlcpError, TlsError};
pub use record::next_nonce;
pub use session_keys::SessionKeys;
// Re-exporting deprecated convenience functions by design (crate-level API
// compatibility during migration); suppress the self-deprecation warning.
#[allow(deprecated)]
pub use tlcp::{
    accept_tlcp, accept_tlcp_with_context, connect_tlcp, connect_tlcp_with_context,
    TlcpAcceptor, TlcpAlert, TlcpAlertDescription, TlcpAlertLevel, TlcpCertPair,
    TlcpCipherSuite, TlcpClientHello, TlcpClientKeyExchange, TlcpConnector,
    TlcpEcdheContext, TlcpFinished, TlcpHandshake, TlcpHandshakeState, TlcpKeyMaterial,
    TlcpResumeResult, TlcpResumedSession, TlcpServerHandshake, TlcpServerHello,
    TlcpServerHelloDone, TlcpServerKeyExchange, TlcpSessionCache, TlcpStream,
    TLS_ECC_SM4_CBC_SM3, TLS_ECC_SM4_GCM_SM3, TLS_ECDHE_SM4_CBC_SM3,
    TLS_ECDHE_SM4_GCM_SM3, TLCP_VERSION_1_0, MAX_TLCP_RECORD_SIZE,
};
