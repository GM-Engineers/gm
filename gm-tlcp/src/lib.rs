//! # gm-tlcp
//!
//! **TLCP**（**T**ransport **L**ayer **C**ryptographic **P**rotocol，
//! GB/T 38636-2020《信息安全技术 传输层密码协议》）的纯 Rust 实现。
//!
//! TLCP 是中国国家标准化管理委员会发布的国家标准，结构上类似 TLS 1.3，但
//! 使用国密 **SM2 / SM3 / SM4** 算法族，且与 TLS 1.3（RFC 8446）**协议层不兼容**
//! （版本字节、握手流程、密码套件、双证书系统、会话恢复机制均不同）。
//!
//! 本 crate 在 Phase 1 主体 PR（[`35fa661`]）中接收了从 `gm-tls/src/tlcp.rs` 迁出的
//! 4501 行实现代码，目前**已经可以独立使用**：握手状态机、4 套密码套件、双证书
//! （sign + enc）支持、记录层、Stream 封装、Connector/Acceptor 全部到位。
//!
//! [`35fa661`]: https://github.com/GM-Engineers/gm/commit/35fa661
//!
//! # ⚠️ 与 TLS 1.3（gm-tls）的关键差异
//!
//! | 维度 Dimension | TLS 1.3 (RFC 8446) | TLCP (GB/T 38636-2020) |
//! |---------------|---------------------|--------------------------|
//! | **版本字节** | `0x03, 0x03` | `0x01, 0x01` |
//! | **证书系统** | 单证书 | **双证书**（sign 签名证书 + enc 加密证书）|
//! | **密钥交换** | `key_share` 扩展（TLS 1.3 风） | `ServerKeyExchange` / `ClientKeyExchange`（TLS 1.2 风） |
//! | **会话恢复** | session ticket（RFC 5077） | session_id（TLS 1.2 风） |
//! | **密码套件 ID** | `0x13xx` | `0xE0xx`（IANA 私有空间） |
//! | **PRF** | HKDF（RFC 5869） | SM3 迭代式（TLS 1.2 PRF 风） |
//! | **0-RTT / Early Data** | 支持 | **不支持** |
//! | **PSK** | 支持 | **不支持** |
//! | **KeyUpdate** | 支持 | **不支持** |
//! | **监管口径** | IETF RFC | 中国国家标准 |
//!
//! # 快速上手（Quick Start）
//!
//! ## 服务端 Server
//!
//! ```no_run
//! use gm_tlcp::TlcpAcceptor;
//! use std::error::Error;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     // 1. 加载双证书（DER 编码的 X.509）
//!     let sign_cert = std::fs::read("server-sign.crt")?;
//!     let enc_cert  = std::fs::read("server-enc.crt")?;
//!
//!     // 2. 加载双私钥（PEM 格式 SM2 私钥）
//!     let sign_pem = std::fs::read_to_string("server-sign.key.pem")?;
//!     let enc_pem  = std::fs::read_to_string("server-enc.key.pem")?;
//!     let sign_key = gm_crypto::sm2::Sm2KeyPair::from_private_key_pem(&sign_pem)?;
//!     let enc_key  = gm_crypto::sm2::Sm2KeyPair::from_private_key_pem(&enc_pem)?;
//!
//!     // 3. 构造 Acceptor 并配置双证书
//!     let acceptor = TlcpAcceptor::new()
//!         .with_dual_certs(sign_cert, enc_cert, sign_key, enc_key);
//!
//!     // 4. 监听 + 接受 TLCP 客户端连接
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
//!     loop {
//!         let (tcp, _peer) = listener.accept().await?;
//!         let acceptor = acceptor.clone();
//!         tokio::spawn(async move {
//!             let mut tls = acceptor.accept_with_certs(tcp).await?;
//!             let req = tls.read_application_data().await?;
//!             tls.write_application_data(&req).await?;  // echo
//!             Ok::<_, gm_tlcp::TlcpError>(())
//!         });
//!     }
//! }
//! ```
//!
//! ## 客户端 Client
//!
//! ```no_run
//! use gm_tlcp::TlcpConnector;
//! use std::error::Error;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     // 1. 构造 Connector（可选：配置期望的服务端 sign 公钥用于验证 ServerKeyExchange）
//!     let connector = TlcpConnector::new();
//!
//!     // 2. TCP 连接 → TLCP 握手
//!     let tcp = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
//!     let mut tls = connector.connect_with_certs(tcp).await?;
//!
//!     // 3. 收发应用数据
//!     tls.write_application_data(b"GET / HTTP/1.1\r\n\r\n").await?;
//!     let resp = tls.read_application_data().await?;
//!     println!("Response: {} bytes", resp.len());
//!     Ok(())
//! }
//! ```
//!
//! 完整可运行示例：[`examples/simple_server.rs`](https://github.com/GM-Engineers/gm/blob/main/gm/gm-tlcp/examples/simple_server.rs)、
//! [`examples/simple_client.rs`](https://github.com/GM-Engineers/gm/blob/main/gm/gm-tlcp/examples/simple_client.rs)。
//!
//! # 模块结构 Module Structure
//!
//! ```text
//! gm_tlcp
//! ├── lib.rs               // 本文件：crate 级文档 + 公开 API re-export
//! ├── error.rs             // TlcpError / TlsError 别名
//! ├── metrics.rs           // Prometheus 计数器（仅 record_bytes）
//! ├── record.rs            // GCM nonce 派生（next_nonce）
//! ├── session_keys.rs      // SessionKeys（双向 SM4 密钥 + GCM base nonce）
//! └── tlcp.rs              // 协议实现（4501 行）：握手消息、状态机、Stream、Connector、Acceptor
//! ```
//!
//! 按职责拆分策略见 [ADR-001 §3.5](https://github.com/GM-Engineers/gm-kms/blob/main/discuss/10-adr-gm-tlcp-split.md) 与
//! [讨论稿 §10](https://github.com/GM-Engineers/gm-kms/blob/main/discuss/00-tlcp-implementation-status.md)。
//!
//! # API 入口点 API Entry Points
//!
//! | 用户场景 User scenario | 推荐 API Recommended API |
//! |----------------------|-------------------------|
//! | **作为 TLCP 服务端** | [`TlcpAcceptor::new`] + [`TlcpAcceptor::with_dual_certs`] + [`TlcpAcceptor::accept_with_certs`] |
//! | **作为 TLCP 客户端** | [`TlcpConnector::new`] + [`TlcpConnector::connect_with_certs`] |
//! | **低层握手消息构造/解析** | [`tlcp::TlcpClientHello`] / [`tlcp::TlcpServerHello`] / [`tlcp::TlcpServerKeyExchange`] 等 |
//! | **会话恢复 Session resumption** | [`tlcp::TlcpSessionCache`] + [`tlcp::TlcpResumedSession`] |
//!   (**注意**：`TlcpConnector::connect_with_certs` 与 `TlcpAcceptor::accept_with_certs` 当前走的是完整 ECDHE 握手机制；resume API 保留供上层使用，但 `is_resumed` 标志不会被自动生效。未来 PR 将补上 resume 生产路径。) |
//! | **错误处理 Error handling** | [`TlcpError`]（所有错误的统一入口） |
//! | **指标采集 Metrics** | [`metrics::record_bytes`] |
//!
//! # 设计目标 Design Goals
//!
//! - **纯 Rust**：无系统库依赖（不依赖 OpenSSL / GmSSL C 库）
//! - **国密合规**：严格遵循 GB/T 38636-2020 各章节定义
//! - **可审计**：清晰模块边界 + 关键路径 KAT（Known Answer Tests）向量
//! - **零拷贝友好**：Stream 实现基于 tokio 的 [`AsyncRead`](tokio::io::AsyncRead) / [`AsyncWrite`](tokio::io::AsyncWrite) trait，
//!   可直接包装任意 I/O（TCP / TLS-in-TLS / in-memory / 仿真 transport）
//!
//! # 与 gm-tls 的关系 Relationship with gm-tls
//!
//! `gm-tlcp` **不**依赖 `gm-tls`；`gm-tls` 依赖 `gm-tlcp`（通过 `path = "../gm-tlcp"`）。
//! 旧路径 `gm_tls::tlcp::*` 在 `gm-tls` 0.2.0+ 标记为 `#[deprecated]`，仍可继续使用
//! 但带迁移警告。新代码请直接 `use gm_tlcp::...`。
//!
//! 详细迁移指南见 [`gm-kms 评审包`](https://github.com/GM-Engineers/gm-kms/blob/main/discuss/20-review-package.md) 与 Phase 2 计划（gm-tls 1.0）。
//!
//! # 许可证 License
//!
//! MIT OR Apache-2.0

// Suppress `rustdoc::redundant_explicit_links` crate-wide: rustdoc 1.85+ emits
// this lint without source location for re-exports at the crate root, so we
// cannot locate and fix each occurrence individually. Each explicit link is
// required for the rustdoc link resolver to find the target when the link text
// is used inside a `pub mod xxx;` doc comment (where the symbol is not yet
// in scope at the doc-resolution pass). Removing the explicit URLs causes
// `unresolved link` warnings instead.
// TODO: revisit when rustdoc source-location reporting for this lint is fixed.
#![allow(rustdoc::redundant_explicit_links)]

// =============================================================================
// Module declarations
// =============================================================================

/// TLCP 错误类型（TLCP error types）。
///
/// `TlcpError` 是本 crate 所有错误的统一入口；`TlsError` 是历史别名
/// （仅用于与 `gm_tls::TlsError` 的源代码级兼容，新代码请使用 `TlcpError`）。
pub mod error;

/// TLCP 指标模块（Prometheus-compatible）。
///
/// 目前仅暴露 [`record_bytes`](crate::metrics::record_bytes)；未来按需扩展。
pub mod metrics;

/// TLCP 记录层辅助（GCM nonce 派生）。
///
/// 当前仅包含 [`next_nonce`]；加密/解密/分帧等完整记录层逻辑
/// 保留在 [`tlcp`] 模块内部，以保证协议自包含性。
pub mod record;

/// TLCP 会话密钥（双向 SM4 key + GCM base nonce）。
///
/// 用于记录层加密/解密的密钥材料；通过 [SessionKeys](crate::session_keys::SessionKeys) 的
/// [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop) 自动在 drop 时清零，避免密钥泄露。
pub mod session_keys;

/// TLCP 协议实现（4501 行）。
///
/// 包含完整的握手消息类型、状态机、Stream 封装、Connector/Acceptor 高层 API。
/// 详细协议概述、握手流程、与 TLS 1.3 的差异见模块级文档。
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
    MAX_TLCP_RECORD_SIZE, TLCP_VERSION_1_0, TLS_ECC_SM4_CBC_SM3, TLS_ECC_SM4_GCM_SM3,
    TLS_ECDHE_SM4_CBC_SM3, TLS_ECDHE_SM4_GCM_SM3, TlcpAcceptor, TlcpAlert, TlcpAlertDescription,
    TlcpAlertLevel, TlcpCertPair, TlcpCipherSuite, TlcpClientHello, TlcpClientKeyExchange,
    TlcpConnector, TlcpEcdheContext, TlcpFinished, TlcpHandshake, TlcpHandshakeState,
    TlcpKeyMaterial, TlcpResumeResult, TlcpResumedSession, TlcpServerHandshake, TlcpServerHello,
    TlcpServerHelloDone, TlcpServerKeyExchange, TlcpSessionCache, TlcpStream, accept_tlcp,
    accept_tlcp_with_context, connect_tlcp, connect_tlcp_with_context,
};
