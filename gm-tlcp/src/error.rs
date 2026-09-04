//! TLCP 错误类型（TLCP error types）。
//!
//! 本模块是 `gm-tls → gm-tlcp` 拆分后独立出来的错误定义子集，仅保留 TLCP 协议
//! 实际使用的错误变体。其他变体（配置错误、会话存储错误、审计错误等）保留在
//! `gm-tls::error` 中，因为它们不专属于 TLCP 协议本身。
//!
//! 设计原则：
//!
//! - **零依赖**：本 enum 不依赖 `gm-tls`，确保 `gm-tlcp` 自包含
//! - **`#[non_exhaustive]`**：未来新增变体不会破坏下游 match 穷尽性
//! - **错误分类**：所有变体均可归入「握手错误」、「记录层错误」、「I/O 错误」三类
//!
//! 拆分理由详见 [`TlcpError`] 枚举的历史变更（搜索 git log 中的 'extract TLCP' 相关 commit），
//! 以及 crate 级 `lib.rs` 中的 `Relationship with gm-tls` 章节。
//!
//! # 示例
//!
//! ```rust
//! use gm_tlcp::TlcpError;
//!
//! fn handle_error(e: TlcpError) {
//!     match e {
//!         TlcpError::NonceReuse => {
//!             // 灾难性安全失败：必须立即关闭连接、销毁会话密钥
//!             eprintln!("FATAL: GCM nonce reuse detected, aborting connection");
//!         }
//!         TlcpError::SequenceOverflow => {
//!             // GCM nonce 序号溢出：必须拒绝新建连接
//!             eprintln!("Connection exhausted (2^64 records), closing");
//!         }
//!         TlcpError::HandshakeFailed(reason) => {
//!             eprintln!("Handshake failed: {}", reason);
//!         }
//!         _ => eprintln!("Other TLCP error: {}", e),
//!     }
//! }
//! ```
//!
//! # 与 `gm_tls::TlsError` 的关系
//!
//! `TlsError` 是历史类型别名，保留以兼容 `gm-tls` 的旧 API。新代码请使用
//! [`TlcpError`]；两者完全等价。

use thiserror::Error;

/// TLCP 错误类型。
///
/// `gm_tls::TlsError` 的 TLCP 专属子集，仅保留 TLCP 协议实现实际使用的变体。
/// 其他变体（配置、审计、会话存储等）保留在 `gm_tls::error` 模块中。
///
/// 该 enum 标记为 [`#[non_exhaustive]`](https://doc.rust-lang.org/reference/attributes/type_system.html#the-non_exhaustive-attribute)，
/// 未来新增变体不会破坏下游 `match` 的穷尽性保证。
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlcpError {
    /// 握手协议错误（协议消息序列错误、签名验证失败、版本不匹配等）
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// 底层 I/O 错误（来自 [`tokio::io`] 或 std 网络栈）
    #[error("I/O error: {0}")]
    IoError(String),

    /// GCM nonce 序号溢出（连接耗尽，已达 `2^64 - 1` 条记录）
    ///
    /// 这是**致命错误**：继续使用会触发 [`TlcpError::NonceReuse`]，必须关闭连接。
    #[error("sequence overflow: GCM nonce cannot exceed 2^64-1")]
    SequenceOverflow,

    /// TLCP record 层分帧错误（长度越界、类型非法、版本不匹配等）
    #[error("TLS record error: {0}")]
    TlsRecordError(String),

    /// 握手消息解析错误（ASN.1 解码失败、字段长度越界等）
    #[error("parse error: {0}")]
    ParseError(String),

    /// GCM nonce 重用检测（**灾难性安全失败**）
    ///
    /// 在 GCM 模式下，同一密钥 + 同一 nonce 加密两条不同明文会泄露明文 XOR
    /// 并最终恢复认证密钥。本错误一旦出现，**必须**立即：
    ///
    /// 1. 关闭当前连接
    /// 2. 销毁 [SessionKeys](crate::session_keys::SessionKeys)
    /// 3. 记录审计事件（若启用了 [`metrics`]）
    #[error("GCM nonce reuse detected: same nonce used twice with the same key")]
    NonceReuse,

    /// 非法握手消息类型（协议状态机收到的消息类型不符合预期）
    #[error("invalid handshake type: {0:#x}")]
    InvalidHandshakeType(u8),

    /// 非法消息格式（必填字段缺失、扩展长度异常等）
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// 协议状态机非法转换（例如：在 `ServerHelloDone` 之前发送 `Finished`）
    #[error("invalid state: {0}")]
    InvalidState(String),
}

impl From<std::io::Error> for TlcpError {
    fn from(e: std::io::Error) -> Self {
        TlcpError::IoError(e.to_string())
    }
}

impl From<gm_crypto::CryptoError> for TlcpError {
    fn from(e: gm_crypto::CryptoError) -> Self {
        TlcpError::HandshakeFailed(e.to_string())
    }
}

/// 向后兼容别名：原 `gm_tls::TlsError` 的 TLCP 变体。
///
/// **新代码请使用 [`TlcpError`]**；本别名仅用于迁移期间源代码级兼容，
/// 将在 Phase 2 移除。
///
/// # 示例
///
/// ```ignore
/// // 旧代码（gm-tls 0.2 之前，外部调用方代码）
/// use gm_tls::TlsError;
///
/// // 新代码（gm-tls 0.2+ / gm-tlcp 0.1+）
/// use gm_tlcp::TlcpError;  // 推荐
/// // 或：
/// use gm_tlcp::TlsError;   // 兼容期使用
/// ```
pub type TlsError = TlcpError;
