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
//! PR-4.21 / PR-4.18 follow-up: 引入了四个 typed variants
//! （`CipherError`、`HandshakeMessageParse`、`Sm2KeyError`、
//! `CertificateVerificationFailed`）和 [`TlcpErrorCode`] 枚举 + [`TlcpError::code`]
//! 方法，把 ~30 处 `HandshakeFailed(format!("..."))` 调用点按失败类型拆分，
//! 让监控告警可按 `code()` 维度切片。
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

/// 结构化错误码（programmatic error handling 和 metrics labels）。
///
/// PR-4.21 与 `gm-tls::ErrorCode` 形状同款（独立定义，不共用，因为
/// `gm-tlcp` 零依赖 `gm-tls`）。使用 [`TlcpError::code`] 取出。
///
/// 用途：
/// - **metrics labels**：`metrics::counter!("tlcp_handshake_failed_total", "code" => code)`
/// - **告警阈值**：operator 可以针对 `Cipher` 失败率单独告警（部署
///   异常指标），不会污染 `HandshakeMessageParse` 的告警（协议层异常）
/// - **错误分类日志**：替代旧的 `Display` 字串 substring 匹配
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlcpErrorCode {
    /// 握手协议错误（保留 fallback，对应 `TlcpError::HandshakeFailed`）
    HandshakeFailed,
    /// PR-4.21: 握手消息 parse / serialize 失败
    HandshakeMessageParse,
    /// PR-4.21: 密码原语失败（SM4 密钥、GCM 加解密、HMAC-SM3）
    Cipher,
    /// PR-4.21: SM2 / RSA 密钥构造、签名、PEM parse 失败
    Sm2Key,
    /// PR-4.21: 证书校验失败（hostname、SPIFFE ID）
    CertificateVerificationFailed,
    /// GCM nonce 序号溢出（连接耗尽，已达 `2^64 - 1` 条记录）
    SequenceOverflow,
    /// GCM nonce 重用检测（**灾难性安全失败**）
    NonceReuse,
    /// 非法握手消息类型
    InvalidHandshakeType,
    /// 非法消息格式
    InvalidMessage,
    /// 协议状态机非法转换
    InvalidState,
    /// ASN.1 / 消息体 parse 失败
    ParseError,
    /// TLCP record 层分帧错误
    TlsRecordError,
    /// 底层 I/O 错误
    IoError,
}

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
    /// 握手协议错误（保留 fallback，协议状态机兜底）
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// PR-4.21: 密码原语失败（SM4 密钥派生、GCM 加解密、HMAC-SM3 等）。
    ///
    /// 区分于 [`TlcpError::HandshakeFailed`]，metrics 可对「密码原语
    /// 异常率」单独告警；通常表征 CPU 侧或硬件加速器异常。
    #[error("GM cipher error: {0}")]
    CipherError(String),

    /// PR-4.21: 握手消息 parse / serialize 失败
    /// （ClientHello、ServerHello、Certificate、CertificateVerify、
    /// ServerKeyExchange、ServerHelloDone 等的 read/write 失败）。
    #[error("handshake message parse failed: {0}")]
    HandshakeMessageParse(String),

    /// PR-4.21: SM2 / RSA 密钥构造、签名、PEM parse 失败
    /// （ECDHE 临时密钥生成、SKE 签名 / 验签、RSA PKCS#8 PEM 解析、
    /// RSA 密钥生成）。
    ///
    /// 区分于 [`TlcpError::CipherError`]，因为密钥错误通常是**配置期**
    /// （PEM 损坏）而非**运行时**（线格式异常）。
    #[error("SM2/RSA key error: {0}")]
    Sm2KeyError(String),

    /// PR-4.21: 证书验证失败（DNS hostname 检查、SPIFFE ID 检查）。
    ///
    /// 注意：当前 gm-tlcp 实现将 hostname 与 SPIFFE ID 检查都归入
    /// 本变体。如未来区分「信任锚链校验失败」vs「应用层身份校验失败」，
    /// 应引入新的 TlcpErrorCode 变体（例如 CertificateChainFailed）。
    #[error("certificate verification failed: {0}")]
    CertificateVerificationFailed(String),

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
    ///
    /// **保留变体**：当前 gm-tlcp 实现主要使用 [`TlcpError::HandshakeFailed`] / [`TlcpError::InvalidMessage`]
    /// 上报 ASN.1 与消息体解析错误（这些错误现阶段无需细分「ASN.1 解析」vs「字段语义」）。
    /// 本变体保留以便未来拆分手 `tlcp::messages::*::from_bytes()` 中的 `nom` / `der`
    /// 错误时使用；下游 `match` 应以 `_` 通配兜底（[`TlcpError`] 是 `#[non_exhaustive]`），
    /// 未来 0.2.0 可能在追加错误细分后开始构造本变体。
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

impl TlcpError {
    /// 返回结构化错误码。
    ///
    /// 用于 metrics labels 和程序化错误分类。
    /// 该方法保证对当前 enum 的所有 variants 穷尽。
    /// PR-4.21: 用于替代旧的 `Display` 字串 substring 匹配模式
    /// （参见 PR-4.18 §6 / gm-tls 的对应演进）。
    ///
    /// # 示例
    ///
    /// ```rust
    /// use gm_tlcp::{TlcpError, TlcpErrorCode};
    ///
    /// let e = TlcpError::CipherError("SM4 key error: invalid key length".into());
    /// assert_eq!(e.code(), TlcpErrorCode::Cipher);
    ///
    /// let e = TlcpError::HandshakeMessageParse("read ServerHello: EOF".into());
    /// assert_eq!(e.code(), TlcpErrorCode::HandshakeMessageParse);
    /// ```
    pub fn code(&self) -> TlcpErrorCode {
        match self {
            TlcpError::HandshakeFailed(_) => TlcpErrorCode::HandshakeFailed,
            TlcpError::CipherError(_) => TlcpErrorCode::Cipher,
            TlcpError::HandshakeMessageParse(_) => TlcpErrorCode::HandshakeMessageParse,
            TlcpError::Sm2KeyError(_) => TlcpErrorCode::Sm2Key,
            TlcpError::CertificateVerificationFailed(_) => {
                TlcpErrorCode::CertificateVerificationFailed
            }
            TlcpError::IoError(_) => TlcpErrorCode::IoError,
            TlcpError::SequenceOverflow => TlcpErrorCode::SequenceOverflow,
            TlcpError::TlsRecordError(_) => TlcpErrorCode::TlsRecordError,
            TlcpError::ParseError(_) => TlcpErrorCode::ParseError,
            TlcpError::NonceReuse => TlcpErrorCode::NonceReuse,
            TlcpError::InvalidHandshakeType(_) => TlcpErrorCode::InvalidHandshakeType,
            TlcpError::InvalidMessage(_) => TlcpErrorCode::InvalidMessage,
            TlcpError::InvalidState(_) => TlcpErrorCode::InvalidState,
        }
    }
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

// ---------------------------------------------------------------------------
// PR-4.21: 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pr421_error_code_tests {
    use super::*;

    /// 验证 code() 对每个变体返回期望的 TlcpErrorCode。
    /// 这是穷尽测试 —— match 漏掉一个变体会编译失败。
    #[test]
    fn code_returns_expected_for_each_variant() {
        assert_eq!(
            TlcpError::HandshakeFailed("x".into()).code(),
            TlcpErrorCode::HandshakeFailed
        );
        assert_eq!(
            TlcpError::CipherError("x".into()).code(),
            TlcpErrorCode::Cipher
        );
        assert_eq!(
            TlcpError::HandshakeMessageParse("x".into()).code(),
            TlcpErrorCode::HandshakeMessageParse
        );
        assert_eq!(
            TlcpError::Sm2KeyError("x".into()).code(),
            TlcpErrorCode::Sm2Key
        );
        assert_eq!(
            TlcpError::CertificateVerificationFailed("x".into()).code(),
            TlcpErrorCode::CertificateVerificationFailed
        );
        assert_eq!(
            TlcpError::IoError("x".into()).code(),
            TlcpErrorCode::IoError
        );
        assert_eq!(
            TlcpError::SequenceOverflow.code(),
            TlcpErrorCode::SequenceOverflow
        );
        assert_eq!(
            TlcpError::TlsRecordError("x".into()).code(),
            TlcpErrorCode::TlsRecordError
        );
        assert_eq!(
            TlcpError::ParseError("x".into()).code(),
            TlcpErrorCode::ParseError
        );
        assert_eq!(TlcpError::NonceReuse.code(), TlcpErrorCode::NonceReuse);
        assert_eq!(
            TlcpError::InvalidHandshakeType(0xab).code(),
            TlcpErrorCode::InvalidHandshakeType
        );
        assert_eq!(
            TlcpError::InvalidMessage("x".into()).code(),
            TlcpErrorCode::InvalidMessage
        );
        assert_eq!(
            TlcpError::InvalidState("x".into()).code(),
            TlcpErrorCode::InvalidState
        );
    }

    /// PR-4.18-style 保证：code() 是总函数（total function），
    /// 对所有变体有定义。match 漏掉一个变体将导致编译失败。
    #[test]
    fn code_is_total_for_all_variants() {
        let all = vec![
            TlcpError::HandshakeFailed("a".into()),
            TlcpError::CipherError("b".into()),
            TlcpError::HandshakeMessageParse("c".into()),
            TlcpError::Sm2KeyError("d".into()),
            TlcpError::CertificateVerificationFailed("e".into()),
            TlcpError::IoError("f".into()),
            TlcpError::SequenceOverflow,
            TlcpError::TlsRecordError("g".into()),
            TlcpError::ParseError("h".into()),
            TlcpError::NonceReuse,
            TlcpError::InvalidHandshakeType(0),
            TlcpError::InvalidMessage("i".into()),
            TlcpError::InvalidState("j".into()),
        ];
        // 期望所有 variants 都返回不同的 code（按设计）
        let mut codes: Vec<TlcpErrorCode> = all.iter().map(|e| e.code()).collect();
        codes.sort_by_key(|c| format!("{c:?}"));
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "TlcpErrorCode codes must be unique across variants"
        );
    }

    /// PR-4.18-style 保证：PR-4.21 新增的 4 个变体的 Display 字符串互不相同。
    /// 避免两个变体映射到完全相同的 Display 串（会破坏日志解析）。
    #[test]
    fn pr421_variants_have_distinct_display() {
        let disps = [
            TlcpError::CipherError("foo".to_string()).to_string(),
            TlcpError::HandshakeMessageParse("foo".to_string()).to_string(),
            TlcpError::Sm2KeyError("foo".to_string()).to_string(),
            TlcpError::CertificateVerificationFailed("foo".to_string()).to_string(),
        ];
        let unique: std::collections::HashSet<_> = disps.iter().collect();
        assert_eq!(
            unique.len(),
            disps.len(),
            "PR-4.21 variants must have distinct Display prefixes; got duplicates: {disps:?}"
        );
    }

    /// PR-4.21 新增的 4 个变体的 Display 字符串前缀验证（防止回退错误）。
    #[test]
    fn pr421_variants_have_expected_display_prefix() {
        assert!(
            TlcpError::CipherError("foo".to_string())
                .to_string()
                .starts_with("GM cipher error:"),
            "CipherError Display prefix mismatch"
        );
        assert!(
            TlcpError::HandshakeMessageParse("foo".to_string())
                .to_string()
                .starts_with("handshake message parse failed:"),
            "HandshakeMessageParse Display prefix mismatch"
        );
        assert!(
            TlcpError::Sm2KeyError("foo".to_string())
                .to_string()
                .starts_with("SM2/RSA key error:"),
            "Sm2KeyError Display prefix mismatch"
        );
        assert!(
            TlcpError::CertificateVerificationFailed("foo".to_string())
                .to_string()
                .starts_with("certificate verification failed:"),
            "CertificateVerificationFailed Display prefix mismatch"
        );
    }

    /// 保留语义：`From<gm_crypto::CryptoError>` 仍映射到 `HandshakeFailed`。
    /// PR-4.21 没有破坏这个语义，调用方代码不需要修改。
    #[test]
    fn from_crypto_error_still_maps_to_handshake_failed() {
        // `CryptoError::Sm4Error` is the canonical public variant; use it
        // to drive the From impl.
        let crypto_err: gm_crypto::CryptoError =
            gm_crypto::CryptoError::Sm4Error("boom".to_string());
        let tlcp_err: TlcpError = crypto_err.into();
        match tlcp_err {
            TlcpError::HandshakeFailed(_) => {}
            other => panic!(
                "expected HandshakeFailed variant, got {other:?}; \
                 PR-4.21 must preserve From<CryptoError> semantics"
            ),
        }
    }

    /// 保留语义：`From<std::io::Error>` 仍映射到 `IoError`。
    #[test]
    fn from_io_error_maps_to_io_error() {
        let io_err = std::io::Error::other("boom");
        let tlcp_err: TlcpError = io_err.into();
        match tlcp_err {
            TlcpError::IoError(_) => {}
            other => panic!("expected IoError, got {other:?}"),
        }
    }

    /// PR-4.21 验证：`code()` 与 Display 解耦。
    /// 同一 code 可对应不同 Display（fallback 行为）。
    #[test]
    fn code_and_display_are_independent() {
        // 两个不同变体，code 不同（这是预期的）；但如果两个变体的 code 相同，
        // 调用方应能仅凭 code 切片而无需解析 Display。
        let a = TlcpError::HandshakeFailed("x".into());
        let b = TlcpError::HandshakeMessageParse("x".into());
        assert_ne!(a.code(), b.code());
    }

    /// 关键安全保证：`NonceReuse` 仍然有独立 code（不被 `HandshakeFailed` 吞并）。
    /// 这是 PR-4.21 的设计意图：metrics 看板对 `NonceReuse` 单独告警。
    #[test]
    fn nonce_reuse_has_distinct_code() {
        let code = TlcpError::NonceReuse.code();
        assert_ne!(code, TlcpErrorCode::HandshakeFailed);
        assert_ne!(code, TlcpErrorCode::Cipher);
        assert_eq!(code, TlcpErrorCode::NonceReuse);
    }

    /// `SequenceOverflow` 也有独立 code（连接耗尽告警）。
    #[test]
    fn sequence_overflow_has_distinct_code() {
        let code = TlcpError::SequenceOverflow.code();
        assert_ne!(code, TlcpErrorCode::HandshakeFailed);
        assert_eq!(code, TlcpErrorCode::SequenceOverflow);
    }

    /// `TlsError` 别名与 `TlcpError` 仍然完全等价。
    /// 验证 PR-4.21 没有破坏 alias 语义。
    #[test]
    fn tls_error_alias_still_works() {
        let original: TlcpError = TlcpError::CipherError("x".into());
        let aliased: TlsError = original.clone();
        let back: TlcpError = aliased;
        assert_eq!(original, back);
    }
}
