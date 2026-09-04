//! TLCP 会话密钥（双向 SM4 key + GCM base nonce）。
//!
//! TLCP 握手完成后，双方各持有 4 个密钥材料：
//!
//! ```text
//! 客户端 → 服务端加密：client_key + client_nonce
//! 服务端 → 客户端加密：server_key + server_nonce
//! ```
//!
//! 每个方向都使用 SM4-GCM 加密（密钥 16 字节、nonce 12 字节）。本结构体将
//! 这 4 个材料打包成一个零化友好的单元（[`zeroize::ZeroizeOnDrop`]），用于在
//! `TlcpStream` 内部管理会话密钥的生命周期。
//!
//! # 与 `gm_tls::session_ticket::SessionKeys` 的关系
//!
//! 本结构体是 `gm_tls::session_ticket::SessionKeys` 的 TLCP 子集复制，
//! 拆分原因：避免 `gm-tlcp` 反向依赖 `gm-tls`（详见 crate 级 `lib.rs`
//! 中的 `Relationship with gm-tls` 章节）。
//!
//! # 安全性 Security
//!
//! - **零化**：`SessionKeys` 实现 [`zeroize::ZeroizeOnDrop`]，drop 时自动清零
//!   （防止内存取证泄露）
//! - **调试输出**：[`Debug`] 实现**不**打印密钥/nonce 实际值，仅打印长度
//!   和 `[redacted]` 占位符，避免日志泄露
//! - **不使用 `Display`**：无 `Display` 实现，禁止意外格式化打印
//!
//! # 示例 Example
//!
//! ```rust
//! use gm_tlcp::SessionKeys;
//!
//! // 握手后构造
//! let keys = SessionKeys {
//!     client_key: vec![0x42; 16],
//!     client_nonce: [0u8; 12],
//!     server_key: vec![0x43; 16],
//!     server_nonce: [0u8; 12],
//! };
//!
//! // Debug 不泄露实际值
//! let dbg = format!("{:?}", keys);
//! assert!(dbg.contains("[redacted]"));
//! assert!(!dbg.contains("0x42"));
//!
//! // drop 后自动零化（由 ZeroizeOnDrop derive 保证）
//! drop(keys);
//! ```
//!
//! 调试输出示例：
//!
//! ```text
//! SessionKeys { client_key_len: 16, server_key_len: 16, client_nonce: [redacted], server_nonce: [redacted] }
//! ```

use gm_crypto::sm4::SM4_GCM_NONCE_LENGTH;
use zeroize::ZeroizeOnDrop;

/// SM4-GCM 会话密钥（TLCP 连接的双向加密密钥 + nonce）。
///
/// 包含四个字段，分别对应客户端→服务端、服务端→客户端两个方向的加密材料。
///
/// # 字段说明 Field Semantics
///
/// - `client_key`：客户端→服务端方向的 SM4 密钥（16 字节）
/// - `client_nonce`：客户端→服务端方向的 GCM base nonce（12 字节）
/// - `server_key`：服务端→客户端方向的 SM4 密钥（16 字节）
/// - `server_nonce`：服务端→客户端方向的 GCM base nonce（12 字节）
///
/// # 安全特性 Security Properties
///
/// - `#[derive(ZeroizeOnDrop)]`：drop 时自动清零所有字段
/// - 自定义 `Debug` 实现：不打印密钥/nonce 实际值，仅显示密钥长度
///
/// # 示例 Example
///
/// ```rust
/// use gm_tlcp::SessionKeys;
///
/// let keys = SessionKeys {
///     client_key: vec![0xAB; 16],
///     client_nonce: [0u8; 12],
///     server_key: vec![0xCD; 16],
///     server_nonce: [1u8; 12],
/// };
///
/// assert_eq!(keys.client_key.len(), 16);
/// assert_eq!(keys.server_nonce[0], 1);
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// 16-byte SM4 key for client-to-server traffic
    pub client_key: Vec<u8>,
    /// 12-byte base nonce for client-to-server GCM
    pub client_nonce: [u8; SM4_GCM_NONCE_LENGTH],
    /// 16-byte SM4 key for server-to-client traffic
    pub server_key: Vec<u8>,
    /// 12-byte base nonce for server-to-client GCM
    pub server_nonce: [u8; SM4_GCM_NONCE_LENGTH],
}

// ZeroizeOnDrop derive handles zeroization automatically for SessionKeys.

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("client_key_len", &self.client_key.len())
            .field("server_key_len", &self.server_key.len())
            .field("client_nonce", &"[redacted]")
            .field("server_nonce", &"[redacted]")
            .finish()
    }
}
