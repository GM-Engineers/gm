//! TLCP 记录层辅助（GCM nonce 派生）。
//!
//! 本模块仅包含 TLCP 记录层所需的最小辅助函数（当前为 [`next_nonce`]）。
//! 加密、解密、record 分帧等完整记录层逻辑保留在 [`crate::tlcp`] 模块内部，
//! 以保证协议自包含性、避免与 `gm-tls` 的 TLS 1.3 记录层产生耦合。
//!
//! # 与 `gm_tls::record_layer::next_nonce` 的关系
//!
//! 本模块的 [`next_nonce`] 与 `gm_tls::record_layer::next_nonce` 实现**完全一致**，
//! 都是 RFC 8446 §5.3 描述的 nonce 派生算法（将 64-bit 序号 XOR 进 12-byte
//! base nonce 的最后 8 字节）。代码复制原因：避免 `gm-tlcp` 反向依赖 `gm-tls`。
//!
//! # GCM nonce 重要安全提示
//!
//! GCM 模式在**同一密钥下重用 nonce 是灾难性的**：
//!
//! - 泄露两条明文的 XOR
//! - 可恢复认证密钥 H = AES_K(0^128)
//! - 后续伪造任意消息认证标签
//!
//! 因此 [`next_nonce`] 包含运行时检查：若计算结果等于 base nonce 且 `seq != 0`，
//! 则返回 [`TlcpError::SequenceOverflow`]，强制调用方关闭连接。
//!
//! 理论最大序号：`2^64 - 1`（u64::MAX），超过即视为连接耗尽。
//!
//! # 示例 Example
//!
//! ```rust
//! use gm_tlcp::next_nonce;
//!
//! let base_nonce = [0u8; 12]; // 实际值由握手派生
//!
//! // 第一条记录（seq=0，nonce == base）
//! let nonce_0 = next_nonce(&base_nonce, 0).unwrap();
//! assert_eq!(nonce_0, base_nonce);
//!
//! // 第二条记录（seq=1，nonce = base XOR 0x00..01）
//! let nonce_1 = next_nonce(&base_nonce, 1).unwrap();
//! assert_ne!(nonce_1, base_nonce);
//!
//! // seq = u64::MAX → SequenceOverflow
//! assert!(next_nonce(&base_nonce, u64::MAX).is_err());
//! ```

use gm_crypto::sm4::SM4_GCM_NONCE_LENGTH;

use crate::error::TlcpError;

/// 计算下一条 GCM record 的 nonce（XOR 64-bit 序号到 base nonce 的最后 8 字节）。
///
/// 与 `gm_tls::record_layer::next_nonce` 实现一致；代码在 `gm-tls → gm-tlcp`
/// 拆分时复制，以避免 `gm-tlcp` 反向依赖 `gm-tls`。
///
/// # 参数 Parameters
///
/// - `base` — 握手派生的 12-byte base nonce
/// - `seq` — 当前 record 的序号（0-indexed）
///
/// # 返回值 Returns
///
/// - `Ok([u8; 12])` — 12-byte nonce，可直接传入 SM4-GCM AEAD
/// - `Err(TlcpError::SequenceOverflow)` — 序号达到 `u64::MAX`，或 nonce
///   与 base 冲突（理论不应发生的安全护栏）
///
/// # 安全性 Security
///
/// GCM 在**同一密钥下重用 nonce 等于完全丧失机密性 + 完整性**。本函数包含
/// 运行时护栏，但**主要责任在调用方**：
///
/// - 每次调用 [`next_nonce`] 必须使用递增的 `seq`（0, 1, 2, ...）
/// - 到达 `u64::MAX` 后**必须**关闭连接、销毁密钥
/// - 任何 nonce 复用必须触发 [`TlcpError::NonceReuse`] 并立即终止连接
///
/// # 示例 Example
///
/// ```rust
/// use gm_tlcp::next_nonce;
///
/// let base = [0u8; 12];
///
/// assert_eq!(next_nonce(&base, 0).unwrap(), base);
/// assert_eq!(
///     next_nonce(&base, 1).unwrap(),
///     [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
/// );
/// assert!(next_nonce(&base, u64::MAX).is_err());
/// ```
pub fn next_nonce(
    base: &[u8; SM4_GCM_NONCE_LENGTH],
    seq: u64,
) -> Result<[u8; SM4_GCM_NONCE_LENGTH], TlcpError> {
    if seq == u64::MAX {
        return Err(TlcpError::SequenceOverflow);
    }
    let mut nonce = *base;
    let ctr_bytes = seq.to_be_bytes();
    let n = ctr_bytes.len();
    // XOR the sequence number into the last 8 bytes of the nonce (RFC 8446 §5.3)
    for i in 0..n {
        nonce[SM4_GCM_NONCE_LENGTH - n + i] ^= ctr_bytes[i];
    }
    // Runtime safety check: GCM catastrophic failure on nonce reuse.
    // Each sequence number must produce a unique nonce; zero seq is
    // safe because it XORs 0 with the base (nonce == base for first use).
    if seq != 0 && nonce == *base {
        return Err(TlcpError::SequenceOverflow);
    }
    Ok(nonce)
}
