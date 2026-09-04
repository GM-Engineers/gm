//! TLCP session keys
//!
//! Minimal subset of `gm_tls::session_ticket::SessionKeys`. Holds the
//! per-direction SM4 key + 12-byte base nonce used by the TLCP record layer.
//! This is duplicated from gm-tls (rather than depending on it) per ADR-001
//! to keep gm-tlcp self-contained.

use gm_crypto::sm4::SM4_GCM_NONCE_LENGTH;
use zeroize::ZeroizeOnDrop;

/// SM4 + SM3-HMAC session keys for a TLCP connection.
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
