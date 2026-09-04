//! TLCP session resumption state and cache.
//!
//! Per GB/T 38636-2020 §6.4, TLCP supports session resumption via
//! session IDs. The server assigns a session ID in ServerHello and
//! caches the session state. The client includes the session ID in
//! subsequent ClientHello messages to resume.
//!
//! ## Security posture
//!
//! The `master_secret` (and the cached `client_random` /
//! `server_random`) are zeroized in `Drop` to prevent them from
//! sitting in the process heap after the cache entry is evicted. We
//! implement `Drop` manually because `Instant` / `Duration` are not
//! `Zeroize` and we cannot derive `ZeroizeOnDrop` directly.
//!
//! Note: `#[derive(Clone)]` is still present; callers who clone this
//! struct **MUST** zeroize the cloned `master_secret` themselves —
//! the `Drop` impl only fires on the original allocation.
//!
//! ## Caveats
//!
//! - The cache is in-process; a server restart loses all sessions.
//! - The cache is best-effort; a crash between `put` and the client
//!   actually using the session can leave a half-formed entry which
//!   will be evicted by TTL or capacity.

use super::TlcpKeyMaterial; // re-exported via `mod.rs`
use super::cipher_suite::TlcpCipherSuite;
use super::constants::{DEFAULT_SESSION_LIFETIME, MAX_CACHED_SESSIONS, MAX_SESSION_ID_LEN};
use crate::error::TlcpError;
use crate::session_keys::SessionKeys;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Resumed session state cached for TLCP session resumption.
///
/// Per GB/T 38636-2020 §6.4, TLCP supports session resumption via session IDs.
/// The server assigns a session ID in ServerHello and caches the session state.
/// The client includes the session ID in subsequent ClientHello messages to resume.
#[derive(Clone)]
pub struct TlcpResumedSession {
    /// Master secret from the original handshake
    pub master_secret: Vec<u8>,
    /// Cipher suite negotiated in the original handshake
    pub cipher_suite: [u8; 2],
    /// Server random from original handshake
    pub server_random: [u8; 32],
    /// Client random from original handshake
    pub client_random: [u8; 32],
    /// Whether client authentication was required
    pub require_client_auth: bool,
    /// Session creation timestamp
    pub created_at: Instant,
    /// Session lifetime
    pub lifetime: Duration,
}

impl TlcpResumedSession {
    /// Create a new session state from handshake results
    pub fn new(
        master_secret: Vec<u8>,
        cipher_suite: [u8; 2],
        server_random: [u8; 32],
        client_random: [u8; 32],
    ) -> Self {
        Self {
            master_secret,
            cipher_suite,
            server_random,
            client_random,
            require_client_auth: false,
            created_at: Instant::now(),
            lifetime: DEFAULT_SESSION_LIFETIME,
        }
    }

    /// Check if this session has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.lifetime
    }

    /// Derive session keys from this resumed session
    pub fn derive_session_keys(&self) -> Result<SessionKeys, TlcpError> {
        let suite = TlcpCipherSuite::from_id(self.cipher_suite).ok_or_else(|| {
            TlcpError::HandshakeFailed(format!("Unknown cipher suite {:02x?}", self.cipher_suite))
        })?;

        let km = TlcpKeyMaterial::derive(
            &self.master_secret,
            &self.client_random,
            &self.server_random,
            suite,
        )?;

        km.to_session_keys()
    }
}

// Security: zeroize the cached master_secret (and the cached randoms) when
// the resumed session is dropped. Without this, the master_secret sits in
// the process heap until something else overwrites the allocation — a
// classic sensitive-material leak.
//
// We implement Drop manually because `Instant` / `Duration` are not
// `Zeroize` and we cannot derive `ZeroizeOnDrop` directly.
//
// Note: `#[derive(Clone)]` is still present; callers who clone this struct
// MUST zeroize the cloned master_secret themselves (the Drop impl only
// fires on the original allocation).
impl Drop for TlcpResumedSession {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.master_secret.zeroize();
        self.server_random.zeroize();
        self.client_random.zeroize();
    }
}

impl std::fmt::Debug for TlcpResumedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlcpResumedSession")
            .field("cipher_suite", &format!("{:02x?}", self.cipher_suite))
            .field("expired", &self.is_expired())
            .field("require_client_auth", &self.require_client_auth)
            .finish()
    }
}

/// In-memory TLCP session cache for session resumption.
///
/// Thread-safe via `Arc<Mutex<>>`. Supports automatic eviction of expired
/// sessions and FIFO eviction when capacity is reached.
#[derive(Clone, Debug)]
pub struct TlcpSessionCache {
    inner: Arc<Mutex<TlcpSessionCacheInner>>,
}

#[derive(Debug)]
struct TlcpSessionCacheInner {
    sessions: HashMap<Vec<u8>, TlcpResumedSession>,
    /// Insertion order for FIFO eviction
    insertion_order: Vec<Vec<u8>>,
    max_entries: usize,
}

impl TlcpSessionCache {
    /// Create a new session cache with default capacity
    pub fn new() -> Self {
        Self::with_capacity(MAX_CACHED_SESSIONS)
    }

    /// Create a new session cache with the given maximum capacity
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TlcpSessionCacheInner {
                sessions: HashMap::new(),
                insertion_order: Vec::new(),
                max_entries,
            })),
        }
    }

    /// Store a session state under the given session ID
    pub async fn put(&self, session_id: Vec<u8>, session: TlcpResumedSession) {
        let mut inner = self.inner.lock().await;

        // Evict expired sessions
        inner.evict_expired();

        // If at capacity, evict oldest (FIFO)
        if inner.sessions.len() >= inner.max_entries {
            if let Some(oldest_id) = inner.insertion_order.first().cloned() {
                inner.sessions.remove(&oldest_id);
                inner.insertion_order.remove(0);
            }
        }

        // Remove old entry if session_id already exists
        if inner.sessions.contains_key(&session_id) {
            inner.insertion_order.retain(|id| id != &session_id);
        }

        inner.insertion_order.push(session_id.clone());
        inner.sessions.insert(session_id, session);
    }

    /// Retrieve a session state by session ID
    ///
    /// Returns `None` if the session ID is not found or the session has expired.
    pub async fn get(&self, session_id: &[u8]) -> Option<TlcpResumedSession> {
        let mut inner = self.inner.lock().await;

        let session = inner.sessions.get(session_id)?;
        if session.is_expired() {
            // Clean up expired session
            let id = session_id.to_vec();
            inner.sessions.remove(&id);
            inner.insertion_order.retain(|sid| sid != &id);
            return None;
        }
        Some(session.clone())
    }

    /// Remove a session from the cache
    pub async fn remove(&self, session_id: &[u8]) {
        let mut inner = self.inner.lock().await;
        inner.sessions.remove(session_id);
        inner.insertion_order.retain(|id| id != session_id);
    }

    /// Get the number of cached sessions (including potentially expired ones)
    pub async fn len(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.sessions.len()
    }

    /// Check if the cache is empty
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

impl TlcpSessionCacheInner {
    fn evict_expired(&mut self) {
        let expired_ids: Vec<Vec<u8>> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        for id in &expired_ids {
            self.sessions.remove(id);
        }
        self.insertion_order.retain(|id| !expired_ids.contains(id));
    }
}

impl Default for TlcpSessionCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a cryptographically random session ID
pub(crate) fn generate_session_id() -> Vec<u8> {
    let mut id = vec![0u8; MAX_SESSION_ID_LEN];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
    id
}

/// Result of a session resumption attempt on the server side
#[derive(Debug)]
pub enum TlcpResumeResult {
    /// Full handshake required (no session_id match or session expired)
    FullHandshake {
        /// The session_id to assign in ServerHello
        session_id: Vec<u8>,
    },
    /// Session resumed successfully (abbreviated handshake)
    Resumed {
        /// The matched session state
        session: TlcpResumedSession,
    },
}
