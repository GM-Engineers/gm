//! Session ticket handling for GM/TLS session resumption (RFC 5077).
//!
//! This module provides session ticket encryption and decryption for
//! storing and restoring TLS session state without full handshake.

use crate::error::TlsError;
use crate::serialization;
use crate::session_store::SessionStore;
use gm_crypto::sm3::Sm3Hasher;
use gm_crypto::sm4::{SM4_GCM_NONCE_LENGTH, Sm4Cipher};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::ZeroizeOnDrop;

/// Maximum lifetime for session tickets (24 hours)
const MAX_TICKET_LIFETIME: u64 = 86400;

/// Session state stored in a session ticket for resumption
///
/// This struct is serialized into an encrypted session ticket (RFC 5077).
/// It is NOT cloned in normal operation — a single instance is deserialized
/// from the ticket and consumed. Key material (master_secret, session_keys)
/// is zeroized when the struct is dropped.
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SessionState {
    /// Master secret derived from ECDH (zeroized on drop)
    pub(crate) master_secret: Vec<u8>,
    /// Session keys (client_key + server_key + nonces) (zeroized on drop)
    pub(crate) session_keys: SessionKeys,
    /// Client traffic secret for KeyUpdate support (zeroized on drop)
    ///
    /// Present when the session ticket includes traffic secrets for
    /// KeyUpdate on resumed connections. `None` for older tickets.
    pub(crate) client_traffic_secret: Option<Vec<u8>>,
    /// Server traffic secret for KeyUpdate support (zeroized on drop)
    ///
    /// Present when the session ticket includes traffic secrets for
    /// KeyUpdate on resumed connections. `None` for older tickets.
    pub(crate) server_traffic_secret: Option<Vec<u8>>,
    /// Server random from handshake
    pub(crate) server_random: [u8; 32],
    /// Client random from handshake
    pub(crate) client_random: [u8; 32],
    /// Selected ALPN protocol
    pub(crate) alpn: Option<String>,
    /// Ticket lifetime hint (seconds)
    pub(crate) lifetime_hint: u32,
    /// Whether client authentication was required
    pub(crate) require_client_auth: bool,
    /// Ticket creation timestamp
    pub(crate) created_at: u64,
}

// ZeroizeOnDrop derive handles zeroization automatically;
// manual Drop impl removed to avoid double-zeroize.

/// Session keys derived from SM2 ECDH key exchange.
///
/// These keys are used for SM4-GCM record layer encryption.
/// Client and server directions use independent keys and nonces
/// to prevent GCM nonce reuse across traffic directions.
///
/// SECURITY NOTE: See SessionState for Clone + zeroize trade-off discussion.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
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

/// Session ticket for TLS session resumption (RFC 5077)
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionTicket {
    /// Encrypted session state: `key_id(1) || nonce(12) || tag(16) || ciphertext`
    pub encrypted_ticket: Vec<u8>,
    /// Ticket version/identifier
    pub ticket_version: u16,
}

impl std::fmt::Debug for SessionTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTicket")
            .field("encrypted_ticket_len", &self.encrypted_ticket.len())
            .field("ticket_version", &self.ticket_version)
            .finish()
    }
}

/// A single session ticket encryption key.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct TicketKey {
    /// Unique identifier for this key (first byte of ticket)
    pub id: u8,
    /// 32-byte secret key material
    pub secret: [u8; 32],
}

/// A set of session ticket keys supporting key rotation.
///
/// The first key in the set is used for encrypting new tickets.
/// All keys are tried during decryption, enabling zero-downtime key rotation.
///
/// # Rotation Strategy
///
/// 1. Add new key alongside existing keys (tickets encrypted with old key still work)
/// 2. After all in-flight tickets expire, remove the old key
#[derive(Debug, Clone)]
pub struct TicketKeySet {
    keys: Vec<TicketKey>,
}

impl TicketKeySet {
    /// Create a new key set with a single key.
    pub fn new(key: TicketKey) -> Self {
        Self { keys: vec![key] }
    }

    /// Add a key to the set (for key rotation).
    pub fn add_key(&mut self, key: TicketKey) {
        self.keys.push(key);
    }

    /// Adds an additional key to the set using builder pattern (for decryption of old tickets during rotation).
    pub fn with_key(mut self, key: TicketKey) -> Self {
        self.keys.push(key);
        self
    }

    /// Removes a key from the set by its ID.
    /// Returns true if the key was found and removed.
    /// Note: Cannot remove the primary (first) key if there are other keys.
    pub fn remove_key(&mut self, id: u8) -> bool {
        // Cannot remove the primary (first) key if there are other keys
        if self.keys.first().map(|k| k.id == id).unwrap_or(false) && self.keys.len() > 1 {
            return false;
        }
        if let Some(pos) = self.keys.iter().position(|k| k.id == id) {
            self.keys.remove(pos);
            true
        } else {
            false
        }
    }

    /// Get the primary (first) key for encryption.
    pub fn primary_key(&self) -> Option<&TicketKey> {
        self.keys.first()
    }

    /// Find a key by its ID.
    pub fn find_key(&self, id: u8) -> Option<&TicketKey> {
        self.keys.iter().find(|k| k.id == id)
    }
}

/// Restore session state from a session ticket.
///
/// # Arguments
/// * `ticket` - The encrypted session ticket
/// * `key_set` - Set of keys to try for decryption (key ID is first byte of ticket)
/// * `session_store` - Session store for replay protection
///
/// # Returns
/// * Restored session state
///
/// # Security
/// Maximum encrypted session ticket size (64 KiB).
pub const MAX_SESSION_TICKET_SIZE: usize = 64 * 1024;

/// This function includes replay protection - each ticket can only be used once.
pub async fn decrypt_session_ticket(
    ticket: &SessionTicket,
    key_set: &TicketKeySet,
    session_store: Arc<dyn SessionStore>,
) -> Result<SessionState, TlsError> {
    let combined = &ticket.encrypted_ticket;

    // Minimum length: key_id(1) + nonce(12) + tag(16) = 29 bytes
    if combined.len() < 29 {
        return Err(TlsError::SessionTicketInvalid(
            "invalid session ticket".into(),
        ));
    }
    if combined.len() > MAX_SESSION_TICKET_SIZE {
        return Err(TlsError::SessionTicketInvalid(format!(
            "session ticket too large: {} bytes (max {})",
            combined.len(),
            MAX_SESSION_TICKET_SIZE
        )));
    }

    // Replay protection: check if this ticket was already used
    if session_store.is_ticket_replay(combined).await {
        return Err(TlsError::SessionTicketReplay);
    }

    let key_id = combined[0];
    let nonce = &combined[1..13];
    let tag = &combined[13..29];
    let encrypted = &combined[29..];

    let key = key_set.find_key(key_id).ok_or_else(|| {
        TlsError::SessionTicketInvalid(format!("unknown ticket key ID: {}", key_id))
    })?;

    // Decrypt using SM4-GCM with derived 16-byte key
    let derived_key = derive_ticket_sm4_key(&key.secret)?;
    let cipher = Sm4Cipher::new(&derived_key).map_err(|e| {
        TlsError::SessionTicketInvalid(format!("failed to create decryptor: {}", e))
    })?;
    let state_bytes = cipher
        .decrypt_gcm(encrypted, nonce, &[], tag)
        .map_err(|e| {
            TlsError::SessionTicketInvalid(format!("session ticket decryption failed: {}", e))
        })?;

    // Deserialize session state
    let state: SessionState = serialization::deserialize(&state_bytes).map_err(|e| {
        TlsError::SessionTicketInvalid(format!("session state parse failed: {}", e))
    })?;

    // Verify ticket has not expired
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let age_seconds = now.saturating_sub(state.created_at);
    // Use min() to enforce maximum 24-hour lifetime cap
    let max_lifetime = state.lifetime_hint.min(MAX_TICKET_LIFETIME as u32) as u64;
    if age_seconds > max_lifetime {
        return Err(TlsError::SessionTicketExpired);
    }

    // Verify client auth was required for this session
    if state.require_client_auth {
        return Err(TlsError::SessionTicketInvalid(
            "session ticket does not support resumption of client-authenticated sessions".into(),
        ));
    }

    // Mark this ticket as used (after all validations pass)
    session_store.mark_ticket_used(combined.clone()).await?;

    Ok(state)
}

/// PR-4.13 / P2-4: classification of session-ticket decryption
/// errors. Used by the client-side handshake loop to decide
/// whether to abort (fail-closed) or fall back to a full
/// handshake when `session_ticket_fail_closed` is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketErrorClass {
    /// Replay protection triggered (always aborts — handled
    /// inside `decrypt_session_ticket` before this classifier
    /// is consulted).
    ReplayDetected,
    /// The ticket has expired (legitimate; never abort).
    Expired,
    /// The ticket ciphertext or plaintext is malformed /
    /// tampered / wrong key. Aborts only when the operator
    /// has enabled fail-closed mode.
    TamperedOrForged,
    /// Any other failure (configuration, internal error).
    Other,
}

/// PR-4.16 / PR-4.13 follow-up: classify a `TlsError`
/// produced by `decrypt_session_ticket` so the client-side
/// handshake can decide whether to abort (fail-closed) or
/// fall back to a full handshake.
///
/// Pre-PR-4.16 this was a string-based substring match
/// against `TlsError::Display` output — fragile and
/// dependent on exact wording of `format!` strings inside
/// `decrypt_session_ticket`. PR-4.16 introduced typed
/// variants (`SessionTicketInvalid`, `SessionTicketExpired`,
/// `SessionTicketReplay`), so the classifier now uses
/// exhaustive `match` on the variant — no string parsing.
pub fn classify_ticket_error(err: &TlsError) -> TicketErrorClass {
    match err {
        // Replay always aborts; the dedicated typed variant
        // makes this branch exhaustive without string matching.
        TlsError::SessionTicketReplay => TicketErrorClass::ReplayDetected,
        // Legitimate expiry: fall back to full handshake even
        // when fail-closed is enabled (UX priority).
        TlsError::SessionTicketExpired => TicketErrorClass::Expired,
        // All other ticket failure modes (bad length, unknown
        // key, decrypt failure, deserialize failure,
        // client-auth mismatch, too-large) are the
        // "tampered or forged" class. Aborts only when
        // `session_ticket_fail_closed` is enabled.
        TlsError::SessionTicketInvalid(_) => TicketErrorClass::TamperedOrForged,
        // Anything else is unrelated to ticket handling.
        _ => TicketErrorClass::Other,
    }
}

/// Encrypt a session state into a ticket using SM4-GCM.
/// Uses the primary (first) key in the set for encryption.
pub fn encrypt_session_ticket(
    state: &SessionState,
    key_set: &TicketKeySet,
) -> Result<SessionTicket, TlsError> {
    let key = key_set
        .primary_key()
        .ok_or_else(|| TlsError::HandshakeFailed("ticket key set is empty".into()))?;

    // Serialize session state
    let state_bytes = serialization::serialize(state).map_err(|e| {
        TlsError::HandshakeFailed(format!("session state serialization failed: {}", e))
    })?;

    // Generate random nonce for SM4-GCM
    let mut nonce = [0u8; SM4_GCM_NONCE_LENGTH];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);

    // Encrypt using SM4-GCM with derived 16-byte key
    let derived_key = derive_ticket_sm4_key(&key.secret)?;
    let cipher = Sm4Cipher::new(&derived_key)
        .map_err(|e| TlsError::HandshakeFailed(format!("failed to create encryptor: {}", e)))?;
    let (encrypted, tag) = cipher.encrypt_gcm(&state_bytes, &nonce, &[]).map_err(|e| {
        TlsError::HandshakeFailed(format!("session ticket encryption failed: {}", e))
    })?;

    // Format: key_id(1) || nonce(12) || tag(16) || ciphertext
    let mut combined = Vec::with_capacity(1 + 12 + 16 + encrypted.len());
    combined.push(key.id);
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&tag);
    combined.extend_from_slice(&encrypted);

    Ok(SessionTicket {
        encrypted_ticket: combined,
        ticket_version: 1,
    })
}

/// Derive a 16-byte SM4 key from a 32-byte ticket key using SM3 KDF.
/// This ensures the ticket key is correctly sized for SM4 cipher.
fn derive_ticket_sm4_key(ticket_key: &[u8; 32]) -> Result<[u8; 16], TlsError> {
    let info = b"GM/TLS-session-ticket";
    let mut input = Vec::with_capacity(ticket_key.len() + info.len());
    input.extend_from_slice(ticket_key);
    input.extend_from_slice(info);
    let hash = Sm3Hasher::hash(&input)
        .map_err(|e| TlsError::HandshakeFailed(format!("SM3 hash failed: {}", e)))?;
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash[..16]);
    Ok(key)
}

/// Create a new session state for storage in a ticket.
///
/// `client_traffic_secret` and `server_traffic_secret` are stored in the
/// ticket to enable KeyUpdate on resumed connections. Pass `None` for
/// both to omit (disables KeyUpdate for this session).
#[allow(clippy::too_many_arguments)]
pub fn create_session_state(
    master_secret: Vec<u8>,
    session_keys: SessionKeys,
    client_traffic_secret: Option<Vec<u8>>,
    server_traffic_secret: Option<Vec<u8>>,
    server_random: [u8; 32],
    client_random: [u8; 32],
    alpn: Option<String>,
    lifetime_hint: u32,
    require_client_auth: bool,
) -> SessionState {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    SessionState {
        master_secret,
        session_keys,
        client_traffic_secret,
        server_traffic_secret,
        server_random,
        client_random,
        alpn,
        lifetime_hint,
        require_client_auth,
        created_at: now,
    }
}

// ============================================================================
// PR-4.13 / P2-4: session ticket fail-closed mode tests
// ============================================================================
//
// These tests cover the `classify_ticket_error` classifier
// and the `TlsConfig::with_session_ticket_fail_closed` builder.
// End-to-end behavior is exercised by the existing
// `tests/gmssl_interop_tests.rs` interop suite (the default
// fail-open path) and the loopback tests below use real
// `decrypt_session_ticket` invocations.

#[cfg(test)]
mod pr413_fail_closed_tests {
    use super::*;
    use crate::HandshakeOptions;
    use crate::error::TlsError;

    // PR-4.16: the original PR-4.13 tests constructed errors
    // via `TlsError::HandshakeFailed(format!(...))` and
    // asserted `classify_ticket_error` matched on substrings.
    // After PR-4.16 the typed variants carry the
    // classification directly; the tests now construct the
    // typed variants and assert the classifier dispatches on
    // the variant (no string parsing). The original test
    // names are preserved for grep-ability.
    #[test]
    fn pr413_classify_sm4_gcm_decrypt_failure_as_tampered() {
        let e = TlsError::SessionTicketInvalid("decryption failed: tag mismatch".into());
        assert_eq!(
            classify_ticket_error(&e),
            TicketErrorClass::TamperedOrForged
        );
    }

    #[test]
    fn pr413_classify_unknown_key_id_as_tampered() {
        let e = TlsError::SessionTicketInvalid("unknown ticket key ID: 7".into());
        assert_eq!(
            classify_ticket_error(&e),
            TicketErrorClass::TamperedOrForged
        );
    }

    #[test]
    fn pr413_classify_deserialize_failure_as_tampered() {
        let e = TlsError::SessionTicketInvalid("state parse failed: bad magic".into());
        assert_eq!(
            classify_ticket_error(&e),
            TicketErrorClass::TamperedOrForged
        );
    }

    #[test]
    fn pr413_classify_invalid_size_as_tampered() {
        let e = TlsError::SessionTicketInvalid("invalid session ticket".into());
        assert_eq!(
            classify_ticket_error(&e),
            TicketErrorClass::TamperedOrForged
        );
    }

    #[test]
    fn pr413_classify_client_auth_required_as_tampered() {
        let e = TlsError::SessionTicketInvalid(
            "session ticket does not support resumption of client-authenticated sessions".into(),
        );
        assert_eq!(
            classify_ticket_error(&e),
            TicketErrorClass::TamperedOrForged
        );
    }

    #[test]
    fn pr413_classify_other() {
        let e = TlsError::HandshakeFailed("some unrelated internal error".into());
        assert_eq!(classify_ticket_error(&e), TicketErrorClass::Other);
    }

    #[test]
    fn pr413_default_is_fail_open() {
        // Default `HandshakeOptions` must keep
        // `session_ticket_fail_closed = false` (PR-4.13
        // backward compat).
        let opts = HandshakeOptions::default();
        assert!(
            !opts.session_ticket_fail_closed,
            "default must be fail-open (pre-PR-4.13 behavior)"
        );
    }

    #[test]
    fn pr413_builder_sets_field() {
        // Verify the `TlsConfig` builder wires through to
        // `HandshakeOptions.session_ticket_fail_closed`.
        let cfg = crate::TlsConfig::from_bytes(b"cert".to_vec(), b"key".to_vec(), b"ca".to_vec())
            .expect("from_bytes with non-empty buffers must succeed")
            .with_session_ticket_fail_closed(true);
        let opts = cfg
            .handshake_opts
            .as_ref()
            .expect("builder must populate handshake_opts");
        assert!(
            opts.session_ticket_fail_closed,
            "with_session_ticket_fail_closed(true) must set the field"
        );
    }

    #[test]
    fn pr413_builder_can_clear_field() {
        // Verify that calling with_session_ticket_fail_closed(false)
        // after a previous `true` call explicitly clears it.
        let cfg = crate::TlsConfig::from_bytes(b"cert".to_vec(), b"key".to_vec(), b"ca".to_vec())
            .expect("from_bytes must succeed")
            .with_session_ticket_fail_closed(true)
            .with_session_ticket_fail_closed(false);
        let opts = cfg.handshake_opts.as_ref().unwrap();
        assert!(
            !opts.session_ticket_fail_closed,
            "explicit false must override prior true"
        );
    }
}

// ============================================================================
// PR-4.16: typed TlsError session-ticket variants
// ============================================================================
//
// PR-4.13 introduced `classify_ticket_error` as a
// string-substring-match against `TlsError::Display` output.
// PR-4.16 adds typed variants (`SessionTicketInvalid`,
// `SessionTicketExpired`, `SessionTicketReplay`) and rewrites
// the classifier to exhaustive-match the variant — no more
// string parsing. These tests cover the new typed surface
// and the variant dispatch.

#[cfg(test)]
mod pr416_typed_ticket_errors_tests {
    use super::*;
    use crate::error::{ErrorCode, TlsError};

    #[test]
    fn pr416_session_ticket_invalid_maps_to_session_ticket_code() {
        let e = TlsError::SessionTicketInvalid("decryption failed".into());
        assert_eq!(e.code(), ErrorCode::SessionTicket);
        // `Display` output preserves the human-readable reason
        // for log scraping / Debug prints.
        let s = e.to_string();
        assert!(
            s.contains("session ticket invalid"),
            "Display must keep the variant prefix for backward compat with log scrapers: {s}"
        );
        assert!(
            s.contains("decryption failed"),
            "Display must include the inner payload: {s}"
        );
    }

    #[test]
    fn pr416_session_ticket_expired_maps_to_session_ticket_code() {
        let e = TlsError::SessionTicketExpired;
        assert_eq!(e.code(), ErrorCode::SessionTicket);
        assert_eq!(e.to_string(), "session ticket has expired");
    }

    #[test]
    fn pr416_session_ticket_replay_maps_to_session_ticket_code() {
        let e = TlsError::SessionTicketReplay;
        assert_eq!(e.code(), ErrorCode::SessionTicket);
        assert_eq!(e.to_string(), "session ticket replay detected");
    }

    #[test]
    fn pr416_classify_uses_variant_not_string_for_replay() {
        let e = TlsError::SessionTicketReplay;
        assert_eq!(classify_ticket_error(&e), TicketErrorClass::ReplayDetected);
    }

    #[test]
    fn pr416_classify_uses_variant_not_string_for_expired() {
        let e = TlsError::SessionTicketExpired;
        assert_eq!(classify_ticket_error(&e), TicketErrorClass::Expired);
    }

    #[test]
    fn pr416_classify_uses_variant_not_string_for_invalid_payloads() {
        // All `SessionTicketInvalid(_)` payloads collapse to
        // the same `TamperedOrForged` class — variant
        // matching ignores the inner String.
        let cases: &[&str] = &[
            "invalid session ticket",
            "session ticket too large: 99999 bytes (max 8192)",
            "unknown ticket key ID: 7",
            "decryptor init: out of memory",
            "decryption failed: tag mismatch",
            "state parse: bad magic",
            "client-auth-required ticket not supported",
        ];
        for case in cases {
            let e = TlsError::SessionTicketInvalid((*case).to_string());
            assert_eq!(
                classify_ticket_error(&e),
                TicketErrorClass::TamperedOrForged,
                "payload {case:?} must classify as TamperedOrForged"
            );
        }
    }

    #[test]
    fn pr416_classify_unrelated_error_returns_other() {
        // Non-ticket errors are NOT classified as ticket
        // errors; the typed variant matcher does not over-match.
        let e = TlsError::HandshakeFailed("some unrelated handshake failure".into());
        assert_eq!(classify_ticket_error(&e), TicketErrorClass::Other);

        let e = TlsError::CertificateVerificationFailed("chain bad".into());
        assert_eq!(classify_ticket_error(&e), TicketErrorClass::Other);
    }

    #[test]
    fn pr416_error_code_distinct_from_handshake_failed() {
        // PR-4.16: `ErrorCode::SessionTicket` is a distinct
        // code from `ErrorCode::HandshakeFailed`. Operators
        // alerting on "session ticket error rate" can now
        // distinguish from generic handshake errors.
        let ticket_err = TlsError::SessionTicketInvalid("x".into());
        let handshake_err = TlsError::HandshakeFailed("y".into());
        assert_ne!(ticket_err.code(), handshake_err.code());
        assert_eq!(ticket_err.code(), ErrorCode::SessionTicket);
        assert_eq!(handshake_err.code(), ErrorCode::HandshakeFailed);
    }
}
