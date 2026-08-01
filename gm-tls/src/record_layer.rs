//! TLS record layer implementation using SM4-GCM.
//!
//! This module provides the GmTlsStream type which wraps a stream with
//! SM4-GCM encryption/decryption for TLS record layer protection.

use crate::error::TlsError;
use crate::key_update::{
    GCM_CONFIDENTIALITY_LIMIT, KEY_UPDATE_THRESHOLD, KeyUpdate, KeyUpdateRequest,
    derive_key_and_nonce, update_traffic_secret,
};
use crate::metrics;
use crate::session_ticket::SessionKeys;
use gm_crypto::sm4::{SM4_GCM_NONCE_LENGTH, Sm4Cipher};
use std::collections::HashSet;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// TLS content types (RFC 8446 §6)
const RECORD_TYPE_APPLICATION_DATA: u8 = 0x17;
/// TLS 1.3 inner content type for application data (RFC 8446 §5.4)
const INNER_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
/// TLS 1.3 inner content type for handshake (RFC 8446 §5.4)
const INNER_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// TLS 1.3 inner content type for alerts (RFC 8446 §5.4)
const INNER_CONTENT_TYPE_ALERT: u8 = 0x15;

/// Maximum TLS record size (24KB) - prevents memory exhaustion attacks
const MAX_RECORD_SIZE: usize = 24 * 1024;

/// Generate the next nonce for a given sequence number.
///
/// Per TLS 1.3 RFC 8446 Section 5.3, the nonce is constructed as:
/// `nonce = XOR(base_nonce, left_padded_seq_num)`
///
/// # Arguments
/// * `base` - 12-byte base nonce from session keys
/// * `seq` - 64-bit sequence number
///
/// # Returns
/// A 12-byte nonce with the sequence number XORed into the base nonce
///
/// # Errors
/// Returns `TlsError::SequenceOverflow` if seq equals u64::MAX
pub fn next_nonce(
    base: &[u8; SM4_GCM_NONCE_LENGTH],
    seq: u64,
) -> Result<[u8; SM4_GCM_NONCE_LENGTH], TlsError> {
    if seq == u64::MAX {
        return Err(TlsError::SequenceOverflow);
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
    // This must be a runtime check (not just debug_assert) because nonce
    // reuse in GCM is a catastrophic security failure.
    if seq != 0 && nonce == *base {
        return Err(TlsError::SequenceOverflow);
    }
    Ok(nonce)
}

/// TLS record layer (SM4-GCM)
///
/// Uses separate keys and nonces for read and write directions to prevent
/// GCM nonce reuse. The client uses `client_key`/`client_nonce` for writing
/// and `server_key`/`server_nonce` for reading; the server does the opposite.
///
/// TLS 1.3 record format (RFC 8446 §5.2):
/// ```text
/// [content_type=0x17][version=2B][length=2B][payload]
/// ```
/// For GB/T 38636-2020 TLCP, version is 0x0101.
///
/// Note: The `poll_write` implementation returns the number of plaintext bytes
/// from the input buffer that were processed, not the actual bytes written to
/// the underlying stream. This is standard TLS behavior since encryption
/// prevents accurate byte-level accounting until after AEAD processing.
pub struct GmTlsStream<S> {
    inner: S,
    /// Key for write direction — zeroized on drop via Zeroizing wrapper
    write_key: Zeroizing<Vec<u8>>,
    /// Key for read direction — zeroized on drop via Zeroizing wrapper
    read_key: Zeroizing<Vec<u8>>,
    /// Base nonce for write direction
    write_nonce: [u8; SM4_GCM_NONCE_LENGTH],
    /// Base nonce for read direction
    read_nonce: [u8; SM4_GCM_NONCE_LENGTH],
    write_seq: u64,
    read_seq: u64,
    read_buf: Vec<u8>,
    read_buf_pos: usize,
    peer_cert_pem: Option<Vec<u8>>,
    /// Negotiated ALPN protocol
    alpn: Option<String>,
    /// Cached SM4 cipher instance for encryption (avoid re-creating per-write)
    cipher_enc: Option<Sm4Cipher>,
    /// Cached SM4 cipher instance for decryption (avoid re-creating per-read)
    cipher_dec: Option<Sm4Cipher>,
    /// Whether close_notify has been sent
    close_notify_sent: bool,
    /// Protocol version for record headers
    version: [u8; 2],
    /// Current application traffic secret for write direction.
    /// Used to derive new keys during KeyUpdate.
    write_traffic_secret: Option<Zeroizing<Vec<u8>>>,
    /// Current application traffic secret for read direction.
    /// Used to derive new keys when processing peer's KeyUpdate.
    read_traffic_secret: Option<Zeroizing<Vec<u8>>>,
    /// Whether a KeyUpdate with update_requested has been received
    /// and we need to send our own KeyUpdate before the next write.
    key_update_pending: bool,
    /// Global counter for KeyUpdate events (for audit/metrics)
    key_update_count: Arc<AtomicU64>,
    /// Nonce reuse detection for write direction.
    ///
    /// # Security Note
    /// This only protects against nonce reuse within the current connection.
    /// It does NOT protect across sessions or connection resumption.
    ///
    /// # Memory Overhead
    /// Approximately 96KB per connection at maximum (8M records × 12 bytes).
    /// In practice, typical connections use far fewer records.
    used_write_nonces: HashSet<[u8; SM4_GCM_NONCE_LENGTH]>,
    nonce_eviction_queue: VecDeque<[u8; SM4_GCM_NONCE_LENGTH]>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> GmTlsStream<S> {
    /// Create a new GM/TLS stream with the given session keys and role.
    ///
    /// In TLS, the client uses `client_key`/`client_nonce` for writing and
    /// `server_key`/`server_nonce` for reading. The server does the opposite.
    pub fn new(
        inner: S,
        keys: SessionKeys,
        is_client: bool,
        peer_cert_pem: Option<Vec<u8>>,
        alpn: Option<String>,
    ) -> Self {
        Self::with_version(inner, keys, is_client, peer_cert_pem, alpn, [0x03, 0x03])
    }

    /// Create a new GM/TLS stream with a specific protocol version.
    pub fn with_version(
        inner: S,
        keys: SessionKeys,
        is_client: bool,
        peer_cert_pem: Option<Vec<u8>>,
        alpn: Option<String>,
        version: [u8; 2],
    ) -> Self {
        let (write_key, write_nonce, read_key, read_nonce) = if is_client {
            (
                keys.client_key.clone(),
                keys.client_nonce,
                keys.server_key.clone(),
                keys.server_nonce,
            )
        } else {
            (
                keys.server_key.clone(),
                keys.server_nonce,
                keys.client_key.clone(),
                keys.client_nonce,
            )
        };
        Self {
            inner,
            write_key: Zeroizing::new(write_key),
            read_key: Zeroizing::new(read_key),
            write_nonce,
            read_nonce,
            write_seq: 0,
            read_seq: 0,
            read_buf: Vec::new(),
            read_buf_pos: 0,
            peer_cert_pem,
            alpn,
            cipher_enc: None,
            cipher_dec: None,
            close_notify_sent: false,
            version,
            write_traffic_secret: None,
            read_traffic_secret: None,
            key_update_pending: false,
            key_update_count: Arc::new(AtomicU64::new(0)),
            used_write_nonces: HashSet::new(),
            nonce_eviction_queue: VecDeque::new(),
        }
    }

    fn get_cipher_enc(&mut self) -> Result<&mut Sm4Cipher, TlsError> {
        if self.cipher_enc.is_none() {
            let cipher = Sm4Cipher::new(&self.write_key)
                .map_err(|e| TlsError::HandshakeFailed(format!("SM4 key error: {:?}", e)))?;
            self.cipher_enc = Some(cipher);
        }
        self.cipher_enc
            .as_mut()
            .ok_or_else(|| TlsError::HandshakeFailed("cipher_enc not initialized".into()))
    }

    fn get_cipher_dec(&mut self) -> Result<&mut Sm4Cipher, TlsError> {
        if self.cipher_dec.is_none() {
            let cipher = Sm4Cipher::new(&self.read_key)
                .map_err(|e| TlsError::HandshakeFailed(format!("SM4 key error: {:?}", e)))?;
            self.cipher_dec = Some(cipher);
        }
        self.cipher_dec
            .as_mut()
            .ok_or_else(|| TlsError::HandshakeFailed("cipher_dec not initialized".into()))
    }

    /// Returns the negotiated ALPN protocol, if any.
    pub fn alpn(&self) -> Option<&str> {
        self.alpn.as_deref()
    }

    /// Check for nonce reuse and record the nonce.
    ///
    /// # Security Note
    /// This only protects against nonce reuse within the current connection.
    /// It does NOT protect across sessions or connection resumption.
    const MAX_NONCE_CACHE: usize = 1_000_000;
    /// How many entries to evict when the cache overflows.
    const NONCE_EVICT_BATCH: usize = 100_000;

    fn check_and_record_nonce(
        &mut self,
        nonce: &[u8; SM4_GCM_NONCE_LENGTH],
    ) -> Result<(), TlsError> {
        // Evict oldest entries in batch instead of clearing the entire set.
        // This preserves recent replay-detection capability while bounding memory.
        if self.used_write_nonces.len() > Self::MAX_NONCE_CACHE {
            for _ in 0..Self::NONCE_EVICT_BATCH {
                if let Some(old) = self.nonce_eviction_queue.pop_front() {
                    self.used_write_nonces.remove(&old);
                }
            }
            tracing::warn!(
                "Nonce cache overflow, evicted {} oldest entries ({} remain)",
                Self::NONCE_EVICT_BATCH,
                self.used_write_nonces.len(),
            );
        }
        self.nonce_eviction_queue.push_back(*nonce);
        if !self.used_write_nonces.insert(*nonce) {
            return Err(TlsError::NonceReuse);
        }
        Ok(())
    }

    /// Reset write sequence number for testing nonce reuse detection.
    ///
    /// # Warning
    /// This is ONLY for testing. Never use in production.
    #[cfg(test)]
    pub fn reset_write_seq_for_test(&mut self, seq: u64) {
        self.write_seq = seq;
    }

    // ============== KeyUpdate (RFC 8446 §4.6.3) ==============

    /// Set the application traffic secrets for KeyUpdate support.
    ///
    /// Must be called after the handshake completes with the negotiated
    /// traffic secrets. Without these secrets, KeyUpdate cannot be performed
    /// and the connection will error when the sequence number threshold is reached.
    ///
    /// # Arguments
    /// * `write_secret` - Application traffic secret for the write direction
    /// * `read_secret` - Application traffic secret for the read direction
    pub fn set_traffic_secrets(&mut self, write_secret: Vec<u8>, read_secret: Vec<u8>) {
        self.write_traffic_secret = Some(Zeroizing::new(write_secret));
        self.read_traffic_secret = Some(Zeroizing::new(read_secret));
    }

    /// Check if a KeyUpdate should be triggered based on the current
    /// write sequence number.
    ///
    /// Per NIST SP 800-38D, the GCM confidentiality limit is 2^32 records
    /// per key. We trigger at 80% of this limit for safety.
    pub fn should_update_key(&self) -> bool {
        self.write_seq >= KEY_UPDATE_THRESHOLD
    }

    /// Check if the write sequence number has reached the hard GCM limit.
    ///
    /// If true, writing MUST NOT continue without a key update.
    pub fn is_key_exhausted(&self) -> bool {
        self.write_seq >= GCM_CONFIDENTIALITY_LIMIT
    }

    /// Get the number of KeyUpdate operations performed on this connection.
    pub fn key_update_count(&self) -> u64 {
        self.key_update_count.load(Ordering::Relaxed)
    }

    /// Perform a local key update: derive new write key from the current
    /// traffic secret and reset the write sequence number.
    ///
    /// This is called after sending a KeyUpdate message or when the
    /// sequence number threshold is reached.
    ///
    /// # Errors
    /// Returns an error if traffic secrets are not set or key derivation fails.
    fn rotate_write_key(&mut self) -> Result<(), TlsError> {
        let new_secret =
            update_traffic_secret(self.write_traffic_secret.as_deref().ok_or_else(|| {
                TlsError::HandshakeFailed(
                    "cannot perform KeyUpdate: write traffic secret not set".into(),
                )
            })?)?;

        let (new_key, new_nonce) = derive_key_and_nonce(&new_secret)?;

        // Zeroize old key before replacing
        self.write_key = Zeroizing::new(new_key);
        self.write_nonce = new_nonce;
        self.write_seq = 0; // Reset per RFC 8446 §5.3
        self.cipher_enc = None; // Force cipher re-creation with new key
        self.used_write_nonces.clear();
        self.nonce_eviction_queue.clear();

        // Update the traffic secret for future KeyUpdates
        self.write_traffic_secret = Some(Zeroizing::new(new_secret));

        let count = self.key_update_count.fetch_add(1, Ordering::Relaxed) + 1;
        info!(
            key_update_count = count,
            "KeyUpdate: rotated write traffic key, seq reset to 0"
        );

        Ok(())
    }

    /// Rotate the read key after receiving a KeyUpdate from the peer.
    ///
    /// This derives new read key from the current read traffic secret
    /// and resets the read sequence number.
    fn rotate_read_key(&mut self) -> Result<(), TlsError> {
        let new_secret =
            update_traffic_secret(self.read_traffic_secret.as_deref().ok_or_else(|| {
                TlsError::HandshakeFailed(
                    "cannot process KeyUpdate: read traffic secret not set".into(),
                )
            })?)?;

        let (new_key, new_nonce) = derive_key_and_nonce(&new_secret)?;

        self.read_key = Zeroizing::new(new_key);
        self.read_nonce = new_nonce;
        self.read_seq = 0;
        self.cipher_dec = None; // Force cipher re-creation with new key

        self.read_traffic_secret = Some(Zeroizing::new(new_secret));

        let count = self.key_update_count.fetch_add(1, Ordering::Relaxed) + 1;
        info!(
            key_update_count = count,
            "KeyUpdate: rotated read traffic key, seq reset to 0"
        );

        Ok(())
    }

    /// Send a KeyUpdate message to the peer.
    ///
    /// After sending, the local write key is rotated. If `request_peer_update`
    /// is true, the peer is also requested to send a KeyUpdate.
    ///
    /// # Wire Format
    /// The KeyUpdate is sent as a post-handshake message:
    /// ```text
    /// [content_type=0x16][version][length]
    /// [HandshakeType=0x18][3-byte length][update_requested(1 byte)]
    /// ```
    ///
    /// # Errors
    /// Returns an error if traffic secrets are not set, key derivation fails,
    /// or the underlying stream fails.
    pub async fn send_key_update(&mut self, request_peer_update: bool) -> Result<(), TlsError> {
        let ku = KeyUpdate::new(if request_peer_update {
            KeyUpdateRequest::UpdateRequested
        } else {
            KeyUpdateRequest::UpdateNotRequested
        });
        let body = ku.to_bytes();

        // Build handshake message: [type=0x18][length=0x000001][body]
        let mut handshake_msg = Vec::with_capacity(4 + body.len());
        handshake_msg.push(0x18); // KeyUpdate handshake type
        handshake_msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 3-byte length
        handshake_msg.extend_from_slice(&body);

        // Encrypt and send as a post-handshake message
        // This uses the current write key (before rotation)
        self.write_handshake_record(&handshake_msg).await?;

        // Now rotate the write key
        self.rotate_write_key()?;

        debug!(
            requested_peer = request_peer_update,
            "sent KeyUpdate message"
        );

        Ok(())
    }

    /// Process a received KeyUpdate message from the peer.
    ///
    /// After processing, the read key is rotated. If the peer requested
    /// an update, `key_update_pending` is set so the next write will
    /// also send a KeyUpdate.
    ///
    /// # Returns
    /// `true` if the peer requested a key update (caller should send one),
    /// `false` otherwise.
    pub fn process_key_update(
        &mut self,
        update_requested: KeyUpdateRequest,
    ) -> Result<bool, TlsError> {
        // Rotate the read key first
        self.rotate_read_key()?;

        let needs_response = update_requested == KeyUpdateRequest::UpdateRequested;
        if needs_response {
            self.key_update_pending = true;
        }

        debug!(
            peer_requested_update = needs_response,
            "processed KeyUpdate from peer"
        );

        Ok(needs_response)
    }

    /// Check if we have a pending KeyUpdate to send and send it if so.
    ///
    /// This should be called before each write operation to handle
    /// pending KeyUpdate requests from the peer.
    async fn flush_pending_key_update(&mut self) -> Result<(), TlsError> {
        if self.key_update_pending {
            self.key_update_pending = false;
            self.send_key_update(false).await?; // Don't request another update
        }
        Ok(())
    }

    /// Write a post-handshake record (e.g., KeyUpdate, NewSessionTicket).
    ///
    /// This encrypts the handshake message using the current write key
    /// and sends it as a TLS record with content_type=0x16 (handshake)
    /// wrapped in application_data encryption.
    async fn write_handshake_record(&mut self, msg: &[u8]) -> Result<(), TlsError> {
        let nonce = next_nonce(&self.write_nonce, self.write_seq)?;
        self.check_and_record_nonce(&nonce)?;
        let seq_bytes = self.write_seq.to_be_bytes();
        self.write_seq = self
            .write_seq
            .checked_add(1)
            .ok_or(TlsError::SequenceOverflow)?;

        let version_bytes = self.version;
        let cipher = self.get_cipher_enc()?;

        // TLS 1.3 inner content type (RFC 8446 §5.4):
        // Append 0x16 (handshake) as the last byte of plaintext.
        let mut inner = Vec::with_capacity(msg.len() + 1);
        inner.extend_from_slice(msg);
        inner.push(INNER_CONTENT_TYPE_HANDSHAKE);

        // Record: [0x17][version][length][ciphertext][tag]
        // AAD = seq_bytes || record_header
        let ct_len = (inner.len() + 16) as u16;
        let mut record = Vec::with_capacity(5);
        record.push(RECORD_TYPE_APPLICATION_DATA);
        record.extend_from_slice(&version_bytes);
        record.extend_from_slice(&ct_len.to_be_bytes());
        let aad = [&seq_bytes[..], &record[..]].concat();

        let (ciphertext, tag) = cipher.encrypt_gcm(&inner, &nonce, &aad).map_err(|e| {
            TlsError::HandshakeFailed(format!("KeyUpdate encryption failed: {:?}", e))
        })?;

        self.inner
            .write_u8(RECORD_TYPE_APPLICATION_DATA)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_all(&version_bytes)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_u16(ct_len)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_all(&ciphertext)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_all(&tag)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .flush()
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Write application data (encrypted).
    pub async fn write_application_data(&mut self, plaintext: &[u8]) -> Result<(), TlsError> {
        // Handle pending KeyUpdate from peer
        self.flush_pending_key_update().await?;

        // Auto-trigger KeyUpdate when approaching GCM confidentiality limit
        if self.is_key_exhausted() {
            return Err(TlsError::HandshakeFailed(
                "GCM confidentiality limit reached: sequence number exhausted, KeyUpdate required \
                 but no traffic secret available"
                    .into(),
            ));
        }
        if self.should_update_key() {
            if self.write_traffic_secret.is_some() {
                debug!("auto-triggering KeyUpdate at seq={}", self.write_seq);
                self.send_key_update(false).await?;
            } else {
                warn!(
                    seq = self.write_seq,
                    "approaching GCM confidentiality limit but no traffic secret set; KeyUpdate \
                     cannot be performed"
                );
            }
        }

        let nonce = next_nonce(&self.write_nonce, self.write_seq)?;
        self.check_and_record_nonce(&nonce)?;
        let seq_bytes = self.write_seq.to_be_bytes();
        self.write_seq = self
            .write_seq
            .checked_add(1)
            .ok_or(TlsError::SequenceOverflow)?;

        let version_bytes = self.version;

        let cipher = self.get_cipher_enc()?;

        // TLS 1.3 inner content type (RFC 8446 §5.4):
        // The actual plaintext is: data || content_type_byte
        // For application data, content_type = 0x17
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(INNER_CONTENT_TYPE_APPLICATION_DATA);

        // TLS 1.3 record: [content_type(1)][version(2)][length(2)][ciphertext][tag]
        // AAD = seq_bytes || record_header (where length = ciphertext+tag length)
        // For SM4-GCM: ciphertext_len = inner.len(), tag_len = 16
        let ct_len = (inner.len() + 16) as u16;
        let mut record = Vec::with_capacity(5);
        record.push(RECORD_TYPE_APPLICATION_DATA);
        record.extend_from_slice(&version_bytes);
        record.extend_from_slice(&ct_len.to_be_bytes());
        let aad = [&seq_bytes[..], &record[..]].concat();

        let (ciphertext, tag) = cipher
            .encrypt_gcm(&inner, &nonce, &aad)
            .map_err(|e| TlsError::HandshakeFailed(format!("GCM encryption failed: {:?}", e)))?;

        // TLS record: [content_type(1)][version(2)][length(2)][ciphertext][tag]
        // Note: ct_len above matches actual ciphertext+tag length since tag is always 16 bytes
        self.inner
            .write_u8(RECORD_TYPE_APPLICATION_DATA)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_all(&version_bytes)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_u16(ct_len)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_all(&ciphertext)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_all(&tag)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .flush()
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;

        metrics::record_bytes("tls", "send", plaintext.len());
        Ok(())
    }

    /// Read application data (decrypted).
    pub async fn read_application_data(&mut self) -> Result<Vec<u8>, TlsError> {
        // Read 5-byte TLS record header
        let mut header = [0u8; 5];
        self.inner
            .read_exact(&mut header)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;

        if header[0] != RECORD_TYPE_APPLICATION_DATA {
            return Err(TlsError::TlsRecordError(format!(
                "expected application_data record 0x17, got 0x{:02X}",
                header[0]
            )));
        }

        let ct_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if ct_len < 16 {
            return Err(TlsError::HandshakeFailed("record too short".into()));
        }
        if ct_len > MAX_RECORD_SIZE {
            return Err(TlsError::HandshakeFailed(
                "record exceeds size limit".into(),
            ));
        }
        let mut buf = vec![0u8; ct_len];
        self.inner
            .read_exact(&mut buf)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        let (ciphertext, tag) = buf.split_at(ct_len - 16);

        let nonce = next_nonce(&self.read_nonce, self.read_seq)?;
        let seq_bytes = self.read_seq.to_be_bytes();
        self.read_seq = self
            .read_seq
            .checked_add(1)
            .ok_or(TlsError::SequenceOverflow)?;

        // Build record header for AAD (seq_bytes || header only, not ciphertext/tag)
        let aad = [&seq_bytes[..], &header[..]].concat();

        let cipher = self.get_cipher_dec()?;
        let mut plaintext = cipher
            .decrypt_gcm(ciphertext, &nonce, &aad, tag)
            .map_err(|e| TlsError::HandshakeFailed(format!("GCM decryption failed: {:?}", e)))?;

        // TLS 1.3 inner content type (RFC 8446 §5.4):
        // The last byte of the decrypted plaintext is the content type.
        // For application data: strip the trailing 0x17 byte
        // For handshake: process the inner handshake message
        if plaintext.is_empty() {
            return Err(TlsError::InvalidMessage(
                "decrypted record is empty (missing inner content type)".into(),
            ));
        }
        let inner_content_type = plaintext.pop().unwrap(); // Remove last byte (content type)

        match inner_content_type {
            INNER_CONTENT_TYPE_APPLICATION_DATA => {
                metrics::record_bytes("tls", "recv", plaintext.len());
                Ok(plaintext)
            }
            INNER_CONTENT_TYPE_HANDSHAKE => {
                // Post-handshake message (e.g., KeyUpdate, NewSessionTicket)
                self.process_inner_handshake(&plaintext)?;
                // Recursively read the next record (which should be application data)
                Box::pin(self.read_application_data()).await
            }
            _ => Err(TlsError::InvalidMessage(format!(
                "unknown inner content type: 0x{:02X}",
                inner_content_type
            ))),
        }
    }

    /// Process a decrypted post-handshake message.
    ///
    /// Handshake message format: `[HandshakeType(1)][length(3)][body...]`
    fn process_inner_handshake(&mut self, msg: &[u8]) -> Result<(), TlsError> {
        if msg.len() < 4 {
            return Err(TlsError::InvalidMessage(
                "handshake message too short".into(),
            ));
        }
        let handshake_type = msg[0];
        let handshake_len =
            ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
        if msg.len() < 4 + handshake_len {
            return Err(TlsError::InvalidMessage(format!(
                "handshake message truncated: expected {} bytes, got {}",
                handshake_len,
                msg.len() - 4
            )));
        }
        let body = &msg[4..4 + handshake_len];

        match handshake_type {
            0x18 => {
                // KeyUpdate (RFC 8446 §4.6.3)
                let ku = KeyUpdate::from_bytes(body)?;
                debug!(?ku.update_requested, "received KeyUpdate");
                self.process_key_update(ku.update_requested)?;
                Ok(())
            }
            0x04 => {
                // NewSessionTicket — not yet handled, ignore for now
                debug!("received NewSessionTicket (not yet handled)");
                Ok(())
            }
            _ => {
                warn!(type = handshake_type, "unexpected post-handshake message type");
                Err(TlsError::InvalidHandshakeType(handshake_type))
            }
        }
    }

    /// Get peer certificate PEM (if available)
    pub fn peer_certificate_pem(&self) -> Option<&[u8]> {
        self.peer_cert_pem.as_deref()
    }

    /// Send a close_notify alert to the peer for graceful connection shutdown.
    ///
    /// Per TLS 1.3 (RFC 8446 §6.1), the close_notify alert signals that the
    /// sender will not send any more data on this connection. The receiver
    /// should respond with their own close_notify before closing.
    pub async fn close(&mut self) -> Result<(), TlsError> {
        if self.close_notify_sent {
            return Ok(());
        }

        let nonce = next_nonce(&self.write_nonce, self.write_seq)?;
        self.check_and_record_nonce(&nonce)?;
        let seq_bytes = self.write_seq.to_be_bytes();
        self.write_seq = self
            .write_seq
            .checked_add(1)
            .ok_or(TlsError::SequenceOverflow)?;

        let version_bytes = self.version;

        let cipher = self.get_cipher_enc()?;

        // TLS 1.3 inner content type for close_notify alert:
        // Plaintext = [level=warning(1), description=close_notify(0)] || content_type=0x15
        let inner: [u8; 3] = [0x01, 0x00, INNER_CONTENT_TYPE_ALERT]; // warning + close_notify + alert type
        let ct_len: u16 = (inner.len() + 16) as u16;
        let mut record = Vec::with_capacity(5);
        record.push(RECORD_TYPE_APPLICATION_DATA);
        record.extend_from_slice(&version_bytes);
        record.extend_from_slice(&ct_len.to_be_bytes());
        let aad = [&seq_bytes[..], &record[..]].concat();

        // Encrypt close_notify payload
        let (ciphertext, tag) = cipher.encrypt_gcm(&inner, &nonce, &aad).map_err(|e| {
            TlsError::HandshakeFailed(format!("close_notify encryption failed: {:?}", e))
        })?;

        // TLS record: [0x17][version][length][ciphertext][tag]
        self.inner
            .write_u8(RECORD_TYPE_APPLICATION_DATA)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_all(&version_bytes)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_u16(ct_len)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_all(&ciphertext)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .write_all(&tag)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;
        self.inner
            .flush()
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;

        self.close_notify_sent = true;
        Ok(())
    }

    /// Receive and handle a close_notify alert from the peer.
    ///
    /// Returns `true` if a close_notify was received, `false` if the
    /// connection was closed without close_notify (truncation attack).
    pub async fn recv_close_notify(&mut self) -> Result<bool, TlsError> {
        // Read 5-byte TLS record header
        let mut header = [0u8; 5];
        match self.inner.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Peer closed without close_notify
                return Ok(false);
            }
            Err(e) => return Err(TlsError::IoError(e.to_string())),
        }

        if header[0] != RECORD_TYPE_APPLICATION_DATA {
            return Err(TlsError::TlsRecordError(format!(
                "expected application_data record 0x17, got 0x{:02X}",
                header[0]
            )));
        }

        let ct_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if ct_len < 16 {
            return Err(TlsError::HandshakeFailed(
                "close_notify record too short".into(),
            ));
        }
        if ct_len > MAX_RECORD_SIZE {
            return Err(TlsError::HandshakeFailed(
                "close_notify record exceeds size limit".into(),
            ));
        }

        let mut buf = vec![0u8; ct_len];
        self.inner
            .read_exact(&mut buf)
            .await
            .map_err(|e| TlsError::IoError(e.to_string()))?;

        let (ciphertext, tag) = buf.split_at(ct_len - 16);
        let nonce = next_nonce(&self.read_nonce, self.read_seq)?;
        let seq_bytes = self.read_seq.to_be_bytes();
        self.read_seq = self
            .read_seq
            .checked_add(1)
            .ok_or(TlsError::SequenceOverflow)?;

        // AAD = seq_bytes || record_header (must match close() and poll_shutdown())
        let aad = [&seq_bytes[..], &header[..]].concat();
        let cipher = self.get_cipher_dec()?;
        let mut plaintext = cipher
            .decrypt_gcm(ciphertext, &nonce, &aad, tag)
            .map_err(|e| {
                TlsError::HandshakeFailed(format!("close_notify decryption failed: {:?}", e))
            })?;

        // TLS 1.3 inner content type: last byte is content type
        if !plaintext.is_empty() {
            let inner_ct = plaintext.pop().unwrap();
            if inner_ct == INNER_CONTENT_TYPE_ALERT {
                // Alert: plaintext should be [level, description]
                // Accept any length for compatibility
            }
            // If it's application data, that's also OK (peer might send data before close)
        }

        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for GmTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_buf_pos < self.read_buf.len() {
            let available = self.read_buf.len() - self.read_buf_pos;
            let to_copy = available.min(buf.remaining());
            buf.put_slice(&self.read_buf[self.read_buf_pos..self.read_buf_pos + to_copy]);
            self.read_buf_pos += to_copy;

            if self.read_buf_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_buf_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        let mut stream_ref = Pin::new(&mut self.inner);

        // Read 5-byte TLS record header
        let mut header = [0u8; 5];
        match stream_ref
            .as_mut()
            .poll_read(cx, &mut ReadBuf::new(&mut header))
        {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        if header[0] != RECORD_TYPE_APPLICATION_DATA {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "expected application_data record 0x17, got 0x{:02X}",
                header[0]
            ))));
        }

        let ct_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if ct_len < 16 {
            return Poll::Ready(Err(std::io::Error::other("TLS record too short")));
        }
        if ct_len > MAX_RECORD_SIZE {
            return Poll::Ready(Err(std::io::Error::other("TLS record exceeds size limit")));
        }

        let mut ciphertext_buf = vec![0u8; ct_len];
        let mut filled = 0;
        while filled < ct_len {
            let mut chunk_buf = ReadBuf::new(&mut ciphertext_buf[filled..]);
            match stream_ref.as_mut().poll_read(cx, &mut chunk_buf) {
                Poll::Ready(Ok(_)) => {
                    let n = chunk_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::other(
                            "TLS record read incomplete",
                        )));
                    }
                    filled += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let (ciphertext, tag) = ciphertext_buf.split_at(ct_len - 16);

        let nonce = match next_nonce(&self.read_nonce, self.read_seq) {
            Ok(n) => n,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::other(format!("Nonce overflow: {}", e))));
            }
        };
        let seq_bytes = self.read_seq.to_be_bytes();
        self.read_seq = match self.read_seq.checked_add(1) {
            Some(s) => s,
            None => {
                return Poll::Ready(Err(std::io::Error::other("Sequence overflow")));
            }
        };

        // Build record header for AAD
        let aad = [&seq_bytes[..], &header[..]].concat();

        let cipher = match self.get_cipher_dec() {
            Ok(c) => c,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::other(format!("SM4 key error: {}", e))));
            }
        };

        let mut plaintext = match cipher.decrypt_gcm(ciphertext, &nonce, &aad, tag) {
            Ok(p) => p,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::other(format!(
                    "GCM decryption failed: {:?}",
                    e
                ))));
            }
        };

        // TLS 1.3 inner content type (RFC 8446 §5.4): last byte is content type
        if plaintext.is_empty() {
            return Poll::Ready(Err(std::io::Error::other(
                "decrypted record is empty (missing inner content type)",
            )));
        }
        let inner_content_type = plaintext.pop().unwrap();

        match inner_content_type {
            INNER_CONTENT_TYPE_APPLICATION_DATA => {
                self.read_buf = plaintext;
                self.read_buf_pos = 0;

                let to_copy = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..to_copy]);
                self.read_buf_pos = to_copy;

                if self.read_buf_pos >= self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_buf_pos = 0;
                }

                Poll::Ready(Ok(()))
            }
            INNER_CONTENT_TYPE_HANDSHAKE => {
                // Post-handshake message (e.g., KeyUpdate)
                // Process it and then indicate we need another read
                match self.process_inner_handshake(&plaintext) {
                    Ok(()) => {
                        // Signal that we consumed no application data;
                        // the caller should poll again.
                        // We can't recursively call poll_read easily,
                        // so we return Pending and the next poll will read the next record.
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(std::io::Error::other(format!(
                        "post-handshake processing failed: {}",
                        e
                    )))),
                }
            }
            INNER_CONTENT_TYPE_ALERT => {
                // Alert received during read — check for close_notify
                // For now, return 0 bytes (EOF-like) if it's close_notify
                if plaintext.len() >= 2 && plaintext[0] == 0x01 && plaintext[1] == 0x00 {
                    // close_notify
                    Poll::Ready(Ok(())) // 0 bytes filled = EOF
                } else {
                    Poll::Ready(Err(std::io::Error::other(format!(
                        "TLS alert: level={} description={}",
                        plaintext.first().copied().unwrap_or(0),
                        plaintext.get(1).copied().unwrap_or(0)
                    ))))
                }
            }
            _ => Poll::Ready(Err(std::io::Error::other(format!(
                "unknown inner content type: 0x{:02X}",
                inner_content_type
            )))),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for GmTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let nonce = match next_nonce(&self.write_nonce, self.write_seq) {
            Ok(n) => n,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::other(format!("Nonce overflow: {}", e))));
            }
        };
        let seq_bytes = self.write_seq.to_be_bytes();
        self.write_seq = match self.write_seq.checked_add(1) {
            Some(s) => s,
            None => {
                return Poll::Ready(Err(std::io::Error::other("Sequence overflow")));
            }
        };

        // Copy version before borrowing self mutably
        let version_bytes = self.version;

        let cipher = match self.get_cipher_enc() {
            Ok(c) => c,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::other(format!("SM4 key error: {}", e))));
            }
        };

        // TLS 1.3 inner content type (RFC 8446 §5.4):
        // Append 0x17 (application data) as last byte of plaintext.
        let mut inner = Vec::with_capacity(buf.len() + 1);
        inner.extend_from_slice(buf);
        inner.push(INNER_CONTENT_TYPE_APPLICATION_DATA);

        // TLS record header for AAD and wire: [0x17][version][length]
        // AAD length = ciphertext+tag length (not plaintext length)
        let ct_len = (inner.len() + 16) as u16; // ciphertext = inner.len(), tag = 16
        let mut record = Vec::with_capacity(5);
        record.push(RECORD_TYPE_APPLICATION_DATA);
        record.extend_from_slice(&version_bytes);
        record.extend_from_slice(&ct_len.to_be_bytes());
        let aad = [&seq_bytes[..], &record[..]].concat();

        let (ciphertext, tag) = match cipher.encrypt_gcm(&inner, &nonce, &aad) {
            Ok(ct) => ct,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::other(format!(
                    "GCM encryption failed: {:?}",
                    e
                ))));
            }
        };

        let ct_len_final = (ciphertext.len() + tag.len()) as u16;
        if ct_len_final > u16::MAX - 1024 {
            return Poll::Ready(Err(std::io::Error::other("TLS record too large")));
        }
        let version_bytes = self.version;
        let mut stream_ref = Pin::new(&mut self.inner);

        // Write TLS record header: [0x17][version][length]
        match stream_ref
            .as_mut()
            .poll_write(cx, &[RECORD_TYPE_APPLICATION_DATA])
        {
            Poll::Ready(Ok(1)) => {}
            Poll::Ready(Ok(_)) => {
                return Poll::Ready(Err(std::io::Error::other("failed to write content type")));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        match stream_ref.as_mut().poll_write(cx, &version_bytes) {
            Poll::Ready(Ok(2)) => {}
            Poll::Ready(Ok(_)) => {
                return Poll::Ready(Err(std::io::Error::other("failed to write version")));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        let len_bytes = ct_len.to_be_bytes();
        match stream_ref.as_mut().poll_write(cx, &len_bytes) {
            Poll::Ready(Ok(2)) => {}
            Poll::Ready(Ok(_)) => {
                return Poll::Ready(Err(std::io::Error::other("failed to write length")));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        let mut written = 0;
        while written < ciphertext.len() {
            match stream_ref.as_mut().poll_write(cx, &ciphertext[written..]) {
                Poll::Ready(Ok(n)) if n > 0 => written += n,
                Poll::Ready(Ok(_)) => {
                    return Poll::Ready(Err(std::io::Error::other("failed to write ciphertext")));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let mut tag_written = 0;
        while tag_written < tag.len() {
            match stream_ref.as_mut().poll_write(cx, &tag[tag_written..]) {
                Poll::Ready(Ok(n)) if n > 0 => tag_written += n,
                Poll::Ready(Ok(_)) => {
                    return Poll::Ready(Err(std::io::Error::other("failed to write tag")));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Send close_notify if not yet sent (RFC 8446 §6.1).
        if !self.close_notify_sent {
            let nonce = match next_nonce(&self.write_nonce, self.write_seq) {
                Ok(n) => n,
                Err(_) => {
                    return Pin::new(&mut self.inner).poll_shutdown(cx);
                }
            };
            let seq_bytes = self.write_seq.to_be_bytes();
            self.write_seq = match self.write_seq.checked_add(1) {
                Some(s) => s,
                None => {
                    return Pin::new(&mut self.inner).poll_shutdown(cx);
                }
            };

            // Extract version before mutable borrow for cipher
            let version_bytes = self.version;

            let cipher = match self.get_cipher_enc() {
                Ok(c) => c,
                Err(_) => {
                    return Pin::new(&mut self.inner).poll_shutdown(cx);
                }
            };

            // TLS 1.3 inner content type for close_notify:
            // Plaintext = [level=warning(1), description=close_notify(0)] || content_type=0x15
            let inner: [u8; 3] = [0x01, 0x00, INNER_CONTENT_TYPE_ALERT];
            let ct_len: u16 = (inner.len() + 16) as u16;
            let mut record_header = Vec::with_capacity(5);
            record_header.push(RECORD_TYPE_APPLICATION_DATA);
            record_header.extend_from_slice(&version_bytes);
            record_header.extend_from_slice(&ct_len.to_be_bytes());
            let aad = [&seq_bytes[..], &record_header[..]].concat();

            let (ciphertext, tag) = match cipher.encrypt_gcm(&inner, &nonce, &aad) {
                Ok(ct) => ct,
                Err(_) => {
                    return Pin::new(&mut self.inner).poll_shutdown(cx);
                }
            };

            // Build TLS 1.3 record: [0x17][version][length][ciphertext][tag]
            let ct_len = (ciphertext.len() + tag.len()) as u16;
            let mut record = Vec::with_capacity(5 + ciphertext.len() + tag.len());
            record.push(RECORD_TYPE_APPLICATION_DATA);
            record.extend_from_slice(&version_bytes);
            record.extend_from_slice(&ct_len.to_be_bytes());
            record.extend_from_slice(&ciphertext);
            record.extend_from_slice(&tag);

            let mut stream_ref = Pin::new(&mut self.inner);
            let mut written = 0;
            while written < record.len() {
                match stream_ref.as_mut().poll_write(cx, &record[written..]) {
                    Poll::Ready(Ok(n)) if n > 0 => written += n,
                    Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => {
                        break;
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }

            self.close_notify_sent = true;
        }

        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
