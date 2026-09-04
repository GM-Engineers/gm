//! TLCP key derivation.
//!
//! `TlcpKeyMaterial` holds the per-direction keying material derived
//! from the master secret at the end of the handshake. It is used by:
//!
//! - the record layer (GCM and CBC encrypt/decrypt), and
//! - the session resumption path (`TlcpResumedSession::derive_session_keys`).
//!
//! ## GCM key block layout (GmSSL, post 2026-06 fixes)
//!
//! Per GmSSL's `tls_derive_key_block` (src/tls.c), the key block for
//! GCM cipher suites is **40 bytes** total:
//!
//! ```text
//! | client_enc_key(16) | server_enc_key(16) | client_iv(4) | server_iv(4) |
//! ```
//!
//! The 4-byte fixed IV is concatenated with the 8-byte explicit nonce
//! from the record to form the 12-byte GCM nonce.
//!
//! ## CBC key block layout
//!
//! For SM4-CBC + SM3-HMAC, the key block is **128 bytes** total:
//!
//! ```text
//! | client_mac(32) | server_mac(32) | client_enc(16) | server_enc(16) |
//! | client_iv(16)  | server_iv(16)  |
//! ```
//!
//! ## Security
//!
//! `Debug` is **manually** redacted: `println!("{:?}", km)` only prints
//! field lengths, never the key/IV bytes themselves. `Drop` zeroizes
//! all six key/IV fields.

use super::cipher_suite::TlcpCipherSuite;
use crate::error::TlcpError;
use crate::session_keys::SessionKeys;
use gm_crypto::sm3::Sm3Hmac;

/// TLCP key material derived from master secret.
///
/// # Security
///
/// The `Debug` impl is **manual** and redacts all key/IV bytes. This matches
/// the security pattern of [`SessionKeys`](crate::session_keys::SessionKeys):
/// `println!("{:?}", km)` is safe and will not leak cryptographic material
/// to logs, tracing subscribers, or error reporters.
#[derive(Clone)]
pub struct TlcpKeyMaterial {
    /// Client write MAC key (SM3, 32 bytes)
    pub client_mac_key: Vec<u8>,
    /// Server write MAC key (SM3, 32 bytes)
    pub server_mac_key: Vec<u8>,
    /// Client write encryption key (SM4, 16 bytes)
    pub client_enc_key: Vec<u8>,
    /// Server write encryption key (SM4, 16 bytes)
    pub server_enc_key: Vec<u8>,
    /// Client write IV — 16 bytes for CBC explicit IV, 4 bytes for GCM fixed salt.
    pub client_iv: Vec<u8>,
    /// Server write IV — 16 bytes for CBC explicit IV, 4 bytes for GCM fixed salt.
    pub server_iv: Vec<u8>,
}

impl std::fmt::Debug for TlcpKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlcpKeyMaterial")
            .field("client_mac_key_len", &self.client_mac_key.len())
            .field("server_mac_key_len", &self.server_mac_key.len())
            .field("client_enc_key_len", &self.client_enc_key.len())
            .field("server_enc_key_len", &self.server_enc_key.len())
            .field("client_iv_len", &self.client_iv.len())
            .field("server_iv_len", &self.server_iv.len())
            .finish_non_exhaustive()
    }
}

impl Drop for TlcpKeyMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_mac_key.zeroize();
        self.server_mac_key.zeroize();
        self.client_enc_key.zeroize();
        self.server_enc_key.zeroize();
        self.client_iv.zeroize();
        self.server_iv.zeroize();
    }
}

impl TlcpKeyMaterial {
    /// Derive key material from master secret using SM3-based PRF
    ///
    /// GB/T 38636-2020 §6.1
    ///
    /// key_block = PRF(master_secret, "key expansion", server_random || client_random)
    ///
    /// For GCM, the per-record nonce is `fixed_iv(4) || explicit_nonce(8)`,
    /// where the explicit nonce is the 8-byte seq number carried in the
    /// record. Per GmSSL's `tls_derive_key_block` / `tls_init_application_keys`
    /// (src/tls.c), the key block for GCM cipher suites is only
    /// `(key_size + 4) * 2 = 40` bytes (16+4 for the client half, 16+4 for
    /// the server half). The fixed_iv is **4 bytes**, not 12.
    ///
    /// SM4-CBC+HMAC: 2×32 MAC + 2×16 keys + 2×16 IVs = 128 bytes
    pub fn derive(
        master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        cipher_suite: TlcpCipherSuite,
    ) -> Result<Self, TlcpError> {
        // key_block seed = server_random || client_random
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(server_random);
        seed.extend_from_slice(client_random);

        let needed = if cipher_suite.gcm {
            // SM4-GCM: 2×16 keys + 2×4 fixed-IVs = 40
            40
        } else {
            // SM4-CBC + SM3 HMAC: 2×32 MAC + 2×16 keys + 2×16 IVs = 128
            128
        };

        let key_block = Self::prf_expand(master_secret, b"key expansion", &seed, needed)?;

        if cipher_suite.gcm {
            // GCM layout (per GmSSL tls.c): client_enc(16) | server_enc(16)
            //                              | client_iv(4) | server_iv(4)
            // The 4-byte fixed IV is concatenated with the 8-byte explicit
            // nonce from the record to form the 12-byte GCM nonce.
            Ok(Self {
                client_mac_key: Vec::new(), // GCM uses AEAD, no separate MAC key
                server_mac_key: Vec::new(),
                client_enc_key: key_block[0..16].to_vec(),
                server_enc_key: key_block[16..32].to_vec(),
                client_iv: key_block[32..36].to_vec(),
                server_iv: key_block[36..40].to_vec(),
            })
        } else {
            // CBC layout: client_mac(32) | server_mac(32) | client_enc(16) | server_enc(16) | client_iv(16) | server_iv(16)
            Ok(Self {
                client_mac_key: key_block[0..32].to_vec(),
                server_mac_key: key_block[32..64].to_vec(),
                client_enc_key: key_block[64..80].to_vec(),
                server_enc_key: key_block[80..96].to_vec(),
                client_iv: key_block[96..112].to_vec(),
                server_iv: key_block[112..128].to_vec(),
            })
        }
    }

    /// SM3-HMAC-based PRF expansion (TLS 1.2 P_hash adapted for SM3)
    ///
    /// Per GmSSL's `tls_prf` (src/tls.c) and RFC 5246 §5, the TLCP PRF is:
    ///
    ///   A(1) = HMAC-SM3(secret, label || seed)
    ///   A(i) = HMAC-SM3(secret, A(i-1))           for i > 1
    ///   P(i) = HMAC-SM3(secret, A(i) || label || seed)
    ///   output = P(1) || P(2) || ...  (truncated to `length`)
    ///
    /// `seed` is the concatenation of the seed halves the caller wants to
    /// bind in (e.g. `client_random || server_random`). Keeping it as a
    /// single concatenated buffer matches the bytes GmSSL feeds into its PRF
    /// in order (`label || seed1 || seed2`).
    ///
    /// This MUST be HMAC-SM3, NOT raw SM3 — a raw-SM3 construction is not a
    /// PRF and would lose HMAC's security properties.
    ///
    /// Made `pub(crate)` so `derive_master_secret` can call it for the
    /// GB/T 38636-2020 §6.1 master_secret derivation.
    pub(crate) fn prf_expand(
        secret: &[u8],
        label: &[u8],
        seed: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, TlcpError> {
        // Defensive bound: every internal caller uses length <= 128 (CBC
        // key block). Cap at 16 KiB to reject pathological inputs like
        // `usize::MAX` that would loop billions of times and exhaust memory.
        //
        // IMPORTANT: this check must happen BEFORE `Vec::with_capacity(length)`
        // below, otherwise with_capacity(usize::MAX) panics from the allocator
        // before we can return a structured error.
        const MAX_PRF_OUTPUT: usize = 16 * 1024;
        if length > MAX_PRF_OUTPUT {
            return Err(TlcpError::HandshakeFailed(format!(
                "prf_expand length {} exceeds limit {}",
                length, MAX_PRF_OUTPUT
            )));
        }

        let mut result = Vec::with_capacity(length);
        let hmac_key = Sm3Hmac::new(secret);

        // Build the full seed message = label || seed. This is what we feed
        // to HMAC for both A(1) and P(i) (modulo the running A(i) prefix).
        let mut label_seed = Vec::with_capacity(label.len() + seed.len());
        label_seed.extend_from_slice(label);
        label_seed.extend_from_slice(seed);

        // A(1) = HMAC(secret, label || seed)
        let mut a = hmac_key
            .compute(&label_seed)
            .map_err(|e| TlcpError::HandshakeFailed(format!("prf A(1): {}", e)))?;

        while result.len() < length {
            // P(i) = HMAC(secret, A(i) || label || seed)
            let mut p_input = Vec::with_capacity(a.len() + label_seed.len());
            p_input.extend_from_slice(&a);
            p_input.extend_from_slice(&label_seed);
            let p = hmac_key
                .compute(&p_input)
                .map_err(|e| TlcpError::HandshakeFailed(format!("prf P(i): {}", e)))?;
            result.extend_from_slice(&p);

            // A(i+1) = HMAC(secret, A(i)) — only computed if we still need more.
            if result.len() < length {
                a = hmac_key
                    .compute(&a)
                    .map_err(|e| TlcpError::HandshakeFailed(format!("prf A(i+1): {}", e)))?;
            }
        }
        result.truncate(length);
        Ok(result)
    }

    /// Convert TLCP key material to SessionKeys for use with GmTlsStream
    ///
    /// This bridges the TLCP key derivation output with the existing
    /// record layer's `SessionKeys` format, enabling TLCP to reuse
    /// the SM4-GCM record protection.
    ///
    /// **GCM nonce construction** (per GmSSL `tls.c`):
    ///
    /// Each per-record nonce is `fixed_iv(4) || seq(8)` = 12 bytes total.
    /// GmSSL stores the 4-byte **fixed IV** in the key block; the
    /// per-record 8-byte **explicit nonce** is the sequence number carried
    /// in the record. GmTLS's `next_nonce` XORs the sequence number into
    /// the **last 8 bytes** of a 12-byte base, so the base for `SessionKeys`
    /// is `[fixed_iv(4) || 0(8)]`.
    pub fn to_session_keys(&self) -> Result<SessionKeys, TlcpError> {
        if self.client_enc_key.len() != 16 || self.server_enc_key.len() != 16 {
            return Err(TlcpError::HandshakeFailed(
                "GCM requires 16-byte keys".to_string(),
            ));
        }
        // GCM fixed_iv is 4 bytes (TLCP key block layout per GmSSL).
        // CBC fixed_iv is 16 bytes — that path is handled by the CBC code
        // in `record.rs`, not by this GCM-only helper.
        if self.client_iv.len() != 4 || self.server_iv.len() != 4 {
            return Err(TlcpError::HandshakeFailed(format!(
                "GCM requires 4-byte fixed IV (got {}/{})",
                self.client_iv.len(),
                self.server_iv.len()
            )));
        }

        // Build the 12-byte nonce base: [fixed_iv(4) || 0(8)]. The record
        // layer XORs the per-record sequence number into the last 8 bytes
        // via `next_nonce` for each send/receive, matching GmSSL's
        // `fixed_iv || explicit_nonce` nonce construction in `tls.c`.
        let mut client_nonce = [0u8; 12];
        let mut server_nonce = [0u8; 12];
        client_nonce[0..4].copy_from_slice(&self.client_iv);
        server_nonce[0..4].copy_from_slice(&self.server_iv);

        Ok(SessionKeys {
            client_key: self.client_enc_key.clone(),
            client_nonce,
            server_key: self.server_enc_key.clone(),
            server_nonce,
        })
    }
}
