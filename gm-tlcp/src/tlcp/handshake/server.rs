//! TLCP server-side handshake state machine.

use super::state::TlcpHandshakeState;
use crate::error::TlcpError;
use crate::tlcp::constants::TLCP_VERSION_1_0;
use crate::tlcp::messages::{TlcpCertPair, TlcpClientHello, TlcpFinished, TlcpServerHello};
use crate::tlcp::session::{TlcpResumedSession, TlcpSessionCache, generate_session_id};
use crate::tlcp::{TlcpCipherSuite, TlcpKeyMaterial};

/// TLCP server-side handshake context
pub struct TlcpServerHandshake {
    /// Current state
    pub state: TlcpHandshakeState,
    /// Selected cipher suite
    pub cipher_suite: Option<TlcpCipherSuite>,
    /// Server random
    pub server_random: [u8; 32],
    /// Client random (received)
    pub client_random: Option<[u8; 32]>,
    /// Server dual certificates
    pub server_certs: Option<TlcpCertPair>,
    /// Client certificate chain (DER, leaf-first) — populated when the
    /// server sends a CertificateRequest and the client responds with a
    /// `Certificate` handshake message. The first entry is the leaf;
    /// `server_hs.client_certs[0]` is the cert the server uses to
    /// extract the client's SM2 encryption public key for ECDHE PMS
    /// per GB/T 38636-2020 §6.4.6.2 + GM/T 0003.3-2012 §6.1.
    pub client_certs: Vec<Vec<u8>>,
    /// Pre-master secret (computed after key exchange)
    pub pre_master_secret: Option<Vec<u8>>,
    /// Master secret
    pub master_secret: Option<Vec<u8>>,
    /// Handshake transcript (for Finished message)
    pub transcript: Vec<u8>,
    /// Session ID assigned by server (for resumption)
    pub session_id: Vec<u8>,
    /// Whether this is a resumed session
    pub is_resumed: bool,
    /// Resumed session state (if resuming)
    pub resumed_session: Option<TlcpResumedSession>,
    /// Session cache for looking up and storing sessions
    pub session_cache: Option<TlcpSessionCache>,
}

impl TlcpServerHandshake {
    /// Create a new server-side handshake context
    pub fn new() -> Result<Self, TlcpError> {
        let mut random = [0u8; 32];
        let gmt = crate::tlcp::constants::current_gmt_unix_time();
        random[0..4].copy_from_slice(&gmt.to_be_bytes());
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random[4..]);

        Ok(Self {
            state: TlcpHandshakeState::Idle,
            cipher_suite: None,
            server_random: random,
            client_random: None,
            server_certs: None,
            client_certs: Vec::new(),
            pre_master_secret: None,
            master_secret: None,
            transcript: Vec::new(),
            session_id: Vec::new(),
            is_resumed: false,
            resumed_session: None,
            session_cache: None,
        })
    }

    /// Create a new server-side handshake context with a session cache
    ///
    /// The cache enables session resumption: when a client sends a session_id
    /// that matches a cached session, the server can skip the full handshake.
    pub fn with_session_cache(cache: TlcpSessionCache) -> Result<Self, TlcpError> {
        let mut random = [0u8; 32];
        let gmt = crate::tlcp::constants::current_gmt_unix_time();
        random[0..4].copy_from_slice(&gmt.to_be_bytes());
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random[4..]);

        Ok(Self {
            state: TlcpHandshakeState::Idle,
            cipher_suite: None,
            server_random: random,
            client_random: None,
            server_certs: None,
            client_certs: Vec::new(),
            pre_master_secret: None,
            master_secret: None,
            transcript: Vec::new(),
            session_id: Vec::new(),
            is_resumed: false,
            resumed_session: None,
            session_cache: Some(cache),
        })
    }

    /// Process an incoming ClientHello
    ///
    /// If the client sends a session_id that matches a cached session,
    /// sets `is_resumed` to true and stores the resumed session state.
    pub async fn process_client_hello(&mut self, hello: &TlcpClientHello) -> Result<(), TlcpError> {
        if self.state != TlcpHandshakeState::Idle {
            return Err(TlcpError::InvalidState(format!(
                "Expected Idle state, got {:?}",
                self.state
            )));
        }

        // Verify version
        if hello.version != TLCP_VERSION_1_0 {
            return Err(TlcpError::InvalidMessage(format!(
                "Unsupported TLCP version: {:02x?}",
                hello.version
            )));
        }

        self.client_random = Some(hello.random);

        // Check for session resumption
        if !hello.session_id.is_empty() {
            if let Some(cache) = &self.session_cache {
                if let Some(session) = cache.get(&hello.session_id).await {
                    // Validate: cipher suite must match
                    let suite_matches = hello.cipher_suites.contains(&session.cipher_suite);
                    if suite_matches {
                        self.is_resumed = true;
                        self.session_id = hello.session_id.clone();
                        self.resumed_session = Some(session);
                        // Restore cipher suite from cached session
                        self.cipher_suite = Some(
                            self.resumed_session
                                .as_ref()
                                .and_then(|s| TlcpCipherSuite::from_id(s.cipher_suite))
                                .ok_or_else(|| {
                                    TlcpError::HandshakeFailed(
                                        "cached session has unsupported cipher suite".to_string(),
                                    )
                                })?,
                        );
                        self.state = TlcpHandshakeState::HelloSent;
                        // Still append ClientHello to transcript
                        let hello_bytes = hello.to_bytes()?;
                        self.transcript.extend_from_slice(&hello_bytes);
                        return Ok(());
                    }
                }
            }
            // Session not found or expired — fall through to full handshake
            self.session_id = generate_session_id();
        } else {
            // New session — generate session ID
            self.session_id = generate_session_id();
        }

        // Select cipher suite: prefer ECDHE+GCM, then ECDHE+CBC, then ECC+GCM
        let selected = hello
            .cipher_suites
            .iter()
            .find_map(|cs_id| TlcpCipherSuite::from_id(*cs_id));

        let suite = selected
            .ok_or_else(|| TlcpError::HandshakeFailed("No supported cipher suite".to_string()))?;

        self.cipher_suite = Some(suite);
        self.state = TlcpHandshakeState::HelloSent;

        // Append ClientHello to transcript
        let hello_bytes = hello.to_bytes()?;
        self.transcript.extend_from_slice(&hello_bytes);

        Ok(())
    }

    /// Create ServerHello response
    ///
    /// For resumed sessions, returns the matching session_id.
    /// For new sessions, returns a newly generated session_id.
    pub fn create_server_hello(&self) -> Result<TlcpServerHello, TlcpError> {
        if self.state != TlcpHandshakeState::HelloSent {
            return Err(TlcpError::InvalidState(
                "Not in HelloSent state".to_string(),
            ));
        }

        let suite = self
            .cipher_suite
            .ok_or_else(|| TlcpError::HandshakeFailed("No cipher suite selected".to_string()))?;

        Ok(TlcpServerHello {
            version: TLCP_VERSION_1_0,
            random: self.server_random,
            session_id: self.session_id.clone(),
            cipher_suite: suite.id,
            compression_method: 0x00,
        })
    }

    /// Set the server dual certificates
    pub fn set_server_certs(&mut self, certs: TlcpCertPair) {
        self.server_certs = Some(certs);
    }

    /// Record the client certificate chain received in the client's
    /// `Certificate` handshake message (in reply to a server
    /// `CertificateRequest`). Stored in leaf-first order; the leaf
    /// entry is the cert whose SM2 encryption public key is fed into
    /// the ECDHE PMS KDF per GB/T 38636-2020 §6.4.6.2.
    pub fn set_client_certs(&mut self, chain: Vec<Vec<u8>>) {
        self.client_certs = chain;
    }

    /// Complete the key exchange and derive master secret.
    ///
    /// Per GB/T 38636-2020 §6.1, uses the same PRF derivation as the
    /// client side:
    /// ```text
    /// master_secret(48) = PRF(pre_master_secret, "master secret",
    ///                          client_random || server_random)
    /// ```
    ///
    /// Previous code used a single
    /// `SM3(...)` hash which truncated the 112-byte input to 32 bytes.
    pub fn complete_key_exchange(&mut self, pre_master_secret: Vec<u8>) -> Result<(), TlcpError> {
        // State-machine guard: server-side
        // master_secret derivation requires ClientHello to have been
        // processed first.
        if !matches!(
            self.state,
            TlcpHandshakeState::HelloSent | TlcpHandshakeState::KeyExchange
        ) {
            return Err(TlcpError::InvalidState(format!(
                "complete_key_exchange requires HelloSent or KeyExchange \
                 state, got {:?}",
                self.state
            )));
        }

        let cr = self
            .client_random
            .ok_or_else(|| TlcpError::HandshakeFailed("No client random".to_string()))?;

        let master_seed = {
            let mut seed = Vec::with_capacity(64);
            seed.extend_from_slice(&cr);
            seed.extend_from_slice(&self.server_random);
            seed
        };

        // master_secret is 48 bytes per RFC 5246 / GB/T 38636-2020 §6.1
        let mut pms = pre_master_secret;
        let master = TlcpKeyMaterial::prf_expand(&pms, b"master secret", &master_seed, 48)
            .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;

        // Zeroize the temporary PMS / seed buffers
        use zeroize::Zeroize;
        pms.zeroize();
        let mut master_seed = master_seed;
        master_seed.zeroize();

        self.pre_master_secret = None;
        self.master_secret = Some(master);
        self.state = TlcpHandshakeState::KeyExchange;

        Ok(())
    }

    /// Derive key material for the record layer
    pub fn derive_key_material(&self) -> Result<TlcpKeyMaterial, TlcpError> {
        let master = self
            .master_secret
            .as_ref()
            .ok_or_else(|| TlcpError::HandshakeFailed("No master secret".to_string()))?;

        let cr = self
            .client_random
            .ok_or_else(|| TlcpError::HandshakeFailed("No client random".to_string()))?;

        let suite = self
            .cipher_suite
            .ok_or_else(|| TlcpError::HandshakeFailed("No cipher suite".to_string()))?;

        TlcpKeyMaterial::derive(master, &cr, &self.server_random, suite)
    }

    /// Compute the server Finished message
    pub fn compute_server_finished(&self) -> Result<TlcpFinished, TlcpError> {
        let master = self
            .master_secret
            .as_ref()
            .ok_or_else(|| TlcpError::HandshakeFailed("No master secret".to_string()))?;

        TlcpFinished::compute(master, "server finished", &self.transcript)
    }

    /// Verify the client Finished message
    pub fn verify_client_finished(
        &self,
        client_finished: &TlcpFinished,
    ) -> Result<bool, TlcpError> {
        let master = self
            .master_secret
            .as_ref()
            .ok_or_else(|| TlcpError::HandshakeFailed("No master secret".to_string()))?;

        let expected = TlcpFinished::compute(master, "client finished", &self.transcript)?;
        Ok(client_finished.verify(&expected.verify_data))
    }

    /// Mark handshake as established
    pub fn establish(&mut self) {
        self.state = TlcpHandshakeState::Established;
    }

    /// Check if handshake is established
    pub fn is_established(&self) -> bool {
        self.state == TlcpHandshakeState::Established
    }

    /// Save the current session to the session cache for future resumption.
    ///
    /// Should be called after the handshake is established.
    /// Only saves if a session cache was provided via `with_session_cache()`.
    pub async fn save_session(&self) {
        if let Some(cache) = &self.session_cache {
            if self.session_id.is_empty() {
                return;
            }
            let master = match &self.master_secret {
                Some(m) => m.clone(),
                None => return,
            };
            let suite_id = match &self.cipher_suite {
                Some(s) => s.id,
                None => return,
            };
            let cr = match &self.client_random {
                Some(r) => *r,
                None => return,
            };

            let session = TlcpResumedSession::new(master, suite_id, self.server_random, cr);
            cache.put(self.session_id.clone(), session).await;
        }
    }

    /// Get the session ID assigned by the server.
    ///
    /// The client should cache this ID along with the session state for resumption.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Get a [`TlcpResumedSession`] suitable for client-side caching.
    ///
    /// Returns `None` if the handshake is not yet established or required
    /// fields are missing.
    pub fn to_resumed_session(&self) -> Option<TlcpResumedSession> {
        let master = self.master_secret.as_ref()?.clone();
        let suite_id = self.cipher_suite?.id;
        let cr = self.client_random?;
        let sr = self.server_random;

        Some(TlcpResumedSession::new(master, suite_id, sr, cr))
    }

    /// Check if the current handshake is a resumed (abbreviated) session
    pub fn is_resumed(&self) -> bool {
        self.is_resumed
    }

    /// Cache the current session for future resumption.
    ///
    /// Should be called after a full handshake completes.
    /// Only caches if a session cache was provided via `with_session_cache()`
    /// and the session ID is non-empty.
    pub async fn cache_session(&self) {
        if let Some(cache) = &self.session_cache {
            if self.session_id.is_empty() {
                return;
            }
            if let Some(session) = self.to_resumed_session() {
                cache.put(self.session_id.clone(), session).await;
            }
        }
    }
}
