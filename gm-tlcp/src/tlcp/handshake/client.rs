//! TLCP client-side handshake state machine.

use super::state::TlcpHandshakeState;
use crate::error::TlcpError;
use crate::session_keys::SessionKeys;
use crate::tlcp::constants::{
    TLCP_VERSION_1_0, TLS_ECC_SM4_CBC_SM3, TLS_ECC_SM4_GCM_SM3, TLS_ECDHE_SM4_CBC_SM3,
    TLS_ECDHE_SM4_GCM_SM3,
};
use crate::tlcp::messages::{TlcpCertPair, TlcpClientHello, TlcpFinished, TlcpServerHello};
use crate::tlcp::session::TlcpResumedSession;
use crate::tlcp::{TlcpCipherSuite, TlcpKeyMaterial};

/// TLCP handshake context (client-side)
pub struct TlcpHandshake {
    /// Current state
    pub state: TlcpHandshakeState,
    /// Selected cipher suite
    pub cipher_suite: Option<[u8; 2]>,
    /// Client random
    pub client_random: [u8; 32],
    /// Server random
    pub server_random: Option<[u8; 32]>,
    /// Server dual certificates
    pub server_certs: Option<TlcpCertPair>,
    /// ECDHE shared secret (computed after key exchange)
    pub pre_master_secret: Option<Vec<u8>>,
    /// Master secret (derived from pre-master secret)
    pub master_secret: Option<Vec<u8>>,
    /// Session ID for resumption (set by client to request resume, or by server in ServerHello)
    pub session_id: Vec<u8>,
    /// Whether this is a resumed session (abbreviated handshake)
    pub is_resumed: bool,
    /// Cached session state for resumption (client-side)
    pub resumed_session: Option<TlcpResumedSession>,
    /// Handshake transcript (for Finished message computation)
    pub transcript: Vec<u8>,
    /// Cipher suites to offer in ClientHello (default: all four TLCP suites)
    pub cipher_suites: Vec<[u8; 2]>,
}

impl Drop for TlcpHandshake {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Zeroize all sensitive cryptographic material on drop
        if let Some(ref mut pms) = self.pre_master_secret {
            pms.zeroize();
        }
        if let Some(ref mut ms) = self.master_secret {
            ms.zeroize();
        }
        self.client_random.zeroize();
        if let Some(ref mut sr) = self.server_random {
            sr.zeroize();
        }
    }
}

impl TlcpHandshake {
    /// Create a new client-side handshake context
    pub fn new_client() -> Result<Self, TlcpError> {
        let mut random = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random);

        Ok(Self {
            state: TlcpHandshakeState::Idle,
            cipher_suite: None,
            client_random: random,
            server_random: None,
            server_certs: None,
            pre_master_secret: None,
            master_secret: None,
            session_id: Vec::new(),
            is_resumed: false,
            resumed_session: None,
            transcript: Vec::new(),
            cipher_suites: vec![
                TLS_ECDHE_SM4_GCM_SM3,
                TLS_ECDHE_SM4_CBC_SM3,
                TLS_ECC_SM4_GCM_SM3,
                TLS_ECC_SM4_CBC_SM3,
            ],
        })
    }

    /// Create a new client-side handshake context with a cached session for resumption
    ///
    /// If the server accepts the session ID, the handshake will be abbreviated
    /// (no ECDHE key exchange, no certificate verification needed).
    pub fn new_client_with_session(session: TlcpResumedSession) -> Result<Self, TlcpError> {
        let mut random = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random);

        let session_id = session.server_random[..16].to_vec(); // Use part of server_random as session_id hint
        // Note: the actual session_id should come from the server's ServerHello
        // Here we use a placeholder derived from the cached session

        Ok(Self {
            state: TlcpHandshakeState::Idle,
            cipher_suite: Some(session.cipher_suite),
            client_random: random,
            server_random: Some(session.server_random),
            server_certs: None,
            pre_master_secret: None,
            master_secret: Some(session.master_secret.clone()),
            session_id,
            is_resumed: false, // Will be set to true if server accepts
            resumed_session: Some(session),
            transcript: Vec::new(),
            cipher_suites: vec![
                TLS_ECDHE_SM4_GCM_SM3,
                TLS_ECDHE_SM4_CBC_SM3,
                TLS_ECC_SM4_GCM_SM3,
                TLS_ECC_SM4_CBC_SM3,
            ],
        })
    }

    /// Create the ClientHello message
    ///
    /// If a cached session is available (set via `new_client_with_session`),
    /// the session_id will be included to request session resumption.
    pub fn create_client_hello(&mut self) -> Result<TlcpClientHello, TlcpError> {
        self.state = TlcpHandshakeState::HelloSent;

        // Build ClientHello using the client_random already stored in this context
        Ok(TlcpClientHello {
            version: TLCP_VERSION_1_0,
            random: self.client_random,
            session_id: self.session_id.clone(),
            cipher_suites: self.cipher_suites.clone(),
            compression_methods: vec![0x00],
            sm2_ephemeral_public: None,
        })
    }

    /// Process the ServerHello
    ///
    /// If the server returns the same session_id we sent, this is a resumed session.
    /// If the server returns a new session_id, a full handshake is required.
    pub fn process_server_hello(&mut self, hello: &TlcpServerHello) -> Result<(), TlcpError> {
        if self.state != TlcpHandshakeState::HelloSent {
            return Err(TlcpError::InvalidHandshakeType(0x02));
        }

        // Verify version
        if hello.version != TLCP_VERSION_1_0 {
            return Err(TlcpError::InvalidMessage(format!(
                "Unsupported TLCP version: {:02x?}",
                hello.version
            )));
        }

        self.server_random = Some(hello.random);
        self.cipher_suite = Some(hello.cipher_suite);

        // Check for session resumption
        if !self.session_id.is_empty() && hello.session_id == self.session_id {
            self.is_resumed = true;
            // For resumed sessions, we can derive keys immediately
            // using the cached master_secret with new randoms
        } else {
            // Server did not accept our session_id — full handshake
            self.is_resumed = false;
            self.session_id = hello.session_id.clone();
        }

        Ok(())
    }

    /// Process server certificates (dual cert)
    pub fn process_server_certs(&mut self, certs: TlcpCertPair) -> Result<(), TlcpError> {
        if self.state != TlcpHandshakeState::HelloSent {
            return Err(TlcpError::InvalidHandshakeType(0x0B));
        }
        self.server_certs = Some(certs);
        self.state = TlcpHandshakeState::ServerCertsReceived;
        Ok(())
    }

    /// Derive master secret from pre-master secret
    ///
    /// Derive master_secret from pre-master secret using SM3-based PRF.
    ///
    /// Per GB/T 38636-2020 §6.1, the master_secret is derived via:
    /// ```text
    /// master_secret(48) = PRF(pre_master_secret, "master secret",
    ///                          client_random || server_random)
    /// ```
    ///
    /// `PRF` is the TLS 1.2-style iterative SM3 expansion (defined as a
    /// private helper `prf_expand` on `TlcpKeyMaterial`).
    ///
    /// **Security note**: do NOT change this to a single `SM3(...)` hash —
    /// that would truncate the 112-byte input (`pms || cr || sr`) to a
    /// 32-byte output, discarding 80 bytes of entropy and violating
    /// GB/T 38636-2020.
    ///
    /// After derivation, the pre-master secret is zeroized as it is no
    /// longer needed.
    pub fn derive_master_secret(&mut self) -> Result<(), TlcpError> {
        // FIX (security audit 2026-08-31): state-machine guard. Master secret
        // can only be derived after ServerHello + ServerCerts have been
        // processed; calling it earlier would silently produce keys from
        // incomplete transcript state.
        if !matches!(
            self.state,
            TlcpHandshakeState::ServerCertsReceived | TlcpHandshakeState::KeyExchange
        ) {
            return Err(TlcpError::InvalidState(format!(
                "derive_master_secret requires ServerCertsReceived or \
                 KeyExchange state, got {:?}",
                self.state
            )));
        }

        let pms = self
            .pre_master_secret
            .as_ref()
            .ok_or_else(|| TlcpError::HandshakeFailed("No pre-master secret".to_string()))?;

        let cr = &self.client_random;
        let sr = self
            .server_random
            .as_ref()
            .ok_or_else(|| TlcpError::HandshakeFailed("No server random".to_string()))?;

        // PRF seed = client_random || server_random (label is added by prf_expand)
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(cr);
        seed.extend_from_slice(sr);

        // master_secret is 48 bytes per RFC 5246 / GB/T 38636-2020 §6.1
        let master = TlcpKeyMaterial::prf_expand(pms, b"master secret", &seed, 48)
            .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;

        // Zeroize pre-master secret — no longer needed after master secret derivation
        if let Some(ref mut pms) = self.pre_master_secret {
            use zeroize::Zeroize;
            pms.zeroize();
        }
        self.pre_master_secret = None;

        // Zeroize the temporary seed buffer
        use zeroize::Zeroize;
        seed.zeroize();

        self.master_secret = Some(master);
        Ok(())
    }

    /// Check if handshake is established
    pub fn is_established(&self) -> bool {
        self.state == TlcpHandshakeState::Established
    }

    /// Get the session ID from the server's ServerHello.
    ///
    /// The client should cache this ID along with the session state for resumption.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Check if the current handshake is a resumed (abbreviated) session
    pub fn is_resumed(&self) -> bool {
        self.is_resumed
    }

    /// Create a [`TlcpResumedSession`] from the current handshake for client-side caching.
    ///
    /// Returns `None` if required fields are missing (e.g., handshake not complete).
    pub fn to_resumed_session(&self) -> Option<TlcpResumedSession> {
        let master = self.master_secret.as_ref()?.clone();
        let suite_id = self.cipher_suite?;
        let sr = self.server_random?;
        let cr = self.client_random;

        Some(TlcpResumedSession::new(master, suite_id, sr, cr))
    }

    /// Compute the client Finished message
    ///
    /// verify_data = SM3(master_secret || SM3(handshake_messages))[0..12]
    /// with label "client finished"
    pub fn compute_client_finished(&self) -> Result<TlcpFinished, TlcpError> {
        let master = self
            .master_secret
            .as_ref()
            .ok_or_else(|| TlcpError::HandshakeFailed("No master secret".to_string()))?;

        TlcpFinished::compute(master, "client finished", &self.transcript)
    }

    /// Compute the server Finished message (client-side verification)
    pub fn compute_server_finished(&self) -> Result<TlcpFinished, TlcpError> {
        let master = self
            .master_secret
            .as_ref()
            .ok_or_else(|| TlcpError::HandshakeFailed("No master secret".to_string()))?;

        TlcpFinished::compute(master, "server finished", &self.transcript)
    }

    /// Verify a server Finished message against our transcript + master_secret.
    ///
    /// This is the protocol's transcript-binding check: the server can only
    /// produce a Finished whose verify_data matches `PRF(master_secret,
    /// "server finished", SM3(transcript))` if it derived the same
    /// master_secret (which depends on the ECDHE shared secret + signed
    /// SKE) AND if the bytes it hashed agree with the bytes we hashed.
    pub fn verify_server_finished(
        &self,
        server_finished: &TlcpFinished,
    ) -> Result<bool, TlcpError> {
        let expected = self.compute_server_finished()?;
        Ok(server_finished.verify(&expected.verify_data))
    }

    /// Derive session keys for a resumed session.
    ///
    /// Uses the cached master secret with the new random values from the
    /// abbreviated handshake. Should only be called when `is_resumed()` is true.
    pub fn derive_resumed_keys(&self) -> Result<SessionKeys, TlcpError> {
        let _session = self
            .resumed_session
            .as_ref()
            .ok_or_else(|| TlcpError::InvalidState("No resumed session".to_string()))?;
        let suite = TlcpCipherSuite::from_id(
            self.cipher_suite
                .ok_or_else(|| TlcpError::InvalidState("No cipher suite".to_string()))?,
        )
        .ok_or_else(|| TlcpError::HandshakeFailed("Unknown cipher suite".to_string()))?;

        // For resumed sessions, derive keys using the cached master_secret
        // with the NEW client_random and server_random from the abbreviated handshake
        let master = self
            .master_secret
            .as_ref()
            .ok_or_else(|| TlcpError::InvalidState("No master secret".to_string()))?;
        let cr = self.client_random;
        let sr = self
            .server_random
            .ok_or_else(|| TlcpError::InvalidState("No server random".to_string()))?;

        let km = TlcpKeyMaterial::derive(master, &cr, &sr, suite)?;
        km.to_session_keys()
    }
}
