//! SM2 Key Exchange Protocol (SM2-KEX) implementation
//!
//! Based on GM/T 0003-2012《SM2 椭圆曲线公钥密码算法》
//!
//! # Protocol Overview
//!
//! SM2-KEX allows two parties (A and B) to establish a shared secret key through
//! exchange of ephemeral public keys, without requiring a pre-shared secret.
//!
//! # Example
//!
//! ```rust
//! use gm_crypto::sm2::Sm2KeyPair;
//! use gm_crypto::sm2_kex::KexSession;
//!
//! // Setup: A and B each have long-term key pairs
//! let keypair_a = Sm2KeyPair::generate().unwrap();
//! let keypair_b = Sm2KeyPair::generate().unwrap();
//!
//! // A initiates the exchange
//! let mut session_a = KexSession::new_initiator(&keypair_a, b"user_a").unwrap();
//! let msg1 = session_a.generate_msg1().unwrap();
//!
//! // B processes msg1 and responds (needs A's public key for signature verification)
//! let mut session_b = KexSession::new_responder(&keypair_b, b"user_b").unwrap();
//! let msg2 = session_b.process_msg1(&msg1, keypair_a.public_key()).unwrap();
//!
//! // A processes msg2 and sends confirmation (needs B's public key for signature verification)
//! let msg3 = session_a.process_msg2(&msg2, keypair_b.public_key()).unwrap();
//!
//! // B verifies confirmation and completes
//! session_b.process_msg3(&msg3).unwrap();
//!
//! // Both parties now have the same shared secret
//! let secret_a = session_a.get_result().unwrap().shared_secret;
//! let secret_b = session_b.get_result().unwrap().shared_secret;
//! assert_eq!(secret_a, secret_b);
//! ```

use crate::error::CryptoError;
use crate::sm2::Sm2KeyPair;
use crate::sm3::Sm3Hasher;
use elliptic_curve::{
    Group, PublicKey,
    ops::MulByGenerator,
    sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand_core::{OsRng, RngCore};
use signature::{Signer, Verifier};
use sm2::dsa::{Signature, SigningKey, VerifyingKey};
use sm2::{ProjectivePoint, SecretKey, Sm2};
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

/// User identification length (16 bytes) per GM/T 0003-2012
const USER_ID_LEN: usize = 16;

/// Default user ID per GM/T standard
const DEFAULT_USER_ID: &str = "1234567812345678";

/// Ephemeral key pair for key exchange
#[derive(Clone, ZeroizeOnDrop)]
pub struct EphemeralKeyPair {
    /// Temporary private key r (32 bytes), 1 <= r < n
    pub r: [u8; 32],
    /// Temporary public key R = r·G (64 bytes, uncompressed X || Y)
    pub r_pub: [u8; 64],
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair
    pub fn generate() -> Result<Self, CryptoError> {
        let secret = SecretKey::random(&mut OsRng);
        let r_bytes: [u8; 32] = secret.to_bytes().into();
        let point = ProjectivePoint::mul_by_generator(&secret.to_nonzero_scalar());
        let r_pub = point_to_uncompressed_bytes(&point)?;
        Ok(Self { r: r_bytes, r_pub })
    }

    /// Create from existing private key bytes
    pub fn from_private_key(r: &[u8; 32]) -> Result<Self, CryptoError> {
        let secret = SecretKey::from_bytes(r.as_ref().into()).map_err(|e| {
            CryptoError::Sm2KexError(format!("invalid ephemeral private key: {}", e))
        })?;
        let point = ProjectivePoint::mul_by_generator(&secret.to_nonzero_scalar());
        let r_pub = point_to_uncompressed_bytes(&point)?;
        Ok(Self { r: *r, r_pub })
    }
}

/// SM2 Key Exchange Protocol message
#[derive(Debug, Clone)]
pub struct Sm2KexMessage {
    /// Message type: 1=A→B (initiator), 2=B→A (responder), 3=A→B (confirmation)
    pub msg_type: u8,
    /// Sender user ID (16 bytes)
    pub sender_id: [u8; USER_ID_LEN],
    /// Temporary public key R1 or R2 (64 bytes, used in msg_type 1 and 2)
    pub r_pub: [u8; 64],
    /// Optional signature (64 bytes) - used in msg2 (B→A)
    pub signature: Option<[u8; 64]>,
    /// Confirmation value SA/SB (32 bytes, used in msg_type 3)
    pub confirmation: Option<[u8; 32]>,
}

impl Sm2KexMessage {
    /// Create message type 1 (A → B): initiator request
    pub fn new_initiator(sender_id: [u8; USER_ID_LEN], r1: [u8; 64]) -> Self {
        Self {
            msg_type: 1,
            sender_id,
            r_pub: r1,
            signature: None,
            confirmation: None,
        }
    }

    /// Create message type 2 (B → A): responder with signature
    pub fn new_responder(sender_id: [u8; USER_ID_LEN], r2: [u8; 64], signature: [u8; 64]) -> Self {
        Self {
            msg_type: 2,
            sender_id,
            r_pub: r2,
            signature: Some(signature),
            confirmation: None,
        }
    }

    /// Create message type 3 (A → B): confirmation
    pub fn new_confirmation(sender_id: [u8; USER_ID_LEN], sa: [u8; 32]) -> Self {
        Self {
            msg_type: 3,
            sender_id,
            r_pub: [0u8; 64], // Not used in msg_type 3
            signature: None,
            confirmation: Some(sa),
        }
    }
}

/// Key exchange result containing shared secrets
#[derive(Debug, Clone)]
pub struct Sm2KexResult {
    /// Shared secret K (32 bytes)
    pub shared_secret: [u8; 32],
    /// Session key for subsequent communication (32 bytes)
    pub session_key: [u8; 32],
    /// Confirmation value S (32 bytes)
    pub s: [u8; 32],
}

/// Key exchange protocol state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KexState {
    /// Initial state
    Init,
    /// Waiting for responder message (msg2)
    WaitForResponse,
    /// Waiting for confirmation (msg3)
    WaitForConfirmation,
    /// Key exchange completed successfully
    Completed,
    /// Key exchange failed
    Failed,
}

/// Peer information in key exchange
#[derive(Debug, Clone)]
struct PeerInfo {
    /// Peer user ID
    user_id: [u8; USER_ID_LEN],
    /// Peer ephemeral public key
    peer_r_pub: [u8; 64],
    /// Peer long-term public key for signature verification
    #[allow(dead_code)]
    peer_public_key: PublicKey<Sm2>,
}

/// Key exchange session
pub struct KexSession {
    /// Session ID
    session_id: [u8; 16],
    /// Long-term private key for signing (zeroized on drop)
    private_key: SecretKey,
    /// Long-term public key for signature verification
    #[allow(dead_code)]
    public_key: PublicKey<Sm2>,
    /// User ID
    user_id: [u8; USER_ID_LEN],
    /// Ephemeral key pair
    ephemeral: EphemeralKeyPair,
    /// Current state
    state: KexState,
    /// Peer information
    peer_info: Option<PeerInfo>,
    /// Result of key exchange
    result: Option<Sm2KexResult>,
    /// Role: true = initiator (A), false = responder (B)
    is_initiator: bool,
}

impl Drop for KexSession {
    fn drop(&mut self) {
        // Securely zeroize the private key on drop
        use zeroize::Zeroize;
        let mut key_bytes = self.private_key.to_bytes();
        key_bytes.zeroize();
    }
}

impl KexSession {
    /// Create a new initiator session (A side)
    ///
    /// # Arguments
    /// * `key_pair` - Long-term SM2 key pair for signing
    /// * `user_id` - User identifier (up to 16 bytes)
    pub fn new_initiator(key_pair: &Sm2KeyPair, user_id: &[u8]) -> Result<Self, CryptoError> {
        let user_id = validate_user_id(user_id)?;
        let ephemeral = EphemeralKeyPair::generate()?;
        let mut session_id = [0u8; 16];
        OsRng.fill_bytes(&mut session_id);

        Ok(Self {
            session_id,
            private_key: key_pair.private_key().clone(),
            public_key: *key_pair.public_key(),
            user_id,
            ephemeral,
            state: KexState::Init,
            peer_info: None,
            result: None,
            is_initiator: true,
        })
    }

    /// Create a new responder session (B side)
    ///
    /// # Arguments
    /// * `key_pair` - Long-term SM2 key pair for signing
    /// * `user_id` - User identifier (up to 16 bytes)
    pub fn new_responder(key_pair: &Sm2KeyPair, user_id: &[u8]) -> Result<Self, CryptoError> {
        let user_id = validate_user_id(user_id)?;
        let ephemeral = EphemeralKeyPair::generate()?;
        let mut session_id = [0u8; 16];
        OsRng.fill_bytes(&mut session_id);

        Ok(Self {
            session_id,
            private_key: key_pair.private_key().clone(),
            public_key: *key_pair.public_key(),
            user_id,
            ephemeral,
            state: KexState::Init,
            peer_info: None,
            result: None,
            is_initiator: false,
        })
    }

    /// Get session ID
    #[inline]
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Get current state
    #[inline]
    pub fn state(&self) -> KexState {
        self.state
    }

    /// Get ephemeral public key
    #[inline]
    pub fn ephemeral_public_key(&self) -> [u8; 64] {
        self.ephemeral.r_pub
    }

    /// Get local user ID
    #[inline]
    pub fn user_id(&self) -> [u8; USER_ID_LEN] {
        self.user_id
    }

    /// Get result if key exchange is complete
    #[inline]
    pub fn get_result(&self) -> Option<&Sm2KexResult> {
        self.result.as_ref()
    }

    /// Generate message 1 (A → B): initiator request
    ///
    /// Returns `Sm2KexMessage` containing:
    /// - msg_type = 1
    /// - sender_id (A's user ID)
    /// - r_pub (A's ephemeral public key)
    pub fn generate_msg1(&self) -> Result<Sm2KexMessage, CryptoError> {
        if !self.is_initiator {
            return Err(CryptoError::Sm2KexError(
                "not an initiator session".to_string(),
            ));
        }
        if self.state != KexState::Init {
            return Err(CryptoError::Sm2KexError(
                "invalid state for msg1".to_string(),
            ));
        }

        Ok(Sm2KexMessage::new_initiator(
            self.user_id,
            self.ephemeral.r_pub,
        ))
    }

    /// Process message 1 (B side): validate R1 and prepare response
    ///
    /// # Arguments
    /// * `msg` - Message from initiator (msg_type=1)
    /// * `peer_public_key` - Initiator's long-term public key for signature verification
    ///
    /// # Returns
    /// Message 2 containing B's ephemeral public key and signature
    pub fn process_msg1(
        &mut self,
        msg: &Sm2KexMessage,
        peer_public_key: &PublicKey<Sm2>,
    ) -> Result<Sm2KexMessage, CryptoError> {
        if self.is_initiator {
            return Err(CryptoError::Sm2KexError(
                "not a responder session".to_string(),
            ));
        }
        if self.state != KexState::Init {
            return Err(CryptoError::Sm2KexError(
                "invalid state for msg1 processing".to_string(),
            ));
        }
        if msg.msg_type != 1 {
            return Err(CryptoError::Sm2KexError("expected msg_type=1".to_string()));
        }

        // Validate R1 is on curve
        validate_ephemeral_public_key(&msg.r_pub)?;

        // Store peer info
        self.peer_info = Some(PeerInfo {
            user_id: msg.sender_id,
            peer_r_pub: msg.r_pub,
            peer_public_key: *peer_public_key,
        });

        // Sign (A_ID, B_ID, R1, R2) for message 2
        let signing_key = SigningKey::new(DEFAULT_USER_ID, &self.private_key)
            .map_err(|e| CryptoError::Sm2KexError(format!("signing error: {}", e)))?;

        // Build signed data: A_ID || B_ID || R1 || R2
        let mut signed_data = Vec::with_capacity(USER_ID_LEN * 2 + 64 + 64);
        signed_data.extend_from_slice(&msg.sender_id); // A_ID
        signed_data.extend_from_slice(&self.user_id); // B_ID
        signed_data.extend_from_slice(&msg.r_pub); // R1
        signed_data.extend_from_slice(&self.ephemeral.r_pub); // R2

        let signature: Signature = signing_key.sign(&signed_data);

        self.state = KexState::WaitForConfirmation;

        Ok(Sm2KexMessage::new_responder(
            self.user_id,
            self.ephemeral.r_pub,
            signature.to_bytes(),
        ))
    }

    /// Process message 2 (A side): validate signature and prepare confirmation
    ///
    /// # Arguments
    /// * `msg` - Message from responder (msg_type=2)
    /// * `peer_public_key` - Responder's long-term public key for signature verification
    ///
    /// # Returns
    /// Message 3 containing A's confirmation value
    pub fn process_msg2(
        &mut self,
        msg: &Sm2KexMessage,
        peer_public_key: &PublicKey<Sm2>,
    ) -> Result<Sm2KexMessage, CryptoError> {
        if !self.is_initiator {
            return Err(CryptoError::Sm2KexError(
                "not an initiator session".to_string(),
            ));
        }
        if self.state != KexState::Init {
            return Err(CryptoError::Sm2KexError(
                "invalid state for msg2 processing".to_string(),
            ));
        }
        if msg.msg_type != 2 {
            return Err(CryptoError::Sm2KexError("expected msg_type=2".to_string()));
        }

        let signature = msg
            .signature
            .ok_or_else(|| CryptoError::Sm2KexError("missing signature".to_string()))?;

        // Validate R2 is on curve
        validate_ephemeral_public_key(&msg.r_pub)?;

        // Store peer info
        self.peer_info = Some(PeerInfo {
            user_id: msg.sender_id,
            peer_r_pub: msg.r_pub,
            peer_public_key: *peer_public_key,
        });

        // Verify signature (A_ID, B_ID, R1, R2)
        let verifying_key = VerifyingKey::new(DEFAULT_USER_ID, *peer_public_key)
            .map_err(|e| CryptoError::Sm2KexError(format!("verifying key error: {}", e)))?;

        let mut signed_data = Vec::with_capacity(USER_ID_LEN * 2 + 64 + 64);
        signed_data.extend_from_slice(&self.user_id); // A_ID
        signed_data.extend_from_slice(&msg.sender_id); // B_ID
        signed_data.extend_from_slice(&self.ephemeral.r_pub); // R1
        signed_data.extend_from_slice(&msg.r_pub); // R2

        let sig = Signature::from_bytes(&signature)
            .map_err(|e| CryptoError::Sm2KexError(format!("signature parse error: {}", e)))?;

        verifying_key
            .verify(&signed_data, &sig)
            .map_err(|_| CryptoError::Sm2KexError("signature verification failed".to_string()))?;

        // Compute shared secret and confirmation
        let (shared_secret, s1) = self.compute_shared_secret_and_confirmation(msg.r_pub)?;

        // Derive session key via KDF per GM/T 0003.3 §6.4:
        // session_key = KDF(shared_secret || "session-key", 32)
        // This ensures session_key is cryptographically separated from shared_secret
        let mut session_kdf_input = Vec::with_capacity(32 + 12);
        session_kdf_input.extend_from_slice(&shared_secret);
        session_kdf_input.extend_from_slice(b"session-key");
        let session_key_vec = sm2_kdf(&session_kdf_input, 32)?;
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&session_key_vec);

        // Generate confirmation message
        self.state = KexState::Completed;
        self.result = Some(Sm2KexResult {
            shared_secret,
            session_key,
            s: s1,
        });

        Ok(Sm2KexMessage::new_confirmation(self.user_id, s1))
    }

    /// Process message 3 (B side): validate confirmation and compute shared secret
    ///
    /// # Arguments
    /// * `msg` - Message from initiator (msg_type=3)
    pub fn process_msg3(&mut self, msg: &Sm2KexMessage) -> Result<(), CryptoError> {
        if self.is_initiator {
            return Err(CryptoError::Sm2KexError(
                "not a responder session".to_string(),
            ));
        }
        if self.state != KexState::WaitForConfirmation {
            return Err(CryptoError::Sm2KexError(
                "invalid state for msg3 processing".to_string(),
            ));
        }
        if msg.msg_type != 3 {
            return Err(CryptoError::Sm2KexError("expected msg_type=3".to_string()));
        }

        let peer_info = self
            .peer_info
            .as_ref()
            .ok_or_else(|| CryptoError::Sm2KexError("missing peer info".to_string()))?;

        // Compute V = r_b · R1 and extract coordinates
        let r1_point = parse_uncompressed_point(&peer_info.peer_r_pub)?;
        let self_secret = SecretKey::from_bytes(self.ephemeral.r.as_ref().into()).map_err(|e| {
            CryptoError::Sm2KexError(format!("invalid ephemeral private key: {}", e))
        })?;
        let v_point = r1_point * *self_secret.to_nonzero_scalar();
        let (x, y) = point_xy_bytes(&v_point)?;

        // Compute shared secret K = KDF(x || y || A_ID || B_ID || R1 || R2)
        // Per GM/T 0003.3-2012 §6.4: coordinates first, then IDs, then ephemeral points.
        let mut kdf_input = Vec::with_capacity(64 + USER_ID_LEN * 2 + 128);
        kdf_input.extend_from_slice(&x); // x coordinate
        kdf_input.extend_from_slice(&y); // y coordinate
        kdf_input.extend_from_slice(&peer_info.user_id); // A_ID
        kdf_input.extend_from_slice(&self.user_id); // B_ID
        kdf_input.extend_from_slice(&peer_info.peer_r_pub); // R1 (A's ephemeral)
        kdf_input.extend_from_slice(&self.ephemeral.r_pub); // R2 (B's ephemeral)

        let shared_secret_vec = sm2_kdf(&kdf_input, 32)?;
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&shared_secret_vec);

        // Compute SB for ourselves
        let s2 = self.compute_confirmation_value(&x, &y, &shared_secret)?;

        // Compute what A should have computed: SA_expected = SM3(A_ID || SM3(R1 || R2 || x || y || K))
        let mut inner_input = Vec::with_capacity(64 + 64 + 32 + 32);
        inner_input.extend_from_slice(&peer_info.peer_r_pub); // R1
        inner_input.extend_from_slice(&self.ephemeral.r_pub); // R2
        inner_input.extend_from_slice(&x);
        inner_input.extend_from_slice(&y);
        inner_input.extend_from_slice(&shared_secret);

        let inner_hash = Sm3Hasher::hash(&inner_input)?;

        let mut confirm_input = Vec::with_capacity(USER_ID_LEN + 32);
        confirm_input.extend_from_slice(&peer_info.user_id); // A_ID
        confirm_input.extend_from_slice(&inner_hash);

        let sa_expected = Sm3Hasher::hash(&confirm_input)?;

        let sa = msg
            .confirmation
            .ok_or_else(|| CryptoError::Sm2KexError("missing confirmation".to_string()))?;
        if !bool::from(sa.ct_eq(&sa_expected)) {
            return Err(CryptoError::Sm2KexError(
                "confirmation value mismatch".to_string(),
            ));
        }

        // Derive session key via KDF per GM/T 0003.3 §6.4:
        // session_key = KDF(shared_secret || "session-key", 32)
        // This ensures session_key is cryptographically separated from shared_secret
        let mut session_kdf_input = Vec::with_capacity(32 + 12);
        session_kdf_input.extend_from_slice(&shared_secret);
        session_kdf_input.extend_from_slice(b"session-key");
        let session_key_vec = sm2_kdf(&session_kdf_input, 32)?;
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&session_key_vec);

        self.state = KexState::Completed;
        self.result = Some(Sm2KexResult {
            shared_secret,
            session_key,
            s: s2,
        });

        Ok(())
    }

    /// Compute shared secret and confirmation value
    fn compute_shared_secret_and_confirmation(
        &self,
        peer_r_pub: [u8; 64],
    ) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let peer_info = self
            .peer_info
            .as_ref()
            .ok_or_else(|| CryptoError::Sm2KexError("missing peer info".to_string()))?;

        // Compute V = r_self · R_peer
        let peer_point = parse_uncompressed_point(&peer_r_pub)?;
        let self_secret = SecretKey::from_bytes(self.ephemeral.r.as_ref().into()).map_err(|e| {
            CryptoError::Sm2KexError(format!("invalid ephemeral private key: {}", e))
        })?;
        let self_scalar = self_secret.to_nonzero_scalar();
        let v = peer_point * *self_scalar;
        let (x, y) = point_xy_bytes(&v)?;

        // Compute shared secret KDF input
        // Per GM/T 0003.3-2012 §6.4: KDF(x || y || IDA || IDB || RA || RB)
        let mut kdf_input = Vec::with_capacity(64 + USER_ID_LEN * 2 + 128);
        kdf_input.extend_from_slice(&x); // x coordinate
        kdf_input.extend_from_slice(&y); // y coordinate
        if self.is_initiator {
            kdf_input.extend_from_slice(&self.user_id); // A_ID
            kdf_input.extend_from_slice(&peer_info.user_id); // B_ID
            kdf_input.extend_from_slice(&self.ephemeral.r_pub); // R1 (A's ephemeral)
            kdf_input.extend_from_slice(&peer_r_pub); // R2 (B's ephemeral)
        } else {
            kdf_input.extend_from_slice(&peer_info.user_id); // A_ID
            kdf_input.extend_from_slice(&self.user_id); // B_ID
            kdf_input.extend_from_slice(&peer_info.peer_r_pub); // R1 (A's ephemeral)
            kdf_input.extend_from_slice(&self.ephemeral.r_pub); // R2 (B's ephemeral)
        }

        // KDF to get 32-byte shared secret
        let shared_secret_vec = sm2_kdf(&kdf_input, 32)?;
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&shared_secret_vec);

        // Compute confirmation value
        // SA = SM3(A_ID || SM3(R1 || R2 || x || y || K))
        // SB = SM3(B_ID || SM3(R1 || R2 || x || y || K))
        let (r1, r2) = if self.is_initiator {
            (self.ephemeral.r_pub, peer_r_pub)
        } else {
            (peer_info.peer_r_pub, self.ephemeral.r_pub)
        };
        let inner_hash = compute_inner_hash(&r1, &r2, &x, &y, &shared_secret)?;

        let mut confirm_input = Vec::with_capacity(USER_ID_LEN + 32);
        if self.is_initiator {
            confirm_input.extend_from_slice(&self.user_id); // A_ID
        } else {
            confirm_input.extend_from_slice(&self.user_id); // B_ID
        }
        confirm_input.extend_from_slice(&inner_hash);

        let confirmation = Sm3Hasher::hash(&confirm_input)?;
        let mut confirmation_bytes = [0u8; 32];
        confirmation_bytes.copy_from_slice(&confirmation);

        Ok((shared_secret, confirmation_bytes))
    }

    /// Compute confirmation value given x, y coordinates and shared secret
    fn compute_confirmation_value(
        &self,
        x: &[u8; 32],
        y: &[u8; 32],
        shared_secret: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError> {
        let peer_info = self
            .peer_info
            .as_ref()
            .ok_or_else(|| CryptoError::Sm2KexError("missing peer info".to_string()))?;

        // R1, R2 order depends on role
        let (r1, r2) = if self.is_initiator {
            (self.ephemeral.r_pub, peer_info.peer_r_pub)
        } else {
            (peer_info.peer_r_pub, self.ephemeral.r_pub)
        };

        let inner_hash = compute_inner_hash(&r1, &r2, x, y, shared_secret)?;

        let mut confirm_input = Vec::with_capacity(USER_ID_LEN + 32);
        confirm_input.extend_from_slice(&self.user_id);
        confirm_input.extend_from_slice(&inner_hash);

        let confirmation = Sm3Hasher::hash(&confirm_input)?;
        let mut confirmation_bytes = [0u8; 32];
        confirmation_bytes.copy_from_slice(&confirmation);
        Ok(confirmation_bytes)
    }
}

/// SM2 Key Exchange Protocol handler
pub struct Sm2Kex {
    /// Long-term key pair
    key_pair: Sm2KeyPair,
}

impl Sm2Kex {
    /// Create a new SM2-KEX handler
    pub fn new(key_pair: Sm2KeyPair) -> Self {
        Self { key_pair }
    }

    /// Create initiator session (A side)
    pub fn init_session(&mut self, user_id: &[u8]) -> Result<KexSession, CryptoError> {
        KexSession::new_initiator(&self.key_pair, user_id)
    }

    /// Create responder session (B side)
    pub fn accept_session(&mut self, user_id: &[u8]) -> Result<KexSession, CryptoError> {
        KexSession::new_responder(&self.key_pair, user_id)
    }
}

/// Validate user ID
fn validate_user_id(user_id: &[u8]) -> Result<[u8; USER_ID_LEN], CryptoError> {
    if user_id.is_empty() {
        return Err(CryptoError::Sm2KexError(
            "user ID cannot be empty".to_string(),
        ));
    }
    if user_id.len() > USER_ID_LEN {
        return Err(CryptoError::Sm2KexError(
            "user ID too long (max 16 bytes)".to_string(),
        ));
    }

    let mut id = [0u8; USER_ID_LEN];
    id[..user_id.len()].copy_from_slice(user_id);
    Ok(id)
}

/// Validate ephemeral public key is on SM2 curve (not identity or invalid)
fn validate_ephemeral_public_key(r_pub: &[u8; 64]) -> Result<(), CryptoError> {
    let mut point_bytes = [0u8; 65];
    point_bytes[0] = 0x04;
    point_bytes[1..].copy_from_slice(r_pub);

    let encoded = sm2::EncodedPoint::from_bytes(point_bytes)
        .map_err(|e| CryptoError::Sm2KexError(format!("invalid point encoding: {}", e)))?;

    // Only uncompressed format (0x04 prefix) is allowed
    if encoded.len() != 65 {
        return Err(CryptoError::Sm2KexError(
            "only uncompressed points (65 bytes) supported".to_string(),
        ));
    }

    let point = ProjectivePoint::from_encoded_point(&encoded)
        .into_option()
        .ok_or_else(|| {
            CryptoError::Sm2KexError("point not on curve or invalid encoding".to_string())
        })?;

    if bool::from(point.is_identity()) {
        return Err(CryptoError::Sm2KexError(
            "point cannot be identity element".to_string(),
        ));
    }

    Ok(())
}

/// Parse uncompressed public key bytes (64 bytes) to ProjectivePoint
fn parse_uncompressed_point(r_pub: &[u8; 64]) -> Result<ProjectivePoint, CryptoError> {
    let mut point_bytes = [0u8; 65];
    point_bytes[0] = 0x04;
    point_bytes[1..].copy_from_slice(r_pub);

    let encoded = sm2::EncodedPoint::from_bytes(point_bytes)
        .map_err(|e| CryptoError::Sm2KexError(format!("invalid point: {}", e)))?;

    ProjectivePoint::from_encoded_point(&encoded)
        .into_option()
        .ok_or_else(|| CryptoError::Sm2KexError("point not on SM2 curve".to_string()))
}

/// Convert ProjectivePoint to uncompressed bytes (64 bytes: X || Y)
fn point_to_uncompressed_bytes(p: &ProjectivePoint) -> Result<[u8; 64], CryptoError> {
    let enc = p.to_affine().to_encoded_point(false);
    let bytes = enc.as_bytes();

    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(CryptoError::Sm2KexError(
            "invalid point encoding".to_string(),
        ));
    }

    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[1..65]);
    Ok(out)
}

/// Extract x, y bytes from ProjectivePoint
fn point_xy_bytes(p: &ProjectivePoint) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let enc = p.to_affine().to_encoded_point(false);
    let bytes = enc.as_bytes();

    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(CryptoError::Sm2KexError(
            "invalid point encoding".to_string(),
        ));
    }

    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    Ok((x, y))
}

/// Compute inner hash for confirmation: SM3(R1 || R2 || x || y || K)
fn compute_inner_hash(
    r1: &[u8; 64],
    r2: &[u8; 64],
    x: &[u8; 32],
    y: &[u8; 32],
    k: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    // R1 || R2 || x || y || K
    let mut inner_input = Vec::with_capacity(64 + 64 + 32 + 32);
    inner_input.extend_from_slice(r1); // R1
    inner_input.extend_from_slice(r2); // R2
    inner_input.extend_from_slice(x);
    inner_input.extend_from_slice(y);
    inner_input.extend_from_slice(k);

    let inner_hash = Sm3Hasher::hash(&inner_input)?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&inner_hash);
    Ok(result)
}

/// SM2-KEX Key Derivation Function
///
/// Based on GM/T 0003-2012:
///
/// # Arguments
/// * `z` - Input bytes (concatenation of ID1, ID2, R1, R2, x, y)
/// * `klen` - Desired output length in bytes (max 32)
///
/// # Algorithm
/// 1. ct = 0x00000001
/// 2. For i = 1 to ceil(klen/32):
///    a. ha = SM3(Z || ct)
///    b. ct = ct + 1
///    c. K = K || ha
/// 3. Return `K[0:klen]`
pub fn sm2_kdf(z: &[u8], klen: usize) -> Result<Vec<u8>, CryptoError> {
    if klen == 0 || klen > 32 * 0xFFFFFFFF {
        return Err(CryptoError::Sm2KexError(
            "KDF length out of range".to_string(),
        ));
    }

    let mut k = Vec::with_capacity(klen);
    let mut ct: u32 = 1;

    while k.len() < klen {
        let mut input = Vec::with_capacity(z.len() + 4);
        input.extend_from_slice(z);
        input.extend_from_slice(&ct.to_be_bytes());

        let ha = Sm3Hasher::hash(&input)?;

        let remain = klen - k.len();
        let copy_len = std::cmp::min(32, remain);
        k.extend_from_slice(&ha[..copy_len]);

        ct = ct
            .checked_add(1)
            .ok_or_else(|| CryptoError::Sm2KexError("KDF overflow".to_string()))?;
    }

    k.truncate(klen);
    Ok(k)
}

/// Compute confirmation value for key exchange
///
/// SA = SM3(A_ID || SM3(R1 || R2 || x || y || K))
/// SB = SM3(B_ID || SM3(R1 || R2 || x || y || K))
#[allow(clippy::too_many_arguments)]
pub fn compute_confirmation(
    sender_id: &[u8; USER_ID_LEN],
    r1: &[u8; 64],
    r2: &[u8; 64],
    x: &[u8; 32],
    y: &[u8; 32],
    k: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let mut inner_input = Vec::with_capacity(64 + 64 + 32 + 32);
    inner_input.extend_from_slice(r1);
    inner_input.extend_from_slice(r2);
    inner_input.extend_from_slice(x);
    inner_input.extend_from_slice(y);
    inner_input.extend_from_slice(k);

    let inner_hash = Sm3Hasher::hash(&inner_input)?;

    let mut outer_input = Vec::with_capacity(USER_ID_LEN + 32);
    outer_input.extend_from_slice(sender_id);
    outer_input.extend_from_slice(&inner_hash);

    let confirmation = Sm3Hasher::hash(&outer_input)?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&confirmation);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm2_kdf_basic() {
        let z = b"test";
        let k = sm2_kdf(z, 32).unwrap();
        assert_eq!(k.len(), 32);

        // Different inputs should produce different outputs
        let k2 = sm2_kdf(b"different", 32).unwrap();
        assert_ne!(k, k2);
    }

    #[test]
    fn test_sm2_kdf_different_lengths() {
        let z = b"test-input";
        for len in [1, 16, 31, 32, 64] {
            let k = sm2_kdf(z, len).unwrap();
            assert_eq!(k.len(), len);
        }
    }

    #[test]
    fn test_sm2_kdf_invalid_length() {
        // Length 0 should fail
        assert!(sm2_kdf(b"test", 0).is_err());
    }

    #[test]
    fn test_ephemeral_key_generation() {
        let ek1 = EphemeralKeyPair::generate().unwrap();
        let ek2 = EphemeralKeyPair::generate().unwrap();

        // Each generation should produce unique keys
        assert_ne!(ek1.r, ek2.r);
        assert_ne!(ek1.r_pub, ek2.r_pub);

        // r_pub should be valid uncompressed format (64 bytes)
        assert_eq!(ek1.r_pub.len(), 64);
    }

    #[test]
    fn test_ephemeral_key_from_private_key() {
        let ek = EphemeralKeyPair::generate().unwrap();
        let ek2 = EphemeralKeyPair::from_private_key(&ek.r).unwrap();
        assert_eq!(ek.r, ek2.r);
        assert_eq!(ek.r_pub, ek2.r_pub);
    }

    #[test]
    fn test_user_id_validation() {
        // Valid short ID
        let id = validate_user_id(b"user").unwrap();
        assert_eq!(&id[..4], b"user");

        // Valid exact-length ID
        let id = validate_user_id(b"1234567812345678").unwrap();
        assert_eq!(&id[..], b"1234567812345678");

        // Invalid: too long
        assert!(validate_user_id(b"12345678123456789").is_err());

        // Invalid: empty
        assert!(validate_user_id(b"").is_err());
    }

    #[test]
    fn test_kex_message_creation() {
        let user_id = [0u8; 16];
        let r = [0u8; 64];

        // Message type 1
        let msg1 = Sm2KexMessage::new_initiator(user_id, r);
        assert_eq!(msg1.msg_type, 1);
        assert!(msg1.signature.is_none());
        assert!(msg1.confirmation.is_none());

        // Message type 2
        let sig = [0u8; 64];
        let msg2 = Sm2KexMessage::new_responder(user_id, r, sig);
        assert_eq!(msg2.msg_type, 2);
        assert!(msg2.signature.is_some());
        assert!(msg2.confirmation.is_none());

        // Message type 3
        let sa = [0u8; 32];
        let msg3 = Sm2KexMessage::new_confirmation(user_id, sa);
        assert_eq!(msg3.msg_type, 3);
        assert!(msg3.signature.is_none());
        assert!(msg3.confirmation.is_some());
    }

    #[test]
    fn test_kex_result() {
        let result = Sm2KexResult {
            shared_secret: [1u8; 32],
            session_key: [2u8; 32],
            s: [3u8; 32],
        };
        assert_eq!(result.shared_secret, [1u8; 32]);
        assert_eq!(result.session_key, [2u8; 32]);
        assert_eq!(result.s, [3u8; 32]);
    }

    #[test]
    fn test_kex_state_transitions() {
        assert_eq!(KexState::Init, KexState::Init);
        assert_ne!(KexState::Init, KexState::Completed);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Full SM2-KEX protocol flow test
    #[test]
    fn test_sm2_kex_full_protocol() {
        // Setup: A and B each have long-term key pairs
        let keypair_a = Sm2KeyPair::generate().unwrap();
        let keypair_b = Sm2KeyPair::generate().unwrap();

        // A initiates the exchange
        let mut session_a = KexSession::new_initiator(&keypair_a, b"user_a").unwrap();
        let msg1 = session_a.generate_msg1().unwrap();

        // Verify msg1
        assert_eq!(msg1.msg_type, 1);
        // sender_id is padded with zeros to 16 bytes
        assert_eq!(&msg1.sender_id[..6], *b"user_a");

        // B processes msg1 and responds
        let mut session_b = KexSession::new_responder(&keypair_b, b"user_b").unwrap();
        let msg2 = session_b
            .process_msg1(&msg1, keypair_a.public_key())
            .unwrap();

        // Verify msg2
        assert_eq!(msg2.msg_type, 2);
        assert!(msg2.signature.is_some());

        // A processes msg2 and sends confirmation
        let msg3 = session_a
            .process_msg2(&msg2, keypair_b.public_key())
            .unwrap();

        // Verify msg3
        assert_eq!(msg3.msg_type, 3);
        assert!(msg3.confirmation.is_some());

        // B verifies confirmation and completes
        session_b.process_msg3(&msg3).unwrap();

        // Both parties now have the same shared secret
        let result_a = session_a.get_result().unwrap();
        let result_b = session_b.get_result().unwrap();

        assert_eq!(result_a.shared_secret, result_b.shared_secret);
        assert_eq!(result_a.session_key, result_b.session_key);
        // Note: result_a.s is SA (A's confirmation) and result_b.s is SB (B's confirmation)
        // These are naturally different since SA uses A_ID and SB uses B_ID
        assert_ne!(result_a.s, result_b.s);
    }

    /// Test that signature verification fails with wrong key
    #[test]
    fn test_sm2_kex_signature_verification_fails() {
        let keypair_a = Sm2KeyPair::generate().unwrap();
        let keypair_b = Sm2KeyPair::generate().unwrap();
        let keypair_wrong = Sm2KeyPair::generate().unwrap();

        let mut session_a = KexSession::new_initiator(&keypair_a, b"user_a").unwrap();
        let msg1 = session_a.generate_msg1().unwrap();

        let mut session_b = KexSession::new_responder(&keypair_b, b"user_b").unwrap();
        let msg2 = session_b
            .process_msg1(&msg1, keypair_a.public_key())
            .unwrap();

        // Try to verify with wrong public key - should fail
        let result = session_a.process_msg2(&msg2, keypair_wrong.public_key());
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("signature verification failed"),
            "Expected signature verification error"
        );
    }

    /// Test that confirmation verification fails with wrong value
    #[test]
    fn test_sm2_kex_confirmation_fails() {
        let keypair_a = Sm2KeyPair::generate().unwrap();
        let keypair_b = Sm2KeyPair::generate().unwrap();

        let mut session_a = KexSession::new_initiator(&keypair_a, b"user_a").unwrap();
        let msg1 = session_a.generate_msg1().unwrap();

        let mut session_b = KexSession::new_responder(&keypair_b, b"user_b").unwrap();
        let msg2 = session_b
            .process_msg1(&msg1, keypair_a.public_key())
            .unwrap();

        let msg3 = session_a
            .process_msg2(&msg2, keypair_b.public_key())
            .unwrap();

        // Tamper with confirmation
        let mut tampered_msg = msg3.clone();
        let mut tampered_conf = msg3.confirmation.unwrap();
        tampered_conf[0] ^= 0xFF;
        tampered_msg.confirmation = Some(tampered_conf);

        // Confirmation verification should fail
        let result = session_b.process_msg3(&tampered_msg);
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("confirmation value mismatch"),
            "Expected confirmation mismatch error"
        );
    }

    /// Test state machine transitions
    #[test]
    fn test_kex_state_machine() {
        let keypair_a = Sm2KeyPair::generate().unwrap();
        let keypair_b = Sm2KeyPair::generate().unwrap();

        // Initiator initial state
        let session_a = KexSession::new_initiator(&keypair_a, b"user_a").unwrap();
        assert_eq!(session_a.state(), KexState::Init);

        // Responder initial state
        let session_b = KexSession::new_responder(&keypair_b, b"user_b").unwrap();
        assert_eq!(session_b.state(), KexState::Init);
    }

    /// Test invalid state transitions are rejected
    #[test]
    fn test_invalid_state_transitions() {
        let keypair_a = Sm2KeyPair::generate().unwrap();
        let keypair_b = Sm2KeyPair::generate().unwrap();

        // Try to process msg2 without first processing msg1
        let mut session_a = KexSession::new_initiator(&keypair_a, b"user_a").unwrap();
        let msg2 = Sm2KexMessage::new_responder([0u8; 16], [0u8; 64], [0u8; 64]);

        let result = session_a.process_msg2(&msg2, keypair_b.public_key());
        assert!(result.is_err());

        // Also test responder trying to process msg2 directly
        let mut session_b = KexSession::new_responder(&keypair_b, b"user_b").unwrap();
        let result_b = session_b.process_msg2(&msg2, keypair_a.public_key());
        assert!(result_b.is_err());
    }

    /// Test message type validation
    #[test]
    fn test_invalid_message_type() {
        let keypair_a = Sm2KeyPair::generate().unwrap();
        let keypair_b = Sm2KeyPair::generate().unwrap();

        let mut session_a = KexSession::new_initiator(&keypair_a, b"user_a").unwrap();
        let msg1 = session_a.generate_msg1().unwrap();

        let mut session_b = KexSession::new_responder(&keypair_b, b"user_b").unwrap();
        let _msg2 = session_b
            .process_msg1(&msg1, keypair_a.public_key())
            .unwrap();

        // Create a msg3 but with wrong message type
        let bad_msg = Sm2KexMessage {
            msg_type: 99, // Invalid
            sender_id: [0u8; 16],
            r_pub: [0u8; 64],
            signature: None,
            confirmation: Some([0u8; 32]),
        };

        let result = session_a.process_msg2(&bad_msg, keypair_b.public_key());
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("expected msg_type=2"),
            "Expected msg_type error"
        );
    }
}
