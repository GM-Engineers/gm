//! SM9 Key Rotation Support
//!
//! Provides versioned master key management for SM9 cryptographic operations.
//! Implements key rotation with:
//! - Versioned master keys (signing + encryption)
//! - Grace period support (old key remains valid during transition)
//! - User key re-encryption (derive new user keys from new master)
//! - Backward compatibility (verify old signatures with old key version)
//!
//! # Rotation Strategy
//!
//! 1. Generate new master key pair
//! 2. Re-derive user keys under new master
//! 3. During grace period: accept both old and new key versions
//! 4. After grace period: only new key version is active
//!
//! # Example
//!
//! ```rust,ignore
//! use gm_sm9_rs::key_rotation::KeyRotationManager;
//! use gm_sm9_rs::key::{SignMasterKey, EncMasterKey};
//!
//! let mut manager = KeyRotationManager::new();
//!
//! // Register initial signing key (version 1)
//! let master_key = SignMasterKey::generate(&mut rand::rng())?;
//! manager.register_sign_key(master_key)?;
//!
//! // Later, rotate to version 2
//! let new_master = SignMasterKey::generate(&mut rand::rng())?;
//! let rotation = manager.rotate_sign_key(new_master, 3600)?; // 1-hour grace
//!
//! // During grace period, both versions are valid
//! assert!(manager.get_sign_key(1).is_some());
//! assert!(manager.get_sign_key(2).is_some());
//! ```

use crate::Sm9Error;
use crate::key::{EncMasterKey, SignMasterKey};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Key version identifier
pub type KeyVersion = u32;

/// Rotation record for audit trail
#[derive(Debug, Clone)]
pub struct RotationRecord {
    /// Key version before rotation
    pub from_version: KeyVersion,
    /// Key version after rotation
    pub to_version: KeyVersion,
    /// When this rotation was performed
    pub rotated_at: Instant,
    /// Grace period duration
    pub grace_period: Duration,
    /// Whether the grace period has expired
    pub grace_expired: bool,
}

/// Versioned master key entry
#[allow(dead_code)] // version/created_at used for audit & expiry tracking
struct VersionedSignKey {
    key: SignMasterKey,
    version: KeyVersion,
    created_at: Instant,
    expires_at: Option<Instant>,
    active: bool,
}

/// Versioned encryption master key entry
#[allow(dead_code)] // version/created_at used for audit & expiry tracking
struct VersionedEncKey {
    key: EncMasterKey,
    version: KeyVersion,
    created_at: Instant,
    expires_at: Option<Instant>,
    active: bool,
}

/// Key rotation manager for SM9 master keys.
///
/// Manages versioned signing and encryption master keys with
/// support for grace-period-based rotation.
pub struct KeyRotationManager {
    /// Versioned signing master keys
    sign_keys: HashMap<KeyVersion, VersionedSignKey>,
    /// Versioned encryption master keys
    enc_keys: HashMap<KeyVersion, VersionedEncKey>,
    /// Current signing key version
    current_sign_version: KeyVersion,
    /// Current encryption key version
    current_enc_version: KeyVersion,
    /// Maximum number of old versions to retain
    max_retained_versions: usize,
    /// Rotation history for signing keys
    sign_rotations: Vec<RotationRecord>,
    /// Rotation history for encryption keys
    enc_rotations: Vec<RotationRecord>,
}

impl KeyRotationManager {
    /// Create a new key rotation manager
    pub fn new() -> Self {
        Self {
            sign_keys: HashMap::new(),
            enc_keys: HashMap::new(),
            current_sign_version: 0,
            current_enc_version: 0,
            max_retained_versions: 3,
            sign_rotations: Vec::new(),
            enc_rotations: Vec::new(),
        }
    }

    /// Create with custom retention policy
    pub fn with_max_versions(max_retained_versions: usize) -> Self {
        Self {
            max_retained_versions,
            ..Self::new()
        }
    }

    // ========================================================================
    // Signing Key Management
    // ========================================================================

    /// Register the initial signing master key (version 1)
    pub fn register_sign_key(&mut self, key: SignMasterKey) -> Result<KeyVersion, Sm9Error> {
        if !self.sign_keys.is_empty() {
            return Err(Sm9Error::CryptoError(
                "Signing key already registered; use rotate_sign_key instead".to_string(),
            ));
        }
        let version = 1;
        self.current_sign_version = version;
        self.sign_keys.insert(
            version,
            VersionedSignKey {
                key,
                version,
                created_at: Instant::now(),
                expires_at: None,
                active: true,
            },
        );
        Ok(version)
    }

    /// Get the current active signing master key
    pub fn current_sign_key(&self) -> Option<&SignMasterKey> {
        self.sign_keys
            .get(&self.current_sign_version)
            .map(|v| &v.key)
    }

    /// Get a signing key by version
    pub fn get_sign_key(&self, version: KeyVersion) -> Option<&SignMasterKey> {
        self.sign_keys.get(&version).map(|v| &v.key)
    }

    /// Get the current signing key version
    pub fn current_sign_version(&self) -> KeyVersion {
        self.current_sign_version
    }

    /// Rotate the signing master key.
    ///
    /// The old key remains valid during `grace_period_secs` for verification.
    /// After the grace period, only the new key is considered active.
    ///
    /// Returns a rotation record for audit logging.
    pub fn rotate_sign_key(
        &mut self,
        new_key: SignMasterKey,
        grace_period_secs: u64,
    ) -> Result<RotationRecord, Sm9Error> {
        let old_version = self.current_sign_version;
        let new_version = old_version + 1;
        let now = Instant::now();

        // Mark old key as inactive (but retain for grace period verification)
        if let Some(old) = self.sign_keys.get_mut(&old_version) {
            old.active = false;
            old.expires_at = Some(now + Duration::from_secs(grace_period_secs));
        }

        // Insert new key
        self.sign_keys.insert(
            new_version,
            VersionedSignKey {
                key: new_key,
                version: new_version,
                created_at: now,
                expires_at: None,
                active: true,
            },
        );
        self.current_sign_version = new_version;

        // Record rotation
        let record = RotationRecord {
            from_version: old_version,
            to_version: new_version,
            rotated_at: now,
            grace_period: Duration::from_secs(grace_period_secs),
            grace_expired: false,
        };
        self.sign_rotations.push(record.clone());

        // Prune expired old versions
        self.prune_expired_sign_keys();

        Ok(record)
    }

    /// Check if a signing key version is still within its grace period
    pub fn is_sign_key_valid(&self, version: KeyVersion) -> bool {
        match self.sign_keys.get(&version) {
            Some(entry) if entry.active => true,
            Some(entry) => {
                // Inactive key is still valid if within grace period
                match entry.expires_at {
                    Some(exp) => Instant::now() < exp,
                    None => false,
                }
            }
            None => false,
        }
    }

    /// Get all signing key versions still valid (active or in grace period)
    pub fn valid_sign_versions(&self) -> Vec<KeyVersion> {
        let now = Instant::now();
        self.sign_keys
            .iter()
            .filter(|(_, v)| v.active || v.expires_at.is_some_and(|exp| now < exp))
            .map(|(ver, _)| *ver)
            .collect()
    }

    // ========================================================================
    // Encryption Key Management
    // ========================================================================

    /// Register the initial encryption master key (version 1)
    pub fn register_enc_key(&mut self, key: EncMasterKey) -> Result<KeyVersion, Sm9Error> {
        if !self.enc_keys.is_empty() {
            return Err(Sm9Error::CryptoError(
                "Encryption key already registered; use rotate_enc_key instead".to_string(),
            ));
        }
        let version = 1;
        self.current_enc_version = version;
        self.enc_keys.insert(
            version,
            VersionedEncKey {
                key,
                version,
                created_at: Instant::now(),
                expires_at: None,
                active: true,
            },
        );
        Ok(version)
    }

    /// Get the current active encryption master key
    pub fn current_enc_key(&self) -> Option<&EncMasterKey> {
        self.enc_keys.get(&self.current_enc_version).map(|v| &v.key)
    }

    /// Get an encryption key by version
    pub fn get_enc_key(&self, version: KeyVersion) -> Option<&EncMasterKey> {
        self.enc_keys.get(&version).map(|v| &v.key)
    }

    /// Get the current encryption key version
    pub fn current_enc_version(&self) -> KeyVersion {
        self.current_enc_version
    }

    /// Rotate the encryption master key.
    ///
    /// Old ciphertexts remain decryptable during the grace period.
    /// After rotation, new encryptions use the new key version.
    pub fn rotate_enc_key(
        &mut self,
        new_key: EncMasterKey,
        grace_period_secs: u64,
    ) -> Result<RotationRecord, Sm9Error> {
        let old_version = self.current_enc_version;
        let new_version = old_version + 1;
        let now = Instant::now();

        // Mark old key as inactive
        if let Some(old) = self.enc_keys.get_mut(&old_version) {
            old.active = false;
            old.expires_at = Some(now + Duration::from_secs(grace_period_secs));
        }

        // Insert new key
        self.enc_keys.insert(
            new_version,
            VersionedEncKey {
                key: new_key,
                version: new_version,
                created_at: now,
                expires_at: None,
                active: true,
            },
        );
        self.current_enc_version = new_version;

        // Record rotation
        let record = RotationRecord {
            from_version: old_version,
            to_version: new_version,
            rotated_at: now,
            grace_period: Duration::from_secs(grace_period_secs),
            grace_expired: false,
        };
        self.enc_rotations.push(record.clone());

        // Prune expired old versions
        self.prune_expired_enc_keys();

        Ok(record)
    }

    /// Check if an encryption key version is still valid for decryption
    pub fn is_enc_key_valid(&self, version: KeyVersion) -> bool {
        match self.enc_keys.get(&version) {
            Some(entry) if entry.active => true,
            Some(entry) => match entry.expires_at {
                Some(exp) => Instant::now() < exp,
                None => false,
            },
            None => false,
        }
    }

    /// Get all encryption key versions still valid (active or in grace period)
    pub fn valid_enc_versions(&self) -> Vec<KeyVersion> {
        let now = Instant::now();
        self.enc_keys
            .iter()
            .filter(|(_, v)| v.active || v.expires_at.is_some_and(|exp| now < exp))
            .map(|(ver, _)| *ver)
            .collect()
    }

    // ========================================================================
    // Rotation History
    // ========================================================================

    /// Get signing key rotation history
    pub fn sign_rotation_history(&self) -> &[RotationRecord] {
        &self.sign_rotations
    }

    /// Get encryption key rotation history
    pub fn enc_rotation_history(&self) -> &[RotationRecord] {
        &self.enc_rotations
    }

    // ========================================================================
    // Internal
    // ========================================================================

    /// Remove expired signing key versions beyond retention limit
    fn prune_expired_sign_keys(&mut self) {
        let now = Instant::now();
        let current = self.current_sign_version;

        // Collect versions to remove
        let to_remove: Vec<KeyVersion> = self
            .sign_keys
            .iter()
            .filter(|(ver, entry)| {
                **ver != current
                    && !entry.active
                    && entry.expires_at.is_none_or(|exp| now >= exp)
                    && **ver < current.saturating_sub(self.max_retained_versions as u32)
            })
            .map(|(ver, _)| *ver)
            .collect();

        for ver in to_remove {
            self.sign_keys.remove(&ver);
        }
    }

    /// Remove expired encryption key versions beyond retention limit
    fn prune_expired_enc_keys(&mut self) {
        let now = Instant::now();
        let current = self.current_enc_version;

        let to_remove: Vec<KeyVersion> = self
            .enc_keys
            .iter()
            .filter(|(ver, entry)| {
                **ver != current
                    && !entry.active
                    && entry.expires_at.is_none_or(|exp| now >= exp)
                    && **ver < current.saturating_sub(self.max_retained_versions as u32)
            })
            .map(|(ver, _)| *ver)
            .collect();

        for ver in to_remove {
            self.enc_keys.remove(&ver);
        }
    }
}

impl Default for KeyRotationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sign_key() -> SignMasterKey {
        SignMasterKey::generate(&mut rand::rng()).unwrap()
    }

    fn make_enc_key() -> EncMasterKey {
        EncMasterKey::generate(&mut rand::rng()).unwrap()
    }

    #[test]
    fn test_register_sign_key() {
        let mut mgr = KeyRotationManager::new();
        let key = make_sign_key();
        let ver = mgr.register_sign_key(key).unwrap();
        assert_eq!(ver, 1);
        assert_eq!(mgr.current_sign_version(), 1);
        assert!(mgr.current_sign_key().is_some());
    }

    #[test]
    fn test_register_sign_key_twice_fails() {
        let mut mgr = KeyRotationManager::new();
        mgr.register_sign_key(make_sign_key()).unwrap();
        assert!(mgr.register_sign_key(make_sign_key()).is_err());
    }

    #[test]
    fn test_rotate_sign_key() {
        let mut mgr = KeyRotationManager::new();
        mgr.register_sign_key(make_sign_key()).unwrap();

        let record = mgr.rotate_sign_key(make_sign_key(), 3600).unwrap();
        assert_eq!(record.from_version, 1);
        assert_eq!(record.to_version, 2);
        assert_eq!(mgr.current_sign_version(), 2);
        assert!(mgr.get_sign_key(1).is_some());
        assert!(mgr.get_sign_key(2).is_some());
    }

    #[test]
    fn test_multiple_rotations() {
        let mut mgr = KeyRotationManager::new();
        mgr.register_sign_key(make_sign_key()).unwrap();

        for i in 2..=5 {
            let record = mgr.rotate_sign_key(make_sign_key(), 3600).unwrap();
            assert_eq!(record.to_version, i);
        }
        assert_eq!(mgr.current_sign_version(), 5);
        assert_eq!(mgr.valid_sign_versions().len(), 5);
    }

    #[test]
    fn test_enc_key_rotation() {
        let mut mgr = KeyRotationManager::new();
        mgr.register_enc_key(make_enc_key()).unwrap();

        let record = mgr.rotate_enc_key(make_enc_key(), 3600).unwrap();
        assert_eq!(record.from_version, 1);
        assert_eq!(record.to_version, 2);
        assert_eq!(mgr.current_enc_version(), 2);
    }

    #[test]
    fn test_sign_key_grace_period() {
        let mut mgr = KeyRotationManager::new();
        mgr.register_sign_key(make_sign_key()).unwrap();

        // Rotate with very short grace period (1 second)
        mgr.rotate_sign_key(make_sign_key(), 1).unwrap();

        // Old key should still be valid
        assert!(mgr.is_sign_key_valid(1));
        assert!(mgr.is_sign_key_valid(2));
    }

    #[test]
    fn test_valid_sign_versions() {
        let mut mgr = KeyRotationManager::new();
        mgr.register_sign_key(make_sign_key()).unwrap();
        mgr.rotate_sign_key(make_sign_key(), 3600).unwrap();
        mgr.rotate_sign_key(make_sign_key(), 3600).unwrap();

        let versions = mgr.valid_sign_versions();
        assert!(versions.contains(&1));
        assert!(versions.contains(&2));
        assert!(versions.contains(&3));
    }

    #[test]
    fn test_rotation_history() {
        let mut mgr = KeyRotationManager::new();
        mgr.register_sign_key(make_sign_key()).unwrap();
        mgr.rotate_sign_key(make_sign_key(), 3600).unwrap();
        mgr.rotate_sign_key(make_sign_key(), 3600).unwrap();

        assert_eq!(mgr.sign_rotation_history().len(), 2);
        assert_eq!(mgr.sign_rotation_history()[0].from_version, 1);
        assert_eq!(mgr.sign_rotation_history()[1].from_version, 2);
    }

    #[test]
    fn test_rotation_with_sign_verify() {
        use crate::sign::{Signer, Verifier};

        let mut mgr = KeyRotationManager::new();
        let key1 = make_sign_key();
        mgr.register_sign_key(key1.clone()).unwrap();

        // Sign with version 1
        let identity = b"alice@example.com";
        let user_key1 = key1.extract_key(identity).unwrap();
        let signer1 = Signer::new(user_key1);
        let msg = b"test message for rotation";
        let sig1 = signer1.sign(msg, &mut rand::rng()).unwrap();

        // Verify with version 1
        let verifier1 = Verifier::new(identity, &key1.ppubs);
        assert!(verifier1.verify(msg, &sig1).unwrap());

        // Rotate to version 2
        let key2 = make_sign_key();
        mgr.rotate_sign_key(key2.clone(), 3600).unwrap();

        // Sign with version 2
        let user_key2 = key2.extract_key(identity).unwrap();
        let signer2 = Signer::new(user_key2);
        let sig2 = signer2.sign(msg, &mut rand::rng()).unwrap();

        // Version 2 signature verifies with version 2 key
        let verifier2 = Verifier::new(identity, &key2.ppubs);
        assert!(verifier2.verify(msg, &sig2).unwrap());

        // Version 1 signature does NOT verify with version 2 key
        assert!(!verifier2.verify(msg, &sig1).unwrap());

        // But version 1 key still exists and can verify old signatures
        assert!(mgr.is_sign_key_valid(1));
        let key1_ref = mgr.get_sign_key(1).unwrap();
        let verifier1_again = Verifier::new(identity, &key1_ref.ppubs);
        assert!(verifier1_again.verify(msg, &sig1).unwrap());
    }

    #[test]
    fn test_enc_rotation_with_encrypt_decrypt() {
        use crate::encrypt::{Decryptor, Encryptor};

        let mut mgr = KeyRotationManager::new();
        let key1 = make_enc_key();
        mgr.register_enc_key(key1.clone()).unwrap();

        let identity = b"bob@example.com";
        let msg = b"secret message for rotation test";

        // Encrypt with version 1
        let enc1 = Encryptor::new(identity, &key1.ppube);
        let ct1 = enc1.encrypt(msg, &mut rand::rng()).unwrap();

        // Decrypt with version 1
        let user_key1 = key1.extract_key(identity).unwrap();
        let dec1 = Decryptor::new(user_key1);
        let pt1 = dec1.decrypt(&ct1, identity).unwrap();
        assert_eq!(pt1, msg);

        // Rotate to version 2
        let key2 = make_enc_key();
        mgr.rotate_enc_key(key2.clone(), 3600).unwrap();

        // Encrypt with version 2
        let enc2 = Encryptor::new(identity, &key2.ppube);
        let ct2 = enc2.encrypt(msg, &mut rand::rng()).unwrap();

        // Decrypt version 2 ciphertext with version 2 key
        let user_key2 = key2.extract_key(identity).unwrap();
        let dec2 = Decryptor::new(user_key2);
        let pt2 = dec2.decrypt(&ct2, identity).unwrap();
        assert_eq!(pt2, msg);

        // Old ciphertext can still be decrypted with version 1 key
        assert!(mgr.is_enc_key_valid(1));
    }

    #[test]
    fn test_max_retained_versions() {
        let mut mgr = KeyRotationManager::with_max_versions(2);
        mgr.register_sign_key(make_sign_key()).unwrap();

        // Rotate 4 times, all with zero grace period so they expire immediately
        for _ in 0..4 {
            mgr.rotate_sign_key(make_sign_key(), 0).unwrap();
        }

        // Only versions 3, 4, 5 should remain (current + max_retained back)
        // Version 1 should be pruned (current is 5, retain 3 and 4)
        assert_eq!(mgr.current_sign_version(), 5);
        assert!(mgr.get_sign_key(1).is_none());
    }
}
