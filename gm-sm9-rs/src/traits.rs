//! SM9 trait implementations for gm-crypto abstract interfaces.
//!
//! Implements the cryptographic trait definitions from `gm_crypto::traits`
//! for SM9 types, enabling backend-agnostic usage.

use gm_crypto::error::CryptoError;
use gm_crypto::traits::{AsymmetricDecrypt, AsymmetricEncrypt, AsymmetricSign, AsymmetricVerify};

use crate::key::SignUserKey;
use crate::{Ciphertext, Decryptor, Encryptor, Signature, Signer, Verifier};
use rand::rng;

// ============================================================================
// SM9 Signature Trait Implementations
// ============================================================================

impl AsymmetricSign for Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut os_rng = rng();
        let sig = self
            .sign(data, &mut os_rng)
            .map_err(|e| CryptoError::Sm9Error(e.to_string()))?;
        Ok(sig.to_bytes())
    }

    fn sign_with_identity(&self, data: &[u8], _identity: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Identity is already embedded in the Signer at construction time;
        // the _identity parameter is ignored.
        let mut os_rng = rng();
        let sig = self
            .sign(data, &mut os_rng)
            .map_err(|e| CryptoError::Sm9Error(e.to_string()))?;
        Ok(sig.to_bytes())
    }
}

impl AsymmetricVerify for Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig =
            Signature::from_bytes(signature).map_err(|e| CryptoError::Sm9Error(e.to_string()))?;
        let valid = self
            .verify(data, &sig)
            .map_err(|e| CryptoError::Sm9Error(e.to_string()))?;
        if valid {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }

    fn verify_with_identity(
        &self,
        data: &[u8],
        signature: &[u8],
        _identity: &[u8],
    ) -> Result<(), CryptoError> {
        // Identity is already embedded in the Verifier at construction time.
        // Delegate to the trait's verify() to get proper type conversion.
        <Self as AsymmetricVerify>::verify(self, data, signature)
    }
}

// ============================================================================
// SM9 Encryption Trait Implementations
// ============================================================================

impl AsymmetricEncrypt for Encryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut os_rng = rng();
        let ct = self
            .encrypt(plaintext, &mut os_rng)
            .map_err(|e| CryptoError::Sm9Error(e.to_string()))?;
        Ok(ct.to_bytes())
    }

    fn encrypt_with_identity(
        &self,
        plaintext: &[u8],
        _identity: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Identity is already embedded in the Encryptor at construction time.
        let mut os_rng = rng();
        let ct = self
            .encrypt(plaintext, &mut os_rng)
            .map_err(|e| CryptoError::Sm9Error(e.to_string()))?;
        Ok(ct.to_bytes())
    }
}

impl AsymmetricDecrypt for Decryptor {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ct =
            Ciphertext::from_bytes(ciphertext).map_err(|e| CryptoError::Sm9Error(e.to_string()))?;
        // Use empty identity as default; prefer decrypt_with_identity for correct behavior
        self.decrypt(&ct, b"")
            .map_err(|e| CryptoError::Sm9Error(e.to_string()))
    }

    fn decrypt_with_identity(
        &self,
        ciphertext: &[u8],
        identity: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let ct =
            Ciphertext::from_bytes(ciphertext).map_err(|e| CryptoError::Sm9Error(e.to_string()))?;
        self.decrypt(&ct, identity)
            .map_err(|e| CryptoError::Sm9Error(e.to_string()))
    }
}

// ============================================================================
// Convenience: SignUserKey-based signer wrapper
// ============================================================================

/// Wrapper that creates a [`Signer`] from a [`SignUserKey`] with an identity,
/// implementing [`AsymmetricSign`] for direct use without explicit `Signer` construction.
pub struct Sm9IdentitySigner {
    signer: Signer,
}

impl Sm9IdentitySigner {
    /// Create a new identity-based signer
    pub fn new(key: SignUserKey, identity: &[u8]) -> Self {
        Self {
            signer: Signer::with_identity(key, identity),
        }
    }
}

impl AsymmetricSign for Sm9IdentitySigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut os_rng = rng();
        let sig = self
            .signer
            .sign(data, &mut os_rng)
            .map_err(|e| CryptoError::Sm9Error(e.to_string()))?;
        Ok(sig.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{EncMasterKey, SignMasterKey};
    use rand::rng;

    #[test]
    fn test_sm9_sign_verify_traits() {
        let mut rng = rng();
        let master = SignMasterKey::generate(&mut rng).unwrap();
        let identity = b"alice@example.com";
        let user_key = master.extract_key(identity).unwrap();

        let signer = Signer::with_identity(user_key, identity);
        let data = b"test message for SM9 trait";

        let signature_bytes = <Signer as AsymmetricSign>::sign(&signer, data).unwrap();
        assert!(!signature_bytes.is_empty());

        let ppubs = &master.ppubs;
        let verifier = Verifier::new(identity, ppubs);
        <Verifier as AsymmetricVerify>::verify(&verifier, data, &signature_bytes).unwrap();
    }

    #[test]
    fn test_sm9_encrypt_decrypt_traits() {
        let mut rng = rng();
        let master = EncMasterKey::generate(&mut rng).unwrap();
        let identity = b"bob@example.com";
        let user_key = master.extract_key(identity).unwrap();

        let ppube = &master.ppube;
        let encryptor = Encryptor::new(identity, ppube);
        let plaintext = b"secret SM9 message";

        let ciphertext_bytes =
            <Encryptor as AsymmetricEncrypt>::encrypt(&encryptor, plaintext).unwrap();
        assert!(!ciphertext_bytes.is_empty());

        let decryptor = Decryptor::new(user_key);
        let decrypted = <Decryptor as AsymmetricDecrypt>::decrypt_with_identity(
            &decryptor,
            &ciphertext_bytes,
            identity,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
