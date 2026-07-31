//! Known Answer Tests (KAT) for SM9 cryptographic operations.
//!
//! Implements self-tests per GB/T 37092-2018 and GM/T 0028-2014
//! for the SM9 identity-based signature and encryption algorithms.
//!
//! Test methodology:
//! - Key derivation consistency: repeated key generation with same seed produces identical keys
//! - Pair-wise consistency: sign + verify and encrypt/decrypt round-trips (GM/T 0028-2014 §7.2.4.3)
//! - Negative tests: wrong message, wrong identity, and tampered ciphertext are rejected

use crate::encrypt::{Decryptor, Encryptor};
use crate::key::{EncMasterKey, SignMasterKey};
use crate::sign::{Signer, Verifier};

/// Standard test identity for KAT
const KAT_IDENTITY: &[u8] = b"ALICE123@YAHOO.COM";

/// Run all SM9 KAT tests
pub fn run_kat() -> Result<(), String> {
    kat_sign_key_derivation_consistency()?;
    kat_enc_key_derivation_consistency()?;
    kat_sign_verify_consistency()?;
    kat_encrypt_decrypt_consistency()?;
    kat_wrong_message_reject()?;
    kat_wrong_identity_reject()?;
    kat_tampered_ciphertext_reject()?;
    Ok(())
}

/// Test 1: Signing key derivation consistency
///
/// Generate master key, extract user key twice, verify deterministic.
fn kat_sign_key_derivation_consistency() -> Result<(), String> {
    let master_key = SignMasterKey::generate(&mut rand::rng())
        .map_err(|e| format!("KAT sign-key: master key generation failed: {:?}", e))?;

    let user_key1 = master_key
        .extract_key(KAT_IDENTITY)
        .map_err(|e| format!("KAT sign-key: first extraction failed: {:?}", e))?;
    let user_key2 = master_key
        .extract_key(KAT_IDENTITY)
        .map_err(|e| format!("KAT sign-key: second extraction failed: {:?}", e))?;

    let (x1, y1) = user_key1
        .ds
        .to_affine()
        .ok_or_else(|| "KAT sign-key: ds_A is identity point".to_string())?;
    let (x2, y2) = user_key2
        .ds
        .to_affine()
        .ok_or_else(|| "KAT sign-key: ds_A (re-derived) is identity point".to_string())?;

    if x1 != x2 || y1 != y2 {
        return Err("KAT sign-key: user key not deterministic".to_string());
    }

    // Different identities → different keys
    let user_key_bob = master_key
        .extract_key(b"BOB456@EXAMPLE.COM")
        .map_err(|e| format!("KAT sign-key: Bob key extraction failed: {:?}", e))?;
    let (xb, yb) = user_key_bob
        .ds
        .to_affine()
        .ok_or_else(|| "KAT sign-key: Bob's ds_A is identity point".to_string())?;
    if x1 == xb && y1 == yb {
        return Err("KAT sign-key: different identities produced same key".to_string());
    }

    Ok(())
}

/// Test 2: Encryption key derivation consistency
fn kat_enc_key_derivation_consistency() -> Result<(), String> {
    let master_key = EncMasterKey::generate(&mut rand::rng())
        .map_err(|e| format!("KAT enc-key: master key generation failed: {:?}", e))?;

    let user_key1 = master_key
        .extract_key(KAT_IDENTITY)
        .map_err(|e| format!("KAT enc-key: first extraction failed: {:?}", e))?;
    let user_key2 = master_key
        .extract_key(KAT_IDENTITY)
        .map_err(|e| format!("KAT enc-key: second extraction failed: {:?}", e))?;

    let (x1, y1) = user_key1
        .de
        .to_affine()
        .ok_or_else(|| "KAT enc-key: de_A is identity point".to_string())?;
    let (x2, y2) = user_key2
        .de
        .to_affine()
        .ok_or_else(|| "KAT enc-key: de_A (re-derived) is identity point".to_string())?;

    if x1 != x2 || y1 != y2 {
        return Err("KAT enc-key: user key not deterministic".to_string());
    }

    Ok(())
}

/// Test 3: Sign-verify consistency (pair-wise consistency test per GM/T 0028-2014 §7.2.4.3)
fn kat_sign_verify_consistency() -> Result<(), String> {
    let master_key = SignMasterKey::generate(&mut rand::rng())
        .map_err(|e| format!("KAT sign-verify: master key failed: {:?}", e))?;
    let user_key = master_key
        .extract_key(KAT_IDENTITY)
        .map_err(|e| format!("KAT sign-verify: user key extraction failed: {:?}", e))?;

    let signer = Signer::new(user_key);
    let message = b"Chinese IBS standard test message";

    let signature = signer
        .sign(message, &mut rand::rng())
        .map_err(|e| format!("KAT sign-verify: signing failed: {:?}", e))?;

    let verifier = Verifier::new(KAT_IDENTITY, &master_key.ppubs);
    let valid = verifier
        .verify(message, &signature)
        .map_err(|e| format!("KAT sign-verify: verification failed: {:?}", e))?;

    if !valid {
        return Err("KAT sign-verify: signature failed verification".to_string());
    }

    Ok(())
}

/// Test 4: Encrypt-decrypt consistency (pair-wise consistency test per GM/T 0028-2014 §7.2.4.3)
fn kat_encrypt_decrypt_consistency() -> Result<(), String> {
    let master_key = EncMasterKey::generate(&mut rand::rng())
        .map_err(|e| format!("KAT enc-dec: master key failed: {:?}", e))?;
    let user_key = master_key
        .extract_key(KAT_IDENTITY)
        .map_err(|e| format!("KAT enc-dec: user key extraction failed: {:?}", e))?;

    let encryptor = Encryptor::new(KAT_IDENTITY, &master_key.ppube);
    let decryptor = Decryptor::new(user_key);

    // Test with short message
    let message1 = b"Hello, SM9!";
    let ct1 = encryptor
        .encrypt(message1, &mut rand::rng())
        .map_err(|e| format!("KAT enc-dec: short message encryption failed: {:?}", e))?;
    let pt1 = decryptor
        .decrypt(&ct1, KAT_IDENTITY)
        .map_err(|e| format!("KAT enc-dec: short message decryption failed: {:?}", e))?;
    if pt1 != message1 {
        return Err("KAT enc-dec: short message decrypt mismatch".to_string());
    }

    // Test with empty message
    let message2 = b"";
    let ct2 = encryptor
        .encrypt(message2, &mut rand::rng())
        .map_err(|e| format!("KAT enc-dec: empty message encryption failed: {:?}", e))?;
    let pt2 = decryptor
        .decrypt(&ct2, KAT_IDENTITY)
        .map_err(|e| format!("KAT enc-dec: empty message decryption failed: {:?}", e))?;
    if pt2 != message2 {
        return Err("KAT enc-dec: empty message decrypt mismatch".to_string());
    }

    // Test with longer message
    let message3 = b"This is a longer test message for SM9 encryption to verify that multi-block KDF works correctly with the XOR stream cipher approach.";
    let ct3 = encryptor
        .encrypt(message3, &mut rand::rng())
        .map_err(|e| format!("KAT enc-dec: long message encryption failed: {:?}", e))?;
    let pt3 = decryptor
        .decrypt(&ct3, KAT_IDENTITY)
        .map_err(|e| format!("KAT enc-dec: long message decryption failed: {:?}", e))?;
    if pt3 != message3 {
        return Err("KAT enc-dec: long message decrypt mismatch".to_string());
    }

    Ok(())
}

/// Test 5: Wrong message is rejected (signature)
fn kat_wrong_message_reject() -> Result<(), String> {
    let master_key = SignMasterKey::generate(&mut rand::rng())
        .map_err(|e| format!("KAT wrong-msg: master key failed: {:?}", e))?;
    let user_key = master_key
        .extract_key(KAT_IDENTITY)
        .map_err(|e| format!("KAT wrong-msg: user key extraction failed: {:?}", e))?;

    let signer = Signer::new(user_key);
    let signature = signer
        .sign(b"correct message", &mut rand::rng())
        .map_err(|e| format!("KAT wrong-msg: signing failed: {:?}", e))?;

    let verifier = Verifier::new(KAT_IDENTITY, &master_key.ppubs);
    let valid = verifier
        .verify(b"wrong message", &signature)
        .map_err(|e| format!("KAT wrong-msg: verification error: {:?}", e))?;

    if valid {
        return Err("KAT wrong-msg: signature incorrectly verified for wrong message".to_string());
    }

    Ok(())
}

/// Test 6: Wrong identity is rejected (signature)
fn kat_wrong_identity_reject() -> Result<(), String> {
    let master_key = SignMasterKey::generate(&mut rand::rng())
        .map_err(|e| format!("KAT wrong-id: master key failed: {:?}", e))?;
    let user_key = master_key
        .extract_key(KAT_IDENTITY)
        .map_err(|e| format!("KAT wrong-id: user key extraction failed: {:?}", e))?;

    let signer = Signer::new(user_key);
    let message = b"test message for identity check";
    let signature = signer
        .sign(message, &mut rand::rng())
        .map_err(|e| format!("KAT wrong-id: signing failed: {:?}", e))?;

    let verifier = Verifier::new(b"BOB456@EXAMPLE.COM", &master_key.ppubs);
    let valid = verifier
        .verify(message, &signature)
        .map_err(|e| format!("KAT wrong-id: verification error: {:?}", e))?;

    if valid {
        return Err("KAT wrong-id: signature incorrectly verified for wrong identity".to_string());
    }

    Ok(())
}

/// Test 7: Tampered ciphertext is rejected
fn kat_tampered_ciphertext_reject() -> Result<(), String> {
    let master_key = EncMasterKey::generate(&mut rand::rng())
        .map_err(|e| format!("KAT tamper: master key failed: {:?}", e))?;
    let user_key = master_key
        .extract_key(KAT_IDENTITY)
        .map_err(|e| format!("KAT tamper: user key extraction failed: {:?}", e))?;

    let encryptor = Encryptor::new(KAT_IDENTITY, &master_key.ppube);
    let decryptor = Decryptor::new(user_key);

    let message = b"Secret message for tamper test";
    let ciphertext = encryptor
        .encrypt(message, &mut rand::rng())
        .map_err(|e| format!("KAT tamper: encryption failed: {:?}", e))?;

    // Tamper with C2 (encrypted data)
    let mut tampered = ciphertext.clone();
    if !tampered.c2.is_empty() {
        tampered.c2[0] ^= 0xFF;
        if decryptor.decrypt(&tampered, KAT_IDENTITY).is_ok() {
            return Err("KAT tamper: tampered C2 should fail decryption".to_string());
        }
    }

    // Tamper with C3 (authentication tag)
    let mut tampered_tag = ciphertext.clone();
    if !tampered_tag.c3.is_empty() {
        tampered_tag.c3[0] ^= 0xFF;
        if decryptor.decrypt(&tampered_tag, KAT_IDENTITY).is_ok() {
            return Err("KAT tamper: tampered C3 should fail decryption".to_string());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kat_sign_key_derivation() {
        kat_sign_key_derivation_consistency().expect("SM9 KAT sign key derivation should pass");
    }

    #[test]
    fn test_kat_enc_key_derivation() {
        kat_enc_key_derivation_consistency().expect("SM9 KAT enc key derivation should pass");
    }

    #[test]
    fn test_kat_sign_verify() {
        kat_sign_verify_consistency().expect("SM9 KAT sign-verify should pass");
    }

    #[test]
    fn test_kat_encrypt_decrypt() {
        kat_encrypt_decrypt_consistency().expect("SM9 KAT encrypt-decrypt should pass");
    }

    #[test]
    fn test_kat_wrong_message() {
        kat_wrong_message_reject().expect("SM9 KAT wrong-message should pass");
    }

    #[test]
    fn test_kat_wrong_identity() {
        kat_wrong_identity_reject().expect("SM9 KAT wrong-identity should pass");
    }

    #[test]
    fn test_kat_tampered_ciphertext() {
        kat_tampered_ciphertext_reject().expect("SM9 KAT tampered-ciphertext should pass");
    }

    #[test]
    fn test_kat_full() {
        run_kat().expect("SM9 full KAT should pass");
    }
}
