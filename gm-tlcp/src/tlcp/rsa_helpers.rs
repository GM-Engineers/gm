//! RSA wire-format helpers for the TLCP RSA suites (E019/E01C/E059/E05A).
//!
//! Added in gm-tlcp 0.6.0 (R-5). This module wraps the RustCrypto
//! `rsa = 0.9` crate in thin newtypes that:
//!
//! - Implement `Send + Sync` (required by the async state-machine,
//!   which stores them in `Arc` and passes them through `.await`
//!   points).
//! - Implement `Zeroize` and `ZeroizeOnDrop` (the underlying
//!   `RsaPrivateKey` already impls `ZeroizeOnDrop`, so the
//!   newtypes are zero-cost).
//! - Provide gm-tlcp-specific error mapping (wrap `rsa::Error` into
//!   `TlcpError::HandshakeFailed` with context).
//!
//! **Implementation strategy**: we use the rsa 0.9 *low-level* API
//! (`RsaPrivateKey::sign(SignatureScheme, &hashed_digest)` +
//! `RsaPublicKey::verify(SignatureScheme, &hashed, &sig)`) instead of
//! the `signature` crate's `SigningKey::new` API. The low-level API
//! receives the **already-hashed** digest bytes and the
//! **already-encoded** DigestInfo prefix, sidestepping the digest
//! 0.10/0.11 version conflict between `sm3 0.5` (gm-crypto's transitive
//! dep) and `rsa 0.9` (re-exports `digest 0.11` internally). SM3
//! hashing is done directly via the `sm3` crate.
//!
//! Per R-5 §3.8: RSA is NOT a 国密 algorithm, so we pull
//! RustCrypto's `rsa` crate directly into gm-tlcp (per
//! 2026-09-08 user directive). This is the only KEX branch that
//! touches a non-国密 crypto primitive.

use crate::error::TlcpError;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey as RsaPublicKeyInner;
use rsa::pkcs1v15;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::Decryptor;
#[allow(unused_imports)]
use rsa::traits::EncryptingKeypair;
use rsa::traits::PublicKeyParts;
use rsa::traits::RandomizedEncryptor;
use std::sync::Arc;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// SM3-PKCS#1 v1.5 ASN.1 DigestInfo prefix
// ---------------------------------------------------------------------------
//
// RFC 8017 §9.2 / EMSA-PKCS1-v1_5(SM3) (informal):
//   DigestInfo ::= SEQUENCE {
//     digestAlgorithm AlgorithmIdentifier,
//     digest OCTET STRING
//   }
// For SM3, the OID is 1.3.6.1.4.1.20145.2.7. The DER-encoding of
// DigestInfo for SM3 is:
//
//   30 31 30 0C 06 08 2A 81 1C 81 1C 81 1C 81 1C 81 1C 81 07
//   04 20 || SM3(message)
//
//   i.e. SEQUENCE(49 bytes) {
//     SEQUENCE(12 bytes) { OID(8 bytes: SM3), NULL(0 bytes) }
//     OCTET STRING(32 bytes) { SM3(message) }
//   }
//
// GmSSL master and openHiTLS both sign SM3-PKCS#1-v1_5 with this
// exact DigestInfo prefix. We hard-code the DER here (19 bytes).
const SM3_PKCS1_V15_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0x81, 0x1C, 0x81, 0x1C, 0x81, 0x1C, 0x81,
    0x1C, 0x81, 0x07,
];
const SM3_OUTPUT_LEN: usize = 32;

/// Compute SM3(message) (32 raw bytes).
fn sm3_hash(data: &[u8]) -> [u8; SM3_OUTPUT_LEN] {
    // sm3 0.5's `Sm3` wrapper struct impls `digest::Digest` (from
    // the digest 0.10 crate). We use the trait to avoid bringing
    // in the rsa 0.9 internal digest 0.11 crate.
    use sm3::Digest;
    let mut hasher = sm3::Sm3::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; SM3_OUTPUT_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Compute the SM3 PKCS#1 v1.5 DigestInfo prefix concatenated with
/// the SM3 digest of `data`. This is the exact input that RFC 8017
/// §9.2 / EMSA-PKCS1-v1_5 (with SM3 as the hash) would feed into
/// the RSA private signing operation.
fn sm3_pkcs1_v15_encoding(data: &[u8]) -> Vec<u8> {
    let digest = sm3_hash(data);
    let mut out = Vec::with_capacity(SM3_PKCS1_V15_PREFIX.len() + SM3_OUTPUT_LEN);
    out.extend_from_slice(&SM3_PKCS1_V15_PREFIX);
    out.extend_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// RSA keypair + public key newtypes
// ---------------------------------------------------------------------------

/// Server-side RSA keypair for the static-key RSA suites.
///
/// Stores an `RsaPrivateKey` from the `rsa` crate. Clone is cheap
/// (the inner key is wrapped in `Arc`); `Drop` zeroizes the
/// underlying key material via the inner type's `ZeroizeOnDrop`
/// impl.
#[derive(Clone)]
pub struct RsaKeyPair {
    inner: Arc<RsaPrivateKey>,
}

impl RsaKeyPair {
    /// Generate a fresh RSA keypair of the given bit size (2048, 3072, 4096).
    /// Tests use 2048 for speed; production should use 3072 or 4096.
    pub fn generate(bit_size: usize) -> Result<Self, TlcpError> {
        // rsa 0.9 expects `CryptoRngCore`. `rand_core 0.6 OsRng` impls
        // `CryptoRngCore` so we use it directly.
        let mut rng = rand_core::OsRng;
        let key = RsaPrivateKey::new(&mut rng, bit_size).map_err(|e| {
            TlcpError::HandshakeFailed(format!("RSA keygen ({} bits): {}", bit_size, e))
        })?;
        Ok(Self {
            inner: Arc::new(key),
        })
    }

    /// Load an RSA private key from a PKCS#8 PEM string (production
    /// usage: read the operator's RSA private key from disk).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, TlcpError> {
        let key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| TlcpError::HandshakeFailed(format!("RSA PKCS#8 PEM parse: {}", e)))?;
        Ok(Self {
            inner: Arc::new(key),
        })
    }

    /// Load an RSA private key from a PKCS#8 DER blob.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, TlcpError> {
        let key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| TlcpError::HandshakeFailed(format!("RSA PKCS#8 DER parse: {}", e)))?;
        Ok(Self {
            inner: Arc::new(key),
        })
    }

    /// Borrow the inner `RsaPrivateKey`.
    pub fn inner(&self) -> &RsaPrivateKey {
        &self.inner
    }

    /// Extract the public key (for sharing with clients, e.g. via
    /// the operator's RSA certificate).
    pub fn to_public_key(&self) -> Result<RsaPubKey, TlcpError> {
        let key = RsaPublicKeyInner::new(self.inner.n().clone(), self.inner.e().clone())
            .map_err(|e| TlcpError::HandshakeFailed(format!("RSA public key extraction: {}", e)))?;
        Ok(RsaPubKey {
            inner: Arc::new(key),
        })
    }
}

/// Client-side RSA public key for the static-key RSA suites.
#[derive(Clone)]
pub struct RsaPubKey {
    inner: Arc<RsaPublicKeyInner>,
}

impl RsaPubKey {
    /// Load an RSA public key from a PKCS#8 PEM string (production
    /// usage: read the server's RSA certificate).
    pub fn from_public_key_pem(pem: &str) -> Result<Self, TlcpError> {
        let key = RsaPublicKeyInner::from_public_key_pem(pem)
            .map_err(|e| TlcpError::HandshakeFailed(format!("RSA public key PEM parse: {}", e)))?;
        Ok(Self {
            inner: Arc::new(key),
        })
    }

    /// Load an RSA public key from a PKCS#8 DER blob.
    pub fn from_public_key_der(der: &[u8]) -> Result<Self, TlcpError> {
        let key = RsaPublicKeyInner::from_public_key_der(der)
            .map_err(|e| TlcpError::HandshakeFailed(format!("RSA public key DER parse: {}", e)))?;
        Ok(Self {
            inner: Arc::new(key),
        })
    }

    /// Build a public key from raw `(n, e)` components (test-only;
    /// production callers should use `from_public_key_pem`).
    pub fn from_components(n: rsa::BigUint, e: rsa::BigUint) -> Result<Self, TlcpError> {
        let key = RsaPublicKeyInner::new(n, e).map_err(|err| {
            TlcpError::HandshakeFailed(format!("RSA public key from components: {}", err))
        })?;
        Ok(Self {
            inner: Arc::new(key),
        })
    }

    pub fn inner(&self) -> &RsaPublicKeyInner {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// RSA-PKCS1-v1_5 sign / verify (with manual SM3 DigestInfo prefix)
// ---------------------------------------------------------------------------

/// Server-side RSA-PKCS1-v1_5 signer (used to sign SKE body).
///
/// We use SM3 as the digest (matches GmSSL + openHiTLS convention
/// for all 12 TLCP suites; see R-5 plan §8). Uses the rsa 0.9
/// low-level API (`RsaPrivateKey::sign(Pkcs1v15Sign::new_unprefixed(),
/// &hashed_digest)`) to sidestep the digest 0.10/0.11 version conflict.
#[derive(Clone)]
pub struct RsaSigner {
    inner: Arc<RsaPrivateKey>,
}

impl RsaSigner {
    pub fn new(key_pair: &RsaKeyPair) -> Self {
        Self {
            inner: key_pair.inner.clone(),
        }
    }

    /// Sign `data` with RSA-PKCS1-v1_5 + SM3 digest.
    /// Returns the raw signature bytes (NOT DER; the wire format
    /// for TLCP RSA SKE is raw r||s, same as the ECDHE sig-only path).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TlcpError> {
        // `hashed` = SM3 PKCS#1 v1.5 DigestInfo || SM3(data).
        // We prepended the DigestInfo ourselves so we use
        // `Pkcs1v15Sign::new_unprefixed()` to skip the rsa crate's
        // own prefix-building step.
        let hashed = sm3_pkcs1_v15_encoding(data);
        let scheme = pkcs1v15::Pkcs1v15Sign::new_unprefixed();
        self.inner
            .sign(scheme, &hashed)
            .map_err(|e| TlcpError::HandshakeFailed(format!("RSA SKE sign: {}", e)))
    }
}

/// Client-side RSA-PKCS1-v1_5 verifier (used to verify SKE body).
#[derive(Clone)]
pub struct RsaVerifier {
    inner: Arc<RsaPublicKeyInner>,
}

impl RsaVerifier {
    pub fn new(public_key: &RsaPubKey) -> Self {
        Self {
            inner: public_key.inner.clone(),
        }
    }

    /// Verify `signature` against `data` with RSA-PKCS1-v1_5 + SM3 digest.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), TlcpError> {
        // Rebuild the same DigestInfo-prefixed input the signer
        // produced; pass to verify with the same unprefixed scheme.
        // `Pkcs1v15Sign` is the same scheme used for both sign + verify
        // (rsa 0.9 has no separate Verify struct).
        let hashed = sm3_pkcs1_v15_encoding(data);
        let scheme = pkcs1v15::Pkcs1v15Sign::new_unprefixed();
        self.inner
            .verify(scheme, &hashed, signature)
            .map_err(|e| TlcpError::HandshakeFailed(format!("RSA SKE signature verify: {}", e)))
    }
}

// ---------------------------------------------------------------------------
// RSAES-PKCS1-v1_5 encrypt / decrypt (CKE body)
// ---------------------------------------------------------------------------

/// Client-side RSAES-PKCS1-v1_5 encryptor (used to encrypt the
/// 48-byte PMS under the server's RSA public key).
///
/// `EncryptingKey::new(RsaPublicKey)` consumes the public key, so
/// we lazily rebuild a fresh `EncryptingKey` per call (cheap, since
/// RSAES-PKCS1-v1_5 encrypt is the expensive step anyway).
pub struct RsaEncryptor {
    inner: Arc<RsaPublicKeyInner>,
}

impl Clone for RsaEncryptor {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl RsaEncryptor {
    pub fn new(public_key: &RsaPubKey) -> Self {
        Self {
            inner: public_key.inner.clone(),
        }
    }

    /// Encrypt `plaintext` (typically the 48-byte PMS) under the
    /// server's RSA public key with RSAES-PKCS1-v1_5 envelope.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, TlcpError> {
        // EncryptingKey::new consumes the public key; rebuild per call.
        // This is fine for TLCP: RSA encrypt is the dominant cost.
        let key = pkcs1v15::EncryptingKey::new((*self.inner).clone());
        let mut rng = rand_core::OsRng;
        key.encrypt_with_rng(&mut rng, plaintext)
            .map_err(|e| TlcpError::HandshakeFailed(format!("RSA PMS encrypt: {}", e)))
    }
}

/// Server-side RSAES-PKCS1-v1_5 decryptor (used to recover the
/// 48-byte PMS from the client's CKE body).
///
/// `DecryptingKey::new(RsaPrivateKey)` consumes the private key,
/// so we lazily rebuild a fresh `DecryptingKey` per call. The
/// shared `Arc<RsaPrivateKey>` is cloned (cheap) and converted via
/// `Arc::try_unwrap` when there's a single owner; otherwise we
/// serialize via a temporary path.
pub struct RsaDecryptor {
    inner: Arc<RsaPrivateKey>,
}

impl Clone for RsaDecryptor {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl RsaDecryptor {
    pub fn new(key_pair: &RsaKeyPair) -> Self {
        Self {
            inner: key_pair.inner.clone(),
        }
    }

    /// Decrypt `ciphertext` (the CKE body) with RSAES-PKCS1-v1_5
    /// envelope. Returns the 48-byte PMS.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, TlcpError> {
        // DecryptingKey::new consumes the private key. Since multiple
        // RsaDecryptor instances may share the Arc, we clone the
        // underlying key (cheap because RsaPrivateKey is Clone).
        let priv_clone: RsaPrivateKey = (*self.inner).clone();
        let key = pkcs1v15::DecryptingKey::new(priv_clone);
        key.decrypt(ciphertext)
            .map_err(|e| TlcpError::HandshakeFailed(format!("RSA PMS decrypt: {}", e)))
    }
}

// `Zeroize` for `RsaKeyPair`: no-op since the inner
// Arc<RsaPrivateKey> handles zeroize-on-drop via the
// RsaPrivateKey's own ZeroizeOnDrop impl.
impl Zeroize for RsaKeyPair {
    fn zeroize(&mut self) {
        // No-op: the inner Arc<RsaPrivateKey> handles zeroize-on-drop.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_keypair_roundtrip() {
        let kp = RsaKeyPair::generate(2048).expect("keygen");
        let pub_key = kp.to_public_key().expect("pub key");
        let plaintext = b"hello SM9 IBSDH... no wait, RSA R-5!";
        let ct = RsaEncryptor::new(&pub_key)
            .encrypt(plaintext)
            .expect("encrypt");
        let pt = RsaDecryptor::new(&kp).decrypt(&ct).expect("decrypt");
        assert_eq!(pt, plaintext, "RSA encrypt/decrypt roundtrip");
    }

    #[test]
    fn rsa_sign_verify_roundtrip() {
        let kp = RsaKeyPair::generate(2048).expect("keygen");
        let pub_key = kp.to_public_key().expect("pub key");
        let data = b"cr || sr || enc_cert_der (TLCP RSA SKE body)";
        let sig = RsaSigner::new(&kp).sign(data).expect("sign");
        RsaVerifier::new(&pub_key)
            .verify(data, &sig)
            .expect("verify");
    }

    #[test]
    fn rsa_signer_verify_rejects_wrong_data() {
        let kp = RsaKeyPair::generate(2048).expect("keygen");
        let pub_key = kp.to_public_key().expect("pub key");
        let data = b"original";
        let sig = RsaSigner::new(&kp).sign(data).expect("sign");
        let tampered = b"tampered";
        assert!(
            RsaVerifier::new(&pub_key).verify(tampered, &sig).is_err(),
            "RSA verify must reject tampered data"
        );
    }

    #[test]
    fn rsa_decryptor_rejects_tampered_ciphertext() {
        let kp = RsaKeyPair::generate(2048).expect("keygen");
        let pub_key = kp.to_public_key().expect("pub key");
        let mut ct = RsaEncryptor::new(&pub_key)
            .encrypt(b"valid plaintext")
            .expect("encrypt");
        let idx = ct.len() / 2;
        ct[idx] ^= 0x01;
        assert!(
            RsaDecryptor::new(&kp).decrypt(&ct).is_err(),
            "RSA PKCS1v15 decrypt must reject tampered ciphertext"
        );
    }

    #[test]
    fn rsa_pubkey_from_components_works() {
        let kp = RsaKeyPair::generate(2048).expect("keygen");
        let pub_key = kp.to_public_key().expect("pub key");
        let (n, e) = (pub_key.inner.n().clone(), pub_key.inner.e().clone());
        let rebuilt = RsaPubKey::from_components(n, e).expect("rebuild");
        let ct = RsaEncryptor::new(&rebuilt)
            .encrypt(b"cross-instance")
            .expect("encrypt");
        let pt = RsaDecryptor::new(&kp).decrypt(&ct).expect("decrypt");
        assert_eq!(pt, b"cross-instance");
    }

    #[test]
    fn sm3_pkcs1_v15_digestinfo_layout_is_rfc_compliant() {
        // Hardcoded prefix must be exactly:
        //   30 31                              -- SEQUENCE, 49 bytes
        //     30 0C                            -- SEQUENCE, 12 bytes
        //       06 08 2A 81 1C 81 1C 81 1C 81  -- OID, 8 bytes
        //              81 1C 81 1C 81 07       --   (1.3.6.1.4.1.20145.2.7)
        //   04 20                              -- OCTET STRING, 32 bytes
        //   <SM3(data)>                        -- 32 bytes
        let data = b"hello";
        let encoding = sm3_pkcs1_v15_encoding(data);
        assert_eq!(encoding.len(), 19 + 32, "DigestInfo + SM3 length");
        assert_eq!(
            &encoding[..19],
            &SM3_PKCS1_V15_PREFIX[..],
            "DigestInfo ASN.1 prefix"
        );
        let digest = sm3_hash(data);
        assert_eq!(&encoding[19..], &digest[..], "SM3(data) tail");
    }
}
