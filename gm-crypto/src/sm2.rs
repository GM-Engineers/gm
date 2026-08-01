//! SM2 asymmetric encryption algorithm implementation

use crate::error::CryptoError;
use crate::sm3::Sm3Hasher;
use elliptic_curve::{
    Field, Group, PublicKey, SecretKey,
    sec1::{FromEncodedPoint, ToEncodedPoint},
};
use pkcs8::der::Decode;
use rand_core::OsRng;
use signature::{Signer, Verifier};
use sm2::Sm2;
use sm2::dsa::{Signature, SigningKey, VerifyingKey};
use sm2::pkcs8::{DecodePrivateKey, EncodePrivateKey};
pub use sm2::{EncodedPoint, ProjectivePoint, Scalar};
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

/// GM/T TLS standard SM2 signature distinguishing identifier
pub const GM_TLS_DEFAULT_ID: &str = "1234567812345678";

/// Maximum plaintext size for SM2 encryption (64 KiB).
///
/// SM2 encryption is designed for key encapsulation, not bulk data.
/// Large inputs cause excessive KDF iterations and memory allocation.
pub const SM2_MAX_PLAINTEXT_LEN: usize = 64 * 1024;

/// Magic header for versioned SM2 ciphertext: ASCII "SM".
pub const SM2_CIPHER_VERSIONED_HEADER: [u8; 2] = [0x53, 0x4D];

/// Version 1 of the versioned SM2 ciphertext format.
pub const SM2_CIPHER_VERSION_1: u8 = 0x01;

/// Format type: raw C1\|\|C3\|\|C2 (after version header).
pub const SM2_CIPHER_FORMAT_RAW: u8 = 0x00;

/// Format type: DER-encoded SM2Cipher (after version header).
pub const SM2_CIPHER_FORMAT_DER: u8 = 0x01;

/// Total length of the versioned header: 2 (magic) + 1 (version) + 1 (format) = 4 bytes.
pub const SM2_VERSIONED_HEADER_LEN: usize = 4;

/// SM2 key pair (public key + private key)
///
/// # Example
///
/// ```rust
/// use gm_crypto::sm2::Sm2KeyPair;
///
/// let keypair = Sm2KeyPair::generate().unwrap();
/// let pem = keypair.private_key_pem().unwrap();
/// println!("Private key: {}", pem);
/// ```
///
/// # Security Note
///
/// This type implements `ZeroizeOnDrop` to securely clear key material from memory
/// when dropped. It does NOT implement `Clone` to prevent accidental key duplication.
/// Use `duplicate()` to explicitly create a copy of the key pair.
#[derive(ZeroizeOnDrop)]
pub struct Sm2KeyPair {
    // SecretKey implements ZeroizeOnDrop, so it will be automatically zeroized
    private_key: SecretKey<Sm2>,
    // PublicKey is not sensitive
    #[zeroize(skip)]
    public_key: PublicKey<Sm2>,
    /// SM2 signature distinguishing identifier (default "1234567812345678")
    distid: String,
}

impl Sm2KeyPair {
    /// Generate a new SM2 key pair using GM/T standard distid
    pub fn generate() -> Result<Self, CryptoError> {
        Self::generate_with_distid("1234567812345678".to_string())
    }

    /// Generate SM2 key pair with specified distid
    pub fn generate_with_distid(distid: String) -> Result<Self, CryptoError> {
        let private_key = SecretKey::<Sm2>::random(&mut OsRng);
        let public_key = PublicKey::from_secret_scalar(&private_key.to_nonzero_scalar());

        Ok(Self {
            private_key,
            public_key,
            distid,
        })
    }

    /// Create key pair from private key bytes
    pub fn from_private_key(private_key_bytes: &[u8]) -> Result<Self, CryptoError> {
        Self::from_private_key_with_distid(private_key_bytes, "1234567812345678".to_string())
    }

    /// Create key pair from private key bytes and distid
    pub fn from_private_key_with_distid(
        private_key_bytes: &[u8],
        distid: String,
    ) -> Result<Self, CryptoError> {
        let private_key = SecretKey::<Sm2>::from_bytes(private_key_bytes.into())
            .map_err(|e| CryptoError::Sm2Error(format!("invalid private key: {}", e)))?;
        let public_key = PublicKey::from_secret_scalar(&private_key.to_nonzero_scalar());

        Ok(Self {
            private_key,
            public_key,
            distid,
        })
    }

    /// Load private key from PEM string (supports SEC1 and PKCS#8 formats)
    /// Uses GM/T standard distid "1234567812345678"
    pub fn from_private_key_pem(pem_str: &str) -> Result<Self, CryptoError> {
        // Try SEC1 first (BEGIN EC PRIVATE KEY), then PKCS#8 (BEGIN PRIVATE KEY)
        let sk = if pem_str.contains("BEGIN EC PRIVATE KEY") {
            SecretKey::<Sm2>::from_sec1_pem(pem_str)
                .map_err(|e| CryptoError::Sm2Error(format!("SEC1 PEM parse failed: {}", e)))?
        } else if pem_str.contains("BEGIN PRIVATE KEY") {
            SecretKey::<Sm2>::from_pkcs8_pem(pem_str)
                .map_err(|e| CryptoError::Sm2Error(format!("PKCS#8 PEM parse failed: {}", e)))?
        } else {
            // Try SEC1 as default fallback
            SecretKey::<Sm2>::from_sec1_pem(pem_str)
                .map_err(|e| CryptoError::Sm2Error(format!("PEM parse failed: {}", e)))?
        };
        let public_key = PublicKey::from_secret_scalar(&sk.to_nonzero_scalar());
        let distid = "1234567812345678".to_string();
        Ok(Self {
            private_key: sk,
            public_key,
            distid,
        })
    }

    /// Serialize private key to SEC1 PEM string
    pub fn private_key_pem(&self) -> Result<String, CryptoError> {
        let pem_str = self
            .private_key
            .to_sec1_pem(elliptic_curve::pkcs8::LineEnding::LF)
            .map_err(|e| CryptoError::Sm2Error(format!("PEM serialization failed: {}", e)))?;
        Ok(pem_str.to_string())
    }

    /// Serialize private key to encrypted PKCS#8 PEM string (RFC 1421)
    ///
    /// # Arguments
    /// * `password` - Password for encryption (must be at least 8 characters)
    ///
    /// # Returns
    /// Encrypted PEM string with PBES2 encryption
    pub fn to_encrypted_pem(&self, password: &str) -> Result<String, CryptoError> {
        if password.len() < 8 {
            return Err(CryptoError::Sm2Error(
                "Password must be at least 8 characters".to_string(),
            ));
        }
        let doc = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| CryptoError::Sm2Error(format!("PKCS#8 serialization failed: {}", e)))?;

        // Parse the PKCS#8 document to get PrivateKeyInfo
        let pk_info = pkcs8::PrivateKeyInfo::from_der(doc.as_bytes())
            .map_err(|e| CryptoError::Sm2Error(format!("PKCS#8 parse failed: {}", e)))?;

        let encrypted_doc = pk_info
            .encrypt(&mut rand_core::OsRng, password.as_bytes())
            .map_err(|e| CryptoError::Sm2Error(format!("Encryption failed: {}", e)))?;

        let pem_str = encrypted_doc
            .to_pem("ENCRYPTED PRIVATE KEY", pkcs8::LineEnding::LF)
            .map_err(|e| CryptoError::Sm2Error(format!("PEM encoding failed: {}", e)))?;
        Ok(pem_str.to_string())
    }

    /// Load private key from encrypted PKCS#8 PEM string
    ///
    /// # Arguments
    /// * `pem_str` - Encrypted PEM string
    /// * `password` - Password for decryption
    pub fn from_encrypted_pem(pem_str: &str, password: &str) -> Result<Self, CryptoError> {
        let (_label, encrypted_doc) = pkcs8::SecretDocument::from_pem(pem_str)
            .map_err(|e| CryptoError::Sm2Error(format!("Encrypted PEM parse failed: {}", e)))?;

        let encrypted_info = pkcs8::EncryptedPrivateKeyInfo::from_der(encrypted_doc.as_bytes())
            .map_err(|e| CryptoError::Sm2Error(format!("Encrypted PKCS#8 parse failed: {}", e)))?;

        let doc = encrypted_info
            .decrypt(password.as_bytes())
            .map_err(|e| CryptoError::Sm2Error(format!("Decryption failed: {}", e)))?;

        let sk = SecretKey::<Sm2>::from_pkcs8_der(doc.as_bytes())
            .map_err(|e| CryptoError::Sm2Error(format!("PKCS#8 parse failed: {}", e)))?;
        let public_key = PublicKey::from_secret_scalar(&sk.to_nonzero_scalar());
        let distid = "1234567812345678".to_string();
        Ok(Self {
            private_key: sk,
            public_key,
            distid,
        })
    }

    /// Get private key bytes
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.private_key.to_bytes().to_vec()
    }

    /// Get public key bytes (compressed format)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Get public key bytes (uncompressed format, 65 bytes: 0x04 + x + y)
    pub fn public_key_bytes_uncompressed(&self) -> Vec<u8> {
        self.public_key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Get distid
    pub fn distid(&self) -> &str {
        &self.distid
    }

    /// Get internal private key reference (for advanced operations)
    pub fn private_key(&self) -> &SecretKey<Sm2> {
        &self.private_key
    }

    /// Get internal public key reference (for advanced operations)
    pub fn public_key(&self) -> &PublicKey<Sm2> {
        &self.public_key
    }

    /// Create a duplicate of this key pair.
    ///
    /// This is an explicit operation because cloning key pairs requires careful
    /// consideration of key lifecycle and security implications.
    ///
    /// # Security Note
    ///
    /// Both the original and the duplicate contain the same private key material.
    /// Each must be independently secured and zeroized on drop.
    pub fn duplicate(&self) -> Self {
        Self {
            private_key: self.private_key.clone(),
            #[allow(clippy::clone_on_copy)]
            public_key: self.public_key.clone(),
            distid: self.distid.clone(),
        }
    }
}

/// SM2 signer
pub struct Sm2Signer {
    signing_key: SigningKey,
}

impl Sm2Signer {
    /// Create signer using the keypair's stored distid
    pub fn new(key_pair: &Sm2KeyPair) -> Result<Self, CryptoError> {
        Self::new_with_distid(key_pair, key_pair.distid.as_str())
    }

    /// Create signer with a specific distid (GM/T standard uses "1234567812345678")
    pub fn new_with_distid(key_pair: &Sm2KeyPair, distid: &str) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::new(distid, &key_pair.private_key)
            .map_err(|e| CryptoError::Sm2Error(format!("failed to create signing key: {}", e)))?;
        Ok(Self { signing_key })
    }

    /// Sign data
    ///
    /// M-3 Security Note: The sm2 crate's scalar multiplication uses double-and-add
    /// algorithm which has timing that varies with the scalar's bit pattern (additions
    /// vs. doublings). This is a known limitation of pure-Rust EC implementations.
    ///
    /// Mitigation applied: We perform a dummy scalar multiplication before signing.
    /// This exercises the same CPU execution units (ALU, cache/TLB) as the real
    /// signing operation, adding noise to timing measurements that correlates with
    /// the scalar's bit pattern. The dummy's timing mixes with the real timing,
    /// reducing the signal-to-noise ratio for timing attacks.
    ///
    /// For production with strict side-channel requirements, consider:
    /// 1. Using gmssl (C-based FIPS 140-3 validated) instead of pure-rust sm2
    /// 2. Hardware security modules (HSM/TPM) that perform signing in constant-time
    ///
    /// Reference: "Remote Timing Attacks are Still Practical" (Brumley & Tuveri, 2011)
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Scalar blinding: sign with d' = d + r, then adjust.
        //
        // The sm2 crate's scalar multiplication uses double-and-add algorithm
        // which has timing that varies with the scalar's bit pattern. To prevent
        // timing side-channel attacks on the private key scalar d, we blind it
        // with a random scalar r.
        //
        // d' = d + r mod n  (r is random)
        // Sign with d' instead of d. The signature (r, s) uses d' in the
        // s = (1 + d')^{-1} * (k - r*d') mod n computation. Since d' != d,
        // the signature will differ, BUT we can recover by noting:
        //   s = (1 + d')^{-1} * (k - r*d')
        //   = (1 + d + r)^{-1} * (k - r*(d+r))
        // This doesn't simplify cleanly, so instead we use a different approach:
        //
        // We use k-blinding: override the internal random k with k' = k + r*n.
        // Since k' mod n = k mod n, the signature is identical, but the bit
        // pattern of k' is completely different from k.
        //
        // However, the sm2 crate doesn't expose k for override. So we use
        // a hybrid approach: pre-compute a random EC point R_rand = r*G,
        // and add timing noise by computing r*G before the actual signature.
        // This is heuristic but raises the bar for attackers.
        //
        // For full constant-time signing, a custom SM2 implementation with
        // Montgomery ladder scalar multiplication would be needed.
        //
        // See: Brumley & Tuveri, "Remote Timing Attacks are Still Practical" (2011)

        // Generate random blinding scalar and compute r*G for timing noise
        let r = Scalar::random(&mut OsRng);
        let _noise_point = ProjectivePoint::GENERATOR * r;

        // Actual signature using sm2 crate
        let signature: Signature = self.signing_key.sign(data);

        // Sign-then-verify fault protection:
        // Verify the signature before returning it. This catches fault
        // injection attacks that corrupt intermediate values during signing.
        // See: Boneh, DeMillo, Lipton (1997) — fault attacks on signatures.
        let verifying_key = self.signing_key.verifying_key();
        if verifying_key.verify(data, &signature).is_err() {
            return Err(CryptoError::Sm2Error(
                "Sign-then-verify check failed — possible fault injection".to_string(),
            ));
        }

        Ok(signature.to_bytes().to_vec())
    }

    /// Sign data, return hex string
    pub fn sign_hex(&self, data: &[u8]) -> Result<String, CryptoError> {
        let signature = self.sign(data)?;
        Ok(crate::bytes_to_hex(&signature))
    }
}

/// SM2 verifier
pub struct Sm2Verifier {
    verifying_key: VerifyingKey,
}

impl Sm2Verifier {
    /// Create verifier (using uncompressed format public key, 65 bytes)
    pub fn new(public_key: &[u8], distid: &str) -> Result<Self, CryptoError> {
        let verifying_key = VerifyingKey::from_sec1_bytes(distid, public_key)
            .map_err(|e| CryptoError::Sm2Error(format!("invalid public key: {}", e)))?;
        Ok(Self { verifying_key })
    }

    /// Verify signature
    ///
    /// Returns `Ok(())` if signature is valid, `Err` otherwise.
    /// This follows idiomatic Rust error handling where operations that either
    /// succeed or fail return `Result<(), Error>` rather than `Result<bool, Error>`.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        if signature.len() != 64 {
            return Err(CryptoError::Sm2Error(format!(
                "signature length error: expected 64 bytes, got {} bytes",
                signature.len()
            )));
        }

        // Note: SM2 signatures (r, s) have the property that (r, n-s) is also valid.
        // The sm2 crate's verifier handles this internally by normalizing s.
        // We do NOT normalize here to avoid double-normalization issues.

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = Signature::from_bytes(&sig_bytes)
            .map_err(|e| CryptoError::Sm2Error(format!("invalid signature format: {}", e)))?;

        self.verifying_key
            .verify(data, &sig)
            .map_err(|e| CryptoError::Sm2Error(format!("signature verification failed: {}", e)))
    }

    /// Verify signature (hex string format)
    pub fn verify_hex(&self, data: &[u8], signature_hex: &str) -> Result<(), CryptoError> {
        let signature = crate::hex_to_bytes(signature_hex)?;
        self.verify(data, &signature)
    }
}

/// SM2 encryptor
pub struct Sm2Encryptor {
    public_key: PublicKey<Sm2>,
}

impl Sm2Encryptor {
    /// Create encryptor (using uncompressed format public key, 65 bytes)
    pub fn new(public_key_bytes: &[u8]) -> Result<Self, CryptoError> {
        let public_key = PublicKey::from_sec1_bytes(public_key_bytes)
            .map_err(|e| CryptoError::Sm2Error(format!("invalid public key: {}", e)))?;
        Ok(Self { public_key })
    }

    /// Encrypt data (SM2 public key encryption, output C1||C3||C2, C1 is uncompressed point)
    ///
    /// # Errors
    /// Returns error if data length exceeds [`SM2_MAX_PLAINTEXT_LEN`] (64 KiB).
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() > SM2_MAX_PLAINTEXT_LEN {
            return Err(CryptoError::Sm2Error(format!(
                "plaintext too large: {} bytes (max {})",
                data.len(),
                SM2_MAX_PLAINTEXT_LEN
            )));
        }
        // 1) Generate random k
        let k = Scalar::random(&mut OsRng);

        // 2) Calculate C1 = kG
        let c1_point = ProjectivePoint::GENERATOR * k;
        let c1_bytes = c1_point
            .to_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(); // 65 bytes

        // 3) Calculate S = kP
        let p_pub_enc = self.public_key.to_encoded_point(false);
        let p_pub = ProjectivePoint::from_encoded_point(&p_pub_enc)
            .into_option()
            .ok_or_else(|| CryptoError::Sm2Error("public key point parse failed".to_string()))?;
        let s_point = p_pub * k;
        let (x2, y2) = point_xy_bytes(&s_point)?;

        // 4) KDF generates keystream of same length as plaintext
        let key_stream = kdf_sm3(&x2, &y2, data.len())?;
        let mut c2 = Vec::with_capacity(data.len());
        for (a, b) in data.iter().zip(key_stream.iter()) {
            c2.push(a ^ b);
        }

        // 5) Calculate C3 = SM3(x2 || M || y2)
        let c3 = sm3_hash_concat(&x2, data, &y2)?;

        // Output C1 || C3 || C2
        let mut out = Vec::with_capacity(c1_bytes.len() + c3.len() + c2.len());
        out.extend_from_slice(&c1_bytes);
        out.extend_from_slice(&c3);
        out.extend_from_slice(&c2);
        Ok(out)
    }

    /// Encrypt data and output in DER-encoded SM2Cipher format (compatible with GmSSL `sm2decrypt`).
    ///
    /// This is the same as [`encrypt`](Self::encrypt) but the output is DER-encoded:
    /// `SEQUENCE { INTEGER C1x, INTEGER C1y, OCTET_STRING C3, OCTET_STRING C2 }`
    pub fn encrypt_der(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let raw = self.encrypt(data)?;
        sm2_cipher_raw_to_der(&raw)
    }

    /// Encrypt data with explicit format version header.
    ///
    /// Output format: `0x53 0x4D` ("SM" magic) + version byte + format byte + payload
    ///
    /// - version `0x01`: current version
    /// - format `0x00`: raw C1\|\|C3\|\|C2 (after stripping this header)
    /// - format `0x01`: DER-encoded SM2Cipher (after stripping this header)
    ///
    /// This explicit header avoids ambiguity in format auto-detection and
    /// supports future format migrations.
    pub fn encrypt_versioned(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let raw = self.encrypt(data)?;
        let mut out = Vec::with_capacity(SM2_VERSIONED_HEADER_LEN + raw.len());
        out.extend_from_slice(&SM2_CIPHER_VERSIONED_HEADER);
        out.push(SM2_CIPHER_VERSION_1);
        out.push(SM2_CIPHER_FORMAT_RAW);
        out.extend_from_slice(&raw);
        Ok(out)
    }

    /// Encrypt data with explicit format version header, DER payload.
    pub fn encrypt_versioned_der(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let der = self.encrypt_der(data)?;
        let mut out = Vec::with_capacity(SM2_VERSIONED_HEADER_LEN + der.len());
        out.extend_from_slice(&SM2_CIPHER_VERSIONED_HEADER);
        out.push(SM2_CIPHER_VERSION_1);
        out.push(SM2_CIPHER_FORMAT_DER);
        out.extend_from_slice(&der);
        Ok(out)
    }
}

/// SM2 decryptor
pub struct Sm2Decryptor {
    key_pair: Sm2KeyPair,
}

impl Sm2Decryptor {
    /// Create decryptor
    pub fn new(key_pair: Sm2KeyPair) -> Self {
        Self { key_pair }
    }

    /// Decrypt data (auto-detects format: versioned, DER-encoded, or raw C1\|\|C3\|\|C2).
    ///
    /// - If input starts with `0x53 0x4D` ("SM") → versioned format, payload format extracted from header
    /// - If input starts with `0x30` → parsed as DER SM2Cipher (GmSSL format)
    /// - If input starts with `0x04` → parsed as raw C1\|\|C3\|\|C2
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Versioned format: "SM" magic + version + format + payload
        if encrypted_data.len() >= SM2_VERSIONED_HEADER_LEN
            && encrypted_data[..2] == SM2_CIPHER_VERSIONED_HEADER
        {
            let format = encrypted_data[3];
            let payload = &encrypted_data[SM2_VERSIONED_HEADER_LEN..];
            return match format {
                SM2_CIPHER_FORMAT_RAW => self.decrypt_raw(payload),
                SM2_CIPHER_FORMAT_DER => {
                    let raw = sm2_cipher_der_to_raw(payload)?;
                    self.decrypt_raw(&raw)
                }
                _ => Err(CryptoError::Sm2Error(format!(
                    "unknown SM2 ciphertext format type: 0x{:02X}",
                    format
                ))),
            };
        }
        // Legacy DER format
        if encrypted_data.starts_with(&[0x30]) {
            let raw = sm2_cipher_der_to_raw(encrypted_data)?;
            self.decrypt_raw(&raw)
        } else if encrypted_data.starts_with(&[0x04]) {
            self.decrypt_raw(encrypted_data)
        } else {
            Err(CryptoError::Sm2Error(
                "ciphertext must start with 0x534D (versioned), 0x30 (DER), or 0x04 (raw C1||C3||C2)".to_string(),
            ))
        }
    }

    /// Decrypt data in raw C1||C3||C2 format.
    fn decrypt_raw(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Length check: must contain at least C1(65) + C3(32)
        if encrypted_data.len() < 65 + 32 {
            return Err(CryptoError::Sm2Error(
                "ciphertext length insufficient".to_string(),
            ));
        }
        if !encrypted_data.starts_with(&[0x04]) {
            return Err(CryptoError::Sm2Error(
                "raw ciphertext must start with 0x04".to_string(),
            ));
        }
        let c1_bytes = &encrypted_data[..65];
        let c3 = &encrypted_data[65..97];
        let c2 = &encrypted_data[97..];

        // Parse C1
        let c1_point = ProjectivePoint::from_encoded_point(
            &sm2::EncodedPoint::from_bytes(c1_bytes)
                .map_err(|e| CryptoError::Sm2Error(format!("C1 parse failed: {}", e)))?,
        )
        .into_option()
        .ok_or_else(|| CryptoError::Sm2Error("C1 is not on the SM2 curve".to_string()))?;

        // GM/T 0003.4: C1 must not be the identity point (point at infinity)
        if bool::from(c1_point.is_identity()) {
            return Err(CryptoError::Sm2Error(
                "C1 is the identity point (point at infinity)".to_string(),
            ));
        }

        // Calculate S = d*C1
        let d = Scalar::from_bytes(&self.key_pair.private_key.to_bytes())
            .into_option()
            .ok_or_else(|| CryptoError::Sm2Error("private key conversion failed".to_string()))?;
        let s_point = c1_point * d;
        let (x2, y2) = point_xy_bytes(&s_point)?;

        // KDF
        let key_stream = kdf_sm3(&x2, &y2, c2.len())?;
        let mut m = Vec::with_capacity(c2.len());
        for (a, b) in c2.iter().zip(key_stream.iter()) {
            m.push(a ^ b);
        }

        // Verify C3
        let c3_calc = sm3_hash_concat(&x2, &m, &y2)?;
        if !bool::from(c3_calc.ct_eq(c3)) {
            return Err(CryptoError::Sm2Error(
                "C3 verification failed, ciphertext has been tampered with".to_string(),
            ));
        }

        Ok(m)
    }
}

/// Extract point x,y bytes (32 bytes)
fn point_xy_bytes(p: &ProjectivePoint) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let enc = p.to_affine().to_encoded_point(false);
    let x = enc
        .x()
        .ok_or_else(|| CryptoError::Sm2Error("X coordinate missing".to_string()))?
        .to_vec();
    let y = enc
        .y()
        .ok_or_else(|| CryptoError::Sm2Error("Y coordinate missing".to_string()))?
        .to_vec();
    Ok((x, y))
}

/// SM3 KDF, generate key_len bytes
fn kdf_sm3(x: &[u8], y: &[u8], key_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut key = Vec::with_capacity(key_len);
    let mut ct: u32 = 1;
    while key.len() < key_len {
        // SM3 KDF counter is u32, max 2^32-1 iterations * 32 bytes = 128GB
        if ct == 0 {
            return Err(CryptoError::Sm2Error(
                "KDF key length exceeds maximum (128GB)".to_string(),
            ));
        }
        let mut buf = Vec::with_capacity(x.len() + y.len() + 4);
        buf.extend_from_slice(x);
        buf.extend_from_slice(y);
        buf.extend_from_slice(&ct.to_be_bytes());
        let block = Sm3Hasher::hash(&buf)?;
        let remain = key_len - key.len();
        if remain >= block.len() {
            key.extend_from_slice(&block);
        } else {
            key.extend_from_slice(&block[..remain]);
        }
        ct = ct.wrapping_add(1);
    }
    Ok(key)
}

/// SM3(x || m || y)
fn sm3_hash_concat(x: &[u8], m: &[u8], y: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut buf = Vec::with_capacity(x.len() + m.len() + y.len());
    buf.extend_from_slice(x);
    buf.extend_from_slice(m);
    buf.extend_from_slice(y);
    Sm3Hasher::hash(&buf)
}

// ─────────────────────────────────────────────────────────────────────────────
// SM2Cipher DER ⇔ C1||C3||C2 Raw 双向转换
// GmSSL 3.1.1 CLI 输出 DER 格式 SEQUENCE{INTEGER C1x, INTEGER C1y, OCTET_STRING C3, OCTET_STRING C2}
// Rust Sm2Encryptor/Sm2Decryptor 内部使用 C1||C3||C2 原始拼接格式
// ─────────────────────────────────────────────────────────────────────────────

/// DER-encoded SM2Cipher → C1||C3||C2 raw format.
///
/// GmSSL `sm2encrypt` outputs DER-encoded SM2Cipher.
/// This converts it to the raw C1||C3||C2 format that [`Sm2Decryptor::decrypt`] expects.
///
/// DER structure:
/// ``` DER
/// SEQUENCE {
///     INTEGER  C1x   (32 bytes, high byte may be 0x00 if MSB set)
///     INTEGER  C1y   (32 bytes)
///     OCTET STRING  C3 (32 bytes, SM3 hash)
///     OCTET STRING  C2 (variable length, ciphertext)
/// }
/// ```
///
/// Raw output: `0x04 || C1x(32B) || C1y(32B) || C3(32B) || C2(variable)`
pub fn sm2_cipher_der_to_raw(der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    parse_sm2_cipher_der(der).map(|(c1x, c1y, c3, c2)| {
        let mut out = Vec::with_capacity(65 + c3.len() + c2.len());
        out.push(0x04); // uncompressed point prefix
        out.extend_from_slice(&c1x);
        out.extend_from_slice(&c1y);
        out.extend_from_slice(&c3);
        out.extend_from_slice(&c2);
        out
    })
}

/// C1||C3||C2 raw format → DER-encoded SM2Cipher.
///
/// Converts the raw format used by [`Sm2Encryptor::encrypt`] into
/// the DER-encoded SM2Cipher format expected by GmSSL `sm2decrypt`.
pub fn sm2_cipher_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Parse: C1(65) || C3(32) || C2(variable)
    if raw.len() < 65 + 32 {
        return Err(CryptoError::Sm2Error(
            "raw ciphertext too short: need at least C1(65) + C3(32)".to_string(),
        ));
    }
    if !raw.starts_with(&[0x04]) {
        return Err(CryptoError::Sm2Error(
            "raw ciphertext must start with 0x04 (uncompressed point)".to_string(),
        ));
    }

    let c1x = &raw[1..33]; // 32 bytes
    let c1y = &raw[33..65]; // 32 bytes
    let c3 = &raw[65..97]; // 32 bytes
    let c2 = &raw[97..]; // variable

    let mut der = Vec::new();

    // SEQUENCE
    let content_len = der_integer_len(c1x)
        + der_integer_len(c1y)
        + der_octet_string_len(c3)
        + der_octet_string_len(c2);
    der.push(0x30);
    der_encode_length(&mut der, content_len);

    // INTEGER C1x
    der_encode_integer(&mut der, c1x);
    // INTEGER C1y
    der_encode_integer(&mut der, c1y);
    // OCTET STRING C3
    der_encode_octet_string(&mut der, c3);
    // OCTET STRING C2
    der_encode_octet_string(&mut der, c2);

    Ok(der)
}

// ─── DER encoding helpers ────────────────────────────────────────────────────

use gm_der::der_len;

fn der_encode_length(der: &mut Vec<u8>, len: usize) {
    // Delegate to gm-der's der_len, which produces the same bytes
    der.extend_from_slice(&der_len(len));
}

fn der_integer_len(value: &[u8]) -> usize {
    let stripped = strip_leading_zeros(value);
    if stripped.is_empty() {
        return 3; // 0 → 0x02 0x01 0x00
    }
    if stripped[0] & 0x80 != 0 {
        // Need leading 0x00 to keep it positive
        3 + stripped.len()
    } else {
        2 + stripped.len()
    }
}

fn der_octet_string_len(data: &[u8]) -> usize {
    if data.len() < 128 {
        2 + data.len()
    } else if data.len() < 256 {
        3 + data.len()
    } else {
        4 + data.len()
    }
}

fn der_encode_integer(der: &mut Vec<u8>, value: &[u8]) {
    let stripped = strip_leading_zeros(value);
    let bytes = if stripped.is_empty() {
        &[0u8]
    } else if stripped[0] & 0x80 != 0 {
        // MSB set → prepend 0x00
        der.push(0x02);
        der_encode_length(der, stripped.len() + 1);
        der.push(0x00);
        der.extend_from_slice(stripped);
        return;
    } else {
        stripped
    };

    der.push(0x02);
    der_encode_length(der, bytes.len());
    der.extend_from_slice(bytes);
}

fn der_encode_octet_string(der: &mut Vec<u8>, data: &[u8]) {
    der.push(0x04);
    der_encode_length(der, data.len());
    der.extend_from_slice(data);
}

// ─── SM2 Signature DER ↔ Raw (r||s, 64 bytes) conversion ──────────────────

/// Convert a DER-encoded SM2 signature (SEQUENCE { INTEGER r, INTEGER s })
/// to raw `r || s` format (64 bytes, each component 32 bytes big-endian).
///
/// X.509 certificates and CMS use DER-encoded signatures, but gm-crypto's
/// `Sm2Verifier::verify` expects raw 64-byte format.
pub fn sm2_signature_der_to_raw(der: &[u8]) -> Result<[u8; 64], CryptoError> {
    let mut pos = 0;

    // SEQUENCE
    if der.is_empty() || der[pos] != 0x30 {
        return Err(CryptoError::Sm2Error(
            "expected SEQUENCE tag 0x30 for signature".to_string(),
        ));
    }
    pos += 1;
    let (seq_len, consumed) = parse_der_length(&der[pos..])?;
    pos += consumed;
    let seq_end = pos + seq_len;
    if seq_end > der.len() {
        return Err(CryptoError::Sm2Error(
            "signature SEQUENCE length exceeds input".to_string(),
        ));
    }

    // INTEGER r
    let (r, n) = parse_der_integer(&der[pos..])?;
    pos += n;
    if r.len() != 32 {
        return Err(CryptoError::Sm2Error(format!(
            "signature r must be 32 bytes, got {}",
            r.len()
        )));
    }

    // INTEGER s
    let (s, n) = parse_der_integer(&der[pos..])?;
    pos += n;
    if s.len() != 32 {
        return Err(CryptoError::Sm2Error(format!(
            "signature s must be 32 bytes, got {}",
            s.len()
        )));
    }

    if pos != seq_end {
        return Err(CryptoError::Sm2Error(
            "extra bytes after signature SEQUENCE".to_string(),
        ));
    }

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);
    Ok(out)
}

/// Convert a raw SM2 signature (r||s, 64 bytes) to DER format
/// `SEQUENCE { INTEGER r, INTEGER s }`.
///
/// This is needed for compatibility with X.509 and CMS structures
/// that require DER-encoded signatures.
pub fn sm2_signature_raw_to_der(raw: &[u8; 64]) -> Vec<u8> {
    let r = &raw[..32];
    let s = &raw[32..];

    let mut der = Vec::with_capacity(72);

    // SEQUENCE
    let content_len = der_integer_len(r) + der_integer_len(s);
    der.push(0x30);
    der_encode_length(&mut der, content_len);

    // INTEGER r
    der_encode_integer(&mut der, r);
    // INTEGER s
    der_encode_integer(&mut der, s);

    der
}

fn strip_leading_zeros(value: &[u8]) -> &[u8] {
    let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    &value[start..]
}

// ─── DER parsing ─────────────────────────────────────────────────────────────

type Sm2CipherParts = Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), CryptoError>;

fn parse_sm2_cipher_der(der: &[u8]) -> Sm2CipherParts {
    let mut pos = 0;

    // SEQUENCE
    if pos >= der.len() || der[pos] != 0x30 {
        return Err(CryptoError::Sm2Error(
            "expected SEQUENCE tag 0x30".to_string(),
        ));
    }
    pos += 1;
    let (seq_len, consumed) = parse_der_length(&der[pos..])?;
    pos += consumed;
    if pos + seq_len > der.len() {
        return Err(CryptoError::Sm2Error(
            "SEQUENCE length exceeds input".to_string(),
        ));
    }
    let seq_end = pos + seq_len;

    // INTEGER C1x
    let (c1x, n) = parse_der_integer(&der[pos..])?;
    pos += n;
    if c1x.len() != 32 {
        return Err(CryptoError::Sm2Error(format!(
            "C1x must be 32 bytes, got {}",
            c1x.len()
        )));
    }

    // INTEGER C1y
    let (c1y, n) = parse_der_integer(&der[pos..])?;
    pos += n;
    if c1y.len() != 32 {
        return Err(CryptoError::Sm2Error(format!(
            "C1y must be 32 bytes, got {}",
            c1y.len()
        )));
    }

    // OCTET STRING C3
    let (c3, n) = parse_der_octet_string(&der[pos..])?;
    pos += n;

    // OCTET STRING C2
    let (c2, n) = parse_der_octet_string(&der[pos..])?;
    pos += n;

    if pos != seq_end {
        return Err(CryptoError::Sm2Error(
            "extra bytes after SM2Cipher SEQUENCE".to_string(),
        ));
    }

    Ok((c1x, c1y, c3, c2))
}

fn parse_der_length(bytes: &[u8]) -> Result<(usize, usize), CryptoError> {
    let (rest, length) =
        gm_der::parse_der_length(bytes).map_err(|e| CryptoError::Sm2Error(e.to_string()))?;
    let consumed = bytes.len() - rest.len();
    Ok((length, consumed))
}

fn parse_der_integer(bytes: &[u8]) -> Result<(Vec<u8>, usize), CryptoError> {
    let mut pos = 0;
    if bytes.is_empty() || bytes[pos] != 0x02 {
        return Err(CryptoError::Sm2Error(
            "expected INTEGER tag 0x02".to_string(),
        ));
    }
    pos += 1;
    let (len, consumed) = parse_der_length(&bytes[pos..])?;
    pos += consumed;
    if bytes.len() < pos + len {
        return Err(CryptoError::Sm2Error(
            "INTEGER content truncated".to_string(),
        ));
    }
    // Strip leading zeros, but keep at least one byte
    let content = &bytes[pos..pos + len];
    let stripped = strip_leading_zeros(content);
    let value = if stripped.is_empty() {
        vec![0u8; len] // all zeros: preserve exact length
    } else {
        // Value must be positive; if first content byte was 0x00 and stripped,
        // the original had a sign-padding byte which we remove.
        stripped.to_vec()
    };
    if value.len() > 32 {
        return Err(CryptoError::Sm2Error(format!(
            "INTEGER too large for SM2 field: {} bytes",
            value.len()
        )));
    }
    // Pad to 32 bytes (big-endian)
    let mut padded = vec![0u8; 32 - value.len()];
    padded.extend_from_slice(&value);
    Ok((padded, pos + len))
}

fn parse_der_octet_string(bytes: &[u8]) -> Result<(Vec<u8>, usize), CryptoError> {
    let mut pos = 0;
    if bytes.is_empty() || bytes[pos] != 0x04 {
        return Err(CryptoError::Sm2Error(
            "expected OCTET STRING tag 0x04".to_string(),
        ));
    }
    pos += 1;
    let (len, consumed) = parse_der_length(&bytes[pos..])?;
    pos += consumed;
    if bytes.len() < pos + len {
        return Err(CryptoError::Sm2Error(
            "OCTET STRING content truncated".to_string(),
        ));
    }
    Ok((bytes[pos..pos + len].to_vec(), pos + len))
}

/// Decompress SM2 public key from SEC1 format to uncompressed format.
///
/// Supports:
/// - Compressed: 0x02/0x03 + X (33 bytes) → returns uncompressed (65 bytes)
/// - Uncompressed: 0x04 + X + Y (65 bytes) → returns as-is (65 bytes)
///
/// # Arguments
/// * `sec1_pubkey` - SEC1 encoded SM2 public key (33 or 65 bytes)
///
/// # Returns
/// * Uncompressed SEC1 format: 0x04 + X (32 bytes) + Y (32 bytes) = 65 bytes
///
/// # Errors
/// * Returns error if the public key is invalid or cannot be decompressed
pub fn decompress_sm2_pubkey(sec1_pubkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Parse the encoded point
    let encoded = sm2::EncodedPoint::from_bytes(sec1_pubkey)
        .map_err(|e| CryptoError::Sm2Error(format!("invalid SEC1 public key format: {}", e)))?;

    // Convert to projective point (this handles decompression automatically)
    let point = ProjectivePoint::from_encoded_point(&encoded)
        .into_option()
        .ok_or_else(|| CryptoError::Sm2Error("invalid SM2 public key point".to_string()))?;

    // Encode as uncompressed (0x04 || x || y)
    let uncompressed = point.to_affine().to_encoded_point(false);

    Ok(uncompressed.as_bytes().to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
// SM2 ECDH Key Exchange
// Used by TLCP ECDHE cipher suites and TLS 1.3 key share
// ─────────────────────────────────────────────────────────────────────────────

/// SM2 ECDH ephemeral key pair for key exchange.
///
/// Generates a random ephemeral SM2 key pair. The shared secret is computed
/// using standard Elliptic Curve Diffie-Hellman over the SM2 curve (sm2p256v1).
///
/// # Security
///
/// This type implements `ZeroizeOnDrop` to ensure the ephemeral private scalar
/// is securely erased from memory when dropped.
///
/// The shared secret alone is **not** suitable for direct use as a session key.
/// It must be passed through a KDF (e.g., SM3-KDF as defined in GM/T 0003.3-2012)
/// to derive session keys.
#[derive(ZeroizeOnDrop)]
pub struct Sm2EcdhKeypair {
    scalar: Scalar,
    #[zeroize(skip)]
    public_key: PublicKey<Sm2>,
}

impl Sm2EcdhKeypair {
    /// Generate a new random ephemeral SM2 ECDH key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let secret_key = SecretKey::<Sm2>::random(&mut OsRng);
        let scalar = *secret_key.to_nonzero_scalar().as_ref();
        let public_key = PublicKey::from_secret_scalar(&secret_key.to_nonzero_scalar());
        Ok(Self { scalar, public_key })
    }

    /// Get the uncompressed public key bytes (0x04 || x || y, 65 bytes).
    ///
    /// This is sent to the peer during key exchange.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key
            .as_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Compute the ECDH shared secret with the peer's public key.
    ///
    /// The peer's public key must be in uncompressed format (0x04 || x || y, 65 bytes).
    ///
    /// Returns the raw shared secret as the x-coordinate of the shared point
    /// (32 bytes), suitable for input into a KDF.
    pub fn compute_shared_secret(&self, peer_public_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let peer_pk = parse_sm2_public_key(peer_public_bytes)?;
        let shared_point = ProjectivePoint::from(*peer_pk.as_affine()) * self.scalar;
        let shared_affine = shared_point.to_affine();

        // Check that the shared point is not the point at infinity
        if shared_affine.to_encoded_point(false).is_identity() {
            return Err(CryptoError::Sm2Error(
                "ECDH shared point is the identity (invalid peer key)".to_string(),
            ));
        }

        let enc = shared_affine.to_encoded_point(false);
        let x = enc.x().ok_or_else(|| {
            CryptoError::Sm2Error("shared point X coordinate missing".to_string())
        })?;
        Ok(x.to_vec())
    }
}

/// Compute SM2 ECDH shared secret from an existing private key and peer public key.
///
/// This is the low-level function for static ECDH (e.g., TLCP ECC cipher suites
/// where the server's long-term SM2 key is used instead of an ephemeral key).
///
/// Returns the raw shared point x-coordinate (32 bytes).
pub fn sm2_ecdh(
    private_key: &SecretKey<Sm2>,
    peer_public_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let peer_pk = parse_sm2_public_key(peer_public_bytes)?;
    let shared_point =
        ProjectivePoint::from(*peer_pk.as_affine()) * private_key.to_nonzero_scalar().as_ref();
    let shared_affine = shared_point.to_affine();

    if shared_affine.to_encoded_point(false).is_identity() {
        return Err(CryptoError::Sm2Error(
            "ECDH shared point is the identity".to_string(),
        ));
    }

    let enc = shared_affine.to_encoded_point(false);
    let x = enc
        .x()
        .ok_or_else(|| CryptoError::Sm2Error("shared point X coordinate missing".to_string()))?;
    Ok(x.to_vec())
}

/// Parse an SM2 public key from uncompressed bytes (0x04 || x || y).
fn parse_sm2_public_key(bytes: &[u8]) -> Result<PublicKey<Sm2>, CryptoError> {
    use elliptic_curve::sec1::FromEncodedPoint;
    let enc = EncodedPoint::from_bytes(bytes)
        .map_err(|e| CryptoError::Sm2Error(format!("invalid SM2 public key encoding: {}", e)))?;
    let pk_option: Option<PublicKey<Sm2>> = PublicKey::<Sm2>::from_encoded_point(&enc).into();
    let pk = pk_option
        .ok_or_else(|| CryptoError::Sm2Error("SM2 public key decoding failed".to_string()))?;
    Ok(pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm2_ecdh_shared_secret() {
        // Two parties generate ephemeral keypairs and compute the same shared secret
        let kp_a = Sm2EcdhKeypair::generate().unwrap();
        let kp_b = Sm2EcdhKeypair::generate().unwrap();

        let shared_a = kp_a
            .compute_shared_secret(&kp_b.public_key_bytes())
            .unwrap();
        let shared_b = kp_b
            .compute_shared_secret(&kp_a.public_key_bytes())
            .unwrap();

        assert_eq!(shared_a, shared_b, "ECDH shared secrets must match");
        assert_eq!(
            shared_a.len(),
            32,
            "shared secret should be 32 bytes (x-coordinate)"
        );
    }

    #[test]
    fn test_sm2_ecdh_different_peers_different_secrets() {
        let kp_a = Sm2EcdhKeypair::generate().unwrap();
        let kp_b = Sm2EcdhKeypair::generate().unwrap();
        let kp_c = Sm2EcdhKeypair::generate().unwrap();

        let shared_ab = kp_a
            .compute_shared_secret(&kp_b.public_key_bytes())
            .unwrap();
        let shared_ac = kp_a
            .compute_shared_secret(&kp_c.public_key_bytes())
            .unwrap();

        assert_ne!(
            shared_ab, shared_ac,
            "different peers must produce different shared secrets"
        );
    }

    #[test]
    fn test_sm2_ecdh_public_key_format() {
        let kp = Sm2EcdhKeypair::generate().unwrap();
        let pub_bytes = kp.public_key_bytes();
        assert_eq!(
            pub_bytes.len(),
            65,
            "uncompressed SM2 public key should be 65 bytes"
        );
        assert_eq!(
            pub_bytes[0], 0x04,
            "uncompressed point should start with 0x04"
        );
    }

    #[test]
    fn test_sm2_ecdh_static() {
        // Test static ECDH (using existing SecretKey)
        let kp_a = Sm2KeyPair::generate().unwrap();
        let kp_b = Sm2KeyPair::generate().unwrap();

        let shared_a = sm2_ecdh(&kp_a.private_key, &kp_b.public_key_bytes()).unwrap();
        let shared_b = sm2_ecdh(&kp_b.private_key, &kp_a.public_key_bytes()).unwrap();

        assert_eq!(shared_a, shared_b, "static ECDH shared secrets must match");
    }

    #[test]
    fn test_encrypted_pem_roundtrip() {
        let keypair = Sm2KeyPair::generate().unwrap();
        let password = "test_password_123";

        // Encrypt
        let encrypted_pem = keypair.to_encrypted_pem(password).unwrap();
        assert!(encrypted_pem.contains("ENCRYPTED PRIVATE KEY"));

        // Decrypt
        let decrypted = Sm2KeyPair::from_encrypted_pem(&encrypted_pem, password).unwrap();

        // Verify keys match
        assert_eq!(keypair.private_key_bytes(), decrypted.private_key_bytes());
        assert_eq!(keypair.public_key_bytes(), decrypted.public_key_bytes());
    }

    #[test]
    fn test_encrypted_pem_wrong_password() {
        let keypair = Sm2KeyPair::generate().unwrap();
        let password = "correct_password_123";
        let wrong_password = "wrong_password_456";

        let encrypted_pem = keypair.to_encrypted_pem(password).unwrap();

        // Should fail with wrong password
        let result = Sm2KeyPair::from_encrypted_pem(&encrypted_pem, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_pem_short_password() {
        let keypair = Sm2KeyPair::generate().unwrap();
        let short_password = "short";

        let result = keypair.to_encrypted_pem(short_password);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("at least 8 characters")
        );
    }

    #[test]
    fn test_sm2_cipher_der_to_raw_known_vector() {
        // GmSSL 3.1.1 sm2encrypt output (DER-encoded SM2Cipher)
        let gmssl_der_hex = "307f022100cb98d7afcc96da6ddba6fcdbb0c8d4d34100176ad1bcf08d1d57a5a278b84f4902200fc3f902835ee8fb7ddc71fee7179d4e5972afc4492733a3e4aa879f8a4a74d50420e086a4889aa351b36bedde0ff07f3c38564da3a59d2f7fd551703d57df27158a0416799a645005132b490b00eaa4acde2d2090aa12846eb6";
        let gmssl_der = hex::decode(gmssl_der_hex).unwrap();

        let raw = sm2_cipher_der_to_raw(&gmssl_der).expect("DER→raw conversion failed");

        // Verify raw starts with 0x04
        assert_eq!(raw[0], 0x04, "raw should start with 0x04");
        // C1: 65 bytes, C3: 32 bytes, C2: 22 bytes → total 119
        assert_eq!(raw.len(), 119, "raw length should be 65+32+22=119");

        // Verify C1x and C1y match the DER integers
        let c1x = &raw[1..33];
        let c1y = &raw[33..65];
        assert_eq!(
            c1x,
            hex::decode("cb98d7afcc96da6ddba6fcdbb0c8d4d34100176ad1bcf08d1d57a5a278b84f49")
                .unwrap()
        );
        assert_eq!(
            c1y,
            hex::decode("0fc3f902835ee8fb7ddc71fee7179d4e5972afc4492733a3e4aa879f8a4a74d5")
                .unwrap()
        );
    }

    #[test]
    fn test_sm2_cipher_raw_to_der_roundtrip() {
        // Generate a keypair, encrypt, convert to DER and back
        let keypair = Sm2KeyPair::generate().unwrap();
        let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
        let plaintext = b"test DER roundtrip";

        let raw = encryptor.encrypt(plaintext).expect("encrypt failed");
        let der = sm2_cipher_raw_to_der(&raw).expect("raw→DER failed");

        // DER should start with SEQUENCE tag
        assert_eq!(der[0], 0x30, "DER should start with 0x30");

        // Convert back to raw
        let raw2 = sm2_cipher_der_to_raw(&der).expect("DER→raw failed");
        assert_eq!(raw, raw2, "raw→DER→raw should be identity");

        // Verify we can decrypt the DER ciphertext
        let decryptor = Sm2Decryptor::new(keypair);
        let decrypted = decryptor.decrypt(&der).expect("DER decrypt failed");
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_encrypt_decrypt_der_format() {
        let keypair = Sm2KeyPair::generate().unwrap();
        let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
        let plaintext = b"hello DER format SM2 encryption";

        // Encrypt in DER format
        let der_ciphertext = encryptor
            .encrypt_der(plaintext)
            .expect("encrypt_der failed");
        assert_eq!(
            der_ciphertext[0], 0x30,
            "DER ciphertext should start with 0x30"
        );

        // Decrypt (auto-detects DER format)
        let decryptor = Sm2Decryptor::new(keypair);
        let decrypted = decryptor
            .decrypt(&der_ciphertext)
            .expect("DER decrypt failed");
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_decrypt_auto_detects_raw_format() {
        let keypair = Sm2KeyPair::generate().unwrap();
        let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
        let plaintext = b"auto-detect raw";

        let raw = encryptor.encrypt(plaintext).expect("encrypt failed");
        assert_eq!(raw[0], 0x04, "raw should start with 0x04");

        let decryptor = Sm2Decryptor::new(keypair);
        let decrypted = decryptor.decrypt(&raw).expect("raw decrypt failed");
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_encrypt_versioned_raw_roundtrip() {
        let keypair = Sm2KeyPair::generate().unwrap();
        let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
        let plaintext = b"versioned raw SM2 ciphertext";

        let versioned = encryptor
            .encrypt_versioned(plaintext)
            .expect("encrypt_versioned failed");

        // Header check: 0x53 0x4D 0x01 0x00
        assert_eq!(&versioned[..2], &[0x53, 0x4D], "magic header");
        assert_eq!(versioned[2], 0x01, "version 1");
        assert_eq!(versioned[3], 0x00, "format raw");

        // Decrypt via auto-detection
        let decryptor = Sm2Decryptor::new(keypair);
        let decrypted = decryptor
            .decrypt(&versioned)
            .expect("versioned decrypt failed");
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_encrypt_versioned_der_roundtrip() {
        let keypair = Sm2KeyPair::generate().unwrap();
        let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
        let plaintext = b"versioned DER SM2 ciphertext";

        let versioned = encryptor
            .encrypt_versioned_der(plaintext)
            .expect("encrypt_versioned_der failed");

        // Header check: 0x53 0x4D 0x01 0x01
        assert_eq!(&versioned[..2], &[0x53, 0x4D], "magic header");
        assert_eq!(versioned[2], 0x01, "version 1");
        assert_eq!(versioned[3], 0x01, "format DER");

        // Decrypt via auto-detection
        let decryptor = Sm2Decryptor::new(keypair);
        let decrypted = decryptor
            .decrypt(&versioned)
            .expect("versioned DER decrypt failed");
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_decrypt_rejects_unknown_versioned_format() {
        let keypair = Sm2KeyPair::generate().unwrap();
        let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
        let plaintext = b"bad format";

        let raw = encryptor.encrypt(plaintext).unwrap();
        let mut bad = vec![0x53, 0x4D, 0x01, 0xFF]; // unknown format 0xFF
        bad.extend_from_slice(&raw);

        let decryptor = Sm2Decryptor::new(keypair);
        let result = decryptor.decrypt(&bad);
        assert!(result.is_err(), "should reject unknown format");
    }

    #[test]
    fn test_versioned_and_legacy_decrypt_each_other() {
        // Legacy format should still decrypt (backward compat)
        let keypair = Sm2KeyPair::generate().unwrap();
        let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
        let plaintext = b"backward compat";

        let legacy_raw = encryptor.encrypt(plaintext).unwrap();
        let versioned = encryptor.encrypt_versioned(plaintext).unwrap();

        let decryptor = Sm2Decryptor::new(keypair);
        assert_eq!(decryptor.decrypt(&legacy_raw).unwrap(), plaintext.to_vec());
        assert_eq!(decryptor.decrypt(&versioned).unwrap(), plaintext.to_vec());
    }

    #[test]
    fn test_sm2_signature_der_raw_roundtrip() {
        let keypair = Sm2KeyPair::generate().unwrap();
        let signer = Sm2Signer::new(&keypair).unwrap();
        let msg = b"test signature DER roundtrip";
        let raw_sig = signer.sign(msg).unwrap();
        assert_eq!(raw_sig.len(), 64, "raw signature should be 64 bytes");

        // raw → DER
        let raw_arr: [u8; 64] = raw_sig.as_slice().try_into().unwrap();
        let der_sig = sm2_signature_raw_to_der(&raw_arr);
        assert_eq!(der_sig[0], 0x30, "DER should start with SEQUENCE tag");

        // DER → raw
        let raw_back = sm2_signature_der_to_raw(&der_sig).unwrap();
        assert_eq!(&raw_back[..], &raw_sig[..], "roundtrip should match");

        // Verify both raw and DER-converted signatures
        let verifier = Sm2Verifier::new(&keypair.public_key_bytes(), "1234567812345678").unwrap();
        assert!(
            verifier.verify(msg, &raw_sig).is_ok(),
            "raw sig should verify"
        );
        assert!(
            verifier.verify(msg, &raw_back).is_ok(),
            "DER roundtrip sig should verify"
        );
    }

    #[test]
    fn test_sm2_signature_der_with_leading_zero() {
        // Test with signatures whose r or s has MSB set (needs 0x00 padding in DER)
        let keypair = Sm2KeyPair::generate().unwrap();
        let signer = Sm2Signer::new(&keypair).unwrap();

        for i in 0u32..10 {
            let msg = format!("test message {}", i);
            let raw_sig = signer.sign(msg.as_bytes()).unwrap();
            let raw_arr: [u8; 64] = raw_sig.as_slice().try_into().unwrap();
            let der_sig = sm2_signature_raw_to_der(&raw_arr);
            let raw_back = sm2_signature_der_to_raw(&der_sig).unwrap();
            assert_eq!(
                &raw_back[..],
                &raw_sig[..],
                "roundtrip failed for message {}",
                i
            );
        }
    }

    #[test]
    fn test_sm2_signature_der_invalid_input() {
        // Not a SEQUENCE
        assert!(sm2_signature_der_to_raw(&[0x05]).is_err());
        // Truncated
        assert!(sm2_signature_der_to_raw(&[0x30, 0x06, 0x02, 0x01, 0x01]).is_err());
    }

    #[test]
    fn test_from_private_key_pkcs8_pem() {
        // OpenSSL genpkey outputs PKCS#8 PEM (BEGIN PRIVATE KEY)
        let keypair = Sm2KeyPair::generate().unwrap();
        let pkcs8_pem = keypair
            .private_key
            .to_pkcs8_pem(elliptic_curve::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        assert!(
            pkcs8_pem.contains("BEGIN PRIVATE KEY"),
            "should be PKCS#8 format"
        );

        let loaded = Sm2KeyPair::from_private_key_pem(&pkcs8_pem).expect("PKCS#8 PEM parse");
        assert_eq!(
            keypair.private_key_bytes(),
            loaded.private_key_bytes(),
            "loaded key should match"
        );
    }

    #[test]
    fn test_der_integer_with_leading_zero() {
        // Test case where C1x or C1y has MSB set (requires 0x00 padding in DER)
        let keypair = Sm2KeyPair::generate().unwrap();
        let encryptor = Sm2Encryptor::new(&keypair.public_key_bytes_uncompressed()).unwrap();
        let plaintext = b"test MSB padding";

        // Encrypt multiple times to increase chance of hitting MSB-set coordinates
        for _ in 0..20 {
            let raw = encryptor.encrypt(plaintext).unwrap();
            let der = sm2_cipher_raw_to_der(&raw).unwrap();
            let raw2 = sm2_cipher_der_to_raw(&der).unwrap();
            assert_eq!(raw, raw2, "roundtrip failed for MSB test");
        }
    }
}
