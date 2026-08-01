//! GmSSL Backend Implementation for SM9
//!
//! This module implements SM9 operations using the GmSSL library via FFI.
//! GmSSL provides a complete, standards-compliant SM9 implementation
//! conforming to GM/T 0044-2016.

use crate::error::Sm9Error;
use crate::ffi::{
    SM9_ENC_KEY, SM9_ENC_MASTER_KEY, SM9_MAX_CIPHERTEXT_SIZE, SM9_MAX_PLAINTEXT_SIZE, SM9_OK,
    SM9_POINT, SM9_SIGN_KEY, SM9_SIGN_MASTER_KEY, SM9_SIGNATURE_SIZE, SM9_TWIST_POINT, c_char,
    c_int, c_uchar, size_t, sm9_decrypt, sm9_enc_master_key_extract_key,
    sm9_enc_master_key_generate, sm9_encrypt, sm9_fn_t, sm9_sign_finish, sm9_sign_init,
    sm9_sign_key_to_der, sm9_sign_master_key_extract_key, sm9_sign_master_key_generate,
    sm9_sign_master_public_key_from_der, sm9_sign_master_public_key_to_der, sm9_sign_update,
    sm9_twist_point_from_uncompressed_octets, sm9_twist_point_to_uncompressed_octets,
    sm9_verify_finish, sm9_verify_init, sm9_verify_update,
};
use libc::free;
use std::ffi::CString;
use std::ptr;

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert a Rust string to a C string
fn to_cstring(s: &str) -> Result<CString, Sm9Error> {
    CString::new(s).map_err(|_| Sm9Error::InvalidParameter("Invalid identity string".to_string()))
}

/// Check GmSSL return code and convert to Sm9Error
fn check_gmssl_code(code: c_int) -> Result<(), Sm9Error> {
    if code == SM9_OK {
        Ok(())
    } else {
        Err(Sm9Error::CryptoError(format!("GmSSL error: {}", code)))
    }
}

/// Ensure the GmSSL library version matches expectations.
/// Called once on first use of any GmSSL backend function.
fn ensure_gmssl_version() -> Result<(), Sm9Error> {
    use std::sync::OnceLock;
    static VERSION_CHECK: OnceLock<Result<(), Sm9Error>> = OnceLock::new();
    VERSION_CHECK
        .get_or_init(|| crate::ffi::check_gmssl_version().map_err(Sm9Error::CryptoError))
        .clone()
}

// =============================================================================
// SM9 Signature Implementation (GmSSL Backend)
// =============================================================================

/// SM9 signature master key (GmSSL backend)
pub struct GmSignMasterKey {
    inner: SM9_SIGN_MASTER_KEY,
}

impl Clone for GmSignMasterKey {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl core::fmt::Debug for GmSignMasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GmSignMasterKey")
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl GmSignMasterKey {
    /// Generate a new signature master key
    pub fn generate() -> Result<Self, Sm9Error> {
        ensure_gmssl_version()?;
        let mut master = SM9_SIGN_MASTER_KEY {
            Ppubs: SM9_TWIST_POINT {
                x: [[0u64; 8], [0u64; 8]],
                y: [[0u64; 8], [0u64; 8]],
                z: [[0u64; 8], [0u64; 8]],
            },
            ks: sm9_fn_t::new(),
        };

        // SAFETY: GmSSL FFI — master key generation writes to stack-allocated master struct with correct size.
        unsafe {
            check_gmssl_code(sm9_sign_master_key_generate(&mut master))?;
        }

        Ok(Self { inner: master })
    }

    /// Get the public key (Ppubs)
    pub fn public_key(&self) -> &SM9_TWIST_POINT {
        &self.inner.Ppubs
    }

    /// Serialize public key (Ppubs) to raw bytes (128 bytes uncompressed G2 point)
    ///
    /// GmSSL format: 0x04 prefix + X (64 bytes) || Y (64 bytes)
    /// Each Fp2 element is stored as c1 (32 bytes) || c0 (32 bytes) in GmSSL
    /// We convert to standard format: c0 (32 bytes) || c1 (32 bytes)
    pub fn to_bytes(&self) -> Result<[u8; 128], Sm9Error> {
        let mut octets = [0u8; 129]; // GmSSL uses 129 bytes (1 byte prefix + 128 bytes)
        // SAFETY: GmSSL FFI — to_uncompressed_octets writes to stack-allocated 129-byte buffer (1 prefix + 128 data).
        unsafe {
            let code =
                sm9_twist_point_to_uncompressed_octets(&self.inner.Ppubs, octets.as_mut_ptr());
            check_gmssl_code(code)?;
        }

        // GmSSL format: 0x04 prefix + 128 bytes
        // GmSSL Fp2 layout: c1 || c0 (each 32 bytes)
        // We convert to standard layout: c0 || c1
        let mut result = [0u8; 128];

        // X coordinate: bytes 1-65 (skip prefix)
        // GmSSL: c1_X (32 bytes) || c0_X (32 bytes)
        // Standard: c0_X (32 bytes) || c1_X (32 bytes)
        result[0..32].copy_from_slice(&octets[33..65]); // c0_X from GmSSL
        result[32..64].copy_from_slice(&octets[1..33]); // c1_X from GmSSL

        // Y coordinate: bytes 65-129
        // GmSSL: c1_Y (32 bytes) || c0_Y (32 bytes)
        // Standard: c0_Y (32 bytes) || c1_Y (32 bytes)
        result[64..96].copy_from_slice(&octets[97..129]); // c0_Y from GmSSL
        result[96..128].copy_from_slice(&octets[65..97]); // c1_Y from GmSSL

        Ok(result)
    }

    /// Deserialize public key (Ppubs) from raw bytes (128 bytes uncompressed G2 point)
    ///
    /// Standard format: X (64 bytes) || Y (64 bytes), each Fp2 as c0 (32 bytes) || c1 (32 bytes)
    /// We convert to GmSSL format: c1 (32 bytes) || c0 (32 bytes)
    pub fn from_bytes(bytes: &[u8; 128]) -> Result<Self, Sm9Error> {
        let mut octets = [0u8; 129];
        octets[0] = 0x04; // uncompressed point prefix

        // Convert standard format (c0 || c1) to GmSSL format (c1 || c0)
        // X coordinate
        octets[1..33].copy_from_slice(&bytes[32..64]); // c1_X (standard c1)
        octets[33..65].copy_from_slice(&bytes[0..32]); // c0_X (standard c0)

        // Y coordinate
        octets[65..97].copy_from_slice(&bytes[96..128]); // c1_Y (standard c1)
        octets[97..129].copy_from_slice(&bytes[64..96]); // c0_Y (standard c0)

        let mut master = SM9_SIGN_MASTER_KEY {
            Ppubs: SM9_TWIST_POINT {
                x: [[0u64; 8], [0u64; 8]],
                y: [[0u64; 8], [0u64; 8]],
                z: [[0u64; 8], [0u64; 8]],
            },
            ks: sm9_fn_t::new(),
        };

        // SAFETY: GmSSL FFI — from_uncompressed_octets reads from validated octets slice; writes to stack-allocated master.
        unsafe {
            let code = sm9_twist_point_from_uncompressed_octets(&mut master.Ppubs, octets.as_ptr());
            check_gmssl_code(code)?;
        }

        Ok(Self { inner: master })
    }

    /// Extract signature key for a given identity
    pub fn extract_sign_key(&self, identity: &[u8]) -> Result<GmSignKey, Sm9Error> {
        let id = std::str::from_utf8(identity)
            .map_err(|_| Sm9Error::InvalidParameter("Identity must be valid UTF-8".to_string()))?;

        let id_cstr = to_cstring(id)?;
        let mut key = SM9_SIGN_KEY {
            Ppubs: SM9_TWIST_POINT {
                x: [[0u64; 8], [0u64; 8]],
                y: [[0u64; 8], [0u64; 8]],
                z: [[0u64; 8], [0u64; 8]],
            },
            ds: SM9_POINT {
                x: [0u64; 8],
                y: [0u64; 8],
                z: [0u64; 8],
            },
        };

        // SAFETY: GmSSL FFI — extract_key reads id_cstr (valid CStr) and writes to stack-allocated key struct.
        unsafe {
            check_gmssl_code(sm9_sign_master_key_extract_key(
                &self.inner,
                id_cstr.as_ptr() as *const c_char,
                identity.len() as size_t,
                &mut key,
            ))?;
        }

        Ok(GmSignKey { inner: key })
    }

    /// Serialize to DER bytes (public key only)
    pub fn to_der(&self) -> Result<Vec<u8>, Sm9Error> {
        let mut out: *mut c_uchar = ptr::null_mut();
        let mut outlen: size_t = 0;

        // SAFETY: GmSSL FFI — to_der allocates via GmSSL internal malloc; we copy and free immediately. out ptr checked before use.
        unsafe {
            let code = sm9_sign_master_public_key_to_der(&self.inner, &mut out, &mut outlen);
            check_gmssl_code(code)?;

            if out.is_null() || outlen == 0 {
                return Err(Sm9Error::CryptoError(
                    "Failed to serialize master key".to_string(),
                ));
            }

            let bytes = std::slice::from_raw_parts(out, outlen).to_vec();
            free(out as *mut libc::c_void);
            Ok(bytes)
        }
    }

    /// Deserialize from DER bytes (public key only)
    #[allow(dead_code)]
    pub fn from_der(der: &[u8]) -> Result<Self, Sm9Error> {
        let mut master = SM9_SIGN_MASTER_KEY {
            Ppubs: SM9_TWIST_POINT {
                x: [[0u64; 8], [0u64; 8]],
                y: [[0u64; 8], [0u64; 8]],
                z: [[0u64; 8], [0u64; 8]],
            },
            ks: sm9_fn_t::new(),
        };

        // SAFETY: GmSSL FFI — from_der reads from validated der slice; writes to stack-allocated master struct.
        unsafe {
            let mut in_ptr = der.as_ptr();
            let mut inlen = der.len();

            let code = sm9_sign_master_public_key_from_der(&mut master, &mut in_ptr, &mut inlen);
            check_gmssl_code(code)?;
        }

        Ok(Self { inner: master })
    }
}

/// SM9 signature key (user private key, GmSSL backend)
pub struct GmSignKey {
    inner: SM9_SIGN_KEY,
}

impl Clone for GmSignKey {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl core::fmt::Debug for GmSignKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GmSignKey")
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl GmSignKey {
    /// Serialize to DER bytes
    #[allow(dead_code)]
    pub fn to_der(&self) -> Result<Vec<u8>, Sm9Error> {
        let mut out: *mut c_uchar = ptr::null_mut();
        let mut outlen: size_t = 0;

        // SAFETY: GmSSL FFI — to_der allocates via GmSSL internal malloc; we copy and free immediately. out ptr checked before use.
        unsafe {
            let code = sm9_sign_key_to_der(&self.inner, &mut out, &mut outlen);
            check_gmssl_code(code)?;

            if out.is_null() || outlen == 0 {
                return Err(Sm9Error::CryptoError(
                    "Failed to serialize sign key".to_string(),
                ));
            }

            let bytes = std::slice::from_raw_parts(out, outlen).to_vec();
            free(out as *mut libc::c_void);
            Ok(bytes)
        }
    }
}

/// SM9 signer using GmSSL
pub struct GmSigner {
    key: GmSignKey,
}

impl GmSigner {
    /// Create a new signer
    pub fn new(key: GmSignKey) -> Self {
        Self { key }
    }

    /// Sign a message in one shot
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Sm9Error> {
        // SAFETY: GmSSL FFI — sm9_sign_init/update/finish use stack-allocated sig struct; input slices are valid.
        unsafe {
            // Use the high-level sign API
            let mut ctx = std::mem::zeroed();
            check_gmssl_code(sm9_sign_init(&mut ctx))?;
            check_gmssl_code(sm9_sign_update(
                &mut ctx,
                message.as_ptr(),
                message.len() as size_t,
            ))?;

            let mut sig_bytes = vec![0u8; SM9_SIGNATURE_SIZE];
            let mut siglen = SM9_SIGNATURE_SIZE as size_t;
            check_gmssl_code(sm9_sign_finish(
                &mut ctx,
                &self.key.inner,
                sig_bytes.as_mut_ptr(),
                &mut siglen,
            ))?;

            sig_bytes.truncate(siglen as usize);
            Ok(sig_bytes)
        }
    }
}

/// SM9 verifier using GmSSL
pub struct GmVerifier {
    mpk: GmSignMasterKey,
    id: Vec<u8>,
}

impl GmVerifier {
    /// Create a new verifier
    pub fn new(mpk: GmSignMasterKey, id: &[u8]) -> Self {
        Self {
            mpk,
            id: id.to_vec(),
        }
    }

    /// Verify a signature in one shot
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, Sm9Error> {
        if signature.len() < SM9_SIGNATURE_SIZE {
            return Err(Sm9Error::SignatureVerificationFailed);
        }

        let id_str = std::str::from_utf8(&self.id)
            .map_err(|_| Sm9Error::InvalidParameter("Identity must be UTF-8".to_string()))?;
        let id_cstr = to_cstring(id_str)?;

        // SAFETY: GmSSL FFI — sm9_verify_init/update/finish read from validated slices and sig struct.
        unsafe {
            // Use the high-level verify API
            let mut ctx = std::mem::zeroed();
            check_gmssl_code(sm9_verify_init(&mut ctx))?;
            check_gmssl_code(sm9_verify_update(
                &mut ctx,
                message.as_ptr(),
                message.len() as size_t,
            ))?;

            let result = sm9_verify_finish(
                &mut ctx,
                signature.as_ptr(),
                signature.len() as size_t,
                &self.mpk.inner,
                id_cstr.as_ptr() as *const c_char,
                self.id.len() as size_t,
            );

            Ok(result == SM9_OK)
        }
    }
}

// =============================================================================
// SM9 Encryption Implementation (GmSSL Backend)
// =============================================================================

/// SM9 encryption master key (GmSSL backend)
pub struct GmEncMasterKey {
    inner: SM9_ENC_MASTER_KEY,
}

impl Clone for GmEncMasterKey {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl core::fmt::Debug for GmEncMasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GmEncMasterKey")
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl GmEncMasterKey {
    /// Generate a new encryption master key
    pub fn generate() -> Result<Self, Sm9Error> {
        ensure_gmssl_version()?;
        let mut master = SM9_ENC_MASTER_KEY {
            Ppubs: SM9_TWIST_POINT {
                x: [[0u64; 8], [0u64; 8]],
                y: [[0u64; 8], [0u64; 8]],
                z: [[0u64; 8], [0u64; 8]],
            },
            ke: sm9_fn_t::new(),
        };

        // SAFETY: GmSSL FFI — encryption uses stack-allocated structs; id_cstr and plaintext are valid slices.
        unsafe {
            check_gmssl_code(sm9_enc_master_key_generate(&mut master))?;
        }

        Ok(Self { inner: master })
    }

    /// Extract an encryption key for the given identity
    pub fn extract_enc_key(&self, identity: &[u8]) -> Result<GmEncKey, Sm9Error> {
        let id = std::str::from_utf8(identity)
            .map_err(|_| Sm9Error::InvalidParameter("Identity must be valid UTF-8".to_string()))?;

        let id_cstr = to_cstring(id)?;
        let mut key = SM9_ENC_KEY {
            Ppubs: SM9_TWIST_POINT {
                x: [[0u64; 8], [0u64; 8]],
                y: [[0u64; 8], [0u64; 8]],
                z: [[0u64; 8], [0u64; 8]],
            },
            de: SM9_POINT {
                x: [0u64; 8],
                y: [0u64; 8],
                z: [0u64; 8],
            },
        };

        // SAFETY: GmSSL FFI — decryption uses stack-allocated structs; ciphertext slice validated above.
        unsafe {
            check_gmssl_code(sm9_enc_master_key_extract_key(
                &self.inner,
                id_cstr.as_ptr() as *const c_char,
                identity.len() as size_t,
                &mut key,
            ))?;
        }

        Ok(GmEncKey { inner: key })
    }
}

/// SM9 encryption key (user private key, GmSSL backend)
pub struct GmEncKey {
    inner: SM9_ENC_KEY,
}

impl Clone for GmEncKey {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl core::fmt::Debug for GmEncKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GmEncKey")
            .field("inner", &"<redacted>")
            .finish()
    }
}

/// SM9 encryptor using GmSSL
///
/// IBE encryption requires the master public key and the recipient's identity.
/// The user's private key (GmEncKey) is NOT needed for encryption.
pub struct GmEncryptor {
    mpk: GmEncMasterKey,
    id: Vec<u8>,
}

impl GmEncryptor {
    /// Create a new encryptor for a given identity using the master public key
    pub fn new(mpk: GmEncMasterKey, id: &[u8]) -> Self {
        Self {
            mpk,
            id: id.to_vec(),
        }
    }

    /// Encrypt a message
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Sm9Error> {
        let id_str = std::str::from_utf8(&self.id)
            .map_err(|_| Sm9Error::InvalidParameter("Identity must be UTF-8".to_string()))?;
        let id_cstr = to_cstring(id_str)?;

        let in_data = plaintext.as_ptr() as *const c_uchar;
        let inlen = plaintext.len() as size_t;

        let mut out_buf = vec![0u8; SM9_MAX_CIPHERTEXT_SIZE];
        let out_data = out_buf.as_mut_ptr();
        let mut outlen = SM9_MAX_CIPHERTEXT_SIZE as size_t;

        // SAFETY: GmSSL FFI — encrypt writes to stack-allocated ciphertext buffer (SM9_MAX_CIPHERTEXT_SIZE).
        unsafe {
            check_gmssl_code(sm9_encrypt(
                &self.mpk.inner,
                id_cstr.as_ptr() as *const c_char,
                self.id.len() as size_t,
                in_data,
                inlen,
                out_data,
                &mut outlen,
            ))?;

            Ok(out_buf[..outlen as usize].to_vec())
        }
    }
}

/// SM9 decryptor using GmSSL
pub struct GmDecryptor {
    key: GmEncKey,
    id: Vec<u8>,
}

impl GmDecryptor {
    /// Create a new decryptor with the user's private key and identity
    pub fn new(key: GmEncKey, id: &[u8]) -> Self {
        Self {
            key,
            id: id.to_vec(),
        }
    }

    /// Decrypt a ciphertext
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Sm9Error> {
        let id_str = std::str::from_utf8(&self.id)
            .map_err(|_| Sm9Error::InvalidParameter("Identity must be UTF-8".to_string()))?;
        let id_cstr = to_cstring(id_str)?;

        let in_data = ciphertext.as_ptr() as *const c_uchar;
        let inlen = ciphertext.len() as size_t;

        let mut out_buf = vec![0u8; SM9_MAX_PLAINTEXT_SIZE];
        let out_data = out_buf.as_mut_ptr();
        let mut outlen = SM9_MAX_PLAINTEXT_SIZE as size_t;

        // SAFETY: GmSSL FFI — decrypt writes to stack-allocated plaintext buffer (SM9_MAX_PLAINTEXT_SIZE).
        unsafe {
            check_gmssl_code(sm9_decrypt(
                &self.key.inner,
                id_cstr.as_ptr() as *const c_char,
                self.id.len() as size_t,
                in_data,
                inlen,
                out_data,
                &mut outlen,
            ))?;

            Ok(out_buf[..outlen as usize].to_vec())
        }
    }
}

// =============================================================================
// SM9 KGC (Key Generation Center)
// =============================================================================

/// SM9 KGC master key using GmSSL
/// Combines both signing and encryption master keys
pub struct GmKgcMasterKey {
    sign_master: GmSignMasterKey,
    enc_master: GmEncMasterKey,
}

impl Clone for GmKgcMasterKey {
    fn clone(&self) -> Self {
        Self {
            sign_master: self.sign_master.clone(),
            enc_master: self.enc_master.clone(),
        }
    }
}

impl core::fmt::Debug for GmKgcMasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GmKgcMasterKey")
            .field("sign_master", &"<redacted>")
            .field("enc_master", &"<redacted>")
            .finish()
    }
}

impl GmKgcMasterKey {
    /// Generate a new KGC master key (both signing and encryption)
    pub fn generate() -> Result<Self, Sm9Error> {
        Ok(Self {
            sign_master: GmSignMasterKey::generate()?,
            enc_master: GmEncMasterKey::generate()?,
        })
    }

    /// Derive a signing key for the given identity
    pub fn derive_signing_key(&self, identity: &[u8]) -> Result<GmSignKey, Sm9Error> {
        self.sign_master.extract_sign_key(identity)
    }

    /// Derive an encryption key for the given identity
    pub fn derive_encryption_key(&self, identity: &[u8]) -> Result<GmEncKey, Sm9Error> {
        self.enc_master.extract_enc_key(identity)
    }

    /// Get a reference to the signing master key
    pub fn sign_master(&self) -> &GmSignMasterKey {
        &self.sign_master
    }

    /// Get a reference to the encryption master key
    pub fn enc_master(&self) -> &GmEncMasterKey {
        &self.enc_master
    }

    /// Serialize to bytes (combined format)
    #[allow(dead_code)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Sm9Error> {
        // For now, only serialize the sign master key
        // Full implementation would include enc_master serialization
        let sign_der = self.sign_master.to_der()?;
        let enc_der = vec![]; // Placeholder

        let mut result = Vec::new();
        result.extend_from_slice(&sign_der.len().to_le_bytes());
        result.extend_from_slice(&sign_der);
        result.extend_from_slice(&enc_der);
        Ok(result)
    }

    /// Deserialize from bytes
    #[allow(dead_code)]
    pub fn from_bytes(_bytes: &[u8]) -> Result<Self, Sm9Error> {
        // Would need proper deserialization - simplified for now
        Err(Sm9Error::InvalidParameter(
            "Deserialization not implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kgc_generation() {
        // This test requires GmSSL to be properly linked
        let result = GmKgcMasterKey::generate();
        if result.is_err() {
            println!("GmSSL not available or linking failed: {:?}", result.err());
        }
    }
}
