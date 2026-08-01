//! GmSSL FFI Bindings for SM9
//!
//! This module provides FFI bindings to the GmSSL 3.1.1 library's SM9 implementation.
//! GmSSL implements SM9 according to GM/T 0044-2016 standard.
//!
//! # Safety
//! All FFI functions here are unsafe and must be called with valid pointers.

#![allow(non_snake_case)]

use libc;
pub use libc::{FILE, c_char, c_int, c_long, c_uchar, c_void, size_t};

/// Expected GmSSL version number (3.1.1 = 0x7595 = 30101)
const EXPECTED_GMSSL_VERSION_NUM: c_long = 0x7595;

/// Expected GmSSL version string
const EXPECTED_GMSSL_VERSION_STR: &str = "GmSSL 3.1.1";

// GmSSL version query functions
#[link(name = "gmssl")]
unsafe extern "C" {
    fn gmssl_version_num() -> c_long;
    fn gmssl_version_str() -> *const c_char;
}

/// Check that the loaded GmSSL library matches the expected version.
///
/// Returns `Ok(())` if the version matches, or an error message if not.
/// This prevents subtle cryptographic mismatches from using a different
/// GmSSL version with incompatible parameter layouts.
///
/// # Errors
/// Returns error if the linked GmSSL version doesn't match 3.1.1.
pub fn check_gmssl_version() -> Result<(), String> {
    unsafe {
        let ver_num = gmssl_version_num();
        if ver_num != EXPECTED_GMSSL_VERSION_NUM {
            let ver_str = CStr::from_ptr(gmssl_version_str())
                .to_str()
                .unwrap_or("(invalid UTF-8)");
            return Err(format!(
                "GmSSL version mismatch: expected {} ({}), got {} ({})",
                EXPECTED_GMSSL_VERSION_NUM, EXPECTED_GMSSL_VERSION_STR, ver_num, ver_str
            ));
        }
    }
    Ok(())
}

use std::ffi::CStr;

// =============================================================================
// SM9 Constants and Types
// =============================================================================

/// Size of signature
pub const SM9_SIGNATURE_SIZE: usize = 104;

/// Maximum plaintext size
pub const SM9_MAX_PLAINTEXT_SIZE: usize = 255;

/// Maximum ciphertext size
pub const SM9_MAX_CIPHERTEXT_SIZE: usize = 367;

/// SM9 master public key size
pub const SM9_SIGN_MASTER_PUBLIC_KEY_SIZE: usize = 136;

/// SM9 sign master key max size
pub const SM9_SIGN_MASTER_KEY_MAX_SIZE: usize = 171;

/// SM9 sign key size
pub const SM9_SIGN_KEY_SIZE: usize = 204;

/// SM9 big number (256 bits, 8 x uint64_t)
/// Matches GmSSL 3.1.1's sm9_bn_t = uint64_t[8]
/// Note: Only first 4 limbs (32 bytes) hold the actual 256-bit value;
/// upper 4 limbs are padding/alignment but must be present for C struct compatibility.
#[allow(non_camel_case_types)]
pub type sm9_bn_t = [u64; 8];

/// SM9 function (element in scalar field Fp)
/// Also used for signature component h
/// Note: In GmSSL 3.1.1, sm9_fn_t = sm9_bn_t = uint64_t[8]
/// Only first 4 limbs hold the value; upper 4 are padding.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct sm9_fn_t {
    /// 8 x uint64_t limbs to match C layout, first 4 hold value
    pub data: [u64; 8],
}

impl sm9_fn_t {
    pub fn new() -> Self {
        Self { data: [0u64; 8] }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut data = [0u64; 8];
        // GmSSL stores big-endian bytes in little-endian u64 array
        // bytes[0..8] (MSB) -> data[3]
        // bytes[24..32] (LSB) -> data[0]
        for i in 0..4 {
            data[3 - i] = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        Self { data }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        // data[3] (high limb) -> bytes[0..8]
        // data[0] (low limb) -> bytes[24..32]
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&self.data[3 - i].to_be_bytes());
        }
        bytes
    }
}

/// SM3 digest size
pub const SM3_DIGEST_SIZE: usize = 32;

/// SM3 context
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SM3_CTX {
    /// Internal state (8 x uint32_t)
    pub state: [u32; 8],
    /// Total message bits high
    pub vlan: u64,
    /// Buffer
    pub data: [u8; 64],
    /// Bytes in buffer (0-63)
    pub datalen: u32,
    /// Total message bytes
    pub nlo: u32,
}

/// SM9 point on G1 (affine coordinates with projective for internal use)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SM9_POINT {
    /// X coordinate (fp - element in prime field)
    pub x: sm9_bn_t,
    /// Y coordinate
    pub y: sm9_bn_t,
    /// Z coordinate (for projective representation)
    pub z: sm9_bn_t,
}

/// SM9 twist point on G2 (over quadratic extension field)
/// Stored as (X, Y) where X = x0 + x1 * u, Y = y0 + y1 * u
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SM9_TWIST_POINT {
    /// X = x0 + x1 * u (two fp elements)
    pub x: [sm9_bn_t; 2],
    /// Y = y0 + y1 * u
    pub y: [sm9_bn_t; 2],
    /// Z coordinate
    pub z: [sm9_bn_t; 2],
}

/// SM9 signature master key
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SM9_SIGN_MASTER_KEY {
    /// Public key Ppubs = ks * P2
    pub Ppubs: SM9_TWIST_POINT,
    /// Master secret key ks
    pub ks: sm9_fn_t,
}

/// SM9 signature key (user private key)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SM9_SIGN_KEY {
    /// Public key Ppubs
    pub Ppubs: SM9_TWIST_POINT,
    /// Private key ds
    pub ds: SM9_POINT,
}

/// SM9 signature
/// According to GM/T 0080-2020:
/// SM9Signature ::= SEQUENCE {
///     h OCTET STRING,
///     S BIT STRING }
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SM9_SIGNATURE {
    /// h component
    pub h: sm9_fn_t,
    /// S component (point on G1)
    pub S: SM9_POINT,
}

/// SM9 encryption master key
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SM9_ENC_MASTER_KEY {
    /// Public key Ppubs = ke * P2
    pub Ppubs: SM9_TWIST_POINT,
    /// Master secret key ke
    pub ke: sm9_fn_t,
}

/// SM9 encryption key (user private key)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SM9_ENC_KEY {
    /// Public key Ppubs
    pub Ppubs: SM9_TWIST_POINT,
    /// Private key de
    pub de: SM9_POINT,
}

/// SM9 sign context (for multi-part sign/verify)
#[repr(C)]
#[derive(Debug)]
pub struct SM9_SIGN_CTX {
    /// SM3 context
    pub sm3_ctx: SM3_CTX,
    /// HID (1 for sign, 2 for encryption)
    pub hid: c_int,
    /// Signer ID
    pub id: *mut c_char,
    /// ID length
    pub idlen: size_t,
    /// Is verifying
    pub vflg: c_int,
}

impl Drop for SM9_SIGN_CTX {
    fn drop(&mut self) {
        // Free the signer ID string allocated by GmSSL C library.
        // sm9_sign_init / sm9_verify_init internally copies the ID
        // (likely via strdup/malloc), so we must free it on Drop.
        if !self.id.is_null() {
            unsafe {
                // Safety: id was allocated by C library (GmSSL) with malloc/strdup.
                // Calling libc::free is the correct deallocation.
                libc::free(self.id as *mut libc::c_void);
            }
            self.id = std::ptr::null_mut();
        }
    }
}

// =============================================================================
// SM9 Sign API
// =============================================================================

// Generate SM9 signature master key
//
// # Safety
// Undefined behavior if master pointer is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_sign_master_key_generate(master: *mut SM9_SIGN_MASTER_KEY) -> c_int;
}

// Extract signature key for a given identity
//
// # Safety
// Undefined behavior if any pointer is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_sign_master_key_extract_key(
        master: *const SM9_SIGN_MASTER_KEY,
        id: *const c_char,
        idlen: size_t,
        key: *mut SM9_SIGN_KEY,
    ) -> c_int;
}

// Sign a message using SM9 signature key
//
// # Safety
// Undefined behavior if any pointer is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_do_sign(
        key: *const SM9_SIGN_KEY,
        sm3_ctx: *const SM3_CTX,
        sig: *mut SM9_SIGNATURE,
    ) -> c_int;
}

// Verify SM9 signature
//
// # Safety
// Undefined behavior if any pointer is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_do_verify(
        mpk: *const SM9_SIGN_MASTER_KEY,
        id: *const c_char,
        idlen: size_t,
        sm3_ctx: *const SM3_CTX,
        sig: *const SM9_SIGNATURE,
    ) -> c_int;
}

// Initialize SM9 sign context
//
// # Safety
// Undefined behavior if ctx is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_sign_init(ctx: *mut SM9_SIGN_CTX) -> c_int;
}

// Update SM9 sign with data
//
// # Safety
// Undefined behavior if ctx or data is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_sign_update(ctx: *mut SM9_SIGN_CTX, data: *const c_uchar, datalen: size_t) -> c_int;
}

// Finish SM9 signing
//
// # Safety
// Undefined behavior if any pointer is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_sign_finish(
        ctx: *mut SM9_SIGN_CTX,
        key: *const SM9_SIGN_KEY,
        sig: *mut c_uchar,
        siglen: *mut size_t,
    ) -> c_int;
}

// Initialize SM9 verify context
//
// # Safety
// Undefined behavior if ctx is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_verify_init(ctx: *mut SM9_SIGN_CTX) -> c_int;
}

// Update SM9 verify with data
//
// # Safety
// Undefined behavior if ctx or data is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_verify_update(
        ctx: *mut SM9_SIGN_CTX,
        data: *const c_uchar,
        datalen: size_t,
    ) -> c_int;
}

// Finish SM9 verification
//
// # Safety
// Undefined behavior if any pointer is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_verify_finish(
        ctx: *mut SM9_SIGN_CTX,
        sig: *const c_uchar,
        siglen: size_t,
        mpk: *const SM9_SIGN_MASTER_KEY,
        id: *const c_char,
        idlen: size_t,
    ) -> c_int;
}

// =============================================================================
// SM9 Encrypt API
// =============================================================================

// Generate SM9 encryption master key
//
// # Safety
// Undefined behavior if master pointer is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_enc_master_key_generate(master: *mut SM9_ENC_MASTER_KEY) -> c_int;
}

// Extract encryption key for a given identity
//
// # Safety
// Undefined behavior if any pointer is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_enc_master_key_extract_key(
        master: *const SM9_ENC_MASTER_KEY,
        id: *const c_char,
        idlen: size_t,
        key: *mut SM9_ENC_KEY,
    ) -> c_int;
}

// Encrypt data using SM9
//
// # Safety
// Undefined behavior if any pointer is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_encrypt(
        mpk: *const SM9_ENC_MASTER_KEY,
        id: *const c_char,
        idlen: size_t,
        in_data: *const c_uchar,
        inlen: size_t,
        out_data: *mut c_uchar,
        outlen: *mut size_t,
    ) -> c_int;
}

// Decrypt data using SM9
//
// # Safety
// Undefined behavior if any pointer is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_decrypt(
        key: *const SM9_ENC_KEY,
        id: *const c_char,
        idlen: size_t,
        in_data: *const c_uchar,
        inlen: size_t,
        out_data: *mut c_uchar,
        outlen: *mut size_t,
    ) -> c_int;
}

// =============================================================================
// SM3 Hash API
// =============================================================================

// Initialize SM3 context
//
// # Safety
// Undefined behavior if ctx is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm3_init(ctx: *mut SM3_CTX);
}

// Update SM3 hash with data
//
// # Safety
// Undefined behavior if ctx or data is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm3_update(ctx: *mut SM3_CTX, data: *const c_uchar, datalen: size_t);
}

// Finish SM3 hash
//
// # Safety
// Undefined behavior if ctx or hash is null.
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm3_finish(ctx: *mut SM3_CTX, hash: *mut c_uchar);
}

// =============================================================================
// Helper Functions
// =============================================================================

// Print BN to file
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_bn_print(
        fp: *mut FILE,
        fmt: c_int,
        ind: c_int,
        label: *const c_char,
        a: *const sm9_bn_t,
    ) -> c_int;
}

// Print point to file
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_point_print(
        fp: *mut FILE,
        fmt: c_int,
        ind: c_int,
        label: *const c_char,
        P: *const SM9_POINT,
    ) -> c_int;
}

// Convert point to uncompressed octets (65 bytes)
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_point_to_uncompressed_octets(P: *const SM9_POINT, octets: *mut c_uchar) -> c_int;
}

// Convert point from uncompressed octets
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_point_from_uncompressed_octets(P: *mut SM9_POINT, octets: *const c_uchar) -> c_int;
}

// Convert twist point to uncompressed octets (129 bytes)
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_twist_point_to_uncompressed_octets(
        P: *const SM9_TWIST_POINT,
        octets: *mut c_uchar,
    ) -> c_int;
}

// Convert twist point from uncompressed octets
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_twist_point_from_uncompressed_octets(
        P: *mut SM9_TWIST_POINT,
        octets: *const c_uchar,
    ) -> c_int;
}

// =============================================================================
// Frobenius Functions
// =============================================================================

// Apply Frobenius pi1 to twist point
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_twist_point_pi1(R: *mut SM9_TWIST_POINT, P: *const SM9_TWIST_POINT);
}

// Apply Frobenius pi2 to twist point
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_twist_point_pi2(R: *mut SM9_TWIST_POINT, P: *const SM9_TWIST_POINT);
}

// =============================================================================
// DER Serialization Functions
// =============================================================================

// Serialize SM9 sign master public key to DER
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_sign_master_public_key_to_der(
        mpk: *const SM9_SIGN_MASTER_KEY,
        out: *mut *mut c_uchar,
        outlen: *mut size_t,
    ) -> c_int;
}

// Deserialize SM9 sign master public key from DER
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_sign_master_public_key_from_der(
        mpk: *mut SM9_SIGN_MASTER_KEY,
        inp: *mut *const c_uchar,
        inlen: *mut size_t,
    ) -> c_int;
}

// Serialize SM9 sign key to DER
#[allow(dead_code)]
#[link(name = "gmssl")]
unsafe extern "C" {
    pub fn sm9_sign_key_to_der(
        key: *const SM9_SIGN_KEY,
        out: *mut *mut c_uchar,
        outlen: *mut size_t,
    ) -> c_int;
}

// =============================================================================
// Error Codes
// =============================================================================

/// SM9 success code
pub const SM9_OK: c_int = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_sizes() {
        // Verify type sizes match C expectations
        assert_eq!(std::mem::size_of::<sm9_bn_t>(), 64); // 8 x u64 = 64 bytes (matches C sm9_bn_t)
        assert_eq!(std::mem::size_of::<sm9_fn_t>(), 64); // 8 x u64 = 64 bytes (matches C sm9_fn_t)
        assert_eq!(std::mem::size_of::<SM9_POINT>(), 192); // 3 x sm9_bn_t
        assert_eq!(std::mem::size_of::<SM9_SIGNATURE>(), 256); // sm9_fn_t (64) + SM9_POINT (192)
    }

    #[test]
    fn test_fn_default() {
        let fn_t = sm9_fn_t::default();
        assert_eq!(fn_t.data, [0u64; 8]);
    }
}
