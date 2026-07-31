# gm-crypto Guide

> Last Updated: 2026-06-29

Pure Rust implementation of national cryptography (GM) algorithms: SM2 (sign/encrypt), SM3 (hash), and SM4 (symmetric encryption). All algorithms use `zeroize` to automatically zeroize sensitive key material on `Drop`, and `OsRng` as the secure random source.


## Module Overview

```
gm_crypto
├── sm2   # SM2 elliptic curve: signing, verification, encryption
├── sm3   # SM3 hash and HMAC
├── sm4   # SM4 symmetric encryption (GCM/CBC/ECB)
├── utils # Utilities (hex/base64 conversion)
└── x509  # X.509 certificate parsing
```

## Adding Dependencies

```toml
[dependencies]
gm-crypto = { path = "gm-crypto" }
```

---

## SM2 Module

SM2 is an elliptic curve asymmetric cryptography algorithm over GF(p), supporting sign/verify and encrypt/decrypt.


### Key Pair Generation and Management

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier, Sm2Encryptor, Sm2Decryptor};

// Generate key pair (uses GM/T standard distid "1234567812345678")
let key_pair = Sm2KeyPair::generate().unwrap();

// Generate with custom distid (only when protocol explicitly requires it)
let key_pair2 = Sm2KeyPair::generate_with_distid("custom_distid".to_string()).unwrap();

// Load from existing private key bytes
let key_pair3 = Sm2KeyPair::from_private_key(private_key_bytes).unwrap();

// Load from PEM string (supports SEC1, PKCS#8, and encrypted PKCS#8)
let pem = std::fs::read_to_string("key.pem")?;
let key_pair4 = Sm2KeyPair::from_private_key_pem(&pem).unwrap();

// Load from encrypted PEM (PBES2 AES-256-CBC)
let encrypted_pem = std::fs::read_to_string("key-encrypted.pem")?;
let key_pair5 = Sm2KeyPair::from_encrypted_pem(&encrypted_pem, "password123").unwrap();

// Serialization
let private_key_pem = key_pair.private_key_pem().unwrap();                    // SEC1 PEM
let private_key_bytes = key_pair.private_key_bytes();                         // Raw bytes
let public_key_compressed = key_pair.public_key_bytes();                      // Compressed (33 bytes)
let public_key_uncompressed = key_pair.public_key_bytes_uncompressed();       // Uncompressed (65 bytes)

// Encrypt private key for storage (recommended for production)
let encrypted = key_pair.to_encrypted_pem("strong_password_123").unwrap();
```

**Note**:
- `Sm2Verifier::new()` and `Sm2Encryptor::new()` require the **uncompressed format** (65 bytes) public key
- `Sm2KeyPair` implements `ZeroizeOnDrop`, automatically zeroizing key material on drop
- `Sm2KeyPair` does not implement `Clone`; use `duplicate()` if you need to copy
- Encrypted PEM uses PBES2 (AES-256-CBC), password minimum length 8 characters

### Signing and Verification

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier};

// Sign
let key_pair = Sm2KeyPair::generate().unwrap();
let signer = Sm2Signer::new(&key_pair).unwrap();

let message = b"Hello, GM TLS!";
let signature = signer.sign(message).unwrap();
let signature_hex = signer.sign_hex(message).unwrap();  // hex string

// Verify (use uncompressed format public key)
let public_key = key_pair.public_key_bytes_uncompressed(); // 65 bytes
let verifier = Sm2Verifier::new(&public_key, key_pair.distid()).unwrap();

// verify() returns Ok(()) on success, Err on failure
verifier.verify(message, &signature).unwrap();
println!("Signature OK!");

// Verify using hex string
verifier.verify_hex(message, &signature_hex).unwrap();
```

### Encryption and Decryption

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Encryptor, Sm2Decryptor};

// Encrypt (use recipient's public key)
let key_pair_receiver = Sm2KeyPair::generate().unwrap();
let public_key = key_pair_receiver.public_key_bytes_uncompressed(); // 65 bytes

let encryptor = Sm2Encryptor::new(&public_key).unwrap();
let ciphertext = encryptor.encrypt(b"secret message").unwrap();

// Decrypt (use recipient's private key)
let decryptor = Sm2Decryptor::new(key_pair_receiver).unwrap();
let plaintext = decryptor.decrypt(&ciphertext).unwrap();
assert_eq!(plaintext, b"secret message");
```

---

## SM3 Module

SM3 is the national standard hash algorithm, outputting 256-bit (32-byte) digests.


### Basic Hash

```rust
use gm_crypto::sm3::Sm3Hasher;

let data = b"hello world";

// Returns a byte array
let hash = Sm3Hasher::hash(data).unwrap();         // 32 bytes
let hash_hex = Sm3Hasher::hash_hex(data).unwrap();  // hex string
let hash_b64 = Sm3Hasher::hash_base64(data).unwrap(); // Base64 string
```

### HMAC

```rust
use gm_crypto::sm3::Sm3Hmac;

let hmac = Sm3Hmac::new(b"my_secret_key");

// Compute
let mac = hmac.compute(b"message").unwrap();
let mac_hex = hmac.compute_hex(b"message").unwrap();

// Verify (uses constant-time comparison, prevents timing attacks)
let valid = hmac.verify(b"message", &mac).unwrap();
assert!(valid);
```

---

## SM4 Module

SM4 is the national standard block cipher with 16-byte key and 16-byte block size.


### Constants

```rust
use gm_crypto::sm4::*;
assert_eq!(SM4_KEY_LENGTH, 16);        // Key length
assert_eq!(SM4_BLOCK_SIZE, 16);        // Block size
assert_eq!(SM4_GCM_TAG_LENGTH, 16);   // GCM auth tag length
assert_eq!(SM4_GCM_NONCE_LENGTH, 12); // Recommended GCM nonce length
```

### GCM Mode (Recommended)

GCM provides authenticated encryption, ensuring both confidentiality and integrity. **Recommended for all new use cases**.


```rust
use gm_crypto::sm4::Sm4Cipher;

let key = b"0123456789abcdef"; // 16 bytes
let cipher = Sm4Cipher::new(key).unwrap();

// Encrypt: returns (ciphertext, auth tag)
let nonce = b"0123456789ab"; // 12 bytes
let (ciphertext, tag) = cipher.encrypt_gcm(b"secret data", nonce, b"aad").unwrap();

// Decrypt (pass correct nonce and tag)
let plaintext = cipher.decrypt_gcm(&ciphertext, nonce, b"aad", &tag).unwrap();
assert_eq!(plaintext, b"secret data");
```

> **Security Warning**: Each encryption **must** use a unique nonce. GCM's security depends on nonce uniqueness; reusing a nonce leaks the key.
>

### CBC Mode

CBC mode supports PKCS#7 padding (handled automatically).


```rust
use gm_crypto::sm4::Sm4Cipher;

let key = b"0123456789abcdef";
let cipher = Sm4Cipher::new(key).unwrap();
let iv = b"0123456789abcdef"; // 16-byte IV

// Encrypt (CBC auto-pads data to block boundary)
let ciphertext = cipher.encrypt_cbc(b"hello", iv).unwrap();

// Decrypt (auto-removes PKCS#7 padding)
let plaintext = cipher.decrypt_cbc(&ciphertext, iv).unwrap();
assert_eq!(plaintext, b"hello");
```

### ECB Mode (Deprecated)

```rust
use gm_crypto::sm4::Sm4Cipher;

#[deprecated(since = "0.2.0", note = "use CBC or GCM mode instead")]
fn use_ecb() {
    let cipher = Sm4Cipher::new(b"0123456789abcdef").unwrap();
    // ECB mode is deprecated; do not use in new code
}
```

> **Security Warning**: ECB mode produces identical ciphertext blocks for identical plaintext blocks, leaking patterns. **Do not use in new code**; only for legacy compatibility.
>

---

## Utilities

```rust
use gm_crypto::{bytes_to_hex, hex_to_bytes, bytes_to_base64, base64_to_bytes};

// hex conversion
let hex = bytes_to_hex(b"\xde\xad\xbe\xef");   // "deadbeef"
let bytes = hex_to_bytes("deadbeef").unwrap();

// base64 conversion
let b64 = bytes_to_base64(b"hello");            // "aGVsbG8="
let bytes = base64_to_bytes("aGVsbG8=").unwrap();
```

---

## X.509 Certificate Parsing

```rust
use gm_crypto::x509;

let cert_pem = std::fs::read_to_string("cert.pem")?;
let cert = x509::parse_cert_pem(&cert_pem).unwrap();
// cert exposes subject, issuer, validity, etc.
```

---

## Security Notes

| Rule | Description |
| -------------- | --------------------- |
| Key storage | Set private key file permissions to 600, readable only by owner; use encrypted PEM in production |
| Randomness | Always use `Sm2KeyPair::generate()` (internally uses `OsRng`), never supply your own |
| Nonce | Each GCM encryption must use a unique nonce; never reuse |
| ECB mode | **Do not use**, marked deprecated |
| HMAC verification | `verify()` uses constant-time comparison, prevents timing attacks |
| Key zeroization | `Sm2KeyPair` and `Sm3Hmac` implement `ZeroizeOnDrop`, auto-zeroized on drop |
| Plaintext size | SM2 encryption max plaintext 64 KiB (`SM2_MAX_PLAINTEXT_LEN`), returns error if exceeded |

---

## SM2 Advanced Features

### Encryption Formats and Compatibility

SM2 supports multiple ciphertext formats for compatibility with different implementations (e.g., GmSSL):


```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Encryptor, Sm2Decryptor};

let key_pair = Sm2KeyPair::generate().unwrap();
let encryptor = Sm2Encryptor::new(&key_pair.public_key_bytes_uncompressed()).unwrap();
let plaintext = b"test message";

// 1. Raw format: C1||C3||C2 (default)
let raw = encryptor.encrypt(plaintext).unwrap();

// 2. DER format: compatible with GmSSL sm2encrypt command
let der = encryptor.encrypt_der(plaintext).unwrap();

// 3. Versioned format: with magic header, supports format auto-detection
let versioned_raw = encryptor.encrypt_versioned(plaintext).unwrap();
let versioned_der = encryptor.encrypt_versioned_der(plaintext).unwrap();

// Decrypt with auto-format detection
let decryptor = Sm2Decryptor::new(key_pair);
assert_eq!(decryptor.decrypt(&raw).unwrap(), plaintext);
assert_eq!(decryptor.decrypt(&der).unwrap(), plaintext);
assert_eq!(decryptor.decrypt(&versioned_raw).unwrap(), plaintext);
assert_eq!(decryptor.decrypt(&versioned_der).unwrap(), plaintext);
```

**Format Description**:

| Format | Signature | Use Case |
| --------------- | ------------------ | ----------------- |
| Raw C1\ | \ | C3\ | \ | C2 | starts with `0x04` | internal use, efficient transmission |
| DER SM2Cipher | starts with `0x30` | GmSSL compatibility |
| Versioned | starts with `0x53 0x4D` | explicit format, future-proof |

### ECDH Key Exchange

SM2 supports standard ECDH key exchange for TLCP ECDHE cipher suites and TLS 1.3 key share:


```rust
use gm_crypto::sm2::Sm2EcdhKeypair;

// Both parties generate ephemeral key pairs
let alice = Sm2EcdhKeypair::generate().unwrap();
let bob = Sm2EcdhKeypair::generate().unwrap();

// Exchange public keys and compute shared secret
let shared_alice = alice.compute_shared_secret(&bob.public_key_bytes()).unwrap();
let shared_bob = bob.compute_shared_secret(&alice.public_key_bytes()).unwrap();

assert_eq!(shared_alice, shared_bob);
// Shared secret is 32 bytes (x-coordinate), must pass through KDF for session keys
```

### Signature Format Conversion

SM2 signature supports DER ↔ raw conversion for X.509 and CMS compatibility:


```rust
use gm_crypto::sm2::{sm2_signature_raw_to_der, sm2_signature_der_to_raw};

// Raw signature (r||s, 64 bytes) → DER format
let der_sig = sm2_signature_raw_to_der(&raw_64_bytes);

// DER format → raw signature
let raw_sig = sm2_signature_der_to_raw(&der_bytes).unwrap();
```
