//! SM9 signature algorithm

use crate::Sm9Error;
use crate::curve::g1::G1Point;
use crate::curve::g2::G2Point;
use crate::curve::{Identity, ScalarMul};
use crate::field::FieldElement;
use crate::hash;
use crate::key::SignUserKey;
use crate::key::{random_scalar, sub_mod};
use crate::pairing;
use crate::z256::Z256;
use rand::CryptoRng;
use zeroize::ZeroizeOnDrop;

/// SM9 signature
#[derive(Clone, ZeroizeOnDrop)]
pub struct Signature {
    /// h component
    pub h: Z256,
    /// S component (G1 point)
    pub s: G1Point,
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signature")
            .field("h", &"<redacted>")
            .field("s", &self.s)
            .finish()
    }
}

impl Signature {
    /// Serialize signature to raw bytes (h || s)
    /// h: 32 bytes (Z256), s: 65 bytes (uncompressed G1 point)
    pub fn to_bytes(&self) -> Vec<u8> {
        use crate::z256::to_bytes_be;
        let mut bytes = Vec::with_capacity(32 + 65);
        bytes.extend_from_slice(&to_bytes_be(&self.h));
        // G1 point: 0x04 || x || y
        if let Some((x, y)) = self.s.to_affine() {
            bytes.push(0x04);
            bytes.extend_from_slice(&x.to_bytes());
            bytes.extend_from_slice(&y.to_bytes());
        } else {
            // Identity point: 0x00 || 0x00...00
            bytes.push(0x00);
            bytes.extend_from_slice(&[0u8; 64]);
        }
        bytes
    }

    /// Serialize signature to DER format (GM/T 0080-2020)
    /// SM9Signature ::= SEQUENCE { h INTEGER, S BIT STRING }
    /// Note: GM/T 0044-2016 §5.2 specifies h as INTEGER, not OCTET STRING.
    pub fn to_der(&self) -> Vec<u8> {
        use crate::z256::to_bytes_be;

        // h as INTEGER per GM/T 0044-2016 §5.2 (was incorrectly OCTET STRING)
        let h_bytes = to_bytes_be(&self.h);
        let h_int = asn1_integer(&h_bytes);

        // S as BIT STRING (uncompressed point: 0x04 || x || y)
        let s_bitstring = if let Some((x, y)) = self.s.to_affine() {
            let mut point = Vec::with_capacity(65);
            point.push(0x04); // uncompressed
            point.extend_from_slice(&x.to_bytes());
            point.extend_from_slice(&y.to_bytes());
            asn1_bit_string(&point)
        } else {
            // Identity point
            let mut point = vec![0u8; 65];
            point[0] = 0x00;
            asn1_bit_string(&point)
        };

        // SEQUENCE { h, S }
        let mut content = Vec::with_capacity(h_int.len() + s_bitstring.len());
        content.extend_from_slice(&h_int);
        content.extend_from_slice(&s_bitstring);

        asn1_sequence(&content)
    }

    /// Parse signature from raw bytes (h || s)
    /// h: 32 bytes (Z256), s: 65 bytes (uncompressed G1 point with 0x04 prefix) or 64 bytes (raw x||y)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Sm9Error> {
        if bytes.len() == 32 + 65 {
            // 0x04 prefix format
            let h = crate::z256::from_bytes_be(&bytes[..32])
                .ok_or_else(|| Sm9Error::InvalidParameter("Invalid h value".to_string()))?;
            if bytes[32] != 0x04 {
                return Err(Sm9Error::InvalidParameter(format!(
                    "Invalid S point prefix: expected 0x04, got 0x{:02x}",
                    bytes[32]
                )));
            }
            let x = crate::field::fp::Fp::from_bytes(&bytes[33..65])?;
            let y = crate::field::fp::Fp::from_bytes(&bytes[65..97])?;
            let s = crate::curve::g1::G1Point::from_affine(x, y);
            Ok(Self { h, s })
        } else if bytes.len() == 32 + 64 {
            // Raw x||y format (no prefix)
            let h = crate::z256::from_bytes_be(&bytes[..32])
                .ok_or_else(|| Sm9Error::InvalidParameter("Invalid h value".to_string()))?;
            let x = crate::field::fp::Fp::from_bytes(&bytes[32..64])?;
            let y = crate::field::fp::Fp::from_bytes(&bytes[64..96])?;
            let s = crate::curve::g1::G1Point::from_affine(x, y);
            Ok(Self { h, s })
        } else {
            Err(Sm9Error::InvalidParameter(format!(
                "Invalid signature bytes length: expected 97 or 96, got {}",
                bytes.len()
            )))
        }
    }

    /// Parse signature from DER format
    /// Supports both GM/T 0044-2016 (INTEGER for h) and GmSSL 3.1.1 (OCTET STRING for h)
    pub fn from_der(der: &[u8]) -> Result<Self, Sm9Error> {
        // Parse SEQUENCE
        let content = parse_asn1_sequence(der)?;

        // Parse h — GmSSL 3.1.1 uses OCTET STRING (0x04), GM/T 0044 uses INTEGER (0x02)
        let (h_bytes, rest) = if !content.is_empty() && content[0] == 0x04 {
            // GmSSL format: OCTET STRING — parse_der_octet_string returns (remaining, contents)
            let (rest, val) = parse_der_octet_string(content)
                .map_err(|e| Sm9Error::InvalidParameter(e.to_string()))?;
            (val, rest)
        } else {
            // Standard format: INTEGER
            parse_asn1_integer(content)?
        };
        if h_bytes.len() != 32 {
            return Err(Sm9Error::InvalidParameter(format!(
                "Invalid h length: expected 32, got {}",
                h_bytes.len()
            )));
        }
        let h = crate::z256::from_bytes_be(h_bytes)
            .ok_or_else(|| Sm9Error::InvalidParameter("Invalid h value".to_string()))?;

        // Parse S (BIT STRING)
        let (s_bytes, _rest) = parse_asn1_bit_string(rest)?;
        if s_bytes.len() != 65 || s_bytes[0] != 0x04 {
            return Err(Sm9Error::InvalidParameter(format!(
                "Invalid S point format: expected 65 bytes with 0x04 prefix, got {} bytes with prefix 0x{:02x}",
                s_bytes.len(),
                s_bytes.first().unwrap_or(&0)
            )));
        }

        let x = crate::field::fp::Fp::from_bytes(&s_bytes[1..33])
            .map_err(|_| Sm9Error::InvalidParameter("Invalid S x coordinate".to_string()))?;
        let y = crate::field::fp::Fp::from_bytes(&s_bytes[33..65])
            .map_err(|_| Sm9Error::InvalidParameter("Invalid S y coordinate".to_string()))?;
        let s = crate::curve::g1::G1Point::from_affine(x, y);

        Ok(Signature { h, s })
    }
}

// DER/ASN.1 helpers — re-exported from gm-der crate with Sm9Error adapter

use gm_der::{
    der_bit_string as asn1_bit_string, der_len as asn1_length, der_sequence as asn1_sequence,
    parse_der_bit_string, parse_der_integer, parse_der_length, parse_der_octet_string,
    parse_der_sequence,
};

/// DER INTEGER encoding per X.690 §8.3.
/// Handles positive integers with minimum-length encoding (no leading zero padding
/// unless required to indicate sign).
fn asn1_integer(data: &[u8]) -> Vec<u8> {
    // Remove leading zeros and determine if we need a leading 0x00 to prevent negative interpretation
    let trimmed = data
        .iter()
        .skip_while(|&&b| b == 0)
        .copied()
        .collect::<Vec<_>>();
    let data = if trimmed.is_empty() {
        &[0u8] as &[u8]
    } else {
        &trimmed
    };

    // If high bit is set, prepend 0x00 to make it unsigned
    let needs_sign_bit = (data[0] & 0x80) != 0;
    let mut result = vec![0x02]; // INTEGER tag
    let content_len = data.len() + if needs_sign_bit { 1 } else { 0 };
    result.extend_from_slice(&asn1_length(content_len));
    if needs_sign_bit {
        result.push(0x00);
    }
    result.extend_from_slice(data);
    result
}

#[allow(dead_code)] // Kept for potential future DER parsing needs
fn parse_asn1_tag_length(data: &[u8]) -> Result<(u8, usize, &[u8]), Sm9Error> {
    if data.len() < 2 {
        return Err(Sm9Error::InvalidParameter(
            "ASN.1 data too short".to_string(),
        ));
    }
    let tag = data[0];
    let (length, rest) = parse_asn1_length(&data[1..])?;
    Ok((tag, length, rest))
}

#[allow(dead_code)] // Kept for potential future DER parsing needs
fn parse_asn1_length(data: &[u8]) -> Result<(usize, &[u8]), Sm9Error> {
    let (rest, length) =
        parse_der_length(data).map_err(|e| Sm9Error::InvalidParameter(e.to_string()))?;
    Ok((length, rest))
}

fn parse_asn1_sequence(data: &[u8]) -> Result<&[u8], Sm9Error> {
    let (rest, content) =
        parse_der_sequence(data).map_err(|e| Sm9Error::InvalidParameter(e.to_string()))?;
    // gm-sm9's original returned &rest[..length], which is the same as content
    let _ = rest;
    Ok(content)
}

#[allow(dead_code)] // Kept for potential future DER parsing needs
fn parse_asn1_octet_string(data: &[u8]) -> Result<(&[u8], &[u8]), Sm9Error> {
    parse_der_octet_string(data).map_err(|e| Sm9Error::InvalidParameter(e.to_string()))
}

fn parse_asn1_bit_string(data: &[u8]) -> Result<(&[u8], &[u8]), Sm9Error> {
    let (rest, content_with_unused) =
        parse_der_bit_string(data).map_err(|e| Sm9Error::InvalidParameter(e.to_string()))?;
    // gm-sm9's original stripped the unused-bits byte; gm-der returns it
    if content_with_unused.is_empty() || content_with_unused[0] != 0 {
        return Err(Sm9Error::InvalidParameter(
            "Unsupported unused bits in BIT STRING".to_string(),
        ));
    }
    let content = &content_with_unused[1..];
    Ok((content, rest))
}

/// Parse an ASN.1 INTEGER into a big-endian byte slice.
/// Handles the optional leading 0x00 that may precede positive integers.
fn parse_asn1_integer(data: &[u8]) -> Result<(&[u8], &[u8]), Sm9Error> {
    let (rest, content) =
        parse_der_integer(data).map_err(|e| Sm9Error::InvalidParameter(e.to_string()))?;
    // Strip optional leading zero used to indicate positive sign
    let content = if content.len() > 1 && content[0] == 0x00 {
        &content[1..]
    } else {
        content
    };
    Ok((content, rest))
}

/// SM9 signer
pub struct Signer {
    key: SignUserKey,
    identity: Vec<u8>,
}

impl Signer {
    /// Create a new signer with a user signing key and identity
    pub fn new(key: SignUserKey) -> Self {
        // Default identity for backward compatibility
        Self {
            key,
            identity: Vec::new(),
        }
    }

    /// Create a new signer with a user signing key and identity string
    /// The identity is needed for sign-then-verify fault protection.
    pub fn with_identity(key: SignUserKey, identity: &[u8]) -> Self {
        Self {
            key,
            identity: identity.to_vec(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8], rng: &mut impl CryptoRng) -> Result<Signature, Sm9Error> {
        // g = e(P1, Ppubs) where P1 ∈ G1, Ppubs ∈ G2
        // GmSSL: sm9_z256_pairing(g, &key->Ppubs, sm9_z256_generator()) = e(P1, Ppubs)
        // Our pairing(p: G1, q: G2) computes e(P, Q), so we pass (P1, Ppubs)
        let p1 = crate::params::g1_generator();
        let g = pairing::ate::pairing(&p1, &self.key.ppubs);

        const MAX_SIGN_RETRIES: u32 = 128; // Practical limit; probability of hitting this is <2^-128
        for _ in 0..MAX_SIGN_RETRIES {
            // rand r in [1, N-1]
            let r = random_scalar(rng)?;

            // w = g^r
            let w = g.pow(&r);
            let w_bytes = w.to_bytes_gmssl();

            // h = H2(M || w, N)
            let h = hash::hash2(message, &w_bytes);

            // l = (r - h) mod N
            let l = sub_mod(&r, &h, &Z256::N);

            if !l.is_zero() {
                // S = l * ds
                let s = self.key.ds.scalar_mul(&l);
                let sig = Signature { h, s };

                // Sign-then-verify fault protection:
                // Verify the signature before returning it. This catches fault
                // injection attacks that corrupt intermediate values during
                // signing. Only performed when identity is available.
                // See: Boneh, DeMillo, Lipton (1997) — fault attacks on signatures.
                if !self.identity.is_empty() {
                    let verifier = Verifier::new(&self.identity, &self.key.ppubs);
                    if !verifier.verify(message, &sig)? {
                        // Signature verification failed — likely a fault.
                        // Retry with a new random r.
                        continue;
                    }
                }

                return Ok(sig);
            }
        }
        Err(Sm9Error::SigningError(
            "Max retries exceeded — this should never happen".to_string(),
        ))
    }
}

/// SM9 verifier
pub struct Verifier {
    identity: Vec<u8>,
    ppubs: G2Point,
}

impl Verifier {
    /// Create a new verifier for an identity and master public key
    pub fn new(identity: &[u8], ppubs: &G2Point) -> Self {
        Self {
            identity: identity.to_vec(),
            ppubs: *ppubs,
        }
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool, Sm9Error> {
        if signature.s.is_identity() {
            return Ok(false);
        }

        // h1 = H1(ID_A || hid, N)
        let h1 = hash::hash1(&self.identity, 0x01);

        // P = h1 * P2 + Ppubs
        let p2 = crate::params::g2_generator();
        let p = p2.scalar_mul(&h1).add(&self.ppubs);

        // P 必须非单位元（已在曲线上由 G2 群运算保证）

        // g = e(P1, Ppubs) where P1 ∈ G1, Ppubs ∈ G2
        let p1 = crate::params::g1_generator();
        let g = pairing::ate::pairing(&p1, &self.ppubs);

        // S 必须非单位元

        // u = e(S, P) where S ∈ G1, P ∈ G2
        let u = pairing::ate::pairing(&signature.s, &p);

        // t = g^h
        let t = g.pow(&signature.h);

        // w' = u * t
        let w_prime = u.mul(&t);
        let w_bytes = w_prime.to_bytes_gmssl();

        // h' = H2(M || w', N)
        let h_prime = hash::hash2(message, &w_bytes);

        // h' == h ? (constant-time comparison to prevent timing attacks)
        use subtle::ConstantTimeEq;
        let h_matches: bool = h_prime.ct_eq(&signature.h).into();
        Ok(h_matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SignMasterKey;

    #[test]
    fn test_signature_roundtrip() {
        use rand::rng as thread_rng;

        // Generate master key
        let master =
            SignMasterKey::generate(&mut thread_rng()).expect("Failed to generate master key");

        // Extract user signing key
        let identity = b"test@example.com";
        let user_key = master.extract_key(identity).expect("Failed to extract key");

        // Sign a message
        let signer = Signer::new(user_key);
        let message = b"Hello, SM9!";
        let signature = signer
            .sign(message, &mut thread_rng())
            .expect("Failed to sign");

        // Verify the signature
        let verifier = Verifier::new(identity, &master.ppubs);
        let valid = verifier
            .verify(message, &signature)
            .expect("Verification failed");

        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn test_signature_invalid_message() {
        use rand::rng as thread_rng;

        let master =
            SignMasterKey::generate(&mut thread_rng()).expect("Failed to generate master key");
        let identity = b"test@example.com";
        let user_key = master.extract_key(identity).expect("Failed to extract key");

        let signer = Signer::new(user_key);
        let message = b"Hello, SM9!";
        let signature = signer
            .sign(message, &mut thread_rng())
            .expect("Failed to sign");

        // Verify with wrong message
        let verifier = Verifier::new(identity, &master.ppubs);
        let valid = verifier
            .verify(b"Wrong message", &signature)
            .expect("Verification failed");

        assert!(!valid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_signature_der_roundtrip() {
        use rand::rng as thread_rng;

        let master =
            SignMasterKey::generate(&mut thread_rng()).expect("Failed to generate master key");
        let identity = b"test@example.com";
        let user_key = master.extract_key(identity).expect("Failed to extract key");

        let signer = Signer::new(user_key);
        let message = b"Hello, SM9!";
        let signature = signer
            .sign(message, &mut thread_rng())
            .expect("Failed to sign");

        // Serialize to DER
        let der = signature.to_der();
        println!("DER length: {}", der.len());
        println!("DER: {:02x?}", der);

        // Parse from DER
        let parsed = Signature::from_der(&der).expect("Failed to parse DER");

        // Verify parsed signature
        let verifier = Verifier::new(identity, &master.ppubs);
        let valid = verifier
            .verify(message, &parsed)
            .expect("Verification failed");
        assert!(valid, "Parsed signature should be valid");

        // Components should match
        assert_eq!(signature.h, parsed.h, "h component should match");
    }

    #[test]
    fn test_signature_with_small_scalar() {
        // Test with a small fixed scalar to avoid slow pairing computation
        // This verifies the signature logic without waiting for large scalar mul
        use crate::curve::{Identity, ScalarMul};

        // Create a master key with small scalar s=2
        let s = Z256([2, 0, 0, 0]);
        let p2 = crate::params::g2_generator();
        let ppubs = p2.scalar_mul(&s);
        let master = SignMasterKey { s, ppubs };

        let identity = b"test@example.com";
        let user_key = master.extract_key(identity).expect("Failed to extract key");

        let _signer = Signer::new(user_key);
        let _message = b"Hello, SM9!";

        // Sign with a small random scalar (we'll use a fixed one for speed)
        // For this test, we just verify the key extraction works
        assert!(
            !master.ppubs.is_identity(),
            "Master public key should not be identity"
        );

        // Note: Full signature with small scalar still requires pairing,
        // which is slow. This test just verifies key generation.
    }
}
