//! Fuzz target for TLS record parsing
//!
//! This fuzz target tests the parsing of TLS records with various inputs.

#![no_main]

use libfuzzer_sys::{fuzz_target, arbitrary::Arbitrary};
use gm_tls::gm::next_nonce;
use gm_crypto::sm4::Sm4Cipher;
use std::io::{Cursor, Read};

// Unified input enum
#[derive(Arbitrary, Debug)]
enum TlsRecordInput {
    // Test TLS record encryption/decryption
    Record(TlsRecordFuzzInput),
    // Test nonce generation
    Nonce(NonceInput),
    // Test SM2 point operations
    Sm2Point(Sm2PointInput),
}

#[derive(Arbitrary, Debug)]
struct TlsRecordFuzzInput {
    /// Plaintext data to encrypt and format
    data: Vec<u8>,
    /// Base nonce for GCM (12 bytes)
    nonce: [u8; 12],
    /// Sequence number
    seq: u64,
    /// Associated data for GCM
    aad: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct NonceInput {
    base: [u8; 12],
    seq: u64,
}

#[derive(Arbitrary, Debug)]
struct Sm2PointInput {
    x: [u8; 32],
    y: [u8; 32],
    scalar: [u8; 32],
}

fuzz_target!(|input: TlsRecordInput| {
    match input {
        TlsRecordInput::Record(r) => fuzz_record(r),
        TlsRecordInput::Nonce(n) => fuzz_nonce(n),
        TlsRecordInput::Sm2Point(s) => fuzz_sm2_point(s),
    }
});

fn fuzz_record(input: TlsRecordFuzzInput) {
    // Create a valid key
    let key = vec![0x42u8; 16];
    let cipher = match Sm4Cipher::new(&key) {
        Ok(c) => c,
        Err(_) => return, // Invalid key, skip
    };

    // Build nonce from base and sequence
    let nonce = match next_nonce(&input.nonce, input.seq) {
        Ok(n) => n,
        Err(_) => return,
    };

    // Encrypt the data
    let aad_bytes: &[u8] = if input.aad.len() <= 8 {
        &input.aad
    } else {
        &input.aad[..8]
    };

    let encrypt_result = cipher.encrypt_gcm(&input.data, &nonce, aad_bytes);

    match encrypt_result {
        Ok((ciphertext, tag)) => {
            // Build a TLS record: 4-byte length + ciphertext + 16-byte tag
            let record_len = (ciphertext.len() + tag.len()) as u32;
            let mut record = Vec::with_capacity(4 + ciphertext.len() + tag.len());
            record.extend_from_slice(&record_len.to_be_bytes());
            record.extend_from_slice(&ciphertext);
            record.extend_from_slice(&tag);

            // Try to parse the record back
            let mut cursor = Cursor::new(&record);

            // Read length (u32)
            let mut len_buf = [0u8; 4];
            if cursor.read_exact(&mut len_buf).is_err() {
                return;
            }
            let total_len = u32::from_be_bytes(len_buf) as usize;

            // Validate length bounds
            if total_len < 16 {
                // Minimum: some ciphertext + 16-byte tag
                return;
            }

            // Read ciphertext + tag
            let mut buf = vec![0u8; total_len];
            if cursor.read_exact(&mut buf).is_err() {
                return;
            }

            // Split into ciphertext and tag
            let (ct, tg) = buf.split_at(total_len.saturating_sub(16));
            let tag: [u8; 16] = match tg.try_into() {
                Ok(t) => t,
                Err(_) => return,
            };

            // Try to decrypt
            let _ = cipher.decrypt_gcm(ct, &nonce, aad_bytes, &tag);
        }
        Err(_) => {
            // Encryption failed, which is fine for some inputs
        }
    }
}

fn fuzz_nonce(input: NonceInput) {
    let nonce = match next_nonce(&input.base, input.seq) {
        Ok(n) => n,
        Err(_) => return,
    };

    // Verify nonce follows RFC 8446 §5.3: nonce = XOR(base, left_padded_seq)
    let seq_bytes = input.seq.to_be_bytes();
    for i in 0..12 {
        let expected = if i < 4 {
            // First 4 bytes: XOR with 0x00 (seq high bytes are 0 for u64)
            input.base[i]
        } else {
            // Last 8 bytes: XOR with big-endian seq
            input.base[i] ^ seq_bytes[i - 4]
        };
        assert_eq!(nonce[i], expected);
    }
}

fn fuzz_sm2_point(input: Sm2PointInput) {
    use sm2::ProjectivePoint;
    use elliptic_curve::sec1::FromEncodedPoint;
    use sm2::EncodedPoint;

    // Try to decode as an encoded point
    let mut encoded = vec![0x04u8]; // Uncompressed point
    encoded.extend_from_slice(&input.x);
    encoded.extend_from_slice(&input.y);

    let enc_point = match EncodedPoint::from_bytes(&encoded) {
        Ok(ep) => ep,
        Err(_) => return,
    };

    let point = ProjectivePoint::from_encoded_point(&enc_point);

    // If valid point, try scalar multiplication
    if let Some(_pt) = point.into_option() {
        // Point is on the curve
    }
}