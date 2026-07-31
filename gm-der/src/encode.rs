//! DER encoding primitives.

// ============================================================================
// DER Length Encoding
// ============================================================================

/// Encode a DER length field.
///
/// - `< 0x80`: single byte
/// - `< 0x100`: `0x81` + 1 byte
/// - `< 0x10000`: `0x82` + 2 bytes
/// - etc.
pub fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len < 0x1000000 {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        vec![
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

// ============================================================================
// DER Tag Encoding
// ============================================================================

/// Encode an OBJECT IDENTIFIER (tag 0x06).
pub fn encode_oid(oid: &[u8]) -> Vec<u8> {
    let mut v = vec![0x06];
    v.extend_from_slice(&der_len(oid.len()));
    v.extend_from_slice(oid);
    v
}

/// Encode an INTEGER (tag 0x02) from positive bytes.
/// Adds a leading `0x00` if the high bit is set (DER signed-integer rule).
pub fn der_integer_positive(bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![0x02];
    let content = if !bytes.is_empty() && bytes[0] >= 0x80 {
        std::iter::once(&0x00u8)
            .chain(bytes.iter())
            .copied()
            .collect()
    } else {
        bytes.to_vec()
    };
    v.extend_from_slice(&der_len(content.len()));
    v.extend_from_slice(&content);
    v
}

/// Encode a UTF8String (tag 0x0C).
pub fn der_utf8_string(s: &[u8]) -> Vec<u8> {
    let mut v = vec![0x0C];
    v.extend_from_slice(&der_len(s.len()));
    v.extend_from_slice(s);
    v
}

/// Encode a SEQUENCE (tag 0x30) from pre-concatenated contents.
pub fn der_sequence(contents: &[u8]) -> Vec<u8> {
    let mut v = vec![0x30];
    v.extend_from_slice(&der_len(contents.len()));
    v.extend_from_slice(contents);
    v
}

/// Encode a SEQUENCE (tag 0x30) from a slice of already-encoded items.
pub fn der_sequence_v(items: &[Vec<u8>]) -> Vec<u8> {
    let content_len: usize = items.iter().map(|i| i.len()).sum();
    let mut v = vec![0x30];
    v.extend_from_slice(&der_len(content_len));
    for item in items {
        v.extend_from_slice(item);
    }
    v
}

/// Encode a BIT STRING (tag 0x03).
/// Adds an unused-bits byte (`0x00`) at the start of the bit-string contents.
pub fn der_bit_string(bits: &[u8]) -> Vec<u8> {
    let mut v = vec![0x03];
    v.extend_from_slice(&der_len(bits.len() + 1));
    v.push(0x00); // unused bits count
    v.extend_from_slice(bits);
    v
}

/// Encode an OCTET STRING (tag 0x04).
pub fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04];
    v.extend_from_slice(&der_len(data.len()));
    v.extend_from_slice(data);
    v
}

/// Encode a BOOLEAN (tag 0x01).
pub fn der_bool(b: bool) -> Vec<u8> {
    vec![0x01, 0x01, if b { 0xFF } else { 0x00 }]
}

/// Encode a SET (tag 0x31) from a slice of already-encoded items.
pub fn der_set(items: &[Vec<u8>]) -> Vec<u8> {
    let content_len: usize = items.iter().map(|i| i.len()).sum();
    let mut v = vec![0x31];
    v.extend_from_slice(&der_len(content_len));
    for item in items {
        v.extend_from_slice(item);
    }
    v
}

/// Encode an EXPLICIT context-tagged value `[tag]` (tag byte = `0xA0 | tag`).
/// Used for `version` (tag 0), `extensions` (tag 3), etc.
pub fn der_explicit_context(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut v = vec![0xA0 | tag];
    v.extend_from_slice(&der_len(contents.len()));
    v.extend_from_slice(contents);
    v
}

/// Encode a length as a 2-byte big-endian value (non-DER, TLS-style).
pub fn der_len_u16(len: usize) -> [u8; 2] {
    [(len >> 8) as u8, len as u8]
}
