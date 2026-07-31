//! DER decoding/parsing primitives.

use super::DerError;

// ============================================================================
// DER Length Parsing
// ============================================================================

/// Parse a DER length field (1–4 byte long form).
/// Returns `(remaining_after_length_field, length_value)`.
pub fn parse_der_length(data: &[u8]) -> Result<(&[u8], usize), DerError> {
    if data.is_empty() {
        return Err(DerError::ParseError("truncated length".to_string()));
    }
    let first = data[0];
    if first < 0x80 {
        Ok((&data[1..], first as usize))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return Err(DerError::ParseError(format!(
                "invalid long form length ({})",
                num_bytes
            )));
        }
        if data.len() < 1 + num_bytes {
            return Err(DerError::ParseError(
                "truncated long form length".to_string(),
            ));
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((&data[1 + num_bytes..], len))
    }
}

// ============================================================================
// DER Tag Parsing
// ============================================================================

/// Parse a DER SEQUENCE (tag `0x30`).
/// Returns `(remaining_after_sequence, sequence_contents)`.
pub fn parse_der_sequence(data: &[u8]) -> Result<(&[u8], &[u8]), DerError> {
    if data.is_empty() {
        return Err(DerError::ParseError("empty data".to_string()));
    }
    if data[0] != 0x30 {
        return Err(DerError::ParseError(format!(
            "expected SEQUENCE tag 0x30, got 0x{:02X}",
            data[0]
        )));
    }
    let (remaining, length) = parse_der_length(&data[1..])?;
    if remaining.len() < length {
        return Err(DerError::ParseError("truncated SEQUENCE".to_string()));
    }
    Ok((&remaining[length..], &remaining[..length]))
}

/// Parse a DER EXPLICIT context tag `[tag]` (tag byte = `0xA0 | tag`).
/// Returns `(remaining_after_tag, inner_contents)`.
pub fn parse_der_explicit(data: &[u8], tag: u8) -> Result<(&[u8], &[u8]), DerError> {
    if data.is_empty() {
        return Err(DerError::ParseError("empty data".to_string()));
    }
    let expected = 0xA0 | tag;
    if data[0] != expected {
        return Err(DerError::ParseError(format!(
            "expected context [{}] tag 0x{:02X}, got 0x{:02X}",
            tag, expected, data[0]
        )));
    }
    let (remaining, length) = parse_der_length(&data[1..])?;
    if remaining.len() < length {
        return Err(DerError::ParseError("truncated EXPLICIT".to_string()));
    }
    Ok((&remaining[length..], &remaining[..length]))
}

/// Parse a DER INTEGER (tag `0x02`) as unsigned bytes.
/// Returns `(remaining_after_integer, value_bytes)`.
pub fn parse_der_integer(data: &[u8]) -> Result<(&[u8], &[u8]), DerError> {
    if data.is_empty() {
        return Err(DerError::ParseError("empty data".to_string()));
    }
    if data[0] != 0x02 {
        return Err(DerError::ParseError(format!(
            "expected INTEGER tag 0x02, got 0x{:02X}",
            data[0]
        )));
    }
    let (remaining, length) = parse_der_length(&data[1..])?;
    if remaining.len() < length {
        return Err(DerError::ParseError("truncated INTEGER".to_string()));
    }
    Ok((&remaining[length..], &remaining[..length]))
}

/// Parse a DER OID (tag `0x06`).
/// Returns `(remaining_after_oid, oid_bytes)`.
pub fn parse_der_oid(data: &[u8]) -> Result<(&[u8], &[u8]), DerError> {
    if data.is_empty() {
        return Err(DerError::ParseError("empty data".to_string()));
    }
    if data[0] != 0x06 {
        return Err(DerError::ParseError(format!(
            "expected OID tag 0x06, got 0x{:02X}",
            data[0]
        )));
    }
    let (remaining, length) = parse_der_length(&data[1..])?;
    if remaining.len() < length {
        return Err(DerError::ParseError("truncated OID".to_string()));
    }
    Ok((&remaining[length..], &remaining[..length]))
}

/// Parse a DER OCTET STRING (tag `0x04`).
/// Returns `(remaining_after_octet_string, contents)`.
pub fn parse_der_octet_string(data: &[u8]) -> Result<(&[u8], &[u8]), DerError> {
    if data.is_empty() {
        return Err(DerError::ParseError("empty data".to_string()));
    }
    if data[0] != 0x04 {
        return Err(DerError::ParseError(format!(
            "expected OCTET STRING tag 0x04, got 0x{:02X}",
            data[0]
        )));
    }
    let (remaining, length) = parse_der_length(&data[1..])?;
    if remaining.len() < length {
        return Err(DerError::ParseError("truncated OCTET STRING".to_string()));
    }
    Ok((&remaining[length..], &remaining[..length]))
}

/// Parse a DER BIT STRING (tag `0x03`).
/// Returns `(remaining_after_bit_string, bit_string_contents)`.
/// The returned contents include the unused-bits byte.
pub fn parse_der_bit_string(data: &[u8]) -> Result<(&[u8], &[u8]), DerError> {
    if data.is_empty() {
        return Err(DerError::ParseError("empty data".to_string()));
    }
    if data[0] != 0x03 {
        return Err(DerError::ParseError(format!(
            "expected BIT STRING tag 0x03, got 0x{:02X}",
            data[0]
        )));
    }
    let (remaining, length) = parse_der_length(&data[1..])?;
    if remaining.len() < length {
        return Err(DerError::ParseError("truncated BIT STRING".to_string()));
    }
    Ok((&remaining[length..], &remaining[..length]))
}

// ============================================================================
// Utility
// ============================================================================

/// Read exactly `n` bytes from the start of `data`.
/// Returns `(remaining, consumed_bytes)`.
pub fn read_bytes(data: &[u8], n: usize) -> Result<(&[u8], &[u8]), DerError> {
    if data.len() < n {
        return Err(DerError::ParseError(format!(
            "need {} bytes, got {}",
            n,
            data.len()
        )));
    }
    Ok((&data[n..], &data[..n]))
}

/// Read a `u16` in big-endian format.
pub fn read_u16(data: &[u8]) -> Result<(&[u8], u16), DerError> {
    if data.len() < 2 {
        return Err(DerError::ParseError("need 2 bytes for u16".to_string()));
    }
    let val = u16::from_be_bytes([data[0], data[1]]);
    Ok((&data[2..], val))
}

/// Read a `u32` in big-endian format.
pub fn read_u32(data: &[u8]) -> Result<(&[u8], u32), DerError> {
    if data.len() < 4 {
        return Err(DerError::ParseError("need 4 bytes for u32".to_string()));
    }
    let val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Ok((&data[4..], val))
}
