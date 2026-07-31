//! DER encoding/decoding helpers and TLS constants.
//!
//! DER encoding/decoding primitives are re-exported from the `gm-der` crate.
//! This module additionally provides TLS protocol constants and record header
//! types specific to GM/TLS (RFC 8446 + GB/T 38636-2020).

// Re-export DER encoding/decoding primitives from gm-der
pub use gm_der::{
    der_bit_string, der_bool, der_explicit_context, der_integer_positive, der_len, der_len_u16,
    der_octet_string, der_sequence, der_sequence_v, der_set, der_utf8_string, encode_oid,
    parse_der_bit_string, parse_der_explicit, parse_der_integer, parse_der_length,
    parse_der_octet_string, parse_der_oid, parse_der_sequence, read_bytes, read_u16, read_u32,
};

use crate::error::TlsError;

// ============================================================================
// TLS Constants
// ============================================================================

/// TLS content types (RFC 8446 §6)
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const CONTENT_TYPE_ALERT: u8 = 0x15;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;

/// TLS handshake message types (RFC 8446 §6)
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
pub const HANDSHAKE_TYPE_NEW_SESSION_TICKET: u8 = 0x04;
pub const HANDSHAKE_TYPE_END_OF_EARLY_DATA: u8 = 0x05;
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 0x0B;
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 0x0F;
pub const HANDSHAKE_TYPE_FINISHED: u8 = 0x14;
pub const HANDSHAKE_TYPE_CERTIFICATE_REQUEST: u8 = 0x0D;
pub const HANDSHAKE_TYPE_MESSAGE_DUMP: u8 = 0xFF; // Not standard

/// Protocol versions
pub const VERSION_TLS_1_3: [u8; 2] = [0x03, 0x03];
pub const VERSION_TLCP_1_0: [u8; 2] = [0x01, 0x01];

/// GM cipher suites (RFC 8998 + GB/T 38636-2020)
/// GM_SM4_GCM_SM2 = 0xE001
pub const CIPHER_SUITE_GM_SM4_GCM_SM2: [u8; 2] = [0xE0, 0x01];

/// SM2 signature algorithm OID: 1.2.156.10197.1.501
pub const SM2_SIG_OID: &[u8] = &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x02, 0x01, 0xF5];
/// SM2 public key OID: 1.2.156.10197.1.301
pub const SM2_PK_OID: &[u8] = &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x01, 0x01];

/// TLS SignatureScheme for SM2withSM3 (RFC 8998)
/// Assigned IANA value: 0x0708 (pending official assignment)
pub const SIGNATURE_SCHEME_SM2_WITH_SM3: u16 = 0x0708;

// ============================================================================
// TLS Record Header
// ============================================================================

/// TLS record header (5 bytes: content_type + version + length).
/// This is the unencrypted record header that precedes all TLS records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsRecordHeader {
    pub content_type: u8,
    pub version: [u8; 2],
    pub length: u16,
}

impl TlsRecordHeader {
    pub const SIZE: usize = 5;

    /// Encode the header as 5 bytes.
    pub fn encode(&self) -> [u8; 5] {
        [
            self.content_type,
            self.version[0],
            self.version[1],
            (self.length >> 8) as u8,
            self.length as u8,
        ]
    }

    /// Decode a 5-byte header from the start of data.
    pub fn decode(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 5 {
            return Err(TlsError::DerParseError(
                "need 5 bytes for record header".to_string(),
            ));
        }
        Ok(Self {
            content_type: data[0],
            version: [data[1], data[2]],
            length: u16::from_be_bytes([data[3], data[4]]),
        })
    }

    /// Create a handshake record header.
    pub fn handshake(length: u16, version: &[u8; 2]) -> Self {
        Self {
            content_type: CONTENT_TYPE_HANDSHAKE,
            version: *version,
            length,
        }
    }

    /// Create an application data record header.
    pub fn application_data(length: u16, version: &[u8; 2]) -> Self {
        Self {
            content_type: CONTENT_TYPE_APPLICATION_DATA,
            version: *version,
            length,
        }
    }

    /// Create an alert record header.
    pub fn alert(_level: u8, _description: u8, version: &[u8; 2]) -> Self {
        Self {
            content_type: CONTENT_TYPE_ALERT,
            version: *version,
            length: 2, // alert level + description
        }
    }
}

/// Protocol version for TLS 1.3 or GB/T 38636-2020 TLCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    TLS1_3,
    TLCP1_0,
}

impl ProtocolVersion {
    pub fn bytes(&self) -> [u8; 2] {
        match self {
            ProtocolVersion::TLS1_3 => VERSION_TLS_1_3,
            ProtocolVersion::TLCP1_0 => VERSION_TLCP_1_0,
        }
    }

    pub fn from_bytes(bytes: &[u8; 2]) -> Option<Self> {
        if *bytes == VERSION_TLS_1_3 {
            Some(ProtocolVersion::TLS1_3)
        } else if *bytes == VERSION_TLCP_1_0 {
            Some(ProtocolVersion::TLCP1_0)
        } else {
            None
        }
    }
}
