//! TLCP alert protocol.
//!
//! Alerts carry a 1-byte level (`Warning` or `Fatal`) and a 1-byte
//! description code. The single wire-format record is exactly
//! `[level, description]` (2 bytes total) inside a HANDSHAKE-type
//! record (per GmSSL's `tls_send_alert`).
//!
//! GB/T 38636-2020 §6.4.5.2.1 specifies that the alert *record* uses
//! the HANDSHAKE content type, not the alert content type that some
//! other implementations expect. This is one of the spots where
//! early GmSSL versions had a wire-level bug; the current master
//! (`3.3.0-dev.1183+`) is correct.

use crate::error::TlcpError;

/// TLCP alert level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlcpAlertLevel {
    /// Warning: connection can continue
    Warning = 0x01,
    /// Fatal: connection must be terminated
    Fatal = 0x02,
}

impl TryFrom<u8> for TlcpAlertLevel {
    type Error = TlcpError;
    fn try_from(value: u8) -> Result<Self, TlcpError> {
        match value {
            0x01 => Ok(Self::Warning),
            0x02 => Ok(Self::Fatal),
            _ => Err(TlcpError::InvalidMessage(format!(
                "Invalid alert level: {}",
                value
            ))),
        }
    }
}

/// TLCP alert description
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlcpAlertDescription {
    /// Connection closed cleanly
    CloseNotify = 0x00,
    /// Message could not be decoded
    UnexpectedMessage = 0x0A,
    /// Handshake failure
    HandshakeFailure = 0x28,
    /// No supported cipher suite
    HandshakeFailureNoCipher = 0x29,
    /// Certificate could not be verified
    BadCertificate = 0x2A,
    /// Certificate type not supported
    UnsupportedCertificate = 0x2B,
    /// Certificate was revoked
    CertificateRevoked = 0x2C,
    /// Certificate expired
    CertificateExpired = 0x2D,
    /// Unknown CA
    UnknownCa = 0x30,
    /// Decryption failed
    DecryptError = 0x33,
    /// Record MAC or GCM tag verification failed
    BadRecordMac = 0x14,
    /// Decompression failure
    DecompressionFailure = 0x16,
    /// Protocol version not supported
    ProtocolVersion = 0x46,
    /// Internal error
    InternalError = 0x50,
    /// Insufficient security level
    InsufficientSecurity = 0x47,
    /// User canceled handshake
    UserCanceled = 0x5A,
}

impl TryFrom<u8> for TlcpAlertDescription {
    type Error = TlcpError;
    fn try_from(value: u8) -> Result<Self, TlcpError> {
        match value {
            0x00 => Ok(Self::CloseNotify),
            0x0A => Ok(Self::UnexpectedMessage),
            0x14 => Ok(Self::BadRecordMac),
            0x16 => Ok(Self::DecompressionFailure),
            0x28 => Ok(Self::HandshakeFailure),
            0x29 => Ok(Self::HandshakeFailureNoCipher),
            0x2A => Ok(Self::BadCertificate),
            0x2B => Ok(Self::UnsupportedCertificate),
            0x2C => Ok(Self::CertificateRevoked),
            0x2D => Ok(Self::CertificateExpired),
            0x30 => Ok(Self::UnknownCa),
            0x33 => Ok(Self::DecryptError),
            0x46 => Ok(Self::ProtocolVersion),
            0x47 => Ok(Self::InsufficientSecurity),
            0x50 => Ok(Self::InternalError),
            0x5A => Ok(Self::UserCanceled),
            _ => Err(TlcpError::InvalidMessage(format!(
                "Unknown alert description: {}",
                value
            ))),
        }
    }
}

/// TLCP Alert message
#[derive(Debug, Clone)]
pub struct TlcpAlert {
    /// Alert level
    pub level: TlcpAlertLevel,
    /// Alert description
    pub description: TlcpAlertDescription,
}

impl TlcpAlert {
    /// Create a new alert
    pub fn new(level: TlcpAlertLevel, description: TlcpAlertDescription) -> Self {
        Self { level, description }
    }

    /// Create a close_notify warning
    pub fn close_notify() -> Self {
        Self::new(TlcpAlertLevel::Warning, TlcpAlertDescription::CloseNotify)
    }

    /// Create a fatal handshake failure
    pub fn handshake_failure() -> Self {
        Self::new(
            TlcpAlertLevel::Fatal,
            TlcpAlertDescription::HandshakeFailure,
        )
    }

    /// Create a fatal protocol version error
    pub fn protocol_version() -> Self {
        Self::new(TlcpAlertLevel::Fatal, TlcpAlertDescription::ProtocolVersion)
    }

    /// Create a fatal bad record MAC error
    pub fn bad_record_mac() -> Self {
        Self::new(TlcpAlertLevel::Fatal, TlcpAlertDescription::BadRecordMac)
    }

    /// Serialize to bytes (2 bytes: level + description)
    pub fn to_bytes(&self) -> [u8; 2] {
        [self.level as u8, self.description as u8]
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlcpError> {
        if data.len() < 2 {
            return Err(TlcpError::InvalidMessage(
                "Alert message too short".to_string(),
            ));
        }
        let level = TlcpAlertLevel::try_from(data[0])?;
        let description = TlcpAlertDescription::try_from(data[1])?;
        Ok(Self { level, description })
    }

    /// Check if this is a fatal alert
    pub fn is_fatal(&self) -> bool {
        self.level == TlcpAlertLevel::Fatal
    }

    /// Check if this is a close_notify
    pub fn is_close_notify(&self) -> bool {
        self.description == TlcpAlertDescription::CloseNotify
    }
}
