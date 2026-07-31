//! GM/TLS handshake types and utilities.
//!
//! This module contains the core handshake message types and cryptographic
//! operations used during the GM/TLS handshake process based on
//! GB/T 38636-2020 (TLCP) and RFC 8446.
//!
//! # Handshake Flow
//!
//! ```text
//! Client                                               Server
//! ClientHello          -------->
//!                                                 ServerHello
//!                                                 Certificate*
//!                                           CertificateVerify*
//!                       <--------           Finished(Server)
//! Certificate*
//! CertificateVerify*
//! Finished(Client)     -------->
//!                       <--------       [Application Data]
//! [Application Data]   <------->       [Application Data]
//! ```
//!
//! *: Optional for client (required for mutual TLS / mTLS).
//!
//! # Key Types
//!
//! - [`ClientHello`] / [`ServerHello`]: Handshake initiation messages with
//!   supported cipher suites, extensions, and random values
//! - [`CertificateVerify`]: SM2 signature over transcript hash, proving key
//!   possession and binding certificate to session
//! - [`Finished`]: HMAC-SM3 over transcript hash, confirming handshake integrity
//!
//! # Extensions
//!
//! Supported TLS extensions include:
//! - Server Name Indication (SNI)
//! - Application-Layer Protocol Negotiation (ALPN)
//! - Session Tickets (RFC 5077)
//! - Supported Versions
//!
//! # TLS 1.3 / GB/T 38636-2020 Compliance
//!
//! Handshake messages are encoded using standard TLS 1.3 wire format per RFC 8446 / GB/T 38636-2020.
//! Each message struct implements `to_bytes()` and `from_bytes()` methods for wire-format serialization.
//!
//! # Extension Format
//!
//! TLS extensions follow the standard IANA format:
//! ```text
//! Extension {
//!   extension_type: u16 (IANA assigned),
//!   extension_data: opaque<0..2^16-1>
//! }
//! ```

use crate::cert_verify::CrlInfo;
use crate::der;
use crate::error::TlsError;
use crate::session_ticket::{SessionKeys, SessionTicket, TicketKeySet};
use elliptic_curve::Field;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use gm_crypto::sm2::{
    EncodedPoint, GM_TLS_DEFAULT_ID, ProjectivePoint, Scalar, Sm2KeyPair, Sm2Signer, Sm2Verifier,
};
use gm_crypto::sm3::Sm3Hasher;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ============================================================================
// Handshake Message Types (DER Encodable)
// ============================================================================

/// Client hello message (TLS 1.3 / GB/T 38636-2020 format).
///
/// Wire format follows RFC 8446 §4.1.2 ClientHello structure:
/// ```text
/// ClientHello {
///   client_version: ProtocolVersion (2 bytes),
///   random: Random (32 bytes),
///   session_id: opaque<0..32>,
///   cipher_suites: CipherSuite<2..2^16-2>,
///   compression_methods: CompressionMethod<1..2^8-1>,
///   extensions: Extension<0..2^16-1>
/// }
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClientHello {
    /// Protocol version (0x0303 for TLS 1.3, 0x0101 for TLCP)
    pub version: [u8; 2],
    /// 32 bytes of random data
    pub random: [u8; 32],
    /// Session identifier (variable length, max 32)
    pub session_id: Vec<u8>,
    /// Cipher suites (list of u16, GM cipher suite = 0xE001)
    pub cipher_suites: Vec<u16>,
    /// Compression methods (list of u8, default = 0x00)
    pub compression_methods: Vec<u8>,
    /// Extensions for TLS 1.3 / TLCP features
    pub extensions: Vec<ClientHelloExtension>,
    /// Session ticket for resumption (client offers ticket or empty for new session)
    pub session_ticket: Option<SessionTicket>,
    /// Ephemeral SM2 public key (65 bytes: 0x04 || x || y in SEC1 format)
    pub eph_pubkey: Vec<u8>,
    /// ALPN protocol list
    pub alpn: Vec<String>,
    /// SNI hostname (optional)
    pub sni: Option<String>,
}

impl ClientHello {
    /// Encode to standard TLS 1.3 wire format bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlsError> {
        let mut buf = Vec::new();

        // client_version: ProtocolVersion (2 bytes)
        buf.extend_from_slice(&self.version);

        // random: 32 bytes
        buf.extend_from_slice(&self.random);

        // session_id: length(1) + opaque<0..32>
        buf.push(self.session_id.len() as u8);
        buf.extend_from_slice(&self.session_id);

        // cipher_suites: length(2) + CipherSuite[]
        let cs_len = self.cipher_suites.len() * 2;
        buf.extend_from_slice(&(cs_len as u16).to_be_bytes());
        for cs in &self.cipher_suites {
            buf.extend_from_slice(&cs.to_be_bytes());
        }

        // compression_methods: length(1) + CompressionMethod[]
        buf.push(self.compression_methods.len() as u8);
        buf.extend_from_slice(&self.compression_methods);

        // extensions: length(2) + Extension[]
        let ext_bytes: Vec<u8> = self
            .extensions
            .iter()
            .map(|e| e.to_bytes())
            .collect::<Result<Vec<Vec<u8>>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        buf.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&ext_bytes);

        Ok(buf)
    }

    /// Decode from standard TLS 1.3 wire format bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        let mut rem = data;

        // client_version: 2 bytes
        if rem.len() < 2 {
            return Err(TlsError::ParseError("truncated version".to_string()));
        }
        let version = [rem[0], rem[1]];
        rem = &rem[2..];

        // random: 32 bytes
        if rem.len() < 32 {
            return Err(TlsError::ParseError("truncated random".to_string()));
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&rem[..32]);
        rem = &rem[32..];

        // session_id: length(1) + data
        if rem.is_empty() {
            return Err(TlsError::ParseError("truncated session_id".to_string()));
        }
        let sid_len = rem[0] as usize;
        if sid_len > 32 || sid_len + 1 > rem.len() {
            return Err(TlsError::ParseError(
                "invalid session_id length".to_string(),
            ));
        }
        let session_id = rem[1..1 + sid_len].to_vec();
        rem = &rem[1 + sid_len..];

        // cipher_suites: length(2) + data
        if rem.len() < 2 {
            return Err(TlsError::ParseError("truncated cipher_suites".to_string()));
        }
        let cs_len = u16::from_be_bytes([rem[0], rem[1]]) as usize;
        rem = &rem[2..];
        if cs_len > rem.len() || cs_len % 2 != 0 {
            return Err(TlsError::ParseError(
                "invalid cipher_suites length".to_string(),
            ));
        }
        let mut cipher_suites = Vec::new();
        for i in (0..cs_len).step_by(2) {
            cipher_suites.push(u16::from_be_bytes([rem[i], rem[i + 1]]));
        }
        rem = &rem[cs_len..];

        // compression_methods: length(1) + data
        if rem.is_empty() {
            return Err(TlsError::ParseError("truncated compression".to_string()));
        }
        let cm_len = rem[0] as usize;
        if cm_len > rem.len() - 1 {
            return Err(TlsError::ParseError(
                "invalid compression length".to_string(),
            ));
        }
        let compression_methods = rem[1..1 + cm_len].to_vec();
        rem = &rem[1 + cm_len..];

        // extensions: length(2) + Extension[]
        let mut extensions = Vec::new();
        let mut session_ticket = None;
        let mut alpn = Vec::new();
        let mut sni = None;
        let mut eph_pubkey = Vec::new();

        if !rem.is_empty() {
            if rem.len() < 2 {
                return Err(TlsError::ParseError("truncated extensions".to_string()));
            }
            let ext_len = u16::from_be_bytes([rem[0], rem[1]]) as usize;
            rem = &rem[2..];
            if ext_len > rem.len() {
                return Err(TlsError::ParseError(
                    "invalid extensions length".to_string(),
                ));
            }
            let mut ext_rem = &rem[..ext_len];

            while !ext_rem.is_empty() {
                let ext = ClientHelloExtension::from_bytes(ext_rem)?;
                // Track remaining bytes after this extension
                let consumed = ext.consumed_bytes();
                ext_rem = &ext_rem[consumed..];

                // Extract custom fields from extensions
                match &ext {
                    ClientHelloExtension::ALPN(protocols) => alpn = protocols.clone(),
                    ClientHelloExtension::SNI(hostname) => sni = Some(hostname.clone()),
                    ClientHelloExtension::KeyShare(ks) => eph_pubkey = ks.clone(),
                    ClientHelloExtension::SessionTicket(ticket_data) => {
                        session_ticket =
                            Some(crate::serialization::deserialize(ticket_data).ok()).flatten();
                    }
                    _ => {}
                }
                extensions.push(ext);
            }
        }

        Ok(ClientHello {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
            session_ticket,
            eph_pubkey,
            alpn,
            sni,
        })
    }
}

/// ClientHello extensions (standard TLS 1.3 IANA format).
///
/// Extension wire format (RFC 8446 §4.2):
/// ```text
/// Extension {
///   extension_type: u16,
///   extension_data: opaque<0..2^16-1>
/// }
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ClientHelloExtension {
    /// ALPN (Application-Layer Protocol Negotiation) — extension_type = 0x0010
    ALPN(Vec<String>),
    /// SNI (Server Name Indication) — extension_type = 0x0000
    SNI(String),
    /// Key share (SM2 ephemeral public key) — extension_type = 0x0033
    KeyShare(Vec<u8>),
    /// Session ticket (RFC 5077) — extension_type = 0x0023
    SessionTicket(Vec<u8>),
    /// Supported versions (TLS 1.3 / TLCP) — extension_type = 0x002B
    SupportedVersions([u8; 2]),
    /// Signature algorithms — extension_type = 0x000D
    SignatureAlgorithms(Vec<u16>),
    /// Unknown extension
    Unknown(u16, Vec<u8>),
}

// IANA TLS ExtensionType values (RFC 8446)
const EXT_TYPE_SERVER_NAME: u16 = 0x0000;
const EXT_TYPE_SIGNATURE_ALGORITHMS: u16 = 0x000D;
const EXT_TYPE_ALPN: u16 = 0x0010;
const EXT_TYPE_SESSION_TICKET: u16 = 0x0023;
const EXT_TYPE_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_TYPE_KEY_SHARE: u16 = 0x0033;

impl ClientHelloExtension {
    /// Encode extension to standard TLS 1.3 wire format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlsError> {
        let (ext_type, ext_data) = match self {
            ClientHelloExtension::ALPN(protocols) => {
                // RFC 8446 §4.2.11: ALPN extension
                // ProtocolNameList: length(2) + ProtocolName[]
                // ProtocolName: length(1) + opaque<1..2^8-1>
                let mut list = Vec::new();
                for proto in protocols {
                    list.push(proto.len() as u8);
                    list.extend_from_slice(proto.as_bytes());
                }
                let mut data = Vec::new();
                data.extend_from_slice(&(list.len() as u16).to_be_bytes());
                data.extend_from_slice(&list);
                (EXT_TYPE_ALPN, data)
            }
            ClientHelloExtension::SNI(hostname) => {
                // RFC 8446 §4.2.11: SNI extension
                // ServerNameList: length(2) + ServerName[]
                // ServerName: name_type(1) + length(2) + HostName
                let mut name = Vec::new();
                name.push(0x00); // host_name
                name.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
                name.extend_from_slice(hostname.as_bytes());
                let mut data = Vec::new();
                data.extend_from_slice(&(name.len() as u16).to_be_bytes());
                data.extend_from_slice(&name);
                (EXT_TYPE_SERVER_NAME, data)
            }
            ClientHelloExtension::KeyShare(pk) => {
                // RFC 8446 §4.2.8: KeyShare extension
                // KeyShareEntry: group(2) + length(2) + key_exchange<0..2^16-1>
                // For SM2, we use a custom group identifier
                let mut entry = Vec::new();
                entry.extend_from_slice(&0xE001u16.to_be_bytes()); // SM2 group (custom)
                entry.extend_from_slice(&(pk.len() as u16).to_be_bytes());
                entry.extend_from_slice(pk);
                let mut data = Vec::new();
                data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
                data.extend_from_slice(&entry);
                (EXT_TYPE_KEY_SHARE, data)
            }
            ClientHelloExtension::SessionTicket(ticket) => {
                // RFC 5077: SessionTicket extension
                // opaque<0..2^16-1>
                let mut data = Vec::new();
                data.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
                data.extend_from_slice(ticket);
                (EXT_TYPE_SESSION_TICKET, data)
            }
            ClientHelloExtension::SupportedVersions(version) => {
                // RFC 8446 §4.2.1: SupportedVersions
                // SupportedVersions: length(1) + ProtocolVersion[]
                let mut data = Vec::new();
                data.push(2u8); // 1 version, 2 bytes
                data.extend_from_slice(version);
                (EXT_TYPE_SUPPORTED_VERSIONS, data)
            }
            ClientHelloExtension::SignatureAlgorithms(algs) => {
                // RFC 8446 §4.2.3: SignatureAlgorithms
                // SupportedSignatureAlgorithms: length(2) + SignatureScheme[]
                let mut list = Vec::new();
                for alg in algs {
                    list.extend_from_slice(&alg.to_be_bytes());
                }
                let mut data = Vec::new();
                data.extend_from_slice(&(list.len() as u16).to_be_bytes());
                data.extend_from_slice(&list);
                (EXT_TYPE_SIGNATURE_ALGORITHMS, data)
            }
            ClientHelloExtension::Unknown(ext_type, data) => (*ext_type, data.clone()),
        };

        let mut result = Vec::new();
        result.extend_from_slice(&ext_type.to_be_bytes());
        result.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        result.extend_from_slice(&ext_data);
        Ok(result)
    }

    /// Decode extension from standard TLS 1.3 wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 4 {
            return Err(TlsError::ParseError("truncated extension".to_string()));
        }
        let ext_type = u16::from_be_bytes([data[0], data[1]]);
        let ext_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + ext_len {
            return Err(TlsError::ParseError("truncated extension data".to_string()));
        }
        let ext_data = &data[4..4 + ext_len];

        let ext = match ext_type {
            EXT_TYPE_ALPN => {
                // ALPN: ProtocolNameList
                if ext_data.len() < 2 {
                    return Ok(ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()));
                }
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if list_len > ext_data.len() - 2 {
                    return Ok(ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()));
                }
                let mut protocols = Vec::new();
                let mut rem = &ext_data[2..2 + list_len];
                while !rem.is_empty() {
                    if rem.is_empty() {
                        break;
                    }
                    let name_len = rem[0] as usize;
                    if rem.len() < 1 + name_len {
                        break;
                    }
                    protocols.push(String::from_utf8_lossy(&rem[1..1 + name_len]).to_string());
                    rem = &rem[1 + name_len..];
                }
                ClientHelloExtension::ALPN(protocols)
            }
            EXT_TYPE_SERVER_NAME => {
                // SNI: ServerNameList
                if ext_data.len() < 2 {
                    return Ok(ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()));
                }
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if list_len > ext_data.len() - 2 {
                    return Ok(ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()));
                }
                let mut rem = &ext_data[2..2 + list_len];
                let mut hostname = String::new();
                while !rem.is_empty() && rem.len() >= 3 {
                    let name_type = rem[0];
                    let name_len = u16::from_be_bytes([rem[1], rem[2]]) as usize;
                    if rem.len() < 3 + name_len {
                        break;
                    }
                    if name_type == 0x00 {
                        // host_name
                        hostname = String::from_utf8_lossy(&rem[3..3 + name_len]).to_string();
                    }
                    rem = &rem[3 + name_len..];
                }
                ClientHelloExtension::SNI(hostname)
            }
            EXT_TYPE_KEY_SHARE => {
                // KeyShare: KeyShareEntry[]
                if ext_data.len() < 2 {
                    return Ok(ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()));
                }
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if list_len > ext_data.len() - 2 || list_len < 4 {
                    return Ok(ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()));
                }
                let entry = &ext_data[2..2 + list_len];
                // group(2) + length(2) + key_exchange
                if entry.len() < 4 {
                    return Ok(ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()));
                }
                let key_len = u16::from_be_bytes([entry[2], entry[3]]) as usize;
                if entry.len() < 4 + key_len {
                    return Ok(ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()));
                }
                ClientHelloExtension::KeyShare(entry[4..4 + key_len].to_vec())
            }
            EXT_TYPE_SESSION_TICKET => ClientHelloExtension::SessionTicket(ext_data.to_vec()),
            EXT_TYPE_SUPPORTED_VERSIONS => {
                if ext_data.len() >= 3 && ext_data[0] == 2 {
                    ClientHelloExtension::SupportedVersions([ext_data[1], ext_data[2]])
                } else {
                    ClientHelloExtension::Unknown(ext_type, ext_data.to_vec())
                }
            }
            EXT_TYPE_SIGNATURE_ALGORITHMS => {
                if ext_data.len() < 2 {
                    return Ok(ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()));
                }
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                if list_len > ext_data.len() - 2 || list_len % 2 != 0 {
                    return Ok(ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()));
                }
                let mut algs = Vec::new();
                for i in (0..list_len).step_by(2) {
                    algs.push(u16::from_be_bytes([ext_data[2 + i], ext_data[2 + i + 1]]));
                }
                ClientHelloExtension::SignatureAlgorithms(algs)
            }
            _ => ClientHelloExtension::Unknown(ext_type, ext_data.to_vec()),
        };

        Ok(ext)
    }

    /// Return the number of bytes consumed by this extension in wire format.
    pub fn consumed_bytes(&self) -> usize {
        // Type(2) + Length(2) + data_len
        4 + match self {
            ClientHelloExtension::ALPN(protocols) => {
                let list: Vec<u8> = protocols
                    .iter()
                    .flat_map(|p| {
                        let mut v = vec![p.len() as u8];
                        v.extend_from_slice(p.as_bytes());
                        v
                    })
                    .collect();
                2 + list.len()
            }
            ClientHelloExtension::SNI(hostname) => 2 + 1 + 2 + hostname.len(),
            ClientHelloExtension::KeyShare(pk) => 2 + 2 + 2 + pk.len(),
            ClientHelloExtension::SessionTicket(ticket) => 2 + ticket.len(),
            ClientHelloExtension::SupportedVersions(_) => 1 + 2,
            ClientHelloExtension::SignatureAlgorithms(algs) => 2 + algs.len() * 2,
            ClientHelloExtension::Unknown(_, data) => data.len(),
        }
    }
}

/// Server hello message (TLS 1.3 / GB/T 38636-2020 format).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerHello {
    /// Protocol version (0x0303 for TLS 1.3, 0x0101 for TLCP)
    pub version: [u8; 2],
    /// 32 bytes of random data
    pub random: [u8; 32],
    /// Session identifier (variable length, max 32)
    pub session_id: Vec<u8>,
    /// Selected cipher suite (u16)
    pub cipher_suite: u16,
    /// Selected compression method (u8)
    pub compression: u8,
    /// Extensions
    pub extensions: Vec<ServerHelloExtension>,
    /// Ephemeral SM2 public key (empty if resuming session)
    pub eph_pubkey: Vec<u8>,
    /// Selected ALPN protocol
    pub alpn: Option<String>,
    /// Server certificate chain (PEM-encoded)
    pub cert_chain_pem: Vec<u8>,
    /// Whether client authentication is required
    pub require_client_auth: bool,
}

impl ServerHello {
    /// Encode to standard TLS 1.3 wire format bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlsError> {
        let mut buf = Vec::new();

        // version: 2 bytes
        buf.extend_from_slice(&self.version);

        // random: 32 bytes
        buf.extend_from_slice(&self.random);

        // session_id: length(1) + opaque<0..32>
        buf.push(self.session_id.len() as u8);
        buf.extend_from_slice(&self.session_id);

        // cipher_suite: 2 bytes
        buf.extend_from_slice(&self.cipher_suite.to_be_bytes());

        // compression: 1 byte
        buf.push(self.compression);

        // extensions: length(2) + Extension[]
        let ext_bytes: Vec<u8> = self
            .extensions
            .iter()
            .map(|e| e.to_bytes())
            .collect::<Result<Vec<Vec<u8>>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        buf.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&ext_bytes);

        Ok(buf)
    }

    /// Decode from standard TLS 1.3 wire format bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        let mut rem = data;

        // version: 2 bytes
        if rem.len() < 2 {
            return Err(TlsError::ParseError("truncated version".to_string()));
        }
        let version = [rem[0], rem[1]];
        rem = &rem[2..];

        // random: 32 bytes
        if rem.len() < 32 {
            return Err(TlsError::ParseError("truncated random".to_string()));
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&rem[..32]);
        rem = &rem[32..];

        // session_id
        if rem.is_empty() {
            return Err(TlsError::ParseError("truncated ServerHello".to_string()));
        }
        let sid_len = rem[0] as usize;
        if sid_len > 32 || sid_len + 1 > rem.len() {
            return Err(TlsError::ParseError(
                "invalid session_id length".to_string(),
            ));
        }
        let session_id = rem[1..1 + sid_len].to_vec();
        rem = &rem[1 + sid_len..];

        // cipher_suite
        if rem.len() < 2 {
            return Err(TlsError::ParseError("truncated cipher_suite".to_string()));
        }
        let cipher_suite = u16::from_be_bytes([rem[0], rem[1]]);
        rem = &rem[2..];

        // compression
        if rem.is_empty() {
            return Err(TlsError::ParseError("truncated compression".to_string()));
        }
        let compression = rem[0];
        rem = &rem[1..];

        // extensions
        let mut extensions = Vec::new();
        let mut alpn = None;
        let mut eph_pubkey = Vec::new();

        if !rem.is_empty() {
            if rem.len() < 2 {
                return Err(TlsError::ParseError("truncated extensions".to_string()));
            }
            let ext_len = u16::from_be_bytes([rem[0], rem[1]]) as usize;
            rem = &rem[2..];
            if ext_len > rem.len() {
                return Err(TlsError::ParseError(
                    "invalid extensions length".to_string(),
                ));
            }
            let mut ext_rem = &rem[..ext_len];

            while !ext_rem.is_empty() {
                let ext = ServerHelloExtension::from_bytes(ext_rem)?;
                let consumed = ext.consumed_bytes();
                ext_rem = &ext_rem[consumed..];

                match &ext {
                    ServerHelloExtension::ALPN(proto) => alpn = Some(proto.clone()),
                    ServerHelloExtension::KeyShare(ks) => eph_pubkey = ks.clone(),
                    _ => {}
                }
                extensions.push(ext);
            }
        }

        Ok(ServerHello {
            version,
            random,
            session_id,
            cipher_suite,
            compression,
            extensions,
            eph_pubkey,
            alpn,
            cert_chain_pem: Vec::new(), // Not part of ServerHello wire format
            require_client_auth: false, // Negotiated separately
        })
    }
}

/// ServerHello extensions (standard TLS 1.3 IANA format).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ServerHelloExtension {
    ALPN(String),
    KeyShare(Vec<u8>),
    Unknown(u16, Vec<u8>),
}

impl ServerHelloExtension {
    /// Encode extension to standard TLS 1.3 wire format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlsError> {
        let (ext_type, ext_data) = match self {
            ServerHelloExtension::ALPN(proto) => {
                // RFC 8446 §4.2.11: ALPN in ServerHello
                // ProtocolName: length(1) + opaque<1..2^8-1>
                let mut data = Vec::new();
                data.push(proto.len() as u8);
                data.extend_from_slice(proto.as_bytes());
                (EXT_TYPE_ALPN, data)
            }
            ServerHelloExtension::KeyShare(pk) => {
                // RFC 8446 §4.2.8: KeyShare in ServerHello
                // KeyShareEntry: group(2) + length(2) + key_exchange<0..2^16-1>
                let mut data = Vec::new();
                data.extend_from_slice(&0xE001u16.to_be_bytes()); // SM2 group
                data.extend_from_slice(&(pk.len() as u16).to_be_bytes());
                data.extend_from_slice(pk);
                (EXT_TYPE_KEY_SHARE, data)
            }
            ServerHelloExtension::Unknown(ext_type, data) => (*ext_type, data.clone()),
        };

        let mut result = Vec::new();
        result.extend_from_slice(&ext_type.to_be_bytes());
        result.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        result.extend_from_slice(&ext_data);
        Ok(result)
    }

    /// Decode extension from standard TLS 1.3 wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 4 {
            return Err(TlsError::ParseError("truncated extension".to_string()));
        }
        let ext_type = u16::from_be_bytes([data[0], data[1]]);
        let ext_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + ext_len {
            return Err(TlsError::ParseError("truncated extension data".to_string()));
        }
        let ext_data = &data[4..4 + ext_len];

        let ext = match ext_type {
            EXT_TYPE_ALPN => {
                if !ext_data.is_empty() {
                    let name_len = ext_data[0] as usize;
                    if ext_data.len() > name_len {
                        ServerHelloExtension::ALPN(
                            String::from_utf8_lossy(&ext_data[1..1 + name_len]).to_string(),
                        )
                    } else {
                        ServerHelloExtension::Unknown(ext_type, ext_data.to_vec())
                    }
                } else {
                    ServerHelloExtension::Unknown(ext_type, ext_data.to_vec())
                }
            }
            EXT_TYPE_KEY_SHARE => {
                if ext_data.len() >= 4 {
                    let key_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                    if ext_data.len() >= 4 + key_len {
                        ServerHelloExtension::KeyShare(ext_data[4..4 + key_len].to_vec())
                    } else {
                        ServerHelloExtension::Unknown(ext_type, ext_data.to_vec())
                    }
                } else {
                    ServerHelloExtension::Unknown(ext_type, ext_data.to_vec())
                }
            }
            _ => ServerHelloExtension::Unknown(ext_type, ext_data.to_vec()),
        };

        Ok(ext)
    }

    /// Return the number of bytes consumed by this extension in wire format.
    pub fn consumed_bytes(&self) -> usize {
        4 + match self {
            ServerHelloExtension::ALPN(proto) => 1 + proto.len(),
            ServerHelloExtension::KeyShare(pk) => 2 + 2 + pk.len(),
            ServerHelloExtension::Unknown(_, data) => data.len(),
        }
    }
}

/// RFC 5077 NewSessionTicket message.
#[derive(Debug, Clone)]
pub struct NewSessionTicket {
    /// The session ticket for resumption
    pub ticket: SessionTicket,
}

impl NewSessionTicket {
    /// Encode to standard TLS 1.3 wire format (RFC 8446 §4.6.1).
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlsError> {
        let ticket_bytes = crate::serialization::serialize(&self.ticket)
            .map_err(|e| TlsError::SerializationFailed(format!("ticket serialize: {}", e)))?;
        let mut buf = Vec::new();
        // ticket_lifetime: u32 (seconds)
        buf.extend_from_slice(&86400u32.to_be_bytes());
        // ticket_age_add: u32 (random)
        buf.extend_from_slice(&0u32.to_be_bytes());
        // ticket_nonce: length(1) + opaque
        buf.push(0u8);
        // ticket: length(2) + opaque
        buf.extend_from_slice(&(ticket_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&ticket_bytes);
        // extensions: length(2) (empty)
        buf.extend_from_slice(&0u16.to_be_bytes());
        Ok(buf)
    }

    /// Decode from standard TLS 1.3 wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        let mut rem = data;
        // ticket_lifetime
        if rem.len() < 4 {
            return Err(TlsError::ParseError(
                "truncated ticket lifetime".to_string(),
            ));
        }
        let _lifetime = u32::from_be_bytes([rem[0], rem[1], rem[2], rem[3]]);
        rem = &rem[4..];
        // ticket_age_add
        if rem.len() < 4 {
            return Err(TlsError::ParseError("truncated ticket age add".to_string()));
        }
        rem = &rem[4..];
        // ticket_nonce
        if rem.is_empty() {
            return Err(TlsError::ParseError("truncated ticket nonce".to_string()));
        }
        let nonce_len = rem[0] as usize;
        if rem.len() < 1 + nonce_len {
            return Err(TlsError::ParseError("invalid ticket nonce".to_string()));
        }
        rem = &rem[1 + nonce_len..];
        // ticket
        if rem.len() < 2 {
            return Err(TlsError::ParseError("truncated ticket".to_string()));
        }
        let ticket_len = u16::from_be_bytes([rem[0], rem[1]]) as usize;
        rem = &rem[2..];
        if ticket_len > rem.len() {
            return Err(TlsError::ParseError("invalid ticket length".to_string()));
        }
        let ticket_data = &rem[..ticket_len];
        rem = &rem[ticket_len..];
        // extensions (skip)
        if rem.len() >= 2 {
            let ext_len = u16::from_be_bytes([rem[0], rem[1]]) as usize;
            rem = &rem[2..];
            let _ = &rem[ext_len..];
        }

        let ticket: SessionTicket = crate::serialization::deserialize(ticket_data)
            .map_err(|e| TlsError::SerializationFailed(format!("ticket deserialize: {}", e)))?;

        Ok(NewSessionTicket { ticket })
    }
}

/// Finished message — signed confirmation of handshake integrity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finished {
    /// Verify data: HMAC-SM3 of transcript hash
    pub verify_data: Vec<u8>,
}

impl Finished {
    /// Encode to standard TLS 1.3 wire format (RFC 8446 §4.4.4).
    /// verify_data: opaque<0..2^16-1>
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlsError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.verify_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.verify_data);
        Ok(buf)
    }

    /// Decode from standard TLS 1.3 wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::ParseError("truncated Finished".to_string()));
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len {
            return Err(TlsError::ParseError("invalid Finished length".to_string()));
        }
        Ok(Finished {
            verify_data: data[2..2 + len].to_vec(),
        })
    }
}

/// CertificateVerify message — proves server owns the certificate private key.
#[derive(Debug, Clone)]
pub struct CertificateVerify {
    /// Signature over the transcript hash using the certificate's private key
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    /// Encode to standard TLS 1.3 wire format (RFC 8446 §4.4.3).
    /// AlgorithmIdentifier + signature
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlsError> {
        // AlgorithmIdentifier: length(2) + OID + parameters
        let mut alg_id = Vec::new();
        // OID for SM2withSM3: 1.2.156.10197.1.501
        let oid = der::encode_oid(der::SM2_SIG_OID);
        alg_id.extend_from_slice(&(oid.len() as u16).to_be_bytes());
        alg_id.extend_from_slice(&oid);
        // NULL parameters
        alg_id.push(0x05);
        alg_id.push(0x00);

        let mut buf = Vec::new();
        buf.extend_from_slice(&(alg_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(&alg_id);
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        Ok(buf)
    }

    /// Decode from standard TLS 1.3 wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 2 {
            return Err(TlsError::ParseError(
                "truncated CertificateVerify".to_string(),
            ));
        }
        let alg_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + alg_len {
            return Err(TlsError::ParseError("invalid algorithm length".to_string()));
        }
        let rem = &data[2 + alg_len..];
        if rem.len() < 2 {
            return Err(TlsError::ParseError("truncated signature".to_string()));
        }
        let sig_len = u16::from_be_bytes([rem[0], rem[1]]) as usize;
        if rem.len() < 2 + sig_len {
            return Err(TlsError::ParseError("invalid signature length".to_string()));
        }
        Ok(CertificateVerify {
            signature: rem[2..2 + sig_len].to_vec(),
        })
    }
}

/// Client Certificate message — sent by the client after server authentication.
#[derive(Debug, Clone)]
pub struct ClientCertificate {
    /// PEM-encoded client certificate chain
    pub cert_chain_pem: Vec<u8>,
}

impl ClientCertificate {
    /// Encode to standard TLS 1.3 wire format (RFC 8446 §4.4.2).
    /// CertificateList: length(3) + CertificateEntry[]
    pub fn to_bytes(&self) -> Result<Vec<u8>, TlsError> {
        let mut entries = Vec::new();
        // Single entry with PEM cert
        entries.extend_from_slice(&(self.cert_chain_pem.len() as u32).to_be_bytes()[1..]); // 3-byte length
        entries.extend_from_slice(&self.cert_chain_pem);
        // extensions: length(2) (empty)
        entries.extend_from_slice(&0u16.to_be_bytes());

        let mut buf = Vec::new();
        buf.extend_from_slice(&(entries.len() as u32).to_be_bytes()[1..]); // 3-byte length
        buf.extend_from_slice(&entries);
        Ok(buf)
    }

    /// Decode from standard TLS 1.3 wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        if data.len() < 3 {
            return Err(TlsError::ParseError("truncated Certificate".to_string()));
        }
        let len = ((data[0] as u32) << 16 | (data[1] as u32) << 8 | data[2] as u32) as usize;
        if data.len() < 3 + len {
            return Err(TlsError::ParseError(
                "invalid Certificate length".to_string(),
            ));
        }
        let entries = &data[3..3 + len];
        // Parse first entry
        if entries.len() < 3 {
            return Err(TlsError::ParseError(
                "truncated CertificateEntry".to_string(),
            ));
        }
        let cert_len =
            ((entries[0] as u32) << 16 | (entries[1] as u32) << 8 | entries[2] as u32) as usize;
        if entries.len() < 3 + cert_len + 2 {
            return Err(TlsError::ParseError("invalid CertificateEntry".to_string()));
        }
        let cert_pem = entries[3..3 + cert_len].to_vec();
        Ok(ClientCertificate {
            cert_chain_pem: cert_pem,
        })
    }
}

// ============================================================================
// HandshakeSecrets (Not DER encoded - internal use)
// ============================================================================

/// Handshake key material derived from SM2 ECDH
///
/// The `master_secret` is wrapped in `Zeroizing` to ensure the key material
/// is zeroized on drop, preventing secrets from lingering in memory after
/// the handshake completes.
#[derive(Debug, Clone)]
pub struct HandshakeSecrets {
    pub master_secret: zeroize::Zeroizing<Vec<u8>>,
    /// Client application traffic secret — needed for KeyUpdate (RFC 8446 §7.2)
    pub client_traffic_secret: zeroize::Zeroizing<Vec<u8>>,
    /// Server application traffic secret — needed for KeyUpdate (RFC 8446 §7.2)
    pub server_traffic_secret: zeroize::Zeroizing<Vec<u8>>,
    pub session_keys: SessionKeys,
}

// ============================================================================
// HandshakeOptions (Configuration, not DER)
// ============================================================================

/// Handshake optional parameters
///
/// # Example
///
/// ```
/// use gm_tls::gm::{HandshakeOptions, TicketKey, TicketKeySet};
///
/// let current_key = TicketKey {
///     id: 1,
///     secret: [0x01; 32],
/// };
/// let old_key = TicketKey {
///     id: 0,
///     secret: [0x00; 32],
/// };
/// let key_set = TicketKeySet::new(current_key).with_key(old_key);
/// let mut opts = HandshakeOptions::default();
/// opts.session_ticket_key = Some(key_set);
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct HandshakeOptions {
    /// Session ticket for resuming a previously established TLS session (used on client side)
    pub session_ticket: Option<SessionTicket>,
    /// Session ticket encryption key set. First key is used to encrypt new tickets; all keys can decrypt.
    pub session_ticket_key: Option<TicketKeySet>,
    /// Session store for replay protection. Defaults to in-memory if not set.
    pub session_store: Option<crate::session_store::SessionStoreConfig>,
    /// CRL (Certificate Revocation List) for checking certificate revocation during handshake.
    /// When provided, each certificate in the chain is checked against the CRL.
    pub crl_info: Option<CrlInfo>,
}

// ============================================================================
// Transcript Hash Functions
// ============================================================================

/// Compute the transcript hash from ClientHello and ServerHello bytes.
pub fn compute_transcript_hash(ch_bytes: &[u8], sh_bytes: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut buf = Vec::with_capacity(ch_bytes.len() + sh_bytes.len());
    buf.extend_from_slice(ch_bytes);
    buf.extend_from_slice(sh_bytes);
    let digest = Sm3Hasher::hash(&buf).map_err(TlsError::from)?;
    Ok(digest)
}

/// Hash multiple handshake messages for transcript (used when NewSessionTicket
/// is inserted between ServerHello and Finished per RFC 5077).
pub fn compute_transcript_hash_multi(slices: &[&[u8]]) -> Result<Vec<u8>, TlsError> {
    let total_len: usize = slices.iter().map(|s| s.len()).sum();
    let mut buf = Vec::with_capacity(total_len);
    for s in slices {
        buf.extend_from_slice(s);
    }
    let digest = Sm3Hasher::hash(&buf).map_err(TlsError::from)?;
    Ok(digest)
}

/// Sign transcript hash to create Finished message.
pub fn sign_finished(signer: &Sm2Signer, transcript_hash: &[u8]) -> Result<Finished, TlsError> {
    let sig = signer
        .sign(transcript_hash)
        .map_err(|e| TlsError::HandshakeFailed(format!("Finished signing failed: {}", e)))?;
    Ok(Finished { verify_data: sig })
}

/// Verify Finished message.
pub fn verify_finished(
    verifier: &Sm2Verifier,
    transcript_hash: &[u8],
    finished: &Finished,
) -> Result<(), TlsError> {
    verifier
        .verify(transcript_hash, &finished.verify_data)
        .map_err(|e| TlsError::HandshakeFailed(format!("Finished verification error: {}", e)))?;
    Ok(())
}

// ============== Key Generation ==============

/// Generate an SM2 ephemeral keypair for ECDH key exchange.
pub fn generate_sm2_ephemeral() -> Result<(Scalar, Vec<u8>), TlsError> {
    let sk = Scalar::random(rand_core::OsRng);
    let pk_point = ProjectivePoint::GENERATOR * sk;
    let pk_bytes = pk_point
        .to_affine()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    Ok((sk, pk_bytes))
}

/// Parse SEC1-encoded public key bytes into a ProjectivePoint.
pub(crate) fn parse_sm2_pubkey(bytes: &[u8]) -> Result<ProjectivePoint, TlsError> {
    let enc = EncodedPoint::from_bytes(bytes)
        .map_err(|e| TlsError::HandshakeFailed(format!("public key parse failed: {}", e)))?;
    ProjectivePoint::from_encoded_point(&enc)
        .into_option()
        .ok_or_else(|| TlsError::HandshakeFailed("invalid public key point".into()))
}

// ============== Handshake Message Builders ==============

/// Build a ClientHello message with a new ephemeral key.
pub fn build_client_hello(
    alpn: &[String],
    sni: Option<&str>,
) -> Result<(ClientHello, Scalar), TlsError> {
    let (sk, pk) = generate_sm2_ephemeral()?;
    let hello = ClientHello {
        version: der::VERSION_TLS_1_3,
        random: random_bytes(),
        session_id: Vec::new(),
        cipher_suites: vec![0xE001], // GM_SM4_GCM_SM2
        compression_methods: vec![0x00],
        extensions: vec![
            ClientHelloExtension::SupportedVersions(der::VERSION_TLS_1_3),
            ClientHelloExtension::KeyShare(pk.clone()),
            ClientHelloExtension::ALPN(alpn.to_vec()),
        ],
        session_ticket: None,
        eph_pubkey: pk,
        alpn: alpn.to_vec(),
        sni: sni.map(|s| s.to_string()),
    };
    Ok((hello, sk))
}

/// Build a ClientHello that includes a session ticket for resumption.
pub fn build_client_hello_with_ticket(
    alpn: &[String],
    sni: Option<&str>,
    ticket: SessionTicket,
) -> Result<(ClientHello, Scalar), TlsError> {
    let (sk, pk) = generate_sm2_ephemeral()?;
    let hello = ClientHello {
        version: der::VERSION_TLS_1_3,
        random: random_bytes(),
        session_id: Vec::new(),
        cipher_suites: vec![0xE001],
        compression_methods: vec![0x00],
        extensions: vec![
            ClientHelloExtension::SupportedVersions(der::VERSION_TLS_1_3),
            ClientHelloExtension::KeyShare(pk.clone()),
            ClientHelloExtension::ALPN(alpn.to_vec()),
        ],
        session_ticket: Some(ticket),
        eph_pubkey: pk,
        alpn: alpn.to_vec(),
        sni: sni.map(|s| s.to_string()),
    };
    Ok((hello, sk))
}

/// Build a ServerHello message with a new ephemeral key.
pub fn build_server_hello(
    alpn: Option<&str>,
    cert_chain_pem: &[u8],
    require_client_auth: bool,
) -> Result<(ServerHello, Scalar), TlsError> {
    let (sk, pk) = generate_sm2_ephemeral()?;

    let mut extensions = vec![ServerHelloExtension::KeyShare(pk.clone())];
    if let Some(proto) = alpn {
        extensions.push(ServerHelloExtension::ALPN(proto.to_string()));
    }

    let random = random_bytes();
    // Per RFC 8446 §4.1.3: a TLS 1.3 server MUST set the downgrade sentinel
    // ONLY when it has negotiated down to TLS 1.2 (or legacy TLCP).
    // Writing it unconditionally in a TLS 1.3-only server is incorrect —
    // it breaks legitimate TLS 1.3 clients that check this sentinel.
    // The sentinel is written inside build_server_hello only when the
    // caller explicitly passes TLS 1.2 as the negotiated version.
    // random[24..].copy_from_slice(DOWNGRADE_SENTINEL_TLS12);

    let hello = ServerHello {
        version: der::VERSION_TLS_1_3,
        random,
        session_id: Vec::new(),
        cipher_suite: 0xE001,
        compression: 0x00,
        extensions,
        eph_pubkey: pk,
        alpn: alpn.map(|s| s.to_string()),
        cert_chain_pem: cert_chain_pem.to_vec(),
        require_client_auth,
    };
    Ok((hello, sk))
}

// ============== ALPN Negotiation ==============

/// Select ALPN protocol. The client offers protocols in preference order.
/// The server picks the first protocol it also supports, respecting the client's preference.
pub fn select_alpn<'a>(server: &'a [String], client: &'a [String]) -> Option<&'a str> {
    for c in client {
        if server.iter().any(|s| s == c) {
            return Some(c.as_str());
        }
    }
    None
}

// ============== Wire I/O Helpers ==============

/// Generate cryptographically secure random bytes using OsRng.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut buf);
    buf
}

/// Write a handshake message with TLS record layer header.
///
/// TLS record format (RFC 8446 §5.2):
/// ```text
/// [content_type=0x16][version=2B][length=2B][payload]
/// ```
///
/// For GM/TLS (GB/T 38636-2020), version is 0x0101.
pub(crate) async fn write_handshake_record<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
    version: &[u8; 2],
) -> Result<(), TlsError> {
    if data.len() > u16::MAX as usize {
        return Err(TlsError::HandshakeFailed("record payload too long".into()));
    }
    // TLS record header: content_type + version + length
    stream
        .write_u8(der::CONTENT_TYPE_HANDSHAKE)
        .await
        .map_err(|e| TlsError::IoError(e.to_string()))?;
    stream
        .write_all(version)
        .await
        .map_err(|e| TlsError::IoError(e.to_string()))?;
    stream
        .write_u16(data.len() as u16)
        .await
        .map_err(|e| TlsError::IoError(e.to_string()))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| TlsError::IoError(e.to_string()))?;
    Ok(())
}

/// Read a handshake message with TLS record layer header.
///
/// Returns the payload (handshake message bytes) without the record header.
pub(crate) async fn read_handshake_record<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, TlsError> {
    // Read 5-byte TLS record header
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| TlsError::IoError(e.to_string()))?;

    if header[0] != der::CONTENT_TYPE_HANDSHAKE {
        return Err(TlsError::TlsRecordError(format!(
            "expected handshake content_type 0x16, got 0x{:02X}",
            header[0]
        )));
    }

    let length = u16::from_be_bytes([header[3], header[4]]) as usize;

    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| TlsError::IoError(e.to_string()))?;

    Ok(payload)
}

// ============== Signing Helpers ==============

/// Create an Sm2Signer from a Scalar (ephemeral key).
pub(crate) fn signer_from_scalar(sk: &Scalar) -> Result<Sm2Signer, TlsError> {
    let raw = sk.to_bytes();
    let kp = Sm2KeyPair::from_private_key_with_distid(raw.as_ref(), GM_TLS_DEFAULT_ID.to_string())
        .map_err(|e| TlsError::HandshakeFailed(format!("SM2 key construction failed: {}", e)))?;
    Sm2Signer::new(&kp)
        .map_err(|e| TlsError::HandshakeFailed(format!("SM2 signer creation failed: {}", e)))
}

/// Create an Sm2Signer from a PEM-encoded private key.
pub(crate) fn signer_from_pem_key(key_pem: &[u8]) -> Result<Sm2Signer, TlsError> {
    let pem_str = std::str::from_utf8(key_pem)
        .map_err(|e| TlsError::HandshakeFailed(format!("invalid key PEM UTF-8: {}", e)))?;
    let kp = Sm2KeyPair::from_private_key_pem(pem_str)
        .map_err(|e| TlsError::HandshakeFailed(format!("SM2 key parse failed: {}", e)))?;
    Sm2Signer::new(&kp)
        .map_err(|e| TlsError::HandshakeFailed(format!("SM2 signer creation failed: {}", e)))
}

/// Get the server's ephemeral public key for Finished verification.
pub(crate) fn select_pubkey_for_finished(sh: &ServerHello) -> Result<Vec<u8>, TlsError> {
    Ok(sh.eph_pubkey.clone())
}

/// Get the client's ephemeral public key for Finished verification.
pub(crate) fn select_client_pubkey_for_finished(ch: &ClientHello) -> Result<Vec<u8>, TlsError> {
    Ok(ch.eph_pubkey.clone())
}

// ============== TLS Downgrade Protection ==============

/// RFC 8446 §4.1.3: Downgrade protection sentinel values.
///
/// When a TLS 1.3-capable server responds with TLS 1.2 (due to compatibility),
/// the last 8 bytes of ServerHello.random contain these sentinel values.
/// This allows clients to detect downgrade attacks.
///
/// - TLS 1.2 sentinel: { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 }
/// - TLS 1.1 or below sentinel: { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00 }
const DOWNGRADE_SENTINEL_TLS12: &[u8; 8] = b"DOWNGRD\x01";
const DOWNGRADE_SENTINEL_LEGACY: &[u8; 8] = b"DOWNGRD\x00";

/// Check if ServerHello.random contains a TLS 1.2 downgrade sentinel.
///
/// If the last 8 bytes are the TLS 1.2 sentinel, it means a TLS 1.3-capable
/// server was forced to downgrade to TLS 1.2 (attack detected).
///
/// Returns `true` if downgrade sentinel detected (attack indicator).
pub fn check_downgrade_sentinel(random: &[u8; 32]) -> bool {
    &random[24..] == DOWNGRADE_SENTINEL_TLS12 || &random[24..] == DOWNGRADE_SENTINEL_LEGACY
}

/// Check if client's ClientHello contains TLS 1.3 in its supported_versions extension.
///
/// Returns `true` if TLS 1.3 is offered by the client.
pub fn client_offers_tls_1_3(ch: &ClientHello) -> bool {
    for ext in &ch.extensions {
        if let ClientHelloExtension::SupportedVersions(version) = ext {
            if *version == der::VERSION_TLS_1_3 {
                return true;
            }
        }
    }
    false
}

/// Validate that a TLS 1.3 handshake was not subject to a downgrade attack.
///
/// Call this after receiving ServerHello when the client offered TLS 1.3.
///
/// # Arguments
/// * `ch` - The client's ClientHello (to check if TLS 1.3 was offered)
/// * `sh_version` - The server's negotiated version from ServerHello
/// * `sh_random` - The server's random bytes from ServerHello
///
/// # Returns
/// * `Ok(())` if no downgrade detected
/// * `Err(TlsError)` if downgrade is indicated
pub fn validate_downgrade_protection(
    ch: &ClientHello,
    sh_version: &[u8; 2],
    sh_random: &[u8; 32],
) -> Result<(), TlsError> {
    let client_offers_tls13 = client_offers_tls_1_3(ch);

    // If client offered TLS 1.3 but server responded with TLS 1.2, check sentinel
    if client_offers_tls13
        && *sh_version != der::VERSION_TLS_1_3
        && check_downgrade_sentinel(sh_random)
    {
        return Err(TlsError::HandshakeFailed(
            "TLS downgrade detected: server responded with lower version despite client \
             supporting TLS 1.3"
                .to_string(),
        ));
    }

    // If client offered TLS 1.3 and server responded with TLS 1.3, ensure NO sentinel
    if client_offers_tls13
        && *sh_version == der::VERSION_TLS_1_3
        && check_downgrade_sentinel(sh_random)
    {
        // This is a protocol violation - TLS 1.3 server should NOT include sentinel
        return Err(TlsError::HandshakeFailed(
            "invalid ServerHello: TLS 1.3 response contains downgrade sentinel".to_string(),
        ));
    }

    Ok(())
}
