//! GM/TLS core library
//!
//! Provides GM/TLS implementation based on SM2/SM3/SM4, supporting mutual certificate authentication and SM4-GCM encrypted communication.
//!
//! # Features
//!
//! - SM2 key exchange + SM3 KDF derived session keys
//! - SM4-GCM record layer encryption/decryption
//! - RFC 5077 session tickets (session resumption support)
//! - Certificate chain verification (SM2 signature verification)
//! - Finished message signing/verification
//! - Mutual authentication support (mTLS)
//!
//! # Metrics (optional)
//!
//! This library provides observability metrics via the `metrics` crate. To collect metrics, install
//! appropriate exporter (e.g., `metrics-exporter-prometheus`) and call
//! [`describe_metrics`] to register metric descriptions before use:
//!
//! ```ignore
//! use gm_tls::describe_metrics;
//! use metrics_exporter_prometheus::PrometheusBuilder;
//!
//! describe_metrics();
//! PrometheusBuilder::new().install().unwrap();
//! ```
//!
//! # Example (client)
//!
//! ```no_run
//! use gm_tls::{TlsConfig, TlsConnector};
//! use std::fs;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?;
//!     let connector = TlsConnector::new(config)?;
//!
//!     let tcp = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
//!     let mut tls = connector.connect(tcp).await?;
//!
//!     tls.write_application_data(b"Hello").await?;
//!     let response = tls.read_application_data().await?;
//!     println!("Received: {:?}", response);
//!     Ok(())
//! }
//! ```
//!
//! # Example (server)
//!
//! ```no_run
//! use gm_tls::{TlsConfig, TlsAcceptor};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?
//!         .with_require_client_auth(true);
//!     let acceptor = TlsAcceptor::new(config)?;
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
//!     let (tcp, _) = listener.accept().await?;
//!     let mut tls = acceptor.accept(tcp).await?;
//!
//!     let data = tls.read_application_data().await?;
//!     tls.write_application_data(&data).await?;
//!     Ok(())
//! }
//! ```

// `async_trait` (used in `session_store.rs`) generates `#[must_use]` futures. Newer
// clippy (CI runs on nightly) flags this as `clippy::double_must_use` because
// `futures::Future` is already `#[must_use]`. This is a false positive on
// macro-generated code we don't control, so we allow it here.
#![allow(clippy::double_must_use)]

pub mod audit;
#[doc(hidden)]
pub mod cert_verify;
pub mod crypto_traits;
#[doc(hidden)]
pub mod der;
pub mod error;
#[doc(hidden)]
pub mod gm;
#[doc(hidden)]
pub mod handshake;
#[doc(hidden)]
pub(crate) mod kdf;
#[doc(hidden)]
pub mod key_update;
pub mod metrics;
#[doc(hidden)]
pub mod record_layer;
#[doc(hidden)]
pub(crate) mod serialization;
pub mod session_store;
#[doc(hidden)]
pub(crate) mod session_ticket;
pub mod tlcp;
#[allow(deprecated)]
pub use tlcp::{
    TlcpAcceptor, TlcpConnector, TlcpEcdheContext, accept_tlcp, accept_tlcp_with_context,
    connect_tlcp, connect_tlcp_with_context,
};

#[cfg(feature = "grpc")]
pub mod grpc;

// ============================================================================
// Public API — stable types intended for external use
// ============================================================================

// Error types
pub use error::{ErrorCode, TlsError};

// Stream and session management
pub use gm::{
    CertificateVerify, ClientCertificate, ClientHello, CrlInfo, Finished, GmTlsStream,
    HandshakeOptions, HandshakeSecrets, OwnedCert, ServerHello, SessionKeys, SessionTicket,
    TicketKey, TicketKeySet,
};

// Session ticket operations
pub use gm::{
    build_client_hello, build_client_hello_with_ticket, build_server_hello, create_session_state,
    decrypt_session_ticket, derive_session_keys_sm2, encrypt_session_ticket,
};

// Certificate and CRL verification
pub use gm::{validate_cert_pem, verify_cert_chain_sm2_chain, verify_cert_crl, verify_crl};

// Session store
pub use session_store::{SessionStore, SessionStoreConfig};

// Metrics
pub use metrics::describe_metrics;

// Audit logging
pub use audit::{
    ActionResult, Actor, AuditConfig, AuditContext, AuditEvent, AuditEventType, AuditLogger,
    Severity,
};

// ============================================================================
// Semi-public API — exposed for advanced use cases, may change
// ============================================================================

pub use crypto_traits::{BlockCipher, Hasher, Hmac, Signer, Verifier};

// ============================================================================
// Internal API — exposed for crate-internal use; not part of the public API
// ============================================================================

#[doc(hidden)]
pub use gm::{
    compute_transcript_hash, compute_transcript_hash_multi, generate_sm2_ephemeral, hkdf_sm3,
    next_nonce, select_alpn, sign_finished, verify_finished,
};
#[doc(hidden)]
pub use serialization::{deserialize, serialize};

use gm::{accept_gm_rust, accept_gm_rust_with_client_cert, connect_gm_rust};
use gm_crypto::kat;
use std::fs;
use std::path::{Path, PathBuf};

/// TLS backend implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsBackend {
    /// GM/TLS GM implementation
    GmRust,
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    cert_path: PathBuf,
    key_path: PathBuf,
    ca_path: PathBuf,
    /// Pre-loaded certificate bytes (used when constructed via `from_bytes`)
    cert_bytes: Option<Vec<u8>>,
    /// Pre-loaded private key bytes (used when constructed via `from_bytes`)
    key_bytes: Option<Vec<u8>>,
    /// Pre-loaded CA certificate bytes (used when constructed via `from_bytes`)
    ca_bytes: Option<Vec<u8>>,
    domain: Option<String>,
    alpn: Vec<String>,
    require_client_auth: bool,
    backend: TlsBackend,
    handshake_opts: Option<HandshakeOptions>,
}

impl TlsConfig {
    /// Load TLS configuration from file path
    ///
    /// # Arguments
    /// * `cert_path` - certificate file path (PEM format)
    /// * `key_path` - private key file path (PEM format)
    /// * `ca_path` - CA certificate file path (PEM format)
    ///
    /// # Errors
    /// Returns error if any file does not exist or cannot be read
    pub fn load<P: AsRef<Path>>(cert_path: P, key_path: P, ca_path: P) -> Result<Self, TlsError> {
        for p in [cert_path.as_ref(), key_path.as_ref(), ca_path.as_ref()] {
            if !p.exists() {
                return Err(TlsError::ConfigError(format!(
                    "certificate/key file does not exist: {}",
                    p.display()
                )));
            }
        }
        Ok(Self {
            cert_path: cert_path.as_ref().to_path_buf(),
            key_path: key_path.as_ref().to_path_buf(),
            ca_path: ca_path.as_ref().to_path_buf(),
            cert_bytes: None,
            key_bytes: None,
            ca_bytes: None,
            domain: None,
            alpn: Vec::new(),
            require_client_auth: true,
            backend: TlsBackend::GmRust,
            handshake_opts: None,
        })
    }

    /// Create TLS configuration from in-memory byte buffers.
    ///
    /// This is useful when certificates and keys are loaded from a secure
    /// secrets manager, environment, or embedded at compile time, rather
    /// than from the filesystem.
    ///
    /// # Arguments
    /// * `cert_pem` - Certificate bytes (PEM format)
    /// * `key_pem` - Private key bytes (PEM format)
    /// * `ca_pem` - CA certificate bytes (PEM format)
    ///
    /// # Errors
    /// Returns error if any buffer is empty
    pub fn from_bytes(
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        ca_pem: Vec<u8>,
    ) -> Result<Self, TlsError> {
        if cert_pem.is_empty() {
            return Err(TlsError::ConfigError(
                "certificate PEM must not be empty".into(),
            ));
        }
        if key_pem.is_empty() {
            return Err(TlsError::ConfigError(
                "private key PEM must not be empty".into(),
            ));
        }
        if ca_pem.is_empty() {
            return Err(TlsError::ConfigError(
                "CA certificate PEM must not be empty".into(),
            ));
        }
        Ok(Self {
            cert_path: PathBuf::new(),
            key_path: PathBuf::new(),
            ca_path: PathBuf::new(),
            cert_bytes: Some(cert_pem),
            key_bytes: Some(key_pem),
            ca_bytes: Some(ca_pem),
            domain: None,
            alpn: Vec::new(),
            require_client_auth: true,
            backend: TlsBackend::GmRust,
            handshake_opts: None,
        })
    }

    /// Returns true if this config was created from in-memory bytes
    /// (i.e., cert/key/ca are all provided as bytes, not filesystem paths).
    pub fn is_from_bytes(&self) -> bool {
        self.cert_bytes.is_some() && self.key_bytes.is_some() && self.ca_bytes.is_some()
    }

    /// Set domain validation
    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Set ALPN protocol list
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn;
        self
    }

    /// Set whether client certificate is required
    pub fn with_require_client_auth(mut self, require: bool) -> Self {
        self.require_client_auth = require;
        self
    }

    /// Set handshake options (session ticket, CRL, etc.)
    ///
    /// This allows configuration of session resumption, certificate revocation
    /// checking, and other handshake-level options.
    pub fn with_handshake_options(mut self, opts: HandshakeOptions) -> Self {
        self.handshake_opts = Some(opts);
        self
    }

    /// Set session ticket for session resumption (client-side)
    pub fn with_session_ticket(mut self, ticket: SessionTicket) -> Self {
        self.handshake_opts
            .get_or_insert_with(HandshakeOptions::default);
        if let Some(opts) = &mut self.handshake_opts {
            opts.session_ticket = Some(ticket);
        }
        self
    }

    /// Set session ticket key for session resumption (server-side)
    pub fn with_session_ticket_key(mut self, key_set: TicketKeySet) -> Self {
        self.handshake_opts
            .get_or_insert_with(HandshakeOptions::default);
        if let Some(opts) = &mut self.handshake_opts {
            opts.session_ticket_key = Some(key_set);
        }
        self
    }

    /// Set CRL info for certificate revocation checking
    pub fn with_crl_info(mut self, crl_info: CrlInfo) -> Self {
        self.handshake_opts
            .get_or_insert_with(HandshakeOptions::default);
        if let Some(opts) = &mut self.handshake_opts {
            opts.crl_info = Some(crl_info);
        }
        self
    }
}

/// GM/TLS client connector
#[derive(Clone)]
pub struct TlsConnector {
    cfg: TlsConfig,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
    opts: HandshakeOptions,
}

impl TlsConnector {
    /// Create new TLS connector
    ///
    /// # Errors
    /// Returns error if certificate/private key/CA file read fails or KAT self-test fails
    pub fn new(cfg: TlsConfig) -> Result<Self, TlsError> {
        // GM/T 0028-2014 §7.2.4.1: power-up self-test on first initialization
        kat::ensure_self_test()
            .map_err(|e| TlsError::HandshakeFailed(format!("KAT self-test failed: {}", e)))?;
        let (cert_pem, key_pem, ca_pem) = if cfg.is_from_bytes() {
            (
                cfg.cert_bytes
                    .clone()
                    .ok_or_else(|| TlsError::IoError("cert_bytes missing".into()))?,
                cfg.key_bytes
                    .clone()
                    .ok_or_else(|| TlsError::IoError("key_bytes missing".into()))?,
                cfg.ca_bytes
                    .clone()
                    .ok_or_else(|| TlsError::IoError("ca_bytes missing".into()))?,
            )
        } else {
            let cert_pem = fs::read(&cfg.cert_path)
                .map_err(|e| TlsError::IoError(format!("failed to read certificate: {}", e)))?;
            let key_pem = fs::read(&cfg.key_path)
                .map_err(|e| TlsError::IoError(format!("failed to read private key: {}", e)))?;
            let ca_pem = fs::read(&cfg.ca_path)
                .map_err(|e| TlsError::IoError(format!("failed to read CA: {}", e)))?;
            (cert_pem, key_pem, ca_pem)
        };
        let opts = cfg.handshake_opts.clone().unwrap_or_default();
        Ok(Self {
            cfg,
            cert_pem,
            key_pem,
            ca_pem,
            opts,
        })
    }

    /// Connect to TLS server
    ///
    /// # Type Parameters
    /// * `S` - stream implementing AsyncRead + AsyncWrite + Unpin
    pub async fn connect<S>(&self, stream: S) -> Result<GmTlsStream<S>, TlsError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        match self.cfg.backend {
            TlsBackend::GmRust => {
                connect_gm_rust(
                    &self.cert_pem,
                    &self.key_pem,
                    &self.ca_pem,
                    self.cfg.domain.as_deref(),
                    &self.cfg.alpn,
                    stream,
                    &self.opts,
                )
                .await
            }
        }
    }
}

/// GM/TLS server acceptor
#[derive(Clone)]
pub struct TlsAcceptor {
    cfg: TlsConfig,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
    opts: HandshakeOptions,
}

impl TlsAcceptor {
    /// Create new TLS acceptor
    ///
    /// # Errors
    /// Returns error if certificate/private key/CA file read fails or KAT self-test fails
    pub fn new(cfg: TlsConfig) -> Result<Self, TlsError> {
        // GM/T 0028-2014 §7.2.4.1: power-up self-test on first initialization
        kat::ensure_self_test()
            .map_err(|e| TlsError::HandshakeFailed(format!("KAT self-test failed: {}", e)))?;
        let (cert_pem, key_pem, ca_pem) = if cfg.is_from_bytes() {
            (
                cfg.cert_bytes
                    .clone()
                    .ok_or_else(|| TlsError::IoError("cert_bytes missing".into()))?,
                cfg.key_bytes
                    .clone()
                    .ok_or_else(|| TlsError::IoError("key_bytes missing".into()))?,
                cfg.ca_bytes
                    .clone()
                    .ok_or_else(|| TlsError::IoError("ca_bytes missing".into()))?,
            )
        } else {
            let cert_pem = fs::read(&cfg.cert_path)
                .map_err(|e| TlsError::IoError(format!("failed to read certificate: {}", e)))?;
            let key_pem = fs::read(&cfg.key_path)
                .map_err(|e| TlsError::IoError(format!("failed to read private key: {}", e)))?;
            let ca_pem = fs::read(&cfg.ca_path)
                .map_err(|e| TlsError::IoError(format!("failed to read CA: {}", e)))?;
            (cert_pem, key_pem, ca_pem)
        };
        let opts = cfg.handshake_opts.clone().unwrap_or_default();
        Ok(Self {
            cfg,
            cert_pem,
            key_pem,
            ca_pem,
            opts,
        })
    }

    /// Accept TLS client connection
    pub async fn accept<S>(&self, stream: S) -> Result<GmTlsStream<S>, TlsError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        match self.cfg.backend {
            TlsBackend::GmRust => {
                accept_gm_rust(
                    &self.cert_pem,
                    &self.key_pem,
                    &self.ca_pem,
                    self.cfg.require_client_auth,
                    &self.cfg.alpn,
                    stream,
                    &self.opts,
                )
                .await
            }
        }
    }

    /// Accept TLS client connection and return client certificate info
    pub async fn accept_with_client_cert<S>(
        &self,
        stream: S,
    ) -> Result<(GmTlsStream<S>, Option<String>, Option<SessionTicket>), TlsError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        match self.cfg.backend {
            TlsBackend::GmRust => {
                accept_gm_rust_with_client_cert(
                    &self.cert_pem,
                    &self.key_pem,
                    &self.ca_pem,
                    self.cfg.require_client_auth,
                    &self.cfg.alpn,
                    stream,
                    &self.opts,
                )
                .await
            }
        }
    }
}
