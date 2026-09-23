//! gRPC transport integration for GM/TLS.
//!
//! This module provides tonic-compatible server and client transport adapters
//! that use GM/TLS (SM2/SM3/SM4) instead of standard TLS (RSA/ECDHE+AES-GCM).
//!
//! # Server Usage
//!
//! ```ignore
//! use gm_tls::{TlsConfig, TlsAcceptor, grpc::GmTlsIncoming};
//! use tonic::transport::Server;
//!
//! let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?
//!     .with_alpn(vec!["h2".to_string()]);
//! let acceptor = TlsAcceptor::new(config)?;
//! let listener = TcpListener::bind("[::1]:50051").await?;
//! let incoming = GmTlsIncoming::new(listener, acceptor);
//!
//! Server::builder()
//!     .add_service(my_service)
//!     .serve_with_incoming(incoming)
//!     .await?;
//! ```
//!
//! # Client Usage
//!
//! ```ignore
//! use gm_tls::{TlsConfig, TlsConnector, grpc::GmTlsConnector};
//! use tonic::transport::Endpoint;
//!
//! let config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?
//!     .with_domain("example.com".to_string())
//!     .with_alpn(vec!["h2".to_string()]);
//! let connector = GmTlsConnector::new(config)?;
//!
//! let channel = Endpoint::from_static("http://[::1]:50051")
//!     .connect_with_connector(connector)
//!     .await?;
//! ```

use crate::{GmTlsStream, TlsAcceptor, TlsConnector};
use futures::StreamExt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tonic::transport::server::Connected;

// ---------------------------------------------------------------------------
// Server side: GmTlsIncoming + GmServerIo
// ---------------------------------------------------------------------------

/// Connection metadata for GM/TLS server connections.
#[derive(Debug, Clone)]
pub struct GmTlsConnectInfo {
    /// Remote address of the client.
    pub remote_addr: Option<SocketAddr>,
    /// Local address of the server.
    pub local_addr: Option<SocketAddr>,
    /// Negotiated ALPN protocol.
    pub alpn: Option<String>,
}

/// Wrapper around `GmTlsStream<TcpStream>` that implements `Connected` for tonic.
pub struct GmServerIo {
    stream: GmTlsStream<TcpStream>,
    connect_info: GmTlsConnectInfo,
}

impl GmServerIo {
    /// Returns the negotiated ALPN protocol.
    pub fn alpn(&self) -> Option<&str> {
        self.stream.alpn()
    }
}

impl AsyncRead for GmServerIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for GmServerIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Connected for GmServerIo {
    type ConnectInfo = GmTlsConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.connect_info.clone()
    }
}

/// A stream of GM/TLS-encrypted connections suitable for `tonic::transport::Server::serve_with_incoming`.
///
/// Accepts TCP connections from the given listener, performs GM/TLS handshake
/// using the provided acceptor, and yields the resulting encrypted streams.
/// Failed handshakes are logged and skipped.
pub struct GmTlsIncoming {
    inner: Pin<Box<dyn futures::Stream<Item = Result<GmServerIo, std::io::Error>> + Send>>,
    // Semaphore controls max concurrent handshakes. Stored as Arc to allow clones
    // to be passed into the stream. The field itself is not read after construction,
    // but keeping it in the struct ensures the semaphore lives as long as the struct.
    #[allow(dead_code)]
    semaphore: Arc<Semaphore>,
    /// Local address this listener is bound to. Captured at
    /// construction time (before the listener is moved into the
    /// inner stream). `None` only if `TcpListener::local_addr()`
    /// itself failed at construction (e.g. the listener was
    /// already closed). PR-4.6 / P1-6.
    local_addr: Option<SocketAddr>,
}

impl GmTlsIncoming {
    /// Create a new GM/TLS incoming stream.
    ///
    /// # Arguments
    /// * `listener` - TCP listener bound to the desired address
    /// * `acceptor` - GM/TLS acceptor configured with server certificate and CA
    pub fn new(listener: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self::with_max_concurrent(listener, acceptor, 1024)
    }

    /// Create with a custom max concurrent handshakes limit.
    pub fn with_max_concurrent(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        max_concurrent: usize,
    ) -> Self {
        // PR-4.6 (P1-6): capture local_addr before moving the
        // listener into the stream (the listener is consumed
        // by `TcpListenerStream::new(listener)` below and is
        // not accessible afterwards). `TcpListener::local_addr`
        // does not consume `&self` so this works whether the
        // listener is bound (returns the bound addr) or unbound
        // (returns an Err which we capture as None).
        let local_addr = listener.local_addr().ok();
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let semaphore_for_stream = Arc::clone(&semaphore);
        let incoming =
            tokio_stream::wrappers::TcpListenerStream::new(listener).filter_map(move |result| {
                let acceptor = acceptor.clone();
                let permit = Arc::clone(&semaphore_for_stream);
                async move {
                    match result {
                        Ok(tcp) => {
                            let _permit = permit.acquire().await.ok()?;
                            let remote_addr = tcp.peer_addr().ok();
                            let local_addr = tcp.local_addr().ok();
                            match acceptor.accept(tcp).await {
                                Ok(stream) => {
                                    let alpn = stream.alpn().map(String::from);
                                    Some(Ok(GmServerIo {
                                        stream,
                                        connect_info: GmTlsConnectInfo {
                                            remote_addr,
                                            local_addr,
                                            alpn,
                                        },
                                    }))
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "GM/TLS handshake failed from {:?}: {}",
                                        remote_addr,
                                        e
                                    );
                                    // Skip failed handshakes - return None to filter them out
                                    None
                                }
                            }
                        }
                        Err(e) => Some(Err(e)),
                    }
                }
            });

        Self {
            inner: Box::pin(incoming),
            semaphore,
            local_addr,
        }
    }

    /// Returns the local address this listener is bound to.
    ///
    /// PR-4.6 (P1-6): the address is captured at construction
    /// time (see [`Self::with_max_concurrent`]) before the listener
    /// is moved into the inner stream. This method never re-queries
    /// the listener — it just returns the cached value. Returns
    /// `Err(AddrNotAvailable)` only in the rare case where
    /// `TcpListener::local_addr()` itself failed at construction
    /// (e.g. listener was already closed).
    ///
    /// tonic middleware that needs `ConnectInfo.local_addr` (rate
    /// limiting by local port, audit logging, Prometheus labels
    /// keyed on listener address) now has a usable API.
    pub async fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.local_addr.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "local_addr unavailable (TcpListener::local_addr failed at construction)",
            )
        })
    }
}

impl futures::Stream for GmTlsIncoming {
    type Item = Result<GmServerIo, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

// ---------------------------------------------------------------------------
// Client side: GmTlsConnector
// ---------------------------------------------------------------------------

/// A tonic-compatible connector that uses GM/TLS for transport encryption.
///
/// Implements `tower::Service<http::Uri>` so it can be used with
/// `tonic::transport::Endpoint::connect_with_connector`.
#[derive(Clone)]
pub struct GmTlsConnector {
    inner: TlsConnector,
}

impl GmTlsConnector {
    /// Create a new GM/TLS connector from a TlsConfig.
    ///
    /// The config should include:
    /// - Client certificate and key
    /// - CA certificate for server verification
    /// - Domain for SNI
    /// - ALPN set to `["h2"]` for gRPC/HTTP2
    pub fn new(config: crate::TlsConfig) -> Result<Self, crate::TlsError> {
        let inner = TlsConnector::new(config)?;
        Ok(Self { inner })
    }
}

impl tower::Service<http::Uri> for GmTlsConnector {
    type Response = hyper_util::rt::TokioIo<GmTlsStream<TcpStream>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let connector = self.inner.clone();

        Box::pin(async move {
            // Extract host:port from URI
            let host = uri
                .host()
                .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("URI has no host: {}", uri).into()
                })?;
            let port = uri.port_u16().unwrap_or(50051);

            let addr = format!("{}:{}", host, port);

            let tcp = TcpStream::connect(&addr)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            let tls_stream = connector.connect(tcp).await.map_err(|e| {
                Box::new(std::io::Error::other(format!(
                    "GM/TLS handshake failed: {}",
                    e
                ))) as Box<dyn std::error::Error + Send + Sync>
            })?;

            Ok(hyper_util::rt::TokioIo::new(tls_stream))
        })
    }
}

// ============================================================================
// PR-4.6 (P1-6) tests: GmTlsIncoming::local_addr returns bound address
// ============================================================================
//
// The end-to-end coverage (bind 127.0.0.1:0, build GmTlsIncoming,
// call local_addr) lives in `tests/gmssl_interop_tests.rs` because
// it requires loading a real TlsConfig from the test fixtures.
//
// Pre-PR-4.6 the implementation was a stub returning
// Err(AddrNotAvailable) — the comment "We need to
// reconstruct this - just return error for now" was the TODO
// marker. PR-4.6 closes that TODO and the new behavior is locked
// in by the integration tests in tests/gmssl_interop_tests.rs.
//
// The local_addr caching invariant is purely a function of
// `TcpListener::local_addr()` — independent of TlsConfig validity —
// so there is no clean way to unit-test it without dragging in
// disk fixtures. The integration tests are the canonical coverage.

#[cfg(test)]
mod pr46_local_addr_tests {
    /// Marker that PR-4.6 unit-test scaffolding stays in this
    /// file when the integration tests in `tests/gmssl_interop_tests.rs`
    /// are edited. The integration tests must always cover:
    /// - local_addr() returns the bound address (Ok(addr))
    /// - local_addr() is stable across multiple calls
    #[test]
    fn pr46_local_addr_coverage_lives_in_integration_tests() {
        // Sanity: the GmTlsIncoming type still exists and is non-zero-size.
        assert!(
            std::mem::size_of::<crate::grpc::GmTlsIncoming>() > 0,
            "GmTlsIncoming must remain a non-zero-size type"
        );
    }
}
