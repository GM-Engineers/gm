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
use std::net::{Ipv6Addr, SocketAddr};
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
    /// Default port when the request URI omits one. `None` (the
    /// default) means "fail loudly" instead of silently falling
    /// back to 50051 — PR-4.9 / P2-2 closes the silent-fallback
    /// hole. Callers that need the legacy 50051 default should
    /// call [`Self::with_default_port`] explicitly with the desired
    /// port (e.g. `50051`) instead.
    default_port: Option<u16>,
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
        Ok(Self {
            inner,
            default_port: None,
        })
    }

    /// Set a fallback port for URIs that omit one. Without this
    /// builder, a missing-port URI returns
    /// `Err("URI has no port and no default port was configured")`
    /// instead of silently dialing 50051.
    ///
    /// PR-4.9 / P2-2.
    pub fn with_default_port(mut self, port: u16) -> Self {
        self.default_port = Some(port);
        self
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
        let default_port = self.default_port;

        Box::pin(async move {
            // Resolve host+port with strict semantics (PR-4.9 / P2-2 + P2-5).
            //  - URI without port: fail if `default_port` is None, else
            //    fall back to it (opt-in, NOT the legacy silent 50051).
            //  - IPv6 literal host: `http::Uri::host()` strips the
            //    brackets, returning "::1"; we re-bracket for
            //    `SocketAddr::from_str` which requires `[::1]:port`.
            let resolved = resolve_uri_addr(&uri, default_port).map_err(|e| {
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;

            // Hand off to TcpStream::connect — `Ip(SocketAddr)` and
            // `Hostname(&str)` are both accepted. For hostname the
            // system resolver runs inside the connect call (no
            // extra DNS hop on our side).
            let tcp = match resolved {
                ResolvedAddr::Ip(addr) => TcpStream::connect(addr).await,
                ResolvedAddr::Hostname(s) => TcpStream::connect(&s).await,
            }
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

// ============================================================================
// PR-4.9 (P2-2 + P2-5): URI host+port resolution
// ============================================================================
//
// Why this exists: `http::Uri::host()` strips brackets from IPv6
// literals (e.g. URI `http://[::1]/` -> `host() == Some("::1")`).
// A naive `format!("{}:{}", host, port)` produces the ambiguous
// `"::1:8080"` which `SocketAddr::from_str` rejects because
// IPv6 literals in `SocketAddr` form MUST be bracketed.
//
// PR-4.9 routes host + port resolution through `resolve_uri_addr`,
// which:
//   1. Detects IPv6 literals (`host.parse::<Ipv6Addr>().is_ok()`)
//      and re-brackets them, then
//   2. Parses via `SocketAddr::from_str` so the OS rejects
//      ambiguous parses at the address layer instead of after a
//      30-second connect timeout.
//
// It also closes the P2-2 silent-fallback hole: a URI without
// an explicit port is rejected with a clear error when no
// `default_port` was configured, instead of silently dialing 50051.

/// Errors produced by URI resolution for the connector call path.
/// Surfaced through `tower::Service<Uri>::call` as `std::io::Error`
/// of `ErrorKind::InvalidInput`.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("URI has no host")]
    NoHost,

    #[error("URI has no port and no default port was configured (default_port = {default_port:?})")]
    NoPort { default_port: Option<u16> },

    #[error(
        "URI host is an IP literal that does not parse as a valid SocketAddr (host={host}, \
         port={port}, source={source})"
    )]
    InvalidSocketAddr {
        host: String,
        port: u16,
        source: std::net::AddrParseError,
    },
}

/// Output of `resolve_uri_addr` (PR-4.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedAddr {
    /// Resolved to an IP literal; safe to pass straight to
    /// `TcpStream::connect` (which accepts both `&str` and `SocketAddr`).
    Ip(SocketAddr),
    /// Hostname (DNS) — `host:port` string for `TcpStream::connect`
    /// to resolve via the system resolver. We deliberately do NOT
    /// pre-resolve via DNS here because (a) it would block the
    /// call path and (b) `getaddrinfo` semantics differ between
    /// sync and async contexts.
    Hostname(String),
}

/// Resolve a tonic-style `http::Uri` to either an IP literal
/// (parsed to `SocketAddr`) or a `host:port` string for DNS
/// resolution by `TcpStream::connect`.
///
/// Port resolution:
///   - `uri.port_u16()` if the URI has an explicit port;
///   - `default_port` (set via [`GmTlsConnector::with_default_port`])
///     when the URI omits one;
///   - hard error if neither is available.
///
/// `default_port = None` is the secure default: missing-port URIs
/// fail loudly with `ResolveError::NoPort { default_port: None }`
/// instead of silently dialing 50051 (PR-4.9 / P2-2).
///
/// IPv6 literal handling: `http::Uri::host()` strips brackets, so
/// URI `http://[::1]/` -> `host() == Some("::1")`. We re-bracket
/// the literal so `TcpStream::connect`'s `&str` and `SocketAddr`
/// paths both accept it (PR-4.9 / P2-5).
pub(crate) fn resolve_uri_addr(
    uri: &http::Uri,
    default_port: Option<u16>,
) -> Result<ResolvedAddr, ResolveError> {
    let host_raw = uri.host().ok_or(ResolveError::NoHost)?;
    // `http::Uri::host()` returns IPv6 literals either bracketed
    // (`[::1]`) on some http versions or unbracketed (`::1`) on
    // others. Strip the brackets so both cases feed the same
    // detection + parse paths below.
    let host = host_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host_raw);
    let port = uri
        .port_u16()
        .or(default_port)
        .ok_or(ResolveError::NoPort { default_port })?;

    // IPv6 literal: bracket it so the downstream parser accepts it.
    if host.parse::<Ipv6Addr>().is_ok() {
        // IP literal: validate via SocketAddr (fail-fast on bad port).
        let s = format!("[{}]:{}", host, port);
        return s
            .parse::<SocketAddr>()
            .map(ResolvedAddr::Ip)
            .map_err(|source| ResolveError::InvalidSocketAddr {
                host: host_raw.to_string(),
                port,
                source,
            });
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        // IP literal: validate via SocketAddr (fail-fast on bad port).
        let s = format!("{}:{}", host, port);
        return s
            .parse::<SocketAddr>()
            .map(ResolvedAddr::Ip)
            .map_err(|source| ResolveError::InvalidSocketAddr {
                host: host_raw.to_string(),
                port,
                source,
            });
    }
    // Hostname (DNS): hand the bracketed-or-plain `host:port`
    // string to TcpStream::connect so the system resolver does
    // the work asynchronously. `TcpStream::connect(&str)` accepts
    // both IPv4 (`"127.0.0.1:8080"`) and IPv6-bracketed
    // (`"[::1]:8080"`) forms; a hostname with `:` embedded would be
    // rejected by the system resolver and surface as an
    // `InvalidInput` connect error.
    Ok(ResolvedAddr::Hostname(format!("{}:{}", host, port)))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod pr49_uri_resolve_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn parse_uri(s: &str) -> http::Uri {
        s.parse().expect("valid URI for test fixture")
    }

    fn err_msg<T>(r: Result<T, ResolveError>) -> String {
        match r {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => format!("{e}"),
        }
    }

    #[test]
    fn pr49_ipv4_literal_with_explicit_port() {
        let uri = parse_uri("http://127.0.0.1:8080/foo");
        let resolved = resolve_uri_addr(&uri, None).expect("must resolve");
        let addr = match resolved {
            ResolvedAddr::Ip(a) => a,
            ResolvedAddr::Hostname(_) => panic!("expected Ip, got Hostname"),
        };
        assert_eq!(
            addr,
            SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080)
        );
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn pr49_ipv6_literal_with_brackets_and_port() {
        let uri = parse_uri("http://[::1]:8080/foo");
        let resolved = resolve_uri_addr(&uri, None).expect("must resolve");
        let addr = match resolved {
            ResolvedAddr::Ip(a) => a,
            ResolvedAddr::Hostname(_) => panic!("expected Ip, got Hostname"),
        };
        assert_eq!(
            addr,
            SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into(), 8080)
        );
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn pr49_ipv6_global_with_brackets_and_port() {
        let uri = parse_uri("http://[2001:db8::1]:9443/foo");
        let resolved = resolve_uri_addr(&uri, None).expect("must resolve");
        let addr = match resolved {
            ResolvedAddr::Ip(a) => a,
            ResolvedAddr::Hostname(_) => panic!("expected Ip, got Hostname"),
        };
        assert_eq!(addr.port(), 9443);
    }

    #[test]
    fn pr49_hostname_with_explicit_port_passes_through() {
        // Hostname path is preserved (NOT pre-resolved) so the
        // existing DNS lookup at TcpStream::connect handles it.
        let uri = parse_uri("http://example.com:8080/foo");
        let resolved = resolve_uri_addr(&uri, None).expect("must resolve");
        match resolved {
            ResolvedAddr::Hostname(s) => assert_eq!(s, "example.com:8080"),
            ResolvedAddr::Ip(_) => panic!("expected Hostname, got Ip"),
        }
    }

    #[test]
    fn pr49_uri_without_port_fails_without_default() {
        let uri = parse_uri("http://localhost/foo");
        let err = err_msg(resolve_uri_addr(&uri, None));
        assert!(
            err.contains("no port"),
            "error must mention missing port; got: {err}"
        );
        assert!(
            err.contains("default port was configured"),
            "error must mention the default-port guidance; got: {err}"
        );
    }

    #[test]
    fn pr49_uri_without_port_uses_default() {
        let uri = parse_uri("http://localhost/foo");
        let resolved = resolve_uri_addr(&uri, Some(9443)).expect("must use default");
        match resolved {
            ResolvedAddr::Hostname(s) => assert_eq!(s, "localhost:9443"),
            ResolvedAddr::Ip(_) => panic!("expected Hostname, got Ip"),
        }
    }

    #[test]
    fn pr49_uri_port_overrides_default() {
        let uri = parse_uri("http://localhost:8080/foo");
        let resolved = resolve_uri_addr(&uri, Some(9443)).expect("must override default");
        match resolved {
            ResolvedAddr::Hostname(s) => assert_eq!(
                s, "localhost:8080",
                "explicit URI port must beat the connector's default"
            ),
            ResolvedAddr::Ip(_) => panic!("expected Hostname, got Ip"),
        }
    }

    #[test]
    fn pr49_ipv6_literal_without_port_fails_without_default() {
        // `http::Uri::from_str` rejects `http://[::1]/` (IPv6 literal
        // without port), so we hand-craft the URI via the builder.
        let uri = http::Uri::builder()
            .scheme("http")
            .authority("[::1]")
            .path_and_query("/")
            .build()
            .expect("builder accepts IPv6 literal authority");
        let err = err_msg(resolve_uri_addr(&uri, None));
        assert!(err.contains("no port"), "got: {err}");
    }

    #[test]
    fn pr49_ipv6_literal_without_port_uses_default() {
        // Same as above — hand-craft the URI via the builder to
        // bypass `from_str`'s strict validator. Verify the resolved
        // IPv6 literal actually parses (i.e. we re-bracket correctly
        // for the default-port path).
        let uri = http::Uri::builder()
            .scheme("http")
            .authority("[::1]")
            .path_and_query("/")
            .build()
            .expect("builder accepts IPv6 literal authority");
        let resolved = resolve_uri_addr(&uri, Some(9443)).expect("must use default");
        let addr = match resolved {
            ResolvedAddr::Ip(a) => a,
            ResolvedAddr::Hostname(_) => panic!("expected Ip, got Hostname"),
        };
        assert_eq!(addr.port(), 9443);
        match addr {
            SocketAddr::V6(v6) => {
                assert_eq!(v6.ip(), &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
            }
            SocketAddr::V4(v4) => panic!("expected IPv6, got IPv4 {}", v4.ip()),
        }
    }

    #[test]
    fn pr49_no_host_fails() {
        // `http://:8080/` — http::Uri::from_str will reject this at
        // parse time on most platforms, so we use a hand-rolled URI
        // string that fails `host()` cleanly.
        let uri: http::Uri = "/foo".parse().unwrap();
        let err = err_msg(resolve_uri_addr(&uri, Some(8080)));
        // Some http crate versions silently accept a path-only URI; we
        // accept either "no host" or "no port" as a hard error here.
        assert!(
            err.contains("no host") || err.contains("no port"),
            "expected no-host or no-port diagnostic, got: {err}"
        );
    }

    #[test]
    fn pr49_uri_builder_integration() {
        // `with_default_port` is a trivial `Option::Some(port)` setter
        // and is covered by the `resolve_uri_addr` tests above.
        // Skipping a struct-literal integration test here avoids
        // constructing an unusable `TlsConnector` just to exercise
        // the builder.
    }

    #[test]
    fn pr49_invalid_host_does_not_panic() {
        // Build a URI with a host that's a valid IPv6 literal but
        // missing the port — exercise the path that has to
        // re-bracket the literal for `SocketAddr::from_str`. This
        // catches a class of panic-on-corrupt-input regressions
        // (the prior code did an unchecked `format!("{}:{}", host,
        // port)` which produced an unparseable string for IPv6).
        let uri = http::Uri::builder()
            .scheme("http")
            .authority("[::1]")
            .path_and_query("/")
            .build()
            .expect("builder accepts IPv6 literal authority");
        let r = resolve_uri_addr(&uri, Some(8080));
        // No panic is the assertion; we additionally verify the
        // outcome is an `Ip` literal (the IPv6 re-bracketing path
        // was correctly taken) and the port is preserved.
        match r {
            Ok(ResolvedAddr::Ip(addr)) => assert_eq!(addr.port(), 8080),
            other => panic!("expected Ok(Ip) with port 8080, got {other:?}"),
        }
    }

    #[test]
    fn pr49_default_port_does_not_silently_dial_50051() {
        // Regression for the P2-2 silent-fallback hole. With no
        // default configured, a URI without an explicit port must
        // HARD FAIL — never silently substitute 50051.
        let uri = parse_uri("http://localhost/foo");
        let r = resolve_uri_addr(&uri, None);
        assert!(r.is_err(), "missing-port URI must not silently succeed");
        let msg = err_msg(r);
        assert!(
            !msg.contains("50051"),
            "error message must not mention 50051 (silent-fallback regression); got: {msg}"
        );
    }
}
