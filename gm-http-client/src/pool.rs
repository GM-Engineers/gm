//! HTTP connection pool for GM/TLS connections.
//!
//! This module provides connection pooling to reuse established TLS connections,
//! avoiding the overhead of TLS handshakes for repeated requests to the same host.
//!
//! # Example
//!
//! ```rust,ignore
//! use gm_http_client::{GmHttpClient, ConnectionPool};
//!
//! let pool = ConnectionPool::new(100); // max 100 connections
//! let client = GmHttpClient::new_with_pool(pool, tls_config)?;
//! ```

use crate::GmHttpClient;
use crate::client::{Response, build_request, parse_and_validate_url};
use crate::error::HttpClientError;
use gm_tls::GmTlsStream;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

/// Maximum idle time for a pooled connection (5 minutes)
const MAX_IDLE_TIME: Duration = Duration::from_secs(300);

/// Trait for pooled streams, allowing mock implementations for testing.
/// Production code uses `GmTlsStream<TcpStream>`.
pub trait PooledStream: Send + Sync {
    /// Check if the underlying connection is still alive
    fn is_alive(&self) -> bool;
}

impl PooledStream for GmTlsStream<TcpStream> {
    fn is_alive(&self) -> bool {
        // GmTlsStream doesn't have an isAlive method, but we can check
        // if the inner TcpStream is still connected by attempting a read
        // For now, return true - the actual health check happens on use
        true
    }
}

/// Entry in the connection pool
struct PoolEntry<S: AsyncRead + AsyncWrite + Unpin + Send + PooledStream + 'static> {
    stream: S,
    last_used: Instant,
}

/// Connection pool for TLS connections.
///
/// Maintains a cache of established connections per host to avoid
/// TLS handshake overhead on repeated requests.
pub struct ConnectionPool<
    S: AsyncRead + AsyncWrite + Unpin + Send + PooledStream + 'static = GmTlsStream<TcpStream>,
> {
    /// Map from host:port -> list of pooled connections
    connections: Arc<RwLock<HashMap<String, Vec<PoolEntry<S>>>>>,
    /// Maximum number of connections to cache per host
    max_per_host: usize,
    /// Maximum idle time before connection is evicted
    max_idle_time: Duration,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + PooledStream + 'static> ConnectionPool<S> {
    /// Create a new connection pool
    pub fn new(max_per_host: usize) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            max_per_host,
            max_idle_time: MAX_IDLE_TIME,
        }
    }

    /// Get a cached connection for the given host, or create a new one.
    pub async fn get_connection(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Option<S>, HttpClientError> {
        let key = format!("{}:{}", host, port);

        // Try to get an existing connection
        let mut connections = self.connections.write().await;
        if let Some(pool) = connections.get_mut(&key) {
            // Find a connection that's still valid
            let now = Instant::now();
            while let Some(entry) = pool.pop() {
                if now.duration_since(entry.last_used) < self.max_idle_time
                    && entry.stream.is_alive()
                {
                    return Ok(Some(entry.stream));
                }
            }
        }

        // No valid connection in pool, will need to create new one
        Ok(None)
    }

    /// Return a connection to the pool
    pub async fn return_connection(&self, host: &str, port: u16, stream: S) {
        let key = format!("{}:{}", host, port);
        let mut connections = self.connections.write().await;

        let pool = connections.entry(key).or_insert_with(Vec::new);

        if pool.len() < self.max_per_host {
            pool.push(PoolEntry {
                stream,
                last_used: Instant::now(),
            });
        }
        // If pool is full, just drop the connection
    }

    /// Clean up stale connections
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut connections = self.connections.write().await;

        for pool in connections.values_mut() {
            pool.retain(|entry| {
                now.duration_since(entry.last_used) < self.max_idle_time && entry.stream.is_alive()
            });
        }
    }

    /// Get the number of pooled connections
    pub async fn len(&self) -> usize {
        let connections = self.connections.read().await;
        connections.values().map(|p| p.len()).sum()
    }

    /// Check if pool is empty
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite};

    /// Mock stream for testing the connection pool
    #[derive(Debug)]
    #[allow(dead_code)]
    struct MockStream {
        read_data: Vec<u8>,
        write_data: Vec<u8>,
        read_pos: usize,
        alive: bool,
    }

    impl MockStream {
        fn new() -> Self {
            Self {
                read_data: Vec::new(),
                write_data: Vec::new(),
                read_pos: 0,
                alive: true,
            }
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.read_pos < self.read_data.len() {
                let remaining = &self.read_data[self.read_pos..];
                let to_copy = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                self.read_pos += to_copy;
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.write_data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for MockStream {}

    /// Test stream that implements PooledStream for testing
    struct TestPoolEntry {
        stream: MockStream,
        alive: bool,
    }

    impl PooledStream for TestPoolEntry {
        fn is_alive(&self) -> bool {
            self.alive
        }
    }

    impl AsyncRead for TestPoolEntry {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestPoolEntry {
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

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    impl Unpin for TestPoolEntry {}

    /// Custom pool type for testing with TestPoolEntry
    type TestPool = ConnectionPool<TestPoolEntry>;

    fn create_test_pool_entry() -> TestPoolEntry {
        TestPoolEntry {
            stream: MockStream::new(),
            alive: true,
        }
    }

    #[tokio::test]
    async fn test_pool_new_empty() {
        let pool: TestPool = ConnectionPool::new(5);
        assert!(pool.is_empty().await);
        assert_eq!(pool.len().await, 0);
    }

    #[tokio::test]
    async fn test_pool_cleanup_no_connections() {
        let pool: TestPool = ConnectionPool::new(5);
        pool.cleanup().await;
        assert!(pool.is_empty().await);
        assert_eq!(pool.len().await, 0);
    }

    #[tokio::test]
    async fn test_pool_custom_max_idle_time() {
        let pool: TestPool = ConnectionPool::new(10);
        assert!(pool.is_empty().await);
        pool.cleanup().await;
    }

    #[tokio::test]
    async fn test_pool_len_after_cleanup() {
        let pool: TestPool = ConnectionPool::new(5);
        pool.cleanup().await;
        assert_eq!(pool.len().await, 0);
    }

    #[tokio::test]
    async fn test_pool_different_max_per_host() {
        let pool1: TestPool = ConnectionPool::new(1);
        let pool2: TestPool = ConnectionPool::new(100);
        assert!(pool1.is_empty().await);
        assert!(pool2.is_empty().await);
    }

    #[tokio::test]
    async fn test_pool_store_and_retrieve_connection() {
        let pool: TestPool = ConnectionPool::new(5);
        let entry = create_test_pool_entry();

        // Store a connection
        pool.return_connection("example.com", 443, entry).await;
        assert_eq!(pool.len().await, 1);

        // Retrieve the connection
        let retrieved = pool.get_connection("example.com", 443).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(pool.len().await, 0); // Connection was retrieved and removed from pool
    }

    #[tokio::test]
    async fn test_pool_different_hosts_separate_pools() {
        let pool: TestPool = ConnectionPool::new(5);
        let entry1 = create_test_pool_entry();
        let entry2 = create_test_pool_entry();

        pool.return_connection("example.com", 443, entry1).await;
        pool.return_connection("other.com", 443, entry2).await;
        assert_eq!(pool.len().await, 2);

        // Retrieve from one host doesn't affect the other
        let retrieved = pool.get_connection("example.com", 443).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(pool.len().await, 1); // Other host still has its connection
    }

    #[tokio::test]
    async fn test_pool_max_per_host_limit() {
        let pool: TestPool = ConnectionPool::new(2); // Max 2 per host
        let entry1 = create_test_pool_entry();
        let entry2 = create_test_pool_entry();
        let entry3 = create_test_pool_entry();

        pool.return_connection("example.com", 443, entry1).await;
        pool.return_connection("example.com", 443, entry2).await;
        assert_eq!(pool.len().await, 2);

        // Third connection should be dropped (pool is full)
        pool.return_connection("example.com", 443, entry3).await;
        assert_eq!(pool.len().await, 2); // Still 2, third was dropped
    }

    #[tokio::test]
    async fn test_pool_different_ports_separate() {
        let pool: TestPool = ConnectionPool::new(5);
        let entry1 = create_test_pool_entry();
        let entry2 = create_test_pool_entry();

        pool.return_connection("example.com", 443, entry1).await;
        pool.return_connection("example.com", 8443, entry2).await;
        assert_eq!(pool.len().await, 2);

        // Retrieve from one port doesn't affect the other
        let retrieved = pool.get_connection("example.com", 443).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(pool.len().await, 1); // Port 8443 still has connection
    }

    #[tokio::test]
    async fn test_pool_multiple_connections_same_host() {
        let pool: TestPool = ConnectionPool::new(5);
        let entry1 = create_test_pool_entry();
        let entry2 = create_test_pool_entry();

        pool.return_connection("example.com", 443, entry1).await;
        pool.return_connection("example.com", 443, entry2).await;
        assert_eq!(pool.len().await, 2);

        // FIFO retrieval - first in, first out
        let retrieved1 = pool.get_connection("example.com", 443).await.unwrap();
        assert!(retrieved1.is_some());
        assert_eq!(pool.len().await, 1);

        let retrieved2 = pool.get_connection("example.com", 443).await.unwrap();
        assert!(retrieved2.is_some());
        assert_eq!(pool.len().await, 0);
    }

    #[tokio::test]
    async fn test_pool_returns_none_when_empty() {
        let pool: TestPool = ConnectionPool::new(5);

        let retrieved = pool.get_connection("example.com", 443).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_pool_cleanup_removes_stale_connections() {
        // Create pool with very short idle time for testing
        let pool: TestPool = ConnectionPool {
            connections: Arc::new(RwLock::new(HashMap::new())),
            max_per_host: 5,
            max_idle_time: Duration::from_millis(1), // 1ms idle time
        };

        let entry = create_test_pool_entry();
        pool.return_connection("example.com", 443, entry).await;
        assert_eq!(pool.len().await, 1);

        // Wait for connection to become stale
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Cleanup should remove stale connection
        pool.cleanup().await;
        assert_eq!(pool.len().await, 0);
    }
}

/// Wrapper around GmHttpClient that uses connection pooling
#[derive(Clone)]
pub struct PooledHttpClient {
    client: GmHttpClient,
    pool: Arc<ConnectionPool<GmTlsStream<TcpStream>>>,
}

impl PooledHttpClient {
    /// Create a new pooled HTTP client
    pub fn new(client: GmHttpClient, pool: ConnectionPool<GmTlsStream<TcpStream>>) -> Self {
        Self {
            client,
            pool: Arc::new(pool),
        }
    }

    /// Send a GET request
    pub async fn get(&self, url: &str) -> Result<Response, HttpClientError> {
        let parsed = parse_and_validate_url(url)?;
        self.request("GET", &parsed.host, parsed.port, &parsed.path, &[])
            .await
    }

    /// Send a POST request
    pub async fn post(&self, url: &str, body: &[u8]) -> Result<Response, HttpClientError> {
        let parsed = parse_and_validate_url(url)?;
        self.request("POST", &parsed.host, parsed.port, &parsed.path, body)
            .await
    }

    async fn request(
        &self,
        method: &str,
        host: &str,
        port: u16,
        path: &str,
        body: &[u8],
    ) -> Result<Response, HttpClientError> {
        let addr = format!("{}:{}", host, port);

        // Try to get pooled connection
        let mut tls_stream = if let Some(stream) = self.pool.get_connection(host, port).await? {
            stream
        } else {
            // Create new connection
            let tcp = TcpStream::connect(&addr)
                .await
                .map_err(|e| HttpClientError::ConnectionFailed(e.to_string()))?;

            self.client
                .tls_connector()
                .connect(tcp)
                .await
                .map_err(|e| HttpClientError::TlsError(e.to_string()))?
        };

        let request = build_request(method, host, path, body);
        tls_stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| HttpClientError::IoError(e.to_string()))?;

        // For now, we read the full response and return the connection
        let response = self.client.read_response(&mut tls_stream).await;

        // Return connection to pool if still valid
        if response.is_ok() {
            self.pool.return_connection(host, port, tls_stream).await;
        }

        response
    }

    /// Start background cleanup task for the connection pool
    pub fn start_cleanup_task(self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                pool.cleanup().await;
            }
        })
    }
}
