//! GM/HTTP-Client - HTTP client with GM/TLS support
//!
//! Provides an HTTP client that uses GM/TLS (国密TLS) for secure communication.

mod client;
mod error;
mod pool;

pub use client::GmHttpClient;
pub use error::HttpClientError;
pub use gm_tls::TlsConfig;
pub use pool::{ConnectionPool, PooledHttpClient};
