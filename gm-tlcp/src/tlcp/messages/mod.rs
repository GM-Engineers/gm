//! TLCP handshake message types (ClientHello, ServerHello, CertPair,
//! ECDHE params, ServerKeyExchange, ServerHelloDone, ClientKeyExchange,
//! Finished).
//!
//! GB/T 38636-2020 §6.4.1. Each module mirrors a sub-section of
//! the standard and contains the wire-format encoder and decoder
//! for one message type. The state machine that strings these
//! messages together lives in `crate::tlcp::handshake::client` /
//! `server`.

pub mod cert_pair;
pub mod client_hello;
pub mod client_key_exchange;
pub mod ecdhe;
pub mod finished;
pub mod server_hello;
pub mod server_hello_done;

pub use cert_pair::TlcpCertPair;
pub use client_hello::TlcpClientHello;
pub use client_key_exchange::TlcpClientKeyExchange;
pub use ecdhe::{Sm2EcdheParams, TlcpServerKeyExchange};
pub use finished::TlcpFinished;
pub use server_hello::TlcpServerHello;
pub use server_hello_done::TlcpServerHelloDone;
