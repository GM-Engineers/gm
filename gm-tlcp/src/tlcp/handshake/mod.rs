//! TLCP handshake state machine.
//!
//! Two flavours: a client-side driver (`TlcpHandshake`) and a
//! server-side driver (`TlcpServerHandshake`). Both share the
//! `TlcpHandshakeState` enum and consume / produce the message
//! types from `crate::tlcp::messages`. The actual record-layer
//! I/O lives in the `stream` module; this one only does state
//! transitions and key derivation.

pub mod client;
pub mod server;
pub mod state;

pub use client::TlcpHandshake;
pub use server::TlcpServerHandshake;
pub use state::TlcpHandshakeState;
