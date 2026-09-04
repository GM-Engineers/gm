//! TLCP handshake state.
//!
//! Shared between the client-side and server-side state machines.
//! The `Established` and `Failed` terminal states are reached after
//! the Finished messages round-trip; in between the driver walks
//! `HelloSent → ServerCertsReceived → KeyExchange → WaitFinished`.

/// TLCP handshake state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlcpHandshakeState {
    /// Initial state
    Idle,
    /// Client hello sent / received
    HelloSent,
    /// Server hello + certs received
    ServerCertsReceived,
    /// Key exchange in progress
    KeyExchange,
    /// Waiting for server finished
    WaitFinished,
    /// Handshake complete
    Established,
    /// Handshake failed
    Failed,
}
