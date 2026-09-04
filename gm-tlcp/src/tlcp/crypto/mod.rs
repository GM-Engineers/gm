//! TLCP record-layer cryptographic helpers (Phase E, partial).
//!
//! As of this commit only the signature-verification helpers live
//! here (`verify::verify_ske_signature` and the cert pubkey
//! extraction wrapper). The SM4-CBC + SM4-GCM encrypt/decrypt
//! functions remain inside the `TlcpStream` impl block in
//! `crate::tlcp::mod` because they are interleaved with the async
//! read/write state machine.
//!
//! Pulling them out cleanly would require turning the impl methods
//! into a free function that takes the relevant fields
//! (`read_seq`, `write_seq`, `read_keys`, `write_keys`, etc.) and
//! returning the resulting ciphertext or plaintext. That is a
//! more invasive refactor than the current phase warrants; it is
//! tracked as Phase E follow-up.

pub mod verify;
