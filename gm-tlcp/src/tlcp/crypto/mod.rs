//! TLCP record-layer cryptographic helpers.
//!
//! Currently exposes [`verify::verify_ske_signature`] for SKE signature
//! verification and [`verify::extract_sm2_pubkey_from_cert_der`] for
//! pulling the SM2 pubkey out of an X.509 cert's SubjectPublicKeyInfo.
//! The SM4-CBC / SM4-GCM record-layer encrypt/decrypt functions remain
//! inside the `TlcpStream` impl block because they are interleaved
//! with the async read/write state machine.

pub mod verify;
