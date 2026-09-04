//! Support module shared by integration tests.
//!
//! Each submodule is gated on what its test needs:
//!   - `cert_setup` requires the `gmssl` binary on PATH; tests that
//!     use it should call `cert_setup::gmssl_present()` first.
//!   - `gmssl_key` decrypts GmSSL-format `ENCRYPTED PRIVATE KEY` PEM
//!     files (SM3-PBKDF2 + SM4-CBC). Needed for tests that have to
//!     load the *signing/encryption keys* (not just verify Sigs on
//!     certs). Pure-Rust; does not require `gmssl` to be installed.

pub mod cert_setup;
pub mod gmssl_key;
