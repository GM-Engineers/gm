//! `gm_ca::profiles` — TLCP-specific `CertProfile` preset families.
//!
//! This module exists only when the `tlcp-profiles` Cargo feature is
//! enabled (`#[cfg(feature = "tlcp-profiles")]`). Default builds
//! (`cargo build` / `cargo test`) skip it entirely so the base
//! `gm_ca::cert_profile` API surface stays minimal for non-TLCP
//! deployments (e.g. a GM/CA instance that only signs gRPC service
//! certs for gm-tls).
//!
//! Currently exposed submodules:
//!   * [`tlcp`] — TLCP end-entity profile presets (GB/T 38636-2020 §6.4.6).
//!     The two RSA variants (`tlcp_server_rsa`, `tlcp_client_rsa`) are
//!     additionally gated behind the `rsa` feature.

#[cfg(feature = "tlcp-profiles")]
pub mod tlcp;
