//! Support module shared by integration tests.
//!
//! ## Naming convention
//!
//! Every submodule file name is **prefixed with the binary it depends
//! on** (or `pem_` for pure-Rust PEM helpers):
//!
//! | Module                  | External binary | Pure Rust | Notes |
//! |-------------------------|-----------------|-----------|-------|
//! | `gmssl_cert_setup`      | `gmssl`         | no        | Spawns `gmssl` for `sm2keygen` / `certgen` / `reqgen` / `reqsign`. |
//! | `gmssl_pbes2_decoder`   | (none)          | yes       | Pure-Rust PBES2 envelope walker (SM3-PBKDF2 + SM4-CBC). Exists because GmSSL's custom envelope is incompatible with the standard `pkcs8` crate. |
//! | `pem_helpers`           | (none)          | yes       | Tiny PEM/DER byte manipulation. |
//! | `gmca_cert_setup`       | (none)          | yes       | In-process cert generation via `gm-ca` `CaSigner` + `CsrBuilder`. Gated on `tlcp-profiles` feature. **Prefer this for new in-process tests** — no `gmssl` CLI required. |
//!
//! ## When to use which helper
//!
//! - **In-process loopback tests** (gm-tlcp ↔ gm-tlcp over
//!   `tokio::io::duplex`): use `gmca_cert_setup`. Pure-Rust, no
//!   external binary, runs in CI without `gmssl` installed.
//!
//! - **Wire interop tests** (gm-tlcp ↔ `gmssl tlcp_server`):
//!   use `gmssl_cert_setup` to produce the GmSSL-style cert hierarchy
//!   that `gmssl tlcp_server` expects (cert layout must match GmSSL's
//!   `x509_certs_verify_tlcp` chain walk). These tests are `#[ignore]`-d
//!   by default and run only with `-- --ignored` in CI.

pub mod gmssl_cert_setup;
pub mod gmssl_pbes2_decoder;
pub mod pem_helpers;

#[cfg(feature = "tlcp-profiles")]
pub mod gmca_cert_setup;
