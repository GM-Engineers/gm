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
//! | `gmca_cert_setup`       | (none)          | yes       | In-process SM2 cert generation via `gm-ca` `CaSigner` + `CsrBuilder`. Gated on `tlcp-profiles` feature. **Prefer this for new in-process SM2 tests** — no `gmssl` CLI required. |
//! | `rsa_cert_setup`        | (none)          | yes       | In-process RSA cert generation via `gm-ca` `RsaCaSigner` + custom PKCS#10 CSR builder. Gated on `tlcp-profiles + rsa` features. **Prefer this for new in-process RSA tests** — no `gmssl` CLI required. |
//!
//! ## When to use which helper
//!
//! - **In-process loopback tests** (gm-tlcp ↔ gm-tlcp over
//!   `tokio::io::duplex`):
//!   - SM2 ECDHE/ECC suites → use `gmca_cert_setup`
//!   - RSA suites (E059/E019/E05A/E01C) → use `rsa_cert_setup`
//!   - SM9 IBC/IBSDH suites → use `KgcMasterKey::generate()` + dummy
//!     `vec![0x01; 100]` cert placeholders (the SM9 wire path does
//!     NOT consume the SM2 cert slot, per audit Bug 3 R-4.1-hotfix)
//!
//!   All three are pure-Rust, no external binary, run in CI without
//!   `gmssl` installed.
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

#[cfg(all(feature = "tlcp-profiles", feature = "rsa"))]
pub mod rsa_cert_setup;
