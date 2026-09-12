//! Pure-Rust PEM/DER byte manipulation helpers for integration tests.
//!
//! No external binary (e.g. `gmssl`) is required to use these
//! functions. The module is deliberately tiny so that it can be
//! shared between any test that needs to decode a PEM block without
//! pulling in a heavier dependency.
//!
//! Companion modules:
//!   - `gmssl_cert_setup`      — spawns the `gmssl` CLI.
//!   - `gmssl_pbes2_decoder`   — pure-Rust PBES2 envelope decryption.
//!   - `gmca_cert_setup`       — in-process cert generation via `gm-ca`.

use std::path::Path;

/// Decode the first PEM block with the given label from `path`,
/// returning its base64-decoded DER bytes.
///
/// `label` is the inner part of the PEM banner, e.g. `"CERTIFICATE"`,
/// `"EC PRIVATE KEY"`, `"PRIVATE KEY"`. Whitespace inside the base64
/// payload is stripped. Returns `None` if the file cannot be read, the
/// label does not appear, or the base64 block is malformed.
pub fn read_pem_to_der(path: &Path, label: &str) -> Option<Vec<u8>> {
    let pem = std::fs::read_to_string(path).ok()?;
    let begin = format!("-----BEGIN {}-----", label);
    let end = format!("-----END {}-----", label);
    let start = pem.find(&begin)? + begin.len();
    let stop = pem[start..].find(&end)? + start;
    let b64: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}
