//! GmSSL test certificate generation helper.
//!
//! Generates a complete CA hierarchy usable by both `gmssl tlcp_server`
//! (server side) and `gm-tlcp` (client side):
//!
//! ```text
//!   ca.key / ca.crt                  self-signed CA (keyCertSign + cRLSign)
//!     │
//!     ├── signs ─► server_sign.key / server_sign.crt   (signing cert)
//!     ├── signs ─► server_enc.key  / server_enc.crt    (encryption cert)
//!     └── signs ─► client.key      / client.crt        (client auth cert)
//! ```
//!
//! All certs are SM2 with `-gen_authority_key_id` + `-gen_subject_key_id`
//! so that GmSSL's `tls_cert_chain_verify` can build a chain to the CA.
//!
//! ## Why a single chain file for the server?
//!
//! Per GB/T 38636-2020 and GmSSL's `tlcp_server`, the `-cert` argument
//! is a single PEM file containing both the signing and encryption
//! X.509 certificates (in that order). The `-key` argument is a single
//! PEM file containing both matching private keys (concatenated;
//! `x509_private_key_from_file` decodes one PEM block per call, two
//! calls read two keys).
//!
//! ## Why a real CA?
//!
//! GmSSL 2026-06+ master sets `conn->client_certificate_verify = 1`
//! unconditionally for the ECDHE_*_SM4_* cipher suites. The server
//! then sends a `CertificateRequest` after `ServerKeyExchange` and
//! expects a client certificate chain that chains back to a CA the
//! server trusts. If no CA is configured (`-cacert`) the server's
//! `tls_recv_client_certificate` short-circuits with `-1`, closing
//! the connection. So we MUST:
//!   1. generate a CA,
//!   2. sign server sign/enc certs with the CA,
//!   3. sign a client cert with the same CA,
//!   4. pass `-cacert ca.crt` to `gmssl tlcp_server`.
//!
//! The default distid is the GmSSL standard value `1234567812345678`.
//! Any TLCP client that wishes to verify the server's SKE signature
//! must use the same distid string.
//!
//! **This helper runs only when the `gmssl` binary is available on
//! PATH.** In CI (Docker Linux) and in any environment without
//! `gmssl` installed, it is skipped via `gmssl_present()`.

use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_PASSWORD: &str = "P@ssw0rd";

/// Check whether the `gmssl` CLI is available on the current PATH.
pub fn gmssl_present() -> bool {
    Command::new("gmssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The output of a successful certificate generation.
///
/// All paths are absolute. Pre-extracted DER blobs are provided so
/// callers do not have to re-parse PEM for every test (e.g. when
/// loading the cert into `TlcpAcceptor::with_dual_certs`).
/// `GmsslCerts` exposes both PEM paths and DER-decoded byte buffers
/// of every certificate in the generated chain. The PEM fields
/// (`client_cert`, `client_key`) are retained for symmetry with the
/// server-side fields even when only the DER buffers are consumed by
/// a given test; the redundant fields are marked `#[allow(dead_code)]`
/// to satisfy nightly clippy.
#[allow(dead_code)]
pub struct GmsslCerts {
    /// Combined sign + enc cert PEM (one chain).
    pub chain_crt: PathBuf,
    /// Sign cert PEM path (standalone; used as `-cacert` when gmssl
    /// tlcp_client needs to verify our server cert chain).
    pub sign_cert: PathBuf,
    /// Sign private key path (SM3-PBKDF2 encrypted PKCS#8).
    pub sign_key: PathBuf,
    /// Enc private key path (SM3-PBKDF2 encrypted PKCS#8).
    pub enc_key: PathBuf,
    /// Combined sign + enc private key PEM (sign key first, then enc
    /// key). Required by GmSSL >= 2026-06 master, which calls
    /// `x509_private_key_from_file` twice on a single `-key` file
    /// pointer (once for the sign slot, once for the enc slot).
    pub combined_key: PathBuf,
    /// CA certificate PEM (issuer of all server and client certs).
    pub ca_cert: PathBuf,
    /// Client cert PEM (signed by the CA).
    pub client_cert: PathBuf,
    /// Client encryption cert PEM (signed by the CA, with
    /// keyEncipherment keyUsage). Required by GmSSL master as the
    /// second entry in the client chain for ECDHE TLCP suites.
    pub client_enc_crt: PathBuf,
    /// Client private key PEM (SM3-PBKDF2 encrypted PKCS#8 — the
    /// output of `gmssl sm2keygen -pass ...`). Most callers will
    /// prefer [`client_key_unenc`] which is in standard SEC1 form.
    pub client_key: PathBuf,
    /// Client encryption-key PEM (SM3-PBKDF2 encrypted PKCS#8), used
    /// by the connector's `with_client_certs(.., Some(enc_key_pem), ..)`
    /// API for TLCP ECDHE suites. Decrypted on demand via the test-
    /// only `support::gmssl_key` helper.
    pub client_enc_key: PathBuf,
    /// Client private key in UNENCRYPTED SEC1 PEM form (`BEGIN EC
    /// PRIVATE KEY`). Generated from `client.key` by decoding the
    /// GmSSL PBES2 envelope via `gmssl_key::load_sm2_key_from_gmssl_pem`
    /// and re-serializing. Compatible with `gm-crypto`'s
    /// `Sm2KeyPair::from_private_key_pem`.
    pub client_key_unenc: PathBuf,
    /// DER-encoded sign certificate (decoded from sign.crt PEM).
    pub sign_cert_der: Vec<u8>,
    /// DER-encoded enc certificate (decoded from enc.crt PEM).
    pub enc_cert_der: Vec<u8>,
    /// DER-encoded client certificate (decoded from client.crt PEM).
    pub client_cert_der: Vec<u8>,
    /// 65-byte SEC1 uncompressed SM2 public key (extracted from sign.crt).
    pub sign_pub_65: Vec<u8>,
}

/// Generate the CA hierarchy (CA + server sign/enc + client) under
/// `out_dir`. Uses `gmssl sm2keygen`, `gmssl certgen`, `gmssl reqgen`,
/// `gmssl reqsign`.
pub fn generate_test_certs<P: AsRef<Path>>(out_dir: P) -> Result<GmsslCerts, String> {
    let out_dir = out_dir.as_ref().to_path_buf();
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("mkdir {}: {}", out_dir.display(), e))?;

    // Step 1: CA key + self-signed CA cert.
    let ca_key = out_dir.join("ca.key");
    let ca_crt = out_dir.join("ca.crt");
    run_gmssl(&[
        "sm2keygen",
        "-pass",
        DEFAULT_PASSWORD,
        "-out",
        ca_key.to_str().unwrap(),
    ])?;
    run_gmssl(&[
        "certgen",
        "-days",
        "3650",
        "-key",
        ca_key.to_str().unwrap(),
        "-pass",
        DEFAULT_PASSWORD,
        "-CN",
        "test-ca",
        "-serial_len",
        "4",
        "-ca",
        "-key_usage",
        "keyCertSign",
        "-key_usage",
        "cRLSign",
        "-gen_authority_key_id",
        // GmSSL's `x509_cert_is_signed_by_root_ca_cert` reads the
        // CA's SubjectKeyIdentifier to compare against the entity
        // cert's AuthorityKeyIdentifier (keyIdentifier field). Without
        // SKI, the entity-vs-root anchor compare in
        // `x509_certs_verify_tlcp` returns 0 and aborts the chain
        // walk with `X509_verify_err_trust_anchor`.
        "-gen_subject_key_id",
        "-out",
        ca_crt.to_str().unwrap(),
    ])?;

    // Step 2: server sign key + sign CSR + sign cert signed by CA.
    let sign_key = out_dir.join("sign.key");
    let sign_csr = out_dir.join("sign.csr");
    let sign_crt = out_dir.join("sign.crt");
    run_gmssl(&[
        "sm2keygen",
        "-pass",
        DEFAULT_PASSWORD,
        "-out",
        sign_key.to_str().unwrap(),
    ])?;
    run_gmssl(&[
        "reqgen",
        "-CN",
        "localhost",
        "-key",
        sign_key.to_str().unwrap(),
        "-pass",
        DEFAULT_PASSWORD,
        "-out",
        sign_csr.to_str().unwrap(),
    ])?;
    run_gmssl(&[
        "reqsign",
        "-cacert",
        ca_crt.to_str().unwrap(),
        "-key",
        ca_key.to_str().unwrap(),
        "-pass",
        DEFAULT_PASSWORD,
        "-days",
        "365",
        "-serial_len",
        "16",
        "-gen_authority_key_id",
        "-gen_subject_key_id",
        "-key_usage",
        "digitalSignature",
        "-out",
        sign_crt.to_str().unwrap(),
        "-in",
        sign_csr.to_str().unwrap(),
    ])?;

    // Step 3: server enc key + enc CSR + enc cert signed by CA.
    let enc_key = out_dir.join("enc.key");
    let enc_csr = out_dir.join("enc.csr");
    let enc_crt = out_dir.join("enc.crt");
    run_gmssl(&[
        "sm2keygen",
        "-pass",
        DEFAULT_PASSWORD,
        "-out",
        enc_key.to_str().unwrap(),
    ])?;
    run_gmssl(&[
        "reqgen",
        "-CN",
        "localhost",
        "-key",
        enc_key.to_str().unwrap(),
        "-pass",
        DEFAULT_PASSWORD,
        "-out",
        enc_csr.to_str().unwrap(),
    ])?;
    run_gmssl(&[
        "reqsign",
        "-cacert",
        ca_crt.to_str().unwrap(),
        "-key",
        ca_key.to_str().unwrap(),
        "-pass",
        DEFAULT_PASSWORD,
        "-days",
        "365",
        "-serial_len",
        "16",
        "-gen_authority_key_id",
        "-gen_subject_key_id",
        "-key_usage",
        "keyAgreement",
        "-key_usage",
        "dataEncipherment",
        "-out",
        enc_crt.to_str().unwrap(),
        "-in",
        enc_csr.to_str().unwrap(),
    ])?;

    // Step 4: client sign key + client CSR + client sign cert signed by CA.
    //
    // GmSSL master `x509_certs_verify_tlcp` requires both sign and enc
    // certs to:
    //   1. carry `extendedKeyUsage = clientAuth`
    //      (sign_cert_type == X509_cert_client_auth and
    //       kenc_cert_type == X509_cert_client_key_encipher both
    //       check for `OID_kp_client_auth`).
    //   2. have IDENTICAL subject DN
    //      (`x509_tlcp_cert_pair_entity_match` returns 0 unless both
    //       subject and issuer match).
    //
    // So both client certs use the same subject `localhost-client`
    // and have `-ext_key_usage clientAuth` in addition to the
    // appropriate `keyUsage` bits.
    let client_key = out_dir.join("client.key");
    let client_csr = out_dir.join("client.csr");
    let client_crt = out_dir.join("client.crt");
    run_gmssl(&[
        "sm2keygen",
        "-pass",
        DEFAULT_PASSWORD,
        "-out",
        client_key.to_str().unwrap(),
    ])?;
    run_gmssl(&[
        "reqgen",
        "-CN",
        "localhost-client",
        "-key",
        client_key.to_str().unwrap(),
        "-pass",
        DEFAULT_PASSWORD,
        "-out",
        client_csr.to_str().unwrap(),
    ])?;
    run_gmssl(&[
        "reqsign",
        "-cacert",
        ca_crt.to_str().unwrap(),
        "-key",
        ca_key.to_str().unwrap(),
        "-pass",
        DEFAULT_PASSWORD,
        "-days",
        "365",
        "-serial_len",
        "16",
        "-gen_authority_key_id",
        "-gen_subject_key_id",
        "-key_usage",
        "digitalSignature",
        "-key_usage",
        "keyAgreement",
        "-ext_key_usage",
        "clientAuth",
        "-out",
        client_crt.to_str().unwrap(),
        "-in",
        client_csr.to_str().unwrap(),
    ])?;

    // Step 4.5: client enc key + client enc cert signed by CA.
    //
    // GmSSL's `tls_recv_client_certificate` requires at least 2 certs
    // in the client chain for ECDHE_*_SM4_* suites (index 0 = sign
    // cert, index 1 = enc cert). The enc cert is checked via
    // `tlcp_cert_is_encryption_cert` which demands the
    // `X509_KU_KEY_ENCIPHERMENT` keyUsage bit. Both certs must carry
    // `extendedKeyUsage = clientAuth` and must share the same subject
    // DN (see comment on step 4).
    //
    // TLCP ECDHE mode doesn't actually use the client's enc cert for
    // key exchange (only the server's is used), but GmSSL's
    // `x509_certs_verify_tlcp` still requires the slot to be
    // populated and pass both `tlcp_cert_is_encryption_cert` and
    // `x509_tlcp_cert_pair_entity_match`. We deliberately give it the
    // SAME subject DN as the sign cert so entity match succeeds.
    let client_enc_key = out_dir.join("client.enc.key");
    let client_enc_csr = out_dir.join("client.enc.csr");
    let client_enc_crt = out_dir.join("client.enc.crt");
    run_gmssl(&[
        "sm2keygen",
        "-pass",
        DEFAULT_PASSWORD,
        "-out",
        client_enc_key.to_str().unwrap(),
    ])?;
    run_gmssl(&[
        "reqgen",
        "-CN",
        "localhost-client", // SAME subject as the signing cert above
        "-key",
        client_enc_key.to_str().unwrap(),
        "-pass",
        DEFAULT_PASSWORD,
        "-out",
        client_enc_csr.to_str().unwrap(),
    ])?;
    run_gmssl(&[
        "reqsign",
        "-cacert",
        ca_crt.to_str().unwrap(),
        "-key",
        ca_key.to_str().unwrap(),
        "-pass",
        DEFAULT_PASSWORD,
        "-days",
        "365",
        "-serial_len",
        "16",
        "-gen_authority_key_id",
        "-gen_subject_key_id",
        "-key_usage",
        "keyEncipherment",
        "-key_usage",
        "dataEncipherment",
        "-key_usage",
        "keyAgreement",
        "-ext_key_usage",
        "clientAuth",
        "-out",
        client_enc_crt.to_str().unwrap(),
        "-in",
        client_enc_csr.to_str().unwrap(),
    ])?;

    // Step 5: build the chain file: sign cert first, then enc cert.
    let chain_crt = out_dir.join("chain.crt");
    let mut chain = String::new();
    chain.push_str(
        &std::fs::read_to_string(&sign_crt).map_err(|e| format!("read sign.crt: {}", e))?,
    );
    chain.push_str(&std::fs::read_to_string(&enc_crt).map_err(|e| format!("read enc.crt: {}", e))?);
    std::fs::write(&chain_crt, chain).map_err(|e| format!("write chain.crt: {}", e))?;

    // Step 6: build the combined key file (sign + enc).
    let combined_key = out_dir.join("combined.key");
    let mut combined_key_pem = String::new();
    combined_key_pem.push_str(
        &std::fs::read_to_string(&sign_key).map_err(|e| format!("read sign.key: {}", e))?,
    );
    combined_key_pem
        .push_str(&std::fs::read_to_string(&enc_key).map_err(|e| format!("read enc.key: {}", e))?);
    std::fs::write(&combined_key, combined_key_pem)
        .map_err(|e| format!("write combined.key: {}", e))?;

    // Step 6.5: also produce an UNENCRYPTED SEC1 PEM of the client
    // signing key. The encrypted PEM that `gmssl sm2keygen` emits
    // uses GmSSL's custom PBES2 SM3-PBKDF2 + SM4-CBC envelope, which
    // the standard Rust `pkcs8` crate (and therefore
    // `Sm2KeyPair::from_encrypted_pem` in `gm-crypto`) cannot parse.
    // We decode it via the test-support helper
    // `load_sm2_key_from_gmssl_pem` (a pure-Rust walker that knows
    // GmSSL's specific PBES2 layout) and re-serialize as
    // `BEGIN EC PRIVATE KEY` SEC1, which `gm-crypto` understands
    // through `Sm2KeyPair::from_private_key_pem`.
    let client_key_unenc = out_dir.join("client.key.unenc.pem");
    let client_kp =
        crate::support::gmssl_key::load_sm2_key_from_gmssl_pem(&client_key, DEFAULT_PASSWORD)
            .map_err(|e| format!("decrypt client.key: {}", e))?;
    std::fs::write(
        &client_key_unenc,
        client_kp
            .private_key_pem()
            .map_err(|e| format!("client key sec1: {}", e))?,
    )
    .map_err(|e| format!("write client.key.unenc.pem: {}", e))?;

    // Pre-decode certs to DER for callers.
    let sign_cert_der = read_pem_to_der(&sign_crt, "CERTIFICATE")
        .ok_or_else(|| "could not decode sign.crt PEM".to_string())?;
    let enc_cert_der = read_pem_to_der(&enc_crt, "CERTIFICATE")
        .ok_or_else(|| "could not decode enc.crt PEM".to_string())?;
    let client_cert_der = read_pem_to_der(&client_crt, "CERTIFICATE")
        .ok_or_else(|| "could not decode client.crt PEM".to_string())?;

    let sign_pub_65 = extract_uncompressed_pubkey_from_der(&sign_cert_der)
        .ok_or_else(|| "could not locate SubjectPublicKeyInfo BIT STRING".to_string())?;

    Ok(GmsslCerts {
        chain_crt,
        sign_cert: sign_crt,
        sign_key,
        enc_key,
        combined_key,
        ca_cert: ca_crt,
        client_cert: client_crt,
        client_enc_crt,
        client_key,
        client_enc_key,
        client_key_unenc,
        sign_cert_der,
        enc_cert_der,
        client_cert_der,
        sign_pub_65,
    })
}

/// Run `gmssl <args>` and surface a clean error on failure.
fn run_gmssl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("gmssl")
        .args(args)
        .output()
        .map_err(|e| format!("failed to spawn gmssl: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "gmssl {:?} failed: stderr=\n{}stdout=\n{}",
            args,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        ));
    }
    Ok(())
}

/// Decode the first PEM block with the given label from `path`,
/// returning its base64-decoded DER bytes.
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

/// Pull the uncompressed SM2 public key (65 bytes: `04 || x || y`) out
/// of an X.509 certificate's SubjectPublicKeyInfo BIT STRING.
fn extract_uncompressed_pubkey_from_der(cert_der: &[u8]) -> Option<Vec<u8>> {
    // The SubjectPublicKeyInfo BIT STRING starts with `03 <len> 00 <key-bytes>`.
    // Search for the SM2 OID (1.2.840.10045.2.1) followed by SM2 curve OID
    // (1.2.156.10197.1.301), then the BIT STRING wrapping the public key.
    let sm2_oid_seq: &[u8] = &[
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
        0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, // SM2 curve
    ];
    let pos = cert_der
        .windows(sm2_oid_seq.len())
        .position(|w| w == sm2_oid_seq)?;
    // After the curve OID, BIT STRING starts with `03 <len> 00 04 <x> <y>` (65 bytes).
    let after_oid = pos + sm2_oid_seq.len();
    // Scan forward for the first `03 <len>` tag with a 65-byte payload.
    for i in after_oid..cert_der.len().saturating_sub(2) {
        if cert_der[i] == 0x03 && cert_der[i + 1] == 0x42 && cert_der[i + 2] == 0x00 {
            return Some(cert_der[i + 3..i + 3 + 65].to_vec());
        }
    }
    let _ = base64::engine::general_purpose::STANDARD; // keep import alive
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_uncompressed_pubkey_works_on_gmssl_cert() {
        if !gmssl_present() {
            eprintln!("gmssl not installed — skipping");
            return;
        }
        let tmp = std::env::temp_dir().join("gm-tlcp-test-cert-extract");
        let _ = std::fs::remove_dir_all(&tmp);
        let certs = generate_test_certs(&tmp).expect("generate certs");
        assert_eq!(certs.sign_pub_65.len(), 65);
        assert_eq!(certs.sign_pub_65[0], 0x04); // uncompressed point indicator
    }
}
