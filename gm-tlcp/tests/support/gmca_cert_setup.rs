//! In-process SM2 certificate hierarchy generation for gm-tlcp tests.
//!
//! Generates a CA + server sign/enc + client sign/enc hierarchy **in
//! pure Rust** using [`gm_ca::cert::CaSigner`] +
//! [`gm_crypto::x509::CsrBuilder`]. **No external binary (e.g. `gmssl`)
//! is required**, so this helper is the right choice for any in-process
//! loopback test (`gm-tlcp ↔ gm-tlcp` over `tokio::io::duplex`).
//!
//! Compare with the sibling [`gmssl_cert_setup`] module which spawns
//! the `gmssl` CLI; that helper is needed only by the wire-interop
//! tests (`gm-tlcp ↔ gmssl tlcp_server` over real TCP) because GmSSL's
//! `x509_certs_verify_tlcp` chain walk requires a GmSSL-specific cert
//! layout that `gm-ca` does not currently emit.
//!
//! ## Why no on-disk artifacts?
//!
//! All keys + certs are generated in memory and returned as DER bytes
//! / SEC1 PEM strings. The `gm-tlcp` `TlcpAcceptor` and `TlcpConnector`
//! APIs consume those bytes directly — they never need to point at a
//! file path. Skipping the disk step also avoids stale temp-dir
//! artifacts and the need for `.gitignore` cleanup.
//!
//! ## Feature gate
//!
//! This module is gated on `tlcp-profiles` (a gm-tlcp dev-dep-only
//! feature added in gm-tlcp 0.6.5 / R-12) because the TLCP cert
//! presets it uses (`tlcp_server_sign_ecc`, etc.) live behind the
//! same feature flag in `gm-ca`.

#![cfg(feature = "tlcp-profiles")]

use gm_ca::cert::CaSigner;
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;

/// The output of a successful in-process cert generation.
///
/// All keys are SM2, all certs are signed by the same self-signed
/// root CA. The private keys are returned as **unencrypted SEC1 PEM**
/// (`BEGIN EC PRIVATE KEY`), which is the format the gm-tlcp
/// `TlcpAcceptor::with_dual_certs` and `TlcpConnector::with_client_certs`
/// APIs accept via `Sm2KeyPair::from_private_key_pem`.
#[allow(dead_code)]
#[derive(Debug)]
pub struct GmcaCerts {
    /// DER-encoded root CA cert (for chain walk in
    /// `with_client_certs` and for ad-hoc introspection).
    pub ca_cert_der: Vec<u8>,
    /// DER-encoded server signing cert (consumed by
    /// `TlcpAcceptor::with_dual_certs`).
    pub server_sign_cert_der: Vec<u8>,
    /// DER-encoded server encryption cert (consumed by
    /// `TlcpAcceptor::with_dual_certs`).
    pub server_enc_cert_der: Vec<u8>,
    /// Server signing private key in SEC1 PEM form.
    pub server_sign_key_pem: String,
    /// Server encryption private key in SEC1 PEM form.
    pub server_enc_key_pem: String,
    /// 65-byte SEC1 uncompressed SM2 pubkey extracted from the
    /// server signing cert (consumed by `TlcpConnector::with_server_sign_key`).
    pub server_sign_pub_65: Vec<u8>,
    /// DER-encoded client signing cert (consumed by
    /// `TlcpConnector::with_client_certs`).
    pub client_sign_cert_der: Vec<u8>,
    /// DER-encoded client encryption cert (consumed by
    /// `TlcpConnector::with_client_certs`).
    pub client_enc_cert_der: Vec<u8>,
    /// Client signing private key in SEC1 PEM form.
    pub client_sign_key_pem: String,
    /// Client encryption private key in SEC1 PEM form.
    pub client_enc_key_pem: String,
}

/// Generate the cert hierarchy described in [`GmcaCerts`]'s doc
/// comment, in memory. The root CA is generated with subject
/// `gm-tlcp test CA (gmca)` and a 10-year validity; leaf certs are
/// signed with 365-day validity and the TLCP profiles
/// (`tlcp_server_sign_ecc`, `tlcp_server_enc_ecc`, etc.).
///
/// `out_dir` is currently unused; it is kept as a parameter for API
/// symmetry with [`crate::support::gmssl_cert_setup::generate_test_certs`]
/// so call sites can be swapped in the future without changing their
/// argument list.
#[allow(dead_code)] // not used by gmssl_interop target (which uses GmsslCerts instead)
pub fn generate_gmca_test_certs(_out_dir: &std::path::Path) -> Result<GmcaCerts, String> {
    // ---- Root CA (self-signed SM2) ----
    let ca_key = Sm2KeyPair::generate().map_err(|e| format!("CA keygen: {}", e))?;
    let ca_signer = CaSigner::new(ca_key, "gm-tlcp test CA (gmca)");
    let ca_pem = ca_signer
        .self_sign_ca(3650, &gm_ca::cert_profile::CertProfile::root_ca())
        .map_err(|e| format!("CA self_sign_ca: {}", e))?;
    let ca_cert_der = pem::parse(ca_pem.as_bytes())
        .map_err(|e| format!("CA PEM parse: {}", e))?
        .into_contents();

    // ---- Server signing key + CSR + cert ----
    let server_sign_key =
        Sm2KeyPair::generate().map_err(|e| format!("server sign keygen: {}", e))?;
    let server_sign_pub_65 = server_sign_key.public_key_bytes_uncompressed();
    let server_sign_csr_pem = CsrBuilder::new_sm2("server-sign.local", &server_sign_pub_65)
        .map_err(|e| format!("CsrBuilder server_sign: {}", e))?
        .build_pem(&server_sign_key)
        .map_err(|e| format!("server_sign CSR build_pem: {}", e))?;
    let (_, server_sign_cert_pem) = ca_signer
        .sign_csr_with_profile(
            server_sign_csr_pem.as_bytes(),
            365,
            &gm_ca::profiles::tlcp::tlcp_server_sign_ecc(),
        )
        .map_err(|e| format!("sign_csr_with_profile server_sign: {}", e))?;
    let server_sign_cert_der = pem::parse(server_sign_cert_pem.as_bytes())
        .map_err(|e| format!("PEM parse server_sign.crt: {}", e))?
        .into_contents();
    let server_sign_key_pem = server_sign_key
        .private_key_pem()
        .map_err(|e| format!("server_sign SEC1 PEM: {}", e))?;

    // ---- Server encryption key + CSR + cert ----
    let server_enc_key = Sm2KeyPair::generate().map_err(|e| format!("server enc keygen: {}", e))?;
    let server_enc_pub_65 = server_enc_key.public_key_bytes_uncompressed();
    let server_enc_csr_pem = CsrBuilder::new_sm2("server-enc.local", &server_enc_pub_65)
        .map_err(|e| format!("CsrBuilder server_enc: {}", e))?
        .build_pem(&server_enc_key)
        .map_err(|e| format!("server_enc CSR build_pem: {}", e))?;
    let (_, server_enc_cert_pem) = ca_signer
        .sign_csr_with_profile(
            server_enc_csr_pem.as_bytes(),
            365,
            &gm_ca::profiles::tlcp::tlcp_server_enc_ecc(),
        )
        .map_err(|e| format!("sign_csr_with_profile server_enc: {}", e))?;
    let server_enc_cert_der = pem::parse(server_enc_cert_pem.as_bytes())
        .map_err(|e| format!("PEM parse server_enc.crt: {}", e))?
        .into_contents();
    let server_enc_key_pem = server_enc_key
        .private_key_pem()
        .map_err(|e| format!("server_enc SEC1 PEM: {}", e))?;

    // ---- Client signing key + CSR + cert ----
    let client_sign_key =
        Sm2KeyPair::generate().map_err(|e| format!("client sign keygen: {}", e))?;
    let client_sign_pub_65 = client_sign_key.public_key_bytes_uncompressed();
    let client_sign_csr_pem = CsrBuilder::new_sm2("client-sign.local", &client_sign_pub_65)
        .map_err(|e| format!("CsrBuilder client_sign: {}", e))?
        .build_pem(&client_sign_key)
        .map_err(|e| format!("client_sign CSR build_pem: {}", e))?;
    let (_, client_sign_cert_pem) = ca_signer
        .sign_csr_with_profile(
            client_sign_csr_pem.as_bytes(),
            365,
            &gm_ca::profiles::tlcp::tlcp_client_sign_ecc(),
        )
        .map_err(|e| format!("sign_csr_with_profile client_sign: {}", e))?;
    let client_sign_cert_der = pem::parse(client_sign_cert_pem.as_bytes())
        .map_err(|e| format!("PEM parse client_sign.crt: {}", e))?
        .into_contents();
    let client_sign_key_pem = client_sign_key
        .private_key_pem()
        .map_err(|e| format!("client_sign SEC1 PEM: {}", e))?;

    // ---- Client encryption key + CSR + cert ----
    let client_enc_key = Sm2KeyPair::generate().map_err(|e| format!("client enc keygen: {}", e))?;
    let client_enc_pub_65 = client_enc_key.public_key_bytes_uncompressed();
    let client_enc_csr_pem = CsrBuilder::new_sm2("client-enc.local", &client_enc_pub_65)
        .map_err(|e| format!("CsrBuilder client_enc: {}", e))?
        .build_pem(&client_enc_key)
        .map_err(|e| format!("client_enc CSR build_pem: {}", e))?;
    let (_, client_enc_cert_pem) = ca_signer
        .sign_csr_with_profile(
            client_enc_csr_pem.as_bytes(),
            365,
            &gm_ca::profiles::tlcp::tlcp_client_enc_ecc(),
        )
        .map_err(|e| format!("sign_csr_with_profile client_enc: {}", e))?;
    let client_enc_cert_der = pem::parse(client_enc_cert_pem.as_bytes())
        .map_err(|e| format!("PEM parse client_enc.crt: {}", e))?
        .into_contents();
    let client_enc_key_pem = client_enc_key
        .private_key_pem()
        .map_err(|e| format!("client_enc SEC1 PEM: {}", e))?;

    // Sanity: re-derive the server signing pubkey from the cert DER to
    // make sure the SEC1 bytes we're returning match the cert chain.
    // (Defensive — the `server_sign_pub_65` field is what
    // `with_server_sign_key` consumes for SKE signature verification,
    // so a mismatch here would silently break the handshake.)
    let verified_pub = gm_crypto::x509::extract_sm2_pubkey_from_der(&server_sign_cert_der)
        .map_err(|e| {
            format!(
                "re-extract SM2 pubkey from server_sign cert failed: {} (DER len={})",
                e,
                server_sign_cert_der.len()
            )
        })?;
    if verified_pub != server_sign_pub_65 {
        return Err(format!(
            "server_sign pubkey derivation mismatch: keypair pub={:02x?}... cert pub={:02x?}...",
            &server_sign_pub_65[..8.min(server_sign_pub_65.len())],
            &verified_pub[..8.min(verified_pub.len())]
        ));
    }

    Ok(GmcaCerts {
        ca_cert_der,
        server_sign_cert_der,
        server_enc_cert_der,
        server_sign_key_pem,
        server_enc_key_pem,
        server_sign_pub_65,
        client_sign_cert_der,
        client_enc_cert_der,
        client_sign_key_pem,
        client_enc_key_pem,
    })
}

/// Default TLCP distid (must match what gm-ca-emitted certs use when
/// the in-process client verifier computes the SM2 KAP Z-values).
///
/// Matches `GMSSL_DEFAULT_DISTID` in `gmssl_interop.rs` and the
/// default in `tests/gmssl_interop.rs`; gm-crypto's `Sm2KeyPair`
/// defaults to this distid too.
#[allow(dead_code)] // not used by gmssl_interop target
pub const DEFAULT_DISTID: &str = "1234567812345678";
