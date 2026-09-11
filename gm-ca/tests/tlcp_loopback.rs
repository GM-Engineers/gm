//! Phase 6a (Phase 4g close-out): in-process loopback handshakes that prove
//! `RsaCaSigner` (gm-ca) produces X.509 certs wire-compatible with gm-tlcp's
//! 4 RSA cipher suites — E019 / E01C / E059 / E05A.
//!
//! ## Why this file exists
//!
//! gm-tlcp's own `tests/gm_tlcp_loopback.rs` covers the 4 RSA suites but uses
//! a **dummy 100-byte DER blob** as the cert (`vec![0..100u8]`). Those tests
//! exercise the handshake logic (PMS derivation, master_secret, record layer)
//! but do NOT validate that real X.509 certs round-trip through the pipeline.
//!
//! `RsaCaSigner::sign_csr_with_profile` produces real, well-formed X.509 RSA
//! certs (rsaEncryption SPKI + sha256WithRSAEncryption signature). The Phase 4
//! docs explicitly call out "Required for the TLCP RSA suites" — this file
//! is the regression gate proving end-to-end interop.
//!
//! ## Design notes
//!
//! * All 4 tests use `with_rsa_certs_single` (R-7) for GB/T 38636-2020
//!   §6.4.5.5-conformant single-Certificate emission.
//! * The connector takes only `server_rsa_pub` for SKE verify + CKE encrypt.
//!   Per `gm_tlcp_loopback.rs` line 178-182, the cert bytes are opaque to
//!   the connector — it does not parse the SPKI.
//! * No GmSSL dependency. The CSR is built inline with the same pattern as
//!   `rsa_signer::tests::build_test_rsa_csr_pem` (Phase 4's helper).
//! * 2048-bit RSA modulus (matches gm-tlcp's own RSA loopback tests).
//!
//! ## Wall-clock
//!
//! Each test ≈ 1.5s (RSA keygen + certify + handshake + 1 record round-trip).
//! All 4 tests run in CI under `--features rsa`; default builds skip this file
//! via `#[cfg(feature = "rsa")]`.

#![cfg(feature = "rsa")]

use gm_ca::cert_profile::CertProfile;
use gm_ca::rsa_signer::RsaCaSigner;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::PrehashSigner;
use rsa::traits::PublicKeyParts;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256 as RawSha256;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// RSA-2048 keypair generated via the `rsa` crate (gm-ca's `RsaCaSigner`
/// doesn't manage the leaf keypair directly — the caller provides the
/// leaf's RSA private key, just like with `Sm2KeyPair`).
fn make_leaf_rsa_keypair() -> RsaPrivateKey {
    let mut rng = rsa::rand_core::OsRng;
    RsaPrivateKey::new(&mut rng, 2048).expect("RSA-2048 keygen")
}

/// SHA-1(SPKI BIT STRING value)[:20] — RFC 7093 §2 Method 1 SKI/AKI for RSA.
///
/// We need this because RsaCaSigner computes the SKI hash internally,
/// but when validating the leaf cert on the connector side we want to
/// confirm the wire format is what the connector expects. Currently
/// unused — kept for future test expansion (e.g. introspecting the
/// issued cert's AKI on the wire).
#[allow(dead_code)]
fn sha1_key_id(pubkey_bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(pubkey_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

/// SHA-256(data) — used to hash the CSR's CertificationRequestInfo DER
/// before signing it with the leaf's RSA key.
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = RawSha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Build a minimal PKCS#10 RSA CSR (PEM-encoded) signed with
/// sha256WithRSAEncryption. Mirrors `rsa_signer::tests::build_test_rsa_csr_pem`
/// — duplicated here because that helper lives inside the `#[cfg(test)]`
/// block of `rsa_signer.rs` and isn't reachable from integration tests.
fn build_test_rsa_csr_pem(subject_cn: &str, key_pair: &RsaPrivateKey) -> String {
    use gm_der::{der_integer_positive, der_sequence, der_set, der_utf8_string, encode_oid};

    // CN OID: 2.5.4.3 = 55 04 03
    const CN_OID: &[u8] = &[0x55, 0x04, 0x03];
    // rsaEncryption OID: 1.2.840.113549.1.1.1 = 2A 86 48 86 F7 0D 01 01 01
    const RSA_ENCRYPTION_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    // sha256WithRSAEncryption OID: 1.2.840.113549.1.1.11 = 2A 86 48 86 F7 0D 01 01 0B
    const SHA256_RSA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

    // Name: SEQUENCE { SET { SEQUENCE { OID(cn), UTF8String(cn) } } }
    let cn_attr =
        der_sequence(&[encode_oid(CN_OID), der_utf8_string(subject_cn.as_bytes())].concat());
    let cn_set = der_set(&[cn_attr]);
    let subject = der_sequence(&[cn_set].concat());

    // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING(PKCS#1 RSAPublicKey) }
    let pkcs1_pub = {
        let pubkey = rsa::RsaPublicKey::new(key_pair.n().clone(), key_pair.e().clone())
            .expect("RSA pubkey extraction");
        pubkey
            .to_pkcs1_der()
            .expect("PKCS#1 RSAPublicKey DER encoding")
            .as_bytes()
            .to_vec()
    };
    let spki_alg = der_sequence(&[encode_oid(RSA_ENCRYPTION_OID), vec![0x05, 0x00]].concat());
    let spki_key = gm_der::der_bit_string(&pkcs1_pub);
    let spki = der_sequence(&[spki_alg, spki_key].concat());

    let version = der_integer_positive(&[0x00]); // v1
    let attributes: Vec<u8> = vec![0xA0, 0x00]; // [0] IMPLICIT empty attributes

    // CertificationRequestInfo = SEQUENCE { version, subject, SPKI, [0] attributes }
    let cri = der_sequence(&[version, subject, spki, attributes].concat());

    // Sign CRI with sha256WithRSAEncryption.
    let prehash = sha256(&cri);
    let signing_key = SigningKey::<Sha256>::new(key_pair.clone());
    let sig = signing_key.sign_prehash(&prehash).expect("CSR sign");

    // Full CSR = SEQUENCE { CRI, sig_alg_alg_id, BIT STRING(sig) }
    let sig_alg = der_sequence(&[encode_oid(SHA256_RSA_OID), vec![0x05, 0x00]].concat());
    let sig_bits = gm_der::der_bit_string(&sig.to_vec());
    let csr = der_sequence(&[cri, sig_alg, sig_bits].concat());

    let pem_obj = pem::Pem::new("CERTIFICATE REQUEST", csr);
    pem::encode(&pem_obj)
}

/// Convert a `rsa::RsaPrivateKey` to gm-tlcp's `RsaKeyPair` by serializing
/// through PKCS#8 PEM. We use PKCS#8 (not PKCS#1) because that's the modern
/// format produced by `openssl genpkey` and consumed by gm-tlcp's
/// `RsaKeyPair::from_pkcs8_pem`.
fn to_gm_tlcp_rsa_kp(leaf_kp: &RsaPrivateKey) -> gm_tlcp::tlcp::rsa_helpers::RsaKeyPair {
    let pem_z = leaf_kp
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("PKCS#8 PEM encode");
    // `Zeroizing<String>` derefs to `&str`.
    gm_tlcp::tlcp::rsa_helpers::RsaKeyPair::from_pkcs8_pem(pem_z.as_str())
        .expect("gm-tlcp RsaKeyPair::from_pkcs8_pem")
}

/// Common harness: build a real RSA cert chain via RsaCaSigner, configure
/// both ends, run the handshake over `tokio::io::duplex`, and verify a
/// single app-data record round-trip succeeds.
///
/// Returns the leaf RSA private keypair so callers can perform any
/// post-handshake sanity checks (currently none).
async fn run_rsaca_loopback(suite: [u8; 2]) -> RsaPrivateKey {
    use gm_tlcp::tlcp::{TlcpAcceptor, TlcpConnector};

    // 1. RsaCaSigner — root CA + leaf cert issuance (Phase 4 path).
    let ca_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("CA keygen");
    let ca_signer = RsaCaSigner::new(ca_key, "GM RSA Test CA");
    let _root_pem = ca_signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("RsaCaSigner::self_sign_ca");

    // 2. Leaf RSA keypair + CSR + cert.
    let leaf_kp = make_leaf_rsa_keypair();
    let csr_pem = build_test_rsa_csr_pem("tlcp-rsa-leaf.test", &leaf_kp);
    let (_serial_hex, leaf_pem) = ca_signer
        .sign_csr_with_profile(csr_pem.as_bytes(), 365, &CertProfile::default())
        .expect("RsaCaSigner::sign_csr_with_profile");

    // 3. Parse the issued leaf cert PEM → DER for TlcpAcceptor.
    let leaf_pem_obj = pem::parse(leaf_pem.as_bytes()).expect("PEM parse");
    assert_eq!(
        leaf_pem_obj.tag(),
        "CERTIFICATE",
        "leaf PEM must be a CERTIFICATE"
    );
    let leaf_cert_der = leaf_pem_obj.contents().to_vec();

    // 4. Bridge the rsa-crate keypair → gm-tlcp's RsaKeyPair (PKCS#8 PEM).
    let gm_tlcp_kp = to_gm_tlcp_rsa_kp(&leaf_kp);
    let server_rsa_pub = gm_tlcp_kp.to_public_key().expect("server RSA pub");

    // 5. Configure both sides with `with_rsa_certs_single` (R-7, GB/T 38636
    //    §6.4.5.5-conformant single-Certificate emission).
    let acceptor = TlcpAcceptor::new().with_rsa_certs_single(gm_tlcp_kp, leaf_cert_der);

    let connector = TlcpConnector::new()
        .with_cipher_suites(vec![suite])
        .with_rsa_certs_single(server_rsa_pub);

    // 6. tokio::io::duplex (16 KiB buffer is plenty for the 1-record
    //    round-trip — same as gm-tlcp's own RSA loopback tests).
    let (client_io, server_io) = tokio::io::duplex(16384);

    // 7. Spawn server.
    let server_handle = tokio::spawn(async move {
        acceptor
            .accept_with_certs(server_io)
            .await
            .expect("server: RsaCaSigner-issued cert must round-trip through RSA handshake")
    });

    // 8. Spawn client.
    let client_handle = tokio::spawn(async move {
        connector
            .connect_with_certs(client_io)
            .await
            .expect("client: RsaCaSigner-issued cert must round-trip through RSA handshake")
    });

    // 9. Wait for handshake (15s budget matches gm-tlcp's RSA loopback).
    let mut server_stream = tokio::time::timeout(Duration::from_secs(15), server_handle)
        .await
        .expect("server task timed out (>15s)")
        .expect("server task panicked");

    let mut client_stream = tokio::time::timeout(Duration::from_secs(15), client_handle)
        .await
        .expect("client task timed out (>15s)")
        .expect("client task panicked");

    // 10. App-data round-trip (proves master_secret derivation round-trips).
    let msg: &[u8] = b"hello-rsa-loopback";
    client_stream.write_all(msg).await.expect("client write");
    client_stream.flush().await.expect("client flush");

    let mut buf = vec![0u8; 256];
    let n = server_stream.read(&mut buf).await.expect("server read");
    assert_eq!(
        &buf[..n],
        msg,
        "server received wrong bytes -- RsaCaSigner cert + gm-tlcp handshake PMS diverged"
    );

    // Server -> Client round-trip.
    server_stream.write_all(msg).await.expect("server write");
    server_stream.flush().await.expect("server flush");
    let n = client_stream.read(&mut buf).await.expect("client read");
    assert_eq!(
        &buf[..n],
        msg,
        "client received wrong bytes -- RsaCaSigner cert + gm-tlcp handshake PMS diverged"
    );

    // 11. Bonus: the leaf cert we issued IS the same one TlcpAcceptor sent —
    //     x509-parser round-trip on the issued cert proves RsaCaSigner
    //     output is well-formed end-to-end. We re-parse leaf_pem (not the
    //     wire bytes) for clarity.
    use x509_parser::prelude::FromDer;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(leaf_pem_obj.contents())
        .expect("x509-parser must accept RsaCaSigner output");
    assert_eq!(
        parsed.public_key().algorithm.algorithm.as_bytes(),
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
        "SPKI OID must be rsaEncryption (1.2.840.113549.1.1.1)"
    );
    assert_eq!(
        parsed.signature_algorithm.algorithm.as_bytes(),
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
        "outer sig OID must be sha256WithRSAEncryption (1.2.840.113549.1.1.11)"
    );

    leaf_kp
}

// ---------------------------------------------------------------------------
// The 4 RSA cipher suites (GB/T 38636-2020 §6.4.5.2.1 表 2)
// ---------------------------------------------------------------------------
//
// Per gm-tlcp CHANGELOG 0.6.0 "RSA suite set" and the conftest notes in
// `tests/gm_tlcp_loopback.rs`:
//   * The PRF discriminator (SM3 vs SHA-256 for `_SHA256` suites) is a
//     no-op as of gm-tlcp 0.6.0 — all 12 suites use SM3-PRF (matching
//     GmSSL master + openHiTLS convention). We still cover E05A / E01C
//     to prove suite-id dispatch works.

/// E059 — `TLS_RSA_WITH_SM4_GCM_SM3` (GCM, SM3-PRF).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rsaca_signer_e059_gcm_sm3_loopback() {
    let _leaf_kp = run_rsaca_loopback([0xE0, 0x59]).await;
}

/// E019 — `TLS_RSA_WITH_SM4_CBC_SM3` (CBC, SM3-PRF).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rsaca_signer_e019_cbc_sm3_loopback() {
    let _leaf_kp = run_rsaca_loopback([0xE0, 0x19]).await;
}

/// E05A — `TLS_RSA_WITH_SM4_GCM_SHA256` (GCM, SHA256-PRF per spec §6.3,
/// SM3-PRF per gm-tlcp 0.6.0+ convention — see file-level docs).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rsaca_signer_e05a_gcm_sha256_loopback() {
    let _leaf_kp = run_rsaca_loopback([0xE0, 0x5A]).await;
}

/// E01C — `TLS_RSA_WITH_SM4_CBC_SHA256` (CBC, SHA256-PRF per spec,
/// SM3-PRF per gm-tlcp 0.6.0+ convention).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rsaca_signer_e01c_cbc_sha256_loopback() {
    let _leaf_kp = run_rsaca_loopback([0xE0, 0x1C]).await;
}

// ---------------------------------------------------------------------------
// Bonus: cert-chain introspection
// ---------------------------------------------------------------------------
//
// Sanity-checks that the leaf cert issued by RsaCaSigner carries the
// SubjectPublicKeyInfo that `with_rsa_certs_single` will eventually hand to
// gm-tlcp's RSA signature-verifier on the connector side. We don't *use*
// the SPKI on the connector (per `gm_tlcp_loopback.rs` line 178-182 the
// pubkey comes via `with_rsa_certs(server_rsa_pub)`), but the cert's
// algorithm OID must be rsaEncryption — if it weren't, an openssl/gmssl
// verifier would reject the chain at the X.509 layer before the SKE
// signature check.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rsaca_signer_issued_leaf_cert_has_rsa_spki_and_sha256_sig() {
    let ca_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("CA keygen");
    let ca_signer = RsaCaSigner::new(ca_key, "GM RSA Test CA");
    ca_signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("self_sign_ca");

    let leaf_kp = make_leaf_rsa_keypair();
    let csr_pem = build_test_rsa_csr_pem("introspect.test", &leaf_kp);
    let (_serial, leaf_pem) = ca_signer
        .sign_csr_with_profile(csr_pem.as_bytes(), 365, &CertProfile::default())
        .expect("sign_csr_with_profile");

    let pem_obj = pem::parse(leaf_pem.as_bytes()).expect("PEM parse");
    use x509_parser::prelude::FromDer;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(pem_obj.contents())
        .expect("x509-parser");

    // rsaEncryption
    assert_eq!(
        parsed.public_key().algorithm.algorithm.as_bytes(),
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
        "SPKI OID must be rsaEncryption"
    );

    // sha256WithRSAEncryption
    assert_eq!(
        parsed.signature_algorithm.algorithm.as_bytes(),
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
        "outer signature OID must be sha256WithRSAEncryption"
    );

    // The self-validating crypto path is covered by
    // `rsa_signer::tests::root_ca_self_signed_has_sha256_rsa_sig_and_rsa_spki`
    // (Phase 4); this bonus test focuses on the wire-format OIDs that an
    // openssl/gmssl verifier reads from the cert at the X.509 layer before
    // the SKE signature check.
}
