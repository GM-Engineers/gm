//! PR-4.8 / P2-1: RFC 5280 §4.2 unknown critical extension rejection.
//!
//! Per RFC 5280 §4.2:
//!   "Certificate-using applications processing certificates that
//!    contain extensions that they do not recognize SHOULD reject the
//!    certificate if the extension is critical."
//!
//! These tests synthesize SM2 self-signed certificates via `openssl req
//! -x509 -extfile` (one with a custom critical extension OID, one with
//! the same extension but non-critical, one with only RFC 5280 standard
//! critical extensions) and verify that gm-crypto's verifier applies
//! the §4.2 rule correctly.

use gm_crypto::x509::verify::{
    KNOWN_X509_EXTENSIONS, check_unknown_critical_extensions, validate_cert_pem,
};
use std::io::Write;
use std::process::Command;
use time::OffsetDateTime;
use x509_parser::prelude::FromDer;

/// Render the temp-file scaffolding for an openssl cert-build
/// invocation. Returns `(dir, cert_path, key_path)`; the caller must
/// keep `dir` alive (via `let _dir = ...`) for the duration.
fn openssl_scratch(prefix: &str) -> (tempdir::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempdir::TempDir::new(prefix).expect("tempdir");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    (dir, cert, key)
}

/// Issue a self-signed cert via openssl with a custom extension. The
/// `extfile_body` is the body of an OpenSSL extfile; use
/// `1.2.3.4=critical,ASN1:NULL` for an unknown critical extension or
/// `1.2.3.4=ASN1:NULL` for the same OID non-critical.
fn issue_cert_with_ext(extfile_body: &str) -> (tempdir::TempDir, Vec<u8>) {
    let (dir, cert, key) = openssl_scratch("pr48-unknown-ext");
    let extfile = dir.path().join("ext.cnf");
    {
        let mut f = std::fs::File::create(&extfile).expect("ext.cnf create");
        f.write_all(extfile_body.as_bytes()).expect("ext.cnf write");
    }
    let out = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:SM2",
            "-keyout",
        ])
        .arg(&key)
        .args(["-out"])
        .arg(&cert)
        .args([
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/CN=pr48-test",
            "-config",
        ])
        .arg(&extfile)
        .args(["-extensions", "v3_req"])
        .output()
        .expect("openssl req failed to spawn");
    assert!(
        out.status.success(),
        "openssl req failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pem = std::fs::read(&cert).expect("read cert.pem");
    (dir, pem)
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::seconds(60)
}

// ============================================================================
// KNOWN_X509_EXTENSIONS — static invariant checks (T4)
// ============================================================================

#[test]
fn pr48_known_extension_set_includes_rfc5280_listed() {
    // The RFC 5280 §4.2 list of "standard" extensions that a CA MUST
    // mark non-critical if not understood by the relying party. We
    // recognize a superset (including 1.2.840.113549.1.x PKIX extensions
    // not in the "always non-critical" list). The smoke test below
    // asserts the §4.2 baseline is present; if a future PR trims the
    // list intentionally, the test must be updated alongside.
    use x509_parser::oid_registry::{
        OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_CERTIFICATE_POLICIES,
        OID_X509_EXT_CRL_DISTRIBUTION_POINTS, OID_X509_EXT_EXTENDED_KEY_USAGE,
        OID_X509_EXT_KEY_USAGE, OID_X509_EXT_NAME_CONSTRAINTS, OID_X509_EXT_SUBJECT_ALT_NAME,
    };
    let must_be_present: &[&x509_parser::oid_registry::Oid<'static>] = &[
        &OID_X509_EXT_BASIC_CONSTRAINTS,
        &OID_X509_EXT_KEY_USAGE,
        &OID_X509_EXT_EXTENDED_KEY_USAGE,
        &OID_X509_EXT_SUBJECT_ALT_NAME,
        &OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
        &OID_X509_EXT_NAME_CONSTRAINTS,
        &OID_X509_EXT_CERTIFICATE_POLICIES,
    ];
    for oid in must_be_present {
        assert!(
            KNOWN_X509_EXTENSIONS.iter().any(|k| *k == **oid),
            "KNOWN_X509_EXTENSIONS must include {} (RFC 5280 §4.2 baseline)",
            oid
        );
    }
}

// ============================================================================
// unknown critical rejection (T1, T5)
// ============================================================================

#[test]
fn pr48_rejects_cert_with_unknown_critical_extension() {
    // `1.2.3.4` is reserved (RFC 5612 registry gap) and recognized by
    // NO relying-party application; marking it critical is the
    // exact attack scenario the new check defends against.
    let (_dir, pem) = issue_cert_with_ext(
        "[v3_req]\nbasicConstraints=critical,CA:FALSE\n\
         1.2.3.4=critical,ASN1:NULL\n",
    );
    let err = validate_cert_pem(&pem, now(), None)
        .expect_err("cert with unknown critical extension must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("unrecognized critical extension"),
        "error must mention unrecognized critical extension; got: {msg}"
    );
}

#[test]
fn pr48_accepts_cert_with_unknown_non_critical_extension() {
    // Same OID, but non-critical. RFC 5280 §4.2 only requires rejection
    // when the unknown extension IS critical; non-critical unknown
    // extensions are tolerated and ignored.
    let (_dir, pem) = issue_cert_with_ext(
        "[v3_req]\nbasicConstraints=critical,CA:FALSE\n\
         1.2.3.4=ASN1:NULL\n",
    );
    validate_cert_pem(&pem, now(), None)
        .expect("cert with unknown non-critical extension must be accepted");
}

#[test]
fn pr48_unknown_critical_extension_message_mentions_oid() {
    let (_dir, pem) = issue_cert_with_ext(
        "[v3_req]\n\
         1.2.3.4=critical,ASN1:NULL\n",
    );
    let err = validate_cert_pem(&pem, now(), None).expect_err("must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("1.2.3.4"),
        "error message must include the offending OID; got: {msg}"
    );
}

// ============================================================================
// cert with all RFC 5280 standard critical extensions (T3) — must pass
// ============================================================================

#[test]
fn pr48_accepts_cert_with_all_rfc5280_critical_extensions() {
    // KU + BC + SAN — all marked critical, all in KNOWN_X509_EXTENSIONS.
    let (_dir, pem) = issue_cert_with_ext(
        "[v3_req]\n\
         basicConstraints=critical,CA:FALSE\n\
         keyUsage=critical,digitalSignature\n\
         subjectAltName=critical,DNS:pr48.example\n\
         extendedKeyUsage=critical,serverAuth\n",
    );
    validate_cert_pem(&pem, now(), Some("pr48.example"))
        .expect("cert with only RFC 5280 standard critical extensions must pass");
}

// ============================================================================
// check_unknown_critical_extensions unit-level (T2 + sanity)
// ============================================================================

#[test]
fn pr48_check_helper_accepts_well_formed_cert() {
    use x509_parser::prelude::X509Certificate;
    let (_dir, pem) = issue_cert_with_ext(
        "[v3_req]\n\
         basicConstraints=critical,CA:FALSE\n",
    );
    let der = pem::parse(&pem).unwrap().into_contents();
    let (_, cert) = X509Certificate::from_der(&der).expect("parse cert");
    check_unknown_critical_extensions(&cert).expect("known critical extension must pass");
}

#[test]
fn pr48_check_helper_rejects_unknown_critical() {
    use x509_parser::prelude::X509Certificate;
    let (_dir, pem) = issue_cert_with_ext(
        "[v3_req]\n\
         1.2.3.4=critical,ASN1:NULL\n",
    );
    let der = pem::parse(&pem).unwrap().into_contents();
    let (_, cert) = X509Certificate::from_der(&der).expect("parse cert");
    let err = check_unknown_critical_extensions(&cert)
        .expect_err("unknown critical extension must be rejected at helper level");
    assert!(format!("{err}").contains("unrecognized critical extension"));
}
