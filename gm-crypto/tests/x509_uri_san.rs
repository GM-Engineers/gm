//! PR-2.3 (P0-6): URI SAN matching — SPIFFE ID verification.
//!
//! Tests the new `validate_uri_only` entry point + `SpiffeId::parse` helper.
//! Certs used in these tests are issued via `gm_ca::cert::CaSigner`
//! (which already supports the `GeneralName::UniformResourceIdentifier`
//! SAN type — `gm-ca/src/cert_profile.rs:256`) so we exercise the
//! real wire format end-to-end.
//!
//! References:
//! - SPIFFE-ID §2.1 — `<scheme>://<trust-domain>/<workload-path>`
//!   <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md>
//! - RFC 5280 §4.2.1.6 — `uniformResourceIdentifier` IA5String SAN
//!
//! Strategy: cover both the helper (`SpiffeId::parse` happy / unhappy
//! paths) and the integration (`validate_uri_only` matching policy
//! semantics). No live CRL, no chain walk — these tests are focused
//! on the URI-matching surface.

use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::x509::CsrBuilder;
use gm_crypto::x509::verify::{SpiffeId, SpiffePathPolicy, UriMatchPolicy, validate_uri_only};
use x509_parser::prelude::FromDer;

// Use the real current time as `now`. The certs issued by
// `issue_uri_san_cert` are valid from issuance (gm-ca sets
// `not_before = now_utc - skew_tolerance`) to issuance + 365
// days. Picking `now_utc() + 1 minute` guarantees we land
// strictly inside the validity window regardless of CI clock
// drift; the absolute value is irrelevant to the URI-matching
// tests, which care only about the *comparison*, not the date.
fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::seconds(60)
}

// ============================================================================
// SpiffeId::parse — structural validation
// ============================================================================

#[test]
fn pr23_spiffe_id_parse_accepts_well_formed() {
    let id = SpiffeId::parse("spiffe://example.org/ns/foo/sa/bar").expect("well-formed SPIFFE ID");
    assert_eq!(id.trust_domain(), "example.org");
    assert_eq!(id.path(), "/ns/foo/sa/bar");
}

#[test]
fn pr23_spiffe_id_parse_accepts_minimal() {
    // SPIFFE-ID §2.1: minimal valid ID is `spiffe://<td>/<one-label-path>`
    let id = SpiffeId::parse("spiffe://example.org/x").expect("minimal SPIFFE ID");
    assert_eq!(id.trust_domain(), "example.org");
    assert_eq!(id.path(), "/x");
}

#[test]
fn pr23_spiffe_id_parse_rejects_bad_scheme() {
    let err = SpiffeId::parse("https://example.org/x").expect_err("https scheme must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("SPIFFE") && msg.contains("scheme"),
        "expected scheme-rejection diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_spiffe_id_parse_rejects_empty_trust_domain() {
    let err = SpiffeId::parse("spiffe:///path").expect_err("empty trust domain must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("trust domain"),
        "expected trust-domain diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_spiffe_id_parse_rejects_missing_path() {
    let err = SpiffeId::parse("spiffe://example.org").expect_err("missing path must fail");
    let msg = format!("{err}");
    assert!(msg.contains("path"), "expected path diagnostic, got: {msg}");
}

#[test]
fn pr23_spiffe_id_parse_rejects_uppercase_trust_domain() {
    // SPIFFE-ID §2.1.2: trust domain must be lowercase. We surface
    // this as a hard parse error (not case-insensitive equality)
    // because the SPIFFE spec is explicit that trust-domain matching
    // is case-sensitive.
    let err = SpiffeId::parse("spiffe://Example.Org/x").expect_err("uppercase must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("lowercase"),
        "expected lowercase diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_spiffe_id_parse_rejects_path_with_query() {
    let err = SpiffeId::parse("spiffe://example.org/x?y=1").expect_err("? in path must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("normalised") || msg.contains("?"),
        "expected normalisation diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_spiffe_id_parse_rejects_double_slash_path() {
    let err = SpiffeId::parse("spiffe://example.org/a//b").expect_err("// in path must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("normalised") || msg.contains("//"),
        "expected normalised-path diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_spiffe_id_parse_rejects_overlong() {
    // 2049 bytes total — 1 over the SPIFFE-ID §2.1 limit.
    let td = "example.org";
    let pad = "a".repeat(2049 - "spiffe://".len() - td.len() - "/".len());
    let overlong = format!("spiffe://{td}/{pad}");
    let err = SpiffeId::parse(&overlong).expect_err("overlong must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("max length"),
        "expected max-length diagnostic, got: {msg}"
    );
}

// ============================================================================
// validate_uri_only — matching policy semantics
//
// We issue a single SM2 cert via gm-ca with a fixed URI SAN
// `spiffe://prod.example.com/ns/foo/sa/web`, then exercise the
// matching policy matrix against it.
// ============================================================================

/// Issue a self-signed SM2 cert that carries the given URI SAN.
/// Returns the leaf cert's DER bytes (suitable for `validate_uri_only`).
fn issue_uri_san_cert(uri_san: &str) -> Vec<u8> {
    use gm_ca::cert::CaSigner;
    use gm_ca::cert_profile::{CertProfile, ExtendedKeyUsage, GeneralName, KeyUsageBits};

    // Root CA — used to sign the leaf below.
    let ca_key = Sm2KeyPair::generate().expect("CA keygen");
    let ca_signer = CaSigner::new(ca_key, "PR-2.3 test CA");
    let ca_pem = ca_signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("CA self-sign");
    let _ca_der = pem::parse(ca_pem.as_bytes())
        .expect("CA PEM parse")
        .into_contents();

    // Leaf key + CSR + cert with URI SAN.
    let leaf_key = Sm2KeyPair::generate().expect("leaf keygen");
    let leaf_pub_65 = leaf_key.public_key_bytes_uncompressed();
    let csr_pem = CsrBuilder::new_sm2("pr23-test", &leaf_pub_65)
        .expect("CsrBuilder")
        .build_pem(&leaf_key)
        .expect("CSR build");

    let leaf_profile = CertProfile {
        sans: vec![GeneralName::UniformResourceIdentifier(uri_san.to_string())],
        key_usage: KeyUsageBits::digital_signature(),
        ext_key_usage: vec![ExtendedKeyUsage::ServerAuth],
        ..CertProfile::server_end_entity()
    };

    let (_, leaf_pem) = ca_signer
        .sign_csr_with_profile(csr_pem.as_bytes(), 365, &leaf_profile)
        .expect("sign CSR");
    pem::parse(leaf_pem.as_bytes())
        .expect("leaf PEM parse")
        .into_contents()
}

const LEAF_URI: &str = "spiffe://prod.example.com/ns/foo/sa/web";

#[test]
fn pr23_validate_uri_only_accepts_exact_spiffe() {
    let cert = issue_uri_san_cert(LEAF_URI);
    validate_uri_only(&cert, LEAF_URI, now(), UriMatchPolicy::default())
        .expect("exact SPIFFE match must succeed");
}

#[test]
fn pr23_validate_uri_only_accepts_prefix_path() {
    let cert = issue_uri_san_cert(LEAF_URI);
    // Expected path is a strict prefix of the cert path — SPIFFE
    // Federation §4.1 "Prefix" matching accepts this.
    let expected = "spiffe://prod.example.com/ns/foo/sa";
    validate_uri_only(&cert, expected, now(), UriMatchPolicy::default())
        .expect("prefix path match must succeed");
}

#[test]
fn pr23_validate_uri_only_rejects_prefix_when_exact_required() {
    let cert = issue_uri_san_cert(LEAF_URI);
    let expected = "spiffe://prod.example.com/ns/foo/sa";
    let strict = UriMatchPolicy::Spiffe {
        path: SpiffePathPolicy::Exact,
    };
    let err = validate_uri_only(&cert, expected, now(), strict)
        .expect_err("prefix path must NOT match under Exact policy");
    let msg = format!("{err}");
    assert!(
        msg.contains("no URI SAN matched"),
        "expected no-match diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_validate_uri_only_rejects_mismatched_trust_domain() {
    let cert = issue_uri_san_cert(LEAF_URI);
    let expected = "spiffe://staging.example.com/ns/foo/sa/web";
    let err = validate_uri_only(&cert, expected, now(), UriMatchPolicy::default())
        .expect_err("trust-domain mismatch must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("no URI SAN matched"),
        "expected no-match diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_validate_uri_only_rejects_mismatched_path_prefix() {
    let cert = issue_uri_san_cert(LEAF_URI);
    // Expected path has a leading `/x` that the cert path does NOT
    // share; prefix-match must reject.
    let expected = "spiffe://prod.example.com/x";
    let err = validate_uri_only(&cert, expected, now(), UriMatchPolicy::default())
        .expect_err("non-prefix path must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("no URI SAN matched"),
        "expected no-match diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_validate_uri_only_rejects_invalid_expected_uri() {
    let cert = issue_uri_san_cert(LEAF_URI);
    let expected = "spiffe://Example.Org/ns/foo/sa/web"; // uppercase TD
    let err = validate_uri_only(&cert, expected, now(), UriMatchPolicy::default())
        .expect_err("uppercase expected URI must fail at parse");
    let msg = format!("{err}");
    assert!(
        msg.contains("lowercase"),
        "expected lowercase-trust-domain diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_validate_uri_only_rejects_cert_without_uri_san() {
    // Issue a cert WITHOUT a URI SAN.
    use gm_ca::cert::CaSigner;
    use gm_ca::cert_profile::{CertProfile, ExtendedKeyUsage, KeyUsageBits};

    let ca_key = Sm2KeyPair::generate().expect("CA keygen");
    let ca_signer = CaSigner::new(ca_key, "PR-2.3 test CA (no URI)");
    let _ca_pem = ca_signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("CA self-sign");

    let leaf_key = Sm2KeyPair::generate().expect("leaf keygen");
    let leaf_pub_65 = leaf_key.public_key_bytes_uncompressed();
    let csr_pem = CsrBuilder::new_sm2("pr23-no-uri", &leaf_pub_65)
        .expect("CsrBuilder")
        .build_pem(&leaf_key)
        .expect("CSR build");
    let leaf_profile = CertProfile {
        // No URI SAN — only the CN from the CSR.
        sans: vec![],
        key_usage: KeyUsageBits::digital_signature(),
        ext_key_usage: vec![ExtendedKeyUsage::ServerAuth],
        ..CertProfile::server_end_entity()
    };
    let (_, leaf_pem) = ca_signer
        .sign_csr_with_profile(csr_pem.as_bytes(), 365, &leaf_profile)
        .expect("sign CSR");
    let cert = pem::parse(leaf_pem.as_bytes())
        .expect("leaf PEM parse")
        .into_contents();

    let err = validate_uri_only(&cert, LEAF_URI, now(), UriMatchPolicy::default())
        .expect_err("cert without URI SAN must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("no URI SAN"),
        "expected no-URI-SAN diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_validate_uri_only_rejects_cert_with_non_spiffe_uri_san() {
    // Issue a cert with a non-SPIFFE URI SAN (`https://example.org/x`).
    // The policy is Spiffe::Prefix; we expect this to be skipped
    // (not a parse error) and ultimately fail because no SAN parses
    // as a SPIFFE ID.
    use gm_ca::cert::CaSigner;
    use gm_ca::cert_profile::{CertProfile, ExtendedKeyUsage, GeneralName, KeyUsageBits};

    let ca_key = Sm2KeyPair::generate().expect("CA keygen");
    let ca_signer = CaSigner::new(ca_key, "PR-2.3 test CA (non-SPIFFE URI)");
    let _ca_pem = ca_signer
        .self_sign_ca(365, &CertProfile::root_ca())
        .expect("CA self-sign");

    let leaf_key = Sm2KeyPair::generate().expect("leaf keygen");
    let leaf_pub_65 = leaf_key.public_key_bytes_uncompressed();
    let csr_pem = CsrBuilder::new_sm2("pr23-non-spiffe", &leaf_pub_65)
        .expect("CsrBuilder")
        .build_pem(&leaf_key)
        .expect("CSR build");
    let leaf_profile = CertProfile {
        sans: vec![GeneralName::UniformResourceIdentifier(
            "https://example.org/x".to_string(),
        )],
        key_usage: KeyUsageBits::digital_signature(),
        ext_key_usage: vec![ExtendedKeyUsage::ServerAuth],
        ..CertProfile::server_end_entity()
    };
    let (_, leaf_pem) = ca_signer
        .sign_csr_with_profile(csr_pem.as_bytes(), 365, &leaf_profile)
        .expect("sign CSR");
    let cert = pem::parse(leaf_pem.as_bytes())
        .expect("leaf PEM parse")
        .into_contents();

    let err = validate_uri_only(&cert, LEAF_URI, now(), UriMatchPolicy::default())
        .expect_err("non-SPIFFE URI SAN must NOT match a SPIFFE expectation");
    let msg = format!("{err}");
    assert!(
        msg.contains("no URI SAN matched"),
        "expected no-match diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_validate_uri_only_literal_policy_accepts_exact_string() {
    let cert = issue_uri_san_cert(LEAF_URI);
    validate_uri_only(&cert, LEAF_URI, now(), UriMatchPolicy::Literal)
        .expect("literal exact match must succeed");
}

#[test]
fn pr23_validate_uri_only_literal_policy_rejects_substring() {
    let cert = issue_uri_san_cert(LEAF_URI);
    let partial = "spiffe://prod.example.com/ns/foo"; // not the full string
    let err = validate_uri_only(&cert, partial, now(), UriMatchPolicy::Literal)
        .expect_err("literal substring must NOT match");
    let msg = format!("{err}");
    assert!(
        msg.contains("literal") || msg.contains("no URI SAN matched"),
        "expected literal-no-match diagnostic, got: {msg}"
    );
}

#[test]
fn pr23_validate_uri_only_cert_actually_carries_uri_san() {
    // Sanity check on the test fixture itself: confirm the cert
    // issued by `issue_uri_san_cert` carries exactly one URI SAN
    // with the expected value. This is a guard against silent
    // changes to `issue_uri_san_cert` (e.g. if `GeneralName::to_der`
    // or `CertProfile::sans` semantics shifted).
    let cert = issue_uri_san_cert(LEAF_URI);
    let (_, parsed) =
        x509_parser::prelude::X509Certificate::from_der(&cert).expect("parse test cert");
    let san = parsed
        .subject_alternative_name()
        .expect("SAN parse")
        .expect("SAN present");
    let mut found = false;
    for name in &san.value.general_names {
        if let x509_parser::extensions::GeneralName::URI(u) = name {
            assert_eq!(*u, LEAF_URI, "URI SAN must equal LEAF_URI");
            found = true;
        }
    }
    assert!(found, "test cert must carry exactly the expected URI SAN");
}
