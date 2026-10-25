//! PBES2 key-derivation-function selection for encrypted SM2 PKCS#8
//! export (`Sm2KeyPair::to_encrypted_pem_with_kdf`).
//!
//! `to_encrypted_pem` keeps the deliberately expensive scrypt defaults,
//! which is wrong for bulk / CI key issuance where wall-clock time
//! dominates. The new `_with_kdf` entry point lets callers choose PBKDF2
//! (cheap memory) or a tunable scrypt cost. These tests freeze that both
//! selectable KDFs produce a PEM that `from_encrypted_pem` can read back,
//! that the chosen parameters actually land on the wire, and that the
//! default path is untouched.

use gm_crypto::sm2::{PbeKdf, Sm2KeyPair};
use pkcs8::der::Decode;
use pkcs8::{EncryptedPrivateKeyInfo, SecretDocument};

/// Round-trip a key through `to_encrypted_pem_with_kdf` +
/// `from_encrypted_pem`, returning the parsed (not yet decrypted)
/// encrypted key info so tests can assert the embedded KDF parameters.
fn roundtrip(key: &Sm2KeyPair, password: &str, kdf: &PbeKdf) -> (String, Sm2KeyPair) {
    let pem = key
        .to_encrypted_pem_with_kdf(password, kdf)
        .expect("to_encrypted_pem_with_kdf");
    let back = Sm2KeyPair::from_encrypted_pem(&pem, password)
        .expect("from_encrypted_pem must read back the freshly-written KDF");
    (pem, back)
}

/// Extract the KDF identity embedded in an encrypted-PKCS#8 PEM as
/// owned data (the borrowed `Kdf` cannot escape `doc`'s lifetime).
fn pbes2_kdf_summary(pem: &str) -> (bool, bool, Option<u32>) {
    let (_label, doc) = SecretDocument::from_pem(pem).expect("PEM parse");
    let epi = EncryptedPrivateKeyInfo::from_der(doc.as_bytes()).expect("EPKI DER parse");
    match &epi.encryption_algorithm {
        pkcs8::pkcs5::EncryptionScheme::Pbes2(params) => {
            let is_scrypt = params.kdf.scrypt().is_some();
            let pbkdf2_iters = params.kdf.pbkdf2().map(|p| p.iteration_count);
            (is_scrypt, pbkdf2_iters.is_some(), pbkdf2_iters)
        }
        other => panic!("expected PBES2, got {other:?}"),
    }
}

#[test]
fn pbkdf2_roundtrip_and_iteration_count_lands_on_wire() {
    let key = Sm2KeyPair::generate().expect("keygen");
    let password = "super-secret-1";
    let iterations = 4096;
    let (pem, back) = roundtrip(&key, password, &PbeKdf::Pbkdf2 { iterations });

    assert_eq!(
        back.public_key_bytes_uncompressed(),
        key.public_key_bytes_uncompressed(),
        "round-tripped key must be identical"
    );

    let (is_scrypt, is_pbkdf2, pbkdf2_iters) = pbes2_kdf_summary(&pem);
    assert!(is_pbkdf2, "selected KDF must be PBKDF2");
    assert!(!is_scrypt, "must not be scrypt");
    assert_eq!(
        pbkdf2_iters,
        Some(iterations),
        "requested PBKDF2 iteration count must be encoded"
    );
}

#[test]
fn scrypt_roundtrip_and_kdf_is_scrypt() {
    let key = Sm2KeyPair::generate().expect("keygen");
    let password = "super-secret-1";
    // log_n 14 keeps the test fast while still exercising the scrypt path.
    let (pem, back) = roundtrip(
        &key,
        password,
        &PbeKdf::Scrypt {
            log_n: 14,
            r: 8,
            p: 1,
        },
    );
    assert_eq!(
        back.public_key_bytes_uncompressed(),
        key.public_key_bytes_uncompressed(),
        "round-tripped key must be identical"
    );

    let (is_scrypt, is_pbkdf2, _) = pbes2_kdf_summary(&pem);
    assert!(is_scrypt, "selected KDF must be scrypt");
    assert!(!is_pbkdf2, "must not be PBKDF2");
}

#[test]
fn wrong_password_fails_for_pbkdf2() {
    let key = Sm2KeyPair::generate().expect("keygen");
    let pem = key
        .to_encrypted_pem_with_kdf("right-password", &PbeKdf::Pbkdf2 { iterations: 2048 })
        .expect("encrypt");
    assert!(
        Sm2KeyPair::from_encrypted_pem(&pem, "wrong-password").is_err(),
        "decryption with the wrong password must fail"
    );
}

#[test]
fn short_password_is_rejected() {
    let key = Sm2KeyPair::generate().expect("keygen");
    let err = key
        .to_encrypted_pem_with_kdf("short", &PbeKdf::Pbkdf2 { iterations: 2048 })
        .expect_err("passwords under 8 chars must be rejected (same as default path)");
    assert!(
        format!("{err}").contains("at least 8"),
        "expected the password-length diagnostic, got: {err}"
    );
}

#[test]
fn default_to_encrypted_pem_is_read_by_kdf_path_and_scrypt() {
    // The untouched default `to_encrypted_pem` (scrypt) must still
    // produce a PEM that the generic decryptor reads, and it must be a
    // scrypt KDF — guarding against the default silently changing.
    let key = Sm2KeyPair::generate().expect("keygen");
    let pem = key
        .to_encrypted_pem("super-secret-1")
        .expect("default encrypt");
    let back = Sm2KeyPair::from_encrypted_pem(&pem, "super-secret-1").expect("decrypt default");
    assert_eq!(
        back.public_key_bytes_uncompressed(),
        key.public_key_bytes_uncompressed()
    );
    assert!(pbes2_kdf_summary(&pem).0, "default path must remain scrypt");
}
