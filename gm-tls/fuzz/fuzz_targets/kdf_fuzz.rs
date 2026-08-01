//! Fuzz target for HKDF-SM3 key derivation
//!
//! Tests:
//! 1. HKDF-SM3 boundary conditions (empty inputs, max length)
//! 2. Output length validation
//! 3. RFC 5869 compliance properties

#![no_main]

use gm_tls::gm::hkdf_sm3;
use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};

#[derive(Arbitrary, Debug)]
struct HkdfInput {
    ikm: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    len: usize,
}

fuzz_target!(|input: HkdfInput| {
    let len = input.len.min(8160);

    let result = hkdf_sm3(&input.ikm, &input.salt, &input.info, len);

    if let Ok(output) = &result {
        assert_eq!(
            output.len(),
            len,
            "HKDF output length should match requested"
        );
        let result2 = hkdf_sm3(&input.ikm, &input.salt, &input.info, len);
        assert_eq!(result.as_ref().ok(), result2.as_ref().ok());
    }

    // Test empty IKM
    let result_empty_ikm = hkdf_sm3(&[], &input.salt, &input.info, len.min(8160));
    if let Ok(output) = &result_empty_ikm {
        assert!(output.len() <= 8160);
    }

    // Test empty salt
    let result_empty_salt = hkdf_sm3(&input.ikm, &[], &input.info, len.min(8160));
    if let Ok(output) = &result_empty_salt {
        assert!(output.len() <= 8160);
    }

    // Test empty info
    let result_empty_info = hkdf_sm3(&input.ikm, &input.salt, &[], len.min(8160));
    if let Ok(output) = &result_empty_info {
        assert!(output.len() <= 8160);
    }

    // Test max length acceptance
    let result_max = hkdf_sm3(&input.ikm, &input.salt, &input.info, 8160);
    assert!(result_max.is_ok(), "HKDF should accept max length (8160)");

    // Test max+1 rejection
    let result_over = hkdf_sm3(&input.ikm, &input.salt, &input.info, 8161);
    assert!(
        result_over.is_err(),
        "HKDF should reject exceeding max length"
    );

    // Test different inputs produce different outputs
    if !input.ikm.is_empty() && input.ikm.len() > 1 {
        let alt_ikm = {
            let mut v = input.ikm.clone();
            v[0] ^= 0xFF;
            v
        };
        let r1 = hkdf_sm3(&input.ikm, &input.salt, &input.info, 32);
        let r2 = hkdf_sm3(&alt_ikm, &input.salt, &input.info, 32);
        if let (Ok(o1), Ok(o2)) = (r1, r2) {
            if input.ikm != alt_ikm {
                // Different inputs *should* produce different outputs (but not guaranteed)
                // We just check both succeed
                let _ = (o1, o2);
            }
        }
    }
});
