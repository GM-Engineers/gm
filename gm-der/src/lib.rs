//! ASN.1 DER encoding/decoding primitives for GM (国密) cryptography.
//!
//! Provides low-level DER tag, length, and value encoding/decoding functions
//! used across gm-crypto, gm-sm9-rs, gm-ca, and gm-tls.
//!
//! # DER Tag Summary
//!
//! | Tag  | Type         | Encoder                  | Parser                     |
//! |------|-------------|--------------------------|----------------------------|
//! | 0x01 | BOOLEAN     | [`der_bool`]             | —                          |
//! | 0x02 | INTEGER     | [`der_integer_positive`] | [`parse_der_integer`]      |
//! | 0x03 | BIT STRING  | [`der_bit_string`]       | [`parse_der_bit_string`]   |
//! | 0x04 | OCTET STRING| [`der_octet_string`]     | [`parse_der_octet_string`] |
//! | 0x06 | OID         | [`encode_oid`]           | [`parse_der_oid`]          |
//! | 0x0C | UTF8String  | [`der_utf8_string`]      | —                          |
//! | 0x30 | SEQUENCE    | [`der_sequence`] / [`der_sequence_v`] | [`parse_der_sequence`] |
//! | 0x31 | SET         | [`der_set`]              | —                          |
//! | 0xA? | EXPLICIT    | [`der_explicit_context`] | [`parse_der_explicit`]     |

mod decode;
mod encode;
mod error;

pub use decode::*;
pub use encode::*;
pub use error::DerError;
