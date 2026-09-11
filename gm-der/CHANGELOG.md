# Changelog

All notable changes to the `gm-der` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-11

### Added

- **Initial release.** Low-level ASN.1 DER (Distinguished Encoding
  Rules) tag / length / value encoders and parsers used across
  `gm-crypto`, `gm-sm9-rs`, `gm-ca`, and `gm-tls`:
    - `der_bool`, `der_integer_positive`, `der_bit_string`,
      `der_octet_string`, `der_sequence`, `der_sequence_v`,
      `der_set`, `der_utf8_string`, `der_explicit_context`,
      `encode_oid`, `der_len` — encoders.
    - `parse_der_integer`, `parse_der_bit_string`,
      `parse_der_octet_string`, `parse_der_oid`,
      `parse_der_sequence`, `parse_der_explicit` — parsers.
    - `DerError` — typed error variants per failure mode.

  Internal helper crate; not intended for direct use by applications.
  Coverage is provided transitively by `gm-crypto` and `gm-ca` unit
  tests which round-trip DER through `x509-parser`.

[Unreleased]: https://github.com/GM-Engineers/gm/compare/main...HEAD
[0.1.0]: https://github.com/GM-Engineers/gm/releases/tag/gm-der-v0.1.0