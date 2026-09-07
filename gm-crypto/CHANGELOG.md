# Changelog

All notable changes to the `gm-crypto` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-09-07

### Added

- **`Sm2EcdhKeypair::private_key_bytes()`** —
  ([`src/sm2.rs`](src/sm2.rs)).
  Returns the 32-byte big-endian scalar of the raw ECDH keypair's
  private key as `Vec<u8>`. This is the input that the SM2 Key
  Agreement Protocol (GB/T 32918.3-2016 §6.1 B4 / GM/T 0003.3-2012 §6.1)
  needs when computing the per-ephemeral `k_A` (initiator) /
  `k_B` (responder) term in the `V = k_A · R_B` step. The new method
  exposes the scalar without dragging in any of the internal `Scalar`
  machinery, keeping the public API stable for callers that just need
  the bytes to feed into a KAP call.

  Required by the `tlcp-strict` server-side ECDHE PMS fix in
  `gm-tlcp 0.2.2` (audit C-3, originally landed in `gm-tlcp 0.2.1`
  but only now consumable from crates.io because of the matching
  `gm-crypto` version bump).

### Compatibility

This release adds new APIs only; no existing API has been changed or
removed. Fully backwards-compatible with the 0.2.x series.

## [0.2.0] - 2026-09-04

### Added

#### SM4 raw CBC primitives (no PKCS#7 padding)

- **`Sm4Cipher::encrypt_cbc_raw`** — CBC mode encryption that operates
  on the input bytes verbatim without applying PKCS#7 padding. The
  caller is responsible for any padding the protocol layer requires.
  This is the right primitive when the protocol layer (e.g. TLCP
  record-layer MAC-then-Encrypt, TLS 1.1 CBC suites) already manages
  its own padding — using the regular `encrypt_cbc` in that
  situation would add a *second* layer of padding and corrupt the
  wire format.

- **`Sm4Cipher::decrypt_cbc_raw`** — symmetric counterpart of
  `encrypt_cbc_raw`. Decrypts raw ciphertext blocks without removing
  any padding. Callers that need PKCS#7 stripping should call this
  and then run their own `unpad_pkcs7` logic.

These two functions are the foundation for the new `gm-tlcp`
crate's MAC-then-Encrypt CBC record-layer framing.

#### X.509 SM2 public key extraction

- **`x509::extract_sm2_pubkey_from_der`** — given a DER-encoded X.509
  certificate, returns the raw SM2 public key as 65 bytes in
  uncompressed SEC1 form (`0x04 || x || y`). The function defensively
  masks the BIT STRING trailing-bits count because GmSSL has
  historically emitted SPKI BIT STRINGs with non-zero unused-bits
  values (e.g. `4` when the high nibble of the last byte is `0`),
  which would otherwise leak into downstream SM2 encryption/verifier
  constructors and cause them to reject the public key.

  This function is what `gm-tlcp`'s certificate verification path uses
  to extract the server's static encryption pubkey from the enc cert
  and the client's static encryption pubkey from the client enc cert
  before driving SM2 ECDHE key agreement per GB/T 32918.3-2016.

### Compatibility

This release adds new APIs only; no existing API has been changed or
removed. The crate's public surface is fully backwards-compatible with
the 0.1.x series.

[Unreleased]: https://github.com/GM-Engineers/gm/compare/main...HEAD
[0.3.0]: https://github.com/GM-Engineers/gm/compare/gm-crypto-v0.2.0...gm-crypto-v0.3.0
[0.2.0]: https://github.com/GM-Engineers/gm/releases/tag/gm-crypto-v0.2.0
