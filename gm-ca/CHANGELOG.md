# Changelog

All notable changes to the `gm-ca` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-11

### Breaking Changes

- **`CaSigner::sign_csr` removed.** Use
  `CaSigner::sign_csr_with_profile(csr, days, &profile)`. The default
  `CertProfile::default()` (or `CertProfile::server_end_entity()`)
  reproduces the v0.1.x wire-format extension set
  (`digitalSignature | keyEncipherment`, `serverAuth | clientAuth`,
  SKI, SAN, plus a new explicit `BasicConstraints CA:FALSE`).
- **`CaSigner::renew_certificate` removed.** Use
  `CaSigner::renew_certificate_with_profile(cert_pem, days, &profile)`.

### Added

- **`CertProfile`** (in `gm_ca::cert_profile`) — declarative spec for
  the extension set + flags a cert should carry. Presets:
  `CertProfile::default`, `server_end_entity`, `client_end_entity`,
  `intermediate_ca`, `root_ca`.
- **`CaSigner::self_sign_ca(days, &profile)`** — self-sign the CA
  certificate (the trust anchor for chains `sign_csr_with_profile`
  issues). Default profile `CertProfile::root_ca()` produces a
  `keyCertSign | cRLSign` + `BasicConstraints CA:TRUE` root with
  matching SKI / AKI per RFC 7093 Method 1.
- **AuthorityKeyIdentifier extension** emitted by default on every
  certificate — `keyIdentifier = SM3(CA pubkey)[:20]` per RFC 7093
  §2 Method 1. Required by GmSSL master for TLCP chain walks.
- **BasicConstraints emitted by default** — `CA:FALSE` for end-entity
  certs, `CA:TRUE` (with optional `pathLenConstraint`) for CA certs.

### Changed

- Default end-entity extension set now includes an explicit
  `BasicConstraints CA:FALSE` extension (previously omitted).
  `gm-tls` / `gm-tlcp` both accept it unchanged.

## [0.1.2] - 2026-09-07

### Changed

- **Dependency bump**: `gm-crypto` requirement relaxed from `0.2.0`
  to `0.3` (caret range). No public API change in this crate.
  Required because `gm-crypto 0.3.0` adds the
  `Sm2EcdhKeypair::private_key_bytes()` method, which downstream
  callers (notably `gm-tlcp 0.2.2`'s `tlcp-strict` mode) need.

## [0.1.1] - 2026-09-05

### Added

- TLS gRPC integration via `gm-tls = { features = ["grpc"] }` and
  Tonic health endpoints.
- Generic CA service for SM2 certificate management.

[Unreleased]: https://github.com/GM-Engineers/gm/compare/main...HEAD
[0.2.0]: https://github.com/GM-Engineers/gm/compare/gm-ca-v0.1.2...gm-ca-v0.2.0
[0.1.2]: https://github.com/GM-Engineers/gm/compare/gm-ca-v0.1.1...gm-ca-v0.1.2
[0.1.1]: https://github.com/GM-Engineers/gm/releases/tag/gm-ca-v0.1.1
