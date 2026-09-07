# Changelog

All notable changes to the `gm-ca` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
[0.1.2]: https://github.com/GM-Engineers/gm/compare/gm-ca-v0.1.1...gm-ca-v0.1.2
[0.1.1]: https://github.com/GM-Engineers/gm/releases/tag/gm-ca-v0.1.1
