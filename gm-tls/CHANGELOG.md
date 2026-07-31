# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-14

### Added
- Initial release of gm-tls
- SM2/SM3/SM4 cryptographic primitives via gm-crypto
- GM/TLS handshake protocol implementation
- SM4-GCM record layer encryption/decryption
- Certificate chain validation (SM2 signatures)
- Finished message signing and verification
- mTLS (mutual TLS) support
- Async I/O support via Tokio
- Comprehensive test suite (141 tests)
- Fuzzing infrastructure
- Performance benchmarks
- Security assessment report
- GitHub Actions CI/CD

### Security
- Uses OS CSPRNG for key generation (OsRng)
- Constant-time signature verification
- GCM authentication before decryption

### Known Limitations
- `bincode` dependency is unmaintained (see RUSTSEC-2025-0141)
- No session resumption support
- No 0-RTT support
- Domain validation is case-insensitive only