# Contributing to gm

Thank you for your interest in contributing to **gm** — a Rust workspace implementing
Chinese national cryptography (国密: SM2 / SM3 / SM4 / SM9), TLS 1.3 with the
TLCP profile, a minimal CA, an HTTP client, and ASN.1 DER tooling.

This document is the bilingual (中文 / English) contribution guide.

## Code of Conduct / 行为准则

This project adheres to the [Contributor Covenant](CODE_OF_CONDUCT.md).
By participating, you agree to uphold it.

本项目遵循 [Contributor Covenant 行为准则](CODE_OF_CONDUCT.md)，参与即表示同意遵守。

## Getting started / 环境准备

- **Rust toolchain 1.85+** (Edition 2024). Install via [rustup](https://rustup.rs).
- Clone and build:

  ```bash
  cargo build --workspace
  cargo test  --workspace
  ```

- Known-answer (KAT) self-tests are part of the test suite. Run them explicitly:

  ```bash
  cargo test -p gm-crypto      # SM2 / SM3 / SM4 KAT vectors
  cargo test -p gm-sm9-rs      # SM9 KAT vectors
  ```

## Workspace layout / 工作区结构

| Crate | Purpose |
|-------|---------|
| `gm-der` | ASN.1 DER encode/decode for certs & keys |
| `gm-crypto` | SM2 / SM3 / SM4 implementations + KAT self-tests |
| `gm-sm9-rs` | SM9 IBE: signatures, encryption, key exchange (pure-Rust + GmSSL FFI). Field & pairing arithmetic live in its internal `arith` / `pairing` modules |
| `gm-tls` | TLS 1.3 with TLCP; `gm-tls/fuzz` holds cargo-fuzz targets |
| `gm-ca` | Minimal certificate authority |
| `gm-http-client` | HTTP client built on `gm-tls` |

## Development workflow / 开发规范

- Format: `cargo fmt --all`
- Lint: `cargo clippy --workspace --all-targets`
- Supply chain: `cargo deny check` (see `deny.toml`)
- Fuzzing (gm-tls):

  ```bash
  cd gm-tls/fuzz && cargo +nightly fuzz run tls_record_parse
  ```

## Commit & PR guidelines / 提交规范

- Keep PRs focused; explain the motivation and include test evidence.
- Sign your commits (DCO): `git commit -s`.
- CI must be green (`cargo test`, `clippy`, `cargo deny check`, `cargo fmt`).
- Prefer small, reviewable commits over large squashes where possible.

## License / 许可证

By contributing, you agree your contributions are licensed under **MIT OR Apache-2.0**,
consistent with the project. Do not introduce code under GPL / LGPL / AGPL.

## Security / 安全

Do **not** open public issues for vulnerabilities. Follow
[SECURITY.md](SECURITY.md) and report privately.

## Questions / 疑问

Open an issue or discussion on `GM-Engineers/gm`.
