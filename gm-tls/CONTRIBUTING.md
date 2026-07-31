# Contributing to gm-tls

Thank you for your interest in contributing to gm-tls!

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful and constructive in all interactions.

## How to Contribute

### Reporting Issues

- Search existing issues before creating a new one
- Use issue templates when available
- Include minimal reproducible examples for bugs
- Security issues: See [SECURITY.md](./SECURITY.md) - do NOT open public issues

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests (`cargo test --all`)
5. Format code (`cargo fmt`)
6. Lint code (`cargo clippy --all -- -D warnings`)
7. Commit with clear messages
8. Push to your fork
9. Open a Pull Request

### Coding Standards

- Follow Rust idioms and conventions
- Document public APIs with doc comments
- Add tests for new functionality
- Keep PRs focused and small

### Testing

```bash
# Run all tests
cargo test --all

# Run with all features
cargo test --all --all-features

# Run benchmarks
cargo bench

# Run fuzz tests (requires nightly)
cargo +nightly fuzz run tls_record_parse
```

## License

By contributing, you agree that your contributions will be licensed under the MIT OR Apache-2.0 license as specified in the project.