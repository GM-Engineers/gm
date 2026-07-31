# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue for security problems
2. Send an email to the maintainers
3. Describe the nature and potential impact of the issue

## Known Limitations

### 1. bincode Maintenance Status

The `bincode` v1.3.3 dependency has been marked as unmaintained (RUSTSEC-2025-0141).
Consider migrating to alternatives in future versions:

- `postcard`
- `rkyv`
- `bitcode`

### 2. Unicode License

`unicode-ident` uses `(MIT OR Apache-2.0) AND Unicode-3.0` license.
This requires compliance with both the MIT/Apache-2.0 and Unicode License v3.
Consult your legal counsel if this is a concern in your jurisdiction.

## Security Best Practices

1. **Always verify certificate chains** - do not skip verification
2. **Use unique nonces** - each encryption uses a different sequence number
3. **Keep dependencies updated** - apply security patches promptly
4. **Use deny.toml** - enforce license and security checks in CI/CD

## Dependency Security Monitoring

- Run `cargo deny check` regularly to audit dependencies
- Monitor RUSTSEC database for security advisories
- Use `cargo outdated` to check for available updates