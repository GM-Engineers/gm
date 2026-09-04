# Publishing gm-tlcp to crates.io

This document explains the policy that governs what goes into the
published `gm-tlcp` crate. **It is the source of truth for any PR
that adds a new top-level directory or tooling script.**

## TL;DR

Only library code, the five `examples/*.rs` files, and the standard
Cargo metadata are shipped. **Everything else** (interop scripts,
build artifacts, integration tests, CI workflow) is excluded.

The exclusion is enforced by **two independent mechanisms**:

1. **`Cargo.toml` `exclude` field** — declarative whitelist of paths
   that cargo must not include.
2. **`scripts/check-publish.sh`** — runs `cargo package --list
   --allow-dirty` and asserts the result is clean. Invoked by CI on
   every PR.

A contributor who adds a new directory MUST update **both** of these.

## What ships

Library source:

```
src/error.rs
src/lib.rs
src/metrics.rs
src/record.rs
src/session_keys.rs
src/tlcp/{alert,cipher_suite,constants,handshake_type,key_material,mod,pms,session}.rs
src/tlcp/crypto/{mod,verify}.rs
src/tlcp/handshake/{client,mod,server,state}.rs
src/tlcp/messages/{cert_pair,client_hello,client_key_exchange,ecdhe,finished,mod,server_hello,server_hello_done}.rs
```

Examples:

```
examples/interop_client.rs
examples/interop_proxy.rs
examples/pms_kat.rs
examples/simple_client.rs
examples/simple_server.rs
```

Cargo metadata:

```
Cargo.toml
Cargo.toml.orig
README.md
```

(`Cargo.lock` is published despite the workspace-level `.gitignore`
because cargo produces it on demand for crates that need a stable
lock. The `Cargo.lock` is for our own internal-version pinning —
downstream users still resolve their own.)

## What does NOT ship

| Path             | Reason                                                                                  |
|------------------|-----------------------------------------------------------------------------------------|
| `interop/`       | Tongsuo build / run scripts. Reproducibility tool for devs, not crate consumers.          |
| `scripts/`       | `check-publish.sh` and any future release tooling.                                       |
| `tests/`         | `tests/gmssl_interop.rs` requires the `gmssl` binary on PATH; `tests/support/` has GmSSL-specific PEM / PBKDF2 helpers. Both are repo-only. Unit tests live inline in `src/*.rs` via `#[cfg(test)]`. |
| `.github/`       | CI workflows.                                                                            |
| `PUBLISHING.md`  | This document — only relevant to maintainers.                                            |
| `target/`        | Build artifacts. Excluded by cargo default; declared for explicitness.                    |

## How to verify locally

```sh
cd gm-tlcp
./scripts/check-publish.sh
```

Expected output:

```
==> cargo package --list --allow-dirty (gm-tlcp)
          N entries
    package staging area: ?

OK: gm-tlcp publish list is clean.
```

If the file count changes, you almost certainly added (or moved) a file
and need to update `Cargo.toml`'s `exclude` and `scripts/check-publish.sh`.

## How to verify the actual tarball

```sh
cd gm-tlcp
cargo package --allow-dirty --no-verify
tar tzf ../target/package/gm-tlcp-0.1.0.crate | sort
```

The file list under "What ships" above should appear (with a
`gm-tlcp-0.1.0/` prefix).

## CI guard

The `.github/workflows/ci.yml` job `publish-guard` runs
`scripts/check-publish.sh` on every PR. A PR that introduces a new
top-level directory without updating the exclude list will fail CI.

## Why `--allow-dirty`?

`cargo package` refuses to run on a dirty working tree by default.
That means the script would silently skip its check whenever a
contributor has uncommitted changes — exactly the moment when we
most need it to run. `--allow-dirty` is what makes the guard actually
catch the "I forgot to add this to exclude" case before the PR is
filed.

## Versioning & SemVer

gm-tlcp follows SemVer 2.0:

- **MAJOR** bump for breaking API changes (TlcpConnector / TlcpAcceptor
  public surface, cipher suite enum values).
- **MINOR** bump for additive changes (new optional builder methods,
  new cipher suites).
- **PATCH** bump for bug fixes, performance work, internal refactors
  with no public surface change.

The current version is `0.1.0`. We will not push to 1.0 until:

1. All four TLCP cipher suites are interop-tested against at least
   two independent implementations (GmSSL ✅, Tongsuo blocked on
   upstream NTLS state-machine fix).
2. A third-party code review (not by the original authors) has been
   integrated.

## Releasing

```sh
# 1. Update version in Cargo.toml (SemVer per the rules above).
# 2. Bump the gm-crypto dep if it changed in a SemVer-incompatible way.
# 3. Run the publish-guard script locally.
cd gm-tlcp && ./scripts/check-publish.sh

# 4. Dry-run publish to make sure crates.io accepts the metadata.
cargo publish --dry-run --allow-dirty

# 5. Tag the release.
git tag -s gm-tlcp-vX.Y.Z -m "gm-tlcp vX.Y.Z"
git push origin gm-tlcp-vX.Y.Z

# 6. Publish.
cargo publish
```

## Interop dev scripts are repo-only by design

The `interop/tongsuo/` directory (build / run Tongsuo for cross-impl
interop testing) lives in the GitHub repo so anyone can reproduce
our Tongsuo interop results. It MUST NOT ship to crates.io because:

- The Tongsuo build is ~16 MB of static binary + fuzz corpora.
- The `interop/` scripts are POSIX `bash` + Docker — useless to a
  Windows / non-Docker downstream user.
- The `tests/gmssl_interop.rs` integration test that consumes the
  same scripts is also repo-only for the same reason.

If you find yourself wanting to share these tools with downstream
users, **publish them as a separate crate** (e.g. `gm-tlcp-interop`)
with its own `Cargo.toml` and a public binary.
