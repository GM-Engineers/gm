# Changelog

All notable changes to the `gm-ca` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`tlcp-profiles` Cargo feature** (off by default) — enables the
  new `gm_ca::profiles::tlcp` submodule exposing 5 TLCP end-entity
  `CertProfile` preset constructors matching the KU/EKU layout that
  [GB/T 38636-2020] §6.4.6 / GmSSL master / openHiTLS expect:

  | Preset | KU bits | EKU | Algorithm |
  |---|---|---|---|
  | `tlcp_server_sign_ecc` | digitalSignature \| keyAgreement | serverAuth | SM2 |
  | `tlcp_server_enc_ecc` | keyEncipherment \| keyAgreement \| dataEncipherment | (none — GmSSL convention) | SM2 |
  | `tlcp_client_sign_ecc` | digitalSignature \| keyAgreement | clientAuth | SM2 |
  | `tlcp_server_rsa` (gated `rsa`) | digitalSignature \| keyEncipherment | serverAuth | RSA |
  | `tlcp_client_rsa` (gated `rsa`) | digitalSignature \| keyEncipherment | clientAuth | RSA |

  The enc cert preset deliberately has **no EKU** because GB/T 38636
  §6.4.6.1.2 b) marks EKU as optional and GmSSL/openHiTLS both emit
  none — matching that keeps TLCP enc certs GmSSL-chain-walkable.
  Presets leave `sans` empty so callers push their own
  `GeneralName::DnsName` / `IpAddress` entries before passing the
  profile to `CaSigner`/`RsaCaSigner`.

[GB/T 38636-2020]: https://openstd.samr.gov.cn/

- **`RsaCaSigner` (feature `rsa`)** — X.509 CA signer backed by an
  RSA private key, mirror of `CaSigner` for the SM2 path. Produces
  certs with `rsaEncryption` (1.2.840.113549.1.1.1) SPKI and
  `sha256WithRSAEncryption` (1.2.840.113549.1.1.11) signatures —
  the surface expected by general-purpose X.509 verifiers
  (GmSSL master, openHiTLS, OpenSSL) for the TLCP RSA suites
  ([GB/T 38636-2020] §6.4.5.2.1 表 2 — E019/E01C/E059/E05A).
  SKI/AKI key-ids use SHA-1 per RFC 7093 §2 Method 1 (interop
  with global PKI; SM3 is reserved for SM2 certs). Methods:
  `self_sign_ca`, `sign_csr_with_profile` (CSR must use
  `rsaEncryption`; SM2-signed CSRs are rejected up front),
  `renew_certificate_with_profile`, `from_pkcs8_pem`. RSA CSRs
  are signature-verified with sha256WithRSAEncryption before
  issuing.

- **`rsa` Cargo feature** (off by default) — enables
  `RsaCaSigner` and pulls `rsa = "0.9"` + `sha2 = "0.10"` +
  `sha1 = "0.10"` (versions synced with gm-tlcp 0.6.x). Default
  build stays strictly SM2 + 国密; the SM2 path is the canonical
  CA signer.

### Internal

- **`cert::build_tbs_certificate`, `cert::build_certificate_der`,
  `cert::build_extensions` refactored to be algorithm-agnostic.**
  They now take pre-built `sig_alg_id`, `spki_alg_id`, and 20-byte
  `subject_key_id` / `ca_key_id` values instead of SM2-specific
  pubkey bytes. The SM2 `CaSigner` path uses thin SM2 wrappers
  (`sm2_sig_alg_id`, `sm2_spki_alg_id`, `sm3_key_id`) and the
  new `RsaCaSigner` path uses RSA wrappers (`rsa_sig_alg_id`,
  `rsa_spki_alg_id`, `sha1_key_id`). No behavior change to
  existing SM2 callers.

[GB/T 38636-2020]: https://openstd.samr.gov.cn/

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
