# gm-ca

**SM2 Certificate Authority** — gRPC-based CA service.

**[中文版](./README.md)**

## Features

### v0.2.0 (Phase 2c / 3 / 4 / 5 / 6 / 9)

- **`CertProfile`** — declarative spec controlling issued cert's
  KU / EKU / BC / SKI / AKI / SAN extensions
- **`RsaCaSigner`** *(feature `rsa`)* — RSA-backed CA signer for
  the TLCP RSA suites (E019/E01C/E059/E05A)
- **`gm_ca::profiles::tlcp`** *(feature `tlcp-profiles`)* — 6 TLCP end-entity presets:
  `tlcp_server_sign_ecc` / `tlcp_server_enc_ecc` / `tlcp_client_sign_ecc` / `tlcp_client_enc_ecc` (SM2) +
  `tlcp_server_rsa` / `tlcp_client_rsa` (RSA)
- **`CsrBuilder`** (in `gm-crypto::x509`) — unified CSR builder for SM2 / RSA
- **In-process TLCP loopback tests** *(features `rsa` + `tlcp-profiles`)* —
  `tests/tlcp_loopback.rs` (4 RSA suites) + `tests/tlcp_loopback_sm2.rs` (4 ECC suites)

### v0.1.x (baseline)

- SM2 certificate issuance
- Certificate Revocation List (CRL) management
- Certificate status queries

## Start the Service

```bash
# Set up database (required, no default)
export DATABASE_URL="postgres://user:password@localhost:5432/gm_ca"

# Set auth token (required)
export CA_AUTH_TOKEN="$(openssl rand -hex 32)"

# Start CA service (default listening on [::1]:50051, localhost only)
cargo run --bin gm-ca-server
```

## gRPC API

The service implements interfaces defined in `proto/ca.proto` (proto package: `gm.ca.v1`), including:
- `SignCertificate` — Issue new certificate (input: CSR PEM and validity days)
- `RenewCertificate` — Renew an existing certificate (input: serial number)
- `RevokeCertificate` — Revoke certificate
- `GetCertificate` — Query certificate
- `GetCrl` — Get CRL

## Library API (v0.2.0)

For Rust library use (`gm-ca = "0.2"`), the core types live in the
`gm_ca::cert` and `gm_ca::cert_profile` modules:

```rust
use gm_ca::cert::{CaSigner, Certificate};
use gm_ca::cert_profile::{CertProfile, ExtendedKeyUsage, GeneralName, KeyUsageBits};
use gm_crypto::sm2::Sm2KeyPair;

// SM2 root CA
let key = Sm2KeyPair::generate()?;
let ca_signer = CaSigner::new(key, "GM Test CA");
let root_pem = ca_signer.self_sign_ca(365, &CertProfile::root_ca())?;

// End-entity certificate
let mut profile = CertProfile::default();
profile.sans.push(GeneralName::DnsName("leaf.example.com".into()));
let (_, leaf_pem) = ca_signer.sign_csr_with_profile(&csr_pem, 365, &profile)?;
```

Enable the `tlcp-profiles` feature to access the 6 TLCP presets:

```toml
gm-ca = { version = "0.2", features = ["tlcp-profiles", "rsa"] }
```

```rust
use gm_ca::profiles::tlcp::{tlcp_server_sign_ecc, tlcp_client_enc_ecc};
let server_profile = tlcp_server_sign_ecc();
let client_enc_profile = tlcp_client_enc_ecc();
```

## Features

| Feature | Default | Description |
|---|---|---|
| (none) | ✓ | SM2 path only (canonical GM-only build) |
| `rsa` | ✗ | Enable `RsaCaSigner` for TLCP RSA suites |
| `tlcp-profiles` | ✗ | Enable `gm_ca::profiles::tlcp` (6 TLCP presets) |

`rsa` and `tlcp-profiles` are orthogonal — enable either, both, or neither. External deps (`rsa = "0.9"`, `sha2 = "0.10"`, `sha1 = "0.10"`) are pulled in only when `rsa` is enabled.

## License

MIT OR Apache-2.0 — See [../LICENSE](../LICENSE)
