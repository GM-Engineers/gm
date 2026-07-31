# gm-ca

**SM2 Certificate Authority** — gRPC-based CA service.

**[中文版](./README.md)**

## Features

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

## License

MIT OR Apache-2.0 — See [../LICENSE](../LICENSE)
