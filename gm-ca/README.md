# gm-ca

**SM2 证书颁发机构** — 基于 gRPC 的 CA 服务。

**[English Version](./README.en.md)**

## 功能

### v0.2.0 (Phase 2c / 3 / 4 / 5 / 6 / 9)

- **`CertProfile`** — 声明式 spec,控制签发证书的 KU/EKU/BC/SKI/AKI/SAN 扩展
- **`RsaCaSigner`** *(feature `rsa`)* — RSA 私钥 CA 签发器,TLCP RSA 套件 (E019/E01C/E059/E05A) 用
- **`gm_ca::profiles::tlcp`** *(feature `tlcp-profiles`)* — 6 个 TLCP end-entity preset:
  `tlcp_server_sign_ecc` / `tlcp_server_enc_ecc` / `tlcp_client_sign_ecc` / `tlcp_client_enc_ecc` (SM2) +
  `tlcp_server_rsa` / `tlcp_client_rsa` (RSA)
- **CsrBuilder** (在 `gm-crypto::x509`) — 统一 CSR 构造入口,支持 SM2 / RSA
- **In-process TLCP loopback 测试** *(features `rsa` + `tlcp-profiles`)* —
  `tests/tlcp_loopback.rs` (4 RSA 套件) + `tests/tlcp_loopback_sm2.rs` (4 ECC 套件)

### v0.1.x (基础)

- SM2 证书签发
- 证书吊销列表（CRL）管理
- 证书状态查询

## 启动服务

```bash
# 设置数据库（必须设置，服务不会使用默认值）
export DATABASE_URL="postgres://user:password@localhost:5432/gm_ca"

# 设置认证令牌（必须设置）
export CA_AUTH_TOKEN="$(openssl rand -hex 32)"

# 启动 CA 服务（默认监听 [::1]:50051，仅接受本机连接）
cargo run --bin gm-ca-server
```

## gRPC API

服务实现 `proto/ca.proto` 中定义的接口（proto 包名：`gm.ca.v1`），包括：
- `SignCertificate` — 签发新证书（输入 CSR PEM 和有效期天数）
- `RenewCertificate` — 续签已有证书（输入序列号）
- `RevokeCertificate` — 吊销证书
- `GetCertificate` — 查询证书
- `GetCrl` — 获取 CRL

## 库 API (v0.2.0)

作为 Rust 库使用 (`gm-ca = "0.2"`) 时,核心类型在 `gm_ca::cert` 与
`gm_ca::cert_profile` 模块:

```rust
use gm_ca::cert::{CaSigner, Certificate};
use gm_ca::cert_profile::{CertProfile, ExtendedKeyUsage, GeneralName, KeyUsageBits};
use gm_crypto::sm2::Sm2KeyPair;

// SM2 root CA
let key = Sm2KeyPair::generate()?;
let ca_signer = CaSigner::new(key, "GM Test CA");
let root_pem = ca_signer.self_sign_ca(365, &CertProfile::root_ca())?;

// End-entity 证书
let mut profile = CertProfile::default();
profile.sans.push(GeneralName::DnsName("leaf.example.com".into()));
let (_, leaf_pem) = ca_signer.sign_csr_with_profile(&csr_pem, 365, &profile)?;
```

启用 `tlcp-profiles` feature 后,可使用 6 个 TLCP 专用 preset:

```toml
gm-ca = { version = "0.2", features = ["tlcp-profiles", "rsa"] }
```

```rust
use gm_ca::profiles::tlcp::{tlcp_server_sign_ecc, tlcp_client_enc_ecc};
let server_profile = tlcp_server_sign_ecc();
let client_enc_profile = tlcp_client_enc_ecc();
```

## Features

| Feature | Default | 描述 |
|---|---|---|
| (none) | ✓ | 仅 SM2 路径 (默认 GM-only build) |
| `rsa` | ✗ | 启用 `RsaCaSigner` + RSA 签发 (TLCP RSA 套件用) |
| `tlcp-profiles` | ✗ | 启用 `gm_ca::profiles::tlcp` (6 TLCP preset) |

`rsa` + `tlcp-profiles` 可同时启用。零外部依赖 (`rsa = "0.9"` /
`sha2 = "0.10"` / `sha1 = "0.10"` 仅在启用 `rsa` 时拉取)。

## 许可

MIT OR Apache-2.0 — 参见 [../LICENSE](../LICENSE)
