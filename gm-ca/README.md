# gm-ca

**SM2 证书颁发机构** — 基于 gRPC 的 CA 服务。

**[English Version](./README.en.md)**

## 功能

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

## 许可

MIT OR Apache-2.0 — 参见 [../LICENSE](../LICENSE)
