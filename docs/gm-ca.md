# gm-ca 部署指南

> 上次更新：2026-06-29
> 英文版：[gm-ca.en.md](./gm-ca.en.md)


gm-ca 提供 SM2 证书颁发机构（CA）服务，通过 gRPC 接口提供证书的签发、续期、吊销和查询功能，以及 CRL（证书吊销列表）管理。


## 启动服务

gm-ca 服务**仅通过环境变量配置**，不接受命令行参数。


### 环境变量

|环境变量|必填|默认值|说明|
|---------|------|--------|------|
| `DATABASE_URL` | 是 | — | 数据库连接串：`postgres://user:pass@host:5432/gm_ca` 或 `sqlite:gm_ca.db`|
| `CA_AUTH_TOKEN` | 是 | — | Bearer Token，长度无限制，建议使用 `openssl rand -hex 32` 生成|
| `CA_KEY_PATH` | 否 | `ca_key.pem` | CA 私钥文件路径（SEC1、PKCS#8 或加密 PKCS#8 PEM）|
| `CA_SUBJECT_CN` | 否 | `GM CA` | CA 证书的 CN（Common Name）字段|
| `GRPC_LISTEN_ADDR` | 否 | `[::1]:50051` | gRPC 监听地址（**注意：默认仅监听 IPv6 本机环回**）|
| `METRICS_ADDR` | 否 | `[::1]:9000` | Prometheus 指标监听地址|
| `GRPC_TLS_CERT` | 否 | — | 启用 GM/TLS 传输层：客户端证书路径|
| `GRPC_TLS_KEY` | 否 | — | 启用 GM/TLS 传输层：服务器私钥路径|
| `GRPC_TLS_CA` | 否 | — | 启用 GM/TLS 传输层：CA 证书路径|

> **重要**: 默认 `GRPC_LISTEN_ADDR=[::1]:50051` 仅接受本机 IPv6 连接。若需要外部访问，启动前需设置为 `0.0.0.0:50051`。


### 启动命令

```bash
# 设置必需的环境变量
export DATABASE_URL="postgres://postgres:test_password@localhost:5432/gm_ca"
export CA_AUTH_TOKEN="$(openssl rand -hex 32)"

# 启动 CA 服务
cargo run -p gm-ca-server
```

### 启用 GM/TLS 传输（可选）

三个变量同时设置时，服务使用 GM/TLS 加密 gRPC 通信（而非明文 TCP）：


```bash
export DATABASE_URL="postgres://postgres:test_password@localhost:5432/gm_ca"
export CA_AUTH_TOKEN="$(openssl rand -hex 32)"
export GRPC_TLS_CERT="/path/to/grpc-server.pem"
export GRPC_TLS_KEY="/path/to/grpc-server-key.pem"
export GRPC_TLS_CA="/path/to/ca.pem"   # 客户端证书的 CA

cargo run -p gm-ca-server
```

---


proto 包名：`gm.ca.v1`，所有请求需携带 `Authorization: Bearer <CA_AUTH_TOKEN>` 头部。


### 1. 签发证书（SignCertificate）

签发一个新的终端实体证书（需要先创建 CSR）：


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIICIT...",
    "validity_days": 365
  }' \
  localhost:50051 gm.ca.v1.CaService/SignCertificate
```

**响应示例（成功）**:
```json
{
  "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIICEjCC...",
  "error_code": "",
  "error_message": ""
}
```

### 2. 续期证书（RenewCertificate）

对已有证书进行续期（使用原证书公钥，延长有效期）：


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "serial_number": "00:AA:BB:CC:DD:EE:FF:00:01",
    "validity_days": 365
  }' \
  localhost:50051 gm.ca.v1.CaService/RenewCertificate
```

### 3. 吊销证书（RevokeCertificate）

吊销一个已签发的证书：


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "serial_number": "00:AA:BB:CC:DD:EE:FF:00:01",
    "reason": 1
  }' \
  localhost:50051 gm.ca.v1.CaService/RevokeCertificate
```

`reason` 为整数（RFC 5280 CRL 理由码）：`0`=未指定，`1`=密钥泄露，`2`=CA泄露，`3`=隶属关系变更，`4`=被替代，`5`=停止操作，`6`=证书暂停，`9`=特权撤销，`10`=AA泄露。


**响应示例（成功）**:
```json
{
  "success": true,
  "error_code": "",
  "error_message": ""
}
```

### 4. 查询证书（GetCertificate）

根据序列号查询证书信息：


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "serial_number": "00:AA:BB:CC:DD:EE:FF:00:01"
  }' \
  localhost:50051 gm.ca.v1.CaService/GetCertificate
```

**响应示例**:
```json
{
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "issuer": "GM CA",
  "not_before": "2024-01-01T00:00:00Z",
  "not_after": "2025-01-01T00:00:00Z",
  "status": "valid",
  "error_code": "",
  "error_message": ""
}
```

证书状态 `status` 可选值：`valid`、`revoked`、`expired`。


### 5. 获取 CRL（GetCrl）

获取指定 CA 的 CRL（DER 格式）：


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "issuer_cn": "GM CA"
  }' \
  localhost:50051 gm.ca.v1.CaService/GetCrl
```

返回 `crl_der`（二进制 DER），可配合 OpenSSL 查看：


```bash
# 保存 CRL 后查看内容
openssl crl -inform DER -in crl.der -text -noout
```

---

## 健康检查

gm-ca 内置 gRPC Health Checking Protocol 健康检查服务，可用于 Kubernetes/容器编排：


```bash
grpcurl -plaintext localhost:50051 /grpc.health.v1.Health/Check
```

响应 `{"status":"SERVING"}` 表示服务正常。


---

## 从代码调用（Rust）

```rust
use gm_ca::ca::v1::ca_service_client::CaServiceClient;
use tonic::transport::Channel;

let channel = Channel::from_static("http://[::1]:50051")
    .connect()
    .await?;

let mut client = CaServiceClient::with_interceptor(channel, |mut req| {
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", std::env::var("CA_AUTH_TOKEN")?).parse()?,
    );
    Ok(req)
});

let response = client
    .sign_certificate(tonic::Request::new(SignCertificateRequest {
        csr_pem: csr_pem.clone(),
        validity_days: 365,
    }))
    .await?;
```

## 数据库要求

gm-ca 支持 **PostgreSQL** 和 **SQLite** 双后端，通过 `DATABASE_URL` 环境变量区分：


- PostgreSQL：`postgres://user:password@host:5432/gm_ca`（推荐生产环境，支持 PG 14+）
- SQLite：`sqlite:gm_ca.db`（适用于开发/测试，仅支持内存模式 `sqlite::memory:`）

数据库 schema 由服务自动创建（`store.init_schema().await?`），但需确保连接用户有创建表和索引的权限。


> **安全提示**: CA 私钥文件权限应设为 `600`（仅所有者可读写）。若私钥不存在，需设置 `ALLOW_CA_KEY_GENERATION=true` 才能自动生成。

