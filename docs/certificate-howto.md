# 证书操作指南

> 上次更新：2026-06-29
> 英文版：[certificate-howto.en.md](./certificate-howto.en.md)

本文档介绍如何使用本项目套件生成、验证和管理 SM2 证书。


---

## 证书格式

gm-tls 期望 PEM 格式的证书和私钥。


### 证书（PEM）

```
-----BEGIN CERTIFICATE-----
<base64 编码的 DER 内容
-----END CERTIFICATE-----
```

### 私钥（SEC1 或 PKCS#8）

```
-----BEGIN EC PRIVATE KEY-----
<base64 编码的 SEC1 内容
-----END EC PRIVATE KEY-----

# 或 PKCS#8（加密或不加密）
-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----
```

> **重要**：生产环境中私钥文件权限必须设为 `600`（仅所有者可读写）。


---

## 方式一：使用 GmSSL CLI 生成测试证书（无需 gm-ca）


适用于本地开发和测试，不需要运行任何服务。


> ⚠️ GmSSL 3.x CLI 与 OpenSSL 命令行不兼容，不支持 `openssl ecparam`、`openssl req` 等子命令。请使用 `gmssl` 命令。


### 安装 GmSSL


```bash
brew install gmssl

# Linux（从源码编译）
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL
./config && make && sudo make install
```

### 生成 SM2 密钥对


```bash
# 生成 SM2 密钥对（输出 PEM 格式私钥）
gmssl sm2keygen -out ca-key.pem

# 查看公钥
gmssl sm2sign -help  # 查看签名命令帮助
```

> **注意**：GmSSL 3.x CLI 功能有限，不直接支持证书签发（`req`/`x509` 子命令）。如需完整的证书管理，请使用方式二（gm-ca 服务）或使用 GmSSL 2.x（支持 OpenSSL 兼容命令行）。


---

## 方式二：通过 gm-ca 服务签发证书


适用于正式环境，支持证书的集中管理和 CRL 颁发。


### 前提条件


|条件|说明|
|----------------|------------------|
| PostgreSQL 数据库| 启动数据库服务|
| gm-ca-server | 运行 CA 服务) |
| CSR 文件| PEM 格式的证书签名请求|

### 通过 gRPC 签发


#### 步骤 1：生成 CSR


使用 gm-crypto 生成密钥对并创建 CSR：


```rust
// 生成密钥对
let key_pair = Sm2KeyPair::generate().unwrap();

// 注意：gm-crypto 不提供 CSR 生成 API
// CSR 需要手动构建 ASN.1 DER 结构或使用第三方 crate（如 x509-cert）
// 也可以直接将密钥对传给 gm-ca 的 SignCertificate gRPC 接口
```

#### 步骤 2：调用 gRPC 签发


```bash
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d "{
    \"csr_pem\": \"$(cat client.csr | tr '\n' '\\n')\",
    \"validity_days\": 365
  }" \
  localhost:50051 gm.ca.v1.CaService/SignCertificate
```

响应中的 `certificate_pem` 即为签发的证书。


#### 步骤 3：验证证书


```bash
# 使用标准 OpenSSL 查看证书内容（验证和查看不涉及国密算法，OpenSSL 可用）
openssl x509 -in client-cert.pem -noout -text
```

---

## 方式三：使用 gm-ca CaSigner 签发证书


gm-ca 的 `CaSigner` 可以直接签发 CSR：


```rust
use gm_ca::cert::CaSigner;
use gm_crypto::sm2::Sm2KeyPair;

let ca_key = Sm2KeyPair::generate().unwrap();
let signer = CaSigner::new(ca_key, "GM CA");

// 签发 CSR（返回序列号和证书 PEM）
let (serial_hex, cert_pem) = signer.sign_csr(&csr_pem_bytes, 365).unwrap();
```

> **注意**：`CaSigner` 不提供 `generate_ca_cert` 方法。如需自签名 CA 证书，需手动构建或通过 gRPC API 启动 gm-ca 服务。


---

## 验证证书链


### 使用 OpenSSL


```bash
# 验证完整链（服务器证书 → 中间 CA → 根 CA）
openssl verify -CAfile ca-cert.pem -partial_chain server-cert.pem

# 导出并查看证书链
openssl storeutl -noout -text -certfile server-cert.pem
```

### 使用 gm-tls 验证


```rust
use gm_tls::cert_verify::validate_cert_pem;
use time::OffsetDateTime;

let result = validate_cert_pem(
    &server_cert_pem,             // 证书 PEM 字节
    OffsetDateTime::now_utc(),    // 当前时间
    Some("server.example.com"),   // 可选：期望域名
);
assert!(result.is_ok());
```

> **注意**：`validate_cert_pem` 是同步函数，签名 `(cert_pem: &[u8], now: OffsetDateTime, expected_domain: Option<&str>)`，不验证 CA 链（仅验证单证书有效期和域名）。


---

## 查看证书信息


```bash
# 标准 OpenSSL 可查看 SM2 证书的基本信息（不涉及签名验证）
openssl x509 -in cert.pem -noout -subject -issuer -dates
openssl x509 -in cert.pem -noout -serial

# 转换 PEM → DER
openssl x509 -in cert.pem -outform DER -out cert.der

# 转换 DER → PEM
openssl x509 -in cert.der -inform DER -out cert.pem
```

> ⚠️ `openssl x509 -fingerprint -sm3` 在标准 OpenSSL 中不可用，SM3 指纹需使用 GmSSL 或 gm-crypto 计算。


---

## 私钥格式转换


```bash
openssl pkcs8 -topk8 -nocrypt -in ca-key.pem -out ca-key-pkcs8.pem

openssl ec -in ca-key-pkcs8.pem -out ca-key.pem

# 查看私钥信息（不暴露私钥内容）
openssl ec -in ca-key.pem -text -noout
```

> ⚠️ 标准 OpenSSL 的 `pkcs8 -v2 sm4` 不支持 SM4 加密。私钥加密请使用 gm-crypto 的 PBES2 实现。

