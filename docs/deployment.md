# gm 项目部署指南

> 上次更新：2026-06-29
> 英文版：[deployment.en.md](./deployment.en.md)
> 版本：1.0 | 适用于：gm-tls / gm-kms v0.1.0

## 目录

1. [系统要求](#1-系统要求--system-requirements)
2. [环境变量配置](#2-环境变量配置--environment-variables)
3. [TLS 证书配置](#3-tls-证书配置--tls-certificate-configuration)
4. [数据库连接](#4-数据库连接--database-connection)
5. [密钥管理](#5-密钥管理--key-management)
6. [安全加固](#6-安全加固--security-hardening)
7. [监控与审计](#7-监控与审计--monitoring-and-audit)
8. [Docker 部署](#8-docker-部署--docker-deployment)
9. [故障排查](#9-故障排查--troubleshooting)

---

## 1. 系统要求

### 软件依赖

|依赖|最低版本|说明|
|----------------|---------------------|------------------|
| Rust | 1.85+ | 编译工具链|
| GmSSL | 3.1.1 | FFI 后端（可选，`gmssl` feature 启用）|
| PostgreSQL | 14+ | 密钥存储后端|
| Redis | 7+ | 缓存和速率限制|

### 硬件要求

|环境| CPU |内存|磁盘|
|-----------------|-----|-------------|----------|
| 开发 | 2核| 4GB | 20GB |
| 生产 | 4核+| 8GB+ | 100GB+ SSD |

### 操作系统

- macOS (aarch64, 开发/测试
- Windows (实验性，需 WSL2

---

## 2. 环境变量配置

### 核心配置

```bash
# 必需
export DATABASE_URL="postgres://kms:password@localhost:5432/kms"
export KMS_KEK="your-key-encryption-key-base64"  # 至少 32 字节

# Redis（可选但推荐）
export REDIS_URL="redis://localhost:6379"

# 开发模式（仅限开发环境！）
export KMS_DEV_MODE=1  # 启用开发 API Key
```

### TLS 配置

```bash
# 数据库连接 TLS
export KMS_DB_TLS_MODE="verify_ca"    # disabled | verify_ca | no_verify
export KMS_DB_TLS_CA_CERT="/etc/ssl/ca.pem"
export KMS_DB_TLS_CLIENT_CERT="/etc/ssl/client.pem"  # mTLS
export KMS_DB_TLS_CLIENT_KEY="/etc/ssl/client.key"    # mTLS
```

### 审计日志

```bash
# 审计日志完整性保护（生产环境强烈推荐）
export AUDIT_SIGNING_KEY="your-hmac-key-at-least-32-bytes"
```

### 安全配置

```bash
# 禁止生产环境使用
# KMS_DEV_MODE=1  # 生产环境绝对不要设置！
```

---

## 3. TLS 证书配置

### 3.1 GM TLS 证书

使用 `gm-ca` 生成国密 TLS 证书：


```bash
# 1. 生成 CA 密钥和证书
gm-ca ca-init --cn "GM Root CA" --days 3650

# 2. 签发服务器证书
gm-ca sign --cn "server.example.com" \
  --san "DNS:server.example.com" \
  --days 365 \
  --out server.pem

# 3. 签发客户端证书（mTLS）
gm-ca sign --cn "client@example.com" \
  --days 365 \
  --client \
  --out client.pem
```

### 3.2 证书格式要求

|要求|说明|
|----------------|------------------|
| 密钥格式| PKCS#8（明文）或 SEC1（`gm-crypto` 均支持）|
| 签名格式| DER 编码（自动转换为 64 字节原始格式）|
| SM2 签名 ID | 默认使用 `1234567812345678`（GM/T 标准），自动回退空 ID（OpenSSL 兼容）|

### 3.3 TLS 版本

|协议|版本|说明|
|--------------|-------------|----------|
| TLCP | 0x0101 | 国密 TLCP 传输层密码协议（GB/T 38636-2020）|
| GM/TLS 1.1 | 0x0101 | 本项目 GM/TLS 实现（与 TLCP 同版本号）|
| TLS 1.3 | 0x0303 | 标准 TLS 1.3 |

---

## 4. 数据库连接


```bash
# 基本连接
DATABASE_URL="postgres://user:pass@host:5432/kms"

# 带 TLS
DATABASE_URL="postgres://user:pass@host:5432/kms?sslmode=verify-ca&sslrootcert=/etc/ssl/ca.pem"
```

或使用 `BackendTlsConfig`：


```bash
export DATABASE_URL="postgres://user:pass@host:5432/kms"
export KMS_DB_TLS_MODE="verify_ca"
export KMS_DB_TLS_CA_CERT="/etc/ssl/ca.pem"
```


```bash
# 明文连接
REDIS_URL="redis://localhost:6379"

# TLS 连接（使用 rediss:// 协议）
REDIS_URL="rediss://localhost:6380"
```

### 4.3 连接池配置

|参数|默认值|建议生产值|
|---------------|--------------|--------------------------------|

---

## 5. 密钥管理

### 5.1 KEK（密钥加密密钥）

KEK 用于加密存储在数据库中的密钥材料：


```bash
# 生成 KEK（32 字节，Base64 编码）
openssl rand -base64 32
export KMS_KEK="<generated-key>"
```

⚠️ **安全要求**：
- KEK 必须至少 32 字节
- 生产环境禁止从文件或环境变量直接加载（应使用 HSM）
- 未设置 `KMS_KEK` 时，`KMS_DEV_MODE=1` 允许明文回退（仅开发）

### 5.2 SM9 主密钥

SM9 主密钥对通过 `Sm9MasterKeyStore` 管理：


|存储后端|说明|
|----------------------|-----------------|
| `EnvVarKekStore` | 从环境变量加载 KEK |
| `MemoryKekStore` | 内存中存储（测试用）|

### 5.3 密钥轮换

```rust
// 通过 key_rotation 模块执行
use gm_sm9_rs::key_rotation::KeyRotationManager;
```

当前密钥轮换支持 SM9 签名/加密密钥对的版本化轮换。


---

## 6. 安全加固

### 6.1 网络安全

|措施|状态|
|-------------|------------|
| 启用数据库 TLS（`KMS_DB_TLS_MODE=verify_ca`）| ✅ |
| 启用 Redis TLS（`rediss://`）| ✅ |
| 使用 mTLS 进行服务间认证| ✅ |
| 禁止公网暴露数据库端口| ⚠️ |
| 使用防火墙限制 KMS 服务端口访问| ⚠️ |

### 6.2 密码学安全

|措施|状态|
|-------------|------------|
| GCM nonce 重用运行时检测| ✅ |
| 恒定时间标量乘法（G1/G2）| ✅ |
| 恒定时间 `pow_mod`（费马小定理）| ✅ |
| KAT 自测试（SM2/SM3/SM4/SM9）| ✅ |
| 流量密钥 | ✅ |
| 审计日志 HMAC-SM3 完整性保护| ✅ |

### 6.3 访问控制

|措施|状态|
|-------------|------------|
| gRPC 认证（API Key ）| ✅ |
| 多租户隔离| ✅ |
| 密钥导出审批流程| ✅ |
| MFA TOTP 支持| ✅ |
| TOTP secret 信封加密| ✅ |
| 生产环境禁止 `KMS_DEV_MODE`| ⚠️ |

### 6.4 已知限制

|项目|状态|风险等级|
|---------|-----------|-------------------|
| `rand` 0.8.5 unsound | 已升级至 0.10 | 低|
| `rsa` Marvin Attack | 等待上游 sqlx 更新| 中|
| `atomic-polyfill` 未维护| 传递依赖| 低|
| SM9 `modinv` 大数限制| 返回 None，当前场景够用| 低|

---

## 7. 监控与审计

### 7.1 审计日志

审计日志输出到 `tracing` 框架，包含结构化 JSON：


```json
{
  "seq": 42,
  "timestamp": "2026-06-14T01:23:45Z",
  "event_type": "AuthSuccess",
  "severity": "Info",
  "actor": "client.cn=admin:client",
  "action": "TLS authentication completed successfully",
  "result": "SUCCESS",
  "integrity_hash": "a1b2c3..."
}
```

### 7.2 关键指标

|指标|说明|告警阈值|
|------------|-----------------|------------------------|
| `gmtls_handshake_total` | TLS 握手次数| - |
| `gmtls_handshake_errors` | 握手失败数| > 5/min |
| `gmtls_active_sessions` | 活跃 TLS 会话数| > 10000 |
| `kms_key_operations` | 密钥操作计数| - |
| `kms_auth_failures` | 认证失败数| > 10/min |

### 7.3 日志完整性验证

当配置了 `AUDIT_SIGNING_KEY` 时，可使用 `AuditEvent::verify_integrity()` 验证日志未被篡改。


---

## 8. Docker 部署

### 8.1 构建

```dockerfile
FROM rust:1.85-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p kms

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/kms /usr/local/bin/
EXPOSE 8443
ENTRYPOINT ["kms"]
```


```yaml
version: '3.8'
services:
  kms:
    build: .
    ports:
      - "8443:8443"
    environment:
      - DATABASE_URL=postgres://kms:password@postgres:5432/kms
      - REDIS_URL=redis://redis:6379
      - KMS_KEK=${KMS_KEK}
      - KMS_DB_TLS_MODE=verify_ca
      - KMS_DB_TLS_CA_CERT=/etc/ssl/ca.pem
      - AUDIT_SIGNING_KEY=${AUDIT_SIGNING_KEY}
    volumes:
      - ./certs:/etc/ssl:ro
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16
    environment:
      - POSTGRES_DB=kms
      - POSTGRES_USER=kms
      - POSTGRES_PASSWORD=password
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redisdata:/data

volumes:
  pgdata:
  redisdata:
```

---

## 9. 故障排查

### 9.1 常见问题

|症状|原因|解决方案|
|-------------|-----------|-----------------|
| `PoolTimedOut` | PostgreSQL 未启动或网络不通| 检查 PG 服务和连接字符串|
| `KMS_KEK not set` | 未配置密钥加密密钥| 设置 `KMS_KEK` 或 `KMS_DEV_MODE=1`|
| SM2 签名验证失败| 签名 ID 不匹配| 系统自动回退空 ID，检查证书|
| GmSSL FFI 加载失败| GmSSL 库未安装| 安装 GmSSL 3.1.1 或使用 `pure-rust`|
| Redis 连接超时| Redis 未启动| 检查 Redis 服务|

### 9.2 日志级别

```bash
RUST_LOG=gm_tls=info,kms=info    # 生产
RUST_LOG=gm_tls=debug,kms=debug  # 调试
RUST_LOG=gm_tls=trace             # 详细调试
```

### 9.3 健康检查

```bash
curl -s http://localhost:8443/health | jq .
```

---

## 附录 A：密码套件

|套件|值|协议|
|----------|---------|--------------|

## 附录 B：标准参考

|标准|说明|
|-------------|-----------------|
| GM/T 0028-2014 | 密码模块安全技术要求|
| GB/T 32905-2016 | SM3 密码杂凑算法|
| GB/T 32907-2016 | SM4 分组密码算法|
| GB/T 32918-2016 | SM2 椭圆曲线公钥密码算法|
| GB/T 38636-2020 | TLCP 传输层密码协议|
| GB/T 39786-2021 | 信息系统密码应用要求|
| GM/T 0044-2016 | SM9 标识密码算法|
| GM/T 0080-2020 | SM9 密码算法使用规范|
