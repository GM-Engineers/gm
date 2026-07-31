# gm-ca 证书授权服务详解 / gm-ca Certificate Authority Service Deep Dive

> 上次更新 / Last Updated: 2026-06-29
> 文档版本 / Doc Version: 2026-05-02
> 对应代码 / Corresponding Code: `gm-ca/src/` (~1,580 LOC)
> 阅读对象 / Target Audience: CA 服务维护者 / CA service maintainers
> 标准 / Standard: GM/T 0015-2012《基于 SM2 密码算法的数字证书格式》

---

## 1. 架构概览 / Architecture Overview

`gm-ca` 提供基于 SM2 的证书授权服务，支持：

`gm-ca` provides SM2-based certificate authority service, supporting:

| 功能 Feature | 说明 Description |
|------------|-----------------|
| **证书签发 / Certificate issuance** | 基于 CSR (Certificate Signing Request) |
| **证书吊销 / Certificate revocation** | CRL (Certificate Revocation List) 生成 |
| **证书查询 / Certificate query** | 按序列号、主题、有效期查询 / By serial, subject, validity |
| **gRPC API** | 高效的服务间通信 / Efficient inter-service communication |
| **GM/TLS 支持** | 自身使用国密 TLS 保护通信 / Uses GM/TLS to protect its own communication |

---

## 2. 服务启动流程 / Service Startup Flow

### 2.1 CA 密钥加载 / CA Key Loading

**文件 / File**: `gm-ca/src/main.rs`

```rust
fn load_or_generate_ca_key(
    key_path: &Path,
    allow_generation: bool,
) -> Result<Sm2KeyPair, Box<dyn std::error::Error>> {
    if key_path.exists() {
        // 安全检查: 验证文件权限 / Security check: verify file permissions
        let metadata = fs::metadata(key_path)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != KEY_FILE_MODE {  // 0o600
            return Err(format!(
                "CA key file has insecure permissions ({:#o}), requires {:#o}",
                mode, KEY_FILE_MODE
            ).into());
        }
        
        // 加载密钥 (支持加密 PEM) / Load key (supports encrypted PEM)
        let pem_str = fs::read_to_string(key_path)?;
        Sm2KeyPair::from_private_key_pem(&pem_str)
            .or_else(|_| Sm2KeyPair::from_encrypted_pem(&pem_str, password)?)
    } else if allow_generation {
        // 生成新密钥 / Generate new key
        let key = Sm2KeyPair::generate()?;
        let pem = key.private_key_pem()?;
        fs::write(key_path, &pem)?;
        fs::set_permissions(key_path, fs::Permissions::from_mode(KEY_FILE_MODE))?;
        Ok(key)
    } else {
        Err("CA key file does not exist".into())
    }
}
```

**安全要点 / Security Key Points:**

| 要点 Point | 说明 Description |
|----------|-----------------|
| 私钥文件权限 / Private key file permissions | `0o600` (仅所有者可读写 / Owner read/write only) |
| 密钥格式 / Key format | 支持加密 PEM (PBES2 AES-256-CBC) / Supports encrypted PEM |
| 生成警告 / Generation warning | 生成时发出警告，提示安全复制 / Warns and suggests secure copy |

---

## 3. 证书操作 / Certificate Operations

**文件 / File**: `gm-ca/src/cert.rs` (703 LOC)

### 3.1 证书结构 / Certificate Structure

```rust
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Certificate {
    pub id: i64,
    pub serial_number: String,      // 序列号 (十六进制 / Hexadecimal)
    pub certificate_pem: String,  // PEM 格式证书 / PEM format certificate
    pub issuer_cn: String,        // 颁发者 CN / Issuer CN
    pub subject_cn: String,       // 主题 CN / Subject CN
    pub not_before: DateTime<Utc>,// 生效时间 / Valid from
    pub not_after: DateTime<Utc>, // 过期时间 / Valid until
    pub revoked: bool,            // 是否吊销 / Whether revoked
    pub revocation_reason: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}
```

### 3.2 证书签发流程 / Certificate Issuance Flow

| 步骤 Step | 说明 Description |
|---------|-----------------|
| 1 | 接收 CSR (PEM 或 DER 格式) / Receive CSR (PEM or DER format) |
| 2 | 解码并验证 CSR / Decode and verify CSR |
| 3 | 解析 Subject CN / Parse Subject CN |
| 4 | 验证 SM2 签名 / Verify SM2 signature |
| 5 | 生成证书序列号（随机 20 字节）/ Generate serial number (random 20 bytes) |
| 6 | 构建 X.509 证书（含扩展）/ Build X.509 certificate (with extensions) |
| 7 | CA 签名（SM2 with SM3）/ CA sign (SM2 with SM3) |
| 8 | 存储数据库 / Store in database |
| 9 | 返回证书 PEM / Return certificate PEM |

### 3.3 证书吊销 (CRL) / Certificate Revocation (CRL)

```rust
pub async fn generate_crl(&self) -> Result<String, CaError> {
    // 查询所有已吊销证书 / Query all revoked certificates
    let revoked_certs = sqlx::query_as::<_, Certificate>(
        "SELECT * FROM certificates WHERE revoked = true"
    )
    .fetch_all(&self.db)
    .await?;
    
    // 构建 CRL / Build CRL
    let crl = build_crl(&self.ca_cert, &self.ca_key, &revoked_certs)?;
    
    // 更新 CRL 编号 / Update CRL number
    let crl_number = self.get_next_crl_number().await?;
    
    Ok(crl)
}
```

**CRL 结构 / CRL Structure:**

| 字段 Field | 说明 Description |
|----------|-----------------|
| version | v2 |
| signature | SM2withSM3 |
| issuer | CA Subject |
| thisUpdate | 当前时间 / Current time |
| nextUpdate | 下次更新时间 / Next update time |
| revokedCertificates | 已吊销证书列表 / Revoked certificates list |
| crlExtensions | CRLNumber / CRL number |

---

## 4. 认证授权 / Authentication and Authorization

**文件 / File**: `gm-ca/src/auth.rs` (148 LOC)

### 4.1 Bearer Token 认证 / Bearer Token Authentication

```rust
pub struct BearerTokenInterceptor {
    valid_tokens: Vec<String>,
}
```

### 4.2 权限控制 / Permission Control

| API | 权限要求 Permission |
|-----|-------------------|
| IssueCertificate | admin |
| RevokeCertificate | admin |
| GetCertificate | read |
| ListCertificates | read |
| GetCRL | public |

---

## 5. 数据库设计 / Database Design

**文件 / File**: `gm-ca/src/db.rs` (163 LOC)

### 5.1 表结构 / Table Structure

| 表名 Table Name | 说明 Description |
|---------------|-----------------|
| `certificates` | 证书表 / Certificates table |
| `crl_entries` | CRL 表 / CRL table |
| `audit_logs` | 审计日志表 / Audit log table |

### 5.2 索引 / Indexes

| 索引 Index | 说明 Description |
|-----------|-----------------|
| `idx_cert_subject` | 按主题查询 / Query by subject |
| `idx_cert_serial` | 按序列号查询 / Query by serial |
| `idx_cert_revoked` | 吊销证书查询 / Revoked certificate query |
| `idx_cert_not_after` | 过期检查 / Expiry check |

---

## 6. gRPC API

**文件 / File**: `gm-ca/build.rs` + `gm-ca/src/service.rs`

### 6.1 Proto 定义 / Proto Definition

| RPC 方法 Method | 输入 Input | 输出 Output |
|---------------|----------|----------|
| `IssueCertificate` | CSR (PEM/DER), validity_days, key_usage | certificate_pem, serial_number |
| `RevokeCertificate` | serial_number, reason | RevokeCertificateResponse |
| `GetCertificate` | serial_number | Certificate |
| `ListCertificates` | ListCertificatesRequest | Certificate 列表 |
| `GetCRL` | (empty) | crl_pem, crl_number |

---

## 7. 安全配置 / Security Configuration

### 7.1 环境变量 / Environment Variables

| 变量 Variable | 说明 Description | 默认值 Default | 安全要求 Security Requirement |
|-------------|-----------------|--------------|-----------------------------|
| `CA_KEY_PATH` | CA 私钥路径 / CA private key path | `ca_key.pem` | 权限 0o600 |
| `ALLOW_CA_KEY_GENERATION` | 允许生成新密钥 / Allow key generation | `false` | 生产环境必须 false / Must be false in production |
| `DATABASE_URL` | 数据库连接 / Database URL | - | PostgreSQL 或 SQLite，使用 SSL / PostgreSQL or SQLite with SSL |
| `AUTH_TOKENS` | Bearer Token 列表 / Token list | - | 强随机字符串 / Strong random strings |
| `METRICS_ADDR` | Prometheus 指标地址 / Metrics address | `[::1]:9000` | 内网访问 / Internal network only |
| `TLS_CERT` / `TLS_KEY` | GM/TLS 证书 / GM/TLS certificate | - | 有效证书 / Valid certificate |

---

## 8. 监控与告警 / Monitoring and Alerting

| 指标 Metric | 类型 Type | 说明 Description |
|----------|---------|-----------------|
| `gm_ca_cert_issued_total` | Counter | 签发证书总数 / Total certificates issued |
| `gm_ca_cert_revoked_total` | Counter | 吊销证书总数 / Total certificates revoked |
| `gm_ca_cert_active` | Gauge | 活跃证书数 / Active certificates |
| `gm_ca_issue_duration` | Histogram | 签发耗时 / Issuance duration |
| `gm_ca_crl_generated_total` | Counter | CRL 生成次数 / CRL generation count |

**建议告警规则 / Recommended alert rules:**

| 告警 Alert | 条件 Condition | 严重程度 Severity |
|----------|--------------|----------------|
| 证书即将过期 / Certificate expiring | < 30 天 | Warning |
| CRL 生成失败 / CRL generation failed | any | Critical |
| 数据库连接池耗尽 / DB pool exhausted | any | Critical |
| 异常高的吊销率 / Abnormal revocation rate | > 10%/day | Warning |

---

## 9. 证书生命周期管理 / Certificate Lifecycle Management

### 9.1 生命周期状态 / Lifecycle States

| 状态 State | 说明 Description |
|----------|-----------------|
| `Pending` | 提交 CSR，等待签发 / CSR submitted, awaiting issuance |
| `Active` | 正常服务状态，可验证、可信任 / Normal service, verifiable and trusted |
| `Revoked` | 加入 CRL，不再被信任 / Added to CRL, no longer trusted |
| `Renewed` | 已续期 / Renewed |
| `Expired` | 超过有效期 / Beyond validity period |
| `Rejected` | 审核拒绝 / Rejected |

---

## 10. 运维操作 / Operations

### 10.1 备份 / Backup

```bash
# 数据库备份 / Database backup
pg_dump -h localhost -U gm_ca gm_ca_db > backup_$(date +%Y%m%d).sql

# CA 密钥备份 (加密 / encrypted)
gpg --symmetric --cipher-algo AES256 ca_key.pem
```

### 10.2 故障排查 / Troubleshooting

```bash
# 查看日志 / View logs
journalctl -u gm-ca -f

# 检查数据库连接 / Check database connection
psql $DATABASE_URL -c "SELECT count(*) FROM certificates;"

# 验证证书 / Verify certificate
gmssl certparse -in cert.pem

# 测试 API / Test API
curl -H "Authorization: Bearer $TOKEN" \
     https://ca.example.com:8443/v1/certs/$SERIAL
```

---

## 更新记录 / Changelog

| 日期 Date | 版本 Version | 变更 Changes |
|----------|-------------|-------------|
| 2026-06-29 | 1.1 | ✅ 已双语化 / Bilingual completed |
| 2026-05-02 | 1.0 | 初始版本 / Initial version |
