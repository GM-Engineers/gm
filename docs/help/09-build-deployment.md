# 构建与部署指南 / Build and Deployment Guide

> 上次更新 / Last Updated: 2026-06-29
> 文档版本 / Doc Version: 2026-05-02
> 对应代码 / Corresponding Code: `gm`
> 阅读对象 / Target Audience: 运维人员、DevOps 工程师 / Operations personnel, DevOps engineers

---

## 1. 构建要求 / Build Requirements

### 1.1 工具链 / Toolchain

| 工具 Tool | 最低版本 Min Version | 说明 Description |
|---------|---------------------|------------------|
| Rust | 1.85+ | Edition 2024 |
| Cargo | 1.85+ | 随 Rust 安装 / Bundled with Rust |
| GmSSL | 3.1.1+ | SM9 FFI 后端需要 / Required for SM9 FFI backend |
| PostgreSQL | 14+ | CA 服务需要 / Required for CA service |
| Docker | 24+ | 容器化部署 / Containerized deployment |

### 1.2 系统依赖 / System Dependencies

**macOS:**

```bash
brew install gmssl postgresql
```

**Ubuntu/Debian:**

```bash
sudo apt-get update
sudo apt-get install -y libgmssl-dev libpq-dev pkg-config
```

**CentOS/RHEL:**

```bash
sudo yum install -y gmssl-devel postgresql-devel pkgconfig
```

---

## 2. 构建配置 / Build Configuration

### 2.1 Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "gm-crypto",
    "gm-sm9-rs",
    "gm-tls",
    "gm-tls/fuzz",
    "gm-ca",
    "gm-http-client",
]

[profile.release]
lto = true              # 链接时优化 / Link-time optimization
codegen-units = 1       # 单代码生成单元 (优化) / Single codegen unit (optimized)
strip = true            # 剥离符号表 / Strip symbols
```

### 2.2 构建命令 / Build Commands

```bash
# 开发构建 / Development build
cargo build

# 发布构建 (优化 / Optimized release build)
cargo build --release

# 构建特定 crate / Build specific crate
cargo build -p gm-crypto
cargo build -p gm-tls
cargo build -p gm-ca

# 构建 CA 服务二进制 / Build CA service binary
cargo build --release -p gm-ca --bin gm-ca-server

# 构建文档 / Build documentation
cargo doc --workspace --no-deps

# 检查 (不生成二进制 / Check without building)
cargo check --workspace
```

### 2.3 Feature 标志 / Feature Flags

| Feature | Crate | 说明 Description |
|---------|-------|----------------|
| `gmssl` | gm-sm9-rs | 启用 GmSSL FFI 后端 (推荐 / Recommended) |
| `pure-rust` | gm-sm9-rs | 纯 Rust 后端 (⚠️ 不安全 / ⚠️ Not secure) |
| `grpc` | gm-tls | 启用 gRPC 支持 / Enable gRPC support |
| `metrics` | gm-tls | 启用 Prometheus 指标 / Enable Prometheus metrics |

---

## 3. 运行测试 / Running Tests

```bash
# 完整测试套件 / Full test suite
cargo test --workspace

# 包含文档测试 / Include doc tests
cargo test --workspace --doc

# 特定测试 / Specific tests
cargo test -p gm-crypto sm3
cargo test -p gm-tls handshake

# 持续测试 (文件变化时自动运行 / Auto-run on file change)
cargo watch -x "test --workspace"
```

---

## 4. 部署架构 / Deployment Architecture

### 4.1 单机部署 / Single-Host Deployment

| 组件 Component | 端口 Port | 说明 Description |
|-------------|---------|----------------|
| gm-ca | 8443 | CA 服务 gRPC 端口 / CA service gRPC port |
| gm-ca | 9000 | Prometheus 指标端口 / Metrics port |
| PostgreSQL | 5432 | 数据库（仅内网访问 / Internal network only） |

### 4.2 高可用部署 / High-Availability Deployment

| 组件 Component | 说明 Description |
|-------------|-----------------|
| 负载均衡器 / Load balancer | Nginx/HAProxy，TLS 终止或透传 / TLS termination or passthrough |
| gm-ca 集群 / gm-ca cluster | 多实例自动扩缩容 / Auto-scaling multi-instance |
| PostgreSQL 主从 / PostgreSQL primary-replica | 主从复制保证数据安全 / Primary-replica for data safety |

---

## 5. Docker 部署 / Docker Deployment

### 5.1 Dockerfile

**文件 / File**: `Dockerfile.local`

```dockerfile
# 构建阶段 / Build stage
FROM rust:1.85-bookworm AS builder

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y libgmssl-dev libpq-dev
RUN cargo build --release -p gm-ca --bin gm-ca-server

# 运行阶段 / Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libgmssl3 libpq5 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /bin/bash gmca

COPY --from=builder /app/target/release/gm-ca-server /usr/local/bin/
COPY --from=builder /app/docker/entrypoint.sh /usr/local/bin/

USER gmca
EXPOSE 8443 9000

ENTRYPOINT ["entrypoint.sh"]
CMD ["gm-ca-server"]
```

### 5.2 Docker Compose

**文件 / File**: `docker/docker-compose.yml`

| 配置项 Config | 值 Value | 说明 Description |
|-------------|---------|----------------|
| 数据库 / Database | postgres://gmca:password@db:5432/gmca | PostgreSQL 连接字符串 / PostgreSQL connection string |
| CA 密钥路径 / CA key path | /secrets/ca_key.pem | 只读挂载 / Read-only mount |
| 指标端口 / Metrics port | 0.0.0.0:9000 | Prometheus 采集 / Prometheus scraping |
| 安全选项 / Security | `no-new-privileges:true` | 禁止提权 / Disable privilege escalation |
| 文件系统 / Filesystem | `read_only: true` | 只读根文件系统 / Read-only root filesystem |

### 5.3 部署命令 / Deployment Commands

```bash
# 构建镜像 / Build image
docker-compose -f docker/docker-compose.yml build

# 启动服务 / Start services
docker-compose -f docker/docker-compose.yml up -d

# 查看日志 / View logs
docker-compose -f docker/docker-compose.yml logs -f ca

# 停止服务 / Stop services
docker-compose -f docker/docker-compose.yml down
```

---

## 6. Kubernetes 部署 / Kubernetes Deployment

### 6.1 Deployment 配置 / Deployment Config

| 配置项 Config | 说明 Description |
|-------------|-----------------|
| 副本数 / Replicas | 3 |
| 资源请求 / Resource requests | 256Mi memory, 250m CPU |
| 资源限制 / Resource limits | 512Mi memory, 500m CPU |
| 安全上下文 / Security context | `runAsNonRoot: true`, `allowPrivilegeEscalation: false` |
| 只读根文件系统 / Read-only root fs | `readOnlyRootFilesystem: true` |
| 能力降级 / Capabilities drop | `ALL` |

### 6.2 Service 配置 / Service Config

| 端口 Port | 目标端口 Target Port | 说明 Description |
|---------|---------------------|-----------------|
| 8443 | 8443 | gRPC 端口 / gRPC port |
| 9000 | 9000 | Metrics 端口 / Metrics port |

---

## 7. 监控与告警 / Monitoring and Alerting

### 7.1 Prometheus 指标 / Prometheus Metrics

| 指标 Metric | 类型 Type | 说明 Description |
|----------|---------|-----------------|
| `gm_ca_cert_issued_total` | Counter | 证书签发总次数 / Total certificates issued |
| `gm_ca_cert_revoked_total` | Counter | 证书吊销总次数 / Total certificates revoked |
| `gm_ca_cert_active` | Gauge | 活跃证书数量 / Active certificates |
| `gm_ca_issue_duration` | Histogram | 签发延迟分布 / Issuance latency distribution |
| `gm_tls_handshake_total` | Counter | TLS 握手总次数 / Total TLS handshakes |
| `gm_tls_handshake_failed` | Counter | 握手失败次数 / Failed handshakes |

### 7.2 告警规则 / Alert Rules

| 告警名称 Alert Name | 条件 Condition | 严重程度 Severity |
|------------------|--------------|-----------------|
| HighCertRevocationRate | `rate(gm_ca_cert_revoked_total[1h]) > 0.1` | Warning |
| TLSHandshakeFailure | `rate(...) / rate(...) > 0.05` | Critical |
| DatabaseConnectionError | `pg_stat_activity_count{state="active"} < 1` | Critical |

---

## 8. 备份与恢复 / Backup and Recovery

### 8.1 数据库备份 / Database Backup

```bash
# 自动备份脚本 / Auto backup script
#!/bin/bash
BACKUP_DIR="/backup/gm-ca"
DATE=$(date +%Y%m%d_%H%M%S)

pg_dump -h localhost -U gmca gmca_db | gzip > "$BACKUP_DIR/backup_$DATE.sql.gz"

# 保留最近 30 天备份 / Keep last 30 days of backups
find "$BACKUP_DIR" -name "backup_*.sql.gz" -mtime +30 -delete
```

### 8.2 CA 密钥备份 / CA Key Backup

```bash
# 加密备份 CA 密钥 / Encrypt and backup CA key
tar czf - /secrets/ca_key.pem | gpg --symmetric --cipher-algo AES256 > ca_key_backup.tar.gz.gpg

# 存储到安全位置 / Store to secure location
aws s3 cp ca_key_backup.tar.gz.gpg s3://secure-backups/gm-ca/
```

### 8.3 恢复流程 / Recovery Process

| 步骤 Step | 操作 Action |
|---------|----------|
| 1 | 恢复数据库: `zcat backup_*.sql.gz \| psql ...` / Restore database |
| 2 | 恢复 CA 密钥: 解密并复制到 `/secrets/` / Restore CA key |
| 3 | 重启服务: `docker-compose restart ca` / Restart services |

---

## 9. 安全加固 / Security Hardening

### 9.1 主机安全 / Host Security

| 措施 Measure | 命令 Command |
|------------|------------|
| 更新系统 / Update system | `sudo apt-get update && sudo apt-get upgrade -y` |
| 防火墙 / Firewall | `sudo ufw default deny incoming` |
| GM/TLS 端口 / GM/TLS port | `sudo ufw allow 8443/tcp` |
| Metrics 端口 / Metrics port | `sudo ufw allow 9000/tcp`（限制 IP / restrict IP） |

### 9.2 容器安全 / Container Security

| 配置 Config | 值 Value | 说明 Description |
|-----------|---------|-----------------|
| `no-new-privileges` | `true` | 禁止容器内进程获取新特权 / Prevent privilege escalation |
| `read_only` | `true` | 只读根文件系统 / Read-only root filesystem |
| `cap_drop` | `ALL` | 丢弃所有 Linux 能力 / Drop all Linux capabilities |
| `cap_add` | `NET_BIND_SERVICE` | 仅绑定端口权限 / Only port binding capability |

### 9.3 网络安全 / Network Security

| 限制 Restriction | 命令 Command |
|----------------|------------|
| 数据库访问限制 / DB access restriction | `iptables -A INPUT -p tcp --dport 5432 -s 172.18.0.0/16 -j ACCEPT` |
| Metrics 端口限制 / Metrics port restriction | `iptables -A INPUT -p tcp --dport 9000 -s 10.0.0.10/32 -j ACCEPT` |

---

## 10. 故障排查 / Troubleshooting

### 10.1 常见问题 / Common Issues

| 问题 Problem | 原因 Cause | 解决 Solution |
|------------|----------|-------------|
| KAT 测试失败 / KAT test failed | 代码变更导致哈希不匹配 / Hash mismatch from code changes | 更新 `kat.rs` 预期值 / Update expected values in `kat.rs` |
| GmSSL 链接错误 / GmSSL link error | 库未安装或路径错误 / Library not installed or path incorrect | `export LD_LIBRARY_PATH=/usr/local/lib` |
| 数据库连接失败 / DB connection failed | 网络/认证问题 / Network/authentication issue | 检查 `DATABASE_URL` |
| 权限被拒绝 / Permission denied | 文件权限不正确 / Incorrect file permissions | `chmod 600 ca_key.pem` |
| 端口占用 / Port in use | 其他服务占用端口 / Other service using port | `lsof -i :8443` |

### 10.2 调试命令 / Debug Commands

```bash
# 查看服务状态 / Check service status
curl -H "Authorization: Bearer $TOKEN" http://localhost:8443/health

# 测试 TLS 握手 / Test TLS handshake
openssl s_client -connect localhost:8443 -CAfile ca.pem

# 查看证书信息 / View certificate info
gmssl certparse -in cert.pem

# 数据库查询 / Database query
psql $DATABASE_URL -c "SELECT * FROM certificates WHERE revoked = false;"

# 查看指标 / View metrics
curl http://localhost:9000/metrics
```

---

## 11. 升级指南 / Upgrade Guide

### 11.1 滚动升级 / Rolling Upgrade

```bash
# 1. 构建新版本 / Build new version
cargo build --release -p gm-ca

# 2. 逐个替换实例 (Kubernetes) / Replace instances one by one (Kubernetes)
kubectl set image deployment/gm-ca ca=gm-ca:v2.0.0
kubectl rollout status deployment/gm-ca

# 3. 验证 / Verify
kubectl get pods -l app=gm-ca
```

### 11.2 回滚 / Rollback

```bash
# Kubernetes 回滚 / Kubernetes rollback
kubectl rollout undo deployment/gm-ca

# Docker Compose 回滚 / Docker Compose rollback
docker-compose pull gm-ca:v1.0.0
docker-compose up -d
```

---

## 更新记录 / Changelog

| 日期 Date | 版本 Version | 变更 Changes |
|----------|-------------|-------------|
| 2026-06-30 | 1.2 | 添加 GmSSL 互操作测试守护进程说明 / Added GmSSL interop test daemon setup |
| 2026-06-29 | 1.1 | ✅ 已双语化 / Bilingual completed |
| 2026-05-02 | 1.0 | 初始版本 / Initial version |
