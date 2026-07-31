# GM/TLS 生产部署指南

> 上次更新：2026-06-29
> 英文版：[deployment-guide.en.md](./deployment-guide.en.md)

本文档涵盖使用 SM2/SM3/SM4 密码算法（GM/T 0003/0004/0005-2012）部署 `gm-tls` 服务的完整指南，并满足 GM/T 0028-2014 和 GB/T 39786-2021 的安全要求。


## 目录

- [安全模型](#安全模型--security-model)
- [文件权限](#文件权限--file-permissions)
- [网络隔离](#网络隔离--network-isolation)
- [证书管理](#证书管理--certificate-management)
- [密钥轮换](#密钥轮换--key-rotation)
- [会话存储配置](#会话存储配置--session-store-configuration)
- [Docker 部署](#docker-部署--docker-deployment)
- [Systemd 服务](#systemd-服务--systemd-service)
- [健康检查与监控](#健康检查与监控--health-checks-and-monitoring)
- [审计日志](#审计日志--audit-logging)
- [事件响应](#事件响应--incident-response)

---

## 安全模型

### 威胁模型

|威胁|缓解措施|
|------------|---------------------|
| 私钥泄露| 文件权限、硬件绑定密钥、密钥轮换|
| 中间人攻击| SM2 证书链验证、域名校验|
| 重放攻击| 会话票据重放检测、单调 nonce 计数器|
| 降级攻击| 固定密码套件（仅 SM4-GCM）、无版本协商|
| 侧信道（时序）| 通过 `elliptic-curve` crate 实现恒定时间 SM2 操作|
| 拒绝服务| 连接限制、输入大小校验、超时|

### 密码模块自检（GM/T 0028-2014）

库在首次调用 `TlsConnector::new()` 或 `TlsAcceptor::new()` 时自动执行已知答案测试（KAT）。验证内容包括：


|测试项|说明|
|-----------------|------------------|
| SM2 密钥生成/签名/验签/加密/解密| 完整 SM2 算法测试|
| SM3 哈希| 哈希功能测试|
| SM4 ECB 加解密| 分组密码测试|
| SM4 GCM 加解密| AEAD 测试|
| SM2 密钥交换（KEX）| 共享密钥派生测试|
| 成对一致性测试| 签名/验签往返测试|
| 软件完整性检查| 代码段 SM3 哈希校验|
| 关键功能测试| 密钥加载测试|

自检失败时初始化返回错误，服务不得启动。这满足 GM/T 0028-2014 §7.2.4.1 的要求。


---

## 文件权限

### 证书和密钥文件

私钥**必须**设置受限权限。证书可以全局可读。


```bash
# 私钥：所有者只读（无组/其他访问权限）
chmod 400 /etc/gmtls/private/key.pem
chown root:root /etc/gmtls/private/key.pem

# 证书：所有者可读，必要时组可读
chmod 444 /etc/gmtls/certs/server.pem
chmod 444 /etc/gmtls/certs/ca.pem

# 目录：私钥材料仅所有者可访问
chmod 700 /etc/gmtls/private
chmod 755 /etc/gmtls/certs
```

### 配置文件

配置文件可能包含数据库凭证，需限制访问：


```bash
chmod 600 /etc/gmtls/config.toml
chown root:root /etc/gmtls/config.toml
```

### 运行时用户

使用专用非特权用户运行服务，而非 root：


```bash
useradd --system --no-create-home --shell /sbin/nologin gmtls
```

---

## 网络隔离

### 防火墙规则（iptables）

```bash
# 允许来自可信网络的 8443 端口入站 TLS 连接
iptables -A INPUT -p tcp --dport 8443 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -s 172.16.0.0/12 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP

# 限制新连接速率（防止 SYN 洪水）
iptables -A INPUT -p tcp --dport 8443 --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 --syn -j DROP
```

### 后端连接 TLS

生产环境中会话存储到 PostgreSQL 和 Redis 的连接应使用 TLS：


```rust
use gm_tls::SessionStoreConfig;

// PostgreSQL + TLS（默认失败关闭）
let pg_config = SessionStoreConfig::Postgres {
    url: "postgres://user:pass@host:5432/gm_ca".to_string(),
    fail_closed: true,   // 存储错误时拒绝票据
    use_tls: true,       // 启用 PgSslMode::VerifyFull
};

// Redis + TLS（默认失败关闭）
let redis_config = SessionStoreConfig::Redis {
    url: "redis://:password@host:6379".to_string(),
    fail_closed: true,   // 存储错误时拒绝票据
    use_tls: true,       // 使用 rediss:// 协议
};

// SQLite（本地开发）
let sqlite_config = SessionStoreConfig::Sqlite {
    path: "/tmp/sessions.db".to_string(),
    fail_closed: true,
};
```

### 容器网络策略

使用 Docker 部署时，将 TLS 服务与其他容器隔离：


```yaml
networks:
  frontend:
    # 面向互联网
  backend:
    internal: true  # 无外部访问
    # 仅数据库和 Redis
```

---

## 证书管理

### 证书生命周期

|阶段|操作|
|-----------|------------|
| 生成| 使用 GM/T 合规 CA（如 gm-ca）签发 SM2 证书|
| 分发| 通过配置管理或密钥管理器部署证书|
| 监控| 跟踪过期日期；在 30/14/7/1 天前告警|
| 轮换| 过期前轮换；与旧证书保持重叠期|

### 证书验证

库在每次 TLS 握手期间执行证书链验证：


- 链中每个证书的 SM2 签名验证
- 过期日期检查
- 可选的 CRL 撤销检查（通过 `with_crl_info()` 启用）

```rust
use gm_tls::{TlsConfig, HandshakeOptions, CrlInfo};
use std::fs;

let crl_pem = fs::read("/etc/gmtls/crl.pem")?;
let crl_info = CrlInfo::from_pem(&crl_pem)?;

let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?
    .with_crl_info(crl_info)
    .with_domain("service.example.com".to_string());
```

### 密钥管理

优先从密钥管理器或环境变量加载证书，而非文件系统：


```rust
use gm_tls::TlsConfig;
use std::env;

let cert_pem = env::var("GMTLS_CERT_PEM")?.into_bytes();
let key_pem = env::var("GMTLS_KEY_PEM")?.into_bytes();
let ca_pem = env::var("GMTLS_CA_PEM")?.into_bytes();

let config = TlsConfig::from_bytes(cert_pem, key_pem, ca_pem)?;
assert!(config.is_from_bytes());
```

生产环境密钥管理器推荐：


|平台|方案|
|-------------|--------------|
| HashiCorp Vault | 使用 `vault` crate 或 REST API |
| AWS Secrets Manager | 使用 `aws-sdk-secretsmanager`|
| Kubernetes Secrets | 作为环境变量挂载|

---

## 密钥轮换

### 会话票据密钥

定期轮换会话票据密钥（建议：每 24 小时）。`TicketKeySet` 支持多活动密钥的平滑轮换：


```rust
use gm_tls::gm::{TicketKey, TicketKeySet};
use rand::RngCore;

// 生成新密钥
let mut secret = [0u8; 32];
rand::thread_rng().fill_bytes(&mut secret);
let new_key = TicketKey {
    id: 42,  // 唯一 u8 标识符（票据首字节）
    secret,
};

// 添加新密钥同时保留旧密钥以实现零停机轮换
let key_set = TicketKeySet::new(new_key)
    .with_key(previous_key);  // 保留用于解密

// 迁移期后（如 2x 票据生命周期），移除旧密钥：
let mut key_set = key_set;
key_set.remove_key(old_id);
```

### 证书轮换

1. 在过期前 30 天生成新证书
2. 将新证书与现有证书一起部署
3. 更新 DNS/负载均衡器配置
4. 验证新证书正常工作（健康检查）
5. 所有连接耗尽后移除旧证书

### 密钥销毁

密钥不再需要时，库使用 `Zeroizing`（来自 `zeroize` crate）在 drop 时清除密钥材料。内存中密钥无需额外操作。文件系统密钥：


```bash
# 安全删除：取消链接前覆写
shred -u /etc/gmtls/private/old-key.pem
```

---

## 会话存储配置


```sql
-- 由 gm-tls 首次连接时自动创建
CREATE TABLE IF NOT EXISTS session_tickets (
    id BIGSERIAL PRIMARY KEY,
    ticket_hash VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tickets_hash ON session_tickets(ticket_hash);
CREATE INDEX IF NOT EXISTS idx_tickets_created ON session_tickets(created_at);
```

连接字符串（含 TLS）：

```
postgres://user:password@db-host:5432/gm_tls_sessions?sslmode=verify-full
```

定期清理（cron 或应用侧）：

```sql
DELETE FROM session_tickets WHERE created_at < NOW() - INTERVAL '24 hours';
```


Redis 会话通过 TTL 自动过期。无需手动清理。


连接字符串（含 TLS）：

```
rediss://:password@redis-host:6379
```

### 推荐会话存储生命周期

|使用场景|会话票据生命周期|
|-----------------|---------------------------------------|
| API 网关| 1 小时|
| Web 应用| 8 小时|
| 内部服务网格| 24 小时|
| IoT / 长连接| 7 天（带轮换） |

---

## Docker 部署

### Dockerfile（多阶段构建）

```dockerfile
FROM rust:1.85-slim-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p gm-tls

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --shell /sbin/nologin gmtls

COPY --from=builder /app/target/release/your-service /usr/local/bin/
USER gmtls
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/your-service"]
```


```yaml
version: "3.9"
services:
  gmtls:
    build: .
    ports:
      - "8443:8443"
    environment:
      - DATABASE_URL=postgres://user:pass@postgres:5432/gm_tls_sessions?sslmode=verify-full
      - REDIS_URL=rediss://:pass@redis:6379
      - RUST_LOG=info,gm_tls=debug
    volumes:
      - /etc/gmtls:/etc/gmtls:ro  # 只读证书挂载
    networks:
      - backend
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp

  postgres:
    image: postgres:17
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks:
      - backend
    restart: unless-stopped

  redis:
    image: redis:7
    command: redis-server --requirepass ${REDIS_PASSWORD} --tls-port 6379
    volumes:
      - redisdata:/data
    networks:
      - backend
    restart: unless-stopped

networks:
  backend:
    internal: true

volumes:
  pgdata:
  redisdata:
```

---

## Systemd 服务

```ini
[Unit]
Description=GM/TLS Service
Documentation=https://github.com/GM-Engineers/gm
After=network-online.target postgresql.service redis.service
Wants=network-online.target
Requires=postgresql.service redis.service

[Service]
Type=simple
User=gmtls
Group=gmtls
ExecStart=/usr/local/bin/gmtls-service
Restart=on-failure
RestartSec=5

# 安全加固
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/gmtls
ReadOnlyPaths=/etc/gmtls
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes

# 资源限制
LimitNOFILE=65536
LimitNPROC=512

# 环境变量
Environment=RUST_LOG=info,gm_tls=debug
EnvironmentFile=-/etc/gmtls/environment

[Install]
WantedBy=multi-user.target
```

启用并启动：


```bash
systemctl daemon-reload
systemctl enable gmtls
systemctl start gmtls
```

---

## 健康检查与监控

### 应用健康端点

实现健康检查端点，验证证书有效性和会话存储连接：


```rust
use gm_tls::TlsConfig;

async fn health_check() -> Result<(), Box<dyn std::error::Error>> {
    // 验证证书已加载且近期不会过期（30 天内）
    let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?;
    // 可添加应用级检查（如会话存储清理）
    Ok(())
}
```

### Prometheus 指标

`gm-tls` 库通过 `metrics` crate 发送指标。安装 Prometheus exporter：


```rust
use metrics_exporter_prometheus::PrometheusBuilder;
use gm_tls::describe_metrics;

// 注册指标描述
describe_metrics();

// 安装 Prometheus 记录器
PrometheusBuilder::new()
    .install_recorder()
    .expect("failed to install Prometheus recorder");
```

### 关键监控指标

|指标|告警阈值|严重程度|
|------------|------------------------|----------------|
| TLS 握手失败/分钟| > 5% of total | 警告|
| TLS 握手失败/分钟| > 10% of total | 严重|
| 证书剩余天数| < 30 days | 警告|
| 证书剩余天数| < 7 days | 严重|
| 会话存储连接错误| > 0 | 警告|
| 连接速率| > 80% of limit | 警告|
| 严重程度为 CRITICAL 的审计事件| > 0 | 立即响应|
| KAT 自检失败| > 0 | 严重|

### 日志配置

使用 `RUST_LOG` 配置结构化日志：


```bash
# 生产：info 级别，TLS 操作 debug
RUST_LOG=info,gm_tls=debug

# 调试：trace 级别
RUST_LOG=debug,gm_tls=trace

# 静默噪音依赖
RUST_LOG=info,gm_tls=debug,sqlx=warn,tokio=warn
```

### Docker 健康检查

```dockerfile
# 健康检查端点由应用指定；gm-tls 不提供 HTTP 服务器
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1
```

---

## 审计日志

### 配置

配置审计日志最低严重级别：


```rust
use gm_tls::audit::{AuditConfig, Severity, configure};

configure(AuditConfig {
    min_severity: Severity::Warning,  // 记录警告和严重事件
    include_location: true,
    service_id: "gmtls-production".to_string(),
});
```

### 日志收集

将审计日志转发到集中式日志收集系统（ELK、Loki、Splunk）。审计事件通过 `tracing` crate 发出，根据严重程度使用 `info`、`warn` 或 `error` 级别。


每个审计事件包含单调序列号。监控序列号检测日志篡改或丢失。


### 必需审计事件

根据 GM/T 0028-2014，确保记录以下事件：


|事件|说明|
|----------|-----------------|
| 认证成功/失败| 谁、何时、来源 IP |
| 会话创建/恢复/过期| 会话生命周期事件|
| 密钥生成/加载/销毁| 密钥管理事件|
| 证书验证结果| 验证结果详情|
| 配置变更| 变更前后状态|
| 安全事件| 降级尝试、无效签名等|

---

## 事件响应

### 私钥泄露

1. **撤销**证书（通过 CRL）立即生效
2. **轮换**所有会话票据密钥
3. **调查**访问日志中的未授权使用
4. **通知**受影响方（按安全策略）/ **Notify** affected parties per your security policy
5. **审计**所有有权限访问被泄露密钥的系统

### 疑似降级攻击

1. 检查审计日志中的 `DowngradeAttempt` 事件
2. 验证服务仅接受预期密码套件（SM4-GCM）
3. 审查网络抓包中的协议版本操纵
4. 确认攻击后屏蔽源 IP

### 证书过期紧急情况

1. 部署紧急证书（预先生成，离线存储）
2. 重启受影响服务
3. 验证健康检查通过
4. 安排根因分析

---

## 检查清单

- [ ] 私钥文件：`chmod 400`，root 所有
- [ ] 服务以非特权用户运行
- [ ] 网络防火墙限制对可信网络的访问
- [ ] PostgreSQL/Redis 在生产环境使用 TLS
- [ ] 证书监控过期（30 天告警）
- [ ] 会话票据密钥配置轮换
- [ ] 实现健康检查端点
- [ ] 导出 Prometheus 指标
- [ ] 审计日志配置为 Warning 级别或更高
- [ ] 应用 Systemd 服务加固
- [ ] Docker 容器以 `no-new-privileges` 和 `read_only: true` 运行
- [ ] 记录事件响应计划
- [ ] 服务启动时运行 KAT 自检
- [ ] 会话存储配置自动清理（prune_expired）
- [ ] 启用证书撤销检查（如需要）
- [ ] 会话存储配置 fail_closed 以确保安全
- [ ] 启用后端连接（PostgreSQL/Redis）TLS

---

## 参考资料

|标准|说明|
|-------------|-----------------|
| GM/T 0003-2012 | SM2 公钥密码算法|
| GM/T 0004-2012 | SM3 密码杂凑算法|
| GM/T 0005-2012 | SM4 分组密码算法|
| GM/T 0028-2014 | 密码模块安全技术要求|
| GB/T 38636-2020 | 传输层密码协议（TLCP）|
| GB/T 39786-2021 | 信息系统密码应用要求|
| RFC 5077 | 无服务器端状态的 TLS 会话恢复|
| RFC 5869 | 基于 HMAC 的提取和扩展密钥派生函数（HKDF）|
| RFC 8446 | 传输层安全（TLS）协议版本 1.3 |
