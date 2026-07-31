# gm-http-client 安全客户端详解 / gm-http-client Secure Client Deep Dive

> 上次更新 / Last Updated: 2026-06-29
> 文档版本 / Doc Version: 2026-05-02
> 对应代码 / Corresponding Code: `gm-http-client/src/` (~1,056 LOC)
> 阅读对象 / Target Audience: 客户端维护者 / Client maintainers

---

## 1. 架构概览 / Architecture Overview

`gm-http-client` 提供基于 GM/TLS 的 HTTPS 客户端，核心特性：

`gm-http-client` provides GM/TLS-based HTTPS client with core features:

| 特性 Feature | 说明 Description |
|------------|-----------------|
| **国密 TLS** | 使用 SM2/SM3/SM4 的 TLS 连接 / TLS connection using SM2/SM3/SM4 |
| **连接池** | 复用 TCP/TLS 连接，减少握手开销 / Reuse TCP/TLS connections to reduce handshake overhead |
| **SSRF 防护** | 阻止对私有 IP 的访问 / Block access to private IPs |
| **超时控制** | 连接/读取/写入超时 / Connection/read/write timeout |
| **响应限制** | 防止内存耗尽攻击 / Prevent memory exhaustion attacks |

---

## 2. 客户端设计 / Client Design

### 2.1 核心类型 / Core Types

```rust
/// GM/HTTP 客户端 / GM/HTTP Client
#[derive(Clone)]
pub struct GmHttpClient {
    tls_connector: TlsConnector,
}

/// HTTP 响应 / HTTP Response
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}
```

### 2.2 使用示例 / Usage Example

```rust
use gm_http_client::GmHttpClient;
use gm_tls::TlsConfig;

// 创建客户端 / Create client
let tls_config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?;
let client = GmHttpClient::new(tls_config)?;

// GET 请求 / GET request
let response = client.get("https://api.example.com/data").await?;
println!("Status: {}, Body: {:?}", response.status, response.body);

// POST 请求 / POST request
let response = client.post("https://api.example.com/data", b"payload").await?;
```

---

## 3. SSRF 防护 / SSRF Protection

**文件 / File**: `gm-http-client/src/client.rs`

### 3.1 阻止的 IP 范围 / Blocked IP Ranges

| 范围 Range | CIDR | 说明 Description |
|----------|------|-----------------|
| 10.0.0.0/8 | 10. | 私有网络 A 类 / Class A private network |
| 172.16.0.0/12 | 172.16. - 172.31. | 私有网络 B 类 / Class B private network |
| 192.168.0.0/16 | 192.168. | 私有网络 C 类 / Class C private network |
| 127.0.0.0/8 | 127. | Loopback / 本机服务 |
| 169.254.0.0/16 | 169.254. | Link-local / 自动配置地址 |
| ::1/128 | ::1 | IPv6 Loopback |
| fc00::/7 | fc00:, fd00: | IPv6 ULA / 唯一本地地址 |
| fe80::/10 | fe80: | IPv6 Link-local / 链路本地地址 |

### 3.2 TOCTOU 修复 / TOCTOU Fix

**原问题 / Original issue**: 验证和连接之间存在时间窗口，DNS 可能被劫持

**修复后 / After fix**: 验证后立即使用已解析的 IP 连接，不再二次 DNS 解析

```rust
// 修复前（存在 TOCTOU）/ Before fix (TOCTOU exists)
validate_address_for_ssrf(addr).await?;  // First DNS resolution
let tcp = TcpStream::connect(addr).await?; // Second DNS resolution

// 修复后（消除 TOCTOU）/ After fix (TOCTOU eliminated)
let addrs = validate_and_resolve(addr).await?; // Single resolution + validation
let tcp = TcpStream::connect(&addrs[0]).await?; // Direct use of validated address
```

---

## 4. 连接池 / Connection Pool

**文件 / File**: `gm-http-client/src/pool.rs` (497 LOC)

### 4.1 池设计 / Pool Design

```rust
pub struct ConnectionPool<S = GmTlsStream<TcpStream>> {
    // 按 host:port 分组的连接 / Connections grouped by host:port
    connections: Arc<RwLock<HashMap<String, Vec<PoolEntry<S>>>>>,
    max_per_host: usize,    // 每个 host 最大缓存连接数 / Max cached connections per host
    max_idle_time: Duration, // 最大空闲时间 / Max idle time
}
```

### 4.2 连接复用策略 / Connection Reuse Strategy

| 步骤 Step | 操作 Operation |
|---------|--------------|
| 1 | 请求到达，检查连接池 / Request arrives, check pool |
| 2 | 若存在空闲连接 → 健康检查 → 复用 / If idle connection exists → health check → reuse |
| 3 | 若无空闲连接 → 新建连接 → 执行 TLS 握手 → 加入池 / If no idle → new connection → TLS handshake → add to pool |
| 4 | 请求完成，连接返回池中 / Request complete, return connection to pool |

---

## 5. 安全限制 / Security Limits

### 5.1 限制参数 / Limit Parameters

| 限制 Limit | 值 Value | 说明 Description |
|-----------|---------|-----------------|
| 最大响应体 / Max response body | 10 MB | 防止内存耗尽 / Prevent memory exhaustion |
| 最大头部 / Max header | 64 KB | 防止头部攻击 / Prevent header attacks |
| 连接超时 / Connection timeout | 30 秒 / 30s | 可配置 / Configurable |
| 读取超时 / Read timeout | 30 秒 / 30s | 可配置 / Configurable |
| 写入超时 / Write timeout | 30 秒 / 30s | 可配置 / Configurable |
| 最大重定向 / Max redirects | 10 次 / 10 | 防止循环重定向 / Prevent redirect loops |

---

## 6. 错误处理 / Error Handling

```rust
pub enum HttpClientError {
    TlsError(String),
    ConnectionFailed(String),
    InvalidUrl(String),
    SsrfBlocked(String),        // SSRF 防护触发 / SSRF protection triggered
    ResponseTooLarge,          // 响应超过 10MB / Response exceeds 10MB
    Timeout,
    ParseError(String),
    IoError(String),
}
```

---

## 7. 性能调优指南 / Performance Tuning Guide

| 场景 Scenario | 建议配置 Recommended Config | 说明 Description |
|-------------|--------------------------|-----------------|
| 低并发 API 调用 / Low-concurrency API calls | `max_idle=2`, `max_age=60s` | 减少资源占用 / Reduce resource usage |
| 高并发微服务 / High-concurrency microservices | `max_idle=50`, `max_age=300s` | 提高复用率 / Improve reuse rate |
| 长连接推送 / Long-lived push connections | `max_idle=1`, `max_age=3600s` | 保持单连接长期存活 / Keep single connection alive |
| 网关代理 / Gateway proxy | `max_idle=100`, `max_age=120s` | 大量后端服务连接 / Many backend service connections |

---

## 8. 安全建议 / Security Recommendations

| 建议 Recommendation | 说明 Description |
|------------------|-----------------|
| 始终验证服务器证书 / Always verify server certificate | 使用 `with_domain()` 启用 SNI 验证 / Use `with_domain()` to enable SNI validation |
| 使用 mTLS | 客户端证书提供双向认证 / Client certificate provides mutual authentication |
| 限制响应大小 / Limit response size | 防止服务端发送超大响应导致 OOM / Prevent OOM from oversized responses |
| 启用 SSRF 防护 / Enable SSRF protection | 默认启用，不要禁用 / Enabled by default, don't disable |
| 设置超时 / Set timeouts | 防止慢速攻击 / Prevent slow attacks |
| 连接池大小 / Connection pool size | 根据并发量调整 `max_idle`，避免资源耗尽 / Adjust `max_idle` based on concurrency |
| 连接存活时间 / Connection lifetime | 建议 `max_age` 不超过 10 分钟 / Recommended `max_age` ≤ 10 minutes |

---

## 9. 常见问题排查 / Troubleshooting

| 问题 Problem | 原因 Cause | 解决 Solution |
|------------|----------|-------------|
| `SsrfBlocked` 错误 | 目标地址在私有 IP 范围内 / Target in private IP range | 检查 URL 是否正确 / Check if URL is correct |
| `ResponseTooLarge` 错误 | 响应体超过 10MB 限制 / Response exceeds 10MB | 使用流式接口，或增大限制 / Use streaming interface or increase limit |
| 连接池耗尽 / Pool exhausted | 并发请求超过 `max_idle` 设置 / Concurrent requests exceed `max_idle` | 增大 `max_idle` 或启用请求队列 / Increase `max_idle` or enable request queue |
| TLS 握手失败 / TLS handshake failed | 证书不匹配或不支持 GM/TLS / Certificate mismatch or GM/TLS not supported | 检查证书链，确认服务端支持国密 / Check cert chain, confirm server supports GM |

---

## 10. 测试 / Testing

```bash
# 单元测试 / Unit tests
cargo test -p gm-http-client

# 集成测试 (需要测试服务器 / requires test server)
cargo test -p gm-http-client -- --ignored
```

---

## 更新记录 / Changelog

| 日期 Date | 版本 Version | 变更 Changes |
|----------|-------------|-------------|
| 2026-06-29 | 1.1 | ✅ 已双语化 / Bilingual completed |
| 2026-05-02 | 1.0 | 初始版本 / Initial version |
