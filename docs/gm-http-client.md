# gm-http-client 使用指南

> 上次更新：2026-06-29
> 英文版：[gm-http-client.en.md](./gm-http-client.en.md)


基于 gm-tls 的 HTTPS 客户端，提供 GM/TLS 加密的 HTTP 请求能力，内置 SSRF 防护、连接池和响应大小限制。


## 添加依赖

```toml
[dependencies]
gm-http-client = { path = "gm-http-client" }
```

---

## 基本用法

```rust
use gm_http_client::{GmHttpClient, TlsConfig};

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load(
        "certs/client.pem",
        "certs/client-key.pem",
        "certs/ca.pem",
    )?
    .with_domain("example.com");

    let client = GmHttpClient::new(config)?;

    // GET 请求
    let response = client.get("https://example.com/api").await?;
    println!("Status: {}", response.status);
    println!("Body: {:?}", String::from_utf8_lossy(&response.body));

    // POST 请求
    let response = client.post("https://example.com/api/data", b"hello world").await?;
    println!("Status: {}", response.status);

    Ok(())
}
```

`Response` 结构

```rust
pub struct Response {
    pub status: u16,   // HTTP 状态码
    pub body: Vec<u8>, // 响应体（原始字节）
}
```

---

## 连接池

对于需要频繁发起 HTTPS 请求的场景，使用 `ConnectionPool` 复用 GM/TLS 连接，避免每次请求都进行完整的 TLS 握手。


```rust
use gm_http_client::{GmHttpClient, TlsConfig, ConnectionPool, PooledHttpClient};
use gm_tls::gm::GmTlsStream;
use tokio::net::TcpStream;

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load(
        "certs/client.pem",
        "certs/client-key.pem",
        "certs/ca.pem",
    )?
    .with_domain("example.com");

    let client = GmHttpClient::new(config)?;
    let pool = ConnectionPool::<GmTlsStream<TcpStream>>::new(10); // 每 host 最多 10 个连接
    let pooled_client = PooledHttpClient::new(client, pool);

    // 通过连接池发起请求（复用已有连接）
    let response = pooled_client.get("https://example.com/api").await?;

    // 启动后台清理任务，自动移除空闲超时连接
    let handle = pooled_client.start_cleanup_task();

    // 等待一段时间后取消清理任务（示例）
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    handle.abort();

    Ok(())
}
```

### 连接池 API

```rust
// 创建连接池，指定每个 host 最大并发连接数
let max_per_host: usize = 10;
let pool = ConnectionPool::<GmTlsStream<TcpStream>>::new(max_per_host);

// 获取连接（当前实现由 PooledHttpClient 内部管理）
// 直接使用 PooledHttpClient 更方便

// 启动后台清理任务（定期移除空闲连接）
let handle = pool_client.start_cleanup_task(); // -> JoinHandle<()>
```

---

## SSRF 防护

客户端内置 SSRF（服务器端请求伪造）防护，在 DNS 解析后验证目标地址，拒绝连接私有IP、回环地址和链路本地地址。


**被阻止的地址类型**:

|类型|示例|
|------|-------------------|
| 回环地址 | `127.0.0.1`, `::1` |
| 私有地址 | `10.x.x.x`, `172.16.x.x–31.x.x`, `192.168.x.x` |
| 链路本地 | `169.254.x.x`, `fe80::/10` |
| 被阻止的主机名 | `localhost`, `*.local`, `*.internal` |

> **注意**：
> - 防护在 DNS 解析**之后**生效
> - `validate_address_for_ssrf()` 返回已验证的 `SocketAddr`，直接用于连接，消除 TOCTOU 窗口
> - 若 DNS 解析返回公有 IP 但实际服务器为内部地址（DNS rebinding），当前版本不防护此场景

**响应限制**：
- 最大响应体：10 MB
- 最大响应头：64 KB

---

## 安全说明

|规则|说明|
|------|------------------|
| HTTPS 强制 | 仅接受 `https://` URL，拒绝 HTTP |
| 证书验证 | 必须配置有效的 CA 证书验证服务器身份|
| SSRF 防护 | 默认阻止私有 IP 和本地回环|
| DNS rebinding DNS rebinding | 当前版本不防护，需在应用层额外防护|
| TOCTOU | 已修复：验证和连接使用同一解析结果|
