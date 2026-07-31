# gm-http-client

支持 GM/TLS 的 HTTP 客户端 - 基于 gm-tls 实现的安全 HTTP 客户端。

**[English Version](./README.en.md)**

## 功能特性

- **GM/TLS 加密**: 使用国密TLS协议保护通信安全
- **简洁 API**: 提供 `get()` 和 `post()` 简便方法
- **异步支持**: 基于 tokio 异步运行时
- **SSRF 防护**: 默认阻止对私有 IP、localhost 等内部资源的请求
- **连接池**: 支持 `ConnectionPool` 复用连接，提升性能

## 快速开始

```toml
[dependencies]
gm-http-client = "0.1"
```

```rust
use gm_http_client::{GmHttpClient, TlsConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?
        .with_domain("example.com".to_string());

    let client = GmHttpClient::new(config)?;

    // GET 请求
    let response = client.get("https://example.com/api").await?;
    println!("Status: {}", response.status);
    println!("Body: {:?}", response.body);

    // POST 请求
    let response = client.post("https://example.com/api/data", b"hello").await?;
    println!("Status: {}", response.status);

    Ok(())
}
```

## 连接池

使用 `ConnectionPool` 复用 GM/TLS 连接，减少握手开销：

```rust
use gm_http_client::{GmHttpClient, TlsConfig, ConnectionPool, PooledHttpClient};
use gm_tls::gm::GmTlsStream;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?
        .with_domain("example.com".to_string());

    let client = GmHttpClient::new(config)?;
    let pool = ConnectionPool::<GmTlsStream<TcpStream>>::new(10); // 最多每个 host 10 个连接
    let pooled_client = PooledHttpClient::new(client, pool);

    // 复用连接发起请求
    let response = pooled_client.get("https://example.com/api").await?;

    // 启动后台清理任务，移除空闲超时连接
    let handle = pooled_client.start_cleanup_task();

    Ok(())
}
```

**连接池参数：**
- `ConnectionPool::new(max_per_host)` — 每个 host 最大并发连接数
- `start_cleanup_task()` — 启动后台任务，自动清理空闲连接

## API 参考

### `GmHttpClient`

- `new(tls_config)` - 创建客户端实例
- `get(url)` - 发送 GET 请求
- `post(url, body)` - 发送 POST 请求

### `ConnectionPool<S>`

- `new(max_per_host)` - 创建连接池，指定每个 host 最大连接数
- `get_connection(host, port)` - 从池中获取连接（无连接时返回 None）
- `return_connection(host, port, stream)` - 将连接归还池中
- `cleanup()` - 手动触发清理空闲连接
- `len()` / `is_empty()` - 查询池状态

### `PooledHttpClient`

- `new(client, pool)` - 创建封装了连接池的 HTTP 客户端
- `get(url)` - 通过连接池发送 GET 请求
- `post(url, body)` - 通过连接池发送 POST 请求
- `start_cleanup_task()` - 启动后台清理任务，返回 `JoinHandle`

### `Response`

- `status` - HTTP 状态码
- `body` - 响应体（字节数组）

## 安全说明

- 客户端默认验证服务器证书
- 必须配置有效的 CA 证书
- 建议启用域名验证
- **SSRF 防护**：默认阻止私有 IP、保留地址、localhost 请求；如需禁用，请参考源码中 `is_private_ip()` 的实现逻辑
- **响应限制**：响应体最大 10 MB，响应头最大 64 KB

## 许可

MIT OR Apache-2.0 — 参见 [../LICENSE](../LICENSE)
