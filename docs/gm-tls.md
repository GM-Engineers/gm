# gm-tls 使用指南

> 上次更新：2026-06-30
> 英文版：[gm-tls.en.md](./gm-tls.en.md)


纯 Rust 实现的 GM/TLS 协议库，基于 SM2/SM3/SM4，提供完整的 TLS 握手和记录层加密。默认支持 mTLS 双向证书认证、会话恢复（RFC 5077）和 CRL 证书吊销检查。


## 添加依赖

```toml
[dependencies]
gm-tls = { path = "gm-tls" }

# 如需 Prometheus 指标支持
metrics-exporter-prometheus = "0.16"
```

---

## 两种 API 风格

gm-tls 提供两套 API：


|风格| API |适用场景|
|------------|-----|-------------------|
| 高层 API（推荐） | `TlsConfig` + `TlsConnector` / `TlsAcceptor` | 大多数应用，简单易用 |
| 低层 API | `connect_gm_rust` / `accept_gm_rust` | 需要精细控制握手过程 |

---

## 高层 API：GM/TLS 客户端

```rust
use gm_tls::{TlsConfig, TlsConnector};

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load(
        "certs/client.pem",       // 客户端证书（PEM）Client certificate (PEM)
        "certs/client-key.pem",  // 客户端私钥（PEM）Client private key (PEM)
        "certs/ca.pem",          // CA 证书（验证服务器证书）CA certificate (verifies server certificate)
    )?
    .with_domain("example.com".to_string())  // 验证服务器域名
    .with_alpn(vec!["http/1.1".to_string()]);

    let connector = TlsConnector::new(config)?; // 自动执行 GM/T 0028 KAT 自测试

    let tcp = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
    let mut tls = connector.connect(tcp).await?;

    // GmTlsStream 实现了 AsyncRead + AsyncWrite
    tls.write_application_data(b"GET /api HTTP/1.0\r\n\r\n").await?;
    let response = tls.read_application_data().await?;
    println!("Received: {:?}", response);

    Ok(())
}
```

`GmTlsStream<S>` 实现了 `tokio::io::AsyncRead` 和 `tokio::io::AsyncWrite`，可以直接当作普通 TCP 流使用。


---

## 高层 API：GM/TLS 服务器

```rust
use gm_tls::{TlsConfig, TlsAcceptor};

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load(
        "certs/server.pem",
        "certs/server-key.pem",
        "certs/ca.pem",
    )?
    .with_require_client_auth(true)  // 启用 mTLS，要求客户端证书
    .with_alpn(vec!["http/1.1".to_string()]);

    let acceptor = TlsAcceptor::new(config)?; // 自动执行 GM/T 0028 KAT 自测试

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    loop {
        let (tcp, addr) = listener.accept().await?;
        println!("Connection from {}", addr);

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let data = tls.read_application_data().await.unwrap_or_default();
                    let _ = tls.write_application_data(&data).await;
                }
                Err(e) => eprintln!("Handshake failed: {}", e),
            }
        });
    }
}
```

如需在握手后获取客户端证书信息：


```rust
// accept_with_client_cert 返回 (GmTlsStream, Option<客户端CN>, Option<SessionTicket>)
let (tls, client_cn, ticket) = acceptor.accept_with_client_cert(tcp).await?;
if let Some(cn) = client_cn {
    println!("Client CN: {}", cn);
}
```

---

## TlsConfig 配置项

```rust
use gm_tls::{TlsConfig, HandshakeOptions, SessionStoreConfig, TlsConnector, TlsAcceptor};

// 基础配置（自动执行 GM/T 0028 KAT 自测试）
let config = TlsConfig::load("cert.pem", "key.pem", "ca.pem")?;

// 从内存加载证书（适用于密钥管理系统）
let config = TlsConfig::from_bytes(cert_pem, key_pem, ca_pem)?;

// 验证服务器域名（不设置则跳过域名验证）
let config = config.with_domain("example.com".to_string());

// ALPN 协议列表
let config = config.with_alpn(vec!["http/1.1".to_string()]);

// 是否要求客户端证书（默认 true）
let config = config.with_require_client_auth(true);

// 会话恢复、CRL 检查等高级选项（见下文）
let config = config.with_handshake_options(opts);
```

---

## 会话恢复与会话存储

启用会话恢复后，客户端可以在后续连接中复用已建立的会话，减少握手时间。


### 客户端：发送 session ticket

```rust
use gm_tls::{TlsConfig, TlsConnector, HandshakeOptions, SessionTicket};

let config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?
    .with_domain("example.com")
    .with_handshake_options(HandshakeOptions {
        session_ticket: Some(your_saved_ticket), // 上次连接中收到的 ticket
        ..Default::default()
    });

let connector = TlsConnector::new(config)?;
let mut tls = connector.connect(tcp).await?;
// 若服务器接受 ticket 恢复，则无需完整握手
```

### 服务器：配置 session ticket 密钥

```rust
use gm_tls::{TlsConfig, TlsAcceptor, HandshakeOptions, TicketKey, TicketKeySet};

let current_key = TicketKey { id: 1, secret: generate_32_bytes() };
let key_set = TicketKeySet::new(current_key);

let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?
    .with_handshake_options(HandshakeOptions {
        session_ticket_key: Some(key_set),
        ..Default::default()
    });
```

### 会话存储后端（防重放）

会话恢复时需要存储已用 ticket 以防止重放攻击。支持四种后端：


```rust
use gm_tls::SessionStoreConfig;

// 内存存储（默认，单实例，无持久化，总是 fail-closed）
let config = SessionStoreConfig::InMemory;

// SQLite（本地持久化，单实例）
let config = SessionStoreConfig::Sqlite {
    path: "/tmp/sessions.db".to_string(),
    fail_closed: true,  // 错误时拒绝票证（安全默认）Reject tickets on error (secure default)
};

// PostgreSQL（多实例部署）
let config = SessionStoreConfig::Postgres {
    url: "postgres://user:password@localhost:5432/gm_ca".to_string(),
    fail_closed: true,
    use_tls: true,  // 生产环境启用 TLS
};

// Redis（高性能缓存）
let config = SessionStoreConfig::Redis {
    url: "redis://:password@localhost:6379".to_string(),
    fail_closed: true,
    use_tls: true,  // 生产环境启用 TLS
};
```

在服务器端启用：


```rust
let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?
    .with_handshake_options(HandshakeOptions {
        session_ticket_key: Some(key_set),
        session_store: Some(SessionStoreConfig::Redis {
            url: "redis://:password@localhost:6379".to_string(),
            fail_closed: true,
            use_tls: true,
        }),
        ..Default::default()
    });
```

---

## CRL 证书吊销检查

在握手过程中验证对端证书是否已被吊销：


```rust
use gm_tls::{TlsConfig, HandshakeOptions, CrlInfo};
use std::fs;

// 加载 CRL（PEM 格式）
// 对应代码: gm-tls/src/cert_verify.rs
let crl_pem = fs::read("crl.pem")?;
let crl_info = CrlInfo::from_pem(&crl_pem)?;

// 或 DER 格式

let config = TlsConfig::load("cert.pem", "key.pem", "ca.pem")?
    .with_handshake_options(HandshakeOptions {
        crl_info: Some(crl_info),
        ..Default::default()
    });
```

---

## Prometheus 指标

gm-tls 通过 `metrics` crate 暴露以下指标：


|指标名|类型|标签|说明|
|-------------------|-----------|-------------|------------------|
| `gmtls_handshakes_total` | Counter | `role`, `result` | 握手总次数 |
| `gmtls_handshake_duration_seconds` | Histogram | `role` | 握手耗时 |
| `gmtls_session_resumptions_total` | Counter | `result` | 会话恢复尝试次数 |
| `gmtls_bytes_transferred_total` | Counter | `role`, `dir` | 传输字节数 |
| `gmtls_cert_verification_errors_total` | Counter | `reason` | 证书验证错误次数 |

使用方式：


```rust
use gm_tls::describe_metrics;
use metrics_exporter_prometheus::PrometheusBuilder;

describe_metrics();
PrometheusBuilder::new().install().unwrap();
```

---

## 低层 API

适用于需要精细控制握手过程的场景：


```rust
use gm_tls::gm::{connect_gm_rust, accept_gm_rust, HandshakeOptions};

let tls_stream = connect_gm_rust(
    &cert_pem,
    &key_pem,
    &ca_pem,
    Some("example.com"),           // 域名
    &["http/1.1".to_string()],    // ALPN
    tcp_stream,
    &HandshakeOptions::default(),
).await?;
```

---

## 安全注意事项

|规则|说明|
|-----------|------------------|
| 私钥文件权限 | 设为 600，仅所有者可读 |
| 证书链验证 | 生产环境应验证完整链，不跳过中间 CA |
| 域名验证 | 客户端应使用 `.with_domain()` 验证服务器域名 |
| 序列号唯一性 | 每次加密使用唯一序列号，不重复使用 nonce |
| 会话票据密钥 | 定期轮换，建议不超过 24 小时 |
| KAT 自测试 | `TlsConnector::new()` / `TlsAcceptor::new()` 自动执行 |
| 错误码 | 使用 `TlsError::code()` 获取结构化 `ErrorCode` |

---

## GmSSL 互操作测试

gm-tls 通过 `tests/gmssl_interop_tests.rs` 与 GmSSL 实现完整的双向互操作验证。当前 **7/7 测试全部通过**。


### 测试覆盖

| 测试 | 方向 | 说明 |
|------|------|------|
| `test_gmssl_tls13_server_reachable` | → GmSSL | TCP 连接到 GmSSL TLS 1.3 server（端口 4434）|
| `test_gmssl_tls13_handshake` | → GmSSL | gm-tls 客户端 → GmSSL TLS 1.3 server 握手 |
| `test_gmssl_tls13_client_connects_to_gmtls_server` | ← GmSSL | GmSSL `tls13_client` 子进程 → gm-tls server（端口 4435）|
| `test_gmssl_tlcp_handshake` | → GmSSL | TCP 连接到 GmSSL TLCP server（端口 4433）|
| `test_loopback_handshake` | 自测 | TLS 1.3 自握手（无需外部服务）|
| `test_loopback_mutual_auth` | 自测 | TLS 1.3 双向认证 |
| `test_loopback_echo_large_data` | 自测 | TLS 1.3 大消息（64KB）往返 |

### GmSSL 服务器架构

GmSSL 的 `tls13_server` 和 `tlcp_server` 均为**单连接服务器**，处理一个连接后退出。通过 `launchd` plist 自动重启实现常驻：


```xml
<!-- ~/Library/LaunchAgents/com.gm.interop.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"...">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.gm.interop</string>
  <key>ProgramArguments</key>
  <array>
    <string>/tmp/gmssl-interop-daemon.sh</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict/>
</dict>
</plist>
```

守护进程脚本启动两个服务器：
- TLS 1.3 server：`gmssl tls13_server -port 4434 ...`（GmSSL 二进制路径 `/tmp/gmssl-install/bin/gmssl`）

### 运行测试

```bash
# 前提条件
# 1. GmSSL 已安装（路径 /tmp/gmssl-install/bin/gmssl）
# 2. launchd plist 已加载（launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.gm.interop.plist）
# 3. 服务器进程运行中（端口 4433、4434 监听）

# 运行所有互操作测试
TEST_GMSLL_PORT=4434 \
TEST_GMSLL_CERT=/tmp/gmssl-interop/testkey2.crt \
TEST_GMSLL_KEY=/tmp/gmssl-interop/testkey2.key \
cargo test -p gm-tls --test gmssl_interop_tests -- --include-ignored

# 环境变量
# TEST_GMSLL_PORT   GmSSL TLS 1.3 server 端口（默认 4434）
# TEST_GMSLL_CERT    证书 PEM 路径（默认 /tmp/gmssl-interop/testkey2.crt）
# TEST_GMSLL_KEY     密钥路径（默认 /tmp/gmssl-interop/testkey2.key）
# TEST_GMSLL_BIN     GmSSL 二进制路径（默认 /tmp/gmssl-install/bin/gmssl）
```

### TLCP 双证书配置

TLCP 需要双证书（签名证书 + 加密证书），证书链 PEM 格式为 `sign_cert + enc_cert + ca_cert`：


```bash
# 启动 TLCP server（launchd 自动重启）
/tmp/gmssl-install/bin/gmssl tlcp_server \
  -port 4433 \
  -cert /tmp/gmssl-interop/tlcp_chain.pem \
  -key /tmp/gmssl-interop/tlcp_keys.pem \
  -pass tlcp999 \
  -cipher_suite TLS_ECDHE_SM4_CBC_SM3
```
