# SPEC: PR-4.9 — gm-tls GmTlsConnector URI 端口 + IPv6 主机字面量处理 (P2-2 + P2-5)

- **目标编号**：PR-4.9（Batch 4 — gm-tls 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §四 P2-2 + P2-5`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md#L146, #L149)
- **范围**：`gm-tls/src/grpc.rs` 的 `GmTlsConnector` URI 解析路径
- **影响面**：纯公开 API 增量（新增 `with_default_port` builder）；现有 caller 不带 port + 设置 default 时行为不变

---

## 1. 问题陈述

`gm-tls/src/grpc.rs:284` 当前代码：

```rust
let port = uri.port_u16().unwrap_or(50051);
let addr = format!("{}:{}", host, port);
```

两个独立问题：

### 1.1 P2-2 端口硬编码（master plan §四 P2-2）

> `gm-tls/src/grpc.rs:256` | 客户端 `port_u16().unwrap_or(50051)` 硬编码默认端口，建议显式要求 URI 带端口或可配置

后果：
- URI 缺端口时**静默**回退到 50051，调用方拿到错连 / connection refused 仍不知道原因
- 大多数 gRPC 服务器（8433 / 50051 / 9443）都是非常规端口，50051 是 tonic 默认但实际部署千差万别
- 同一份代码换 deployment 就翻车

### 1.2 P2-5 IPv6 字面量需要括号（master plan §四 P2-5）

> `gm-tls/src/grpc.rs:258` | `format!("{}:{}", host, port)` 对 IPv6 字面量 host 需带括号，补 IPv6 端到端测试

后果：
- 当 `uri.host() == Some("::1")`（IPv6 loopback），拼成 `"::1:8080"` 被解析为 `host = ::1, port = 8080` 中的 host 取 IPv6 字面量后**多冒号**，实际行为是 fail connect
- IPv6 SAN 在 TLCP 部署里常见（`[2001:db8::1]:9443`），无法工作

### 1.3 改进建议依据

- P2-2: "显式要求 URI 带端口或可配置"
- P2-5: "补 IPv6 端到端测试"

---

## 2. Fix 策略

### 2.1 默认端口可配置 + 无端口显式失败

```rust
pub struct GmTlsConnector {
    inner: TlsConnector,
    /// Default port when the request URI omits one. `None` (the default)
    /// means "fail loudly" instead of silently falling back to 50051.
    /// PR-4.9 / P2-2.
    default_port: Option<u16>,
}

impl GmTlsConnector {
    pub fn new(config: crate::TlsConfig) -> Result<Self, crate::TlsError> { ... }

    /// Set a fallback port for URIs that omit one. Without this builder,
    /// a missing-port URI returns `Err("URI has no port and no default
    /// port was configured")` instead of silently dialing 50051.
    /// PR-4.9 / P2-2.
    pub fn with_default_port(mut self, port: u16) -> Self {
        self.default_port = Some(port);
        self
    }
}
```

### 2.2 URI host+port 解析：IPv6 括号 + `SocketAddr` 强类型

```rust
fn resolve_uri(uri: &http::Uri, default_port: Option<u16>) -> Result<SocketAddr, ResolveError> {
    let host = uri.host().ok_or(ResolveError::NoHost)?;
    let port = uri.port_u16()
        .or(default_port)
        .ok_or(ResolveError::NoPort { default_port })?;

    // tokio's TcpStream::connect accepts &str AND SocketAddr. We use
    // SocketAddr so the OS rejects ambiguous parses (e.g. literal
    // "::1" without brackets) at the I/O layer instead of falling
    // through to a 30-second connect timeout against the wrong peer.
    //
    // IPv6 literal in URI form: http://[::1]/foo. The http::Uri::host()
    // method strips the brackets, returning "::1". We re-add them when
    // handing the address to the OS to satisfy SocketAddr::from_str.
    let s = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    s.parse::<SocketAddr>()
        .map_err(|e| ResolveError::InvalidSocketAddr { host: host.to_string(), port, source: e })
}
```

### 2.3 接入点替换

替换 `GmTlsConnector::call` 中的 host/port 提取逻辑，使用 `resolve_uri` 统一处理。

### 2.4 向后兼容

- 现有 caller（`gm-ca`, `gm-tlcp`, `gm-http-client`, `gm-sm9-rs`）都不调用 `GmTlsConnector::new` 或 `.call` 直接（grep 验证）—— 唯一调用者就是 `tonic::transport::Endpoint::connect_with_connector(connector)`，它接受任何带 `tower::Service<Uri>` 的 connector
- 因此本次修改对**全部 gm 仓库 caller 是 API 兼容**的：未设置 `default_port` 的旧代码会从「静默 50051」变为「明确报错」，这是 RFC 6585 风格的 fail-fast 改进，不是 breaking change（用户从未显式选择 50051）
- 新增 `with_default_port(port)` 是纯增量

### 2.5 版本

`gm-tls/Cargo.toml`：patch bump（纯公开 API 增量；现有 URI 带端口的 caller 行为不变）。

---

## 3. Tests

### 3.1 单元测试（`gm-tls/src/grpc.rs::pr49_uri_resolve_tests`）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr49_uri_with_explicit_port` | `http://localhost:8080/` → `SocketAddr::V4("127.0.0.1:8080")` 或 hostname 路径 |
| T2 | `pr49_uri_without_port_fails_without_default` | `http://localhost/` + `default_port=None` → Err(NoPort) |
| T3 | `pr49_uri_without_port_uses_default` | `http://localhost/` + `default_port=Some(9443)` → port 9443 |
| T4 | `pr49_uri_port_overrides_default` | `http://localhost:8080/` + `default_port=Some(9443)` → port 8080 |
| T5 | `pr49_uri_ipv4_literal` | `http://127.0.0.1:8080/` → `SocketAddr::V4` |
| T6 | `pr49_uri_ipv6_literal_with_brackets_and_port` | `http://[::1]:8080/` → `SocketAddr::V6([::1]:8080)` |
| T7 | `pr49_uri_ipv6_literal_without_port_fails_without_default` | `http://[::1]/` + no default → Err(NoPort) |
| T8 | `pr49_uri_no_host_fails` | `http://:8080/` → Err(NoHost) |
| T9 | `pr49_uri_invalid_port_fails` | `http://localhost:99999/` → Err(port out of range) |

### 3.2 集成测试（`gm-tls/tests/gmssl_interop_tests.rs::pr49_*` 或新增测试文件）

| # | 名称 | 场景 |
| --- | --- | --- |
| T10 | `pr49_end_to_end_ipv4_with_default_port` | bind `127.0.0.1:0`，build GmTlsConnector with `with_default_port(<bound>)`, dial URI without port, handshake succeeds |
| T11 | `pr49_end_to_end_no_port_no_default_fails_fast` | bind `127.0.0.1:0`, dial URI without port + no default → returns error before TCP connect |
| T12 | `pr49_end_to_end_ipv6_loopback` | bind `[::1]:0`, dial `http://[::1]:<port>/` → handshake succeeds（可选，依赖 IPv6 环境）|

### 3.3 回归

`GmTlsConnector::new` + 完整 URI（含端口）的所有现有 caller 测试继续通过。

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy -p gm-tls --all-targets -- -D warnings
cargo +1.88 test -p gm-tls --all-targets
cargo +1.88 test -p gm-ca --all-targets
cargo +1.88 test -p gm-tlcp --all-targets
```

CI 含 GmSSL Interop / TLCP Interop。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 旧 caller 依赖隐式 50051 fallback | 仓库内 grep 已确认**无 caller**；生态外 caller 在 UPGRADE.md 加注释 |
| IPv6 测试在 IPv4-only CI 上失败 | T12 标记为 `#[ignore]`，本地可选运行 |
| `SocketAddr::from_str` 比 `format!("{}:{}", ...)` 慢 | 每次握手一次调用，可忽略；如需极致性能可在 cache |

---

## 6. Out of Scope

- 任何 caller 主动启用 `with_default_port` 的迁移（按需独立 PR）
- URI scheme 不是 `http` / `https` 的处理（保持现状）
- IPv6 zone-id（`fe80::1%eth0`）解析（保持现状）

---

## 7. 后续 PR 候选

- **PR-4.10**：gm-tls handshake 失败 metrics (P2-3)
- **PR-4.11**：gm-tls CRL grace period + session cache persistence
- **PR-4.12**：gm-kms WORM logger HMAC key 独立路径 (P2-6)
- **PR-4.13**：gm-ca rate limit per-caller (P2-7)
