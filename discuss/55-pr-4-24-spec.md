# PR-4.24 — TLCP Handshake Timeout (Slowloris-style DoS 防护, gm-tlcp mirror of PR-4.23)

> Status: **PROPOSED**
> Crates: `gm-tlcp`
> Author: gm-tls PR batch
> Target version: gm-tlcp 0.7.2 → 0.7.3 (patch bump)
> Spec version: 1.0
> Generated: 2026-09-24

---

## 0. 上下文

PR-4.23 (75e7300) 给 `gm-tls` 加了 wall-clock handshake timeout (`HandshakeOptions::handshake_timeout`, 默认 30s)。PR-4.23 SPEC §0 已经预告：`gm-tlcp` 同步放到 PR-4.24。

本文是该预告的实现 SPEC。

---

## 1. Background

`gm-tlcp` 的 4 个公开握手入口：

| 入口 | 路由 |
|------|------|
| `TlcpConnector::connect` | 双 cert → `connect_with_certs`; 否则 → deprecated simulated `connect_tlcp` |
| `TlcpConnector::connect_with_certs` | 直接实现（PR-4.22 metrics wrap 只在外层 `connect`） |
| `TlcpAcceptor::accept` | 双 cert or RSA-only → `accept_with_certs`; 否则 → deprecated simulated `accept_tlcp` |
| `TlcpAcceptor::accept_with_certs` | 直接实现 |

外层 `connect` / `accept` 已经是 PR-4.22 的 metrics wrap点（emit `gmtlcp_handshake_errors_total{role, code}`）。本次 PR 在这两个 wrap 点基础上叠加 `tokio::time::timeout`。

### 1.1 与 PR-4.23 的设计差异

PR-4.23 (gm-tls) 把 timeout 字段塞进 `HandshakeOptions` 聚合结构。`gm-tlcp` 没有这个聚合 —— `TlcpConnector` / `TlcpAcceptor` 用直接字段（每个 `with_*` builder 单独 set 一个字段）。所以：

- **本次给 `TlcpConnector` 直接加 `handshake_timeout: Duration` 字段 + 对应 builder**
- **本次给 `TlcpAcceptor` 直接加 `handshake_timeout: Duration` 字段 + 对应 builder**
- 这与 gm-tlcp 现有架构一致（参考 `crl_info`、`session_ticket_fail_closed` 等字段的设计模式 —— 实际是 PR-4.13/4.20 在 gm-tls 用的 `HandshakeOptions` 聚合，但 gm-tlcp 历史没做这个聚合）

如果将来 gm-tlcp 也演进 `HandshakeOptions` 聚合结构，timeout 字段可一并迁入（向后兼容；旧字段标 deprecated）。

### 1.2 风险

- 攻击者开 TCP 连接后不发后续字节，server 一直 block 在 `AsyncReadExt::read` —— Slowloris-style DoS
- gm-tlcp 默认值需要 30s（与 gm-tls 一致），保证 SM2 ECDHE + KDF + 双 cert 验签都有充分时间

---

## 2. Design

### 2.1 `TlcpConnector` 字段

```rust
/// PR-4.24: wall-clock timeout for the TLCP client
/// handshake. Default: 30 seconds (mirror of PR-4.23).
/// Set via
/// [`TlcpConnector::with_handshake_timeout`]. Pass
/// `Duration::ZERO` to disable (tests only).
pub handshake_timeout: Duration,
```

`impl Default for TlcpConnector` (即 `Self::new()`) 初始化为 `Duration::from_secs(30)`。

### 2.2 `TlcpAcceptor` 字段

```rust
/// PR-4.24: wall-clock timeout for the TLCP server
/// handshake. Default: 30 seconds. Set via
/// [`TlcpAcceptor::with_handshake_timeout`]. Pass
/// `Duration::ZERO` to disable (tests only).
pub handshake_timeout: Duration,
```

`impl Default for TlcpAcceptor` (即 `Self::new()`) 初始化为 `Duration::from_secs(30)`。

### 2.3 Builder

```rust
// TlcpConnector::with_handshake_timeout
pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
    self.handshake_timeout = timeout;
    self
}

// TlcpAcceptor::with_handshake_timeout  
pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
    self.handshake_timeout = timeout;
    self
}
```

### 2.4 Timeout 内部 helper

`tlcp/mod.rs` 顶部：

```rust
/// PR-4.24: wrap `inner` in `tokio::time::timeout` if
/// `timeout` is non-zero. Returns a
/// `TlcpError::HandshakeFailed("handshake timeout after
/// Ns ...")` error when the deadline expires. Pass
/// `Duration::ZERO` to disable.
async fn with_handshake_timeout<F, T>(
    timeout: Duration,
    role: &str,
    inner: F,
) -> Result<T, TlcpError>
where
    F: std::future::Future<Output = Result<T, TlcpError>>,
{
    if timeout.is_zero() {
        return inner.await;
    }
    match tokio::time::timeout(timeout, inner).await {
        Ok(result) => result,
        Err(_elapsed) => Err(TlcpError::HandshakeFailed(format!(
            "handshake timeout after {}s ({})",
            timeout.as_secs(),
            role,
        ))),
    }
}
```

### 2.5 Wrap 点

#### `TlcpConnector::connect` —— 把现有 metrics wrap 替换为 timeout + metrics 二合一 wrap

Before:
```rust
let result = if self.server_sign_pubkey.is_some() {
    self.connect_with_certs(transport).await
} else {
    #[allow(deprecated)]
    connect_tlcp(transport, &self.session_cache).await
};
if let Err(ref e) = result {
    crate::metrics::record_handshake_error_code("client", e.code());
}
result
```

After:
```rust
let inner = async {
    if self.server_sign_pubkey.is_some() {
        self.connect_with_certs(transport).await
    } else {
        #[allow(deprecated)]
        connect_tlcp(transport, &self.session_cache).await
    }
};
let result = with_handshake_timeout(self.handshake_timeout, "client", inner).await;
if let Err(ref e) = result {
    crate::metrics::record_handshake_error_code("client", e.code());
}
result
```

#### `TlcpAcceptor::accept` —— 同样改造

Before:
```rust
let result = if (self.sign_cert.is_some() && self.sign_key.is_some())
    || (self.rsa_cert.is_some()
        && self.rsa_signer.is_some()
        && self.rsa_decryptor.is_some())
{
    self.accept_with_certs(transport).await
} else {
    #[allow(deprecated)]
    accept_tlcp(transport, &self.session_cache).await
};
if let Err(ref e) = result {
    crate::metrics::record_handshake_error_code("server", e.code());
}
result
```

After:
```rust
let inner = async {
    if (self.sign_cert.is_some() && self.sign_key.is_some())
        || (self.rsa_cert.is_some()
            && self.rsa_signer.is_some()
            && self.rsa_decryptor.is_some())
    {
        self.accept_with_certs(transport).await
    } else {
        #[allow(deprecated)]
        accept_tlcp(transport, &self.session_cache).await
    }
};
let result = with_handshake_timeout(self.handshake_timeout, "server", inner).await;
if let Err(ref e) = result {
    crate::metrics::record_handshake_error_code("server", e.code());
}
result
```

注意：capture `self` by ref 的 closure 在 async block 里需要 lifetime。在 `async {}` 里编译器会推断；这里 `transport: S` 也是 owned。无需 `move`。

### 2.6 为什么不在 `connect_with_certs` / `accept_with_certs` 加 wrap

这两个是 `connect` / `accept` 的 inner path。外层 wrap 已经覆盖。重复 wrap 会引入双重 metrics emission（PR-4.22 是单 emit 设计）。保持单一 wrap 点便于审计。

### 2.7 Backward Compatibility

- 新字段 `handshake_timeout: Duration` 默认 30s —— 与 PR-4.23 一致
- 公开 builder 名称 `with_handshake_timeout` —— 与 PR-4.23 一致
- 老用户依赖无限等待可显式 `with_handshake_timeout(Duration::ZERO)` 或 `Duration::from_secs(3600)`
- `TlcpConnector::new()` 与 `TlcpAcceptor::new()` 都返回带默认 30s timeout 的实例 —— 与 PR-4.23 行为对齐

### 2.8 为什么不把 timeout 直接交给 TCP 层

- 用户可能用自己的 transport (`TcpStream` / `UnixStream` / in-memory `tokio::io::duplex`)，TCP 层 timeout 配置不归本 crate 管
- 应用层 timeout 更精确 —— 只计时握手阶段
- 与 gm-tls PR-4.23 解释对齐

---

## 3. Test Plan

### 3.1 单元测试

```rust
#[cfg(test)]
mod pr424_handshake_timeout_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn default_tlcp_connector_has_30s_timeout() {
        let c = TlcpConnector::new();
        assert_eq!(c.handshake_timeout, Duration::from_secs(30));
    }

    #[test]
    fn default_tlcp_acceptor_has_30s_timeout() {
        let a = TlcpAcceptor::new();
        assert_eq!(a.handshake_timeout, Duration::from_secs(30));
    }

    #[test]
    fn tlcp_connector_with_handshake_timeout_propagates() {
        let c = TlcpConnector::new().with_handshake_timeout(Duration::from_secs(7));
        assert_eq!(c.handshake_timeout, Duration::from_secs(7));
    }

    #[test]
    fn tlcp_acceptor_with_handshake_timeout_propagates() {
        let a = TlcpAcceptor::new().with_handshake_timeout(Duration::from_secs(11));
        assert_eq!(a.handshake_timeout, Duration::from_secs(11));
    }
}
```

### 3.2 Loopback 集成测试（gm-tlcp/tests/loopback.rs 或新文件 `tests/handshake_timeout.rs`）

mirror gm-tls PR-4.23 的两个测试：

1. `pr424_accept_times_out_on_slow_client` —— 用 `tokio::io::duplex`，client 发 1 字节后 stall，server 端 1s timeout 触发。断言 `HandshakeFailed("handshake timeout after 1s ...")` 且 elapsed ≈ 1s
2. `pr424_zero_timeout_disables_check` —— `Duration::ZERO` 不阻断正常握手

需要给 `TlcpAcceptor` 配置 `with_dual_certs`（PR-4.13/4.18 已支持），构造合法的生产握手路径。

### 3.3 已有 loopback 测试不得破坏

`gm-tlcp` 的 ~16 个现有 loopback 测试（`tests/loopback.rs`）都必须通过 —— 正常握手远小于 30s 默认 timeout。

### 3.4 Metrics 接入检查

write integration：触发 timeout 后用 `metrics::with_local_recorder` 检查 `gmtlcp_handshake_errors_total{role="server",code="HandshakeFailed"}` 增加 1（PR-4.22 已在 `accept` 处 emit，PR-4.24 timeout 错误自然被该 emit 覆盖）。

---

## 4. Rollout

1. SPEC 已写（本文件）
2. 本地 `cargo build -p gm-tlcp` 必须先绿
3. 代码改动 → 本地 build 绿 → `cargo test -p gm-tlcp --tests` 绿
4. 跑 `cargo +nightly fmt -p gm-tlcp` + `cargo clippy -p gm-tlcp --tests --all-features -- -D warnings`
5. CI run 绿（github）
6. 推到 gitee + gitcode

---

## 5. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| 默认 30s 太短，HSM-backed 服务器超时 | 文档明确推荐 120s 用于 HSM 场景 |
| 默认 30s 太长，攻击者仍能拖 30s | 默认已经够短（业界典型）；用户可调更短 |
| `tokio::time::timeout` cancel 不彻底导致 socket leak | 同 PR-4.23 §5：handshake read/write 都是 cancellation-safe |
| 测试 flaky | 用足够大的 timeout（如 5s）给慢 CI 留 margin |
| `connect_with_certs` / `accept_with_certs` 没被直接 timeout wrap | 它们只通过外层 `connect` / `accept` 调用；外层已 wrap |
| gm-tlcp `connect_tlcp`/`accept_tlcp` deprecated simulated 入口 | SPEC 明确只 wrap `connect`/`accept`，即只 wrap 实际生产入口 |

---

## 6. Follow-up

- PR-4.25 candidate: gm-tls RAII `HandshakeTimer` guard（PR-4.10/4.22 后续优化）
- PR-4.26 candidate: gm-ca `CmErrorCode` enum + metrics 接入 (mirror PR-4.18/4.22)
- PR-4.27 candidate: Grafana dashboard JSON for `gmtls_*`/`gmtlcp_*` metrics

---

## 7. Out of Scope

- 不改 TCP keepalive / TCP_USER_TIMEOUT
- 不改 TLCP record-layer 重传超时
- 不引入新依赖（只用 `tokio::time::timeout`，tokio 已是依赖）
- 不重构 gm-tlcp `connect_with_certs` / `accept_with_certs` 的 metrics 接入
- 不为 deprecated `connect_tlcp` / `accept_tlcp` 加 timeout（这些是模拟模式）