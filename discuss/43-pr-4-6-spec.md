# SPEC: PR-4.6 — gm-tls `GmTlsIncoming::local_addr()` cache (P1-6)

- **目标编号**：PR-4.6（Batch 4 — gm-tls 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §6 / §7 P1-6`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md)：GmTlsIncoming::local_addr() 未实现（gm-tls）
- **范围**：`gm-tls/src/grpc.rs`（GmTlsIncoming 缓存 listener.local_addr）
- **影响面**：纯公开 API 实现增量；不破坏任何现有 caller

---

## 1. 问题陈述

[`gm-tls/src/grpc.rs:192-199`](file:///Users/laozhang/Work/opensource/gm/gm-tls/src/grpc.rs#L192)：

```rust
/// Returns the local address this listener is bound to.
pub async fn local_addr(&self) -> std::io::Result<SocketAddr> {
    // We need to reconstruct this - just return error for now
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "local_addr not available after construction",
    ))
}
```

后果：
- tonic 中间件（限流按本地端口、审计、普罗米修斯标签）依赖 `ConnectInfo.local_addr` 的场景拿不到本地地址
- `GmTlsConnectInfo` 已经有 `local_addr: Option<SocketAddr>` 字段（line 62），但 `GmTlsIncoming::local_addr()` 不返回它
- 唯一 caller（gm-ca）必须做额外工作来恢复本地地址

### 1.3 改进建议依据

> §6 / §7 P1-6："构造时保存 `listener.local_addr()`，`local_addr()` 返回 `Ok(addr)`；补测试。"

---

## 2. Fix 策略

### 2.1 GmTlsIncoming 结构体扩展

```rust
pub struct GmTlsIncoming {
    inner: Pin<Box<dyn futures::Stream<Item = Result<GmServerIo, std::io::Error>> + Send>>,
    #[allow(dead_code)]
    semaphore: Arc<Semaphore>,
    /// Local address this listener is bound to. Captured at
    /// construction time (before the listener is moved into
    /// the inner stream). `None` if `TcpListener::local_addr()`
    /// failed at construction (extremely rare; usually means
    /// the listener was already closed).
    local_addr: Option<SocketAddr>,
}
```

### 2.2 with_max_concurrent 捕获 local_addr

```rust
pub fn with_max_concurrent(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    max_concurrent: usize,
) -> Self {
    // Capture local_addr BEFORE moving the listener into the stream.
    let local_addr = listener.local_addr().ok();
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    // ... existing stream construction unchanged ...
    Self {
        inner: Box::pin(incoming),
        semaphore,
        local_addr,
    }
}
```

### 2.3 local_addr 返回 Ok(addr)

```rust
/// Returns the local address this listener is bound to.
///
/// The address is captured at construction time (before the listener
/// is moved into the inner stream), so this method never re-queries
/// the listener. Returns `Err(AddrNotAvailable)` only in the rare
/// case where `TcpListener::local_addr()` itself failed at
/// construction (e.g. listener was already closed).
pub async fn local_addr(&self) -> std::io::Result<SocketAddr> {
    self.local_addr.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "local_addr unavailable (TcpListener::local_addr failed at construction)",
        )
    })
}
```

### 2.4 版本

`gm-tls/Cargo.toml`：patch bump（纯公开 API 增量；公共 API 表面无 breaking change）。

---

## 3. Tests

### 3.1 新增单元测试（`gm-tls/src/grpc.rs::pr46_local_addr_tests`）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr46_local_addr_returns_bound_address` | 绑定到 127.0.0.1:0，`local_addr()` 返回 `Ok(addr)`，addr 与绑定的端口匹配 |
| T2 | `pr46_local_addr_returns_loopback_for_unspecified` | 绑定到 127.0.0.1:0（loopback），addr 是 127.0.0.1 |
| T3 | `pr46_local_addr_consistent_across_calls` | 多次调用 `local_addr()` 返回相同 addr |

### 3.2 回归测试

所有现有 gm-tls 测试必须继续通过（799 passed / 18 ignored，PR-2.x 既有状态）。

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p gm-tls --all-targets
cargo +1.88 test -p gm-ca --all-targets --features tlcp-profiles
```

CI 全套含 GmSSL Interop / TLCP Interop。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 现有调用方假设 `local_addr()` 返回 `Err` | `gm-ca/src/main.rs` 不调用此方法；PR-4.6 保持向后兼容（错误路径仍存在） |
| TcpListener::local_addr 在构造时返回 Err | 极罕见；保持 `Option<SocketAddr>`，返回 `Err(AddrNotAvailable)` 与原契约一致 |
| 端口 0（OS 分配端口）的捕获 | `local_addr()` 在 OS 分配端口后立即调用，返回真实分配的端口；测试 T1 覆盖 |

---

## 6. Out of Scope（不在本 PR 范围）

- `GmTlsConnectInfo.local_addr` 字段语义变更（已存在，保持不变）
- `TlsAcceptor` / `TlsConfig` 任何其他 API（IM 跟随，不变）
- 重构 GmTlsIncoming 整体架构（IM 跟随 gm-tls 后续议题）

---

## 7. 后续 PR 候选

- **PR-4.7**：gm-tls CRL grace period + session cache persistence
- **PR-4.8**：gm-crypto 恒定时间标量乘（如果 sm2 crate 不修复）
- **PR-4.9**：gm-ca SPIRE Federation（信任域联邦）