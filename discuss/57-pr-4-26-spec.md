# PR-4.26 — gm-tlcp HandshakeTimer (RAII mirror of PR-4.25) + 补全 metrics 缺口

> Status: **PROPOSED**
> Crates: `gm-tlcp`
> Author: gm-tls PR batch
> Target version: gm-tlcp 0.7.3 → 0.7.4 (patch bump)
> Spec version: 1.0
> Generated: 2026-09-24

---

## 0. 上下文

PR-4.25 (937e973 + f1ec6ee) 给 `gm-tls` 加了 RAII `HandshakeTimer` guard。
gm-tlcp 一直没有 `HandshakeTimer`，metrics 命名空间也**明显不完整**：

| gm-tls | gm-tlcp |
|--------|---------|
| `gmtls_handshakes_total{role, result}` (PR-4.10) | ❌ 缺失 |
| `gmtls_handshake_duration_seconds{role}` (PR-4.10 histogram) | ❌ 缺失 |
| `gmtls_handshake_errors_total{role, code}` (PR-4.22) | ✅ `gmtlcp_handshake_errors_total{role, code}` (PR-4.22) |
| `gmtls_session_resumptions_total{result}` | ❌ (gm-tlcp 不带 resumption) |
| `gmtls_bytes_transferred_total{role, dir}` (PR-2.x) | ✅ (mirror) |
| `gmtls_cert_verification_errors_total{reason}` | ❌ (gm-tlcp 暂未跟进) |

PR-4.26 同时：
1. **镜像 PR-4.25**：给 gm-tlcp 加 RAII `HandshakeTimer` guard
2. **补全 metrics 缺口**：加 `gmtlcp_handshakes_total{role, result}` + `gmtlcp_handshake_duration_seconds{role}` —— 与 gm-tls 同名同 label 同语义，让 operator 在 dashboard 上能**并列**看两条 TLS / TLCP 流量曲线

---

## 1. Background

### 1.1 现有 gm-tlcp metrics

`gm-tlcp/src/metrics.rs` 当前暴露：

- `gmtlcp_bytes_transferred_total{role, dir}` (counter)
- `gmtlcp_handshake_errors_total{role, code}` (counter, PR-4.22)

完全没有 handshake 总成功/失败计数或耗时分布。这意味着：

1. Operator 看不到"每秒多少 TLCP 握手成功/失败" ——只能看到错误细分（`code="HandshakeFailed"` 之类的离散计数）
2. Operator 看不到 TLCP 握手延迟分布 —— 性能回归无法告警
3. 与 gm-tls 命名空间不对齐 —— dashboard 上 TLS / TLCP 曲线无法并列展示

### 1.2 现有 gm-tlcp connect/accept 入口

之前 PR-4.24 已经 wrap 了 `connect`/`accept` (timeout)。新增 RAII timer 也是 wrap 在这层。

`TlcpConnector::connect` 与 `TlcpAcceptor::accept` 已经 emit `record_handshake_error_code(...)` (PR-4.22)。
本次 PR 在这两个 wrap 点同时新增 `HandshakeTimer` 的 emission。

### 1.3 设计目标

- `TlcpConnector::connect` / `TlcpAcceptor::accept` 内部开头 `let timer = HandshakeTimer::new("client");` / `"server"`，成功完成后 `timer.finish("success")`
- 其他路径（`?` 早返回 / panic）通过 Drop 自动 emit `result="error"`
- 与 gm-tls PR-4.10 + PR-4.25 命名空间一致：`gmtlcp_handshakes_total` + `gmtlcp_handshake_duration_seconds`
- 与 PR-4.22 metrics 互补：错误码指标 (`record_handshake_error_code`) + 总成功/失败计数 + 直方图

---

## 2. Design

### 2.1 数据结构 (mirror gm-tls PR-4.25)

```rust
/// Scope guard for timing a TLCP handshake.
///
/// PR-4.26: RAII form, mirror of `gm_tls::metrics::HandshakeTimer`
/// (PR-4.25). On drop without an explicit `finish()` call, the
/// timer records `result="error"` automatically — eliminates
/// the under-counting class of bug where each `?` early-return
/// inside the handshake coroutine must remember to call
/// `finish("error")` manually.
pub struct HandshakeTimer {
    role: String,
    start: Instant,
    recorded: Option<String>,
}
```

### 2.2 API

```rust
impl HandshakeTimer {
    pub fn new(role: &str) -> Self { ... }
    pub fn finish(mut self, result: &str) { ... }
    fn record(role: &str, result: &str, elapsed_secs: f64) {
        counter!("gmtlcp_handshakes_total",
                 "role" => role.to_string(),
                 "result" => result.to_string())
            .increment(1);
        histogram!("gmtlcp_handshake_duration_seconds",
                   "role" => role.to_string())
            .record(elapsed_secs);
    }
}

impl Drop for HandshakeTimer {
    fn drop(&mut self) {
        if self.recorded.is_some() { return; }
        // PR-4.26: conservative default = "error".
        let elapsed = self.start.elapsed().as_secs_f64();
        let result = "error".to_string();
        self.recorded = Some(result.clone());
        Self::record(&self.role, &result, elapsed);
    }
}
```

### 2.3 Wrap-point 应用

#### `TlcpConnector::connect`

```rust
let timer = HandshakeTimer::new("client");
let timeout = self.handshake_timeout;
let inner = async {
    if self.server_sign_pubkey.is_some() {
        self.connect_with_certs(transport).await
    } else {
        connect_tlcp(transport, &self.session_cache).await
    }
};
let result = with_handshake_timeout(timeout, "client", inner).await;
match &result {
    Ok(_) => timer.finish("success"),  // 显式 success 覆盖
    Err(_) => {
        // PR-4.22: record structured error code.
        crate::metrics::record_handshake_error_code("client", e.code());
        // PR-4.26: drop fires automatically, records result="error".
    }
}
result
```

注意：`Err(_) => drop` 路径依赖 Drop 自动 emit。如果有 `?` 路径在 wrap 之前就返回，`?` 触发的 drop 也是 `result="error"`。

#### `TlcpAcceptor::accept` —— 对称改造

### 2.4 describe_metrics() 同步扩展

```rust
pub fn describe_metrics() {
    describe_counter!(
        "gmtlcp_handshakes_total",
        Unit::Count,
        "Total TLCP handshakes (success and error)"
    );
    describe_histogram!(
        "gmtlcp_handshake_duration_seconds",
        Unit::Seconds,
        "Duration of TLCP handshakes in seconds"
    );
    describe_counter!(
        "gmtlcp_handshake_errors_total",
        Unit::Count,
        "Total TLCP handshake errors tagged by structured TlcpErrorCode"
    );
}
```

### 2.5 测试模式 (mirror gm-tls PR-4.25)

```rust
#[cfg(test)]
mod pr426_handshake_timer_raii_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn drop_without_finish_does_not_panic() {
        drop(HandshakeTimer::new("client"));
        drop(HandshakeTimer::new("server"));
    }

    #[test]
    fn finish_success_is_callable() { ... }
    #[test]
    fn finish_error_is_callable() { ... }

    #[test]
    fn drop_many_timers_concurrently() { ... }
}
```

### 2.6 Backward Compatibility

- `HandshakeTimer` 是新结构体，**没有**已旧 API 影响
- `describe_metrics()` 扩展为 3 个描述（之前 0 个 —— gm-tlcp 当前无 `describe_metrics()`）
- 唯一行为变化：`TlcpConnector::connect` / `TlcpAcceptor::accept` 现在 emit 2 个新 metric

### 2.7 与 PR-4.22 metrics 协同

PR-4.22 在 `Err` 分支调 `record_handshake_error_code(role, code)`。PR-4.26 在该分支**不**调 `record_handshake_error_code`（由 PR-4.22 单独负责）。PR-4.26 负责：
- `gmtlcp_handshakes_total{role, result}` —— 计数
- `gmtlcp_handshake_duration_seconds{role}` —— 直方图

两个 metric 互补：
- 总成功/失败 → `gmtlcp_handshakes_total{result="..."}`
- 失败时的细分原因 → `gmtlcp_handshake_errors_total{code="..."}`
- 耗时分布 → `gmtlcp_handshake_duration_seconds`

---

## 3. Test Plan

### 3.1 单元测试 (mirror PR-4.25)

4 个单元测试 in `mod pr426_handshake_timer_raii_tests`:
- drop without finish 不 panic
- finish("success") callable
- finish("error") callable
- 64 个并发 drop 不死锁

### 3.2 现有测试不得破坏

`gm-tlcp` 全部现有测试（~225 个测试 + 143 lib tests）必须继续通过。

### 3.3 Loopback 验证

`tests/gm_tlcp_loopback.rs`、`tests/integration_tlcp.rs`、`tests/handshake_timeout.rs` 的所有测试都必须继续通过，确认 RAII guard 不影响正常握手路径。

---

## 4. Rollout

1. SPEC 已写（本文件）
2. 本地 `cargo build -p gm-tlcp` 必须先绿
3. 改动 metrics.rs（加 `HandshakeTimer`, RAII, describe_metrics, tests）
4. 改动 tlcp/mod.rs (`connect` + `accept` 用 timer)
5. 本地 build + test + clippy + fmt + doc
6. CI run 绿（github）
7. 推到 gitee + gitcode

---

## 5. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
|  Drop 在 panic unwind 时也触发 | 是优点 —— panic 也是 error，operator 想看到 |
|  Double-emit（finish 后 drop 又触发） | `recorded` 字段做幂幂，仅第一次 emit |
|  gm-tlcp metrics 模块之前无 `describe_metrics()` 函数 | PR-4.26 引入新函数（lib.rs 不重新导出 —— 命名空间隔离，gm-tlcp 不暴露 gm-tls 的 describe_metrics）|
|  现有调用点（PR-4.22 wrap）改了 control flow 可能漏计时 | 现有 Ok 分支已有 `Ok(_)` match，Err 分支有 drop 兜底 |
|  doc intra-doc-links (PR-4.24/4.25 fix memory) | 复盘使用全路径 `[`HandshakeTimer::finish`]` |

---

## 6. Follow-up

- PR-4.27 candidate: gm-tls `audit::AuditLogger` 接入 metrics（auth_success / auth_failure counter）
- PR-4.28 candidate: gm-ca `CmErrorCode` enum + metrics 接入
- PR-4.29 candidate: Grafana dashboard JSON for `gmtls_*` / `gmtlcp_*` metrics

---

## 7. Out of Scope

- 不改 PR-4.22 的 `record_handshake_error_code` 行为
- 不为 deprecated `connect_tlcp` / `accept_tlcp` 加 timer（这些是 simulated 模式，无真实握手）
- 不引入新依赖（只用 `metrics` crate，已是依赖）
- 不改 `gmtlcp_bytes_transferred_total` 行为