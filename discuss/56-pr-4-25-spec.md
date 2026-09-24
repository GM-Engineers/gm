# PR-4.25 — RAII `HandshakeTimer` guard (gm-tls, drop = error 自动 emit)

> Status: **PROPOSED**
> Crates: `gm-tls`
> Author: gm-tls PR batch
> Target version: gm-tls 0.2.12 → 0.2.13 (patch bump)
> Spec version: 1.0
> Generated: 2026-09-24

---

## 1. Background

PR-4.10 (PR-batch 4 / P2-1) 引入了 `HandshakeTimer` scope guard 来 record
`gmtls_handshakes_total{role, result}` + `gmtls_handshake_duration_seconds`
histogram。当前 API 是**手动 finish**：

```rust
let timer = HandshakeTimer::new("client");
// ... lots of work, many `?` early-returns ...
timer.finish("success");  // 必须每个返回点都调
```

### 1.1 当前实现的问题

`HandshakeTimer` 实际上是 RAII guard 的**伪实现**：不 drop 调 `finish`。
任何 `?` 早返回前**必须**手动 `timer.finish("error")` 才能 record histogram。

看 `connect_gm_rust_inner` 实际调用：

```
gm.rs:227  let timer = HandshakeTimer::new("client");
gm.rs:280  timer.finish("success");  // session resumption success
gm.rs:353  timer.finish("success");  // session resumption 另一条路径
gm.rs:386  timer.finish("error");    // 错误路径
gm.rs:433  timer.finish("error");    // 错误路径
gm.rs:566  let timer = HandshakeTimer::new("server");
gm.rs:579  timer.finish("success");
gm.rs:583  timer.finish("error");
```

任何**新增**的 `?` 早返回路径都必须记得手动调 `timer.finish("error")`，
否则该次握手会**漏计**：

1. `gmtls_handshakes_total{result="error"}` —— 漏计
2. `gmtls_handshake_duration_seconds` histogram —— 漏计

这是个**真实的正确性 bug**，因为：

- 添加新的 failure path（例如 PR-4.23 加的 `tokio::time::timeout` wrap、
  PR-4.22 加的 metrics 入口）时容易漏加 `timer.finish("error")`
- 一旦漏，监控告警与 SLO 计算会**少统计** error rate，operator 可能误判健康度

### 1.2 设计目标

把 `HandshakeTimer` 改成**真正的 RAII guard**：

- 创建即开始计时
- 成功路径调用 `guard.finish("success")` 覆盖默认 `result="error"`
- 所有其他路径（`?` 早返回 / panic / drop）自动 emit `result="error"` + histogram
- 向后兼容：现有调用 `.finish("xxx")` 的代码继续工作

---

## 2. Design

### 2.1 数据结构

```rust
/// Scope guard for timing a handshake. The timer starts at
/// construction and **automatically records on drop** with
/// `result="error"` (the conservative default — every handshake
/// that does not explicitly call [`finish`] with `result="success"`
/// counts as an error in metrics).
///
/// PR-4.25: prior to this PR, [`finish`] had to be called
/// manually at *every* control-flow exit point, including each
/// `?` early-return inside the handshake coroutine. Missing
/// one would under-count the handshake-error histogram and
/// `gmtls_handshakes_total{result="error"}` counter. The RAII
/// form eliminates that whole class of bugs.
pub struct HandshakeTimer {
    role: String,
    start: Instant,
    /// `None` means "use the drop default (error)". `Some(...)`
    /// means [`finish`] was called explicitly with that result
    /// label.
    recorded: Option<String>,
}
```

### 2.2 API

```rust
impl HandshakeTimer {
    /// Start a handshake timer for `role` (typically `"client"`
    /// or `"server"`).
    pub fn new(role: &str) -> Self { ... }

    /// Mark this handshake as `result` (`"success"` or
    /// `"error"`). Subsequent drop will be a no-op (already
    /// recorded).
    pub fn finish(mut self, result: &str) {
        // idempotent: only the first call records.
        if self.recorded.is_some() { return; }
        self.recorded = Some(result.to_string());
        let elapsed = self.start.elapsed().as_secs_f64();
        counter!("gmtls_handshakes_total", "role" => self.role.clone(), "result" => result.to_string())
            .increment(1);
        histogram!("gmtls_handshake_duration_seconds", "role" => self.role)
            .record(elapsed);
    }
}

impl Drop for HandshakeTimer {
    fn drop(&mut self) {
        // If [`finish`] was called, do nothing. Otherwise,
        // record as `result="error"` (the conservative default).
        if self.recorded.is_some() { return; }
        let elapsed = self.start.elapsed().as_secs_f64();
        let result = "error".to_string();
        counter!("gmtls_handshakes_total", "role" => self.role.clone(), "result" => result)
            .increment(1);
        histogram!("gmtls_handshake_duration_seconds", "role" => self.role.clone())
            .record(elapsed);
    }
}
```

### 2.3 调用模式变化

**Before (PR-4.10 ~ PR-4.24)**:

```rust
let timer = HandshakeTimer::new("client");
// ... if success ...
timer.finish("success");
// ... if error ...
timer.finish("error");
```

**After (PR-4.25)**:

```rust
let timer = HandshakeTimer::new("client");
// ... if success ...
timer.finish("success");
// ... if `?` early-return, panic, or any path ...
//   → Drop fires automatically, records result="error"
//   → No manual cleanup needed
```

### 2.4 不变量

- 一次握手恰好触发一次 `gmtls_handshakes_total` increment
- 一次握手恰好 record 一次 `gmtls_handshake_duration_seconds`
- success 和 error 调用路径都满足
- 即使 panic / unwind 也触发 Drop

### 2.5 不破坏现有调用

`timer.finish("success")` 和 `timer.finish("error")` 两种调用都不变 —— 它们仍然 record 正确的结果。

唯一变化是**省略**了 `timer.finish("error")` 调用 —— RAII 兜底。

### 2.6 与 PR-4.22 错误码 metrics 的协同

PR-4.22 在 wrap 函数里调用 `record_handshake_error_code(role, code)`。
PR-4.25 改变的是 `record_handshake_total` 的 emission point —— 但 error 路径
仍然触发一次 `record_handshake_error_code`（因为 PR-4.22 是 wrap 函数级别的，
PR-4.25 是 RAII 在 inner function 级别）。两者**互补**：

- `gmtls_handshakes_total{role, result="error"}` 计数器（PR-4.10 + PR-4.25）
  —— 回答"多少次握手失败"
- `gmtls_handshake_errors_total{role, code}` 计数器（PR-4.22）
  —— 回答"失败时各自的 error code"

### 2.7 Backward Compatibility

- `HandshakeTimer::new(role)` API 不变
- `HandshakeTimer::finish(self, result)` API 不变
- 新增私有字段 `recorded: Option<String>`，但 struct 已经是私有字段，公有 API 仅 `new` + `finish`
- 现有调用点 `timer.finish("success")` 和 `timer.finish("error")` 都继续工作
- 唯一的"语义变化"：**省略** `timer.finish("error")` 现在会通过 Drop 自动补上 —— 这正是 PR-4.25 的目的

### 2.8 为什么不直接改所有调用点

可以！但只是治标不治本。RAII guard 才是 Rust 惯用的解决方案，并且确保未来加新的 `?` 早返回路径时**自动正确**。

---

## 3. Test Plan

### 3.1 单元测试

```rust
#[cfg(test)]
mod pr425_handshake_timer_raii_tests {
    use super::*;

    /// PR-4.25: dropping a HandshakeTimer without calling
    /// finish() records `result="error"` automatically.
    #[test]
    fn drop_without_finish_records_error() {
        // Use a local recorder to inspect metrics without
        // touching the global Prometheus registry.
        let snapshot = metrics::with_local_recorder(|| {
            {
                let _t = HandshakeTimer::new("client");
                // Intentionally drop without calling finish().
            }
            // Allow the local recorder to capture emits.
        });
        // Expect: counter increment + histogram record
        // (PR-4.25 unit test asserts the structure of the
        //  emitted counters/histograms).
    }

    /// PR-4.25: explicitly calling finish("success") records
    /// success and a subsequent drop is a no-op (idempotent).
    #[test]
    fn finish_success_then_drop_is_noop() {
        // similar shape, with finish("success") called.
    }

    /// PR-4.25: finish("error") records error (same as drop).
    #[test]
    fn finish_error_records_error() { ... }
}
```

### 3.2 现有测试不得破坏

`gm-tls` 全部现有测试（~230 个）必须继续通过。

### 3.3 Loopback 验证

`tests/spiffe_uri.rs` 的 4 个 loopback 测试 + `tests/handshake_timeout.rs` 的 2 个
PR-4.23 测试都必须继续通过，确认 RAII guard 不影响正常路径。

---

## 4. Rollout

1. SPEC 已写（本文件）
2. 本地 `cargo build -p gm-tls` 必须先绿
3. 改动 metrics.rs (RAII Drop impl)
4. 改动 gm.rs（移除冗余的 `timer.finish("error")` —— RAII 兜底）
5. 本地 build + test + clippy + fmt
6. CI run 绿（github）
7. 推到 gitee + gitcode

---

## 5. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Drop 在 panic unwind 时也触发，可能记录到不准确数据 | 这是**优点** —— panic 也是 error，operator 想看到 |
| Double-emit（finish 后 drop 又触发）| `recorded` 字段做幂幂：仅第一次 emit |
| 现有调用点手动 `timer.finish("error")` 现在会 double-emit | `recorded` 幂幂字段解决；现有代码无变化 |
| Drop 时 `self.start.elapsed()` 不准（未初始化完成） | 现实上 `new` 立即初始化 `start = Instant::now()`，drop 时已有 duration |

---

## 6. Follow-up

- PR-4.26 candidate: 把 RAII guard 模式应用到 `gm-tlcp` 的 handshake timer
- PR-4.27 candidate: gm-ca `CmErrorCode` enum + metrics 接入 (mirror PR-4.18/4.22)

---

## 7. Out of Scope

- 不改 `record_handshake(role, result, duration_secs)` 自由函数 API（它仍然是手动调用接口）
- 不引入新的依赖（只用 `std::mem::ManuallyDrop` 或自管 `Option<String>` 字段）
- 不改 metric 输出名称（`gmtls_handshakes_total` 和 `gmtls_handshake_duration_seconds`）