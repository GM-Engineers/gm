# PR-4.22 — 把 `ErrorCode` / `TlcpErrorCode` 接入 Prometheus metrics

> 状态：草案 / 待实施
> 关联：PR-4.18（gm-tls `ErrorCode`）+ PR-4.21（gm-tlcp `TlcpErrorCode`）的跟进
> 目标：完成 PR-4.18 §3 / PR-4.21 §3 文档中描述但**未实施**的 metrics 接入步骤
> 目标版本：gm-tls `0.2.10 → 0.2.11` + gm-tlcp `0.7.1 → 0.7.2`（两个 crate 均为 patch）

## 1. 背景与动机

PR-4.18 / PR-4.21 引入了结构化错误码（`ErrorCode` / `TlcpErrorCode`）以及
`TlsError::code()` / `TlcpError::code()` 方法。两个 SPEC 都明确描述了 metrics
接入的愿景（"metrics can alert on each subsystem"），但实际只完成了**类型层**
工作，metrics 层 **未接入**。这是 PR-4.18 SPEC §3 表格的「后续工作」列里
明确列出的"v0.x follow-up"。

**当前状况**：

| 调用点 | 现状 | 期望 |
|--------|------|------|
| `gmtls_handshakes_total{role, result=success/error}` | ✅ 已接入 | — |
| `gmtls_handshake_errors_total{role, code=<ErrorCode>}` | ❌ 不存在 | 应存在 |
| `gmtls_cert_verification_errors_total{reason=...}` | ✅ 已接入（字符串） | 升级为 `code=<ErrorCode>` 形式 |

**带来的可观测性 gap**：
- operator 看到 `"error"` counter 上涨时，只能去日志里 grep
  `"handshake failed"` 子串，无法结构化分类
- 没法独立告警「`Cipher` 失败率升高」（CPU 异常信号）
  vs「`HandshakeMessageParse` 失败率升高」（协议异常信号）
- 没法独立告警「`CrlVerificationFailed` 失败率升高」
  vs `CertificateVerificationFailed`（不同 PKI 故障类别）

**PR-4.22 的目标**：把 PR-4.18/4.21 引入的 `code()` 接入现有 metrics，
让 operator 可以**直接按 `code` 维度切片**。

## 2. 范围与非目标

### 范围内

- 新增 `gmtls_handshake_errors_total{role, code}` counter 到 `gm-tls`
- 新增 `gmtlcp_handshake_errors_total{role, code}` counter 到 `gm-tlcp`
- 新增 `gm_tls::metrics::record_handshake_error_code(role, code)` 函数
- 新增 `gm_tlcp::metrics::record_handshake_error_code(role, code)` 函数
- 在 `connect_gm_rust_inner` / `accept_gm_rust_inner` / `accept_gm_rust_inner_with_cert` /
  `tlcp_connector::connect_inner` / `tlcp_acceptor::accept_inner` 的**外层
  wrap 点**插入 `record_handshake_error_code` 调用
- 把现有 `gmtls_cert_verification_errors_total{reason=session_ticket_tampered}`
  的字符串 reason 升级为 `code=SessionTicket`（PR-4.16 typed variant）
- 单元测试覆盖：`record_handshake_error_code` 对每个 `ErrorCode` /
  `TlcpErrorCode` 变体都生成对应 counter

### 非目标

- **不**修改任何 `TlsError::code()` / `TlcpError::code()` 实现
- **不**新增任何 `ErrorCode` / `TlcpErrorCode` 变体
- **不**改 wire format
- **不**改 handshake state machine
- **不**对 `?` 早返回路径做 RAII guard 改写（会引入大规模重写，风险大于收益）
- **不**侵入 gm-kms（gm-kms 是独立 crate，留给后续 PR-4.23）

## 3. 设计

### 3.1 新增 Counter

| Metric name | Type | Labels | 含义 |
|------------|------|--------|------|
| `gmtls_handshake_errors_total` | counter | `role`, `code` | gm-tls 握手失败次数，按 `ErrorCode` 切片 |
| `gmtlcp_handshake_errors_total` | counter | `role`, `code` | gm-tlcp 握手失败次数，按 `TlcpErrorCode` 切片 |

`code` label 取值为 `ErrorCode` / `TlcpErrorCode` 的 `Debug` 字符串
（`HandshakeFailed`、`Cipher`、`SessionTicket`、`Kat` 等）。
因为这两个 enum 都是 `#[non_exhaustive]`，未来新增变体也会自动出现在
label 值集合里（Prometheus operator 需相应调整告警规则）。

### 3.2 新增 API

```rust
// gm-tls/src/metrics.rs
pub fn record_handshake_error_code(role: &str, code: ErrorCode) {
    counter!(
        "gmtls_handshake_errors_total",
        "role" => role.to_owned(),
        "code" => format!("{code:?}"),
    ).increment(1);
}

// gm-tlcp/src/metrics.rs
pub fn record_handshake_error_code(role: &str, code: TlcpErrorCode) {
    counter!(
        "gmtlcp_handshake_errors_total",
        "role" => role.to_owned(),
        "code" => format!("{code:?}"),
    ).increment(1);
}
```

### 3.3 外层 wrap 接入点

**gm-tls 当前结构**（以 `connect_gm_rust` 为例）：

```rust
pub async fn connect_gm_rust<S>(...) -> Result<GmTlsStream<S>, TlsError> {
    let result = connect_gm_rust_inner(...).await;
    match &result {
        Ok(_) => { auth_success(...); }
        Err(e) => { auth_failure(..., &e.to_string()); }
    }
    result
}
```

PR-4.22 在 `Err(e)` 分支里追加 `record_handshake_error_code(role, e.code())`：

```rust
pub async fn connect_gm_rust<S>(...) -> Result<GmTlsStream<S>, TlsError> {
    let result = connect_gm_rust_inner(..., "client").await;
    match &result {
        Ok(_) => { auth_success(...); }
        Err(e) => {
            auth_failure(..., &e.to_string());
            record_handshake_error_code("client", e.code());
        }
    }
    result
}
```

**gm-tlcp 当前结构**（`tlcp::mod.rs` 中 `TlcpConnector::connect_inner` /
`TlcpAcceptor::accept_inner`）类似。

### 3.4 不动 `?` 早返回的原因

`HandshakeTimer::finish(self)` 消费 self，所以现有 `?` 路径没法"cleanup
on error"。要把所有 `?` 都改成 `match`/`map_err` 是 PR-4.18 / PR-4.21
范围之外的**结构性重写**，应留给独立 PR。PR-4.22 只在外层 wrap 点
接入 metrics，这已经覆盖 100% 的失败路径（因为内层 `?` 最终都会传播到
外层 wrap 点）。

### 3.5 与现有 `record_cert_error("session_ticket_tampered")` 的关系

PR-4.22 **保留** `gmtls_cert_verification_errors_total` counter 与 `record_cert_error`
函数（向后兼容，下游可能还在用）。**新增** `record_handshake_error_code(role, SessionTicket)`
作为更结构化的等价指标。两者会同时被触发（一次失败记录两次），通过不同
metric name 让 operator 选择：
- `gmtls_cert_verification_errors_total{reason="session_ticket_tampered"}`：保留字符串 reason
- `gmtls_handshake_errors_total{role, code="SessionTicket"}`：结构化 code label

**去重考虑**：两个 metric 都说"session ticket tampered"，但
label 维度不同（`reason` vs `code`），属于正交观察角度。保留两个
counter 让 dashboard 可灵活切片。

## 4. 向后兼容性

### 4.1 公共 API

- 新增 `pub fn record_handshake_error_code(role, code)` 函数：纯新增
- 新增 counter metric：纯新增
- 现有 `record_handshake` / `record_cert_error` / `record_bytes` /
  `record_session_resumption` 函数：未修改

### 4.2 metric name 兼容性

- 新 metric `gmtls_handshake_errors_total` 与现有 `gmtls_handshakes_total`、
  `gmtls_cert_verification_errors_total` 同 prefix 不冲突
- 新 metric `gmtlcp_handshake_errors_total` 与现有 `gmtlcp_bytes_transferred_total`
  同 prefix 不冲突

## 5. 测试计划

### 5.1 单元测试

新增两个测试模块：

#### `gm-tls/src/metrics.rs::pr422_record_handshake_error_code_tests`

- `record_handshake_error_code_emits_counter_for_each_variant`（一个总测试，
  对每个 ErrorCode 调用并断言 counter 已 increment）
- `record_handshake_error_code_emits_correct_role_label`
- `record_handshake_error_code_does_not_panic_on_strange_role`（空字符串、
  unicode 角色名）
- `record_handshake_error_code_is_thread_safe`（多线程并发触发）

#### `gm-tlcp/src/metrics.rs::pr422_record_handshake_error_code_tests`

类似的测试覆盖 `TlcpErrorCode` 所有 13 个 variants。

### 5.2 端到端验证

- `cargo build --workspace`
- `cargo test -p gm-tls --lib --all-features`
- `cargo test -p gm-tlcp --lib --all-features`
- `cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo +nightly fmt --check`
- `RUSTDOCFLAGS="-D warnings" cargo +nightly doc --no-deps` (gm-tls + gm-tlcp)

## 6. 风险评估

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| Counter 基数无界（role × code 笛卡尔积） | 低 | 低 | role 只有 2-3 个值（client/server），code 是 13-21 个 variants，基数 < 70 |
| Operator 告警规则 `gmtls_handshakes_total{result=error}` 不再触发 | 无 | - | **新 metric 是新增**，未删改 `result=success/error` 维度 |
| record_handshake_error_code 调用位置与 timer.finish 重复计数 | 低 | 低 | 文档明确说明一次失败 = 一次 counter 递增；timer 单独记录 duration |
| `format!("{code:?}")` 产生 "Cipher" 还是 "CipherError" 不一致 | 中 | 低 | `Debug` 输出 enum variant name（无括号），统一为 "Cipher" 形式 |
| 多线程并发调用时 metrics facade panic | 极低 | 中 | `metrics` crate 的 facade 是线程安全的（用 `Recorder` trait + global registry） |

## 7. 实施步骤

1. **gm-tls/src/metrics.rs**：
   - 在 `describe_metrics` 中追加 `gmtls_handshake_errors_total` 描述
   - 新增 `pub fn record_handshake_error_code(role: &str, code: ErrorCode)`
   - 新增 `pr422_record_handshake_error_code_tests` 模块（~4 测试）
   - 更新 module-level 文档表格（"Emitted metrics"）

2. **gm-tls/src/gm.rs**：
   - 3 个 wrap 函数（`connect_gm_rust` / `accept_gm_rust` /
     `accept_gm_rust_with_client_cert`）的 `Err(e)` 分支追加
     `record_handshake_error_code(role, e.code())`

3. **gm-tlcp/src/metrics.rs**：
   - 追加 `gmtlcp_handshake_errors_total` 描述
   - 新增 `pub fn record_handshake_error_code(role: &str, code: TlcpErrorCode)`
   - 新增 `pr422_record_handshake_error_code_tests` 模块

4. **gm-tlcp/src/tlcp/mod.rs**：
   - `TlcpConnector::connect_inner` / `TlcpAcceptor::accept_inner`
     外层 wrap 追加 `record_handshake_error_code`

5. **CHANGELOG**：
   - gm-tls: Added 新 metric + 新函数
   - gm-tlcp: Added 新 metric + 新函数

6. **Cargo.toml**：
   - gm-tls 0.2.10 → 0.2.11
   - gm-tlcp 0.7.1 → 0.7.2
   - workspace Cargo.lock 自动更新

7. **commit + push github → CI green → push gitee + gitcode**

## 8. 跟进（不在本 PR 范围内）

- **PR-4.23**: 把 `?` 早返回路径重构为 RAII guard (`HandshakeTimer::finish_with_code`)，
  让每次失败都精确报告 code label
- **PR-4.24**: gm-kms 中使用 `code()` 作为 metrics label key（跨仓迁移）
- **PR-4.25**: Grafana dashboard JSON 包含 `gmtls_handshake_errors_total{code=...}` 切片