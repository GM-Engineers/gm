# PR-4.28 — gm-tls structured `gmtls_cert_verification_errors_total{code}` (mirror PR-4.22/4.27)

> Status: **PROPOSED**
> Crates: `gm-tls`
> Author: gm-tls PR batch
> Target version: gm-tls 0.2.13 → 0.2.14 (patch bump)
> Spec version: 1.0
> Generated: 2026-09-24

---

## 0. 上下文

PR-4.22 给 `gmtls_handshake_errors_total{role, code}` 加了结构化 `ErrorCode` 标签 (gm-tls)。
PR-4.27 给 `gmca_errors_total{code}` 加了结构化 `CaErrorCode` 标签 (gm-ca)。

但 gm-tls 还有一个**独立**的 cert verification counter：

```
gmtls_cert_verification_errors_total{reason="session_ticket_tampered"}
```

`reason` 是 string（与 PR-4.22/4.27 的 `code` label 形状不一致），且目前**只有一个调用点**：`record_cert_error("session_ticket_tampered")` 在 `connect_gm_rust_inner` 的 session-ticket fail-closed 路径。

PR-4.28 补全这个缺口：
1. 加 `record_cert_error_code(code: ErrorCode)` emit `gmtls_cert_verification_errors_total{code="..."}` —— 结构化 label
2. 把 `record_cert_error` 标记 deprecated —— 继续 emit 旧 `{type="..."}` 一个 release cycle
3. 把现有调用点迁移到 `record_cert_error_code(ErrorCode::SessionTicket)`

---

## 1. Background

### 1.1 当前 `gmtls_cert_verification_errors_total` 痛点

**metrics.rs (gm-tls):**

```rust
pub fn record_cert_error(reason: &str) {
    let reason = reason.to_owned();
    counter!("gmtls_cert_verification_errors_total", "reason" => reason).increment(1);
}
```

**gm.rs (唯一调用点 line 387):**

```rust
record_cert_error("session_ticket_tampered");
```

### 1.2 跨 crate 命名空间一致性问题

| Crate | PR | Code enum | Metric | Label 形状 |
|-------|----|-----------|--------|----------|
| gm-tls | PR-4.22 | `ErrorCode` | `gmtls_handshake_errors_total` | `{role, code}` |
| gm-tls | **PR-4.28** | `ErrorCode` | `gmtls_cert_verification_errors_total` | `{code}` |
| gm-tlcp | PR-4.22 | `TlcpErrorCode` | `gmtlcp_handshake_errors_total` | `{role, code}` |
| gm-ca | PR-4.27 | `CaErrorCode` | `gmca_errors_total` | `{code}` |

PR-4.28 把 gm-tls 第二个 cert verification counter 也升级到结构化 `code` label —— 完成四个 crate 的 `{code}` label 形状统一。

### 1.3 设计目标

- 加 `pub fn record_cert_error_code(code: ErrorCode)` emit `gmtls_cert_verification_errors_total{code="<Debug>"}`
- `pub fn record_cert_error(&str)` deprecated 但保留双 label emit
- 现有 `record_cert_error("session_ticket_tampered")` 替换为 `record_cert_error_code(ErrorCode::SessionTicket)`
- 单元测试覆盖 (mirror PR-4.22/4.27 测试)

### 1.4 两个 cert verification counter 的语义区别

文档化以避免混淆：

| Counter | 何时 emit |
|---------|----------|
| `gmtls_handshake_errors_total{role, code="CertificateVerificationFailed"}` | 握手**失败**时 (PR-4.22 wrap 函数自动 emit, error.code()) |
| `gmtls_cert_verification_errors_total{code="..."}` | 每次 cert verify **调用失败**时 |

注意：`connect_gm_rust_inner` 的 session-ticket fail-closed 路径会同时 emit 这两个（因为它现在返回 `TlsError::HandshakeFailed` 给外层 wrap，外层 wrap emit `handshake_errors_total`；inner 自己 emit `cert_verification_errors_total`）。

---

## 2. Design

### 2.1 `metrics::record_cert_error_code`

```rust
/// PR-4.28: records a certificate verification error tagged by
/// structured [`ErrorCode`] (gm-tls). Mirror of
/// `gm_tls::metrics::record_handshake_error_code` (PR-4.22) and
/// `gm_ca::metrics::record_error_code` (PR-4.27). The `code`
/// label uses `ErrorCode`'s `Debug` representation (e.g.
/// `"SessionTicket"`).
///
/// Replaces this the legacy string-based `record_cert_error`
/// API. The legacy `reason` label is still incremented (from
/// deprecated `record_cert_error`) so existing dashboards do
/// not break during the migration.
///
/// # Companion metrics
///
/// Two cert-related error counters now coexist in gm-tls:
///
/// - `gmtls_handshake_errors_total{role, code}` (PR-4.22) —
///   emits **once per failed handshake**, tagged by the
///   returned `TlsError::code()`. Covers every TLS layer
///   failure, including cert verification.
///
/// - `gmtls_cert_verification_errors_total{code}` (this PR) —
///   emits **per certificate verification attempt** (not
///   necessarily a complete handshake). Use this when you want
///   to alert on PKI-level anomalies independent of the
///   handshake state machine (e.g. session-ticket fail-closed
///   reject before a full handshake even starts).
pub fn record_cert_error_code(code: ErrorCode) {
    let code = format!("{code:?}");
    counter!("gmtls_cert_verification_errors_total", "code" => code)
        .increment(1);
}

/// **Deprecated** since 0.2.14 — use [`record_cert_error_code`]
/// with a structured [`ErrorCode`] instead. The legacy `reason`
/// label continues to be incremented for one release cycle so
/// existing dashboards do not break, but new alerts / dashboards
/// should switch to the `code` label via
/// `record_cert_error_code(ErrorCode::Xxx)`.
#[deprecated(
    since = "0.2.14",
    note = "use record_cert_error_code with structured ErrorCode for compile-time-checked metric labels"
)]
pub fn record_cert_error(reason: &str) {
    counter!("gmtls_cert_verification_errors_total", "reason" => reason.to_string())
        .increment(1);
}
```

### 2.2 describe_metrics 更新

```rust
describe_counter!(
    "gmtls_cert_verification_errors_total",
    Unit::Count,
    "Total certificate verification errors (PR-4.28: emits under both `code` (structured) and `reason` (legacy string) labels)"
);
```

### 2.3 调用点迁移

```rust
// Before (gm.rs:387):
record_cert_error("session_ticket_tampered");

// After:
record_cert_error_code(ErrorCode::SessionTicket);
```

### 2.4 lib.rs re-export

`ErrorCode` 已经在 `pub use error::{ErrorCode, TlsError}` 重新导出。

### 2.5 Backward Compatibility

- **`record_cert_error` API deprecated**: 继续 emit `gmtls_cert_verification_errors_total{reason="..."}` 旧 label
- **`record_cert_error_code` 新 API**: emit `gmtls_cert_verification_errors_total{code="..."}` 新 label
- 现有 dashboard 不漂移
- 0.3.0 删除 `record_cert_error` (本 PR 不做)

---

## 3. Test Plan

### 3.1 单元测试

```rust
#[cfg(test)]
mod pr428_record_cert_error_code_tests {
    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn record_cert_error_code_accepts_all_variants() {
        for code in [ErrorCode::Cipher, ErrorCode::SessionTicket,
                     ErrorCode::CertificateVerificationFailed,
                     ErrorCode::CrlVerificationFailed,
                     /* all ErrorCode variants */] {
            record_cert_error_code(code);
        }
    }

    #[test]
    fn legacy_record_cert_error_still_callable() {
        #[allow(deprecated)]
        record_cert_error("session_ticket_tampered");
    }

    #[test]
    fn record_cert_error_code_is_thread_safe() {
        // 8 threads × N variants concurrent
    }
}
```

### 3.2 现有测试不得破坏

`gm-tls` 全部现有测试（~234 个）必须继续通过。

---

## 4. Rollout

1. SPEC 已写（本文件）
2. 本地 `cargo build -p gm-tls` 必须先绿
3. 改动 metrics.rs (record_cert_error_code + deprecated record_cert_error + 单元测试)
4. 改动 gm.rs (替换 session_ticket_tampered 调用点 + 加 ErrorCode import)
5. 本地 build + test + clippy + fmt + doc
6. CI run 绿（github）
7. 推到 gitee + gitcode

---

## 5. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| gm-tls 1 个调用点漏改 | 唯一一处: `gm.rs:387` 直接替换 |
| deprecated API 误用 | `#[deprecated(since = "0.2.14")]` compile-time warning |
| 跨 counter 语义混淆 | 文档化两个 counter 的区别（每行 doc comment） |
| `ErrorCode` 不存在对应 `code` label variant | ErrorCode 已有 `SessionTicket` variant (PR-4.16 引入) |

---

## 6. Follow-up

- PR-4.29 candidate: gm-tls 启动期独立 `health::run_kat_self_test()` API (PR-4.18 follow-up)
- PR-4.30 candidate: gm-tlcp `gmtlcp_cert_verification_errors_total` 同步
- PR-4.31 candidate: 跨 crate 统一 Grafana dashboard JSON
- PR-4.32 candidate: gm-ca 0.5.0 删除 deprecated `record_error`（PR-4.27 留的 deprecation）

---

## 7. Out of Scope

- 不改 `record_session_resumption` 行为（已经结构化 `result` label）
- 不改 `record_bytes` 行为（已经结构化 `role`/`dir` labels）
- 不改 PR-4.22 wrap 函数行为（已经自动 emit `handshake_errors_total`）
- 不引入新依赖