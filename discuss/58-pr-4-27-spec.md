# PR-4.27 — gm-ca `CaErrorCode` enum + 结构化 metrics (mirror PR-4.18/4.22)

> Status: **PROPOSED**
> Crates: `gm-ca`
> Author: gm-tls PR batch
> Target version: gm-ca 0.4.1 → 0.4.2 (patch bump)
> Spec version: 1.0
> Generated: 2026-09-24

---

## 0. 上下文

PR-4.18 (gm-tls) 引入了 `ErrorCode` enum + `TlsError::code()` 方法，
PR-4.22 (gm-tls) 在 wrap 点把 `record_handshake_error_code(role, code)` emit 到 Prometheus counter `gmtls_handshake_errors_total{role, code}`。

PR-4.21 (gm-tlcp) 镜像了 `TlcpErrorCode` + 同样的 metrics。

**gm-ca 目前用 string `error_type`** 通过 `metrics::record_error(error_type: &str)`：
```rust
pub fn record_error(error_type: &str) {
    counter!("gmca_errors_total", "type" => error_type.to_string()).increment(1);
}
```

调用方在 service.rs 里传 literal strings：
```
metrics::record_error("invalid_profile_json");
metrics::record_error("sign_failed");
metrics::record_error("csr_parse_failed");
metrics::record_error("db_insert_failed");
metrics::record_error("renew_revoked_cert");
metrics::record_error("renew_failed");
metrics::record_error("revoke_failed");
```

PR-4.27 把这些 string 替换成结构化 `CaErrorCode` enum，模式与 PR-4.18/4.22 完全一致。

---

## 1. Background

### 1.1 当前 `gmca_errors_total` 痛点

- **拼写错误无 compile-time 检查**：typo `"renew_failedd"` 不会被捕获
- **新增错误类型不强制同步文档**：dashboard 上线时凭 operator 拼写约定
- **跨 crate 一致性差**：gm-tls 用 `code` label + 结构化 `ErrorCode`, gm-tlcp 用 `code` label + `TlcpErrorCode`,gm-ca 用 `type` label + string —— 三个 crate 各一套
- **Dashboard 字段映射不一致**：gm-tls/tlcp 的 PromQL 用 `code="..."`，gm-ca 用 `type="..."`

### 1.2 设计目标

- 镜像 PR-4.18/4.22: 加 `CaErrorCode` enum + `CaError::code()` 方法
- 把 `record_error` 重命名为 `record_error_code`，参数改为 `CaErrorCode`
- `gmca_errors_total{code=...}` 标签集与 gm-tls/tlcp 一致（label 名改 `type` → `code`）
- 调用方从 string 改为 enum variant —— 编译期检查
- 公开 `pub use error::CaErrorCode` 在 lib.rs re-export

---

## 2. Design

### 2.1 `CaErrorCode` enum

```rust
/// Structured error code for [`CaError`] (PR-4.27 mirror of
/// gm-tls PR-4.18 [`ErrorCode`](gm_tls::error::ErrorCode)).
///
/// The `code` label uses `CaErrorCode`'s `Debug` representation
/// (e.g., `"InvalidArgument"`, `"InvalidCsr"`, `"SigningFailed"`,
/// `"CertificateNotFound"`, `"InvalidCertificate"`,
/// `"DatabaseError"`, `"InternalError"`) so dashboards can alert
/// on differentiated subsystems independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CaErrorCode {
    InvalidArgument,
    InvalidCsr,
    SigningFailed,
    CertificateNotFound,
    InvalidCertificate,
    DatabaseError,
    InternalError,
}
```

### 2.2 `CaError::code()`

```rust
impl CaError {
    pub fn code(&self) -> CaErrorCode {
        match self {
            CaError::InvalidArgument(_) => CaErrorCode::InvalidArgument,
            CaError::InvalidCsr(_) => CaErrorCode::InvalidCsr,
            CaError::SigningFailed(_) => CaErrorCode::SigningFailed,
            CaError::CertificateNotFound(_) => CaErrorCode::CertificateNotFound,
            CaError::InvalidCertificate(_) => CaErrorCode::InvalidCertificate,
            CaError::DatabaseError(_) => CaErrorCode::DatabaseError,
            CaError::InternalError(_) => CaErrorCode::InternalError,
        }
    }
}
```

### 2.3 `metrics::record_error_code`

```rust
/// PR-4.27: Records a CA service error tagged by structured
/// [`CaErrorCode`]. Mirror of
/// `gm_tls::metrics::record_handshake_error_code`. The `code`
/// label uses `CaErrorCode`'s `Debug` representation.
///
/// Replaces the legacy string-based `record_error` API. Existing
/// `record_error` is kept (deprecated) for one release cycle
/// to ease the migration of downstream consumers.
pub fn record_error_code(code: CaErrorCode) {
    let code = format!("{code:?}");
    counter!("gmca_errors_total", "code" => code).increment(1);
}

/// **Deprecated** since 0.4.2 — use [`record_error_code`] with a
/// structured [`CaErrorCode`] instead. The legacy `type` label
/// continues to be incremented for one release cycle so existing
/// dashboards do not break, but new alerts / dashboards should
/// switch to the `code` label.
#[deprecated(since = "0.4.2", note = "use record_error_code with CaErrorCode")]
pub fn record_error(error_type: &str) {
    counter!("gmca_errors_total", "type" => error_type.to_string()).increment(1);
}
```

注意：deprecated `record_error` 保留以**双写** metric —— 老的 `type` label 和新的 `code` label 一同 increment，让 dashboard 切换期不丢数据。

### 2.4 `describe_ca_metrics` 增加 `code` label 文档

`describe_ca_metrics` 已注册 `gmca_errors_total`。加注释说明现在有两个 label：`code` (preferred) + `type` (legacy, deprecated)。

### 2.5 Service.rs 调用点迁移

```rust
// Before:
metrics::record_error("invalid_profile_json");

// After:
metrics::record_error_code(CaErrorCode::InvalidArgument);
```

但等等 —— 当前 service.rs 的 error_string 与 `CaError` variants **不完全 1-to-1 对应**：
- `"invalid_profile_json"` → `CaError::InvalidArgument(String)`
- `"sign_failed"` → `CaError::SigningFailed(String)`
- `"csr_parse_failed"` → `CaError::InvalidCsr(String)`
- `"db_insert_failed"` → `CaError::DatabaseError(String)`
- `"renew_revoked_cert"` → `CaError::InternalError(String)` (没有专门的 `CertRevokedError`)
- `"renew_failed"` → `CaError::InternalError(String)`
- `"revoke_failed"` → `CaError::DatabaseError(String)`

新加 variant `CaErrorCode::InternalError` 是 7 个 variant 之一，`CaError::InternalError` 是对应 variant。`renew_revoked_cert` 实际上是个 internal error case（试图续期已撤销的 cert）。

PR-4.27 维持现有 7 variant 分类不变 —— 业务语义没变，只是 type label → code label + 编译期检查。

### 2.6 lib.rs re-export

```rust
pub use error::{CaError, CaErrorCode};
```

### 2.7 Backward Compatibility

- **`record_error` API deprecated**：仍然工作（同时 increment `type` label）
- **`record_error_code` 新 API**：用结构化 enum + `code` label
- **gmca_errors_total 现在有 2 个 label**：`code` (preferred) + `type` (legacy)
- 一段时间后 (gm-ca 0.5.0?) 删除 deprecated `record_error` —— 本 PR 不做

### 2.8 与 PR-4.18/4.22/4.25/4.26 模式一致

| Crate | Code enum | `code()` method | metric counter |
|-------|-----------|-----------------|----------------|
| gm-tls | `ErrorCode` | `TlsError::code()` (PR-4.18) | `gmtls_handshake_errors_total{role, code}` (PR-4.22) |
| gm-tlcp | `TlcpErrorCode` | `TlcpError::code()` (PR-4.21) | `gmtlcp_handshake_errors_total{role, code}` (PR-4.22) |
| gm-ca | `CaErrorCode` (PR-4.27) | `CaError::code()` (PR-4.27) | `gmca_errors_total{code}` (PR-4.27) |

---

## 3. Test Plan

### 3.1 单元测试

```rust
#[cfg(test)]
mod pr427_ca_error_code_tests {
    use super::*;

    #[test]
    fn all_ca_error_variants_have_a_code() {
        // Iterate every CaError variant → code → variant round-trip.
    }

    #[test]
    fn codes_are_distinct() {
        // Display distinctness.
    }

    #[test]
    fn record_error_code_accepts_all_variants() {
        // Mirror of gm-tls PR-4.22 unit test.
    }

    #[test]
    fn code_method_is_thread_safe() {
        // Mirror of gm-tls PR-4.22 thread-safety test.
    }
}
```

### 3.2 现有测试不得破坏

gm-ca 全部现有测试（lib + integration）必须继续通过。`record_error` deprecated 但仍 emit `type` label —— 现有调用方不破坏。

### 3.3 双 label 行为验证

写一个简单的 unit test 验证 `record_error` + `record_error_code` 各自 increment 对应的 label（不 inspect counter value，只确认不 panic + 不 double-count）。

---

## 4. Rollout

1. SPEC 已写（本文件）
2. 本地 `cargo build -p gm-ca` 必须先绿
3. 改动 error.rs (加 enum + code())
4. 改动 metrics.rs (加 record_error_code, deprecated record_error)
5. 改动 service.rs (9 个调用点迁移) + lib.rs (re-export)
6. 本地 build + test + clippy + fmt + doc
7. CI run 绿（github）
8. 推到 gitee + gitcode

---

## 5. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| gmca_errors_total 增加 `code` label 改变 PromQL 查询语法 | 保留 `type` label（deprecated）让 dashboard 不漂移；文档 CHANGELOG |
| deprecated API 误用 | `#[deprecated(since = "0.4.2")]` 给 compile-time warning |
| service.rs 迁移漏点 | 9 个 literal string 都在 service.rs 一个文件，9 次精确替换 |
| error_string 业务含义不严格对应 enum variant | 文档化映射表 (`renew_revoked_cert` → `CaErrorCode::InternalError`)，CHANGELOG |

---

## 6. Follow-up

- PR-4.28 candidate: gm-ca `record_signature`/`record_renewal`/`record_revocation` 补结构化 `reason` label（用于 fine-grained 业务级细分）
- PR-4.29 candidate: 在 gm-ca 0.5.0 删除 deprecated `record_error`
- PR-4.30 candidate: 跨三个 crate 的统一 dashboard JSON

---

## 7. Out of Scope

- 不改 `gmca_signatures_total` / `gmca_renewals_total` / `gmca_revocations_total`（这些不是错误 metrics）
- 不改 `record_rate_limited` 行为（PR-4.12 已结构化）
- 不改 service.rs 的业务逻辑，只换 metrics 调用 string → enum
- 不引入新依赖（`metrics` crate 已是依赖）