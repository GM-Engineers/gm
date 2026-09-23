# SPEC: PR-4.16 — gm-tls `TlsError` 会话票证变体 typed 化 (PR-4.13 follow-up)

- **目标编号**：PR-4.16（Batch 4 follow-up — gm-tls 工程完善）
- **触发**：PR-4.13 SPEC 显式声明 "PR-4.16: `TlsError` 重构为 typed error enum, 统一 `classify_ticket_error` 等错误分类"
- **范围**：`gm-tls/src/error.rs` 新增 4 个 typed 变体 + `gm-tls/src/session_ticket.rs` 改用 typed 变体 + `classify_ticket_error` 改为变体匹配
- **影响面**：纯增量；`#[non_exhaustive]` 保护下，旧 `HandshakeFailed("decryption failed: ...")` 调用者仍能通过 `Display` / `code()` 兼容

---

## 1. 问题陈述

[`gm-tls/src/session_ticket.rs:189-264`](file:///Users/laozhang/Work/opensource/gm/gm-tls/src/session_ticket.rs#L189)：所有 `decrypt_session_ticket` 失败路径都包装成 `TlsError::HandshakeFailed(format!(...))`，错误细节**仅**通过字符串区分：

```rust
return Err(TlsError::HandshakeFailed("invalid session ticket".into()));
return Err(TlsError::HandshakeFailed(format!(
    "session ticket too large: {} bytes (max {})", combined.len(), MAX_SESSION_TICKET_SIZE
)));
return Err(TlsError::HandshakeFailed(
    "session ticket replay detected - ticket already used".into()
));
return Err(TlsError::HandshakeFailed(format!(
    "unknown ticket key ID: {}", key_id
)));
return Err(TlsError::HandshakeFailed(format!(
    "failed to create decryptor: {}", e
)));
return Err(TlsError::HandshakeFailed(format!(
    "session ticket decryption failed: {}", e
)));
return Err(TlsError::HandshakeFailed(format!(
    "session state parse failed: {}", e
)));
return Err(TlsError::HandshakeFailed("session ticket has expired".into()));
return Err(TlsError::HandshakeFailed(
    "session ticket does not support resumption of client-authenticated sessions".into()
));
```

后果：
- **PR-4.13 的 `classify_ticket_error` 必须做字符串子串匹配**：
  ```rust
  let s = err.to_string();
  if s.contains("replay detected") || s.contains("already used") {
      TicketErrorClass::ReplayDetected
  } else if s.contains("expired") {
      TicketErrorClass::Expired
  } else if s.contains("decryption failed")
      || s.contains("invalid session ticket")
      || s.contains("unknown ticket key")
      || s.contains("session state parse failed")
      || s.contains("does not support resumption of client-authenticated sessions")
      || s.contains("ticket too large")
  {
      TicketErrorClass::TamperedOrForged
  }
  ```
  **脆弱**：任何文案变更 → 静默分类错误（测试可能会覆盖，但分类层级越深越容易漏）
- **无法模式匹配**：调用方只能通过 `Display` 内容判断错误类型，无法用 `match`
- **错误码缺失**：`ErrorCode` 枚举没有专门的"会话票证"分类（仅 `HandshakeFailed`）
- **metrics 标签粗糙**：fail-closed 时发出的 `record_cert_error("session_ticket_tampered")` 是字符串字面量，无枚举引用

### 1.1 改进建议依据（PR-4.13 SPEC 引用）

> **PR-4.16**：`TlsError` 重构为 typed error enum，统一 `classify_ticket_error` 等错误分类

PR-4.16 解决：将 6 个 ticket 相关错误路径改为**类型化变体**，删除字符串依赖。

---

## 2. Fix 策略

### 2.1 新增 `TlsError` 变体（typed）

```rust
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TlsError {
    // ... existing variants ...

    /// PR-4.16: session ticket failed validation that
    /// indicates tampering or wrong key. Distinguished from
    /// `HandshakeFailed` so callers can pattern-match without
    /// string parsing. Covers: bad length, unknown key ID,
    /// SM4-GCM decryption failure, deserialize failure,
    /// client-auth-required mismatch, ticket-too-large.
    #[error("session ticket invalid: {0}")]
    SessionTicketInvalid(String),

    /// PR-4.16: legitimate ticket expiry. Distinct from
    /// `SessionTicketInvalid` because the right operator
    /// response is "fall back to full handshake" (always),
    /// not "abort if fail-closed" (the latter is the
    /// fail-closed mode for tampered tickets).
    #[error("session ticket has expired")]
    SessionTicketExpired,

    /// PR-4.16: replay protection triggered. Always abort
    /// (regardless of fail-closed mode).
    #[error("session ticket replay detected")]
    SessionTicketReplay,
}
```

### 2.2 新增 `ErrorCode` 变体

```rust
pub enum ErrorCode {
    // ... existing variants ...
    /// PR-4.16: ticket-related failure (any of the three
    /// new variants above).
    SessionTicket,
}
```

### 2.3 `decrypt_session_ticket` 改用 typed 变体

替换所有 9 个 `TlsError::HandshakeFailed(format!(...))` 为对应 typed 变体：

| 当前 (string-format) | 替代 |
| --- | --- |
| `HandshakeFailed("invalid session ticket")` | `SessionTicketInvalid("invalid session ticket")` |
| `HandshakeFailed("session ticket too large: ...")` | `SessionTicketInvalid(format!("too large: ... bytes"))` |
| `HandshakeFailed("replay detected - ticket already used")` | `SessionTicketReplay` |
| `HandshakeFailed("unknown ticket key ID: ...")` | `SessionTicketInvalid(format!("unknown key ID: ..."))` |
| `HandshakeFailed("failed to create decryptor: ...")` | `SessionTicketInvalid(format!("decryptor init: ..."))` |
| `HandshakeFailed("session ticket decryption failed: ...")` | `SessionTicketInvalid(format!("decryption failed: ..."))` |
| `HandshakeFailed("session state parse failed: ...")` | `SessionTicketInvalid(format!("state parse: ..."))` |
| `HandshakeFailed("session ticket has expired")` | `SessionTicketExpired` |
| `HandshakeFailed("does not support resumption of client-authenticated sessions")` | `SessionTicketInvalid("client-auth-required ticket not supported".into())` |

### 2.4 `classify_ticket_error` 重写为变体匹配

```rust
pub fn classify_ticket_error(err: &TlsError) -> TicketErrorClass {
    match err {
        TlsError::SessionTicketReplay => TicketErrorClass::ReplayDetected,
        TlsError::SessionTicketExpired => TicketErrorClass::Expired,
        TlsError::SessionTicketInvalid(_) => TicketErrorClass::TamperedOrForged,
        _ => TicketErrorClass::Other,
    }
}
```

删除所有字符串匹配分支。**完全 typed**。

### 2.5 公共 API 兼容

- `TlsError::code()` 新增映射 3 个新变体到 `ErrorCode::SessionTicket`
- `is_config_error()` / `is_transient()` 不变（新变体是 trans 行为外）
- 旧 `HandshakeFailed("...")` 文案不再从 `decrypt_session_ticket` 发出；但其他模块仍可用 `HandshakeFailed`
- `#[non_exhaustive]` 保护：未来 caller 不会因为新变体而 break

### 2.6 版本

`gm-tls/Cargo.toml`：**patch bump**（公共 API 增量；`#[non_exhaustive]` 保护；变体匹配对其他模块无影响）。

---

## 3. Tests

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr416_session_ticket_invalid_variant_matches` | 构造 `TlsError::SessionTicketInvalid("foo")` → `code() == ErrorCode::SessionTicket` |
| T2 | `pr416_session_ticket_expired_variant_matches` | `SessionTicketExpired` → `code() == ErrorCode::SessionTicket` |
| T3 | `pr416_session_ticket_replay_variant_matches` | `SessionTicketReplay` → `code() == ErrorCode::SessionTicket` |
| T4 | `pr416_classify_uses_variant_not_string` | 用 3 个 typed 变体各调用 `classify_ticket_error`；断言 3 个不同的 `TicketErrorClass` |
| T5 | `pr416_classify_falls_back_to_other` | 传入 `HandshakeFailed("anything")` → `Other` |
| T6 | `pr416_decrypt_session_ticket_invalid_size_returns_typed_invalid` | 短 ticket（< 29 字节）→ `SessionTicketInvalid` |
| T7 | `pr416_decrypt_session_ticket_expired_returns_typed_expired` | 构造合法 ticket + back-dated `created_at` → `SessionTicketExpired` |

T6/T7 需要构造 `SessionTicket` + `TicketKeySet` + mock `SessionStore`。Mock 实现见现有 `tests/`。

---

## 4. 验证矩阵

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy -p gm-tls --all-targets -- -D warnings
cargo +1.88 test -p gm-tls --all-targets pr416_
cargo +1.88 test -p gm-tls -p gm-tlcp -p gm-ca --all-targets    # 全量
```

CI 含 GmSSL Interop / TLCP Interop（确认 ticket 路径行为不变）。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 现有 caller 通过 `Display` 内容判断 ticket 错误 | `#[error("...")]` 文案保持完全兼容（旧字串保留在 SessionTicketInvalid 的 payload） |
| 11 个 PR-4.13 测试 (`pr413_*`) 假设字符串分类；改 typed 后可能失败 | 在 PR-4.16 中**同时更新** PR-4.13 测试用 typed 构造替代字符串构造 |
| `gm-tlcp` 镜像使用类似模式 → 是否需要同步改 | PR-4.16 **不**改 gm-tlcp；scope 限于 gm-tls |
| 新变体 + `#[non_exhaustive]` 是否破坏下游 crate | 不会（#[non_exhaustive] 保证向下兼容） |

---

## 6. Out of Scope

- 改 `gm-tlcp` 错误（`gm_tlcp::TlcpError`）的对应 typed 化（gm-tlcp 自有错误类型）
- 改其他模块（`gm.rs`, `record_layer.rs`, `kdf.rs`）的 `HandshakeFailed(format!(...))` → 这些不是 ticket 错误，不在 PR-4.16 scope
- 新增 `SessionTicket` 相关 error 变体外的 typed 化（如 `CertVerificationFailed` 已经有 typed；不需要重复）

---

## 7. 后续 PR 候选

- **PR-4.17**：gm-tls 全面 typed error 化（包括 `HandshakeFailed` 内部细分）
- **PR-4.18**：gm-kms keystore 真正 lazy load（PR-4.15 SPEC 引用）
- **PR-4.19**：gm-tlcp 错误类型统一
