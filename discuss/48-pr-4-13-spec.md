# SPEC: PR-4.13 — gm-tls 会话票证 fail-closed 配置项 (P2-4)

- **目标编号**：PR-4.13（Batch 4 — gm-tls 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §四 P2-4`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md#L145)：会话票证解密失败默认 fail-open（availability over security），建议提供 fail-closed 配置项并评估伪造放大风险
- **范围**：`gm-tls/src/handshake.rs::HandshakeOptions` 增加 `session_ticket_fail_closed` 字段；`gm-tls/src/gm.rs` 解密失败分支按配置行为
- **影响面**：纯增量；默认行为（fail-open）保持不变 → **完全向后兼容**

---

## 1. 问题陈述

[`gm-tls/src/gm.rs:193,313-317`](file:///Users/laozhang/Work/opensource/gm/gm-tls/src/gm.rs#L193)：

```rust
match decrypt_session_ticket(ticket, ticket_key, session_store.clone()).await {
    Ok(mut state) => { /* PSK resumption */ }
    Err(e) => {
        info!("Session ticket decryption failed ({})", e);
        let (ch, sk_client) = build_client_hello(alpn, domain)?;
        (ch, sk_client, None)
    }
}
```

后果：
- **fail-open**：任何解密失败（解密错误 / 反序列化失败 / 解析失败）一律 fallback 到全握手
- **攻击放大风险**：攻击者可以构造大量伪造的 session ticket 推送给客户端 → 客户端每次都执行完整握手 → **CPU/签名验证资源被消耗**
- 攻击者无法获得任何机密（票据里的会话密钥对攻击者不可知），但 DoS 放大真实存在
- **配置语义混乱**：注释说是 "fallback for resilience" 但实际是 fail-open → 安全审计时易漏检

### 1.1 改进建议依据（master plan §四 P2-4）

> `gm-tls/src/session_ticket.rs:231` | 会话票证解密失败默认 fail-open（"availability over security"），建议提供 fail-closed 配置项并评估伪造放大风险

PR-4.13 提供 **opt-in fail-closed 配置项** —— 默认 fail-open 保持兼容；高安全场景下开启 fail-closed。

---

## 2. Fix 策略

### 2.1 配置层：`HandshakeOptions` 新字段

```rust
pub struct HandshakeOptions {
    /* ... existing fields ... */
    /// PR-4.13 / P2-4: when `true`, any session-ticket decryption
    /// failure (other than "expired" or "replay detected", which
    /// always abort) terminates the handshake with an error
    /// instead of falling back to a full handshake. Default:
    /// `false` (fail-open, pre-PR-4.13 behavior).
    pub session_ticket_fail_closed: bool,
}
```

### 2.2 错误分类

`decrypt_session_ticket` 的错误可能来源：
1. **Replay detected**（line 209-213） → 总是 abort（伪造尝试）
2. **Unknown key ID**（line 220-222） → 可能是 attacker 探测 → fail-closed 模式下 abort
3. **SM4-GCM decrypt failure**（line 228-232）→ **真正的密文篡改 / 错误密钥** → fail-closed 模式下 abort
4. **Deserialize failure**（line 235-236） → **密文 OK 但内容损坏 / 伪造** → fail-closed 模式下 abort
5. **Expired ticket**（line 247-251） → **合法但过期** → 即使 fail-closed 也允许 fallback（用户体验优先）
6. **Client-auth-required but no client cert**（line 254-258） → 配置错误 / 协议不匹配 → fail-closed 模式下 abort

**策略**：fail-closed 仅在 **case 2/3/4/6** 生效；case 1（replay）总是 abort；case 5（expired）总是 fallback。

### 2.3 实现位置

在 `gm-tls/src/gm.rs:193` match 中：

```rust
match decrypt_session_ticket(ticket, ticket_key, session_store.clone()).await {
    Ok(mut state) => { /* PSK resumption */ }
    Err(e) => {
        // PR-4.13 / P2-4: classify the error.
        let classification = classify_ticket_error(&e);
        if opts.session_ticket_fail_closed
            && classification == TicketErrorClass::TamperedOrForged
        {
            timer.finish("error");
            return Err(TlsError::HandshakeFailed(format!(
                "session ticket rejected (fail-closed): {}",
                e
            )));
        }
        info!("Session ticket decryption failed ({}): falling back to full handshake", e);
        let (ch, sk_client) = build_client_hello(alpn, domain)?;
        (ch, sk_client, None)
    }
}
```

`classify_ticket_error` 通过匹配 `TlsError` 字符串内容判断（保持简单的字符串匹配 — 避免 `TlsError` 枚举重构）。

### 2.4 TlsConfig builder

```rust
impl TlsConfig {
    pub fn with_session_ticket_fail_closed(mut self, b: bool) -> Self {
        self.session_ticket_fail_closed = b;
        self
    }
}
```

### 2.5 公共 API 兼容

- `TlsConfig::new(...)` 默认 `session_ticket_fail_closed = false`（与 PR-4.13 前 byte-identical）
- `HandshakeOptions.session_ticket_fail_closed` 默认 `false`
- 现有 caller 不需要修改

### 2.6 版本

`gm-tls/Cargo.toml`：**patch bump**（opt-in 配置；默认行为兼容；不破坏现有 API）。

---

## 3. Tests

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr413_default_is_fail_open` | 不调 builder；`HandshakeOptions.session_ticket_fail_closed == false` |
| T2 | `pr413_builder_sets_field` | `TlsConfig::with_session_ticket_fail_closed(true)` 后字段为 true |
| T3 | `pr413_classify_error_distinguishes_expired_vs_tampered` | 字符串 "expired" → Expired；"decryption failed" → TamperedOrForged；"replay" → ReplayDetected |
| T4 | `pr413_fail_closed_aborts_on_tampered_ticket` | mock 一个解密失败的 ticket；fail-closed → 返回 `TlsError::HandshakeFailed`；fail-open → 继续走 full handshake |
| T5 | `pr413_fail_closed_allows_expired_ticket_fallback` | mock "expired" 错误；fail-closed → 仍然 fallback（用户体验优先） |

T1-T3 是单元测试；T4-T5 需要构造 partial `HandshakeOptions` → 通过 mock `decrypt_session_ticket` 路径不切实际；**改为在 `classify_ticket_error` 层面测试**，外加构建一个能触发 `decrypt_session_ticket` 返回特定错误的最小测试 case（如果成本太高，可仅测试 classifier + T1-T3）。

---

## 4. 验证矩阵

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy -p gm-tls --all-targets -- -D warnings
cargo +1.88 test -p gm-tls --all-targets pr413_
cargo +1.88 test -p gm-tls -p gm-tlcp -p gm-ca --all-targets    # 全量回归
```

CI 含 GmSSL Interop / TLCP Interop（确认 default fail-open 行为不破坏 interop）。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 默认 fail-open 被解读为"故意不安全" | docstring 明确说明：fail-open 是 RFC 5077 §3.3 推荐行为（resilience over strictness），fail-closed 是 opt-in 安全加固 |
| 字符串分类 `classify_ticket_error` 脆弱 | 单元测试 T3 锁定字符串格式；任何 TlsError 文案变更会在 PR 触发测试失败 |
| fail-closed 导致用户体验差（合法过期票据 → 强制重连） | 故意**不**把 "expired" 归类为 TamperedOrForged（用户体验优先） |
| 大量客户端升级后忘记开 fail-closed → DoS 放大仍然存在 | CHANGELOG / README 醒目标注 + 文档 `docs/security/ticket-policy.md` 推荐生产环境启用 |

---

## 6. Out of Scope

- 改造 `decrypt_session_ticket` 为结构化错误（typed error enum）—— PR-4.13 只改字符串匹配
- 引入 `classify_ticket_error` 之外的更复杂分类（e.g. network-side vs application-side）
- 任何与 fail-open / fail-closed 策略无关的 session ticket 行为变更

---

## 7. 后续 PR 候选

- **PR-4.14**：gm-crypto SM2 私钥 [1, n-1] 范围校验 (P2-9)
- **PR-4.15**：gm-kms Postgres in-memory 冷热分层 (P2-10)
- **PR-4.16**：`TlsError` 重构为 typed error enum，统一 `classify_ticket_error` 等错误分类
