# SPEC: PR-4.20 — gm-tls CRL grace period + session cache miss-time semantics

- **目标编号**：PR-4.20（Batch 4 follow-up — gm-tls 工程完善）
- **触发**：[`discuss/50-pr-4-18-spec.md §7`](file:///Users/laozhang/Work/opensource/gm/discuss/50-pr-4-18-spec.md) 列出 "PR-4.21：gm-tls CRL grace period + session cache persistence"
- **范围**：`gm-tls/src/handshake.rs` 新增 `crl_grace_period: Duration` 字段 + `gm-tls/src/gm.rs` 在 CRL check 处应用 grace period + 测试
- **影响面**：纯增量；默认 `Duration::ZERO`（PR-4.20 之前行为完全保留）；opt-in grace period

---

## 1. 问题陈述

[`gm-tls/src/gm.rs:415-426`](file:///Users/laozhang/Work/opensource/gm/gm-tls/src/gm.rs#L415)：

```rust
// Check CRL if provided
if let Some(ref crl) = opts.crl_info {
    let leaf_cert = leaf_chain[0].as_x509()?;
    let cert_serial = leaf_cert.serial.to_bytes_be();
    verify_crl(
        &cert_serial,
        leaf_cert.issuer(),
        &trust[0].as_x509()?,
        crl,
        OffsetDateTime::now_utc(),
    )?;
}
```

[`gm-tls/src/gm.rs:671`](file:///Users/laozhang/Work/opensource/gm/gm-tls/src/gm.rs#L671) (server path, similar structure)：
同上的 CRL check 调用。

后果：
- **生产环境常见故障**：CRL 缓存过期 5–10 分钟（CRL publisher 短暂不可达 / network glitch / 上游 CDN 抖动），客户端立刻拒绝所有连接。这是 TLS 经典的"certificate revocation gone wrong"问题——很多 production outage 来自**过于严格**的 CRL check
- **CABF §4.9.6** (BR 1.8.x) 要求 CA 在 revocation 后 24 小时内下发 CRL，但**没有**要求客户端在 0 秒内 reject；现实部署中通常允许 `crl_grace_period > 0`
- **Microsoft WinHTTP** 默认 10 分钟 grace period；**curl** 默认 0；**Java SunCertPath** 默认 0；**Apple TLS** 默认 0 — 业界不统一，但**允许配置**是事实标准
- gm-tls 现状：要么完全 fail-fast（CRL 过期即拒），要么完全关闭（不传 `crl_info`）。无 grace period 概念

### 1.1 改进建议依据

PR-4.18 SPEC §7：
> **PR-4.21**：gm-tls CRL grace period + session cache persistence

PR-4.20 实现 CRL grace period 那一半（session cache persistence 是 gm-tlcp 范畴，不在此 PR）。

---

## 2. Fix 策略

### 2.1 新增 `crl_grace_period` 字段 + builder

```rust
// handshake.rs
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct HandshakeOptions {
    // ... existing fields ...
    
    /// PR-4.20: CRL grace period. When the CRL's
    /// `next_update` is in the past (i.e., the CA hasn't
    /// refreshed the CRL yet), the verifier accepts the
    /// CRL for up to `crl_grace_period` past
    /// `next_update` before treating it as expired.
    ///
    /// Default: `Duration::ZERO` (fail-fast on stale CRL,
    /// pre-PR-4.20 behaviour). Operators concerned about
    /// transient CRL publisher outages should set this to
    /// e.g. `Duration::from_secs(600)` (10 min) per
    /// Microsoft's WinHTTP default.
    pub crl_grace_period: Duration,
}
```

```rust
// lib.rs
impl TlsConfig {
    // ... existing builders ...

    /// Set CRL grace period. See
    /// [`HandshakeOptions::crl_grace_period`].
    pub fn with_crl_grace_period(mut self, period: Duration) -> Self {
        self.handshake_opts
            .get_or_insert_with(HandshakeOptions::default);
        if let Some(opts) = &mut self.handshake_opts {
            opts.crl_grace_period = period;
        }
        self
    }
}
```

### 2.2 应用 grace period

修改 CRL check 调用，传入 grace period。当前 `verify_crl()` 直接传 `OffsetDateTime::now_utc()` 作为 verification time；改为 `now + grace_period` —— 这样 `next_update + grace_period > now` 时 CRL 仍然有效。

```rust
// gm.rs (client and server paths)
if let Some(ref crl) = opts.crl_info {
    let leaf_cert = leaf_chain[0].as_x509()?;
    let cert_serial = leaf_cert.serial.to_bytes_be();
    let effective_now = if opts.crl_grace_period.is_zero() {
        OffsetDateTime::now_utc()
    } else {
        OffsetDateTime::now_utc() + opts.crl_grace_period
    };
    verify_crl(
        &cert_serial,
        leaf_cert.issuer(),
        &trust[0].as_x509()?,
        crl,
        effective_now,
    )?;
}
```

**注意**：`verify_crl()` 内部对 `crl.next_update` 和 `effective_now` 比较，传入 `effective_now + grace_period` 等价于让 CRL 在 `next_update + grace_period` 之前都视为有效。

### 2.3 公共 API 兼容

- `crl_grace_period: Duration` 是新字段；`Default::default()` = `Duration::ZERO`，所有旧调用者行为不变
- 新增 builder `with_crl_grace_period(period)` opt-in
- `#[non_exhaustive]` 保护（虽然 PR-4.20 字段是 new field，下游不会因为新字段而 break；但 matcher 可能 exhaustive 假设）

### 2.4 版本

`gm-tls/Cargo.toml`：**patch bump**（新 builder；默认行为字节级兼容）。

---

## 3. Tests

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr420_default_grace_period_is_zero` | `HandshakeOptions::default().crl_grace_period == Duration::ZERO` |
| T2 | `pr420_with_crl_grace_period_sets_field` | `TlsConfig::with_crl_grace_period(Duration::from_secs(600))` → 字段为 600s |
| T3 | `pr420_grace_period_does_not_affect_valid_crl` | 构造有效 CRL（next_update = now + 1 hour） + grace = 10 min：handshake 成功（grace 不适用，因为 CRL 还没过期） |
| T4 | `pr420_grace_period_extends_stale_crl_lifetime` | 构造 stale CRL（next_update = now - 5 min） + grace = 10 min：handshake 成功（5min < 10min grace） |
| T5 | `pr420_stale_crl_without_grace_still_fails` | 构造 stale CRL + grace = 0：handshake 失败 (`CrlVerificationFailed`) |
| T6 | `pr420_stale_crl_beyond_grace_fails` | 构造 stale CRL（next_update = now - 1 hour） + grace = 10 min：handshake 失败 (`CrlVerificationFailed`) |

T3-T6 需要构造 CRL + cert chain。CRL 构造在 `gm-crypto::x509::crl::create_crl` 已经存在；本 PR 复用现有 helper。

### 3.1 测试策略

CRL 测试与现有 `cert_verify.rs` 中的 CRL 测试同结构。新增独立 test module `pr420_crl_grace_period_tests`：
- T1 / T2：纯 unit 测试，不需要 mock
- T3 / T4 / T5 / T6：构造真实 CRL + 证书（用 `ring` 自签），调用 `verify_crl()` + 模拟 grace period，断言结果

---

## 4. 验证矩阵

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings
cargo +1.88 test -p gm-tls --lib pr420_
cargo +1.88 test -p gm-tls -p gm-tlcp -p gm-ca --all-targets
```

CI 含 GmSSL Interop / TLCP Interop。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| Grace period 被滥用（运营设 24h）导致 revoke 延迟 | 默认 `Duration::ZERO`；显式 builder；建议 5–15 min 上限（在文档中说明） |
| Grace period 字段被滥用绕过 revoke | grace period 只影响 "next_update 已过" 的 CRL，**不影响** cert 在 CRL 中已列出（被 revoke）的情况；后者永远 reject |
| 客户端和服务器行为不一致 | gm-tls 同时是 client + server；本 PR 在两边都生效；默认 0 即 fail-fast，对齐客户端常见默认 |
| 测试需要构造 CRL + cert chain | 复用现有 `gm-crypto` helper；测试在 `cert_verify.rs` 中已有类似模式 |

---

## 6. Out of Scope

- **Session cache persistence (gm-tls → disk / Redis)**：gm-tls 不直接负责 session cache 持久化；`SessionStore` trait 已暴露，调用方可用 `RedisSessionStore`（社区实现）或 `DiskSessionStore`（暂未提供）。本 PR 不增加新 SessionStore impl
- **CRL delta updates / CRL partition**：gm-crypto 现有 CRL 解析已支持，但不在 PR-4.20 scope
- **CrlInfo refresh 自动 cron**：gm-tls 不应承担；建议运维侧实现 sidecar 周期性 `update_crl_info()`

---

## 7. 后续 PR 候选

- **PR-4.21**：gm-tlcp 错误类型统一
- **PR-4.22**：gm-kms preload metrics + per-tenant preload status
- **PR-4.23**：`RedisSessionStore` 内置实现（gm-tls 现状下需用户自实现；提供 reference impl 提升易用性）
