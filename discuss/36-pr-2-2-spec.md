# SPEC: PR-2.2 — SM2 distid silent fallback → STRICT default (with per-anchor opt-out)

- **目标编号**：PR-2.2（Batch 2 / P0-7）
- **触发**：[`/Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md) P0-7
- **范围**：`gm/gm-crypto/src/x509/verify.rs` (`verify_cert_signature` + `verify_crl_signature` 的 distid 静默回退) + 新 `DistidPolicy` 枚举 + 内部链验证路径 (`verify_cert_chain_sm2` → `verify_cert_chain_sm2_chain` → `verify_against_anchors`)，gm-tlcp/gm-tls 调用点对齐
- **影响面**：保持现有公共 API 签名向后兼容（`verify_against_anchors` / `verify_cert_chain_sm2_chain` 行为收紧为 STRICT，新增 `*_with_distid_policy` 入口给需要 OpenSSL 3.x 兼容的调用方）

---

## 1. 问题陈述

### 1.1 fail-open 现状

`gm-crypto/src/x509/verify.rs` 中 `verify_cert_signature`（行 1086-1112）与 `verify_crl_signature`（行 1160-1181）都使用如下模式：

```rust
let verifier = Sm2Verifier::new(&sm2_pub_key, "1234567812345678")?;
match verifier.verify(tbs_bytes, &sig_raw) {
    Ok(()) => Ok(()),
    Err(_) => {
        // Fall back to empty ID (OpenSSL 3.x default)
        let verifier2 = Sm2Verifier::new(&sm2_pub_key, "")?;
        verifier2.verify(tbs_bytes, &sig_raw).map_err(...)
    }
}
```

也就是：先用 GM/T 标准 distid `"1234567812345678"` 验签，失败后**静默**回退到空 distid `""`（OpenSSL 3.x 默认值），两种 distid 都接受。

### 1.2 风险

**签发 / 验证 distid 不对称**（gm-ca `cert.rs:366` 等多处用 `GM_TLS_DEFAULT_ID` 签发，gm-crypto 验证侧却接受空 distid）：

- 攻击者可以用空 distid 签发伪造证书（OpenSSL 3.x 默认行为），绕过"标准 distid 强签"的语义；
- 即使签发生态全部使用标准 distid，攻击者引入一条弱签名的证书链仍能通过验证；
- 探测侧信道：客户端库会同时接受两种 distid，无法通过签名验证结果区分"标准 ID 证书" vs "弱 ID 证书"；
- 静默回退导致审计盲区——没有事件日志/告警记录"本次握手走了弱 ID 路径"。

### 1.3 调用方盘点（核实结论）

**gm-crypto 内部**（需要修改）：
- `verify_cert_signature`（行 1028）— 当前硬编码 fallback
- `verify_crl_signature`（行 1116）— 当前硬编码 fallback

**gm-crypto 公共 API**（保持签名，新增 `_with_distid_policy`）：
- `verify_against_anchors`（行 632）
- `verify_cert_chain_sm2_chain`（行 435）

**gm-tlcp 调用点**（3 处，全部使用旧签名走 STRICT 默认）：
- `src/tlcp/mod.rs:2053`（connector sign leaf 验签）
- `src/tlcp/mod.rs:2106`（connector enc leaf 验签）
- `src/tlcp/mod.rs:4082`（acceptor client sign leaf 验签）

**gm-tls 调用点**（2 处使用 `verify_cert_chain_sm2_chain`，1 处 re-export wrapper）：
- `src/gm.rs:355`（PEM path）
- `src/gm.rs:606`（PEM path）
- `src/cert_verify.rs:60`（thin shim 转发 `verify_cert_chain_sm2_chain`）
- 测试 + fuzz：使用 `verify_cert_chain_sm2_chain`，走 STRICT 默认即可。

`gm-ca` 签发路径：全部用 `GM_TLS_DEFAULT_ID`（行 248/366/453/531），不受 PR-2.2 影响。

---

## 2. Fix 策略

### 2.1 引入 `DistidPolicy` 枚举

```rust
/// SM2 signature distinguishing-identifier policy.
///
/// `Strict` is the secure default (RFC 5280 / GB/T 32918-2016 strict
/// semantics): only the GM/T standard distid `"1234567812345678"`
/// is accepted. `Permissive` preserves the v0.3.x behaviour of also
/// accepting the empty distid (OpenSSL 3.x default) for legacy
/// interop, and emits an audit callback for every fallback event
/// so operators can detect / alert on "weak ID signed" handshakes.
///
/// Note: this knob governs the SM2 `distid` only. The cryptographic
/// signature decision (r/s validation, public-key binding, etc.)
/// is unchanged.
#[derive(Debug, Clone)]
pub enum DistidPolicy {
    /// Only accept the GM/T standard distid `"1234567812345678"`.
    /// Default since v0.3.5.
    Strict,

    /// Accept the GM/T standard distid first, then fall back to a
    /// caller-provided list of weaker distids (typically `[""]` for
    /// OpenSSL 3.x interop). The callback is invoked once per
    /// fallback event with the accepted distid, so the operator can
    /// log / alert.
    Permissive {
        /// Ordered list of distids to attempt, after `"1234567812345678"`.
        /// The first match wins.
        fallback_distids: Vec<String>,
        /// Called when a fallback distid (not the GM/T standard one)
        /// was used to verify a signature. Receives the accepted
        /// distid as `&str`. Set to `None` to silence.
        audit_on_fallback: Option<Arc<dyn Fn(&str) + Send + Sync>>,
    },
}

impl Default for DistidPolicy {
    fn default() -> Self { DistidPolicy::Strict }
}
```

### 2.2 新签名（不破坏旧 API）

```rust
// 旧签名（保留）：默认 STRICT（行为收紧）
pub fn verify_against_anchors(
    leaf_chain_der: &[Vec<u8>],
    anchors_der: &[Vec<u8>],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
    role: Option<CertRole>,
) -> Result<(), CryptoError> {
    verify_against_anchors_with_distid_policy(
        leaf_chain_der,
        anchors_der,
        now,
        expected_domain,
        role,
        DistidPolicy::Strict,
    )
}

// 新签名：调用方显式选择 distid 策略
pub fn verify_against_anchors_with_distid_policy(
    leaf_chain_der: &[Vec<u8>],
    anchors_der: &[Vec<u8>],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
    role: Option<CertRole>,
    distid_policy: DistidPolicy,
) -> Result<(), CryptoError> {
    // ... 转发到 verify_cert_chain_sm2_chain_with_distid_policy
}

// 旧签名（保留）：默认 STRICT
pub fn verify_cert_chain_sm2_chain(
    leaf_chain: &[OwnedCert],
    trust_anchors: &[OwnedCert],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
    role: Option<CertRole>,
) -> Result<(), CryptoError> {
    verify_cert_chain_sm2_chain_with_distid_policy(
        leaf_chain, trust_anchors, now, expected_domain, role,
        DistidPolicy::Strict,
    )
}

// 新签名：调用方显式选择 distid 策略
pub fn verify_cert_chain_sm2_chain_with_distid_policy(
    leaf_chain: &[OwnedCert],
    trust_anchors: &[OwnedCert],
    now: OffsetDateTime,
    expected_domain: Option<&str>,
    role: Option<CertRole>,
    distid_policy: DistidPolicy,
) -> Result<(), CryptoError> {
    // ...
}
```

### 2.3 内部函数签名变更

```rust
// 私有：增加 distid_policy 参数
fn verify_cert_chain_sm2_with_distid(
    leaf: &OwnedCert,
    ca: &OwnedCert,
    now: OffsetDateTime,
    expected_domain: Option<&str>,
    distid_policy: &DistidPolicy,
) -> Result<(), CryptoError> { /* ... */ }

// 私有：替换硬编码 fallback
fn verify_cert_signature_with_distid(
    leaf_cert: &X509Certificate<'_>,
    ca_cert: &X509Certificate<'_>,
    leaf_der: &[u8],
    distid_policy: &DistidPolicy,
) -> Result<(), CryptoError> { /* ... */ }

// 私有：CRL 签名也走相同策略
fn verify_crl_signature_with_distid(
    crl: &CrlInfo,
    ca_cert: &X509Certificate<'_>,
    distid_policy: &DistidPolicy,
) -> Result<(), CryptoError> { /* ... */ }
```

旧 `verify_cert_signature` / `verify_crl_signature` 变成调用 `*_with_distid(.., &DistidPolicy::Strict)` 的 thin shim（保持向后兼容给可能存在的下游直接调用方；目前审计未发现直接调用方）。

### 2.4 STRICT vs PERMISSIVE 行为差异

| 失败源 | STRICT | PERMISSIVE |
| --- | --- | --- |
| 标准 distid (`"1234567812345678"`) 验签通过 | `Ok(())` | `Ok(())` |
| 标准 distid 失败 | `Err` | 尝试 fallback distids |
| Fallback distid 成功（如空 ID） | n/a | `Ok(())` + 触发 audit 回调 |
| 所有 distid 都失败 | `Err` | `Err` |

### 2.5 调用方迁移

**gm-tlcp 3 个调用点**（`src/tlcp/mod.rs:2053, 2106, 4082`）：保持旧签名 → STRICT 默认。如果后续部署需要 OpenSSL 3.x 兼容，可以扩展 `TlcpConnector::with_distid_policy(...)` + `TlcpAcceptor::with_distid_policy(...)` builder（**不在本 PR 范围**，由 PR-2.4+ 路线图处理）。

**gm-tls 2 个调用点 + wrapper**（`src/gm.rs:355, 606` + `src/cert_verify.rs:60`）：保持旧签名 → STRICT 默认。

**gm-tlcp 集成测试**：f01..f10、j01..j05 全部使用 gm-ca 签发的标准 distid 证书，在 STRICT 下应继续通过。需要验证 CI 后再决定是否需要更新测试。

---

## 3. Tests

### 3.1 单元测试（新增 6+ 个到 `verify.rs` 测试 mod）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `distid_policy_default_is_strict` | `DistidPolicy::default() == Strict` |
| T2 | `verify_cert_with_strict_rejects_weak_distid_signature` | 构造一对 GM/T 标准 distid 签名的 CA → leaf，然后用空 distid 签一个伪造 leaf 试图通过 STRICT 验证 → 拒绝 |
| T3 | `verify_cert_with_permissive_accepts_weak_distid_and_audits` | 同样 T2 场景，但 PERMISSIVE 下接受；audit 回调被触发并收到正确的 distid |
| T4 | `verify_crl_with_strict_rejects_weak_distid_signature` | CRL 路径同样验证 STRICT 拒绝弱签名 |
| T5 | `verify_cert_with_permissive_silent_when_no_audit` | PERMISSIVE 但 `audit_on_fallback=None` 时不强求 callback，行为应与 v0.3.x 一致 |
| T6 | `verify_against_anchors_default_is_strict` | 旧签名 `verify_against_anchors(..)` 走 STRICT |

### 3.2 回归测试

确保现有 CRL / 证书验证测试不被破坏。所有现有 fixture 都是 gm-ca 标准 distid 签发的，在 STRICT 下应当继续 `Ok`。

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p gm-crypto --lib
cargo +1.88 test -p gm-tlcp --features tlcp-profiles
cargo +1.88 test -p gm-tls
cargo +1.88 build -p gm-ca
```

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 部署链路上有第三方 CA 用了空 distid（OpenSSL 3.x 默认）→ 升级后握手失败 | 提供 `DistidPolicy::Permissive` opt-in + CHANGELOG 标注 v0.3.5 默认变严；该场景应同时配 audit 回调 |
| 现有 gm-tlcp / gm-tls 集成测试用的是 gm-ca 标准 distid 签发的 fixture → 应继续通过 | 验证矩阵包含全套 gm-tlcp / gm-tls 测试；若有失败，更新测试或放宽为 PERMISSIVE |
| gm-tlcp / gm-tls 接受 OpenSSL 3.x 第三方签发的证书 → 升级后无法建立 | 通过 BLA / BAA 公告"v0.3.5 默认 STRICT，需要 OpenSSL 兼容的部署请使用 0.3.x" |
| audit 回调在 hot path 上引入额外开销 | audit 回调只在 fallback 触发时调用，标准 distid 验签路径无额外开销 |

---

## 6. Out of Scope（不在本 PR 范围）

- gm-tlcp / gm-tls 增加 `with_distid_policy(...)` builder（PR-2.4+ 路线图）
- gm-kms 的 SM2 验签路径（PR-2.6+ 路线图）
- SM2 确定性签名 (P1-2 / PR-6.1)
- 其他 distid 相关加固（如 `Sm2Signer::new_with_distid` 强制非空检查）