# SPEC: PR-2.1 — CRL fail-open → STRICT 默认（PERMISSIVE 作为 opt-in 兼容）

- **目标编号**：PR-2.1（Batch 2 / P0-4）
- **触发**：[`/Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md`](file:///Users/laozhang/Downloads/gm 与gm-kms%E6%BA%90%E7%A0%81%E7%BA%A7%E6%94%B9%E8%BF%9B%E5%BB%BA%E8%AE%AE.md) P0-4
- **范围**：`gm/gm-crypto/src/x509/verify.rs`（`check_revocations` + 新 `CrlVerifyPolicy` 枚举） + 3 个 gm-tlcp 调用点
- **影响面**：**不破坏现有公共 API**（保留旧签名 `check_revocations(chain, crls, now)` 走 STRICT，新增 `check_revocations_with_policy(chain, crls, now, policy)` 给需要 PERMISSIVE 的调用方用）

---

## 1. 问题陈述

### 1.1 fail-open 现状

`gm-crypto/src/x509/verify.rs:881-940` 的 `check_revocations` 在 CRL 处理上有 4 个 `continue` 静默吞错的点：

| 行 | 静默路径 | 安全影响 |
| --- | --- | --- |
| 891-892 | `CrlInfo::from_der` 失败 → continue | 畸形/伪造 CRL 被跳过 |
| 894-896 | `crl.issuer_der()` 失败 → continue | 同上 |
| 911 | 链中找不到与 CRL issuer 匹配的 CA → continue | CRL 与当前链不匹配时被忽略 |
| 924-926 | `cert_owned.as_x509()` 失败 → continue | 链中存在畸形证书时被忽略 |
| 927-928 | `cert.issuer().as_raw()` 不匹配 → continue | 跳过非该 CRL issuer 的链证书（这一项实际上是正确的） |

按 RFC 5280 §6.3 严格语义，CRL 处理失败应拒绝握手；当前实现选择 fail-open（"one bad CRL does not invalidate the whole handshake"），允许降级到无 CRL 验证。

### 1.2 风险

- **CRL 投毒**：攻击者投递畸形 CRL 字节（例如随机截断 / 篡改 TBS 但保留签名），CA 无法解析 → 旧实现跳过 → 攻击者绕过了撤销检查；
- **CRL 缺席攻击**：依赖 CRL 验证的合规场景，畸形 CRL + fail-open = 等价于不验证；
- **RFC 5280 / GB/T 25056-2018 §7.4 合规缺口**：标准要求 CRL 处理失败应 fail-closed。

### 1.3 调用方盘点（核实结论）

```
gm-tlcp/src/tlcp/mod.rs:2082, :2127, :4106  → 3 处调用 check_revocations
gm-tls/src/gm.rs:367, :618                   → 2 处调用 verify_crl（不是 check_revocations）
```

`verify_crl` 已经 fail-closed（`Err(_)` 直接 return），问题集中在 `check_revocations`。

---

## 2. Fix 策略

### 2.1 引入 `CrlVerifyPolicy` 枚举

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlVerifyPolicy {
    /// 任何 CRL 处理失败（解析、签名、过期、链不匹配）都返回错误。
    /// 这是 v0.3.0 之后的默认（RFC 5280 §6.3 严格语义）。
    Strict,
    /// 保留 v0.2.x 的 fail-open 行为：单条 CRL 解析失败 → 跳过；
    /// 仅供 v0.2.x 兼容性迁移使用，新代码不应使用。
    Permissive,
}

impl Default for CrlVerifyPolicy {
    fn default() -> Self { CrlVerifyPolicy::Strict }
}
```

### 2.2 新签名（不破坏旧 API）

```rust
// 旧签名（保留）：默认 STRICT（行为变更，但符合 RFC + 国标）。
pub fn check_revocations(
    chain: &[OwnedCert],
    crls: &[Vec<u8>],
    now: OffsetDateTime,
) -> Result<(), CryptoError> {
    check_revocations_with_policy(chain, crls, now, CrlVerifyPolicy::Strict)
}

// 新签名：调用方显式选择策略。
pub fn check_revocations_with_policy(
    chain: &[OwnedCert],
    crls: &[Vec<u8>],
    now: OffsetDateTime,
    policy: CrlVerifyPolicy,
) -> Result<(), CryptoError> {
    // ... 根据 policy 分支处理
}
```

### 2.3 STRICT vs PERMISSIVE 行为差异

| 错误源 | STRICT | PERMISSIVE（v1 兼容） |
| --- | --- | --- |
| `CrlInfo::from_der` 解析失败 | `Err(CrlVerificationFailed)` | `continue`（跳过该 CRL） |
| `crl.issuer_der()` 失败 | `Err(CrlVerificationFailed)` | `continue` |
| 链中无匹配 CA | `Err(CrlVerificationFailed("no CA in chain matches CRL issuer"))` | `continue` |
| `cert_owned.as_x509()` 解析失败 | `Err(CrlVerificationFailed)` | `continue` |
| CRL 过期（`is_valid` 返回 false） | `Err("CRL has expired or not yet valid")` | 同 STRICT（保留语义） |
| CRL 签名验证失败 | `Err` | 同 STRICT |
| 证书在 CRL 中被撤销 | `Err("certificate serial X has been revoked per CRL")` | 同 STRICT（核心语义） |

### 2.4 调用方迁移

gm-tlcp 3 个调用点保持旧签名 `check_revocations(chain, crls, now)`（走 STRICT 默认）。如果后续需要 PERMISSIVE 兼容（例如对接历史部署），改调 `check_revocations_with_policy(..., CrlVerifyPolicy::Permissive)`。

---

## 3. Tests

### 3.1 单元测试（新增 5+ 个到 `verify.rs` 测试 mod）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `crl_strict_rejects_malformed_crl` | 投入一条畸形 CRL（随机字节），`Strict` 返回 `Err` |
| T2 | `crl_permissive_skips_malformed_crl` | 同 T1，`Permissive` 跳过畸形 CRL 并继续（如果链中无匹配 serial，则整体 `Ok`） |
| T3 | `crl_strict_rejects_no_matching_ca` | CRL issuer 与链中任何 cert 的 subject 都不匹配；`Strict` 报错，`Permissive` 跳过 |
| T4 | `crl_default_is_strict` | `CrlVerifyPolicy::default()` 返回 `Strict` |
| T5 | `crl_revoked_serial_still_rejected_under_both_policies` | 证书确实在合法 CRL 的 revokedCertificates 列表中——两种 policy 都必须 `Err`（核心安全语义） |
| T6 | `crl_empty_input_unchanged` | `crls.is_empty()` → 两种 policy 都 `Ok(());`，行为与 v1 一致 |

### 3.2 回归测试

确保现有 CRL 验证测试不被破坏。所有现有 CRL fixture 都是合法 DER，应当在 `Strict` 下继续 `Ok`。

---

## 4. 验证矩阵（stable 1.88）

```
cargo +1.88 fmt --all -- --check
cargo +1.88 clippy -p gm-crypto --all-targets -- -D warnings
cargo +1.88 test -p gm-crypto --lib
cargo +1.88 build -p gm-tlcp -p gm-tls  # 确认 3 个下游调用点继续编译
```

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 旧 fail-open 部署（如果有）切到 STRICT 后握手失败 | 提供 `Permissive` opt-in + CHANGELOG 标注 v0.3.0 默认变严 |
| 第三方 GM/T 实施产 CRL 与我们解析器不兼容 → 误判畸形 | 升级时仔细阅读 CHANGELOG；部署可临时切 PERMISSIVE |
| gm-tlcp PR 同步修改 | PR-2.1 暂时不动 gm-tlcp 调用点（保留旧签名 → STRICT 默认），gm-tlcp 升级即可 |

---

## 6. Out of Scope（不在本 PR 范围）

- gm-tlcp 三个调用点的策略迁移（保留旧签名即可，等 gm-tlcp 自己升级）
- CRL freshness 之外的 CRL v2 特性（CRL number、delta CRL 等）
- OCSP（P2-8 路线图）
- gm-tls 的 verify_crl 路径（已经是 fail-closed，不需要修改）