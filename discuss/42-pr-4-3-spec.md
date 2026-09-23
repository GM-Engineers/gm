# SPEC: PR-4.3 — gm-crypto SM2 确定性签名（RFC 6979-style，P1-2）

- **目标编号**：PR-4.3（Batch 4 — gm-crypto 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §6 / §7 P1-2`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md)：SM2 签名缺少确定性签名接口（gm-crypto）★CA/KMS 场景刚需
- **范围**：`gm-crypto/src/sm2.rs`（Sm2Signer API 强化 + 文档）；`gm-crypto/tests/`（新增 KAT 测试）；`gm-crypto/CHANGELOG.md`
- **影响面**：纯公开 API 增量；不破坏任何现有 caller（保留 `sign()` 行为不变）

---

## 1. 问题陈述

[`gm-crypto/src/sm2.rs:269-335`](file:///Users/laozhang/Work/opensource/gm/gm-crypto/src/sm2.rs#L269)：

```rust
/// M-3 Security Note: The sm2 crate's scalar multiplication uses double-and-add
/// algorithm which has timing that varies with the scalar's bit pattern ...
///
/// Mitigation applied: We perform a dummy scalar multiplication before signing.
/// ...
/// This is heuristic but raises the bar for attackers.
pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Generate random blinding scalar and compute r*G for timing noise
    let r = Scalar::random(&mut OsRng);
    let _noise_point = ProjectivePoint::GENERATOR * r;

    // Actual signature using sm2 crate
    let signature: Signature = self.signing_key.sign(data);
    ...
}
```

### 1.1 现状调研关键发现（PR-4.3 核心）

审计 [`sm2-0.13.3/src/dsa/signing.rs:115-147`](file:///Users/laozhang/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sm2-0.13.3/src/dsa/signing.rs#L115)：

```rust
impl PrehashSigner<Signature> for SigningKey {
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature> {
        sign_prehash_rfc6979(&self.secret_scalar, prehash, &[])  // ← 已经是 RFC 6979！
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature> {
        let hash = self.verifying_key.hash_msg(msg);
        self.sign_prehash(&hash)
    }
}
```

**关键事实**：`sm2` 0.13.3 内部已经实现了 RFC 6979-style 确定性 k 派生（`sign_prehash_rfc6979`），并把 `Signer::try_sign` 默认接入这条路径。`self.signing_key.sign(data)` 实际上**已经是确定性的**。

后果：
- `gm-crypto` 的现有 `sign()` 已经满足 P1-2 的核心要求（k 由私钥+消息派生态、可重放、可审计、k 永不重用）。
- 但 API 表面**没有显式的 `deterministic_sign()` 方法**，调用方只能依赖 sm2 crate 的默认行为；未来 sm2 crate 若切换到随机路径（概率极低但理论可能），`gm-crypto` 用户毫无预警。
- 文档（line 269-285）**误导性地声称是随机 k + dummy timing noise**，而实际上 k 是确定性的、dummy noise 是冗余的。

### 1.2 改进建议依据

> §6 / §7 P1-2："提供确定性签名变体（GM/T 0003.2 附录的 SM2 确定性 k 或 RFC 6979 适配，k 由私钥+消息派生态），支持可审计、可重放测试"

PR-4.3 的策略不是新写一个 HMAC-SM3-DRBG（sm2 crate 已经做了），而是：
1. **暴露显式 API**：`deterministic_sign()` 和 `randomized_sign()`
2. **修正误导性文档**：澄清 k 是 RFC 6979 派生态的
3. **锁定测试**：添加 KAT（Known Answer Test）向量，防止未来 sm2 升级意外切换 k 派生路径

---

## 2. Fix 策略

### 2.1 API 强化（公开）

```rust
impl Sm2Signer {
    /// Existing randomized / `sign()` API — KEEP unchanged for
    /// backward compatibility. Internally this delegates to the
    /// sm2 crate's `RandomizedSigner::try_sign_with_rng(OsRng, ...)`
    /// which then re-mixes its random seed into the RFC 6979
    /// HMAC-DRBG derivation. Two signatures of the same data over
    /// different invocations differ in their `s` value (audit
    /// trail stays non-replayable across signing sessions).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> { ... }

    /// NEW (PR-4.3 / P1-2): RFC 6979 deterministic signature.
    ///
    /// The signature k is derived from `(private_key, message)` via
    /// HMAC-SM3 DRBG (RFC 6979 §3.2 adapted for SM3 — see
    /// sm2-0.13.3/src/dsa/signing.rs::sign_prehash_rfc6979). For any
    /// given (key, data) pair the signature is byte-identical across
    /// processes, platforms, and signing sessions. This gives:
    ///
    /// - **Audit trail**: signature output is reproducible; can be
    ///   re-verified offline from key + message + signed bytes.
    /// - **K-reuse impossible**: k depends on the message bytes;
    ///   signing two different messages never produces the same k.
    /// - **KAT testable**: PR-4.3 adds KAT vectors locking this in.
    ///
    /// Use this for CA / KMS / long-term archival signing where
    /// reproducibility matters. The wire format is identical to
    /// `sign()` — the on-the-wire `(r, s)` encoding doesn't change.
    pub fn deterministic_sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Pre-compute e = SM3(Z_A || data) per GM/T 0003.2 §6.1 A1-A2.
        let hash = self.signing_key.verifying_key().hash_msg(data);
        // RFC 6979 derive k from (private_key, e, additional_data=[]).
        // The sm2 crate's PrehashSigner impl does exactly this.
        let signature = self.signing_key.sign_prehash(&hash)?;

        // Sign-then-verify fault protection (matches `sign()`):
        let verifying_key = self.signing_key.verifying_key();
        if verifying_key.verify(data, &signature).is_err() {
            return Err(CryptoError::Sm2Error(
                "Sign-then-verify check failed — possible fault injection".to_string(),
            ));
        }

        Ok(signature.to_bytes().to_vec())
    }

    /// NEW (PR-4.3 / P1-2): randomized signature with explicit RNG.
    ///
    /// Equivalent to `sign()` but lets the caller inject their own
    /// RNG (e.g. an HSM-backed RNG, or a deterministic test RNG).
    /// The sm2 crate mixes the RNG output into the RFC 6979 HMAC-DRBG
    /// seed (`additional_data` parameter), so the result is still
    /// RFC 6979-derived but with caller-controlled additional entropy.
    pub fn randomized_sign(&self, data: &[u8], rng: &mut impl CryptoRngCore)
        -> Result<Vec<u8>, CryptoError>
    { ... }
}
```

### 2.2 文档修正（私有）

- 删除 line 269-285 的"heuristic dummy"叙述（这是过时的设计意图，实际未生效）
- 添加新章节"Deterministic vs Randomized Signing"说明两条路径的差异
- 引用 `sm2::SigningKey::sign_prehash_rfc6979` 作为确定性 k 派生的实现位置

### 2.3 公共 trait 集成（可选）

```rust
impl signature::Signer<Signature> for Sm2Signer { ... }   // 暴露给 generic 生态
```

不在 PR-4.3 范围，避免与其他 crate 签名冲突。

### 2.4 版本

`gm-crypto/Cargo.toml`：从 0.3.6 → 0.3.7（patch bump；新增 public API；公共 API 表面纯增量）。

---

## 3. Tests

### 3.1 KAT（Known Answer Test）向量 — 锁定确定性

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr43_kat_deterministic_sm3_standard_distid` | 标准 distid + smoke 输入，签名字节固定 |
| T2 | `pr43_kat_deterministic_custom_distid` | 自定义 distid + 标准输入，签名字节固定 |
| T3 | `pr43_kat_deterministic_empty_message` | 空消息也能签 |
| T4 | `pr43_kat_deterministic_long_message` | 1 MB 消息，签名仍然确定性 |
| T5 | `pr43_kat_cross_process_invariant` | 同一 (key, msg) 两个独立 Sm2Signer 实例 → 相同签名 |
| T6 | `pr43_kat_different_message_different_signature` | 消息差 1 字节 → 签名完全不同（k 确实派生自消息） |

### 3.2 Side-by-side 一致性

| # | 名称 | 场景 |
| --- | --- | --- |
| T7 | `pr43_sign_and_deterministic_sign_verify` | 两条路径都通过 `Sm2Verifier::verify` |
| T8 | `pr43_randomized_sign_differs_across_calls` | 同一 (key, msg) 多次 randomized_sign → 多个不同签名（验证随机性） |

### 3.3 互操作

| # | 名称 | 场景 |
| --- | --- | --- |
| T9 | `pr43_deterministic_sign_then_verify_round_trip` | 完整签名 + 验证 round trip |

### 3.4 回归测试

所有现有 `gm-crypto` 测试必须继续通过（PR-4.3 不破坏任何既有 API）。

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p gm-crypto
cargo +1.88 test -p gm-ca --all-targets --features tlcp-profiles
cargo +1.88 test -p gm-tlcp --features tlcp-profiles
cargo +1.88 test -p gm-tls
cargo +1.88 test -p gm-http-client
```

CI 全套含 GmSSL Interop / TLCP Interop。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| sm2 0.13.3 升级后切换 k 派生路径 | KAT 锁定 + 文档显式引用 `sign_prehash_rfc6979` |
| 调用方混淆 deterministic vs randomized | 文档清晰命名（`deterministic_sign` vs `randomized_sign`）；现有 `sign()` 默认走 randomized（向后兼容） |
| KAT 向量本身跨平台/跨编译器漂移 | RFC 6979 标准化保证；理论上不可能漂移。T1-T6 是 CAVP-style 锁定测试 |
| 与 sm2 crate 的 bug 传播 | 通过 KAT + integration test 检测；sm2 crate 升级时 CI 必跑 |

---

## 6. Out of Scope（不在本 PR 范围）

- sm2 crate 自身的 RFC 6979 实现升级（如要 SM3 之外的 hash 适配）
- Montgomery ladder 常数时间标量乘（属于恒定时间签名专题，独立 PR；当前依赖 sm2 crate 实现）
- HSM/TPM 集成（gm-kms 已有此路径，gm-crypto 只需通用 API 表面）
- 跨消息批量签名优化（GM/T 0003.2-2012 不规定）

---

## 7. 与 PR-2.x 的衔接

- PR-2.3（gm-crypto P0-6 URI SAN）：同 crate（gm-crypto）；PR-4.3 不触碰
- PR-2.4（gm-crypto builder 模式）：PR-4.3 在同一文件添加方法，不冲突

---

## 8. 后续 PR 候选

- **PR-4.4**：gm-kms P1-4（DB / Redis TLS 默认 VerifyCa）
- **PR-4.5**：gm-kms P1-5（SM9 密钥生成 material 检查）
- **PR-4.6**：gm-crypto 恒定时间标量乘（如果 sm2 crate 不修复，gm-crypto 自封装；CVE-class 议题）
- **PR-4.7**：gm-tls CRL grace period + session cache persistence