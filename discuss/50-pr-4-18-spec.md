# SPEC: PR-4.18 — gm-tls crypto / handshake 错误 typed 化 (PR-4.16 follow-up)

- **目标编号**：PR-4.18（Batch 4 follow-up — gm-tls 工程完善）
- **触发**：[`discuss/49-pr-4-16-spec.md §6`](file:///Users/laozhang/Work/opensource/gm/discuss/49-pr-4-16-spec.md) 明确声明 "PR-4.17：gm-tls 全面 typed error 化（包括 `HandshakeFailed` 内部细分）"
- **范围**：`gm-tls/src/error.rs` 新增 4 个 typed 变体（crypto / parse）+ `record_layer.rs`、`gm.rs`、`handshake.rs`、`kdf.rs`、`session_ticket.rs` 调用点迁移
- **影响面**：纯增量；`#[non_exhaustive]` 保护；`Display` 文案保留

---

## 1. 问题陈述

PR-4.16 解决了**会话票证**相关的 9 个错误路径（`SessionTicketInvalid` / `Expired` / `Replay`）。剩余 36 个 `TlsError::HandshakeFailed(format!(...))` 调用点分布在：

| 文件 | 数量 | 主要类目 |
| --- | ---: | --- |
| `record_layer.rs` | 7 | SM4 key init、GCM enc/dec、KeyUpdate、close_notify |
| `gm.rs` | 15 | handshake message parse、SM2 sign/verify/key、cert chain |
| `handshake.rs` | 8 | Finished、SM2 key 构造、PEM parse |
| `session_ticket.rs` | 5 | ticket encryption、KAT、state serialization |
| `crypto_traits.rs` | 3 | cipher wrapper、SM3 hash |
| `kdf.rs` | 1 | HKDF derive |
| `key_update.rs` | 1 | KeyUpdate |
| `lib.rs` | 2 | config glue |
| **合计** | **42** | — |

后果：
- **错误分类粗糙**：所有 42 个站点都映射到 `ErrorCode::HandshakeFailed`，metrics 告警无法区分"SM2 key parse 失败"和"GCM 加密失败"
- **differentiated metrics lost**："Finished verify 失败"和"Finished parse 失败"是两类完全不同的故障（前者是 signature mismatch，可能是攻击；后者是 wire-format 错误，通常是协议不兼容）
- **callers 无法精确 pattern-match**：`is_transient()` 不能区分哪些是"换个 nonces 重试就好"vs"协议不兼容必须升级"

### 1.1 改进建议依据

PR-4.16 SPEC §6 后续 PR 候选：
> **PR-4.17**：gm-tls 全面 typed error 化（包括 `HandshakeFailed` 内部细分）

PR-4.18 解决 PR-4.16 留下的 42 个剩余站点。

---

## 2. Fix 策略

### 2.1 新增 4 个 typed 变体

按**调用频率 × 故障诊断价值**排序：

```rust
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum TlsError {
    // ... existing (including PR-4.16 SessionTicket variants) ...

    /// PR-4.18: cryptographic primitive failed (SM3 hash,
    /// SM4-GCM encrypt/decrypt, SM2 sign/verify/key-parse,
    /// close_notify). Distinct from `HandshakeFailed` so
    /// metrics can alert on "GM cipher error rate" without
    /// contaminating the count with protocol-level errors.
    /// Inner String keeps the underlying `ring`/`gm-crypto`
    /// error message for log scraping.
    #[error("GM cipher error: {0}")]
    CipherError(String),

    /// PR-4.18: handshake message parse / validate failed
    /// (Finished, Certificate, CertificateVerify, etc.).
    /// Distinguished from `CipherError` because the right
    /// operator response is "check wire-format compat" not
    /// "check crypto provider config".
    #[error("handshake message parse failed: {0}")]
    HandshakeMessageParse(String),

    /// PR-4.18: SM2 key construction / parse / load failed.
    /// Wraps both PEM decode and `Sm2KeyPair::from_private_key`
    /// failures. Distinct from `CipherError` because key
    /// errors are usually config-time (bad PEM) not
    /// runtime (bad wire format).
    #[error("SM2 key error: {0}")]
    Sm2KeyError(String),

    /// PR-4.18: KAT (Known Answer Test) self-test failed.
    /// This is a deployment-health indicator (the
    /// cryptographic library is broken in this binary);
    /// it should never fire in production but if it does
    /// the process should refuse to start (handled by
    /// caller).
    #[error("KAT self-test failed: {0}")]
    KatFailed(String),
}
```

### 2.2 新增 `ErrorCode` 变体

```rust
pub enum ErrorCode {
    // ... existing variants ...
    /// PR-4.18: any cipher primitive failure.
    Cipher,
    /// PR-4.18: handshake message parse / validate.
    HandshakeMessageParse,
    /// PR-4.18: SM2 key handling failure.
    Sm2Key,
    /// PR-4.18: KAT self-test failure.
    Kat,
}
```

### 2.3 迁移矩阵

| 当前 prefix | 替代变体 |
| --- | --- |
| `"SM4 key error: ..."` | `CipherError("SM4 key: ...")` |
| `"GCM encryption failed: ..."` | `CipherError("GCM encrypt: ...")` |
| `"GCM decryption failed: ..."` | `CipherError("GCM decrypt: ...")` |
| `"KeyUpdate encryption failed: ..."` | `CipherError("KeyUpdate encrypt: ...")` |
| `"close_notify encryption failed: ..."` | `CipherError("close_notify encrypt: ...")` |
| `"close_notify decryption failed: ..."` | `CipherError("close_notify decrypt: ...")` |
| `"SM3 hash failed: ..."` | `CipherError("SM3: ...")` |
| `"encrypt error: ..."` / `"decrypt error: ..."` | `CipherError("...")` |
| `"cipher error: ..."` | `CipherError(...)` |
| `"failed to create encryptor: ..."` | `CipherError("encryptor init: ...")` |
| `"Finished parse failed: ..."` | `HandshakeMessageParse("Finished: ...")` |
| `"Server Certificate parse failed: ..."` | `HandshakeMessageParse("Server Certificate: ...")` |
| `"ClientCertificate parse failed: ..."` | `HandshakeMessageParse("ClientCertificate: ...")` |
| `"CertificateVerify parse failed: ..."` | `HandshakeMessageParse("CertificateVerify: ...")` |
| `"Client Finished parse failed: ..."` | `HandshakeMessageParse("Client Finished: ...")` |
| `"CertificateVerify verification error: ..."` | `HandshakeMessageParse("CertificateVerify verify: ...")` |
| `"Finished verification error: ..."` | `HandshakeMessageParse("Finished verify: ...")` |
| `"Finished signing failed: ..."` | `HandshakeMessageParse("Finished sign: ...")` |
| `"CertificateVerify signing failed: ..."` | `HandshakeMessageParse("CertificateVerify sign: ...")` |
| `"SM2 key construction failed: ..."` | `Sm2KeyError("construct: ...")` |
| `"SM2 key parse failed: ..."` | `Sm2KeyError("parse: ...")` |
| `"SM2 signer creation failed: ..."` | `Sm2KeyError("signer: ...")` |
| `"SM2 verifier creation failed: ..."` | `Sm2KeyError("verifier: ...")` |
| `"public key parse failed: ..."` | `Sm2KeyError("public: ...")` |
| `"server key parse failed: ..."` | `Sm2KeyError("server: ...")` |
| `"invalid key PEM UTF-8: ..."` | `Sm2KeyError("PEM UTF-8: ...")` |
| `"KAT self-test failed: ..."` | `KatFailed("...")` |
| 保留在 `HandshakeFailed(String)`：session ticket enc/state、KDF、session state | — |

### 2.4 公共 API 兼容

- `Display` 文案 prefix 完全保留（旧前缀被替换为新变体的 `#[error(...)]` prefix + 保留 payload），log scrapers 通过 `e.to_string().contains("...")` 的仍能匹配
- `code()` 映射新增 4 个变体到 `ErrorCode::{Cipher, HandshakeMessageParse, Sm2Key, Kat}`
- `#[non_exhaustive]` 保证下游 `match` 不会被新变体 break

### 2.5 版本

`gm-tls/Cargo.toml`：**patch bump**（增量；`#[non_exhaustive]` 保护）。

---

## 3. Tests

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr418_cipher_error_maps_to_cipher_code` | 构造 `TlsError::CipherError("GCM encrypt: tag mismatch".into())` → `code() == ErrorCode::Cipher` |
| T2 | `pr418_handshake_message_parse_maps_to_parse_code` | `TlsError::HandshakeMessageParse("Finished: too short".into())` → `code() == ErrorCode::HandshakeMessageParse` |
| T3 | `pr418_sm2_key_error_maps_to_sm2_key_code` | `TlsError::Sm2KeyError("PEM: invalid UTF-8".into())` → `code() == ErrorCode::Sm2Key` |
| T4 | `pr418_kat_failed_maps_to_kat_code` | `TlsError::KatFailed("SM3: ...".into())` → `code() == ErrorCode::Kat` |
| T5 | `pr418_distinct_from_handshake_failed` | 4 个新变体的 `code()` ≠ `ErrorCode::HandshakeFailed` |
| T6 | `pr418_display_preserves_prefix_for_log_scrapers` | 每个新变体的 `Display` 输出保留子串 `"GCM"` / `"Finished"` / `"SM2"` / `"KAT"`，方便 log 检索 |

### 3.1 Tests 谨慎范围

由于 gm-tls 错误流主要发生在握手/加密路径上，**不需要为每个 call site 写一个 unit test**——typed 化是 compile-time 检查，CI 现有的 handshake tests（GmSSL Interop / TLCP Interop / loopback）会覆盖所有 call site 的运行时行为。我们只为新增的 4 个变体写上面 6 个测试。

---

## 4. 验证矩阵

```
cargo +1.88 fmt --all -- --check
cargo +1.88 clippy -p gm-tls --all-targets -- -D warnings
cargo +1.88 test -p gm-tls --all-targets pr418_
cargo +1.88 test -p gm-tls -p gm-tlcp -p gm-ca --all-targets
```

CI 含 GmSSL Interop / TLCP Interop（确认所有 call site 行为不变）。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 42 个 call site 手工替换易出错 | 用 `sed` 批量替换 + 编译检查；保留每个原前缀作为 payload 子串 |
| log scraper 依赖旧前缀做 alert | 4 个新变体的 `#[error(...)]` 文案 prefix 与 `Display` payload 子串双重保留 |
| `code()` 不更新导致 metrics 退化为"unmapped error" | 在 PR-4.18 中同步更新 `code()` + 加测试断言 |
| 下游 crate 通过 `Display` 内容 grep 做路由 | `#[non_exhaustive]` 保护；`Display` 输出完全保留原 payload |
| 过度 typed 导致 enum 爆炸 | 仅新增 4 个变体（覆盖 35/42 个 call site）；剩余 7 个（session ticket enc/state、KDF、session state）保持 `HandshakeFailed(String)`，因为它们没有强 metric / alert 价值 |

---

## 6. Out of Scope

- `gm-tlcp` 的 `TlcpError` 同步 typed 化（gm-tlcp 自有错误类型，独立 PR）
- `TlsError::HandshakeFailed(String)` 完全清零（保留为通用 fallback；7 个 site 留在原处）
- 新增 typed variant for `SequenceOverflow` / `NonceReuse` / `InvalidState`（这些已经是 typed，无需重复）

---

## 7. 后续 PR 候选

- **PR-4.19**：`PostgresKeystore::load_keys()` 改为可选后台 task
- **PR-4.20**：gm-tlcp 错误类型统一
- **PR-4.21**：gm-tls CRL grace period + session cache persistence
