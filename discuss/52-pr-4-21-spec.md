# PR-4.21 — gm-tlcp 错误类型统一（typed TlcpError + ErrorCode）

> 状态：草案 / 待实施
> 关联：PR-4.18（gm-tls typed error variants）§7 跟进
> 目标版本：gm-tlcp `0.7.0 → 0.7.1`（patch bump）

## 1. 背景与动机

PR-4.18 在 `gm-tls` 中引入了 4 个 typed error variants
（`CipherError`、`HandshakeMessageParse`、`Sm2KeyError`、`KatFailed`）
及配套 `ErrorCode` 枚举。`gm-tls::error` 与 `gm-tlcp::error` 是两个独立的
错误定义（`gm-tlcp 0.1.0` 起即拆分），PR-4.18 仅迁移了前者。

当前 `gm-tlcp` 中存在 ~30 处 `TlcpError::HandshakeFailed(format!("..."))`
字符串错误。operator / SRE 视角下：
- 监控面板无法区分「SM4 密钥派生失败」（部署侧）vs「GM 密码运算失败」（CPU 侧）
- 健康告警只能用 `handshake_failed_total` 大锅计数
- 排障时只能 grep 日志字串，无法结构化字段过滤

PR-4.21 与 PR-4.18 **同型同款**：把 `gm-tlcp` 的字符串错误按"同型化
模式"拆分到 typed variants，并暴露 `code() -> ErrorCode` 给 metrics
和 metrics labels 使用。

## 2. 范围与非目标 (Scope)

### 范围内

- 在 `gm-tlcp::error` 中新增 4 个 typed variants + 1 个新校验变体
- 新增 `TlcpErrorCode` 枚举 + `TlcpError::code()` 方法
- 重写所有 `HandshakeFailed(format!("..."))` 调用点到 typed variants
- 在 `TlcpConnector` / `TlcpAcceptor` 的关键失败路径上增加 `metrics::counter!`
  接入（如果 metrics 还没接入，则在 PR-4.21 范围内**只做最小接入**：1 个全局
  counter，使用 code 作为 label key）

### 非目标

- **不**改 `TlsError` 别名语义（保留 `pub type TlsError = TlcpError;`）
- **不**改 `From<gm_crypto::CryptoError>` 的现有转换（保留向后兼容）
- **不**触动 `gm-tls` 端的代码（PR-4.18 已经完成）
- **不**改 `metrics` crate 依赖（gm-tlcp 已声明 `metrics = "0.23"`）

## 3. 设计

### 3.1 新增 variants

| 新变体 | 对应 Display | 调用点示例 |
|--------|-------------|-----------|
| `CipherError(String)` | `GM cipher error: {0}` | `SM4 key error`、`GCM encryption/decryption failed`、`HMAC-SM3 compute failed` |
| `HandshakeMessageParse(String)` | `handshake message parse failed: {0}` | `read/write ClientHello/ServerHello/Certificate/CertVerify/Finished/SKE/CHelloDone` |
| `Sm2KeyError(String)` | `SM2/RSA key error: {0}` | `ECDHE keygen`、`SKE sign`、`RSA PKCS#8 PEM parse`、`RSA keygen` |
| `CertificateVerificationFailed(String)` | `certificate verification failed: {0}` | `server hostname check failed`、`server SPIFFE ID check failed` |

**保留 variant**（已存在，无需新增）：
- `SequenceOverflow`、`NonceReuse`、`InvalidHandshakeType`、`InvalidMessage`、`InvalidState`、`ParseError`、`TlsRecordError`、`IoError`、`HandshakeFailed`

### 3.2 ErrorCode 枚举

新增 `pub enum TlcpErrorCode { ... }`，与 `gm-tls::ErrorCode` **形状一致**，
但**不共用**（因为 `gm-tlcp` 零依赖 `gm-tls`）。

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlcpErrorCode {
    HandshakeFailed,
    HandshakeMessageParse,
    Cipher,
    Sm2Key,
    CertificateVerificationFailed,
    SequenceOverflow,
    NonceReuse,
    InvalidHandshakeType,
    InvalidMessage,
    InvalidState,
    ParseError,
    TlsRecordError,
    IoError,
}

impl TlcpError {
    pub fn code(&self) -> TlcpErrorCode {
        match self { ... }
    }
}
```

### 3.3 调用点迁移规则

按字符串前缀 → typed variant 的映射：

| 字符串前缀 | 目标变体 |
|-----------|---------|
| `SM4 key error` | `CipherError` |
| `GCM encryption/decryption failed` | `CipherError` |
| `HMAC-SM3 compute failed` | `CipherError` |
| `read <HandshakeType>` | `HandshakeMessageParse` |
| `write <HandshakeType>` | `HandshakeMessageParse` |
| `Expected <Type>, got <Other>` | `HandshakeMessageParse` |
| `ECDHE keygen` | `Sm2KeyError` |
| `SKE sign` | `Sm2KeyError` |
| `RSA PKCS#8 PEM parse` | `Sm2KeyError` |
| `RSA keygen` | `Sm2KeyError` |
| `server hostname check failed` | `CertificateVerificationFailed` |
| `server SPIFFE ID check failed` | `CertificateVerificationFailed` |
| `unknown cipher suite` | `InvalidMessage` |
| `local/peer ephemeral/point` (PMS) | `Sm2KeyError` |
| 其他（master secret not derived 等） | 保留 `HandshakeFailed` |

## 4. 向后兼容性 (Back-compat)

### 4.1 公共 API

- 新增 `TlcpError::*` variants：下游 `match` 因 `#[non_exhaustive]` 已
  存在 wildcard 分支，不会破坏。
- 新增 `TlcpErrorCode` enum：纯新增。
- 新增 `TlcpError::code()` 方法：纯新增。
- 现有 `From<gm_crypto::CryptoError> for TlcpError` 保持不变。

### 4.2 Display 字符串变化（破坏性 - 微小）

部分变体的 `Display` 输出从 `"handshake failed: SM4 key error: ..."`
变成 `"GM cipher error: SM4 key error: ..."`。**这是破坏性变化**，
但：

1. Display 主要用于 `Result::unwrap()` panic 信息 / `eprintln!("error: {}")`
2. gm-tlcp 0.1.0 起就是 0.x 阶段，SemVer 允许 Display 字符串变化
3. 我们仍然按 patch bump（理由：变体名是新增、不是修改；匹配通过 variant 而非 Display）

**决策**：维持 patch bump（与 PR-4.18 一致）。

## 5. 测试计划

### 5.1 单元测试（`error.rs` 测试模块）

新增 ~10 个单元测试：

- `code_of_handshake_failed` / `code_of_cipher_error` / ...
  （每个 variant 一个测试）
- `code_is_total_function`（穷尽 match 编译期保证）
- `display_strings_are_distinct`（避免两个 variant 显示成相同字符串）
- `from_crypto_error_maps_to_handshake_failed`（保留语义）
- `from_io_error_maps_to_io_error`（保留语义）

### 5.2 调用点迁移验证

- `cargo build` 全 workspace 通过（强保证）
- `cargo test --lib -p gm-tlcp` 全绿
- `cargo +nightly clippy -p gm-tlcp --all-targets -- -D warnings` 全绿

### 5.3 集成测试

不需要新增 interop 测试（行为不变，仅类型细化）。

## 6. 风险评估

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| Display 字符串变化被下游 panic 信息依赖 | 低 | 低 | gm-tlcp 0.x，未承诺 Display 稳定性 |
| 现有日志正则匹配 `handshake failed` | 低 | 低 | 调用方应改用 `code()` 返回的 enum；这是迁移动机 |
| 调用点迁移遗漏某处 | 中 | 低 | `cargo build` 全 workspace 是硬性要求 |
| `ErrorCode` 命名冲突 `gm_tls::ErrorCode` | 无 | - | 命名空间隔离（TlcpErrorCode vs ErrorCode） |

## 7. 实施步骤

1. 在 `gm-tlcp/src/error.rs` 新增 4 个 variants + TlcpErrorCode + code() 方法
2. 用 `grep -rln 'HandshakeFailed(format!' gm-tlcp/src` 列举所有调用点
3. 用 IDE / sed 批量替换（按映射表）
4. `cargo build` 编译验证
5. `cargo test --lib -p gm-tlcp` 全绿
6. `cargo +nightly clippy -p gm-tlcp --all-targets -- -D warnings`
7. 更新 CHANGELOG（Added + Changed 段）
8. `git commit -m "feat(gm-tlcp): typed TlcpError variants + TlcpErrorCode (PR-4.21)"`
9. 推 github → 等 CI 全绿 → 推 gitee + gitcode

## 8. 跟进（不在本 PR 范围内）

- PR-4.22: gm-tls/gm-tlcp shared error trait `GmtlsError` 把两个 crate 的
  error 统一成 trait object，方便应用层 abstract（如果真有必要）。
- PR-4.23: gm-kms 中使用 `code()` 作为 metrics label key（统一观测面）