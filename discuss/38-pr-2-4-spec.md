# SPEC: PR-2.4 — gm-tls / gm-tlcp builder integration (DistidPolicy + expected_uri)

- **目标编号**：PR-2.4（Batch 2 后续 — 路线图 PR-2.4+）
- **触发**：[`/Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md) P0-7 + P0-6 的 builder 落地（PR-2.2 SPEC §6 + PR-2.3 SPEC §2.5 均列为本 PR 范围）
- **范围**：`gm-tls/src/lib.rs` + `gm-tls/src/gm.rs` + `gm-tlcp/src/tlcp/mod.rs` 的 builder 集成；恢复 `gm-tls/tests/gmssl_interop_tests.rs` 中 3 个 `#[ignore]` loopback 测试
- **影响面**：纯新增 builder 方法 + 内部调用路径切换到 PR-2.2/2.3 的 policy-aware 入口；不破坏现有公共 API

---

## 1. 问题陈述

### 1.1 现状

PR-2.2（gm-crypto 0.3.5）把 `verify_against_anchors` 的 SM2 distid 默认值从 permisssive 收紧为 STRICT，PR-2.3（gm-crypto 0.3.6）新增了 `validate_uri_only` 用于 SPIFFE 验证。但两者的 policy knob **只到 gm-crypto crate 边界为止** —— gm-tls 和 gm-tlcp 还没暴露给上层用户：

- **gm-tls**：`TlsConfig::with_distid_policy(...)` / `with_expected_uri(...)` 尚未实现，调用方拿到 PR-2.2 的 STRICT 行为后没有任何 opt-in 通道
- **gm-tlcp**：`TlcpConnector::with_distid_policy(...)` / `TlcpAcceptor::with_distid_policy(...)` / `*::with_expected_uri(...)` 同上

### 1.2 副作用（被 PR-2.2 推迟的债务）

PR-2.2 的提交（`5f11225`）将 `gm-tls/tests/gmssl_interop_tests.rs` 的 3 个 loopback 测试标记为 `#[ignore]`：

- `test_loopback_handshake`
- `test_loopback_mutual_auth`
- `test_loopback_echo_large_data`

这些测试用 `openssl req` 生成 self-signed 证书（默认空 distid），在 PR-2.2 的 STRICT 默认下被正确拒绝。本 PR 通过新增 `with_distid_policy(DistidPolicy::Permissive { fallback_distids: vec!["".to_string()], .. })` 让 loopback 测试能够显式 opt-in permissive 而继续运行，移除 `#[ignore]`。

### 1.3 调用方盘点

- `gm-tls::TlsConfig` (`gm-tls/src/lib.rs:170`) — 新增 `expected_uri: Option<String>` + 内部存储 `distid_policy: Option<DistidPolicy>`
- `gm-tls::TlsConnector` / `TlsAcceptor` (`gm-tls/src/lib.rs:335, 410`) — 直接持有 `TlsConfig`，无需新字段
- `gm-tls/src/gm.rs:355, 606`（2 处 `verify_cert_chain_sm2_chain` 调用）— 切到 `_with_distid_policy` 入口
- `gm-tlcp::TlcpConnector` (`gm-tlcp/src/tlcp/mod.rs:1415`) — 新增 `expected_uri` + `distid_policy` 字段
- `gm-tlcp::TlcpAcceptor` (`gm-tlcp/src/tlcp/mod.rs:3222`) — 新增 `distid_policy` 字段（acceptor 不需要 expected_uri，因为 URI 校验是 client-side 概念）
- `gm-tlcp/src/tlcp/mod.rs:2053, 2106, 4082`（3 处 `verify_against_anchors` 调用）— 切到 `_with_distid_policy` 入口

---

## 2. Fix 策略

### 2.1 `TlsConfig` 通过 `HandshakeOptions` 间接持有新字段

为遵循仓库中既有 `with_session_ticket` / `with_crl_info` / `with_session_ticket_key` 等 builder 的“委托进 `HandshakeOptions`”模式（参见 `gm-tls/src/lib.rs` `TlsConfig::with_crl_info`），`TlsConfig` **不**新增字段；新字段落在 [`HandshakeOptions`](file:///Users/laozhang/Work/opensource/gm/gm-tls/src/handshake.rs) 上，由 builder 链式调用 `get_or_insert_with(HandshakeOptions::default)` 透传：

```rust
pub struct HandshakeOptions {
    // ... 现有字段 ...
    pub crl_info: Option<CrlInfo>,
    /// PR-2.2 (gm-crypto 0.3.5+): SM2 签名 distid 策略。
    /// `None` 默认 = `DistidPolicy::Strict`。
    pub distid_policy: Option<DistidPolicy>,
    /// PR-2.3 (gm-crypto 0.3.6+): peer 证书 URI SAN（SPIFFE ID）。
    /// `Some(uri)` 时验证器在 chain verify 之后追加 `validate_uri_only`。
    pub expected_uri: Option<String>,
}
```

### 2.2 新增 builder 方法

```rust
impl TlsConfig {
    /// Set expected URI SAN (SPIFFE ID) for the peer cert.
    ///
    /// When `Some(uri)`, the verifier additionally requires a
    /// matching `uniformResourceIdentifier` SAN in the leaf cert
    /// per `x509::verify::validate_uri_only` (gm-crypto 0.3.6+).
    pub fn with_expected_uri(mut self, uri: impl Into<String>) -> Self {
        self.expected_uri = Some(uri.into());
        self
    }

    /// Override the SM2 distid policy (default: `Strict`).
    ///
    /// Pass `DistidPolicy::Permissive { fallback_distids: vec![""] }`
    /// for OpenSSL 3.x interop (which defaults to the empty distid).
    pub fn with_distid_policy(mut self, policy: DistidPolicy) -> Self {
        self.distid_policy = Some(policy);
        self
    }
}
```

### 2.3 `gm-tls/src/gm.rs` 内部调用更新

```rust
// 替换：
verify_cert_chain_sm2_chain(leaf_chain, trust, now, domain, Some(CertRole::TlsServer))?
// 改为：
verify_cert_chain_sm2_chain_with_distid_policy(
    leaf_chain, trust, now, domain,
    Some(CertRole::TlsServer),
    cfg.distid_policy.unwrap_or(DistidPolicy::Strict),
)?
// 然后：
if let Some(ref uri) = cfg.expected_uri {
    validate_uri_only(&leaf_der, uri, now, UriMatchPolicy::default())?;
}
```

### 2.4 `TlcpConnector` / `TlcpAcceptor` 新增字段

```rust
pub struct TlcpConnector {
    // ... 现有字段 ...
    server_name: Option<String>,
    /// Expected URI SAN for the server's sign cert (SPIFFE ID).
    /// Set via `TlcpConnector::with_expected_uri(String)`.
    expected_uri: Option<String>,
    /// SM2 distid policy override.
    distid_policy: Option<DistidPolicy>,
}

pub struct TlcpAcceptor {
    // ... 现有字段 ...
    client_ca_anchors: Option<Vec<Vec<u8>>>,
    /// SM2 distid policy override for client-cert verification.
    distid_policy: Option<DistidPolicy>,
}
```

### 2.5 新增 builder 方法（gm-tlcp）

```rust
impl TlcpConnector {
    pub fn with_expected_uri(mut self, uri: impl Into<String>) -> Self { ... }
    pub fn with_distid_policy(mut self, policy: DistidPolicy) -> Self { ... }
}

impl TlcpAcceptor {
    pub fn with_distid_policy(mut self, policy: DistidPolicy) -> Self { ... }
    // (no expected_uri; URI matching is client-side)
}
```

### 2.6 `gm-tlcp/src/tlcp/mod.rs` 内部调用更新

3 处 `verify_against_anchors` 全部切到 `verify_against_anchors_with_distid_policy`，传入 `self.distid_policy.unwrap_or(DistidPolicy::Strict)`。sign leaf 验证后若 `expected_uri.is_some()`，调用 `validate_uri_only`。

### 2.7 Loopback 测试恢复

`gm-tls/tests/gmssl_interop_tests.rs`：

- 移除 3 个测试上的 `#[ignore = "..."]` 属性
- 在 `ensure_test_certs()` 后、`TlsConfig::from_bytes` 前增加 `with_distid_policy(DistidPolicy::Permissive { fallback_distids: vec!["".to_string()], audit_on_fallback: None })`
- 删除文件头部的 `PR-2.2: ...` 长注释（不再适用）

---

## 3. Tests

### 3.1 新增集成测试（gm-tls）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr24_with_expected_uri_accepts_matching_spiffe` | 用 gm-ca 签发带 URI SAN 的 server cert；client 配 `with_expected_uri("spiffe://...")` → 握手成功 |
| T2 | `pr24_with_expected_uri_accepts_prefix_path` | SPIFFE Federation §4.1 prefix 路径匹配；期望 URI = cert URI 前缀 → 通过 |
| T3 | `pr24_with_expected_uri_rejects_mismatch` | URI 信任域不匹配 → 拒绝并断言为 `TlsError::CertificateVerificationFailed` 变体 |
| T4 | `pr24_with_distid_policy_permissive_accepts_openssl_empty_distid` | 编译期断言 `DistidPolicy::{Strict, Permissive}` 可在 gm-tls 公共 API 表面访问；端到端行为由 `gmssl_interop_tests.rs::test_loopback_*` 覆盖 |

### 3.2 Loopback 测试恢复

直接复用 PR-2.2 留下的 fixture；在测试 setup 链上挂 `with_distid_policy` 即可。不需要新建 fixture。

### 3.3 回归测试

确保现有所有 gm-tls / gm-tlcp 测试在 STRICT 默认下继续通过（PR-2.2 路径不变）。

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p gm-crypto --lib
cargo +1.88 test -p gm-tls               # 含 3 个 loopback 测试（恢复）+ 3 个新增
cargo +1.88 test -p gm-tlcp --features tlcp-profiles
cargo +1.88 build -p gm-ca
```

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 旧调用方在 `TlsConfig` 新字段上是 missing | 用 `Option<T>` 默认 `None`，语义与 0.3.6 一致 |
| 3 个 loopback 测试在 PR-2.2 之后没有 PERMISSIVE 通道 | 本 PR 提供 `with_distid_policy` 后才能 un-`#[ignore`]` |
| gm-tlcp 的 `TlcpAcceptor` 新增 `distid_policy` 字段会破坏 clone 语义 | 字段是 `Option<DistidPolicy>`，derive(Clone) 自动覆盖 |
| `validate_uri_only` 与现有 hostname 检查路径不冲突 | hostname 已 run 在 `validate_hostname_only`，URI check 是 orthogonal layer，两条独立分支 |

---

## 6. Out of Scope（不在本 PR 范围）

- gm-ca 的 server 端 `with_expected_uri` builder（gm-ca 是服务端，目前没有 client cert 校验路径，不需要 URI 校验）
- SPIRE Federation 信任域交叉签发（属于 gm-ca SPIRE 联邦场景）
- 运行时切换 distid policy（当前仅 builder 时设置，不可热更新）