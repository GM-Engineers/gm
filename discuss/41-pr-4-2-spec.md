# SPEC: PR-4.2 — gm-ca configurable mTLS (P1-1)

- **目标编号**：PR-4.2（Batch 4 — gm-ca 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §6 / §7 P1-1`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md)：gm-ca 无法启用 mTLS（硬编码 `require_client_auth(false)`）
- **范围**：`gm-ca/src/main.rs`（启动期 TLS 配置读取）；`gm-ca/tests/`（新增 mTLS 集成测试）；`gm-ca/README.md` 与 `gm-ca/CHANGELOG.md`（文档）
- **影响面**：纯环境变量+启动配置；不破坏现有 API / proto / DB schema；向后兼容（默认 `require_client_auth = false`，保留既有行为）

---

## 1. 问题陈述

[`gm-ca/src/main.rs:200`](file:///Users/laozhang/Work/opensource/gm/gm-ca/src/main.rs#L200)：

```rust
let tls_config = gm_tls::TlsConfig::load(cert_path, key_path, ca_path)?
    .with_alpn(vec!["h2".to_string()])
    .with_require_client_auth(false);  // <-- 硬编码
```

后果：
- CA 签发服务只靠 Bearer Token（`interceptor`）单因子认证。
- CA 场景行业标准是 mTLS（RFC 5280 体系、SPIFFE CA 等均如此）；Bearer token 单因子在弱环境易泄漏。
- 客户端证书链校验（`verify_cert_chain_sm2_chain`）已存在但**永远不被调用**。
- 想要 mTLS 的用户只能 fork `main.rs` 改一行字。

### 1.3 改进建议依据

> §6 / §7 P1-1："新增 `GRPC_TLS_REQUIRE_CLIENT_AUTH` 环境变量，支持 'mTLS + Bearer' 双因子模式；客户端证书链校验复用 `verify_cert_chain_sm2_chain`。"

---

## 2. Fix 策略

### 2.1 新增环境变量

| 名称 | 默认 | 取值 | 说明 |
| --- | --- | --- | --- |
| `GRPC_TLS_REQUIRE_CLIENT_AUTH` | `0`（即 `false`，保持向后兼容） | `1` / `true` / `yes` / `on` 视为 `true`；其他值视为 `false` | 启用 mTLS（双因子：客户端证书 + Bearer Token） |

读取语义：沿用 `Bool::from_env("GRPC_TLS_REQUIRE_CLIENT_AUTH")` 模式，与项目内其它 "0/1" env var 一致。

### 2.2 main.rs 启动路径

```rust
// 新增（line 187 后）：
let require_client_auth = parse_bool_env("GRPC_TLS_REQUIRE_CLIENT_AUTH")?;

match (&grpc_tls_cert, &grpc_tls_key, &grpc_tls_ca) {
    (Some(cert_path), Some(key_path), Some(ca_path)) => {
        // Mode 1: TLS 1.3 + SM
        info!(
            "gRPC TLS 1.3 + SM enabled: cert={}, ca={}, require_client_auth={}",
            cert_path, ca_path, require_client_auth
        );
        let tls_config = gm_tls::TlsConfig::load(cert_path, key_path, ca_path)?
            .with_alpn(vec!["h2".to_string()])
            .with_require_client_auth(require_client_auth);
        ...
    }
    ...
}

/// Parse a bool from an env var with strict semantics: only the
/// literal values "1", "true", "yes", "on" (case-insensitive) are
/// accepted as `true`; everything else (including empty string,
/// unset) is `false`. Centralized to keep the policy auditable.
fn parse_bool_env(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}
```

### 2.3 mTLS 校验复用 `verify_cert_chain_sm2_chain`

`gm_tls::TlsAcceptor::new` 在 `with_require_client_auth(true)` 时已经做了 SM2 客户端证书链校验（参见 `gm-tls/src/server.rs`）。本 PR 不重复实现；只接通开关即可。

### 2.4 版本

`gm-ca/Cargo.toml`：从 0.3.0 → 0.4.0（minor bump；新增 public env-var + 配置选项；公共 API 表面无变化，但 feature 加成属于 minor）。

---

## 3. Tests

### 3.1 新增单元测试（`gm-ca/src/main.rs` 内 `#[cfg(test)] mod`）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr42_parse_bool_env_unset` | env 未设 → `false` |
| T2 | `pr42_parse_bool_env_one` | env = `"1"` → `true` |
| T3 | `pr42_parse_bool_env_true_lowercase` | env = `"true"` → `true` |
| T4 | `pr42_parse_bool_env_yes` | env = `"yes"` → `true` |
| T5 | `pr42_parse_bool_env_on` | env = `"on"` → `true` |
| T6 | `pr42_parse_bool_env_TRUE_uppercase` | env = `"TRUE"` → `true` |
| T7 | `pr42_parse_bool_env_empty_string` | env = `""` → `false` |
| T8 | `pr42_parse_bool_env_garbage` | env = `"garbage"` → `false` |
| T9 | `pr42_parse_bool_env_zero` | env = `"0"` → `false` |

### 3.2 新增集成测试（`gm-ca/tests/mtls_test.rs`）

| # | 名称 | 场景 |
| --- | --- | --- |
| T10 | `pr42_mtls_disabled_by_default` | 不设 `GRPC_TLS_REQUIRE_CLIENT_AUTH`，客户端无证书 → gRPC 调用成功 |
| T11 | `pr42_mtls_enabled_requires_client_cert` | 设 `GRPC_TLS_REQUIRE_CLIENT_AUTH=1`，客户端无证书 → 握手失败 / UNAVAILABLE |
| T12 | `pr42_mtls_enabled_accepts_client_cert` | 设 `GRPC_TLS_REQUIRE_CLIENT_AUTH=1`，客户端带证书 → gRPC 调用成功 |

需要先生成测试用 SM2 证书链（参考 `gm-ca/tests/` 既有 fixture 模式）。

### 3.3 回归测试

所有现有测试必须继续通过：
- `gm-ca/tests/service_tests.rs`（11 个 v3 测试）
- `gm-ca/tests/sign_certificate_v3.rs`（11 个 PR-3.1 测试）

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p gm-ca --all-targets --features tlcp-profiles
cargo +1.88 test -p gm-crypto
cargo +1.88 test -p gm-tlcp --features tlcp-profiles
```

CI 全套含 GmSSL Interop Tests / TLCP Interop。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 现有部署升级后未设置 env 但仍使用 TLS，行为变化 | 默认值 `false`，保留向后兼容 |
| 测试 fixture 无法生成 SM2 客户端证书 | 复用 `gm-ca/examples/` 或 `gm-tls/fuzz/` 已有 PEM 生成逻辑 |
| 与 gm-kms 端 mTLS 不协调（gm-kms 用 `require_client_cert` config 选项） | 二者解耦：gm-kms 配置走 KMS.toml，gm-ca 走 env var；CA 独立部署场景居多 |
| `parse_bool_env` 与 `bool::from_env`（planification）混淆 | PR-4.2 的 helper 是 `parse_bool_env`（与 P1-3 的 `is_allow_insecure` 等不同源文件），无歧义 |

---

## 6. Out of Scope（不在本 PR 范围）

- DB / Redis TLS 默认 VerifyCa（P1-4，已在 PR-4.1 范围之外的 gm-kms 议题；下一 PR-4.3 处理）
- SM9 密钥生成 material 检查（P1-5）
- 客户端证书 CRL 检查（gm-tls 已有 CRL support；gm-ca 复用即可，单独 PR）
- TLS 1.3 之外的 TLCP listener 复用 mTLS（gm-tlcp 路径独立，TLCP 与 TLS 1.3+SM 是不同协议族）
- 现有 main.rs 的 plain-TCP 启动模式（line 236-276）加固（属于 PR-4.1 议题在 gm-ca 端的镜像，本 PR 仅触及 TLS 分支）

---

## 7. 与既有 gm-ca TLS 实现决策的一致性

- gm-tls 的 `TlsConfig::with_require_client_auth(bool)` 已经存在且经过 PR-1.x 测试；本 PR 不重复 gm-tls 内部改动
- gm-ca 的 gRPC Bearer Token 拦截器（`interceptor`）继续工作 — mTLS 启用后变成 "mTLS + Bearer" 双因子而非替换

---

## 8. 后续 PR 候选

- **PR-4.3**：gm-kms P1-4（DB / Redis TLS 默认 VerifyCa；与 gm-ca 解耦）
- **PR-4.4**：gm-ca SPIRE Federation（信任域联邦；gm-ca proto v0.4.0 加 `trust_domain` 字段）
- **PR-4.5**：gm-crypto P1-2（SM2 确定性签名 RFC 6979 适配）