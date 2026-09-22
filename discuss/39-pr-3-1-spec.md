# SPEC: PR-3.1 — gm-ca SignCertificate proto v0.3.0 (P1-8 + P1-9 SPIFFE Workload API 刚需)

- **目标编号**：PR-3.1（Batch 3 — SPIFFE 兼容性联合 PR）
- **触发**：[`gm与gm-kms源码级改进建议.md`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md) §5.4 SPIRE 差距矩阵 + 改进路线图 §6（"P1-8 + P1-9 三项组合，即可支撑 SPIFFE Workload API 生态"）
- **范围**：`gm-ca/proto/ca.proto`（proto v0.3.0 wire-format addition）+ `gm-ca/src/cert_profile.rs`（serde derive）+ `gm-ca/src/cert.rs`（signer 接受 sub-day TTL）+ `gm-ca/src/rsa_signer.rs`（同上）+ `gm-ca/src/service.rs`（gRPC handler 路由新字段）+ `gm-ca/tests/`（端到端 SPIFFE SVID scenario）
- **影响面**：proto 字段向后兼容（旧客户端不设新字段时行为不变）；新增字段不影响旧代码路径；gm-ca 0.2.2 → 0.3.0（minor bump: 新公共 API + 行为扩展）

---

## 1. 问题陈述

### 1.1 P1-8：gm-ca 签发接口不支持 profile/SAN 透传

`gm-ca/proto/ca.proto:13` 的 `SignCertificateRequest` 仅含 `csr_pem` + `validity_days`。gRPC handler 在 [`gm-ca/src/service.rs:99`](file:///Users/laozhang/Work/opensource/gm/gm-ca/src/service.rs#L99) 写死 `&CertProfile::default()` —— 调用方**无法**通过 gRPC 让 gm-ca 签发带特定 SAN 的证书：

```rust
self.signer
    .sign_csr_with_profile(csr_bytes, req.validity_days, &CertProfile::default())
```

后果：
- SPIRE Server 必须签发带 URI SAN 的 SVID（`spiffe://trust.domain/ns/.../sa/...`），但 gm-ca 的 gRPC 接口没有透传 SAN/profile 的字段
- TLCP server-enc cert 需要 KU=`keyEncipherment|keyAgreement|dataEncipherment` 而非默认的 `digitalSignature|keyEncipherment`，目前同样无法通过 gRPC 让 gm-ca 签发
- 当前唯一的 workaround 是绕过 gRPC、直接调用 `CaSigner::sign_csr_with_profile` 的 in-process API（破坏 SPIRE 部署形态）

### 1.2 P1-9：TTL 仅支持整天粒度

[`gm-ca/src/cert.rs:218, 318, 415`](file:///Users/laozhang/Work/opensource/gm/gm-ca/src/cert.rs#L218) 的 `not_after = not_before + 86400 * validity_days` 是整天乘法，无 sub-day 粒度。SPIRE Server 的 SVID rotation 模型**结构性地**要求小时级甚至分钟级 TTL（典型 SVID 寿命 = 1h ~ 24h）；目前 gm-ca 强制 1~3650 天整数粒度 = 任何 SPIRE 集成方案都会卡住。

### 1.3 联合修改理由（依据改进建议）

> §6："SPIFFE 协议族支持：URI SAN 匹配（P0-6）+ gm-ca SAN 透传（P1-8）+ 小时级 TTL（P1-9）三项组合，即可支撑 SPIFFE Workload API 生态。三者缺一不可"

PR-2.3 完成 P0-6；本 PR-3.1 一次合并 P1-8 + P1-9（同时修改 proto + 共享签名路径），拆分会引入两次 proto 修订成本。

---

## 2. Fix 策略

### 2.1 proto v0.3.0（wire-format additive backward compat）

`gm-ca/proto/ca.proto`：在 `SignCertificateRequest` / `RenewCertificateRequest` 上**新增**字段（不删除 / 不重命名旧字段）：

```proto
message SignCertificateRequest {
    string csr_pem = 1;
    int64 validity_days = 2;          // 旧字段保留；deprecated；未来主版本移除
    int64 validity_seconds = 3;       // 新字段；优先级 > validity_days
    string profile_json = 4;          // 新字段；空串 = 走 CertProfile::default() 旧路径
}

message RenewCertificateRequest {
    string serial_number = 1;
    int64 validity_days = 2;          // 旧字段保留；deprecated
    int64 validity_seconds = 3;       // 新字段；优先级 > validity_days
    string profile_json = 4;          // 新字段；renew 时附加到原 profile（按字段覆盖合并）
}
```

旧客户端**不感知**新字段 → 服务端解析时 `validity_seconds = 0` + `profile_json = ""` → 走旧的 `validity_days` + `CertProfile::default()` 路径。新客户端可选择性填新字段；旧服务端（pre-v0.3.0）忽略未知字段，行为不变。

### 2.2 CertProfile serde 派生（JSON 透传）

`gm-ca/src/cert_profile.rs`：

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUsageBits { /* 不变 */ }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendedKeyUsage {
    ServerAuth, ClientAuth, CodeSigning, EmailProtection, TimeStamping, OCSPSigning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum GeneralName {
    DnsName(String),
    IpAddress(IpAddr),
    UniformResourceIdentifier(String),
    Rfc822Name(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertProfile { /* 不变 */ }
```

JSON schema 范例（SPIRE Workload API 发出的 SVID 请求）：

```json
{
  "key_usage": { "digital_signature": true },
  "ext_key_usage": ["server_auth"],
  "is_ca": false,
  "ca_path_len_constraint": null,
  "sans": [
    { "type": "uniform_resource_identifier", "value": "spiffe://prod.example.com/ns/foo/sa/web" }
  ],
  "include_san": true,
  "include_aki": true,
  "include_basic_constraints": true,
  "include_ski": true
}
```

`IpAddr` 用 `serde` 的内置 `ip_addr` 实现（已有，不需要额外 impl）。

### 2.3 signer 扩展（sub-day TTL）

`gm-ca/src/cert.rs`：保留旧 `sign_csr_with_profile(csr, days, profile)` 入参，**新增** `sign_csr_with_profile_and_seconds`：

```rust
pub fn sign_csr_with_profile_and_seconds(
    &self,
    csr_input: &[u8],
    validity_seconds: i64,
    profile: &CertProfile,
) -> Result<(String, String), CaError> {
    // 范围: 1s ~ 31536000s (365d)。注：signer API 上限仍 365d
    // (spire SVID 典型寿命 1h~24h，远低于上限)
    if validity_seconds < 1 || validity_seconds > 31_536_000 {
        return Err(CaError::InvalidArgument(format!(
            "validity_seconds must be 1-31536000 (1s-365d), got {}", validity_seconds
        )));
    }
    // 后续 not_after 计算改为 + validity_seconds
}
```

`gm-ca/src/rsa_signer.rs`：对称添加 `RsaCaSigner::sign_csr_with_profile_and_seconds`。

### 2.4 gRPC handler 路由新字段

`gm-ca/src/service.rs`：

```rust
let profile = if req.profile_json.is_empty() {
    CertProfile::default()
} else {
    serde_json::from_str(&req.profile_json).map_err(|e| {
        Status::invalid_argument(format!("invalid profile_json: {}", e))
    })?
};
let validity_seconds = if req.validity_seconds > 0 {
    req.validity_seconds
} else {
    // backward compat: 旧客户端只用 validity_days
    86400 * req.validity_days
};
let (serial_hex, cert_pem) = self.signer
    .sign_csr_with_profile_and_seconds(csr_bytes, validity_seconds, &profile)
    .map_err(...)?;
```

`renew_certificate` 同理。

### 2.5 gm-ca 版本与发布

`gm-ca/Cargo.toml`：

```toml
version = "0.3.0"  # 新公共 API (sign_csr_with_profile_and_seconds) +
                     # proto 字段新增 + serde 依赖 → minor bump
```

新增 dev-dep: `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`。

---

## 3. Tests

### 3.1 新增单元测试（gm-ca/src/cert_profile.rs）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr31_profile_json_roundtrip_default` | `CertProfile::default()` → JSON → 反序列化 → 结构等价 |
| T2 | `pr31_profile_json_spiffe_svid` | URI SAN `spiffe://...` 走 JSON 序列化往返 |
| T3 | `pr31_profile_json_key_usage_bits_all` | `KeyUsageBits` 全 bit true 时序列化 |

### 3.2 新增集成测试（gm-ca/tests/sign_certificate_v3.rs）

使用 `tonic::transport::Channel` 起一个 in-process CaService 测试端点：

| # | 名称 | 场景 |
| --- | --- | --- |
| T4 | `pr31_v3_backward_compat_only_days` | 仅设 `validity_days` 旧字段 → 走 default profile，TTL = days*86400 s |
| T5 | `pr31_v3_subday_ttl_seconds_only` | 仅设 `validity_seconds = 3600`（1 小时）→ TTL = 1h，DB 中 not_after - not_before = 3600s ±skew |
| T6 | `pr31_v3_profile_json_uri_san` | 设 `profile_json` 含 URI SAN → 签发 cert 的 DER 含 SPIFFE ID SAN；用 gm-crypto 解析确认 |
| T7 | `pr31_v3_invalid_profile_json_rejected` | 设非法 JSON → `Status::invalid_argument`，不签发 |
| T8 | `pr31_v3_seconds_priority_over_days` | 两个字段都设（seconds=3600, days=7） → 走 seconds |
| T9 | `pr31_v3_renew_with_new_profile` | renew 时设新 profile_json → 新 cert 用新 profile |

### 3.3 回归测试

确保现有所有 gm-ca 测试在 v0.3.0 默认下继续通过（旧请求形态走默认路径）。

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p gm-ca --all-targets --features tlcp-profiles
cargo +1.88 test -p gm-crypto --lib
cargo +1.88 test -p gm-tls
cargo +1.88 test -p gm-tlcp --features tlcp-profiles
```

CI 必须全绿（gm-ca 的 CI 步骤是 `cargo test -p gm-ca --all-targets`）。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| proto v0.3.0 新字段导致旧客户端 wire-format 不兼容 | 新字段皆为 proto3 默认值（旧客户端不设）；服务端检测 `profile_json.is_empty() && validity_seconds == 0` 后走旧路径 |
| `serde_json` 反序列化 JSON 解析攻击（DoS） | `serde_json` 默认不递归；最大嵌套由 std 自动限制；JSON 由内部 SPIRE 控制输入，不是公开 API |
| `validity_seconds` 上限 365d 仍过于宽松（spire SVID 通常 1h~24h） | 本 PR 仅解决 P1-9 "sub-day 粒度"；future PR 可加 max_validity_seconds 配置项（per-CA policy） |
| `sign_csr_with_profile_and_seconds` 与旧 `sign_csr_with_profile` 重复维护 | 旧函数保留（向后兼容）；新函数为 thin wrapper + 校验 + 调内部 `sign_csr_with_profile_internal`，DRY |
| SPIRE 调用方未设置 `ext_key_usage` 字段（旧 client） | `profile_json = ""` → fallback default profile，行为不变 |
| cert 长度超 365d 上限 (e.g. ca cert 10y) | CaSigner 的 `self_sign_ca` 仍走 `validity_days`，不需 sub-day；只有 leaf CSR 走 sub-day 路径 |

---

## 6. Out of Scope（不在本 PR 范围）

- proto v0.3.0 的 `GetCertificate` / `GetCrl` 字段新增（不需要：这两个 read-only 不受 P1-8/P1-9 影响）
- 移除旧 `validity_days` 字段（proto3 不允许；留作 deprecated，下个 major 版本移除）
- SPIRE Server Federation 信任域 federation（属于 gm-ca SPIRE 联邦场景；后续 PR-3.2+）
- TLS-level 双向 mTLS 鉴权 SPIRE Agent（属于 gm-tlcp 改进；后续 PR-4.x）