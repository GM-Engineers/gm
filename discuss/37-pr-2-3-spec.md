# SPEC: PR-2.3 — URI SAN matching (SPIFFE trust-domain + path policy)

- **目标编号**：PR-2.3（Batch 2 / P0-6）
- **触发**：[`/Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md) P0-6
- **范围**：`gm/gm-crypto/src/x509/verify.rs` 新增 `validate_uri_only` + `SpiffeId` 解析 + 信任域精确 / 路径前缀/全等匹配策略；不修改 `verify_against_anchors` / `verify_cert_chain_sm2_chain` 现有签名
- **影响面**：新增公共 API；现有调用方无需改动（gm-tls builder 集成由 PR-2.4+ 路线图处理）

---

## 1. 问题陈述

### 1.1 现状

`gm-crypto/src/x509/verify.rs` 的 SAN 匹配循环（行 440-447）只识别 `GeneralName::DNSName`，对 `GeneralName::URI(&str)`（RFC 5280 §4.2.1.6 定义的 uniformResourceIdentifier SAN 类型，SPIFFE SVID 的载体）**能解析但直接忽略**：

```rust
for name in san.value.general_names.iter() {
    if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
        if hostname_matches(dns, &domain) { matched = true; break; }
    }
    // ← URI / IPAddress / RFC822Name 等其他类型被静默丢弃
}
```

### 1.2 风险

- **SPIFFE / SPIRE 生态无法落地**：SPIRE 颁发的 SVID 全部使用 URI SAN（`spiffe://trust-domain/workload-id`），gm-ca 已经能签发（`gm-ca/src/cert_profile.rs:256` 的 `UniformResourceIdentifier` SAN 类型），但 gm-crypto 验证路径不识别 → 本项目平替 SPIRE Server 的核心场景无法跑通
- **不对称性**：签发侧支持，验证侧忽略 — 与 P0-7 的 distid 不对称同源
- **探测侧信道**：客户端库要么直接报错（"no matching hostname"），要么接受所有 URI（取决于 fallback 行为），无统一 RFC 5280 / SPIFFE 规范

### 1.3 调用方盘点（核实结论）

- `gm-crypto::x509::verify::validate_cert_parsed`（行 386）— 现有 SAN 匹配逻辑
- `gm-crypto::x509::verify::validate_hostname_only`（行 219）— 叶子证书 hostname 校验，间接使用 validate_cert_parsed
- `gm-tls::TlsConfig::with_domain`（`gm-tls/src/lib.rs:276`）— 调用 validate_cert_parsed 的 expected_domain 入口
- `gm-tlcp::with_server_name`（3 处）— 同上
- `gm-ca::cert::CertProfile`（`gm-ca/src/cert_profile.rs:256`）— **已经支持签发 URI SAN**，仅验证侧缺

新增 API 不修改以上现有调用点；gm-tls / gm-tlcp 的 `with_expected_uri` builder 由 PR-2.4+ 处理（与 PR-2.2 的 `with_distid_policy` 同批路线图）。

---

## 2. Fix 策略

### 2.1 新增 `SpiffeId` 类型 + 解析

```rust
/// SPIFFE ID Verifiable Identity Document per
/// [SPIFFE Workload Identity §2.1](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md).
///
/// Format: `spiffe://<trust-domain>/<workload-path>`
///
/// - `<trust-domain>` is a DNS subdomain (RFC 1035), case-sensitive
///   exact match per SPIFFE §2.1.2.
/// - `<workload-path>` is `/`-prefixed (no leading `/` is invalid).
/// - Total length must be ≤ 2048 bytes per SPIFFE §2.1.
pub struct SpiffeId<'a> {
    pub trust_domain: &'a str,
    pub path: &'a str,
}

impl<'a> SpiffeId<'a> {
    /// Parse a SPIFFE ID. Returns Err on:
    /// - missing `spiffe://` scheme
    /// - empty trust domain
    /// - non-DNS characters in trust domain
    /// - path not starting with `/`
    /// - total length > 2048
    pub fn parse(uri: &'a str) -> Result<Self, CryptoError>;

    pub fn trust_domain(&self) -> &str { self.trust_domain }
    pub fn path(&self) -> &str { self.path }
}
```

### 2.2 新增 `UriMatchPolicy`

```rust
/// URI SAN matching policy.
///
/// `Spiffe` is the secure default: trust-domain exact match +
/// path policy (Prefix or Exact, default Prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UriMatchPolicy {
    /// SPIFFE-aware matching: parse both sides as SPIFFE IDs,
    /// require exact trust-domain match, then apply the
    /// configured path policy. Default since gm-crypto 0.3.6.
    #[default]
    Spiffe {
        path: SpiffePathPolicy,
    },
    /// Raw string equality (case-sensitive). Provided for
    /// non-SPIFFE deployments; new code should prefer
    /// `Spiffe`.
    Literal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiffePathPolicy {
    /// Path prefix match: cert SPIFFE path must START WITH
    /// expected path (the workload hierarchy under a service
    /// account can share the prefix). Default in SPIFFE §4.1.
    Prefix,
    /// Path exact match: cert SPIFFE path must equal expected
    /// path exactly. Use for high-assurance deployments.
    Exact,
}
```

### 2.3 新增公共入口

```rust
/// Validate the leaf certificate's URI SAN against an expected URI.
///
/// `expected_uri` MUST be a SPIFFE ID of the form
/// `spiffe://<trust-domain>/<path>` (RFC SPIFFE-ID §2.1). Use
/// [`UriMatchPolicy`] to choose between SPIFFE-aware matching
/// (default) and raw literal equality.
///
/// # Errors
///
/// - The DER is not parseable as X.509
/// - `notBefore > now` or `notAfter < now`
/// - `expected_uri` is not a valid SPIFFE ID
/// - No `URI` SAN entry matches `expected_uri` per the chosen
///   policy
/// - The cert's `URI` SAN has multiple entries and none match
///   (we accept ANY-match, not first-match)
///
/// # Security
///
/// Per RFC 5280 §4.2.1.6, the URI SAN is IA5String (ASCII-only).
/// The matching is case-sensitive (SPIFFE §2.1.2 requires
/// case-sensitive trust-domain matching).
pub fn validate_uri_only(
    leaf_der: &[u8],
    expected_uri: &str,
    now: OffsetDateTime,
    policy: UriMatchPolicy,
) -> Result<(), CryptoError>;
```

### 2.4 STRICT vs PERMISSIVE 行为差异

| 场景 | `Spiffe::Prefix` | `Spiffe::Exact` | `Literal` |
| --- | --- | --- | --- |
| 信任域大小写不同 | `Err` | `Err` | `Err` |
| 信任域不同 | `Err` | `Err` | `Err` |
| 路径完全相等 | `Ok` | `Ok` | `Ok` |
| 路径为预期的前缀（更长） | `Ok` | `Err` | `Err` |
| 字符串完全相等但不是 SPIFFE 格式 | `Err`（parse 失败） | `Err` | `Ok` |

### 2.5 调用方迁移

**gm-tls / gm-tlcp 调用点**（PR-2.4+ 路线图）：
- `TlsConfig::with_expected_uri(String)` builder
- `TlcpConnector::with_expected_uri(String)` + `TlcpAcceptor::with_expected_uri(String)` builders

本 PR 不修改 gm-tls / gm-tlcp（保持向后兼容 + 原子 PR 范围）。

---

## 3. Tests

### 3.1 单元测试（新增 10+ 个到 `verify.rs` 测试 mod）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `spiffe_id_parse_accepts_well_formed` | `spiffe://example.org/ns/foo/sa/bar` → 解析成功 |
| T2 | `spiffe_id_parse_rejects_bad_scheme` | `https://example.org/...` → Err |
| T3 | `spiffe_id_parse_rejects_empty_trust_domain` | `spiffe:///path` → Err |
| T4 | `spiffe_id_parse_rejects_empty_path` | `spiffe://example.org` → Err |
| T5 | `spiffe_id_parse_rejects_path_without_slash` | `spiffe://example.org foo` → Err |
| T6 | `spiffe_id_parse_rejects_overlong` | > 2048 字节 → Err |
| T7 | `validate_uri_only_accepts_matching_spiffe` | cert URI SAN = expected → Ok |
| T8 | `validate_uri_only_accepts_prefix_path` | cert URI SAN 比 expected 长（prefix 匹配）→ Ok |
| T9 | `validate_uri_only_rejects_non_prefix_under_exact` | Exact policy 下路径是 expected 的前缀 → Err |
| T10 | `validate_uri_only_rejects_trust_domain_mismatch` | 信任域不同 → Err |
| T11 | `validate_uri_only_rejects_no_uri_san` | cert 只有 DNS SAN，没有 URI SAN → Err |
| T12 | `validate_uri_only_rejects_expired` | now > notAfter → Err |
| T13 | `literal_policy_accepts_exact_string` | Literal policy 下字符串完全相等 → Ok |

### 3.2 回归测试

确保现有 `validate_hostname_only` / `validate_cert_parsed` 的 hostname 匹配测试不被破坏。本 PR 不修改这两条路径，仅新增 `validate_uri_only`。

### 3.3 集成测试

- 无（gm-ca 集成测试在 gm-ca crate 中已覆盖 URI SAN 签发）
- gm-tls / gm-tlcp 的 `with_expected_uri` 集成由 PR-2.4+ 处理

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +1.88 test -p gm-crypto --lib
cargo +1.88 test -p gm-tls              # 0 regressions (本 PR 不改 gm-tls)
cargo +1.88 test -p gm-tlcp --features tlcp-profiles  # 0 regressions
cargo +1.88 build -p gm-ca
```

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| SPIFFE 信任域包含大写字母的兼容性 — SPIRE 强制 lowercase | 解析时如果 trust domain 含大写字母，给出明确错误（信任域必须 lowercase per SPIFFE §2.1.2） |
| 路径分隔符 `/` 转义问题 | 解析时强制 path 必须以 `/` 开头；任何 `//` 视为单个 `/`（per SPIFFE §2.1.3 路径归一化） |
| 路径含特殊字符（`?`、`#`） | SPIFFE §2.1.3 明确禁止 path 含 `?` / `#` / `%xx-encoded`；解析时拒绝 |
| gm-tlcp 当前不传 expected_uri → 行为兼容 | 本 PR 不改 gm-tlcp 调用点；现有 hostname 路径继续生效 |
| URI SAN 多条目时的选择策略 | SPIFFE SVID 通常只有一条 URI SAN；如多条，ANY-match 通过（SPIFFE §4.1 的语义） |

---

## 6. Out of Scope（不在本 PR 范围）

- gm-tls / gm-tlcp 的 `with_expected_uri` builder（PR-2.4+）
- SPIFFE Federation 信任域交叉签发（属于 gm-ca SPIRE 联邦场景，P2 路线图）
- 其他 GeneralName 变体的支持（IPAddress / RFC822Name / DirectoryName 等）—— P0-6 仅要求 URI SAN
- 路径归一化的完整 RFC 3986 实现（SPIFFE §2.1.3 的最小子集已覆盖）