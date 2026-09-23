# SPEC: PR-4.8 — gm-crypto X.509 unknown critical extension rejection (P2-1)

- **目标编号**：PR-4.8（Batch 4 — gm-crypto 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §四 P2-1`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md#L145)：补 RFC 5280 §4.2 的 unknown critical extension 拒绝检查
- **范围**：`gm-crypto/src/x509/verify.rs` 新增 `KNOWN_X509_EXTENSIONS` 集合 + `check_unknown_critical_extensions` helper + 在所有 verify entry point 调用
- **影响面**：纯公开 API 增量；现有 well-formed 证书（标准 KU/EKU/BC/SAN/AKI/SKI/CRLDP/CRL Number）继续通过验证

---

## 1. 问题陈述

`gm-crypto/src/x509/verify.rs` 当前**未**执行 RFC 5280 §4.2 的关键检查：

> "Certificate-using applications processing certificates that contain extensions that they do not recognize SHOULD reject the certificate if the extension is critical."

证据：`grep -c critical gm-crypto/src/x509/verify.rs` = 0（除文档外没有任何 critical 检查）。

后果：
- 攻击者可构造带 critical-extension 的恶意证书（如 custom OID `1.2.3.4` with critical=true），gm-crypto 会接受它
- 与 RFC 5280 §4.2 规范**结构性不符**
- gm-tls / gm-tlcp / gm-ca / gm-http-client 等上层组件都依赖这个 verifier，构成信任链底层的脆弱点

### 1.1 改进建议依据（master plan §四 P2-1）

> P2-1 | `gm-crypto/src/x509/verify.rs` | 补 RFC 5280 §4.2 的 unknown critical extension 拒绝检查；nameConstraints/policyConstraints 列入路线图

本 PR 解决 **核心**部分（unknown critical rejection）；nameConstraints / policyConstraints 显式解析留作后续 PR（P2-1 路线图项）。

---

## 2. Fix 策略

### 2.1 `KNOWN_X509_EXTENSIONS` 集合

```rust
/// RFC 5280 §4.2 + GM/T 0018-2012 认可的扩展 OID 集合。
///
/// gm-crypto 当前**识别并处理**以下扩展（verifier 会读它们的语义值，
/// 用于 KU/EKU/BC/SAN/CRL/CRL Number 等检查）。任何**不在此集合**中且
/// `critical = TRUE` 的扩展都会被 [`check_unknown_critical_extensions`]
/// 拒绝，符合 RFC 5280 §4.2 "SHOULD reject" 规则。
pub const KNOWN_X509_EXTENSIONS: &[&Oid] = &[
    &OID_X509_EXT_BASIC_CONSTRAINTS,                // 2.5.29.19
    &OID_X509_EXT_KEY_USAGE,                        // 2.5.29.15
    &OID_X509_EXT_EXTENDED_KEY_USAGE,               // 2.5.29.37
    &OID_X509_EXT_SUBJECT_ALTERNATIVE_NAME,         // 2.5.29.17
    &OID_X509_EXT_ISSUER_ALTERNATIVE_NAME,          // 2.5.29.18
    &OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,           // 2.5.29.14
    &OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER,         // 2.5.29.35 (usually non-critical)
    &OID_X509_EXT_CRL_DISTRIBUTION_POINTS,          // 2.5.29.31
    &OID_X509_EXT_CRL_NUMBER,                       // 2.5.29.20
    &OID_X509_EXT_DELTA_CRL_INDICATOR,              // 2.5.29.27
    &OID_X509_EXT_ISSUING_DISTRIBUTION_POINT,       // 2.5.29.28
    &OID_X509_EXT_FRESHEST_CRL,                     // 2.5.29.46 (usually non-critical)
    &OID_X509_EXT_INHIBIT_ANY_POLICY,               // 2.5.29.54
    &OID_X509_EXT_NAME_CONSTRAINTS,                 // 2.5.29.30 — gm-crypto 不解析但接受
    &OID_X509_EXT_CERTIFICATE_POLICIES,             // 2.5.29.32 (usually non-critical)
    &OID_X509_EXT_POLICY_CONSTRAINTS,               // 2.5.29.36
    &OID_X509_EXT_POLICY_MAPPINGS,                  // 2.5.29.33
    &OID_X509_EXT_AUTHORITY_INFO_ACCESS,            // 1.3.6.1.5.5.7.1.1 (usually non-critical)
    &OID_X509_EXT_SUBJECT_INFO_ACCESS,              // 1.3.6.1.5.5.7.1.11 (always non-critical)
];
```

### 2.2 检查函数

```rust
/// RFC 5280 §4.2: reject certificates that carry critical extensions
/// the verifier does not recognize.
///
/// Returns `Ok(())` when every critical extension on `cert` is in
/// [`KNOWN_X509_EXTENSIONS`] (or the cert has no critical extensions).
/// Returns `Err(CertificateVerificationFailed)` with a clear diagnostic
/// listing the offending OID otherwise.
///
/// NOTE on out-of-scope extensions: `nameConstraints` (2.5.29.30) and
/// `policyConstraints` (2.5.29.36) are listed in [`KNOWN_X509_EXTENSIONS`]
/// but gm-crypto does NOT yet enforce their semantics (i.e. name
/// subtree filtering or require-explicit-policy). They pass the
/// "is recognized" gate; full enforcement is a follow-up PR (see
/// master plan P2-1 路线图项).
pub fn check_unknown_critical_extensions(
    cert: &X509Certificate<'_>,
) -> Result<(), CryptoError> {
    for ext in cert.extensions() {
        if !ext.critical {
            continue;
        }
        if !KNOWN_X509_EXTENSIONS.iter().any(|known| ext.oid == **known) {
            return Err(CryptoError::CertificateVerificationFailed(format!(
                "certificate carries unrecognized critical extension OID {} \
                 (RFC 5280 §4.2: applications MUST reject)",
                ext.oid
            )));
        }
    }
    Ok(())
}
```

### 2.3 接入点

`check_unknown_critical_extensions` 在以下**所有** verify entry point 调用（chain 和 leaf 都要检）：

| 函数 | 行号（当前） | 调用位置 |
| --- | --- | --- |
| `validate_cert_pem` | 195 | leaf + chain |
| `validate_hostname_only` | 228 | leaf only |
| `validate_uri_only` | 450 | leaf only |
| `verify_cert_chain_sm2_chain_with_distid_policy` | 891 | 每个 cert（leaf + intermediates + root）|
| `verify_against_anchors` | 1107 | leaf + root |
| `verify_crl` | 1310 | CRL 自身 |
| `verify_cert_crl` | 1359 | leaf（确认未吊销时）|

### 2.4 既有 cert 生成路径的兼容性

gm-ca 生成的证书只携带 OID 在 `KNOWN_X509_EXTENSIONS` 集合内的扩展：
- BasicConstraints, KeyUsage, ExtendedKeyUsage, SAN, AuthorityKeyIdentifier, SubjectKeyIdentifier, CRL Distribution Points, CRL Number（CRL 时）

→ **零回归风险**。

### 2.5 版本

`gm-crypto/Cargo.toml`：patch bump（新增 pub API 增量；现有证书继续通过）。

---

## 3. Tests（`gm-crypto/tests/x509_unknown_critical_ext.rs` 新文件）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr48_rejects_cert_with_unknown_critical_extension` | openssl 生成带未知 critical extension 的证书 → verifier Err |
| T2 | `pr48_accepts_cert_with_unknown_non_critical_extension` | 同一扩展但 critical=false → Ok（RFC 5280 §4.2 只针对 critical）|
| T3 | `pr48_accepts_cert_with_all_rfc5280_critical_extensions` | KU/BC/SAN/CRLDP critical → Ok |
| T4 | `pr48_known_extension_set_includes_rfc5280_listed` | 静态断言：RFC 5280 §4.2 列举的 critical extension OIDs 全部在 `KNOWN_X509_EXTENSIONS` 中 |
| T5 | `pr48_unknown_critical_extension_message_mentions_oid` | 错误消息包含 OID |
| T6 | `pr48_unknown_critical_extension_blocks_chain` | chain 任何一环（含 root/intermediate/leaf）有 unknown critical → 整链拒 |
| T7 | `pr48_chain_with_known_extension_passes` | 全部用 gm-ca 默认 profile → Ok（回归保护）|

注：T1/T2/T3 用 `openssl req -x509 -extfile` 现场生成带特定 critical extension 的 SM2 证书。Cert chain tests T6/T7 复用 `issue_uri_san_cert` pattern。

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy -p gm-crypto --all-targets -- -D warnings
cargo +1.88 test -p gm-crypto --all-targets pr48_
cargo +1.88 test -p gm-crypto --all-targets    # 全量回归
cargo +1.88 test -p gm-tls --all-targets        # 上层集成回归
cargo +1.88 test -p gm-tlcp --all-targets       # 上层集成回归
```

CI 含 GmSSL Interop / TLCP Interop。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 现有 cert 携带 unknown critical extension（罕见） | 已知 OID 集合覆盖 RFC 5280 §4.2 全部 + GM/T 标准；T7 全量回归；如真有客户证书触发，提供 `with_allow_unknown_critical_extensions(true)` builder 列入路线图 |
| `nameConstraints` / `policyConstraints` 列入 known 但未强制执行 | 文档明确说明（P2-1 路线图项）；当前拒绝行为只针对**真正未知**的 OID |
| x509-parser OID 比较性能（O(n) per ext） | `KNOWN_X509_EXTENSIONS` 长度 ≤ 20，O(n) 远优于 O(1) hashmap 构造开销 |
| GmSSL / openHiTLS / Tongsuo 携带的非标准 critical extension | 调研：GmSSL / openHiTLS / Tongsuo 主要扩展均为 RFC 5280 标准集。PR-4.8 interop test 覆盖 |

---

## 6. Out of Scope（不在本 PR 范围）

- nameConstraints 强制执行（子树过滤）
- policyConstraints / policyMappings / inhibitAnyPolicy 强制执行
- `with_allow_unknown_critical_extensions` opt-out builder（如确有需要由后续 PR 引入）
- 任何 cert parser 自身的扩展解析逻辑（x509-parser 负责）

---

## 7. 后续 PR 候选

- **PR-4.9**：gm-crypto nameConstraints subtree filtering 强制执行
- **PR-4.10**：gm-crypto policyConstraints require-explicit-policy 强制执行
- **PR-4.11**：gm-tls CRL grace period + session cache persistence (P1 系列遗留)
- **PR-4.12**：工程完善（CI gating / property tests / fuzz）