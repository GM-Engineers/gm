# SPEC: PR-4.29 — 第三方集成评估反馈修复批次（gm-tlcp #1–#9）

> Status: **PROPOSED**
> Crates: `gm-tlcp`（0.7.4 → 0.8.0）、`gm-crypto`（0.3.11 → 0.3.12）
> Trigger: 第三方集成评估技术反馈（2026-10-25，3 High / 3 Medium / 2 Low / 1 Feature）
> Spec version: 1.0
> Generated: 2026-10-25

---

## 0. 上下文

评估方在将 `gm-tlcp 0.7.4` 用作 gRPC（tonic 0.14）东西向 TLCP 传输层时，
提出 9 条缺陷/改进与 1 条特性请求。本 SPEC 记录**逐条源码级核实结论**
（含对反馈原文两处不准确的澄清）与本批次的修复范围、接口与测试门禁。

核实基线：`main @ 9e4051a`（gm-tlcp 0.7.4 / gm-crypto 0.3.11 / gm-ca 0.4.3，
与反馈方使用版本完全一致）。

## 1. 核实结论矩阵

| # | 反馈 | 核实结论 | 处置 |
|---|------|---------|------|
| 1 | 🔴 中间 CA 从不上送 | **属实且更严重**：`to_certificate_message` 只序列化两枚 leaf；`from_certificate_message` 在 2 条后截断（反馈称"接收端已能接受链"不准确）；`TlcpAcceptor` 无链配置 API；服务端验证 client 链时对每个条目独立构建单元素链（中间证书不参与链构建） | §2 修复 |
| 2 | 🔴 GM/T 0024 关键扩展被拒 | **属实**：`KNOWN_X509_EXTENSIONS` 无任何 `1.2.156.11235.*`；真实商业 CA 证书若将该扩展置 critical 将被 RFC 5280 §4.2 拒绝。GmSSL 3.1.1 自身不签发该扩展（互操作不可见） | §3 修复 |
| 3 | 🔴 客户端私钥仅明文 PEM | **属实且更严重**：`client_sign_key_password` 为死字段（存入后从未读取），文档承诺的"encrypted PKCS#8 + 默认 P@ssw0rd"未实现；enc key 无 password 参数 | §4 修复 |
| 4 | 🟠 sign 证书 KU/EKU 未校验 | **部分不属实（反馈误读）**：sign leaf 已按 `CertRole::TlcServer`/`TlcClient` 校验（KU digitalSignature + EKU serverAuth/clientAuth，present-then-match）；被注释的 `role=None` 是 **enc** 证书。真实缺口 = enc 证书 KU 未校验 | §5.1 修复（enc KU） |
| 5 | 🟠 `connect()` 静默回退 legacy | **属实**：未配置 `server_sign_pubkey` 时静默走完全不做服务端验证的 deprecated `connect_tlcp`，症状酷似 wire 不兼容；仓库内测试全部配置了 pin，无存量依赖此回退 | §5.2 修复 |
| 6 | 🟠 CRL 静默跳过 | **属实**（有意设计、已文档化）：无匹配 CRL 的证书不检查 | §5.3 修复（opt-in strict） |
| 7 | 🟡 `to_encrypted_pem` 默认 scrypt | **属实**：`pkcs8 0.10.2` 默认 scrypt-aes-256-cbc，批量导出极慢 | §3.2 修复 |
| 8 | 🟡 0.x 无 SemVer 承诺 | 属实，文档改进项 | §6 文档 |
| 9 | ➕ tonic 官方适配器 | 有效特性请求；痛点核实（server 端 tokio traits + `Connected`，client 端 hyper traits + `TokioIo` + `Connected`，两侧不同） | §6 文档先行，完整适配器另立 SPEC |

## 2. #1 — 证书链上送（gm-tlcp）

**线格式**：GB/T 38636-2020 §6.4.5.5 的 Certificate 消息沿用 TLS
`certificate_list` 惯例（ASN.1Cert 条目序列）。双证布局条目序为
`[sign_leaf, enc_leaf, ...intermediate_certs...]`（GmSSL 3.1.1 `src/tlcp.c`
以 index 0=sign / 1=enc 在同一 chain blob 内寻址，中间证书追加其后，
本实现与之对齐）。`total_length` 覆盖全部条目。

**改动**：
- `TlcpCertPair::to_certificate_message`：Dual 模式下追加序列化
  `sign_chain` + `enc_chain` 条目。
- `TlcpCertPair::from_certificate_message`：接受 N≥1 条目；前 1/2 条按
  Single/Dual 判定为 leaf，其余保留进 `sign_chain`（不再静默丢弃）。
- `TlcpAcceptor`：新增 `with_sign_cert_chain(Vec<Vec<u8>>)` /
  `with_enc_cert_chain(Vec<Vec<u8>>)`（leaf 之后的中间 CA，leaf-first）。
- `TlcpConnector` 验证路径：把收到的链 + 配置锚合并为链构建材料
  （`verify_against_anchors` 传入 `[sign_leaf, ...received_intermediates]`）；
  CRL issuer 查找同样使用收到的中间证书（不再无条件 append 全部锚）。
- 服务端对 client `Certificate` 的验证：以 `[entry0, ...中间证书]` 与
  `[entry1, ...中间证书]` 分别构建 sign/enc 链验证，不再对每个条目
  独立当 leaf 验证（该行为在客户端已上送 CA 条目时是误报根源）。

**测试**（红→绿）：三级链 root→intermediate→leaf loopback，客户端仅锚
root：修复前失败（`unable to build chain`），修复后成功；双向（server 链
+ client 链）；无链的 2 条目旧格式回归保护（既有 dual roundtrip 测试）。

## 3. gm-crypto

### 3.1 #2 — GM/T 0024 扩展 OID 白名单

`KNOWN_X509_EXTENSIONS` 增加（accepted, semantics not enforced，沿用
nameConstraints/policyConstraints 既有模式）：
- `1.2.156.11235.1.1.1`（TLCP 服务器证书扩展）
- `1.2.156.11235.1.1.2`（TLCP 客户端证书扩展）

不加入 `1.2.156.11235.1.1.6/.7`（cryptblock，属 PKCS#7 域，不在 X.509
证书扩展路径）。

**测试**：构造带 critical `1.2.156.11235.1.1.1` 扩展的证书 → 修复前
`check_unknown_critical_extensions` 拒绝，修复后接受；同时验证未知
critical OID（如 `1.2.3.4.5.6.7.8.9`）仍被拒绝（白名单不泛化）。

### 3.2 #7 — 加密 PKCS#8 导出 KDF 可选

新增 `Sm2KeyPair::to_encrypted_pem_with_kdf(password, kdf: &PbeKdf)`，
`PbeKdf = { Scrypt { log_n, r, p }, Pbkdf2 { iterations } }`（经
`pkcs8::PrivateKeyInfo::encrypt_with_params`）。`to_encrypted_pem`
默认行为不变（scrypt，故意昂贵）；文档注明批量签发应使用 PBKDF2 路径
并给出最小迭代数建议。解密侧 `from_encrypted_pem` 天然支持两种参数，
文档补一句。

**测试**：PBKDF2 round-trip（快、可进 CI）+ scrypt 显式低成本参数
round-trip + 加密算法 OID 断言。

## 4. #3 — 客户端加密私钥回退（gm-tlcp）

`TlcpConnector` 两处密钥加载（ECDHE client enc key、CertificateVerify
client sign key）：明文 `from_private_key_pem` 失败后回退
`Sm2KeyPair::from_encrypted_pem(pem, password)`；password 取
`client_sign_key_password`（打通死字段，sign/enc 共用），`None` 时回退
文档承诺的 `"P@ssw0rd"`（gmssl sm2keygen 测试证书约定，保留 SECURITY
WARNING 文案）。错误信息区分「明文解析失败 + 解密失败」两级原因。
`with_client_certs` 文档同步修正（去掉未实现的暗示差异）。

**测试**：`to_encrypted_pem`（PBKDF2 快参数）产物作为 client sign/enc key
完成 ECDHE 双向认证握手（修复前报 `PEM parse failed`）；错误密码得到
明确的解密失败错误。

## 5. Medium 修复（gm-tlcp）

### 5.1 #4（修正后）— enc 证书 KU present-then-match

新增 `CertRole::TlcEncServer` / `TlcEncClient`（gm-crypto）：KU 存在时
必须含 `keyEncipherment` 或 `keyAgreement`（GB/T 38636-2020
§6.4.6.1.2 b) 与 GmSSL `x509_certs_verify_tlcp` 口径一致）；KU/EKU 缺失
仍放行（RFC 5280 可选，兼容存量证书）。gm-tlcp 的 enc leaf 验证从
`role=None` 切换到新 role；`mod.rs` 中原易误读注释同步改写（澄清
sign leaf 一直是受校验的）。

### 5.2 #5 — `connect()` 显式错误替代静默回退

`connect()` 在未配置 `server_sign_pubkey` 时返回
`TlcpError::HandshakeFailed("connect() requires with_server_sign_key(...)
for certificate verification; legacy unverified path available via the
free function connect_tlcp()")`。自由函数 `connect_tlcp()`（deprecated
标注保留）仍是显式 legacy 入口，行为不受影响。**行为变更**：静默回退 →
显式错误（面向误配置调用方；仓库内无存量依赖）。

### 5.3 #6 — `strict_crl` opt-in

`TlcpConnector::with_strict_crl(bool)` / `TlcpAcceptor::with_strict_crl(bool)`
（默认 `false`，保持现状）。开启时：配置了 CRL 集合的前提下，链中任一
非自签元素找不到「issuer DN 匹配且签名可验证」的 CRL 即 fail-closed
`CertificateRevocationCheckFailed("no CRL available for issuer ...")`；
同时对被跳过证书发 `log::warn!`。

## 6. 文档（#8 / #9）

- README（中/英，workspace 根 + gm-tlcp）：增加 Versioning/Adoption 段
  —— 0.x 期间无 SemVer 承诺、下游应精确 pin、每发布 CHANGELOG 映射审计
  编号。
- `docs/gm-tlcp.md` / `.en.md`：增加 tonic 集成小节——server 侧
  （tokio AsyncRead/AsyncWrite + `Connected` wrapper）与 client 侧
  （hyper rt traits + `TokioIo` + `Connected`）所需 IO 适配差异示例代码、
  `into_inner()` 取回底层连接以便 tonic 对半关闭写端的处理、以及
  "handshake 完成前不可判定 peer 身份"注意事项。完整官方适配器 crate
  另立 SPEC（候选 PR-4.30），本批次不引入 tonic 依赖。

## 7. 版本与发布

- `gm-crypto` 0.3.11 → **0.3.12**（纯 additive：新 role、新 KDF API、
  扩展白名单条目）。
- `gm-tlcp` 0.7.4 → **0.8.0**（additive API 为主；#5 属误配置路径的
  行为修正，minor bump 并在 CHANGELOG 标注迁移说明：legacy 用户显式改用
  `connect_tlcp()`）。
- 发布顺序：gm-crypto 先行 → gm-tlcp（依赖 path+version caret）。

## 8. 质量门禁

每批次：`cargo +nightly fmt --check`、`cargo clippy --all-targets --
-D warnings`（stable 1.88 与 nightly 双门禁对齐 CI）、workspace 全量
测试、gm-tlcp 特性组合测试（sm9/rsa/metrics）、GmSSL 3.1.1 活体互操作
（`tests/gmssl_interop.rs` shell-out 套件 + 本批新增带链互操作场景）。
所有新测试先证明在修复前失败（红→绿记录进提交信息正文）。

## 9. 明确不做（本批次）

- 不实现 GM/T 0024 扩展语义校验（仅白名单化，避免误拒真实 CA 证书；
  解释性校验留待真实商业 CA 样本）。
- 不引入 tonic 适配器 crate/依赖（§6）。
- 不改动 `to_encrypted_pem` 默认 KDF 参数（避免存量密文兼容性问题）。
- OCSP / CRL 主动抓取（保持确定性、无网络侧攻击面的既有设计决定）。
