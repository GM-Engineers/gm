# gm-tlcp 使用指南

`gm-tlcp` 是 **TLCP（Transport Layer Cryptographic Protocol，GB/T 38636-2020）** 的独立 Rust 实现——这是中国国家标准的传输层密码协议。

本页是快速上手指南。完整 rustdoc 见 [docs.rs/gm-tlcp](https://docs.rs/gm-tlcp)。

## 什么是 TLCP？

TLCP 在结构上类似 TLS 1.3，但**与 TLS 1.3 不兼容**：

- 使用 **SM2**（签名 + 加密 + 密钥交换）、**SM3**（哈希）、**SM4**（分组密码）
- SM2/SM9 套件需要**双证书**（签名证书 + 加密证书）；RSA 套件按 GB/T 38636-2020 §6.4.5.5 走单证书 layout（兼容模式仍保留双证书）
- 协议版本字节为 `[0x01, 0x01]`（TLCP），而非 `[0x03, 0x03]`（TLS 1.3）
- 定义了 **12 套密码套件**（GB/T 38636-2020 §6.4.5.2.1 表 2），gm-tlcp 已实现全部 12 套，且全部具备端到端 in-process loopback 回归覆盖（`tests/gm_tlcp_loopback.rs` 共 21 个测试：16 完整 handshake-loopback + 1 PMS-only KAT + 4 support-module）

| ID | 名称 | 密钥交换 | 说明 |
|----|------|----------|------|
| `0xE051` | `TLS_ECDHE_SM4_GCM_SM3` | SM2 ECDHE | SM4-GCM + SM3 — **首选**，生产推荐 |
| `0xE011` | `TLS_ECDHE_SM4_CBC_SM3` | SM2 ECDHE | SM4-CBC + HMAC-SM3 |
| `0xE053` | `TLS_ECC_SM4_GCM_SM3`  | SM2 static | SM4-GCM + SM3 — 无 ECDHE，性能优化场景 |
| `0xE013` | `TLS_ECC_SM4_CBC_SM3`  | SM2 static | SM4-CBC + HMAC-SM3 — 无 ECDHE |
| `0xE057` | `TLS_IBC_SM4_GCM_SM3`  | SM9 IBC (static) | SM4-GCM + SM3 |
| `0xE017` | `TLS_IBC_SM4_CBC_SM3`  | SM9 IBC (static) | SM4-CBC + HMAC-SM3 |
| `0xE055` | `TLS_IBSDH_SM4_GCM_SM3` | SM9 IBSDH (dynamic) | SM4-GCM + SM3 — 2 轮 KEX |
| `0xE015` | `TLS_IBSDH_SM4_CBC_SM3` | SM9 IBSDH (dynamic) | SM4-CBC + HMAC-SM3 — 2 轮 KEX |
| `0xE059` | `TLS_RSA_SM4_GCM_SM3` | RSA | SM4-GCM + SM3 — 双证书兼容 layout / 单证书 spec layout |
| `0xE019` | `TLS_RSA_SM4_CBC_SM3` | RSA | SM4-CBC + HMAC-SM3 — 同上 |
| `0xE05A` | `TLS_RSA_SM4_GCM_SHA256` | RSA | SM4-GCM + SHA-256 标识；**PRF 仍走 SM3**（spec 模糊，与 GmSSL + openHiTLS 一致），详见 CHANGELOG 已知限制 |
| `0xE01C` | `TLS_RSA_SM4_CBC_SHA256` | RSA | SM4-CBC + SHA-256 标识；**PRF 仍走 SM3**，同上 |

## 与 `gm-tls` 的关系

`gm-tls` 是**独立 crate**，实现 **TLS 1.3 + SM 算法**。原本内嵌在 `gm-tls` 中的 TLCP 实现已提取到独立的 `gm-tlcp` crate（commit `28fbca1`），以便两个协议栈独立演进。根据对端使用的协议选择 crate：

- **对端使用 TLS 1.3**（带或不带 SM 密码套件）→ 用 `gm-tls`
- **对端使用 TLCP**（GB/T 38636-2020）→ 用 `gm-tlcp`

## 快速上手

添加到 `Cargo.toml`：

```toml
[dependencies]
gm-crypto = "0.3"
gm-tlcp = "0.6"
tokio = { version = "1", features = ["full"] }
```

### 服务端（TLCP acceptor）

```rust
use gm_tlcp::{TlcpAcceptor, TlcpError};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. 加载双证书（DER-encoded X.509）和双私钥（PEM-encoded SM2）
    let sign_cert = std::fs::read("server-sign.crt")?;
    let enc_cert  = std::fs::read("server-enc.crt")?;
    let sign_pem  = std::fs::read_to_string("server-sign.key.pem")?;
    let enc_pem   = std::fs::read_to_string("server-enc.key.pem")?;

    // 2. 构造 SM2 密钥对
    let sign_key = gm_crypto::sm2::Sm2KeyPair::from_private_key_pem(&sign_pem)?;
    let enc_key  = gm_crypto::sm2::Sm2KeyPair::from_private_key_pem(&enc_pem)?;

    // 3. 构造 acceptor，配置双证书
    let acceptor = TlcpAcceptor::new()
        .with_dual_certs(sign_cert, enc_cert, sign_key, enc_key);

    // 4. 监听 + 回显循环
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8443").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let mut tlcp = acceptor.accept_with_certs(stream).await?;
            tlcp.write_application_data(b"HTTP/1.1 200 OK\r\n\r\nHello TLCP!").await.ok();
            Ok::<(), TlcpError>(())
        });
    }
}
```

> **RSA / SM9 套件的服务端配置**：分别使用 `TlcpAcceptor::with_rsa_certs_single(...)` / `TlcpAcceptor::with_sm9_certs(...)` 替代 `with_dual_certs(...)`。详见 [docs.rs/gm-tlcp](https://docs.rs/gm-tlcp) 的 builder API 列表。

### 客户端（TLCP connector）

```rust
use gm_tlcp::TlcpConnector;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 默认 connector 提供 10 套密码套件（4 SM2 ECDHE/ECC + 2 SM9 IBC + 4 RSA
    // GCM/CBC × SM3/SHA256 PRF）；不含 SM9 IBSDH 套件 (E055/E015)，
    // 需用 `with_cipher_suites(...)` 显式添加。SM3 distid 默认
    // "1234567812345678"（GmSSL / Tongsuo 约定）。
    let connector = TlcpConnector::new();

    let stream = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
    let mut tlcp = connector.connect_with_certs(stream).await?;

    tlcp.write_application_data(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
    let response = tlcp.read_application_data().await?;
    println!("{}", String::from_utf8_lossy(&response));
    Ok(())
}
```

> **生产部署提示**：ECDHE 握手需配置服务端签名公钥用于验证 `ServerKeyExchange`：
> ```rust
> // 用 DER 编码的 SM2 公钥（65 字节 SEC1 非压缩点）+ distid
> connector.with_server_sign_key(server_sign_pub_der, "1234567812345678".to_string())
> ```
> 双向认证（对端启用 `CertificateRequest`）需 `connector.with_client_certs(chain, sign_key_pem, enc_key_pem, password)`。SM9 IBSDH 套件需显式 `with_cipher_suites(vec![TLS_IBSDH_SM4_GCM_SM3, TLS_IBSDH_SM4_CBC_SM3])`。

## 双证书 PKI

TLCP SM2/SM9 套件要求每个对端拥有**两张独立的 SM2 证书**：

1. **签名证书** —— 用于 `CertificateVerify` 和 `ServerKeyExchange` 签名。公钥在对端共享，用于验签。
2. **加密证书** —— 用于 SM2 ECDH 密钥协商。本地需要私钥；公钥与对端共享。

两张证书必须链到同一可信 CA，且都必须是 SM2（OID `1.2.156.10197.1.301`）。

使用 `gmssl sm2keygen` 和 `gmssl certgen` 生成测试 PKI 的步骤详见 [证书操作指南](./certificate-howto.md)。

## 证书校验与 PKI 策略 (0.6.4+)

从 `gm-tlcp 0.6.4` 起，证书链校验**默认为关闭**以保持与 0.6.x 兼容， 但提供两个**选择加入** (opt-in) 的构建器：

| 方法 | 作用 |
|------|------|
| `TlcpConnector::with_server_ca_chain(Vec<Vec<u8>>)` | 配置服务端证书链**信任锚**。握手时验证服务端的 sign + enc 两张叶子证书都直接或间接锚定到其中一个。 |
| `TlcpConnector::with_server_name(&str)` | 配置预期的服务端主机名。握手时验证服务端 sign 证书的 **SAN / CN** 与此字符串不区分大小写相等。 |
| `TlcpAcceptor::with_client_ca_chain(Vec<Vec<u8>>)` | 配置客户端证书链**信任锚**。TLS 双向认证下要求客户端也提供可验证的叶子证书。 |

这些设置**彼此独立**：仅配主机名导致上一份报告中的 T3 / T4 问题中的部分检查仍由证书本身的 `CertificateVerify` 负责。主机名检查可以**独立于 PKI 信任锚**运行。

### 信任锚加载示例

```rust
// 从 CA PEM bundle 加载（pem crate 是 gm-tlcp 测试 dev-dep；
// 生产代码需要在自己的 Cargo.toml 加 `pem = "3"`）
use pem::Pem;

let bundle = std::fs::read("ca-bundle.pem")?;
let anchors: Vec<Vec<u8>> = Pem::iter_from_buffer(&bundle)
    .map(|p| p.unwrap().into_contents())
    .collect();

let connector = TlcpConnector::new()
    .with_server_sign_key(server_sign_pub_65, distid)
    .with_server_ca_chain(anchors)
    .with_server_name("api.example.com");
```

### 行为矩阵

| 信任锚 | 主机名 | 证书链 | 主机名检查 | 证书链校验 | 总计 |
|--------|--------|--------|------------|------------|------|
| 未设 | 未设 | 任意 | 跳过 | 跳过 | **接受**（仅警告，不验证） |
| 未设 | 已设 | 任意 | ✓ | — | 主机名不匹配→拒绝 |
| 已设 | 未设 | 任意 | — | ✓ | 证书链不匹配→拒绝 |
| 已设 | 已设 | 任意 | ✓ | ✓ | 任一不匹配→拒绝 |
| 已设 | — | **空** | — | — | **拒绝**（要求提供证书） |
| 已设 | — | 任意叶子 | — | ✓ | 叶子不在信任锚列表→拒绝 |

### 默认警告

如果调用了握手但未设置上述任何验证方法且对端发来了非空证书，库会输出**一次性** `eprintln!` 警告到 stderr：

```
gm-tlcp WARNING: accepted server certificate without validation
(no trust anchors configured). Call
TlcpConnector::with_server_ca_chain(anchors) to enable PKI
enforcement.
```

### 已知限制

- **主机名检查仅用于 sign 证书**。enc 证书通常不含主机名。
- **证书链验证**按 RFC 5280 §6 风格逐条进行：SM2 签名、有效期、中间 CA 的
  `basicConstraints CA:TRUE`、`pathLenConstraint`（Phase H）、按角色强制
  的 KeyUsage/ExtendedKeyUsage（Phase H）。验证器按 `leaf → intermediate_1
  → … → root` 线性遍历对端链，并把 root 与配置的每个信任锚逐一尝试。
  对端**必须**发送中间 CA；我们暂不从无中间信息的 leaf 构建候选路径。
- **主机名检查**遵循 RFC 6125 §6.4.1（ASCII 大小写不敏感精确匹配）+ §6.4.3
  （单标签通配符 `*.example.com`）+ §6.4.4（IDN/Punycode 规范化走 UTS #46）。
  运维可直接传 `with_server_name("中国.gov.cn")`，会被自动规范化为
  `xn--fiqs8s.gov.cn` 再与 SAN 比较。SAN/CN 条目始终是 IA5String
  （RFC 5280 §4.2.1.6），无需额外处理。
- **CRL 检查**尚未实现，依靠上层的 OCSP 或短有效期轮换。
- **空客户端证书链** + 已设锚时服务端拒绝。但当前 `TlcpConnector::with_client_certs(vec![], ...)` **不会**发送空 `Certificate` 握手消息（应该按 RFC 5246 §7.4.6 发送）。该 wire-format 缺陷是独立的后续项目。

## 特性开关 (Feature flags)

| Feature | 状态 | 说明 |
|---|---|---|
| `default` | enabled | **GB/T 38636-2020 spec 行为**。ECDHE `ClientKeyExchange` 不带 `uint16` 前缀；静态-ECC 不发/读 `ServerKeyExchange`；ECDHE PMS 走 SM2 KAP (48-byte KDF)。与 openHiTLS / Tongsuo 标准模式一致。 |
| `tlcp-gmssl-compat` | opt-in（默认 off） | 回滚到 GmSSL 2026-06+ master 兼容 wire format。仅当你需要连 GmSSL master 时才打开。 |
| `tlcp-strict` | **DEPRECATED**（no-op） | 为 0.2.x 调用者的 `Cargo.toml` 保留——不再影响行为。 |

## 互操作性

`gm-tlcp` 在 4 个第三方 TLCP 实现上做了不同程度验证：

| 对端 | 状态 | 验证范围 |
|---|---|---|
| **in-process loopback** | ✅ 全部 12 套件 | `tests/gm_tlcp_loopback.rs` 共 21 个测试：16 个 gm-tlcp 作为 client + server 通过 `tokio::io::duplex` 完成完整握手 + app-data 来回（覆盖全部 12 个 cipher suites + 4 个 RSA single-cert 变体），加 1 个 PMS-only KAT (`gm_tlcp_kap_pms_roundtrip_with_real_keys`) 加 4 个 support-module 测试 |
| **GmSSL 3.3.0-dev master** | ✅ handshake / ❌ APP_DATA | 9 个握手消息 byte-for-byte 通过（`tlcp-gmssl-compat` 模式，R-8）。F4 = record-layer 死锁（External-Upstream-Blocker，已提交 [gmssl #1920](https://github.com/guanzhi/GmSSL/issues/1920)） |
| **openHiTLS `s_server -tlcp`** | ✅ wire format / ❌ Finished | CKE wire format通过（R-1: 默认模式不再有 `uint16` 前缀，匹配 openHiTLS 期望）；SKE wire format 通过（R-3: static-ECC 走 interpretation-B）；ECDHE x̂ transform 与 openHiTLS 不一致，server 拒收 client Finished（`Decrypt Error (51)`），跟踪为 open issue |
| **Tongsuo 8.3.0** | ❌ state-machine 拒绝 0x0101 | NTLS 状态机不接受 TLCP 版本字节；[Tongsuo #836](https://github.com/Tongsuo-Project/Tongsuo/issues/836) 已由 EricZHANG1688 提交，维护者已确认根因并开 sub-issue [#840](https://github.com/Tongsuo-Project/Tongsuo/issues/840) + [#841](https://github.com/Tongsuo-Project/Tongsuo/issues/841) |

本地运行 GmSSL 互操作测试需要 `gmssl` 在 `PATH`：

```bash
cargo test --test gmssl_interop
cargo test --test gmssl_interop -- --ignored --nocapture  # 完整套件（7 个 #[ignore]d 测试）
```

## 安全性

- `interop/AUDIT-2026-09-06-v2.md` **v2-rev14**（2026-09-11，gm-tlcp 0.6.4 release 时定基）：0 Critical / 0 Major / 0 Minor / 0 Doc still blocked；1 个 External-Upstream-Blocker (F4)。9 项历史遗留 (M-1/M-2/M-3 + m-2..m-6 + D-1) 全部 RESOLVED。
- 所有敏感类型（`SessionKeys`、`TlcpKeyMaterial`、`TlcpHandshake`、`TlcpEcdheContext`、`TlcpResumedSession`）均实现 `Drop` 零化（`zeroize` crate）
- 签名 / MAC / HMAC / Finished 验签使用 `subtle::ConstantTimeEq` 常量时间比较
- 检测到 GCM nonce 重用时返回致命错误 `TlcpError::NonceReuse`（连接 `Drop` 时终止）

漏洞报告方式见 [SECURITY.md](../SECURITY.md)。

## 许可

MIT OR Apache-2.0 — 详见 [LICENSE](../LICENSE)。