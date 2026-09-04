# gm-tlcp 使用指南

`gm-tlcp` 是 **TLCP（Transport Layer Cryptographic Protocol，GB/T 38636-2020）** 的独立 Rust 实现——这是中国国家标准的传输层密码协议。

本页是快速上手指南。完整 rustdoc 见 [docs.rs/gm-tlcp](https://docs.rs/gm-tlcp)。

## 什么是 TLCP？

TLCP 在结构上类似 TLS 1.3，但**与 TLS 1.3 不兼容**：

- 使用 **SM2**（签名 + 加密 + 密钥交换）、**SM3**（哈希）、**SM4**（分组密码）
- 需要**双证书**（签名证书 + 加密证书），不同于 TLS 1.3 的单证书模式
- 协议版本字节为 `[0x01, 0x01]`（TLCP），而非 `[0x03, 0x03]`（TLS 1.3）
- 定义了 4 套密码套件：

| ID | 名称 | 说明 |
|----|------|------|
| `0xE051` | `TLS_ECDHE_SM4_GCM_SM3` | ECDHE + SM4-GCM + SM3 — **首选** |
| `0xE011` | `TLS_ECDHE_SM4_CBC_SM3` | ECDHE + SM4-CBC + HMAC-SM3 |
| `0xE053` | `TLS_ECC_SM4_GCM_SM3`  | 静态密钥 + SM4-GCM + SM3 — 无 ECDHE |
| `0xE013` | `TLS_ECC_SM4_CBC_SM3`  | 静态密钥 + SM4-CBC + HMAC-SM3 — 无 ECDHE |

## 与 `gm-tls` 的关系

`gm-tls` 是**独立 crate**，实现 **TLS 1.3 + SM 算法**。原本内嵌在 `gm-tls` 中的 TLCP 实现已提取到独立的 `gm-tlcp` crate（commit `28fbca1`），以便两个协议栈独立演进。根据对端使用的协议选择 crate：

- **对端使用 TLS 1.3**（带或不带 SM 密码套件）→ 用 `gm-tls`
- **对端使用 TLCP**（GB/T 38636-2020）→ 用 `gm-tlcp`

## 快速上手

添加到 `Cargo.toml`：

```toml
[dependencies]
gm-crypto = "0.2"
gm-tlcp = "0.1"
tokio = { version = "1", features = ["full"] }
```

### 服务端（TLCP acceptor）

```rust
use gm_tlcp::{TlcpAcceptor, TlcpCipherSuite};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sign_cert = std::fs::read("server-sign.crt")?;     // DER，签名证书
    let enc_cert  = std::fs::read("server-enc.crt")?;      // DER，加密证书
    let sign_key  = std::fs::read("server-sign.key.pem")?; // SEC1 PEM
    let sign_pub_65 = /* 65 字节 SM2 SEC1 非压缩公钥 */;

    let acceptor = TlcpAcceptor::new()
        .with_dual_certs(sign_cert, enc_cert, sign_pub_65)
        .with_server_sign_key(sign_key, None)
        .with_cipher_suites(vec![TlcpCipherSuite::TLS_ECDHE_SM4_GCM_SM3]);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8443").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(mut tlcp) = acceptor.accept(stream).await {
                tlcp.write_all(b"HTTP/1.1 200 OK\r\n\r\nHello TLCP!").await.ok();
            }
        });
    }
}
```

### 客户端（TLCP connector）

```rust
use gm_tlcp::{TlcpConnector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_sign_pub_65 = /* 服务端的 65 字节 SM2 SEC1 非压缩公钥 */;

    let connector = TlcpConnector::new()
        .with_server_sign_key(server_sign_pub_65.to_vec(), b"1234567812345678".to_vec());

    let stream = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
    let mut tlcp = connector.connect(stream).await?;

    tlcp.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
    let mut buf = vec![0u8; 4096];
    let n = tlcp.read(&mut buf).await?;
    println!("{}", String::from_utf8_lossy(&buf[..n]));
    Ok(())
}
```

## 双证书 PKI

TLCP 要求每个对端拥有**两张独立的 SM2 证书**：

1. **签名证书** —— 用于 `CertificateVerify` 和 ServerKeyExchange 签名。公钥在对端共享，用于验签。
2. **加密证书** —— 用于 SM2 ECDH 密钥协商。本地需要私钥；公钥与对端共享。

两张证书必须链到同一可信 CA，且都必须是 SM2（OID `1.2.156.10197.1.301`）。

使用 `gmssl sm2keygen` 和 `gmssl certgen` 生成测试 PKI 的步骤详见 [证书操作指南](./certificate-howto.md)。

## 互操作性

`gm-tlcp` 已逐字节验证与 GmSSL 的互通：

- **GmSSL 3.2.0**（已发布版本）—— 全部 4 套密码套件，完整握手 + APP_DATA 往返
- **GmSSL 3.3.0-dev master**（commit `1183+`）—— 同上，外加 master 强制的客户端证书路径

本地运行 GmSSL 互操作测试需要 `gmssl` 在 `PATH`：

```bash
cargo test --test gmssl_interop
cargo test --test gmssl_interop -- --ignored --nocapture  # 完整套件
```

Tongsuo 8.3.0 互操作**当前未通过**——Tongsuo 的 NTLS 状态机拒绝 TLCP 版本字节 `0x0101`。调查记录见 [`gm-tlcp/interop/tongsuo/upstream/`](https://github.com/GM-Engineers/gm/tree/main/gm/gm-tlcp/interop/tongsuo/upstream/)。

## 安全性

- 发布前已完成 4 轮独立安全审计——见 commit `7b274ad`
- 所有敏感类型（`SessionKeys`、`TlcpKeyMaterial`、`TlcpHandshake`、`TlcpEcdheContext`、`TlcpResumedSession`）均实现 `Drop` 零化
- 签名 / MAC / HMAC / Finished 验签使用常量时间比较
- 检测到 GCM nonce 重用时返回致命错误 `TlcpError::NonceReuse`（连接 `Drop` 时终止）

漏洞报告方式见 [SECURITY.md](../SECURITY.md)。

## 许可

MIT OR Apache-2.0 — 详见 [LICENSE](../LICENSE)。
