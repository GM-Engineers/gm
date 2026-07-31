# 快速入门

> 上次更新：2026-06-29
> 英文版：[getting-started.en.md](./getting-started.en.md)


本指南帮助你从零开始，在 10 分钟内跑通本项目的核心功能。


## 前置条件

|条件|说明|必需|
|---------------|-----------------|--------------|
| Rust 1.85+ | 建议通过 [rustup](https://rustup.rs/) 安装 | ✅ |
| PostgreSQL 17+ | 仅在使用 gm-ca 时需要| ❌ |
| Redis 7+ | 仅在使用 Redis 会话存储时需要| ❌ |
| Docker + docker compose | 可选，用于运行 gm-ca 服务| ❌ |

## 添加依赖

本项目为 Rust workspace。库 crate 可作为依赖添加到你的项目中，gm-ca 是二进制，通过 `cargo run` 运行：


```toml
# 仅使用密码学原语（SM2/SM3/SM4）
gm-crypto = { path = "gm-crypto" }

# 使用 GM/TLS 协议
gm-tls = { path = "gm-tls" }

# 使用 HTTPS 客户端
gm-http-client = { path = "gm-http-client" }
```

gm-ca 是二进制，通过 `cargo run -p gm-ca-server` 运行，不需要加入 `Cargo.toml` 的依赖中。


## 第一个例子：SM2 签名验签

完整签发流程：生成密钥 → 签名 → 验签。


```toml
[dependencies]
gm-crypto = { path = "gm-crypto" }
tokio = { version = "1", features = ["full"] }
```

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier};

fn main() {
    // 1. 生成 SM2 密钥对
    let key_pair = Sm2KeyPair::generate().unwrap();

    // 2. 创建签名者
    let signer = Sm2Signer::new(&key_pair).unwrap();

    // 3. 签名消息
    let message = b"Hello, GM TLS!";
    let signature = signer.sign(message).unwrap();
    println!("Signature (hex): {:x}", signature);

    // 4. 验签
    let public_key = key_pair.public_key_bytes();
    let verifier = Sm2Verifier::new(&public_key, "DEV").unwrap();
    verifier.verify(message, &signature).unwrap();
    println!("Signature verified OK!");
}
```

运行：


```bash
cargo run --example sm2_sign
```

## 第二个例子：GM/TLS 客户端

连接 GM/TLS 服务器，完成双向认证握手。


```toml
[dependencies]
gm-tls = { path = "gm-tls" }
tokio = { version = "1", features = ["full"] }
```

```rust
use gm_tls::{TlsConfig, TlsConnector};

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 加载证书配置（自动执行 GM/T 0028 KAT 自测试）
    let config = TlsConfig::load(
        "certs/client.pem",      // 客户端证书
        "certs/client-key.pem",   // 客户端私钥
        "certs/ca.pem",           // CA 证书（用于验证服务器证书）
    )?
    .with_domain("example.com".to_string());  // 验证服务器域名

    let connector = TlsConnector::new(config)?;

    // 连接服务器
    let tcp = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
    let mut tls = connector.connect(tcp).await?;

    // 发送应用数据
    tls.write_application_data(b"Hello").await?;
    let response = tls.read_application_data().await?;
    println!("Received: {:?}", response);

    Ok(())
}
```

## 第三个例子：GM/TLS 服务器

启动一个支持 mTLS 的 GM/TLS 服务器。


```toml
[dependencies]
gm-tls = { path = "gm-tls" }
tokio = { version = "1", features = ["full"] }
```

```rust
use gm_tls::{TlsConfig, TlsAcceptor};

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TlsConfig::load(
        "certs/server.pem",
        "certs/server-key.pem",
        "certs/ca.pem",
    )?
    .with_require_client_auth(true); // 启用双向认证（mTLS）

    let acceptor = TlsAcceptor::new(config)?; // 自动执行 KAT 自测试

    // 监听 TCP 端口
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    println!("Server listening on 0.0.0.0:8443");

    loop {
        let (tcp, addr) = listener.accept().await?;
        println!("Connection from {}", addr);

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    // 读取客户端请求
                    if let Ok(data) = tls.read_application_data().await {
                        // 原样回显
                        let _ = tls.write_application_data(&data).await;
                    }
                }
                Err(e) => eprintln!("Handshake failed: {}", e),
            }
        });
    }
}
```

## 第四个例子：调用 gm-ca 签发证书

启动 CA 服务后，通过 gRPC 签发证书。


### 步骤 1：启动 CA 服务


```bash
# 设置数据库
export DATABASE_URL="postgres://postgres:test_password@localhost:5432/gm_ca"
export CA_AUTH_TOKEN="$(openssl rand -hex 32)"

# 启动服务（默认监听 [::1]:50051）]:50051)
cargo run -p gm-ca-server
```

### 步骤 2：通过 gRPC 签发证书


```bash
# 使用 grpcurl 调用（需先安装：brew install grpcurl）
grpcurl -plaintext \
  -H "Authorization: Bearer $CA_AUTH_TOKEN" \
  -d '{
    "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
    "validity_days": 365
  }' \
  localhost:50051 gm.ca.v1.CaService/SignCertificate
```

## 第五个例子：SM9 基于身份的签名

SM9 允许直接用身份标识（如邮箱）作为公钥，无需证书管理：


```toml
[dependencies]
gm-sm9-rs = "0.1"
rand = "0.8"
```

```rust
use gm_sm9_rs::{SignMasterKey, Signer, Verifier};

// 1. KGC 生成主密钥
let mut rng = rand::thread_rng();
let master = SignMasterKey::generate(&mut rng)?;

// 2. 为用户派生私钥（用身份标识代替证书）
let user_key = master.extract_key(b"alice@example.com")?;

// 3. 签名
let signer = Signer::new(user_key);
let sig = signer.sign(b"important message", &mut rng)?;

// 4. 验签（任何拥有主公钥的人均可验证）
let verifier = Verifier::new(b"alice@example.com", &master.ppubs);
assert!(verifier.verify(b"important message", &sig)?);
```

SM9 还支持基于身份的加密（`EncMasterKey`/`Encryptor`/`Decryptor`），详见源码 `gm-sm9-rs/` 目录。


## 目录结构参考

```
your-project/
├── Cargo.toml
├── certs/
│   ├── ca.pem           # CA 证书
│   ├── server.pem       # 服务器证书
│   ├── server-key.pem   # 服务器私钥（权限 600）
│   ├── client.pem       # 客户端证书
│   └── client-key.pem   # 客户端私钥（权限 600）
└── src/
    └── main.rs
```

证书生成方式详见 [证书操作指南](./certificate-howto.md)。


## 下一步

|需求|文档|
|----------|-------------------|
| 想深入了解密码学 API |
| 需要自定义 TLS 行为 |
| 想部署 CA 服务 |
| 需要 HTTPS 客户端 |
| 需要 SM9 基于身份的密码| `gm-sm9-rs` crate（签名/加密，双后端） |
