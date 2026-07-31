# gm-crypto

**国密密码学算法库** — 纯 Rust 实现的 SM2/SM3/SM4 密码学原语。

**[English Version](./README.en.md)**

## 算法

| 算法 | 类型 | 说明 |
|------|------|------|
| SM2 | 非对称 | 椭圆曲线签名和密钥交换，基于 GF(p) 曲线 |
| SM3 | 哈希 | 国密哈希算法，256位输出 |
| SM4 | 对称 | 分组密码，支持 ECB/CBC/GCM 模式（⚠️ ECB 已废弃，仅用于兼容旧系统，新项目请使用 GCM） |

## 安全特性

- SM4 密钥在 `Drop` 时自动清零（`ZeroizeOnDrop`）
- HMAC 验证使用常量时间比较（防止时序攻击）
- 所有随机数使用 `OsRng`（操作系统 CSPRNG）

## 快速开始

```toml
[dependencies]
gm-crypto = "0.1"
```

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer};
use gm_crypto::sm3::Sm3Hasher;
use gm_crypto::sm4::Sm4Cipher;

// SM2 签名
let key_pair = Sm2KeyPair::generate().unwrap();  // generate() 返回 Result
let signer = Sm2Signer::new(&key_pair)?;
let sig = signer.sign(b"message")?;

// SM3 哈希
let hash = Sm3Hasher::hash(b"data")?;

// SM4-GCM 加密
let cipher = Sm4Cipher::new(b"0123456789abcdef".as_slice())?;
let (ct, tag) = cipher.encrypt_gcm(b"plaintext", b"0123456789ab", b"")?;
```

## 许可

MIT OR Apache-2.0 — 参见 [../LICENSE](../LICENSE)
