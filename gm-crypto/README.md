# gm-crypto

**国密算法库（gm-crypto）** — 纯 Rust 实现的 SM2/SM3/SM4 密码学原语。

**[English Version](./README.en.md)**

## 算法

| 算法 | 类型 | 说明 |
|------|------|------|
| SM2 | 非对称 | 椭圆曲线签名和密钥交换，基于 GF(p) 曲线 |
| SM3 | 哈希 | 国密哈希算法，256位输出 |
| SM4 | 对称 | 分组密码，支持 ECB/CBC/GCM 模式（⚠️ ECB 已废弃，仅用于兼容旧系统，新项目请使用 GCM）；符合 **GM/T 0028-2024** §7.2.4 核准安全功能、**GB/T 32907-2016**、**GB/T 36624-2018** §8 / 附录 C.5 (SM4-GCM)、**RFC 8998** ShangMi TLS 1.3 套件；Wycheproof SM4-GCM 65/104 vectors 通过；GmSSL 3.1.1 CLI live-interop 通过 |

## 合规与基准

gm-crypto SM4-GCM 实施经过以下标准与基准独立验证：

| 标准 / 基准 | 范围 | 状态 |
|------|------|------|
| **GM/T 0028-2024** | §7.2.4 核准安全功能 / 密码模块自检框架 | ✅ `kat.rs` 自检包装 |
| **GB/T 32907-2016** | SM4 分组密码 ECB KAT（附录 A） | ✅ `kat_sm4` |
| **GB/T 36624-2018** | §8 / 附录 C.5 (Mechanism 5 = SM4-GCM KAT v1+v2) | ✅ `kat_sm4_gcm` |
| **RFC 8998** | ShangMi TLS 1.3 套件 / 附录 A.1 SM4-GCM KAT | ✅ `kat_sm4_gcm` |
| **Wycheproof C2SP** | `testvectors_v1/sm4_gcm_test.json` 12-byte-IV 子集 | ✅ 65/104 vectors (38 valid + 27 invalid) |
| **GmSSL 3.1.1 CLI** | `gmssl sm4 -gcm` live shell-out byte-for-byte | ✅ `gcm_vs_gmssl_cli` |

详细验证报告：[`interop/INTEROP-2026-10-01-sm4-gcm-verification.md`](interop/INTEROP-2026-10-01-sm4-gcm-verification.md)。

## 安全特性

- SM4 密钥在 `Drop` 时自动清零（`ZeroizeOnDrop`）
- HMAC 验证使用常量时间比较（防止时序攻击）
- 所有随机数使用 `OsRng`（操作系统 CSPRNG）

## 快速开始

```toml
[dependencies]
gm-crypto = "0.3"
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
