# gm-sm9-rs: SM9 标识密码算法（国密 GM/T 0044-2016）

**[English Version](./README.en.md)**

## 功能特性

本模块实现 GM/T 0044-2016 标准的 SM9 标识密码算法，包括：

- **纯 Rust 实现** (默认): 使用标准 SM9 曲线参数和 SM3 哈希
- **GmSSL FFI 后端**: 调用 GmSSL 3.1.1 实现

## 架构

```
gm-sm9-rs/
├── src/
│   ├── lib.rs           # 库入口
│   ├── params.rs        # SM9 标准曲线参数 (GM/T 0044-2016)
│   ├── z256/            # 256位整数运算
│   ├── field/           # 有限域 (Fp, Fp2, Fp4, Fp12)
│   ├── curve/           # 椭圆曲线点 (G1, G2)
│   ├── pairing/         # 双线性配对 (R-ate)
│   ├── hash/            # SM3 Hash1/Hash2
│   ├── key/             # 密钥生成与提取
│   ├── sign.rs          # 签名算法
│   ├── encrypt.rs       # 加密算法
│   ├── ffi.rs           # GmSSL FFI 绑定
│   └── gmssl_backend.rs # GmSSL 后端实现
├── tests/
│   └── cross_validation.rs  # 交叉验证测试
├── Cargo.toml
└── README.md
```

## 依赖

- `sm3` - SM3 国密哈希算法
- `subtle` - 常数时间操作
- `zeroize` - 安全内存清理
- `rand` - 随机数生成
- `libc` - GmSSL FFI (gmssl feature)

## API 使用

```rust
use gm_sm9_rs::{Signer, Verifier, Encryptor, Decryptor, SignMasterKey, EncMasterKey};
use rand::thread_rng;

// 生成签名主密钥
let sign_master = SignMasterKey::generate(&mut thread_rng())?;

// 派生用户签名密钥
let sign_key = sign_master.extract_key(b"user@example.com")?;

// 签名
let signer = Signer::new(sign_key);
let signature = signer.sign(b"message", &mut thread_rng())?;

// 验签
let verifier = Verifier::new(b"user@example.com", &sign_master.ppubs);
assert!(verifier.verify(b"message", &signature).unwrap());

// 加密
let enc_master = EncMasterKey::generate(&mut thread_rng())?;
let encryptor = Encryptor::new(b"recipient@example.com", &enc_master.ppube);
let ciphertext = encryptor.encrypt(b"secret message", &mut thread_rng())?;

// 解密
let dec_key = enc_master.extract_key(b"recipient@example.com")?;
let decryptor = Decryptor::new(dec_key);
let plaintext = decryptor.decrypt(&ciphertext, b"recipient@example.com")?;
```

## 交叉验证

GmSSL 后端和纯 Rust 后端之间进行了交叉验证：

```bash
# 纯 Rust 后端
cargo test --no-default-features --test cross_validation

# GmSSL 后端 (需要 GmSSL 3.1.1)
cargo test --features gmssl --test cross_validation
```

所有 17 项交叉验证测试均通过：
- GmSSL 签名 → 纯 Rust 验签
- 纯 Rust 签名 → GmSSL 验签
- 配对计算一致性
- 密钥派生一致性