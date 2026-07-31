# gm-crypto 使用指南

> 上次更新：2026-06-29
> 英文版：[gm-crypto.en.md](./gm-crypto.en.md)

纯 Rust 实现的国密密码学算法库，提供 SM2（签名/加密）、SM3（哈希）、SM4（对称加密）三大模块。所有算法均通过 `zeroize` 在 `Drop` 时自动清零敏感密钥，并使用 `OsRng` 作为安全随机数源。


## 模块概览

```
gm_crypto
├── sm2   # SM2 椭圆曲线签名、验签、加密
├── sm3   # SM3 哈希和 HMAC
├── sm4   # SM4 对称加密（GCM/CBC/ECB）
├── utils # 工具函数（hex/base64 转换）
└── x509  # X.509 证书解析
```

## 添加依赖

```toml
[dependencies]
gm-crypto = { path = "gm-crypto" }
```

---

## SM2 模块

SM2 是基于 GF(p) 椭圆曲线的非对称密码算法，支持签名/验签和加密/解密。


### 密钥对生成与管理

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier, Sm2Encryptor, Sm2Decryptor};

// 生成密钥对（使用国密标准 distid "1234567812345678"）
let key_pair = Sm2KeyPair::generate().unwrap();

// 使用自定义 distid 生成（仅在明确协议要求时使用）
let key_pair2 = Sm2KeyPair::generate_with_distid("custom_distid".to_string()).unwrap();

// 从已有私钥加载
let key_pair3 = Sm2KeyPair::from_private_key(private_key_bytes).unwrap();

// 从 PEM 字符串加载（支持 SEC1、PKCS#8 和加密 PKCS#8）
let pem = std::fs::read_to_string("key.pem")?;
let key_pair4 = Sm2KeyPair::from_private_key_pem(&pem).unwrap();

// 从加密 PEM 加载（PBES2 AES-256-CBC）
let encrypted_pem = std::fs::read_to_string("key-encrypted.pem")?;
let key_pair5 = Sm2KeyPair::from_encrypted_pem(&encrypted_pem, "password123").unwrap();

// 序列化
let private_key_pem = key_pair.private_key_pem().unwrap();  // SEC1 PEM
let private_key_bytes = key_pair.private_key_bytes();       // 原始字节
let public_key_compressed = key_pair.public_key_bytes();    // 压缩格式（33 字节）
let public_key_uncompressed = key_pair.public_key_bytes_uncompressed(); // 非压缩格式（65 字节）

// 加密存储私钥（生产环境推荐）
let encrypted = key_pair.to_encrypted_pem("strong_password_123").unwrap();
```

**注意**：
- `Sm2Verifier::new()` 和 `Sm2Encryptor::new()` 接收的是**非压缩格式**（65字节）的公钥**uncompressed format** (65 bytes) public key
- `Sm2KeyPair` 实现 `ZeroizeOnDrop`，析构时自动清零密钥材料
- `Sm2KeyPair` 不实现 `Clone`，如需复制请使用 `duplicate()` 方法
- 加密 PEM 使用 PBES2 (AES-256-CBC)，密码最小长度 8 字符

### 签名与验签

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier};

// 签名
let key_pair = Sm2KeyPair::generate().unwrap();
let signer = Sm2Signer::new(&key_pair).unwrap();

let message = b"Hello, GM TLS!";
let signature = signer.sign(message).unwrap();
let signature_hex = signer.sign_hex(message).unwrap();  // hex 字符串

// 验签（使用非压缩格式公钥）
let public_key = key_pair.public_key_bytes_uncompressed(); // 65 字节
let verifier = Sm2Verifier::new(&public_key, key_pair.distid()).unwrap();

// verify() 验签成功返回 Ok(())，失败返回 Err
verifier.verify(message, &signature).unwrap();
println!("Signature OK!");

// 使用十六进制字符串验签
verifier.verify_hex(message, &signature_hex).unwrap();
```

### 加密与解密

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Encryptor, Sm2Decryptor};

// 加密（使用接收方的公钥）
let key_pair_receiver = Sm2KeyPair::generate().unwrap();
let public_key = key_pair_receiver.public_key_bytes_uncompressed(); // 65 字节

let encryptor = Sm2Encryptor::new(&public_key).unwrap();
let ciphertext = encryptor.encrypt(b"secret message").unwrap();

// 解密（使用接收方的私钥）
let decryptor = Sm2Decryptor::new(key_pair_receiver).unwrap();
let plaintext = decryptor.decrypt(&ciphertext).unwrap();
assert_eq!(plaintext, b"secret message");
```

---

## SM3 模块

SM3 是国密标准哈希算法，输出 256 位（32 字节）摘要。


### 基本哈希

```rust
use gm_crypto::sm3::Sm3Hasher;

let data = b"hello world";

// 返回字节数组
let hash = Sm3Hasher::hash(data).unwrap();        // 32 字节
let hash_hex = Sm3Hasher::hash_hex(data).unwrap();   // hex 字符串
let hash_b64 = Sm3Hasher::hash_base64(data).unwrap(); // Base64 字符串
```


```rust
use gm_crypto::sm3::Sm3Hmac;

let hmac = Sm3Hmac::new(b"my_secret_key");

// 计算
let mac = hmac.compute(b"message").unwrap();
let mac_hex = hmac.compute_hex(b"message").unwrap();

// 验签（使用常量时间比较，防止时序攻击）
let valid = hmac.verify(b"message", &mac).unwrap();
assert!(valid);
```

---

## SM4 模块

SM4 是国密标准分组密码，密钥长度 16 字节，分组长度 16 字节。


### 常量

```rust
use gm_crypto::sm4::*;
assert_eq!(SM4_KEY_LENGTH, 16);   // 密钥长度
assert_eq!(SM4_BLOCK_SIZE, 16);   // 分组长度
assert_eq!(SM4_GCM_TAG_LENGTH, 16); // GCM 认证标签长度
assert_eq!(SM4_GCM_NONCE_LENGTH, 12); // GCM 推荐 nonce 长度
```

### GCM 模式（推荐）

GCM 是带认证的加密模式，同时保证机密性和完整性。**推荐在所有新场景中使用 GCM**。


```rust
use gm_crypto::sm4::Sm4Cipher;

let key = b"0123456789abcdef"; // 16 字节
let cipher = Sm4Cipher::new(key).unwrap();

// 加密：返回 (密文, 认证标签)
let nonce = b"0123456789ab"; // 12 字节
let (ciphertext, tag) = cipher.encrypt_gcm(b"secret data", nonce, b"aad").unwrap();

// 解密（nonce 和 tag 均需要正确传入）
let plaintext = cipher.decrypt_gcm(&ciphertext, nonce, b"aad", &tag).unwrap();
assert_eq!(plaintext, b"secret data");
```

> **安全警告**：每次加密必须使用**唯一的 nonce**。GCM 的安全性依赖于 nonce 唯一性，重复使用 nonce 会泄漏密钥。

### CBC 模式

CBC 模式支持 PKCS#7 填充（自动处理）。


```rust
use gm_crypto::sm4::Sm4Cipher;

let key = b"0123456789abcdef";
let cipher = Sm4Cipher::new(key).unwrap();
let iv = b"0123456789abcdef"; // 16 字节 IV

// 加密（CBC 会自动填充数据至块对齐）
let ciphertext = cipher.encrypt_cbc(b"hello", iv).unwrap();

// 解密（自动去除 PKCS#7 填充）
let plaintext = cipher.decrypt_cbc(&ciphertext, iv).unwrap();
assert_eq!(plaintext, b"hello");
```

### ECB 模式（已废弃）

```rust
use gm_crypto::sm4::Sm4Cipher;

fn use_ecb() {
    let cipher = Sm4Cipher::new(b"0123456789abcdef").unwrap();
    // ECB 模式已被标记为废弃，不建议在新代码中使用
}
```

> **安全警告**：ECB 模式下相同的明文块产生相同的密文块，会泄漏明文模式。**禁止在新代码中使用**，仅用于兼容遗留系统。

---

## 工具函数

```rust
use gm_crypto::{bytes_to_hex, hex_to_bytes, bytes_to_base64, base64_to_bytes};

// hex 转换
let hex = bytes_to_hex(b"\xde\xad\xbe\xef");  // "deadbeef"
let bytes = hex_to_bytes("deadbeef").unwrap();

// base64 转换
let b64 = bytes_to_base64(b"hello");           // "aGVsbG8="
let bytes = base64_to_bytes("aGVsbG8=").unwrap();
```

---

## X.509 证书解析

```rust
use gm_crypto::x509;

let cert_pem = std::fs::read_to_string("cert.pem")?;
let cert = x509::parse_cert_pem(&cert_pem).unwrap();
// cert 是封装的证书类型，可获取主题、颁发者、有效期等字段
```

---

## 安全说明

| 场景| 建议|
|-----------------|----------------------|
| 密钥存储| 私钥文件权限设为 600，仅所有者可读；生产环境使用加密 PEM |
| 随机数| 始终使用 `Sm2KeyPair::generate()`（内部使用 `OsRng`），不要自己提供随机数|
| Nonce | GCM 模式每次加密必须使用唯一 nonce，绝不重复|
| ECB 模式| **不要使用**，已被标记为废弃|
| HMAC 验证| `verify()` 使用常量时间比较，防止时序攻击|
| 密钥清零| `Sm2KeyPair` 和 `Sm3Hmac` 实现 `ZeroizeOnDrop`，析构时自动清零|
| 明文大小| SM2 加密最大明文 64 KiB（`SM2_MAX_PLAINTEXT_LEN`），超限返回错误|

---

## SM2 高级功能

### 加密格式与兼容性

SM2 支持多种密文格式，以兼容不同实现（如 GmSSL）：


```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Encryptor, Sm2Decryptor};

let key_pair = Sm2KeyPair::generate().unwrap();
let encryptor = Sm2Encryptor::new(&key_pair.public_key_bytes_uncompressed()).unwrap();
let plaintext = b"test message";

// 1. 原始格式：C1||C3||C2（默认）
let raw = encryptor.encrypt(plaintext).unwrap();

// 2. DER 格式：兼容 GmSSL sm2encrypt 命令
let der = encryptor.encrypt_der(plaintext).unwrap();

// 3. 版本化格式：带魔术头，支持格式自动检测
let versioned_raw = encryptor.encrypt_versioned(plaintext).unwrap();
let versioned_der = encryptor.encrypt_versioned_der(plaintext).unwrap();

// 解密时自动检测格式
let decryptor = Sm2Decryptor::new(key_pair);
assert_eq!(decryptor.decrypt(&raw).unwrap(), plaintext);
assert_eq!(decryptor.decrypt(&der).unwrap(), plaintext);
assert_eq!(decryptor.decrypt(&versioned_raw).unwrap(), plaintext);
assert_eq!(decryptor.decrypt(&versioned_der).unwrap(), plaintext);
```

**格式说明**：

| 格式| 特征| 用途|
|---------------|------------------|-----------------|
| Raw C1\|\|C3\|\|C2 | 以 `0x04` 开头| 内部使用、高效传输|
| DER SM2Cipher | 以 `0x30` 开头| GmSSL 兼容|
| Versioned | 以 `0x53 0x4D` 开头| 格式明确、支持未来扩展|

### ECDH 密钥交换

SM2 支持标准 ECDH 密钥交换，用于 TLCP ECDHE 密码套件和 TLS 1.3 密钥共享：


```rust
use gm_crypto::sm2::Sm2EcdhKeypair;

// 双方生成临时密钥对
let alice = Sm2EcdhKeypair::generate().unwrap();
let bob = Sm2EcdhKeypair::generate().unwrap();

// 交换公钥并计算共享密钥
let shared_alice = alice.compute_shared_secret(&bob.public_key_bytes()).unwrap();
let shared_bob = bob.compute_shared_secret(&alice.public_key_bytes()).unwrap();

assert_eq!(shared_alice, shared_bob);
// 共享密钥为 32 字节（x 坐标），需通过 KDF 派生会话密钥
```

### 签名格式转换

SM2 签名支持 DER 与原始格式互换，用于 X.509 和 CMS 兼容：


```rust
use gm_crypto::sm2::{sm2_signature_raw_to_der, sm2_signature_der_to_raw};

// 原始签名（r||s，64 字节）→ DER 格式
let der_sig = sm2_signature_raw_to_der(&raw_64_bytes);

// DER 格式 → 原始签名
let raw_sig = sm2_signature_der_to_raw(&der_bytes).unwrap();
```
