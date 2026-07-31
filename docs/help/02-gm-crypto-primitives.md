# GM 算法原语详解 / GM Algorithm Primitives Deep Dive

> 上次更新 / Last Updated: 2026-06-29
> 文档版本 / Doc Version: 2026-05-21
> 对应代码 / Corresponding Code: `gm-crypto/src/`
> 阅读对象 / Target Audience: 密码学实现者、安全审计者 / Cryptography implementers, security auditors
> 标准 / Standards: GM/T 0002/0004/0006-2012

---

## 1. SM2 椭圆曲线公钥密码 / SM2 Elliptic Curve Public Key Cryptography

### 1.1 概述 / Overview

SM2 是基于椭圆曲线（ECC）的公钥密码算法，定义在 GM/T 0006-2012。

SM2 is an elliptic curve public key cryptography algorithm based on ECC, defined in GM/T 0006-2012.

**曲线参数 / Curve Parameters:**
- 曲线 / Curve: y² = x³ + ax + b (Fp 上的曲线 / curve over Fp)
- 密钥长度 / Key length: 256 位 / 256 bits
- 签名输出 / Signature output: 64 字节 / 64 bytes (r || s)

**gm-crypto 实现 / gm-crypto Implementation:**

| 类型 Type | 文件 File | 职责 Responsibility |
|---------|---------|-------------------|
| `Sm2KeyPair` | sm2.rs | 密钥对生成、导入、PKCS#8 序列化 / Key pair generation, import, PKCS#8 serialization |
| `Sm2Signer` | sm2.rs | SM2 签名（使用 distid 标识符）/ SM2 signing (using distid identifier) |
| `Sm2Verifier` | sm2.rs | SM2 验签（需要公钥+distid）/ SM2 verification (requires public key+distid) |
| `Sm2Encryptor` | sm2.rs | SM2 加密（密钥封装）/ SM2 encryption (key encapsulation) |
| `Sm2Decryptor` | sm2.rs | SM2 解密 / SM2 decryption |

### 1.2 签名机制 / Signature Mechanism

SM2 签名与 ECDSA 类似，但使用专门的签名标识符 (distid)：

SM2 signing is similar to ECDSA but uses a dedicated signature identifier (distid):

```
输入 / Input: 消息 M, 用户标识 ID, 私钥 d / message M, user ID, private key d
输出 / Output: 签名 (r || s) / signature (r || s)

1. ZA = Hash(ENTLA || ID || a || b || xG || yG || xA || yA)
2. M' = ZA || M
3. e = Hash(M')  → 转换为整数 / Convert to integer
4. 生成随机数 k (1 < k < n) / Generate random k
5. 计算点 (x1, y1) = k·G
6. r = (e + x1) mod n  （若 r=0 或 r+k=n=0 则返回步骤 4 / if r=0 or r+k=n=0 return step 4）
7. s = k⁻¹ mod n · (d + r·k) mod n  （若 s=0 则返回步骤 4 / if s=0 return step 4）
8. 返回 (r, s) / Return (r, s)
```

**gm-crypto API:**

```rust
use gm_crypto::sm2::{Sm2KeyPair, Sm2Signer, Sm2Verifier};

let keypair = Sm2KeyPair::generate().unwrap();
let signer = Sm2Signer::new(&keypair).unwrap();
let signature = signer.sign(b"message").unwrap();

let verifier = Sm2Verifier::new(&keypair.public_key_bytes(), "1234567812345678").unwrap();
verifier.verify(b"message", &signature).unwrap(); // 验证通过返回 Ok(()) / Returns Ok(()) if valid
```

### 1.3 加密机制 / Encryption Mechanism

SM2 加密用于密钥封装（key encapsulation），而非 bulk 数据加密：

SM2 encryption is used for key encapsulation, not bulk data encryption:

```
输入 / Input: 消息 M, 公钥 PA / message M, public key PA
输出 / Output: 密文 C1 || C3 || C2 / ciphertext C1 || C3 || C2

1. 生成随机数 k (1 < k < n) / Generate random k
2. 计算点 S = k·G = (x1, y1), 检查 S ≠ O / Compute point, check S ≠ O
3. 计算点 TB = k·PA = (x2, y2), 检查 TB ≠ O / Compute point, check TB ≠ O
4. 派生密钥 / Derive key: t = KDF(x2 || y2, len(M))
5. C2 = M ⊕ t
6. C3 = Hash(x2 || M || y2)
7. C1 = (x1, y1) 以压缩或未压缩形式 / in compressed or uncompressed form
8. 返回 C1 || C3 || C2 / Return C1 || C3 || C2
```

> ⚠️ **限制 / Limitation:** 单次加密的明文上限为 64 KiB（见 `SM2_MAX_PLAINTEXT_LEN`）/ Single encryption plaintext limit is 64 KiB (see `SM2_MAX_PLAINTEXT_LEN`)

### 1.4 密钥交换协议 (SM2-KEX) / Key Exchange Protocol

SM2 密钥交换允许双方通过交换临时公钥建立共享密钥，定义在 GM/T 002-2012：

SM2 key exchange allows two parties to establish a shared secret by exchanging ephemeral public keys, defined in GM/T 002-2012:

**三方角色 / Three-party Roles:**
- A: 发起方（有长期密钥对 KeyA）/ Initiator (has long-term key pair KeyA)
- B: 响应方（有长期密钥对 KeyB）/ Responder (has long-term key pair KeyB)
- KGC: 密钥生成中心（可选，用于密钥托管）/ Key generation center (optional, for key escrow)

**三消息流程 / Three-Message Flow:**

```
A → B (msg1): RA, SA  (临时公钥 + 签名 / ephemeral public key + signature)
B → A (msg2): RB, SB  (临时公钥 + 签名 / ephemeral public key + signature)
A → B (msg3): SB  (验证 B 的签名 / verify B's signature)
```

**gm-crypto API:**

```rust
use gm_crypto::sm2::Sm2KeyPair;
use gm_crypto::sm2_kex::KexSession;

let keypair_a = Sm2KeyPair::generate().unwrap();
let keypair_b = Sm2KeyPair::generate().unwrap();

let mut session_a = KexSession::new_initiator(&keypair_a, b"user_a").unwrap();
let msg1 = session_a.generate_msg1().unwrap();

let mut session_b = KexSession::new_responder(&keypair_b, b"user_b").unwrap();
let msg2 = session_b.process_msg1(&msg1, keypair_a.public_key()).unwrap();

let msg3 = session_a.process_msg2(&msg2, keypair_b.public_key()).unwrap();
session_b.process_msg3(&msg3).unwrap();

let secret_a = session_a.get_result().unwrap().shared_secret;
let secret_b = session_b.get_result().unwrap().shared_secret;
assert_eq!(secret_a, secret_b);
```

---

## 2. SM3 密码哈希算法 / SM3 Cryptographic Hash Algorithm

### 2.1 概述 / Overview

SM3 是国密哈希算法，输出 256 位（32 字节），结构类似 SHA-256 但有不同的线性组合和置换。

SM3 is the national cryptography hash algorithm, outputting 256 bits (32 bytes), structurally similar to SHA-256 but with different linear combinations and permutations.

**特性 / Characteristics:**

| 特性 Feature | 值 Value |
|------------|---------|
| 消息分组 / Message block | 512 位（64 字节 / 64 bytes） |
| 输出长度 / Output length | 256 位（32 字节 / 32 bytes） |
| 迭代结构 / Iterative structure | Merkle-Damgård 构造 / Merkle-Damgård construction |

### 2.2 gm-crypto 实现 / gm-crypto Implementation

```rust
use gm_crypto::sm3::Sm3Hasher;

let hash = Sm3Hasher::hash(b"hello").unwrap();
assert_eq!(hash.len(), 32);  // 256 bits
```

### 2.3 HMAC-SM3

```rust
use gm_crypto::sm3::Sm3Hmac;

let hmac = Sm3Hmac::new(b"key");
let mac = hmac.compute(b"message").unwrap();
assert!(hmac.verify(b"message", &mac).unwrap());
```

**HMAC 结构 / HMAC Structure:** `HMAC(K, m) = H(K' ⊕ ipad || H(K' ⊕ opad || m))`

---

## 3. SM4 分组密码 / SM4 Block Cipher

### 3.1 概述 / Overview

SM4 是 128 位分组密码，密钥长度 128 位，分组长度 128 位。

SM4 is a 128-bit block cipher with 128-bit key length and 128-bit block size.

**模式支持 / Mode Support:**

| 模式 Mode | 用途 Usage | 安全性 Security | 公开 API Public API |
|---------|---------|--------------|------------------|
| ECB | 兼容性 / Compatibility | ⚠️ 不推荐（泄露模式 / Not recommended - leaks patterns） | ✅ |
| CBC | 通用加密 / General encryption | ✅ | ✅ |
| GCM | AEAD 认证加密 / Authenticated encryption | ✅ 首选 / Preferred | ✅ |
| CTR | 内部实现 / Internal use | ✅ | ❌ (内部使用 / Internal only) |

### 3.2 GCM 模式（推荐 / Recommended）

GCM 提供认证加密（AEAD），每次加密包含 16 字节认证标签：

GCM provides authenticated encryption (AEAD) with a 16-byte authentication tag per encryption:

```rust
use gm_crypto::sm4::Sm4Cipher;

let key = [0u8; 16];
let cipher = Sm4Cipher::new(&key).unwrap();
let nonce = [0u8; 12];  // 12 字节 nonce / 12-byte nonce
let (ct, tag) = cipher.encrypt_gcm(b"hello", &nonce, &[]).unwrap();

// 解密时验证 tag / Verify tag on decryption
let pt = cipher.decrypt_gcm(&ct, &nonce, &tag, &[]).unwrap();
```

**参数 / Parameters:**

| 参数 Parameter | 值 Value |
|--------------|---------|
| `SM4_KEY_LENGTH` | 16 字节 / 16 bytes |
| `SM4_BLOCK_SIZE` | 16 字节 / 16 bytes |
| `SM4_GCM_TAG_LENGTH` | 16 字节 / 16 bytes |
| `SM4_GCM_NONCE_LENGTH` | 12 字节 / 12 bytes |

### 3.3 CBC 模式 / CBC Mode

```rust
use gm_crypto::sm4::Sm4Cipher;

let key = [0u8; 16];
let cipher = Sm4Cipher::new(&key).unwrap();
let iv = [0u8; 16];  // 初始化向量 / Initialization vector
let ct = cipher.encrypt_cbc(b"hello", &iv).unwrap();
let pt = cipher.decrypt_cbc(&ct, &iv).unwrap();
```

---

## 4. 安全设计 / Security Design

### 4.1 内存保护 / Memory Protection

| 类型 Type | 保护机制 Protection Mechanism |
|---------|---------------------------|
| `Sm2KeyPair` | `ZeroizeOnDrop` + 无 `Clone` / no `Clone` |
| `Sm4Cipher` | `ZeroizeOnDrop` 保护密钥 / protects key |
| `Sm3Hmac` | `ZeroizeOnDrop` 保护密钥 / protects key |

### 4.2 时序攻击防护 / Timing Attack Protection

- **HMAC 验证 / HMAC verification:** `Sm3Hmac::verify` 使用 `subtle::ConstantTimeEq` 常数时间比较 / uses constant-time comparison
- **SM2 加密 / SM2 encryption:** `Sm2Encryptor::decrypt` 使用 `c3_calc.ct_eq(c3)` 验证密文完整性 / verifies ciphertext integrity
- **CBC padding:** `Sm4Cipher::decrypt_cbc` 使用常数时间 padding 验证，防 padding oracle 攻击 / uses constant-time padding verification to prevent padding oracle attacks

```rust
// Sm3Hmac::verify
Ok(computed.ct_eq(hmac).into())
```

### 4.3 密钥不复制 / No Key Cloning

密钥类型通过 `#[zeroize(skip)]` 和不实现 `Clone` 来防止意外复制：

Key types prevent accidental copying via `#[zeroize(skip)]` and not implementing `Clone`:

```rust
#[derive(ZeroizeOnDrop)]
pub struct Sm2KeyPair {
    private_key: SecretKey<Sm2>,
    #[zeroize(skip)]  // 公钥不敏感，可以访问 / Public key is not sensitive, can be accessed
    public_key: PublicKey<Sm2>,
}
```

---

## 5. KAT 自测试 / KAT Self-Test

gm-crypto 内置 KAT（Known Answer Test）自测试，验证实现正确性：

gm-crypto includes built-in KAT (Known Answer Test) self-testing to verify implementation correctness:

```rust
use gm_crypto::kat;

// 运行所有 KAT 自测试 / Run all KAT self-tests
kat::self_test().expect("KAT self-test failed");

// 或在初始化时确保测试已运行 / Or ensure tests have run at initialization
kat::ensure_self_test().expect("KAT self-test failed");
```

**公开 API / Public API:**

| 函数 Function | 用途 Usage |
|------------|----------|
| `kat::self_test()` | 运行所有 KAT 自测试 / Run all KAT self-tests |
| `kat::self_test_with_options(force)` | 强制重新运行测试 / Force re-run tests |
| `kat::ensure_self_test()` | 确保测试已通过（幂等）/ Ensure tests passed (idempotent) |
| `kat::is_self_test_passed()` | 检查测试状态 / Check test status |
| `kat::verify_software_integrity()` | 验证软件完整性 / Verify software integrity |

**合规性 / Compliance:** GM/T 0028-2014 第 7.2.4.1 节要求的启动自测试 / Startup self-test required by GM/T 0028-2014 §7.2.4.1

---

## 6. 错误处理 / Error Handling

所有密码操作通过 `CryptoError` 报告错误：

All cryptographic operations report errors via `CryptoError`:

```rust
pub enum CryptoError {
    InvalidKeyLength { expected: usize, actual: usize },
    InvalidSignature,
    Sm2KexError(String),
    // ...
}
```

---

## 7. 标准对应 / Standard Mapping

| 算法 Algorithm | 标准号 Standard No. | 主要内容 Main Content |
|--------------|-------------------|---------------------|
| SM2 | GM/T 0006-2012 | 签名、加密、密钥交换 / Sign, encrypt, key exchange |
| SM3 | GM/T 0004-2012 | 哈希算法 / Hash algorithm |
| SM4 | GM/T 0002-2012 | 对称加密 / Symmetric encryption |

---

## 更新记录 / Changelog

| 日期 Date | 版本 Version | 变更 Changes |
|----------|-------------|-------------|
| 2026-06-29 | 1.1 | ✅ 已双语化 / Bilingual completed |
| 2026-05-21 | 1.0 | 初始版本（重写）/ Initial version (rewrite) |
