# SPEC: PR-4.12 — gm-ca 速率限制 per-caller (P2-7)

- **目标编号**：PR-4.12（Batch 4 — gm-ca 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §四 P2-7`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md#L153)：速率限制为全局单桶，建议按 caller 身份分桶防滥用
- **范围**：`gm-ca/src/service.rs` 的 `CaServiceImpl` 把单桶改为 `per-caller` map
- **影响面**：纯增量；现有 `with_rate_limit(capacity, refill_period)` 语义保持（"per-caller capacity / refill_period"）

---

## 1. 问题陈述

[`gm-ca/src/service.rs:32-33`](file:///Users/laozhang/Work/opensource/gm/gm-ca/src/service.rs#L32)：

```rust
/// Rate limiter for certificate signing (token bucket per-peer)
rate_limiter: Arc<Mutex<TokenBucket>>,
```

注释声称是"per-peer"，实际是**全局单桶**：

```rust
// Default: 10 signtures per 60 seconds per peer
rate_limiter: Arc::new(Mutex::new(TokenBucket::new(10, Duration::from_secs(60)))),
```

后果：
- **一个客户端耗尽 → 所有客户端受限**：单个被攻陷 / 行为异常 / 错误循环的客户端耗尽 10 个 token 之后，**所有其他合法客户端**也会收到 `RESOURCE_EXHAUSTED`
- **拒绝服务放大**：CA 资源便宜（每次签名 ~50ms），但限制器是全局共享 — 攻击者用 1 个连接即可锁住整个 CA 服务
- 这是**真实攻击面**：合规要求 "rate limit 必须 per-tenant / per-client identity"

### 1.1 改进建议依据（master plan §四 P2-7）

> `gm-ca/src/service.rs:32-33` | 速率限制为全局单桶（`rate_limiter: Arc<Mutex<TokenBucket>>`），建议按 caller 身份（CN/SAN/IP）分桶防滥用

PR-4.12 按 **peer IP** 分桶 — IP 是最可靠的调用方标识符（不依赖 TLS 客户端身份，因为证书还没签发）。

---

## 2. Fix 策略

### 2.1 数据结构：`HashMap<IpAddr, TokenBucket>`

```rust
pub struct CaServiceImpl {
    signer: Arc<CaSigner>,
    store: Arc<DbStore>,
    crl_number: Arc<AtomicU64>,
    /// PR-4.12 / P2-7: per-caller (peer IP) token buckets.
    /// Each entry is created lazily on first request from that
    /// caller; idle entries are reaped after `idle_ttl`.
    rate_limiters: Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
    /// Per-caller capacity and refill period (shared config).
    rate_limit_capacity: u32,
    rate_limit_refill: Duration,
    /// PR-4.12: TTL after which an idle caller entry is reaped
    /// from the map (prevents unbounded growth from scan attacks).
    rate_limit_idle_ttl: Duration,
}
```

### 2.2 caller identity

从 `tonic::Request::peer_addr()`（gRPC 内置）拿 peer IP — Tonic 在 transport 层总是填充（HTTP/2 CONNECT 阶段），即使不依赖客户端身份验证。

```rust
let peer_ip = request
    .peer_addr()
    .map(|sa| sa.ip())
    .unwrap_or_else(|| "0.0.0.0".parse::<IpAddr>().unwrap());
```

### 2.3 Bucket 取 / 创建 / 销毁

```rust
async fn check_rate_limit(&self, peer_ip: IpAddr) -> Result<(), Status> {
    let mut map = self.rate_limiters.lock().await;
    let now = Instant::now();
    // PR-4.12: lazy reaping — drop entries that have been
    // idle longer than `idle_ttl`. Cap at a small batch to
    // avoid unbounded reaping on hot path; this is opportunistic.
    map.retain(|_, b| now.duration_since(b.last_used) <= self.rate_limit_idle_ttl);

    let bucket = map.entry(peer_ip).or_insert_with(|| {
        TokenBucket::new(self.rate_limit_capacity, self.rate_limit_refill)
    });
    bucket.last_used = now;
    if !bucket.try_consume() {
        metrics::record_error_with_caller("rate_limited", peer_ip);
        return Err(Status::resource_exhausted(...));
    }
    Ok(())
}
```

### 2.4 公共 API 兼容

```rust
impl CaServiceImpl {
    pub fn new(signer: CaSigner, store: Arc<DbStore>) -> Self {
        Self::with_rate_limit(signer, store, 10, Duration::from_secs(60))
    }

    pub fn with_rate_limit(
        signer: CaSigner,
        store: Arc<DbStore>,
        capacity: u32,
        refill_period: Duration,
    ) -> Self {
        Self {
            ...,
            rate_limit_capacity: capacity,
            rate_limit_refill: refill_period,
            rate_limit_idle_ttl: Duration::from_secs(600),  // 10 minutes
        }
    }
}
```

构造函数**签名不变** — `with_rate_limit(capacity, refill_period)` 现在意味着"每个 caller 一个这样的桶"。

### 2.5 版本

`gm-ca/Cargo.toml`：**patch bump**（公共 API 不变；只是 bucket 分配语义改了 + 新内部字段）。

---

## 3. Tests（`gm-ca/src/service.rs::pr412_per_caller_rate_limit_tests`）

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr412_different_ips_have_independent_buckets` | 两个不同 IP 各做 10 次签名 → 都成功；再 1 次 → 都被拒绝 |
| T2 | `pr412_one_ip_exhausted_does_not_block_another` | IP A 耗尽；IP B 仍可签名（pre-PR-4.12 行为下 IP B 也被拒） |
| T3 | `pr412_same_ip_exhausted_blocks_subsequent_requests` | 单个 IP 11 次请求 → 第 11 次返回 `RESOURCE_EXHAUSTED` |
| T4 | `pr412_idle_caller_is_reaped` | IP X 触发一次；mock 时钟超过 `idle_ttl`；下一次访问 IP X 视为新 caller（bucket 重置） |
| T5 | `pr412_zero_peer_addr_falls_back_to_placeholder` | peer_addr 缺失 → 用 `0.0.0.0` 占位（避免 panic） |
| T6 | `pr412_metrics_record_caller_ip_in_label` | `metrics::record_error_with_caller("rate_limited", ip)` 计数器带 caller label |

注：T1-T3 用 mock `CaServiceImpl` + 注入 fake caller IP 通过 `Request::extensions_mut()` 注入一个 mock peer addr — 不实际起 tonic server。

---

## 4. 验证矩阵

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy -p gm-ca --all-targets -- -D warnings
cargo +1.88 test -p gm-ca --all-targets pr412_
cargo +1.88 test -p gm-ca -p gm-tls -p gm-crypto --all-targets   # 全量
```

CI 含 GmSSL Interop（确认 CA 签发流程未破坏）。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| HashMap 受攻击者控制（scan attack）无限增长 | 每次 check_rate_limit 时 retain() 清理 idle > TTL；可配置 TTL |
| NAT 后多个用户共享同一 IP | IP 粒度的限速对共享 IP 不公平；后续 PR 可加 caller 身份 (X-Client-Id header)，本 PR 不做 |
| `peer_addr()` 在 unix socket / local test 下是 None | fallback 到 `0.0.0.0` 占位（这些场景通常不需要限速） |
| 单 IP 攻击者把桶打满 → 该 IP 被限速（OK，正是 PR-4.12 目的） | 由 caller identity 正确分桶后该 IP 限速不影响其他 IP |
| 锁粒度变粗（整个 HashMap 一个 Mutex） | 高 QPS 下是瓶颈；后续可换 `dashmap`；本 PR 不做（QPS 级别 CA 服务通常 <100/s） |

---

## 6. Out of Scope

- `X-Client-Id` header / mTLS caller identity（依赖前置验证链）
- `dashmap` 高性能分片器
- `metrics::record_error_with_caller` 的具体 label schema 调优

---

## 7. 后续 PR 候选

- **PR-4.13**：gm-tls CRL grace period + session cache persistence
- **PR-4.14**：gm-crypto SM2 private key [1, n-1] 范围校验 (P2-9)
- **PR-4.15**：gm-kms 加证书对账 cron (P2-8)
