# PR-4.23 — Handshake Timeout (Slowloris-style DoS 防护, gm-tls 先行)

> Status: **PROPOSED**
> Crates: `gm-tls` (this PR); `gm-tlcp` deferred to PR-4.24
> Author: gm-tls PR batch
> Target version: gm-tls 0.2.11 → 0.2.12 (patch bump)
> Spec version: 1.0
> Generated: 2026-09-24

---

## 0. Scope 调整说明

初版 SPEC 计划同时改 gm-tls 和 gm-tlcp。但 gm-tlcp 当前没有 `HandshakeOptions` 聚合结构，`connect`/`accept` 入口有 6 个变体（`connect`/`connect_with_certs`/`accept`/`accept_with_certs`/`connect_tlcp`/`connect_tlcp_with_context` 等），wrap-point 改造面比 gm-tls 大且每个入口都要确保 wrap 一次。

为降低风险、让 PR-4.23 保持可审查的 diff 规模，**本次 PR 只覆盖 gm-tls**，gm-tlcp 同步放到 PR-4.24（架构选择：新建 `HandshakeOptions` 聚合结构 or 直接字段，由 PR-4.24 SPEC 决定）。

---

## 1. Background

当前 `gm-tls` 和 `gm-tlcp` 的 `connect`/`accept` 握手逻辑底层是 `tokio::net::TcpStream` 上的多次 `AsyncReadExt::read`/`AsyncWriteExt::write` 调用，**没有任何应用层握手超时保护**。

### 1.1 风险

攻击者（恶意客户端对 server；恶意 server 对客户端）可以：

- 打开 TCP 连接（消耗 1 个 fd + 1 个握手并发槽位）
- 在 ClientHello 之后不发后续字节，**慢慢吞吞地每 N 秒发 1 个字节**
- 或者故意构造长度字段让服务器分配大 buffer 但永远不传完
- 累计 N 个这样的连接就能让服务器文件描述符或握手任务耗尽

这是教科书级的 **Slowloris-style application-layer DoS**。TLS 服务器没有第一道防护，常见的缓解是在握手层加 wall-clock timeout。

### 1.2 已有的相关设施

- `gm-tls`/`gm-tlcp` 都已有 `HandshakeOptions`（gm-tls PR-4.13/4.20 已扩展）
- 已有 `record_handshake_duration(role, secs)` metrics 接入（PR-4.10）
- 已有 `record_handshake_error_code(role, code)` 接入（PR-4.22）
- `tokio` 已依赖（PR-4.x 已在 `tokio::time::timeout` 上运行握手）

### 1.3 设计目标

1. 给 `connect`/`accept` 加可配置的握手 wall-clock timeout（默认 30s）
2. 超时返回 `TlsError::HandshakeFailed`/`TlcpError::HandshakeFailed`，错误消息含 "handshake timeout after Ns"
3. 超时也被 metrics 记录为 `HandshakeFailed` 错误码（自然扩展 PR-4.22）
4. 默认值要足够大以容纳 TLS 1.3/TLCP 正常握手（含 KAT、SM2 签名验签），但足够小以避免单连接长时间占用
5. `Duration::ZERO` 表示 disable（保留显式 opt-out，便于测试/特殊场景）

---

## 2. Design

### 2.1 数据结构

#### `gm-tls::HandshakeOptions`

新增字段：

```rust
/// PR-4.23: Wall-clock timeout for the entire handshake
/// (from first byte read/write until Finished is verified).
///
/// Default: 30 seconds (matches mainstream TLS libraries'
/// default handshake timeout — Go crypto/tls defaults to
/// min(15s, ctx-deadline); OpenSSL defaults are platform-
/// dependent but typically 60s; we pick a balanced 30s).
///
/// Slowloris mitigation: an attacker who opens a TCP
/// connection and then dribbles bytes will be terminated
/// after `handshake_timeout` even if the underlying TCP
/// read/write would otherwise block indefinitely. The
/// timer starts when the handshake coroutine begins and
/// is cancelled when handshake completes (success or
/// failure — failure gets a fresh error code
/// `HandshakeFailed` so PR-4.22 metrics slice by code).
///
/// Set via
/// [`TlsConfig::with_handshake_timeout`](crate::TlsConfig::with_handshake_timeout).
/// Use [`Duration::ZERO`] to disable (NOT recommended in
/// production — only intended for tests and known-trusted
/// environments).
pub handshake_timeout: Duration,
```

默认值（`impl Default for HandshakeOptions`）：`Duration::from_secs(30)`。

#### `gm-tlcp::HandshakeOptions`（如尚未存在则新建）

gm-tlcp 之前可能没有 `HandshakeOptions` 这种聚合结构（PR-4.20 CRL grace period 评估时未涉及 gm-tlcp）。需要先确认：

- 如果没有，则同步设计一个 `HandshakeOptions` 聚合
- 如果已有，则追加 `handshake_timeout` 字段

### 2.2 Builder

#### `gm-tls::TlsConfig`

```rust
/// PR-4.23: set the wall-clock timeout for the TLS
/// handshake. See
/// [`HandshakeOptions::handshake_timeout`](gm_tls::gm::HandshakeOptions::handshake_timeout)
/// for the full contract.
///
/// Recommended values:
/// - **default** (`Duration::from_secs(30)`): general production
/// - shorter (e.g. 5s) for fail-fast service-mesh sidecars
///   behind L4 LBs that already enforce their own idle timeout
/// - longer (e.g. 120s) when the server does CPU-intensive
///   work synchronously during handshake (e.g. HSM-backed
///   sign operations, OCSP fetching from a slow CA)
/// - `Duration::ZERO` to disable (tests only)
pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
    self.handshake_opts
        .get_or_insert_with(HandshakeOptions::default);
    if let Some(opts) = &mut self.handshake_opts {
        opts.handshake_timeout = timeout;
    }
    self
}
```

#### `gm-tlcp::TlcpConfig`（如有）

对称加 builder。

### 2.3 Wrap-point 改造

不直接修改 `connect_gm_rust_inner` / `accept_gm_rust_inner` 的内部逻辑（那样风险大），而是在外层 wrap 函数中：

```rust
// gm-tls/src/gm.rs (已有 wrap 函数 connect_gm_rust_inner 被 metrics 包了一层)
pub async fn connect_gm_rust<S>(...) -> Result<GmTlsStream<S>, TlsError>
where S: AsyncRead + AsyncWrite + Unpin,
{
    let timeout_dur = opts.handshake_timeout;
    let fut = connect_gm_rust_inner(...);
    let result = if timeout_dur.is_zero() {
        fut.await
    } else {
        match tokio::time::timeout(timeout_dur, fut).await {
            Ok(r) => r,
            Err(_) => Err(TlsError::HandshakeFailed(format!(
                "handshake timeout after {}s",
                timeout_dur.as_secs()
            ))),
        }
    };
    record_handshake_error_code("client", match &result { Err(e) => e.code(), Ok(_) => ErrorCode::Ok });
    record_handshake_duration("client", start.elapsed());
    result
}
```

注意：超时路径返回的 `TlsError::HandshakeFailed`，其 `code()` 已经是 `ErrorCode::HandshakeFailed`（PR-4.18/4.22 已建），所以 metrics 自动被 PR-4.22 覆盖。

### 2.4 gRPC 集成

`gm-tls::grpc::GmTlsIncoming::with_max_concurrent` 和 `GmTlsConnector::call` 已经 wrap 了 `record_handshake_error_code`（PR-4.22）。这些外层入口不需要再额外 wrap timeout —— timeout 在更内层的 `connect_gm_rust`/`accept_gm_rust` 已经被施加。

### 2.5 TLCP 对等

deferred to PR-4.24 — see §0.

### 2.6 Backward Compatibility

- `HandshakeOptions::default()` 新字段 `handshake_timeout: Duration::from_secs(30)` —— 与老代码兼容（旧代码不读此字段，构建仍 OK）
- 默认 30s 是行为变化：**新版本比老版本更严格**。这是 fail-fast 的安全改进，老用户如果依赖无限等待可以显式 `with_handshake_timeout(Duration::ZERO)` 或 `Duration::from_secs(3600)`。

### 2.7 为什么不把 timeout 直接交给 TCP 层

- 用户可能用自己的 `TcpStream`（而非 `tokio::net::TcpStream`），TCP 层 timeout 配置不归本 crate 管
- 应用层 timeout 更精确 —— 只计时握手阶段，不计时已建链的应用数据
- 可观测性更好 —— 超时时能精确标记为 handshake_timeout 而不是普通的 `io::ErrorKind::TimedOut`

---

## 3. Test Plan

### 3.1 单元测试

```rust
#[cfg(test)]
mod pr423_handshake_timeout_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn default_handshake_options_has_30s_timeout() {
        let opts = HandshakeOptions::default();
        assert_eq!(opts.handshake_timeout, Duration::from_secs(30));
    }

    #[test]
    fn tls_config_with_handshake_timeout_zero_is_disabled() {
        let cfg = TlsConfig::from_bytes(vec![], vec![], vec![]).unwrap_err();  // empty bytes 报错无关本测试
        // 真实测试需要有效的 PEM，迁移到 interop
    }

    #[test]
    fn tls_config_with_handshake_timeout_propagates() {
        // requires dummy PEMs — better as integration test
    }
}
```

### 3.2 Loopback 集成测试（已有 `tests/loopback.rs`）

新增一个 `loopback_handshake_timeout` 测试：

```rust
#[tokio::test]
async fn loopback_handshake_timeout_triggers() {
    // 1. 准备 server + connector（短 timeout，比如 1s）
    // 2. server accept 在协程里等待
    // 3. connector 连接到 server
    // 4. 模拟 slowloris：写 ClientHello 头 1 字节后停顿 3s 再写余下
    // 5. server 应该在 ~1s 内返回 HandshakeFailed（"handshake timeout after 1s"）
}
```

实施需要 mock 流，或者用一个 tokio UnixStream + 半闭 pipe。最简单的方式：用 `tokio::io::duplex()` 构造一对，客户端侧正常发，server 侧用 `tokio::time::sleep` 慢读（不让 duplex buffer 推进）。

### 3.3 已有 loopback 测试不得破坏

确保 `loopback_sm2_basic`、`loopback_sm2_rfc8998`、`loopback_12_suites_*` 等 ~20 个现有 loopback 测试都通过（正常握手应该远小于 30s 默认 timeout）。

### 3.4 Metrics 接入检查

写一个简短的 integration：触发 timeout 后用 `metrics::with_local_recorder` 检查 counter `gmtls_handshake_errors_total{role="server",code="HandshakeFailed"}` 增加 1。

### 3.5 TLCP 对等测试

deferred to PR-4.24.

---

## 4. Rollout

1. SPEC 已写（本文件）
2. 本地 `cargo build --workspace` 必须先绿
3. 代码改动 → 本地 build 绿 → `cargo test -p gm-tls --tests` 绿
4. 跑 `cargo +nightly fmt` + `cargo clippy`
5. CI run 绿（github）
6. 推到 gitee + gitcode
7. 视 PR-4.22 结果决定是否双 crate 发布

---

## 5. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| 默认 30s 太短，HSM-backed 服务器超时 | 文档明确推荐 120s 用于 HSM 场景 |
| 默认 30s 太长，攻击者仍能拖 30s | 默认已经够短（业界典型）；用户可调更短 |
| `tokio::time::timeout` cancel 不彻底导致 socket leak | timeout 之后 inner future 仍然在跑；该协程持有 socket，所以 socket 直到 inner 完成才释放。但 inner 一旦在 read/write 上读到 `tokio::time::timeout` 的 cancellation 信号会立刻退出。Rust tokio 文档明确：timeout 取消 inner future 是 cooperative。`AsyncReadExt::read`/`AsyncWriteExt::write` 是 cancellation-safe，所以 OK。 |
| 测试 flaky（本地 timeout vs CI timeout 抖动） | 用足够大的 timeout（如 5s）给慢 CI 留 margin |
| gm-tlcp 之前无 `HandshakeOptions` 聚合，要新建 | 评估是否值得；如果 gm-tlcp 当前是单一 timeout 直接改 connector/acceptor，可绕过 |

---

## 6. Follow-up

- PR-4.24 candidate: gm-tlcp 如确无 `HandshakeOptions`，则同步建聚合结构
- PR-4.25 candidate: 加 `handshake_active_count` gauge（握手并发上限时再排队），让 operator 看得到握手队列深度
- PR-4.26 candidate: `metrics::histogram` for handshake_duration buckets（PR-4.10 已 record 但用 counter 而非 histogram，分位数无）

---

## 7. Out of Scope

- 不改 TCP keepalive / TCP_USER_TIMEOUT（应用层）
- 不改 TLS 1.3 record-layer 重传超时
- 不改 `SessionStoreConfig` 里已有逻辑
- 不引入新的依赖（只用 `tokio::time::timeout`，tokio 已是依赖）