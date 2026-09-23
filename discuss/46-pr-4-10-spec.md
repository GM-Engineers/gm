# SPEC: PR-4.10 — gm-tls 握手失败 metrics 计数器 (P2-3)

- **目标编号**：PR-4.10（Batch 4 — gm-tls 工程完善）
- **触发**：[`gm与gm-kms源码级改进建议.md §四 P2-3`](file:///Users/laozhang/Downloads/gm与gm-kms源码级改进建议.md#L147)：握手失败仅 `tracing::warn` 无 metrics，建议加计数器/告警
- **范围**：`gm-tls/src/grpc.rs` 在握手失败 / 成功处调用已有 `record_handshake` counter
- **影响面**：纯增量；现有 `tracing::warn!` 保留为调试日志；gm.rs 已有路径（PR-4.10 不重复）

---

## 1. 问题陈述

`gm-tls/src/grpc.rs:184-192` 的服务端握手失败分支：

```rust
Err(e) => {
    tracing::warn!(
        "GM/TLS handshake failed from {:?}: {}",
        remote_addr, e
    );
    None
}
```

`gm-tls/src/grpc.rs:322-326` 的客户端握手失败分支：

```rust
let tls_stream = connector.connect(tcp).await.map_err(|e| {
    Box::new(std::io::Error::other(format!(
        "GM/TLS handshake failed: {}", e
    )))
})?;
```

后果：
- **无 metric 计数**：运维只能 log scrape，告警系统拿不到 Prometheus / OTLP 指标
- **`gmtls_handshakes_total{result="error"}` 现有 schema 但调用方不全**：`gm.rs::connect_gm_rust` / `accept_gm_rust` 走 HandshakeTimer，但 tonic 集成层的 grpc.rs 失败路径**没**调用
- 服务端**成功**握手也没记录 — `result="success"` 永远是 0，告警永远红

### 1.1 改进建议依据（master plan §四 P2-3）

> `gm-tls/src/grpc.rs:170-178` | 握手失败仅 `tracing::warn` 无 metrics，建议加计数器/告警（与 gm-tls metrics 模块打通）

---

## 2. Fix 策略

### 2.1 现有 metrics 复用

`gm-tls/src/metrics.rs` 已定义 `gmtls_handshakes_total{role, result}` counter（line 32-35，line 59-65）。PR-4.10 不引入新 counter —— 现有 schema 已可表达：

- 服务端成功：`counter("gmtls_handshakes_total", role="server", result="success").increment(1)`
- 服务端失败：`counter("gmtls_handshakes_total", role="server", result="error").increment(1)`
- 客户端成功：`counter("gmtls_handshakes_total", role="client", result="success").increment(1)`
- 客户端失败：`counter("gmtls_handshakes_total", role="client", result="error").increment(1)`

### 2.2 grpc.rs 接入

**服务端** (`GmTlsIncoming::new` 内的 `filter_map` 闭包)：

```rust
let timer = HandshakeTimer::new("server");  // 移到 filter_map 闭包外？
match acceptor.accept(tcp).await {
    Ok(stream) => {
        timer.finish("success");
        Some(Ok(GmServerIo { stream, connect_info: ... }))
    }
    Err(e) => {
        tracing::warn!("GM/TLS handshake failed from {:?}: {}", remote_addr, e);
        timer.finish("error");  // PR-4.10
        None
    }
}
```

> `HandshakeTimer::finish` 调用 `record_handshake` 已经存在（metrics.rs line 101）。无需新增 API。

**客户端** (`GmTlsConnector::call`)：

```rust
let timer = HandshakeTimer::new("client");
let tls_stream = match connector.connect(tcp).await {
    Ok(s) => {
        timer.finish("success");
        Ok(s)
    }
    Err(e) => {
        timer.finish("error");  // PR-4.10
        Err(Box::new(std::io::Error::other(format!(
            "GM/TLS handshake failed: {}", e
        ))) as Box<dyn std::error::Error + Send + Sync>)
    }
}?;
```

### 2.3 `tracing::warn!` 保留

现有 `tracing::warn!` **保留**作为调试日志；metrics 计数器只服务于 Prometheus/OTLP 导出。两者职责分明：
- 日志：人工 oncall 看，结构化，附 trace context
- 指标：自动告警系统消费，无 trace context，按 label 聚合

### 2.4 接入点不破坏现有 contract

- `GmTlsIncoming::new(listener, acceptor)`：签名不变；闭包内 timer 加在现有 `filter_map` 里
- `GmTlsConnector::call(uri)`：签名不变；timer 加在 `Box::pin(async move { ... })` 内
- gm.rs / gm-tlcp / gm-ca 等所有 caller 看到的 tonic service trait 不变
- `metrics` crate 已是 gm-tls 依赖（metrics.rs 引用），无需新增 dep

### 2.5 版本

`gm-tls/Cargo.toml`：**patch bump**（仅调用已有 API；现有 caller 行为不变）。

---

## 3. Tests（`gm-tls/src/grpc.rs::pr410_handshake_metrics_tests`）

`metrics` crate 提供 `testing::set_global_recorder` 安装 in-memory recorder，可以直接断言 counter value。

| # | 名称 | 场景 |
| --- | --- | --- |
| T1 | `pr410_server_handshake_success_records_metric` | 安装 `MockRecorder`；构造 `GmTlsIncoming`；用 fake stream 走通 handshake；断言 `gmtls_handshakes_total{role="server", result="success"} >= 1` |
| T2 | `pr410_server_handshake_failure_records_metric` | 用 bad cert 导致 handshake 失败；断言 `gmtls_handshakes_total{role="server", result="error"} >= 1` |
| T3 | `pr410_client_handshake_failure_records_metric` | 构造 `GmTlsConnector`；URI 指向未绑定端口；await 失败；断言 `gmtls_handshakes_total{role="client", result="error"} >= 1` |
| T4 | `pr410_client_handshake_success_records_metric` | end-to-end loopback：bind `127.0.0.1:0`；connector 发起 handshake；断言 `result="success" >= 1` |

注：T1/T2 需要 listener + cert fixture，参考已有的 `gmssl_interop_tests.rs::ensure_test_certs`。
T3/T4 同上。

---

## 4. 验证矩阵（stable 1.88 + nightly）

```
cargo +1.88 fmt --all -- --check
cargo +nightly clippy -p gm-tls --all-targets -- -D warnings
cargo +1.88 test -p gm-tls --all-targets pr410_
cargo +1.88 test -p gm-tls --all-targets    # 全量回归
```

CI 含 GmSSL Interop / TLCP Interop（确认 metrics 改动不破坏 interop 测试）。

---

## 5. 风险与缓解

| 风险 | 缓解 |
| --- | --- |
| 引入 metrics crate 版本冲突 | metrics crate 已被 gm-tls 依赖（gm-tls/src/metrics.rs），无新 dep |
| `MockRecorder` 在多线程下竞争 | `metrics::with_local_recorder` 提供 per-thread scope；测试用 `with_local_recorder` 包裹 |
| `tracing::warn!` 现在 metric 同步发出，可能影响日志采样决策 | `tracing::warn!` 等级不变；metric 走 metrics facade，独立通道 |
| `gmtls_handshakes_total{result="error"}` 现有 schema 不含 reason label | P2-3 现有 schema 已够区分 success/error；详细 reason 由 `tracing` 提供 |

---

## 6. Out of Scope（不在本 PR 范围）

- `gmtls_handshake_failure_reasons_total{reason=...}` 新 counter（详情）
- `metrics-exporter-prometheus` integration（应用层选择）
- 任何 grpc.rs 之外的 caller（gm.rs 已覆盖）

---

## 7. 后续 PR 候选

- **PR-4.11**：gm-tls CRL grace period + session cache persistence
- **PR-4.12**：gm-kms WORM logger HMAC key 独立路径 (P2-6)
- **PR-4.13**：gm-ca rate limit per-caller (P2-7)
- **PR-4.14**：gm-crypto SM2 private key [1, n-1] 范围校验 (P2-9)
