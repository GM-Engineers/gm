//! TLCP 指标模块（Prometheus-compatible）。
//!
//! 使用 [`metrics`] 0.23 crate 作为底层，支持任意 Prometheus exporter
//! （例如 metrics-exporter-prometheus）或 OpenTelemetry exporter。
//!
//! # 当前指标 Current Metrics
//!
//! | 名称 Name | 类型 Type | 标签 Labels | 含义 Meaning |
//! |----------|----------|------------|--------------|
//! | `gmtlcp_handshakes_total` | counter | `role`, `result` | TLCP 握手总计数（success / error）(PR-4.26) |
//! | `gmtlcp_handshake_duration_seconds` | histogram | `role` | TLCP 握手耗时分布（秒）(PR-4.26) |
//! | `gmtlcp_bytes_transferred_total` | counter | `role`, `dir` | TLCP 加密流上的字节传输总量 |
//! | `gmtlcp_handshake_errors_total` | counter | `role`, `code` | TLCP 握手失败次数，按 `TlcpErrorCode` 切片（PR-4.22） |
//!
//! # 使用方法 Usage
//!
//! ```rust,ignore
//! // 1. 在应用启动时安装 Prometheus exporter
//! use metrics_exporter_prometheus::PrometheusBuilder;
//! PrometheusBuilder::new().install().expect("install prometheus exporter");
//!
//! // 2. 在应用启动时调用 describe_metrics() 注册指标元信息
//! use gm_tlcp::metrics::describe_metrics;
//! describe_metrics();
//!
//! // 3. 在应用代码中调用指标函数
//! use gm_tlcp::metrics::record_bytes;
//! record_bytes("server", "read", 1024);
//! ```
//!
//! # 与 gm-tls 指标的关系
//!
//! 本模块镜像 `gm_tls::metrics` 的语义：counter 与 histogram 的 metric
//! 名称前缀用 `gmtlcp_`（而不是 `gmtls_`），但 `role`/`result`/`code` 等
//! 标签集与 gm-tls **完全一致**，这样现有的 Grafana dashboard 可以**不加
//! 修改**地同时聚合 `gm-tls` 和 `gm-tlcp` 流量曲线（通过 metric name
//! 前缀区分两条曲线，标签集保持聚合兼容）。

use crate::error::TlcpErrorCode;
use metrics::{Unit, counter, describe_counter, describe_histogram, histogram};
use std::time::Instant;

/// PR-4.26: register metric descriptors. Call once at application
/// startup before any TLCP operations; mirrors
/// `gm_tls::metrics::describe_metrics` for the `gmtlcp_*` family.
pub fn describe_metrics() {
    describe_counter!(
        "gmtlcp_handshakes_total",
        Unit::Count,
        "Total number of completed TLCP handshakes (success and error)"
    );
    describe_histogram!(
        "gmtlcp_handshake_duration_seconds",
        Unit::Seconds,
        "Duration of TLCP handshakes in seconds"
    );
    describe_counter!(
        "gmtlcp_handshake_errors_total",
        Unit::Count,
        "Total TLCP handshake errors tagged by structured TlcpErrorCode"
    );
}

/// 记录通过 TLCP 流的字节传输量。
///
/// 在记录层加密/解密后调用，反映**明文**（应用层）字节数。
///
/// # 参数 Parameters
///
/// - `role` — 节点角色：`"server"` 或 `"client"`
/// - `direction` — 流量方向：`"read"`（接收）或 `"write"`（发送）
/// - `count` — 字节数（任意 usize）
///
/// # 示例 Example
///
/// ```rust
/// use gm_tlcp::metrics::record_bytes;
///
/// // 服务端接收到 1 KB 请求
/// record_bytes("server", "read", 1024);
///
/// // 客户端发送 512 字节响应
/// record_bytes("client", "write", 512);
/// ```
///
/// # Metric 输出格式
///
/// 在启用 Prometheus exporter 后，指标以如下格式暴露：
///
/// ```text
/// gmtlcp_bytes_transferred_total{role="server",dir="read"} 1024
/// gmtlcp_bytes_transferred_total{role="client",dir="write"} 512
/// ```
pub fn record_bytes(role: &str, direction: &str, count: usize) {
    let role = role.to_owned();
    let direction = direction.to_owned();
    counter!("gmtlcp_bytes_transferred_total", "role" => role, "dir" => direction)
        .increment(count as u64);
}

/// Records a TLCP handshake error tagged by structured [`TlcpErrorCode`] (PR-4.22).
///
/// Mirrors `gm_tls::metrics::record_handshake_error_code`. The `code`
/// label uses `TlcpErrorCode`'s `Debug` representation (e.g. `"Cipher"`,
/// `"HandshakeMessageParse"`, `"Sm2Key"`, `"CertificateVerificationFailed"`).
///
/// This metric is **independent** from any future
/// `gmtlcp_handshakes_total{result=success/error}` — the latter
/// counts each failed handshake once regardless of cause; the former
/// lets operators drill into the *cause*.
pub fn record_handshake_error_code(role: &str, code: TlcpErrorCode) {
    let role = role.to_owned();
    let code = format!("{code:?}");
    counter!("gmtlcp_handshake_errors_total", "role" => role, "code" => code).increment(1);
}

/// Scope guard for timing a TLCP handshake.
///
/// PR-4.26: mirrors `gm_tls::metrics::HandshakeTimer` (PR-4.25).
/// The timer starts at construction and **automatically records
/// on drop** with `result="error"` (the conservative default —
/// every handshake that did not explicitly call
/// [`HandshakeTimer::finish`] with `result="success"` counts as
/// an error in metrics).
///
/// Before PR-4.26, the caller had to invoke `timer.finish(...)`
/// **at every** control-flow exit point — including each `?`
/// early-return inside the handshake coroutine. Missing one
/// under-counted the handshake-error histogram and the
/// `gmtlcp_handshakes_total{result="error"}` counter. The RAII
/// form eliminates that whole class of bugs: any path that
/// leaves the timer's scope — panic, unwind, `?` early-return,
/// or simply forgetting to call `finish` — still produces a
/// single, idempotent `result="error"` record.
///
/// Explicit calls to [`HandshakeTimer::finish`] (with
/// `"success"` or `"error"`) continue to work and take
/// precedence over the drop default — the guard is idempotent
/// on the first record, regardless of which path wins.
pub struct HandshakeTimer {
    role: String,
    start: Instant,
    /// `None` means "no explicit `finish` has been called;
    /// Drop will record `result="error"`". `Some(label)`
    /// means an explicit `finish` already recorded with that
    /// label; Drop is a no-op.
    recorded: Option<String>,
}

impl HandshakeTimer {
    /// Start a handshake timer for `role` (typically
    /// `"client"` or `"server"`).
    pub fn new(role: &str) -> Self {
        Self {
            role: role.to_string(),
            start: Instant::now(),
            recorded: None,
        }
    }

    /// Mark this handshake as `result` (`"success"` or
    /// `"error"`). Subsequent drop will be a no-op
    /// (already recorded).
    pub fn finish(mut self, result: &str) {
        if self.recorded.is_some() {
            return;
        }
        self.recorded = Some(result.to_string());
        Self::record(&self.role, result, self.start.elapsed().as_secs_f64());
    }

    /// Emit the counter + histogram pair. Pulled out so
    /// [`HandshakeTimer::finish`] and `Drop` share one
    /// emission site.
    fn record(role: &str, result: &str, elapsed_secs: f64) {
        counter!(
            "gmtlcp_handshakes_total",
            "role" => role.to_string(),
            "result" => result.to_string()
        )
        .increment(1);
        histogram!(
            "gmtlcp_handshake_duration_seconds",
            "role" => role.to_string()
        )
        .record(elapsed_secs);
    }
}

impl Drop for HandshakeTimer {
    fn drop(&mut self) {
        // PR-4.26: if `finish()` was never called, record
        // the conservative outcome (`"error"`) so the
        // histogram / counter stay accurate even on `?`
        // early-returns, panics, or simply forgotten
        // manual cleanups.
        if self.recorded.is_some() {
            return;
        }
        let elapsed = self.start.elapsed().as_secs_f64();
        let result = "error".to_string();
        // Take the slot so re-drop (e.g. via panic during
        // record itself) is also idempotent.
        self.recorded = Some(result.clone());
        Self::record(&self.role, &result, elapsed);
    }
}

// ---------------------------------------------------------------------------
// PR-4.22 unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod pr422_record_handshake_error_code_tests {
    use super::*;
    use crate::error::{TlcpError, TlcpErrorCode};

    /// Verify `record_handshake_error_code` accepts every
    /// `TlcpErrorCode` variant without panicking. Operators rely on
    /// this metric being incremented for each variant; if a variant
    /// were rejected, the call site would panic at runtime — a
    /// regression we want to catch early.
    #[test]
    fn record_handshake_error_code_accepts_all_variants() {
        let variants = [
            TlcpErrorCode::HandshakeFailed,
            TlcpErrorCode::HandshakeMessageParse,
            TlcpErrorCode::Cipher,
            TlcpErrorCode::Sm2Key,
            TlcpErrorCode::CertificateVerificationFailed,
            TlcpErrorCode::SequenceOverflow,
            TlcpErrorCode::NonceReuse,
            TlcpErrorCode::InvalidHandshakeType,
            TlcpErrorCode::InvalidMessage,
            TlcpErrorCode::InvalidState,
            TlcpErrorCode::ParseError,
            TlcpErrorCode::TlsRecordError,
            TlcpErrorCode::IoError,
        ];
        for code in variants {
            record_handshake_error_code("client", code);
            record_handshake_error_code("server", code);
        }
    }

    /// Verify the `code` label uses Debug output (variant name only).
    #[test]
    fn code_label_is_debug_name_without_payload() {
        assert_eq!(format!("{:?}", TlcpErrorCode::Cipher), "Cipher");
        assert_eq!(
            format!("{:?}", TlcpErrorCode::HandshakeMessageParse),
            "HandshakeMessageParse"
        );
        assert_eq!(format!("{:?}", TlcpErrorCode::Sm2Key), "Sm2Key");
        assert_eq!(
            format!("{:?}", TlcpErrorCode::CertificateVerificationFailed),
            "CertificateVerificationFailed"
        );
    }

    /// `TlcpError::code()` must be invokable on every error variant
    /// so the call site `e.code()` does not panic at runtime.
    #[test]
    fn tlcp_error_code_is_total_for_common_variants() {
        let _ = TlcpError::HandshakeFailed("x".into()).code();
        let _ = TlcpError::CipherError("x".into()).code();
        let _ = TlcpError::HandshakeMessageParse("x".into()).code();
        let _ = TlcpError::Sm2KeyError("x".into()).code();
        let _ = TlcpError::CertificateVerificationFailed("x".into()).code();
        let _ = TlcpError::SequenceOverflow.code();
        let _ = TlcpError::NonceReuse.code();
    }

    /// The function is callable concurrently from multiple threads.
    /// The `metrics` facade is designed to be thread-safe via the
    /// global `Recorder`; this test catches accidental
    /// `!Send`/`!Sync` regressions.
    #[test]
    fn record_handshake_error_code_is_thread_safe() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        let success = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for i in 0..8 {
            let success = Arc::clone(&success);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    record_handshake_error_code(
                        if (i + j) % 2 == 0 { "client" } else { "server" },
                        TlcpErrorCode::Cipher,
                    );
                }
                success.fetch_add(1, Ordering::Relaxed);
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(success.load(Ordering::Relaxed), 8);
    }
}

// ---------------------------------------------------------------------------
// PR-4.26 unit tests: HandshakeTimer RAII guard
// ---------------------------------------------------------------------------
#[cfg(test)]
mod pr426_handshake_timer_raii_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// PR-4.26: dropping a HandshakeTimer without an
    /// explicit `finish()` call still produces exactly one
    /// emission. We can't easily inspect the Prometheus
    /// registry from a unit test, so this test guards the
    /// structural invariant that **no panic** leaks from
    /// Drop when the default `result="error"` path is
    /// taken.
    #[test]
    fn drop_without_finish_does_not_panic() {
        // Construct and immediately drop — the Drop impl
        // should record `result="error"` without complaint.
        drop(HandshakeTimer::new("client"));
        drop(HandshakeTimer::new("server"));
    }

    /// PR-4.26: explicitly calling `finish("success")` must
    /// not double-emit on drop. We exercise the path by
    /// finishing the timer (consuming `self`) and trusting
    /// that the compiler would reject a double-finish call.
    /// The complementary assertion is the unit-test for
    /// `record()` visibility — here we only check that the
    /// `finish()` API surface is still callable.
    #[test]
    fn finish_success_is_callable() {
        HandshakeTimer::new("client").finish("success");
        HandshakeTimer::new("server").finish("success");
    }

    /// PR-4.26: `finish("error")` is also still callable.
    #[test]
    fn finish_error_is_callable() {
        HandshakeTimer::new("client").finish("error");
        HandshakeTimer::new("server").finish("error");
    }

    /// PR-4.26: drop semantics under contention. Even
    /// though most handshakes run in async contexts, we
    /// sanity-check that 64 timers dropped in parallel do
    /// not deadlock or panic.
    #[test]
    fn drop_many_timers_concurrently() {
        let n = 64;
        let success = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let success = Arc::clone(&success);
            handles.push(std::thread::spawn(move || {
                drop(HandshakeTimer::new("client"));
                success.fetch_add(1, Ordering::Relaxed);
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(success.load(Ordering::Relaxed), n);
    }
}
