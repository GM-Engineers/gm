//! TLCP 指标模块（Prometheus-compatible）。
//!
//! 使用 [`metrics`] 0.23 crate 作为底层，支持任意 Prometheus exporter
//! （例如 metrics-exporter-prometheus）或 OpenTelemetry exporter。
//!
//! # 当前指标 Current Metrics
//!
//! | 名称 Name | 类型 Type | 标签 Labels | 含义 Meaning |
//! |----------|----------|------------|--------------|
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
//! // 2. 在应用代码中调用指标函数
//! use gm_tlcp::metrics::record_bytes;
//! record_bytes("server", "read", 1024);
//! ```
//!
//! # 与 gm-tls 指标的关系
//!
//! 本模块镜像 `gm_tls::metrics::record_bytes` 的语义（同样的 metric name 和标签），
//! 这样现有的监控面板（如 Grafana dashboard）可以**不加修改**地同时聚合
//! `gm-tls` 和 `gm-tlcp` 流量。

use crate::error::TlcpErrorCode;
use metrics::counter;

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
