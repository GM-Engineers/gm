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
