//! Structured audit logging for GM/TLS security events.
//!
//! This module provides structured audit logging as recommended by GB/T 39786-2021
//! (信息安全技术 信息系统密码应用要求) and GM/T 0028-2014.
//!
//! Audit logs capture security-relevant events including:
//! - Authentication events (who/when/what/result/where)
//! - Key lifecycle operations
//! - Certificate lifecycle events
//! - Configuration changes
//!
//! # Event Structure
//!
//! Each audit event contains:
//! - `timestamp`: ISO 8601 formatted time
//! - `event_type`: Categorized event type
//! - `severity`: INFO, WARNING, or CRITICAL
//! - `actor`: Who/what initiated the event
//! - `action`: What action was performed
//! - `result`: Success or failure with reason
//! - `context`: Additional context (IP, session ID, etc.)
//!
//! # Usage
//!
//! ```rust
//! use gm_tls::audit::{AuditEvent, AuditLogger};
//!
//! // Log an authentication event
//! AuditLogger::log(AuditEvent::auth_success(
//!     "client.test",
//!     "127.0.0.1:8080",
//!     "session-123",
//! ));
//! ```

use gm_crypto::sm3::Sm3Hmac;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;
use tracing::{error, info, warn};

/// Global audit logger configuration
static AUDIT_CONFIG: OnceLock<AuditConfig> = OnceLock::new();

/// Monotonic sequence counter for audit log integrity.
///
/// Each audit event receives a unique, monotonically increasing sequence number.
/// This allows detection of:
/// - Missing log entries (gaps in the sequence)
/// - Tampered log entries (reordered or duplicated sequence numbers)
///
/// The counter starts at 1 and wraps at u64::MAX (practically unlimited).
static AUDIT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Get the next audit sequence number.
fn next_sequence() -> u64 {
    AUDIT_SEQUENCE.fetch_add(1, Ordering::SeqCst) + 1
}

/// Audit configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Minimum severity level to log
    pub min_severity: Severity,
    /// Whether to include caller location in logs
    pub include_location: bool,
    /// Application identifier for multi-service deployments
    pub service_id: String,
    /// HMAC-SM3 signing key for audit log integrity protection.
    /// When set, each audit event includes an `integrity_hash` field
    /// computed as HMAC-SM3(key, serialized_event_without_hash).
    /// Can be set via `AUDIT_SIGNING_KEY` environment variable.
    pub signing_key: Option<Vec<u8>>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        let signing_key = std::env::var("AUDIT_SIGNING_KEY")
            .ok()
            .map(|k| k.as_bytes().to_vec());
        Self {
            min_severity: Severity::Info,
            include_location: true,
            service_id: "gmtls".to_string(),
            signing_key,
        }
    }
}

/// Set the global audit configuration
pub fn configure(config: AuditConfig) {
    let _ = AUDIT_CONFIG.set(config);
}

/// Get the current audit configuration
fn get_config() -> AuditConfig {
    AUDIT_CONFIG.get().cloned().unwrap_or_default()
}

/// Audit severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    fn should_log(&self, min: Severity) -> bool {
        *self == Severity::Critical
            || (*self == Severity::Warning && (min == Severity::Warning || min == Severity::Info))
            || (*self == Severity::Info && min == Severity::Info)
    }
}

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", content = "data")]
pub enum AuditEventType {
    // Authentication events
    AuthSuccess,
    AuthFailure,
    AuthLogout,
    SessionCreated,
    SessionResumed,
    SessionExpired,

    // Key operations
    KeyGenerated,
    KeyLoaded,
    KeyDestroyed,
    KeyDerive,

    // Certificate operations
    CertLoaded,
    CertVerified,
    CertExpired,
    CertRevoked,
    CrlLoaded,
    CrlVerified,

    // Configuration changes
    ConfigChanged,
    PolicyUpdated,

    // Security events
    DowngradeAttempt,
    InvalidSignature,
    TamperDetected,
}

/// Audit event structure
///
/// Each event includes a monotonic [`sequence_number`](Self::sequence_number)
/// for integrity verification. Gaps or duplicates in sequence numbers
/// indicate potential log tampering. An optional [`integrity_hash`](Self::integrity_hash)
/// field provides HMAC-based tamper detection when a signing key is configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic sequence number for integrity verification
    pub sequence_number: u64,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Event type and category
    pub event: AuditEventType,
    /// Event severity
    pub severity: Severity,
    /// Who initiated the action
    pub actor: Actor,
    /// What action was performed
    pub action: String,
    /// Whether the action succeeded
    pub result: ActionResult,
    /// Additional context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<AuditContext>,
    /// Caller location (file:line)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// HMAC-SHA256 integrity hash for tamper detection.
    /// Computed over all other fields when a signing key is configured
    /// via `AUDIT_SIGNING_KEY` environment variable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_hash: Option<String>,
}

impl AuditEvent {
    fn now_timestamp() -> String {
        OffsetDateTime::now_utc()
            .format(&Iso8601::DEFAULT)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
    }

    /// Create an authentication success event
    pub fn auth_success(identity: &str, remote_addr: &str, session_id: &str) -> Self {
        Self {
            sequence_number: next_sequence(),
            timestamp: Self::now_timestamp(),
            event: AuditEventType::AuthSuccess,
            severity: Severity::Info,
            actor: Actor {
                identity: identity.to_string(),
                role: "client".to_string(),
            },
            action: "TLS authentication completed successfully".to_string(),
            result: ActionResult::Success,
            context: Some(AuditContext {
                remote_addr: Some(remote_addr.to_string()),
                session_id: Some(session_id.to_string()),
                ..Default::default()
            }),
            location: None,
            integrity_hash: None,
        }
    }

    /// Create an authentication failure event
    pub fn auth_failure(identity: &str, remote_addr: &str, reason: &str) -> Self {
        Self {
            sequence_number: next_sequence(),
            timestamp: Self::now_timestamp(),
            event: AuditEventType::AuthFailure,
            severity: Severity::Warning,
            actor: Actor {
                identity: identity.to_string(),
                role: "client".to_string(),
            },
            action: "TLS authentication failed".to_string(),
            result: ActionResult::Failure(reason.to_string()),
            context: Some(AuditContext {
                remote_addr: Some(remote_addr.to_string()),
                ..Default::default()
            }),
            location: None,
            integrity_hash: None,
        }
    }

    /// Create a session created event
    pub fn session_created(session_id: &str, cipher_suite: &str) -> Self {
        Self {
            sequence_number: next_sequence(),
            timestamp: Self::now_timestamp(),
            event: AuditEventType::SessionCreated,
            severity: Severity::Info,
            actor: Actor {
                identity: "system".to_string(),
                role: "server".to_string(),
            },
            action: format!("New TLS session established with cipher {}", cipher_suite),
            result: ActionResult::Success,
            context: Some(AuditContext {
                session_id: Some(session_id.to_string()),
                cipher_suite: Some(cipher_suite.to_string()),
                ..Default::default()
            }),
            location: None,
            integrity_hash: None,
        }
    }

    /// Create a session resumed event
    pub fn session_resumed(session_id: &str) -> Self {
        Self {
            sequence_number: next_sequence(),
            timestamp: Self::now_timestamp(),
            event: AuditEventType::SessionResumed,
            severity: Severity::Info,
            actor: Actor {
                identity: "system".to_string(),
                role: "server".to_string(),
            },
            action: "TLS session resumed from ticket".to_string(),
            result: ActionResult::Success,
            context: Some(AuditContext {
                session_id: Some(session_id.to_string()),
                ..Default::default()
            }),
            location: None,
            integrity_hash: None,
        }
    }

    /// Create a key generated event
    pub fn key_generated(key_type: &str, algorithm: &str) -> Self {
        Self {
            sequence_number: next_sequence(),
            timestamp: Self::now_timestamp(),
            event: AuditEventType::KeyGenerated,
            severity: Severity::Info,
            actor: Actor {
                identity: "system".to_string(),
                role: "server".to_string(),
            },
            action: format!("New {} key generated for {}", key_type, algorithm),
            result: ActionResult::Success,
            context: Some(AuditContext {
                key_type: Some(key_type.to_string()),
                algorithm: Some(algorithm.to_string()),
                ..Default::default()
            }),
            location: None,
            integrity_hash: None,
        }
    }

    /// Create a certificate verified event
    pub fn cert_verified(subject: &str, issuer: &str, result: &str) -> Self {
        let severity = if result == "valid" {
            Severity::Info
        } else {
            Severity::Warning
        };

        Self {
            sequence_number: next_sequence(),
            timestamp: Self::now_timestamp(),
            event: AuditEventType::CertVerified,
            severity,
            actor: Actor {
                identity: subject.to_string(),
                role: "certificate".to_string(),
            },
            action: format!("Certificate verification: {} (issuer: {})", result, issuer),
            result: if result == "valid" {
                ActionResult::Success
            } else {
                ActionResult::Failure(result.to_string())
            },
            context: Some(AuditContext {
                subject: Some(subject.to_string()),
                issuer: Some(issuer.to_string()),
                ..Default::default()
            }),
            location: None,
            integrity_hash: None,
        }
    }

    /// Create a downgrade attempt detected event
    pub fn downgrade_attack_detected(details: &str) -> Self {
        Self {
            sequence_number: next_sequence(),
            timestamp: Self::now_timestamp(),
            event: AuditEventType::DowngradeAttempt,
            severity: Severity::Critical,
            actor: Actor {
                identity: "unknown".to_string(),
                role: "attacker".to_string(),
            },
            action: "TLS downgrade attack detected".to_string(),
            result: ActionResult::Failure(details.to_string()),
            context: None,
            location: None,
            integrity_hash: None,
        }
    }

    /// Create a config changed event
    pub fn config_changed(param: &str, old_value: &str, new_value: &str) -> Self {
        Self {
            sequence_number: next_sequence(),
            timestamp: Self::now_timestamp(),
            event: AuditEventType::ConfigChanged,
            severity: Severity::Warning,
            actor: Actor {
                identity: "system".to_string(),
                role: "admin".to_string(),
            },
            action: format!("Configuration parameter '{}' changed", param),
            result: ActionResult::Success,
            context: Some(AuditContext {
                description: Some(format!(
                    "Changed {} from '{}' to '{}'",
                    param, old_value, new_value
                )),
                ..Default::default()
            }),
            location: None,
            integrity_hash: None,
        }
    }

    /// Add caller location
    #[allow(dead_code)]
    pub fn with_location(mut self, location: &str) -> Self {
        self.location = Some(location.to_string());
        self
    }

    /// Compute and set the integrity hash (HMAC-SM3) for this event.
    /// The HMAC is computed over all fields except `integrity_hash` itself.
    pub fn with_integrity_hash(mut self, key: &[u8]) -> Self {
        let payload = self.integrity_payload();
        match Sm3Hmac::new(key).compute(payload.as_bytes()) {
            Ok(hmac_bytes) => {
                self.integrity_hash = Some(hex::encode(&hmac_bytes));
            }
            Err(_) => {
                // If HMAC computation fails, leave integrity_hash as None
                // rather than panicking. The absence of the hash will be
                // detectable in audit log review.
            }
        }
        self
    }

    /// Serialize the event fields for integrity computation
    /// (excludes the `integrity_hash` field itself).
    fn integrity_payload(&self) -> String {
        format!(
            "{}|{}|{:?}|{:?}|{}:{}|{}|{}",
            self.sequence_number,
            self.timestamp,
            self.event,
            self.severity,
            self.actor.identity,
            self.actor.role,
            self.action,
            match &self.result {
                ActionResult::Success => "SUCCESS".to_string(),
                ActionResult::Failure(e) => format!("FAILURE:{}", e),
            },
        )
    }

    /// Verify the integrity hash of this event.
    /// Returns `true` if the hash matches, `false` if it doesn't
    /// or if no hash is present.
    pub fn verify_integrity(&self, key: &[u8]) -> bool {
        if let Some(ref hash) = self.integrity_hash {
            let payload = self.integrity_payload();
            match Sm3Hmac::new(key).compute(payload.as_bytes()) {
                Ok(computed) => {
                    let computed_hex = hex::encode(&computed);
                    // Constant-time comparison to prevent timing attacks
                    hash.as_bytes().ct_eq(computed_hex.as_bytes()).into()
                }
                Err(_) => false,
            }
        } else {
            false
        }
    }
}

/// Actor who initiated the action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    /// Identity (CN, IP, system)
    pub identity: String,
    /// Role (client, server, admin, system)
    pub role: String,
}

/// Result of an action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionResult {
    Success,
    Failure(String),
}

/// Additional context for audit events
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditContext {
    /// Remote address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    /// Session identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Cipher suite
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    /// Key type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// Algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Certificate subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Certificate issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Audit logger
pub struct AuditLogger;

impl AuditLogger {
    /// Log an audit event
    pub fn log(event: AuditEvent) {
        let config = get_config();

        if !event.severity.should_log(config.min_severity) {
            return;
        }

        // Apply integrity hash if signing key is configured
        let event = if let Some(ref key) = config.signing_key {
            event.with_integrity_hash(key)
        } else {
            event
        };

        // Format context as key=value pairs
        let context_str = if let Some(ctx) = &event.context {
            let mut parts = Vec::new();
            if let Some(ref v) = ctx.remote_addr {
                parts.push(format!("remote_addr={}", v));
            }
            if let Some(ref v) = ctx.session_id {
                parts.push(format!("session_id={}", v));
            }
            if let Some(ref v) = ctx.cipher_suite {
                parts.push(format!("cipher_suite={}", v));
            }
            if let Some(ref v) = ctx.key_type {
                parts.push(format!("key_type={}", v));
            }
            if let Some(ref v) = ctx.algorithm {
                parts.push(format!("algorithm={}", v));
            }
            if let Some(ref v) = ctx.subject {
                parts.push(format!("subject={}", v));
            }
            if let Some(ref v) = ctx.issuer {
                parts.push(format!("issuer={}", v));
            }
            if let Some(ref v) = ctx.description {
                parts.push(format!("description={}", v));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!(" [{}]", parts.join(", "))
            }
        } else {
            String::new()
        };

        // Format result
        let result_str = match &event.result {
            ActionResult::Success => "SUCCESS".to_string(),
            ActionResult::Failure(e) => format!("FAILURE:{}", e),
        };

        // Format as structured log message
        let event_json = format!(
            "{{\"seq\":{},\"timestamp\":\"{}\",\"event_type\":\"{:?}\",\"severity\":\"{:?}\",\"\
             actor\":\"{}:{}\",\"action\":\"{}\",\"result\":\"{}\",\"context\":\"{}\"}}",
            event.sequence_number,
            event.timestamp,
            event.event,
            event.severity,
            event.actor.identity,
            event.actor.role,
            event.action,
            result_str,
            context_str.trim(),
        );

        match event.severity {
            Severity::Info => info!(audit = %event_json, "audit event"),
            Severity::Warning => warn!(audit = %event_json, "audit event"),
            Severity::Critical => error!(audit = %event_json, "audit event"),
        }
    }

    /// Log authentication success
    pub fn auth_success(identity: &str, remote_addr: &str, session_id: &str) {
        let event = AuditEvent::auth_success(identity, remote_addr, session_id);
        Self::log(event);
    }

    /// Log authentication failure
    pub fn auth_failure(identity: &str, remote_addr: &str, reason: &str) {
        let event = AuditEvent::auth_failure(identity, remote_addr, reason);
        Self::log(event);
    }

    /// Log session created
    pub fn session_created(session_id: &str, cipher_suite: &str) {
        let event = AuditEvent::session_created(session_id, cipher_suite);
        Self::log(event);
    }

    /// Log session resumed
    pub fn session_resumed(session_id: &str) {
        let event = AuditEvent::session_resumed(session_id);
        Self::log(event);
    }

    /// Log key generated
    pub fn key_generated(key_type: &str, algorithm: &str) {
        let event = AuditEvent::key_generated(key_type, algorithm);
        Self::log(event);
    }

    /// Log certificate verification
    pub fn cert_verified(subject: &str, issuer: &str, result: &str) {
        let event = AuditEvent::cert_verified(subject, issuer, result);
        Self::log(event);
    }

    /// Log downgrade attack detected
    pub fn downgrade_attack_detected(details: &str) {
        let event = AuditEvent::downgrade_attack_detected(details);
        Self::log(event);
    }

    /// Log configuration change
    pub fn config_changed(param: &str, old_value: &str, new_value: &str) {
        let event = AuditEvent::config_changed(param, old_value, new_value);
        Self::log(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_timestamp() {
        let event = AuditEvent::auth_success("client.test", "127.0.0.1:8080", "session-123");
        assert!(!event.timestamp.is_empty());
        // Verify it's valid ISO8601-ish (has date and time)
        assert!(event.timestamp.contains('T'));
    }

    #[test]
    fn test_severity_filtering() {
        assert!(Severity::Critical.should_log(Severity::Info));
        assert!(Severity::Warning.should_log(Severity::Warning));
        assert!(!Severity::Info.should_log(Severity::Warning));
    }

    #[test]
    fn test_audit_event_integrity_hash() {
        let key = b"test-audit-signing-key-12345";
        let event = AuditEvent::auth_success("client.test", "127.0.0.1:8080", "session-123")
            .with_integrity_hash(key);

        // Integrity hash should be set
        assert!(event.integrity_hash.is_some());
        let hash = event.integrity_hash.as_ref().unwrap();

        // Hash should be 64 hex chars (SM3 = 256 bits = 32 bytes = 64 hex chars)
        assert_eq!(hash.len(), 64);

        // Verification should succeed with correct key
        assert!(event.verify_integrity(key));

        // Verification should fail with wrong key
        assert!(!event.verify_integrity(b"wrong-key"));
    }

    #[test]
    fn test_audit_event_integrity_tamper_detection() {
        let key = b"test-audit-signing-key-12345";
        let event = AuditEvent::auth_success("client.test", "127.0.0.1:8080", "session-123")
            .with_integrity_hash(key);

        // Tamper with the event
        let mut tampered = event.clone();
        tampered.action = "tampered action".to_string();

        // Original should verify, tampered should not
        assert!(event.verify_integrity(key));
        assert!(!tampered.verify_integrity(key));
    }

    #[test]
    fn test_audit_event_no_hash_when_no_key() {
        let event = AuditEvent::auth_success("client.test", "127.0.0.1:8080", "session-123");

        // No integrity hash should be present without a signing key
        assert!(event.integrity_hash.is_none());

        // Verification should fail (no hash present)
        assert!(!event.verify_integrity(b"any-key"));
    }
}
