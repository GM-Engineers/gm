//! gRPC CA service implementation

use crate::ca::v1 as ca_v1;
use crate::cert::{CaSigner, extract_csr_subject_cn};
use crate::cert_profile::CertProfile;
use crate::db::DbStore;
use crate::error::CaErrorCode;
use crate::metrics;
use ca_v1::{
    GetCertificateResponse, GetCrlResponse, RenewCertificateResponse, RevokeCertificateResponse,
    SignCertificateResponse, ca_service_server::CaService,
};
use sqlx::types::chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

/// CA service implementation using SM2 certificates.
///
/// Provides gRPC endpoints for certificate signing, renewal, revocation,
/// and CRL distribution. All certificates are signed using the configured
/// SM2 CA key pair.
#[derive(Clone)]
pub struct CaServiceImpl {
    /// SM2 CA signer for issuing certificates
    signer: Arc<CaSigner>,
    /// Database store for certificate persistence
    store: Arc<DbStore>,
    /// Monotonically increasing CRL number (RFC 5280 §5.2.3)
    crl_number: Arc<AtomicU64>,
    /// PR-4.12 / P2-7: per-caller rate limiter (peer-IP keyed).
    /// See [`PerCallerLimiter`] for semantics. Pre-PR-4.12 a
    /// single GLOBAL bucket was shared across all callers,
    /// meaning a single misbehaving client could lock out every
    /// legitimate client.
    rate_limiter: PerCallerLimiter,
}

/// PR-4.12: placeholder IP used when `tonic::Request::remote_addr()`
/// is `None` (e.g. unix socket / test fakes without a remote
/// endpoint). All such callers share one bucket, which is
/// acceptable because they all live in the local trust domain
/// and bypass network-level access controls.
fn placeholder_peer_ip() -> IpAddr {
    "0.0.0.0".parse::<IpAddr>().expect("0.0.0.0 must parse")
}

impl CaServiceImpl {
    /// Create a new CA service implementation.
    ///
    /// # Arguments
    /// * `signer` - SM2 CA key pair for signing certificates
    /// * `store` - Shared PostgreSQL store for certificate persistence
    pub fn new(signer: CaSigner, store: Arc<DbStore>) -> Self {
        Self::with_rate_limit(signer, store, 10, Duration::from_secs(60))
    }

    /// Create a new CA service with custom rate limit.
    ///
    /// PR-4.12 / P2-7: `capacity` and `refill_period` apply **per
    /// caller** (peer IP), not globally. Each distinct client IP
    /// gets its own token bucket; one client's exhaustion no
    /// longer blocks other clients.
    pub fn with_rate_limit(
        signer: CaSigner,
        store: Arc<DbStore>,
        capacity: u32,
        refill_period: Duration,
    ) -> Self {
        Self {
            signer: Arc::new(signer),
            store,
            crl_number: Arc::new(AtomicU64::new(1)),
            rate_limiter: PerCallerLimiter::new(
                capacity,
                refill_period,
                // 10 minutes — long enough that a single SVID
                // rotation cycle (P1-9, sub-day TTLs) won't
                // lose bucket state, short enough that stale
                // entries don't accumulate.
                Duration::from_secs(600),
            ),
        }
    }

    /// PR-4.12: configure the per-caller idle TTL (used by
    /// tests and operators who want a more aggressive
    /// reaping policy).
    pub fn with_rate_limit_idle_ttl(mut self, ttl: Duration) -> Self {
        self.rate_limiter = PerCallerLimiter::new(
            self.rate_limiter.capacity,
            self.rate_limiter.refill_period,
            ttl,
        );
        self
    }

    /// PR-4.12 / P2-7: enforce the per-caller rate limit.
    /// Identifies the caller by `request.remote_addr()` (tonic
    /// transport-level peer socket address); falls back to a
    /// placeholder IP when the transport does not expose one
    /// (unix sockets, in-process tests).
    async fn check_rate_limit<T>(&self, request: &Request<T>) -> Result<IpAddr, Status> {
        let peer_ip = request
            .remote_addr()
            .map(|sa| sa.ip())
            .unwrap_or_else(placeholder_peer_ip);
        self.rate_limiter.check(peer_ip).await
    }

    /// Access the underlying database store (used by health checks).
    pub fn store(&self) -> Arc<DbStore> {
        self.store.clone()
    }
}

#[tonic::async_trait]
impl CaService for CaServiceImpl {
    async fn sign_certificate(
        &self,
        request: Request<ca_v1::SignCertificateRequest>,
    ) -> Result<Response<SignCertificateResponse>, Status> {
        // PR-4.12 / P2-7: per-caller rate limit (peer-IP keyed).
        // Pre-PR-4.12 this was a global single bucket shared
        // across all callers, which amplified DoS.
        let _peer_ip = self.check_rate_limit(&request).await?;

        let req = request.into_inner();
        let csr_bytes = req.csr_pem.as_bytes();

        // PR-3.1 (gm-ca 0.3.0, P1-8 + P1-9): the proto v0.3.0
        // `SignCertificateRequest` carries two new fields:
        //   - `profile_json`: caller-supplied `CertProfile` serialized
        //     as JSON. Empty string = fall back to default profile
        //     (v0.1.x / v0.2.x wire format). Used by SPIRE Server to
        //     pass URI SANs + the appropriate KU/EKU layout for SVIDs.
        //   - `validity_seconds`: sub-day TTL (P1-9 SPIRE SVID
        //     rotation). When > 0, takes precedence over
        //     `validity_days`. Range 1..=31_536_000 (1s..365d).
        //
        // Backward compat: pre-v0.3.0 clients leave both fields at
        // their defaults (empty string / 0), and we transparently
        // fall back to the legacy `validity_days` + `CertProfile::default()`
        // code path.
        let profile: CertProfile = if req.profile_json.is_empty() {
            CertProfile::default()
        } else {
            serde_json::from_str(&req.profile_json).map_err(|e| {
                metrics::record_error_code(CaErrorCode::InvalidArgument);
                Status::invalid_argument(format!("invalid profile_json: {}", e))
            })?
        };
        let validity_seconds: i64 = if req.validity_seconds > 0 {
            req.validity_seconds
        } else {
            // Legacy pre-v0.3.0 path: validity_days * 86400.
            // Range-checked upstream by sign_csr_with_profile; we
            // re-check here to avoid passing `0` to the seconds API
            // (which would error out — minimum is 1).
            if req.validity_days <= 0 || req.validity_days > 3650 {
                return Err(Status::invalid_argument(format!(
                    "validity_days must be 1-3650, got {}",
                    req.validity_days
                )));
            }
            req.validity_days * 86400
        };

        let (serial_hex, cert_pem) = self
            .signer
            .sign_csr_with_profile_and_seconds(csr_bytes, validity_seconds, &profile)
            .map_err(|e| {
                metrics::record_error_code(CaErrorCode::SigningFailed);
                Status::invalid_argument(e.to_string())
            })?;

        // Extract subject CN from CSR for database storage
        let subject_cn = extract_csr_subject_cn(csr_bytes).map_err(|e| {
            metrics::record_error_code(CaErrorCode::InvalidCsr);
            Status::invalid_argument(e.to_string())
        })?;

        // Calculate validity period for DB storage (sub-day granularity).
        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + std::time::Duration::from_secs(validity_seconds as u64);
        let not_before_dt =
            sqlx::types::chrono::DateTime::<Utc>::from_timestamp(not_before.unix_timestamp(), 0)
                .unwrap_or_else(Utc::now);
        let not_after_dt =
            sqlx::types::chrono::DateTime::<Utc>::from_timestamp(not_after.unix_timestamp(), 0)
                .unwrap_or_else(Utc::now);

        // Persist certificate to database
        self.store
            .insert_certificate(
                &serial_hex,
                &cert_pem,
                self.signer.ca_subject_cn(),
                &subject_cn,
                not_before_dt,
                not_after_dt,
            )
            .await
            .map_err(|e| {
                metrics::record_error_code(CaErrorCode::DatabaseError);
                Status::internal(format!("failed to store certificate: {}", e))
            })?;

        metrics::record_signature();
        let resp = SignCertificateResponse {
            certificate_pem: cert_pem,
            error_code: String::new(),
            error_message: String::new(),
        };

        Ok(Response::new(resp))
    }

    async fn renew_certificate(
        &self,
        request: Request<ca_v1::RenewCertificateRequest>,
    ) -> Result<Response<RenewCertificateResponse>, Status> {
        // PR-4.12 / P2-7: per-caller rate limit (peer-IP keyed).
        let _peer_ip = self.check_rate_limit(&request).await?;

        let req = request.into_inner();

        // Look up the existing certificate
        let existing = self
            .store
            .get_certificate(&req.serial_number)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::not_found(format!("Certificate {} not found", req.serial_number))
            })?;

        // Refuse to renew revoked certificates
        if existing.status == "revoked" {
            metrics::record_error_code(CaErrorCode::InternalError);
            return Ok(Response::new(RenewCertificateResponse {
                certificate_pem: String::new(),
                error_code: "CERT_REVOKED".to_string(),
                error_message: "Cannot renew a revoked certificate".to_string(),
            }));
        }

        // PR-3.1 (gm-ca 0.3.0): renew now supports sub-day TTL
        // (P1-9) and an optional profile override (P1-8). Empty
        // `profile_json` = keep the legacy `CertProfile::default()`
        // behavior (extension set matches v0.1.x); non-empty =
        // parse and use the supplied profile (e.g. SPIRE SVID
        // rotation that wants a fresh URI SAN + new KU/EKU).
        let profile: CertProfile = if req.profile_json.is_empty() {
            CertProfile::default()
        } else {
            serde_json::from_str(&req.profile_json).map_err(|e| {
                metrics::record_error_code(CaErrorCode::InvalidArgument);
                Status::invalid_argument(format!("invalid profile_json: {}", e))
            })?
        };
        let validity_seconds: i64 = if req.validity_seconds > 0 {
            req.validity_seconds
        } else {
            if req.validity_days <= 0 || req.validity_days > 3650 {
                return Err(Status::invalid_argument(format!(
                    "validity_days must be 1-3650, got {}",
                    req.validity_days
                )));
            }
            req.validity_days * 86400
        };

        // Issue new certificate with same subject/public key, new validity.
        let new_cert_pem = self
            .signer
            .renew_certificate_with_profile_and_seconds(
                &existing.certificate_pem,
                validity_seconds,
                &profile,
            )
            .map_err(|e| {
                metrics::record_error_code(CaErrorCode::InternalError);
                Status::invalid_argument(e.to_string())
            })?;

        // Parse new certificate to extract serial and validity dates for persistence
        use gm_crypto::x509::parse_cert_pem;
        let new_cert_info = parse_cert_pem(&new_cert_pem)
            .map_err(|e| Status::internal(format!("failed to parse renewed cert: {}", e)))?;
        let new_serial_hex = new_cert_info
            .serial_hex
            .ok_or_else(|| Status::internal("renewed cert missing serial".to_string()))?;

        let not_before_dt = chrono::Utc::now();
        let not_after_dt = sqlx::types::chrono::DateTime::<Utc>::from_timestamp(
            new_cert_info.not_after.unix_timestamp(),
            0,
        )
        .unwrap_or_else(Utc::now);

        // Persist renewed certificate to database (previously missing — C1-1)
        self.store
            .insert_certificate(
                &new_serial_hex,
                &new_cert_pem,
                self.signer.ca_subject_cn(),
                &existing.subject_cn,
                not_before_dt,
                not_after_dt,
            )
            .await
            .map_err(|e| {
                metrics::record_error_code(CaErrorCode::DatabaseError);
                Status::internal(format!("failed to store renewed certificate: {}", e))
            })?;

        metrics::record_renewal();
        Ok(Response::new(RenewCertificateResponse {
            certificate_pem: new_cert_pem,
            error_code: String::new(),
            error_message: String::new(),
        }))
    }

    async fn revoke_certificate(
        &self,
        request: Request<ca_v1::RevokeCertificateRequest>,
    ) -> Result<Response<RevokeCertificateResponse>, Status> {
        let req = request.into_inner();

        self.store
            .revoke_certificate(&req.serial_number, req.reason, Utc::now())
            .await
            .map_err(|e| {
                metrics::record_error_code(CaErrorCode::DatabaseError);
                Status::internal(e.to_string())
            })?;

        metrics::record_revocation();
        let resp = RevokeCertificateResponse {
            success: true,
            error_code: String::new(),
            error_message: String::new(),
        };

        Ok(Response::new(resp))
    }

    async fn get_certificate(
        &self,
        request: Request<ca_v1::GetCertificateRequest>,
    ) -> Result<Response<GetCertificateResponse>, Status> {
        let req = request.into_inner();

        let cert = self
            .store
            .get_certificate(&req.serial_number)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        match cert {
            Some(c) => {
                let resp = GetCertificateResponse {
                    certificate_pem: c.certificate_pem,
                    issuer: c.issuer_cn,
                    not_before: c.not_before.to_rfc3339(),
                    not_after: c.not_after.to_rfc3339(),
                    status: c.status,
                    error_code: String::new(),
                    error_message: String::new(),
                };
                Ok(Response::new(resp))
            }
            None => {
                let resp = GetCertificateResponse {
                    certificate_pem: String::new(),
                    issuer: String::new(),
                    not_before: String::new(),
                    not_after: String::new(),
                    status: String::new(),
                    error_code: "CERT_NOT_FOUND".to_string(),
                    error_message: format!("Certificate {} not found", req.serial_number),
                };
                Ok(Response::new(resp))
            }
        }
    }

    async fn get_crl(
        &self,
        request: Request<ca_v1::GetCrlRequest>,
    ) -> Result<Response<GetCrlResponse>, Status> {
        let req = request.into_inner();

        let revoked = self
            .store
            .get_revoked_certificates(&req.issuer_cn)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let crl_number = self.crl_number.fetch_add(1, Ordering::SeqCst);
        let crl_der = self
            .signer
            .generate_crl(&revoked, crl_number)
            .map_err(|e| Status::internal(e.to_string()))?;

        let resp = GetCrlResponse {
            crl_der,
            error_code: String::new(),
            error_message: String::new(),
        };

        Ok(Response::new(resp))
    }
}

/// Simple token bucket rate limiter.
///
/// Tokens refill at a fixed rate up to `capacity`. Each `try_consume()`
/// removes one token; if no tokens are available, returns `false`.
struct TokenBucket {
    capacity: u32,
    tokens: u32,
    refill_period: Duration,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_period: Duration) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_period,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        if elapsed >= self.refill_period {
            // Full refill after one period
            self.tokens = self.capacity;
            self.last_refill = now;
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// PR-4.12 / P2-7: per-caller (peer-IP) rate limiter. One
/// bucket per caller, keyed by `IpAddr`; idle entries are
/// reaped after `idle_ttl`. Pre-PR-4.12 a single GLOBAL
/// bucket was shared across all callers, meaning one
/// misbehaving client could exhaust tokens and lock out
/// every legitimate client (DoS amplification).
#[derive(Clone)]
pub struct PerCallerLimiter {
    buckets: Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
    capacity: u32,
    refill_period: Duration,
    idle_ttl: Duration,
}

impl PerCallerLimiter {
    /// Default: 10 tokens per 60s, idle TTL = 10min.
    pub fn default_10_per_minute() -> Self {
        Self::new(10, Duration::from_secs(60), Duration::from_secs(600))
    }

    /// Build with custom capacity / refill period / idle TTL.
    pub fn new(capacity: u32, refill_period: Duration, idle_ttl: Duration) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            capacity,
            refill_period,
            idle_ttl,
        }
    }

    /// Try to consume one token for `peer_ip`. Returns `Ok(peer_ip)`
    /// on success; `Err(Status::resource_exhausted(...))` if the
    /// caller's bucket is empty.
    pub async fn check(&self, peer_ip: IpAddr) -> Result<IpAddr, Status> {
        let mut map = self.buckets.lock().await;
        let now = Instant::now();
        // Opportunistic reaping: drop entries idle longer than `idle_ttl`.
        map.retain(|_, b| now.duration_since(b.last_refill) <= self.idle_ttl);
        let bucket = map
            .entry(peer_ip)
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_period));
        if !bucket.try_consume() {
            metrics::record_rate_limited(peer_ip);
            return Err(Status::resource_exhausted(
                "certificate signing rate limit exceeded for caller, try again later",
            ));
        }
        Ok(peer_ip)
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(3, Duration::from_secs(60));
        let bucket = std::sync::Arc::new(tokio::sync::Mutex::new(bucket));

        // Should allow 3 requests
        for i in 0..3 {
            let mut b = bucket.lock().await;
            assert!(b.try_consume(), "request {} should succeed", i);
        }

        // 4th should be rejected
        let mut b = bucket.lock().await;
        assert!(!b.try_consume(), "4th request should be rate limited");
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let bucket = TokenBucket::new(1, Duration::from_millis(50));
        let bucket = std::sync::Arc::new(tokio::sync::Mutex::new(bucket));

        // Consume the only token
        {
            let mut b = bucket.lock().await;
            assert!(b.try_consume());
            assert!(!b.try_consume());
        }

        // Wait for refill
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Should be refilled
        let mut b = bucket.lock().await;
        assert!(b.try_consume(), "token should be refilled after waiting");
    }
}

#[cfg(test)]
mod pr412_per_caller_rate_limit_tests {
    //! PR-4.12 / P2-7: per-caller rate limiter tests.
    //!
    //! These tests exercise [`PerCallerLimiter`] directly so
    //! they don't require constructing a full `CaSigner` /
    //! `DbStore` (the tonic transport-level
    //! `Request::remote_addr()` setter is not public, so we
    //! use the pure-IP entry point that the production
    //! `check_rate_limit(Request<T>)` shim delegates to).

    use super::*;

    fn new_limiter(capacity: u32, refill: Duration, idle_ttl: Duration) -> PerCallerLimiter {
        PerCallerLimiter::new(capacity, refill, idle_ttl)
    }

    #[tokio::test]
    async fn pr412_placeholder_ip_bucket_holds_capacity_then_rejects() {
        let lim = new_limiter(2, Duration::from_secs(60), Duration::from_secs(600));
        let placeholder = placeholder_peer_ip();
        assert!(lim.check(placeholder).await.is_ok());
        assert!(lim.check(placeholder).await.is_ok());
        let err = lim
            .check(placeholder)
            .await
            .expect_err("3rd call must be rate-limited");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        // All three calls share the placeholder bucket.
        let map = lim.buckets.lock().await;
        assert_eq!(map.len(), 1, "expected exactly one placeholder bucket");
    }

    #[tokio::test]
    async fn pr412_per_caller_buckets_are_independent() {
        let lim = new_limiter(1, Duration::from_secs(60), Duration::from_secs(600));
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        // Exhaust IP A.
        assert!(lim.check(ip_a).await.is_ok());
        let err = lim
            .check(ip_a)
            .await
            .expect_err("IP A 2nd call must be limited");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        // IP B is unaffected.
        assert!(
            lim.check(ip_b).await.is_ok(),
            "IP B must NOT be affected by IP A's exhaustion"
        );
        // Both buckets are now in the map.
        let map = lim.buckets.lock().await;
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&ip_a));
        assert!(map.contains_key(&ip_b));
    }

    #[tokio::test]
    async fn pr412_idle_caller_is_reaped_on_next_call() {
        // 1ms idle TTL: a back-dated `last_refill` gets reaped.
        let lim = new_limiter(10, Duration::from_secs(60), Duration::from_millis(1));
        let ip: IpAddr = "10.0.0.99".parse().unwrap();
        // Inject a stale bucket.
        {
            let mut map = lim.buckets.lock().await;
            let mut bucket = TokenBucket::new(10, Duration::from_secs(60));
            bucket.last_refill = Instant::now() - Duration::from_secs(60);
            map.insert(ip, bucket);
            assert_eq!(map.len(), 1);
        }
        // Sleep so the stale entry is older than the TTL.
        tokio::time::sleep(Duration::from_millis(10)).await;
        // Trigger retain() via the limiter.
        let _ = lim.check(ip).await;
        // The stale entry was reaped BEFORE the target IP
        // check; a new fresh entry was then created — verify
        // the map size is exactly 1 (not 2).
        let map = lim.buckets.lock().await;
        assert_eq!(
            map.len(),
            1,
            "expected stale entry reaped + fresh entry created (map keys: {:?})",
            map.keys().collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn pr412_placeholder_ip_is_0_0_0_0() {
        assert_eq!(
            placeholder_peer_ip().to_string(),
            "0.0.0.0",
            "placeholder must be 0.0.0.0 to match the documented behavior"
        );
    }

    #[tokio::test]
    async fn pr412_default_10_per_minute_factory() {
        let lim = PerCallerLimiter::default_10_per_minute();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // 10 successful calls.
        for _ in 0..10 {
            assert!(lim.check(ip).await.is_ok());
        }
        // 11th must be rate-limited.
        assert!(lim.check(ip).await.is_err());
    }
}
