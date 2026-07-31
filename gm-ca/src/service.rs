//! gRPC CA service implementation

use crate::ca::v1 as ca_v1;
use crate::cert::{CaSigner, extract_csr_subject_cn};
use crate::db::DbStore;
use crate::metrics;
use ca_v1::{
    GetCertificateResponse, GetCrlResponse, RenewCertificateResponse, RevokeCertificateResponse,
    SignCertificateResponse, ca_service_server::CaService,
};
use sqlx::types::chrono::Utc;
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
    /// Rate limiter for certificate signing (token bucket per-peer)
    rate_limiter: Arc<Mutex<TokenBucket>>,
}

impl CaServiceImpl {
    /// Create a new CA service implementation.
    ///
    /// # Arguments
    /// * `signer` - SM2 CA key pair for signing certificates
    /// * `store` - Shared PostgreSQL store for certificate persistence
    pub fn new(signer: CaSigner, store: Arc<DbStore>) -> Self {
        Self {
            signer: Arc::new(signer),
            store,
            crl_number: Arc::new(AtomicU64::new(1)),
            // Default: 10 signtures per 60 seconds per peer
            rate_limiter: Arc::new(Mutex::new(TokenBucket::new(10, Duration::from_secs(60)))),
        }
    }

    /// Create a new CA service with custom rate limit.
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
            rate_limiter: Arc::new(Mutex::new(TokenBucket::new(capacity, refill_period))),
        }
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
        // Rate limit check
        {
            let mut bucket = self.rate_limiter.lock().await;
            if !bucket.try_consume() {
                metrics::record_error("rate_limited");
                return Err(Status::resource_exhausted(
                    "certificate signing rate limit exceeded, try again later",
                ));
            }
        }

        let req = request.into_inner();
        let csr_bytes = req.csr_pem.as_bytes();

        // Sign CSR and get serial + PEM
        let (serial_hex, cert_pem) =
            self.signer
                .sign_csr(csr_bytes, req.validity_days)
                .map_err(|e| {
                    metrics::record_error("sign_failed");
                    Status::invalid_argument(e.to_string())
                })?;

        // Extract subject CN from CSR for database storage
        let subject_cn = extract_csr_subject_cn(csr_bytes).map_err(|e| {
            metrics::record_error("csr_parse_failed");
            Status::invalid_argument(e.to_string())
        })?;

        // Calculate validity period for DB storage
        let not_before = time::OffsetDateTime::now_utc();
        let not_after =
            not_before + std::time::Duration::from_secs(86400 * req.validity_days as u64);
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
                metrics::record_error("db_insert_failed");
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
        // Rate limit check
        {
            let mut bucket = self.rate_limiter.lock().await;
            if !bucket.try_consume() {
                metrics::record_error("rate_limited");
                return Err(Status::resource_exhausted(
                    "certificate renewal rate limit exceeded, try again later",
                ));
            }
        }

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
            metrics::record_error("renew_revoked_cert");
            return Ok(Response::new(RenewCertificateResponse {
                certificate_pem: String::new(),
                error_code: "CERT_REVOKED".to_string(),
                error_message: "Cannot renew a revoked certificate".to_string(),
            }));
        }

        // Issue new certificate with same subject/public key, new validity
        let new_cert_pem = self
            .signer
            .renew_certificate(&existing.certificate_pem, req.validity_days)
            .map_err(|e| {
                metrics::record_error("renew_failed");
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
                metrics::record_error("db_insert_failed");
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
                metrics::record_error("revoke_failed");
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
