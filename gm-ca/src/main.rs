//! GM/CA Server - Generic CA service for SM2 certificates

use gm_ca::auth::BearerTokenInterceptor;
use gm_ca::ca::v1::ca_service_server::CaServiceServer;
use gm_ca::cert::CaSigner;
use gm_ca::db::DbStore;
use gm_ca::service::CaServiceImpl;
use gm_crypto::sm2::Sm2KeyPair;
use gm_tls::grpc::GmTlsIncoming;
use metrics_exporter_prometheus::PrometheusBuilder;
use sqlx::any::AnyPoolOptions;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal as sig_ctrl;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time;
use tonic::transport::Server;
use tonic_health::{ServingStatus, server::health_reporter};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

const DEFAULT_CA_KEY_PATH: &str = "ca_key.pem";
const DEFAULT_CA_SUBJECT_CN: &str = "GM CA";

/// File mode for private key files: owner read/write only (0o600)
const KEY_FILE_MODE: u32 = 0o600;

fn load_or_generate_ca_key(
    key_path: &Path,
    allow_generation: bool,
) -> Result<Sm2KeyPair, Box<dyn std::error::Error>> {
    if key_path.exists() {
        // Reject if key file has insecure permissions
        if let Ok(metadata) = fs::metadata(key_path) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode != KEY_FILE_MODE {
                return Err(format!(
                    "CA key file {} has insecure permissions ({:#o}), requires {:#o}. \
                     Run: chmod 600 {}",
                    key_path.display(),
                    mode,
                    KEY_FILE_MODE,
                    key_path.display()
                )
                .into());
            }
        }
        let pem_str = fs::read_to_string(key_path)?;
        Sm2KeyPair::from_private_key_pem(&pem_str)
            .map_err(|e| format!("Failed to load CA key: {}", e).into())
    } else if allow_generation {
        let key = Sm2KeyPair::generate()?;
        let pem = key.private_key_pem()?;
        fs::write(key_path, &pem)?;
        // Set restrictive permissions on the newly created key file
        fs::set_permissions(key_path, fs::Permissions::from_mode(KEY_FILE_MODE))?;
        warn!(
            "New CA key generated and saved to {} with mode {:#o}. \
             Copy this file to a secure location and set CA_KEY_PATH to use it. \
             This key should be rotated if it was ever exposed.",
            key_path.display(),
            KEY_FILE_MODE
        );
        Ok(key)
    } else {
        Err(format!(
            "CA key file {} does not exist. \
             To initialize a new CA, set ALLOW_CA_KEY_GENERATION=true. \
             For production, generate the key offline and set CA_KEY_PATH to point to it.",
            key_path.display()
        )
        .into())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Describe gm-tls metrics before any TLS operations
    gm_tls::describe_metrics();
    gm_ca::metrics::describe_ca_metrics();

    // Start Prometheus metrics server on separate port
    let metrics_addr: SocketAddr = std::env::var("METRICS_ADDR")
        .unwrap_or_else(|_| "[::1]:9000".to_string())
        .parse()
        .map_err(|e| format!("Invalid METRICS_ADDR: {}", e))?;

    PrometheusBuilder::new()
        .with_http_listener(metrics_addr)
        .install()
        .map_err(|e| format!("failed to install prometheus exporter: {}", e))?;

    info!("Metrics server listening on {}", metrics_addr);

    let database_url = std::env::var("DATABASE_URL").map_err(|_| {
        "DATABASE_URL environment variable must be set. \
                       Example: sqlite:gm_ca.db or postgres://user:password@localhost:5432/gm_ca"
    })?;

    let pool = AnyPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    let store = DbStore::new(pool);
    store.init_schema().await?;

    let ca_key_path =
        std::env::var("CA_KEY_PATH").unwrap_or_else(|_| DEFAULT_CA_KEY_PATH.to_string());
    let allow_key_generation = std::env::var("ALLOW_CA_KEY_GENERATION")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    if allow_key_generation {
        tracing::warn!(
            "SECURITY: ALLOW_CA_KEY_GENERATION is enabled. \
             Auto-generating CA keys is dangerous in production — \
             a misconfiguration could invalidate all issued certificates. \
             Only use this in development/testing environments."
        );
    }
    let ca_key = load_or_generate_ca_key(Path::new(&ca_key_path), allow_key_generation)?;

    let ca_subject_cn =
        std::env::var("CA_SUBJECT_CN").unwrap_or_else(|_| DEFAULT_CA_SUBJECT_CN.to_string());

    let signer = CaSigner::new(ca_key, &ca_subject_cn);

    let auth_token = std::env::var("CA_AUTH_TOKEN").map_err(|_| {
        "CA_AUTH_TOKEN environment variable must be set. \
                       Generate a strong random token (e.g. openssl rand -hex 32) \
                       and set it on both server and client."
    })?;

    let interceptor = BearerTokenInterceptor::new(auth_token)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let addr: SocketAddr = std::env::var("GRPC_LISTEN_ADDR")
        .unwrap_or_else(|_| "[::1]:50051".to_string())
        .parse()
        .map_err(|e| format!("Invalid GRPC_LISTEN_ADDR: {}", e))?;
    // CaServiceImpl is Clone — both the gRPC service and the health-check
    // background task share the same DbStore via Arc
    let store = Arc::new(store);
    let service = CaServiceImpl::new(signer, store.clone());

    // Set up gRPC health check service (gRPC Health Checking Protocol)
    let (health_reporter, health_server) = health_reporter();
    health_reporter
        .set_service_status("gm.ca.v1.CaService", ServingStatus::Serving)
        .await;

    // Background task: periodically check DB and update health status
    let service_for_health = service.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            match service_for_health.store().ping().await {
                Ok(()) => {
                    let _ = health_reporter
                        .set_service_status("gm.ca.v1.CaService", ServingStatus::Serving)
                        .await;
                }
                Err(e) => {
                    error!("Health check failed: {}", e);
                    let _ = health_reporter
                        .set_service_status("gm.ca.v1.CaService", ServingStatus::NotServing)
                        .await;
                }
            }
        }
    });

    // GM/TLS transport: supports three modes
    // 1. GM/TLS (preferred): set GRPC_TLS_CERT, GRPC_TLS_KEY, GRPC_TLS_CA -> uses SM2/SM3/SM4
    // 2. Plain TCP: no TLS env vars set -> no encryption (development only)
    let grpc_tls_cert = std::env::var("GRPC_TLS_CERT").ok();
    let grpc_tls_key = std::env::var("GRPC_TLS_KEY").ok();
    let grpc_tls_ca = std::env::var("GRPC_TLS_CA").ok();

    match (&grpc_tls_cert, &grpc_tls_key, &grpc_tls_ca) {
        (Some(cert_path), Some(key_path), Some(ca_path)) => {
            // Mode 1: GM/TLS — full SM2/SM3/SM4 encryption for gRPC
            info!(
                "gRPC GM/TLS enabled with cert={}, key={}, ca={}",
                cert_path, key_path, ca_path
            );
            let tls_config = gm_tls::TlsConfig::load(cert_path, key_path, ca_path)?
                .with_alpn(vec!["h2".to_string()])
                .with_require_client_auth(false);
            let acceptor = gm_tls::TlsAcceptor::new(tls_config)?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let incoming = GmTlsIncoming::new(listener, acceptor);

            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

            let serve_future = async {
                info!("GM/CA Server listening on {} (GM/TLS)", addr);
                Server::builder()
                    .add_service(health_server)
                    .add_service(CaServiceServer::with_interceptor(service, interceptor))
                    .serve_with_incoming_shutdown(incoming, async {
                        shutdown_rx.await.ok();
                    })
                    .await
            };

            let mut sigterm = signal(SignalKind::terminate())?;

            tokio::select! {
                result = serve_future => {
                    if let Err(e) = result {
                        error!("gRPC server error: {}", e);
                    }
                }
                _ = sig_ctrl::ctrl_c() => {
                    info!("Received SIGINT, initiating graceful shutdown...");
                    let _ = shutdown_tx.send(());
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown...");
                    let _ = shutdown_tx.send(());
                }
            };
        }
        (None, None, None) => {
            // Mode 2: Plain TCP — no TLS (development only)
            warn!(
                "gRPC running without TLS — for development only! \
                   Set GRPC_TLS_CERT, GRPC_TLS_KEY, GRPC_TLS_CA to enable GM/TLS."
            );

            let tcp_listener = tokio::net::TcpListener::bind(addr).await?;
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(tcp_listener);

            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

            let serve_future = async {
                info!("GM/CA Server listening on {} (no TLS)", addr);
                Server::builder()
                    .add_service(health_server)
                    .add_service(CaServiceServer::with_interceptor(service, interceptor))
                    .serve_with_incoming_shutdown(incoming, async {
                        shutdown_rx.await.ok();
                    })
                    .await
            };

            let mut sigterm = signal(SignalKind::terminate())?;

            tokio::select! {
                result = serve_future => {
                    if let Err(e) = result {
                        error!("gRPC server error: {}", e);
                    }
                }
                _ = sig_ctrl::ctrl_c() => {
                    info!("Received SIGINT, initiating graceful shutdown...");
                    let _ = shutdown_tx.send(());
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown...");
                    let _ = shutdown_tx.send(());
                }
            };
        }
        _ => {
            return Err(
                "All three GRPC_TLS_CERT, GRPC_TLS_KEY, and GRPC_TLS_CA must be set \
                        to enable GM/TLS. Set all three or none."
                    .into(),
            );
        }
    }

    info!("Server shutdown complete");
    Ok(())
}
