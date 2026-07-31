//! Session store trait and implementations for session ticket replay protection.
//!
//! This module provides a trait-based abstraction for storing session ticket replay
//! information, allowing different backend implementations (in-memory, SQLite, PostgreSQL, Redis).
//!
//! # Example
//!
//! ```rust,no_run
//! use gm_tls::{HandshakeOptions, SessionStoreConfig};
//!
//! // Use in-memory store (default, always fail-closed)
//! let config = SessionStoreConfig::InMemory;
//!
//! // Use SQLite for local persistence (fail-closed by default)
//! let config = SessionStoreConfig::Sqlite {
//!     path: "/tmp/sessions.db".to_string(),
//!     fail_closed: true,
//! };
//!
//! // Use PostgreSQL for distributed deployment (fail-closed by default)
//! let config = SessionStoreConfig::Postgres {
//!     url: std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
//!     fail_closed: true,
//!     use_tls: true,  // enable TLS for production connections
//! };
//!
//! // Use Redis for high-performance caching (fail-closed by default)
//! let config = SessionStoreConfig::Redis {
//!     url: std::env::var("REDIS_URL").expect("REDIS_URL must be set"),
//!     fail_closed: true,
//!     use_tls: true,  // enable TLS for production connections
//! };
//! ```

use async_trait::async_trait;
use indexmap::IndexSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::error::TlsError;

/// Maximum number of ticket entries to track for replay protection.
/// Used by in-memory store for FIFO eviction.
const MAX_TICKET_CACHE_SIZE: usize = 10000;

/// Session ticket storage backend trait.
///
/// Implementations must be thread-safe (Send + Sync) and handle concurrent access
/// appropriately, especially for the replay check + mark operations.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Check if a ticket has been used before (replay detection).
    ///
    /// Returns `true` if the ticket was already seen (potential replay attack).
    async fn is_ticket_replay(&self, ticket: &[u8]) -> bool;

    /// Mark a ticket as used to prevent future replays.
    ///
    /// Returns `Ok(())` on success, or `TlsError::SessionStoreError` on failure.
    async fn mark_ticket_used(&self, ticket: Vec<u8>) -> Result<(), TlsError>;

    /// Prune expired ticket entries from the store.
    ///
    /// Tickets older than 24 hours are considered expired and should be
    /// removed to prevent unbounded storage growth. The default
    /// implementation is a no-op.
    ///
    /// Returns the number of entries removed, or `TlsError` on failure.
    async fn prune_expired(&self) -> Result<usize, TlsError> {
        Ok(0)
    }
}

// ============================================================================
// In-Memory Session Store
// ============================================================================

/// In-memory session store using IndexSet with FIFO eviction.
///
/// This is the default implementation when no session store is configured.
/// - Pro: No external dependencies, fast
/// - Con: State lost on restart, single-instance only
///
/// Note: In-memory operations never fail, so this store is always fail-closed.
/// The check-and-mark operations use a single mutex lock, providing atomicity
/// within a single process. However, for multi-instance deployments, use a
/// shared database store (PostgreSQL/Redis) for proper replay protection.
pub struct InMemorySessionStore {
    cache: Arc<Mutex<IndexSet<Vec<u8>>>>,
}

impl InMemorySessionStore {
    /// Create a new in-memory session store.
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(IndexSet::with_capacity(MAX_TICKET_CACHE_SIZE))),
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn is_ticket_replay(&self, ticket: &[u8]) -> bool {
        let cache = self.cache.lock().await;
        cache.contains(ticket)
    }

    async fn mark_ticket_used(&self, ticket: Vec<u8>) -> Result<(), TlsError> {
        let mut cache = self.cache.lock().await;

        // Check if this ticket is already marked as used
        if cache.contains(&ticket) {
            return Err(TlsError::SessionStoreError(
                "ticket already marked as used".to_string(),
            ));
        }

        // FIFO eviction: remove oldest entries when full
        if cache.len() >= MAX_TICKET_CACHE_SIZE {
            let to_remove = MAX_TICKET_CACHE_SIZE / 2;
            // IndexSet preserves insertion order, so drain removes the oldest first
            let drained: Vec<Vec<u8>> = cache.drain(..to_remove).collect();
            info!(
                "In-memory session store: evicted {} entries (FIFO)",
                drained.len()
            );
        }

        cache.insert(ticket);
        Ok(())
    }
}

// ============================================================================
// SQLite Session Store
// ============================================================================

/// SQLite-based session store for local persistence.
///
/// - Pro: Local persistence, no separate service needed
/// - Con: Not suitable for multi-instance deployments
pub struct SqliteSessionStore {
    pool: sqlx::sqlite::SqlitePool,
    /// If true, replay check errors cause ticket rejection (fail-closed).
    fail_closed: Arc<AtomicBool>,
}

impl SqliteSessionStore {
    /// Create a new SQLite session store.
    ///
    /// Creates the database file and schema if it doesn't exist.
    ///
    /// # Arguments
    /// * `path` - Path to the SQLite database file
    /// * `fail_closed` - If true, any replay check failure rejects the ticket
    pub async fn new(path: &str, fail_closed: bool) -> Result<Self, sqlx::Error> {
        let database_url = format!("sqlite:{}?mode=rwc", path);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?;

        // Initialize schema
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS session_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(&pool)
        .await?;

        // Create index for faster lookups
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tickets_hash ON session_tickets(ticket_hash)")
            .execute(&pool)
            .await?;

        info!("SQLite session store initialized at {}", path);
        Ok(Self {
            pool,
            fail_closed: Arc::new(AtomicBool::new(fail_closed)),
        })
    }

    /// Clean up expired tickets (older than 24 hours).
    pub async fn cleanup_expired(&self) -> Result<usize, TlsError> {
        self.prune_expired().await
    }
}

#[async_trait]
impl SessionStore for SqliteSessionStore {
    async fn prune_expired(&self) -> Result<usize, TlsError> {
        let result = sqlx::query(
            "DELETE FROM session_tickets WHERE created_at < datetime('now', '-24 hours')",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| TlsError::SessionStoreError(e.to_string()))?;
        let count = result.rows_affected() as usize;
        if count > 0 {
            info!("SQLite session store: cleaned up {} expired tickets", count);
        }
        Ok(count)
    }
    async fn is_ticket_replay(&self, ticket: &[u8]) -> bool {
        let hex_ticket = hex::encode(ticket);
        let result = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_tickets WHERE ticket_hash = ?",
        )
        .bind(&hex_ticket)
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(count)) => count > 0,
            Ok(None) => false,
            Err(e) => {
                warn!("SQLite session store: replay check failed: {}", e);
                // Fail open by default (availability over security), but
                // fail_closed mode rejects tickets when the check fails
                self.fail_closed.load(Ordering::Relaxed)
            }
        }
    }

    async fn mark_ticket_used(&self, ticket: Vec<u8>) -> Result<(), TlsError> {
        let hex_ticket = hex::encode(&ticket);

        // Try to insert; ignore duplicate key errors (ticket already used)
        let result = sqlx::query("INSERT OR IGNORE INTO session_tickets (ticket_hash) VALUES (?)")
            .bind(&hex_ticket)
            .execute(&self.pool)
            .await
            .map_err(|e| TlsError::SessionStoreError(e.to_string()))?;

        if result.rows_affected() == 0 {
            // This shouldn't happen if is_ticket_replay was called first,
            // but handle gracefully
            return Err(TlsError::SessionStoreError(
                "ticket already marked as used".to_string(),
            ));
        }

        Ok(())
    }
}

// ============================================================================
// PostgreSQL Session Store
// ============================================================================

/// PostgreSQL-based session store for distributed deployments.
///
/// - Pro: Suitable for multi-instance, persistent
/// - Con: Requires PostgreSQL service
pub struct PostgresSessionStore {
    pool: sqlx::postgres::PgPool,
    /// If true, replay check errors cause ticket rejection (fail-closed).
    fail_closed: Arc<AtomicBool>,
}

impl PostgresSessionStore {
    /// Create a new PostgreSQL session store.
    ///
    /// Creates the table and indexes if they don't exist.
    /// Uses retry logic to handle concurrent table creation race conditions.
    ///
    /// # Arguments
    /// * `database_url` - PostgreSQL connection URL
    /// * `fail_closed` - If true, any replay check failure rejects the ticket
    /// * `use_tls` - If true, enable TLS with certificate verification
    pub async fn new(
        database_url: &str,
        fail_closed: bool,
        use_tls: bool,
    ) -> Result<Self, sqlx::Error> {
        use sqlx::postgres::{PgConnectOptions, PgSslMode};
        let pool = if use_tls {
            let opts: PgConnectOptions = database_url
                .parse::<PgConnectOptions>()?
                .ssl_mode(PgSslMode::VerifyFull);
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(10)
                .connect_with(opts)
                .await?
        } else {
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(10)
                .connect(database_url)
                .await?
        };

        // Initialize schema with retry logic for race conditions
        let create_table = r#"
            CREATE TABLE IF NOT EXISTS session_tickets (
                id BIGSERIAL PRIMARY KEY,
                ticket_hash VARCHAR(128) NOT NULL UNIQUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#;

        for attempt in 0..3 {
            match sqlx::query(create_table).execute(&pool).await {
                Ok(_) => break,
                Err(e) if attempt < 2 && e.to_string().contains("duplicate key") => {
                    // Another connection created the table, continue
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }

        // Create indexes with retry logic
        for attempt in 0..3 {
            match sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_tickets_hash ON session_tickets(ticket_hash)",
            )
            .execute(&pool)
            .await
            {
                Ok(_) => break,
                Err(e) if attempt < 2 && e.to_string().contains("duplicate key") => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }

        for attempt in 0..3 {
            match sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_tickets_created ON session_tickets(created_at)",
            )
            .execute(&pool)
            .await
            {
                Ok(_) => break,
                Err(e) if attempt < 2 && e.to_string().contains("duplicate key") => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        }

        info!("PostgreSQL session store initialized");
        Ok(Self {
            pool,
            fail_closed: Arc::new(AtomicBool::new(fail_closed)),
        })
    }

    /// Clean up expired tickets (older than 24 hours).
    pub async fn cleanup_expired(&self) -> Result<usize, TlsError> {
        self.prune_expired().await
    }
}

#[async_trait]
impl SessionStore for PostgresSessionStore {
    async fn prune_expired(&self) -> Result<usize, TlsError> {
        let result = sqlx::query(
            "DELETE FROM session_tickets WHERE created_at < NOW() - INTERVAL '24 hours'",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| TlsError::SessionStoreError(e.to_string()))?;

        let count = result.rows_affected() as usize;
        if count > 0 {
            info!(
                "PostgreSQL session store: cleaned up {} expired tickets",
                count
            );
        }
        Ok(count)
    }
    async fn is_ticket_replay(&self, ticket: &[u8]) -> bool {
        let hex_ticket = hex::encode(ticket);

        let result = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_tickets WHERE ticket_hash = $1",
        )
        .bind(&hex_ticket)
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(count)) => count > 0,
            Ok(None) => false,
            Err(e) => {
                warn!("PostgreSQL session store: replay check failed: {}", e);
                self.fail_closed.load(Ordering::Relaxed)
            }
        }
    }

    async fn mark_ticket_used(&self, ticket: Vec<u8>) -> Result<(), TlsError> {
        let hex_ticket = hex::encode(&ticket);

        // Use ON CONFLICT DO NOTHING to handle race conditions
        let result = sqlx::query(
            "INSERT INTO session_tickets (ticket_hash) VALUES ($1) ON CONFLICT (ticket_hash) DO \
             NOTHING",
        )
        .bind(&hex_ticket)
        .execute(&self.pool)
        .await
        .map_err(|e| TlsError::SessionStoreError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(TlsError::SessionStoreError(
                "ticket already marked as used".to_string(),
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Redis Session Store
// ============================================================================

/// Redis-based session store for high-performance caching.
///
/// - Pro: Fast, atomic operations, auto-expiry via TTL
/// - Con: Requires Redis service, ephemeral by default (unless persistence enabled)
pub struct RedisSessionStore {
    pool: deadpool_redis::Pool,
    /// If true, replay check errors cause ticket rejection (fail-closed).
    fail_closed: Arc<AtomicBool>,
}

impl RedisSessionStore {
    /// Create a new Redis session store.
    ///
    /// Requires a Redis connection pool configured via deadpool-redis.
    ///
    /// # Arguments
    /// * `redis_url` - Redis connection URL
    /// * `fail_closed` - If true, any replay check failure rejects the ticket
    /// * `use_tls` - If true, enable TLS by switching to `rediss://` scheme
    pub async fn new(redis_url: &str, fail_closed: bool, use_tls: bool) -> Result<Self, TlsError> {
        let final_url = if use_tls {
            // Switch to rediss:// scheme for TLS connections
            if redis_url.starts_with("redis://") {
                redis_url.replacen("redis://", "rediss://", 1)
            } else if !redis_url.starts_with("rediss://") {
                format!("rediss://{}", redis_url)
            } else {
                redis_url.to_string()
            }
        } else {
            redis_url.to_string()
        };

        let cfg = deadpool_redis::Config {
            url: Some(final_url),
            pool: None,
            connection: None,
        };

        let pool = cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .map_err(|e| {
                TlsError::SessionStoreError(format!("failed to create Redis pool: {}", e))
            })?;

        // Test connection
        let conn = pool.get().await.map_err(|e| {
            TlsError::SessionStoreError(format!("failed to get Redis connection: {}", e))
        })?;

        redis::cmd("PING")
            .query_async::<String>(&mut conn.clone())
            .await
            .map_err(|e| TlsError::SessionStoreError(format!("Redis ping failed: {}", e)))?;

        info!("Redis session store initialized");
        Ok(Self {
            pool,
            fail_closed: Arc::new(AtomicBool::new(fail_closed)),
        })
    }

    /// Redis key prefix for ticket hashes.
    const KEY_PREFIX: &'static str = "gmtls:ticket:";

    /// TTL for ticket entries (24 hours in seconds).
    const TICKET_TTL: u64 = 86400;
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn is_ticket_replay(&self, ticket: &[u8]) -> bool {
        let hex_ticket = hex::encode(ticket);
        let key = format!("{}{}", Self::KEY_PREFIX, hex_ticket);

        match self.pool.get().await {
            Ok(conn) => {
                let exists: Result<bool, _> = redis::cmd("EXISTS")
                    .arg(&key)
                    .query_async(&mut conn.clone())
                    .await;

                match exists {
                    Ok(exists) => exists,
                    Err(e) => {
                        warn!("Redis session store: replay check failed: {}", e);
                        self.fail_closed.load(Ordering::Relaxed)
                    }
                }
            }
            Err(e) => {
                warn!("Redis session store: failed to get connection: {}", e);
                self.fail_closed.load(Ordering::Relaxed)
            }
        }
    }

    async fn mark_ticket_used(&self, ticket: Vec<u8>) -> Result<(), TlsError> {
        let hex_ticket = hex::encode(&ticket);
        let key = format!("{}{}", Self::KEY_PREFIX, hex_ticket);

        let conn = self.pool.get().await.map_err(|e| {
            TlsError::SessionStoreError(format!("failed to get Redis connection: {}", e))
        })?;

        // Use SET NX (set if not exists) with TTL for atomic operation
        // Returns true if the key was set, false if it already existed
        let result: Result<bool, _> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(Self::TICKET_TTL)
            .query_async(&mut conn.clone())
            .await;

        match result {
            Ok(true) => Ok(()), // Successfully set
            Ok(false) => Err(TlsError::SessionStoreError(
                "ticket already marked as used".to_string(),
            )),
            Err(e) => Err(TlsError::SessionStoreError(format!(
                "Redis SET NX failed: {}",
                e
            ))),
        }
    }
}

// ============================================================================
// Configuration and Factory
// ============================================================================

/// Configuration for session ticket storage.
#[derive(Debug, Clone, Default)]
pub enum SessionStoreConfig {
    /// In-memory store (default for backward compatibility).
    /// No external dependencies, state lost on restart.
    /// In-memory store is always fail-closed (operations never fail).
    #[default]
    InMemory,

    /// SQLite local database.
    Sqlite {
        /// Path to the SQLite database file.
        path: String,
        /// If true (default), replay check errors cause ticket rejection (fail-closed).
        /// If false, errors allow the ticket (fail-open).
        fail_closed: bool,
    },

    /// PostgreSQL database.
    Postgres {
        /// PostgreSQL connection URL (e.g., from DATABASE_URL env var).
        url: String,
        /// If true (default), replay check errors cause ticket rejection (fail-closed).
        /// If false, errors allow the ticket (fail-open).
        fail_closed: bool,
        /// If true, enable TLS for the database connection.
        /// Appends `sslmode=verify-full` to the connection URL.
        /// Default: false.
        use_tls: bool,
    },

    /// Redis cache.
    Redis {
        /// Redis connection URL (e.g., from REDIS_URL env var).
        url: String,
        /// If true (default), replay check errors cause ticket rejection (fail-closed).
        /// If false, errors allow the ticket (fail-open).
        fail_closed: bool,
        /// If true, enable TLS for the Redis connection.
        /// Uses `rediss://` scheme for TLS connections.
        /// Default: false.
        use_tls: bool,
    },
}

impl SessionStoreConfig {
    /// Build a SessionStore instance from this configuration.
    ///
    /// Returns a boxed trait object that can be used polymorphically.
    pub async fn build(&self) -> Result<Arc<dyn SessionStore>, TlsError> {
        match self {
            SessionStoreConfig::InMemory => Ok(Arc::new(InMemorySessionStore::new())),

            SessionStoreConfig::Sqlite { path, fail_closed } => {
                let store = SqliteSessionStore::new(path, *fail_closed)
                    .await
                    .map_err(|e| TlsError::SessionStoreError(e.to_string()))?;
                Ok(Arc::new(store))
            }

            SessionStoreConfig::Postgres {
                url,
                fail_closed,
                use_tls,
            } => {
                let store = PostgresSessionStore::new(url, *fail_closed, *use_tls)
                    .await
                    .map_err(|e| TlsError::SessionStoreError(e.to_string()))?;
                Ok(Arc::new(store))
            }

            SessionStoreConfig::Redis {
                url,
                fail_closed,
                use_tls,
            } => {
                let store = RedisSessionStore::new(url, *fail_closed, *use_tls).await?;
                Ok(Arc::new(store))
            }
        }
    }
}
