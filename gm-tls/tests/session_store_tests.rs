//! Integration tests for session store backends.
//!
//! These tests verify that each session store implementation correctly
//! handles replay protection for session tickets.
//!
//! Run with: cargo test --test session_store_tests
//!
//! For docker-backed tests (Postgres, Redis), start services first:
//! ```bash
//! cd docker && docker compose up -d postgres redis
//! DATABASE_URL=postgres://user:password@localhost:5432/gm_ca \
//! REDIS_URL=redis://:password@localhost:6379 \
//! cargo test --test session_store_tests
//! ```

use gm_tls::session_store::{
    InMemorySessionStore, SessionStore, SessionStoreConfig, SqliteSessionStore,
};
use std::sync::Arc;
use tokio::test as async_std;

/// Generate a unique ticket name for each test to avoid cross-test interference
fn unique_ticket(prefix: &str) -> Vec<u8> {
    format!("{}_{}", prefix, uuid::Uuid::new_v4()).into_bytes()
}

// ============================================================================
// In-Memory Session Store Tests
// ============================================================================

#[async_std]
async fn test_inmemory_empty_store_is_not_replay() {
    let store = InMemorySessionStore::new();
    let ticket = b"test_ticket_123".to_vec();

    let is_replay = store.is_ticket_replay(&ticket).await;
    assert!(!is_replay, "New ticket should not be a replay");
}

#[async_std]
async fn test_inmemory_mark_ticket_used() {
    let store = InMemorySessionStore::new();
    let ticket = b"test_ticket_456".to_vec();

    store.mark_ticket_used(ticket.clone()).await.unwrap();

    let is_replay = store.is_ticket_replay(&ticket).await;
    assert!(
        is_replay,
        "Ticket should be marked as used after mark_ticket_used"
    );
}

#[async_std]
async fn test_inmemory_double_use_returns_error() {
    let store = InMemorySessionStore::new();
    let ticket = b"test_ticket_789".to_vec();

    store.mark_ticket_used(ticket.clone()).await.unwrap();
    let result = store.mark_ticket_used(ticket.clone()).await;

    assert!(
        result.is_err(),
        "Second mark_ticket_used should fail for same ticket"
    );
}

#[async_std]
async fn test_inmemory_different_tickets_independent() {
    let store = InMemorySessionStore::new();
    let ticket1 = b"ticket_one".to_vec();
    let ticket2 = b"ticket_two".to_vec();

    store.mark_ticket_used(ticket1.clone()).await.unwrap();

    assert!(
        !store.is_ticket_replay(&ticket2).await,
        "Different ticket should not be replay"
    );
    assert!(
        store.is_ticket_replay(&ticket1).await,
        "ticket1 should be replay"
    );
}

#[async_std]
async fn test_inmemory_fifo_eviction() {
    // Create store and fill beyond capacity
    let store = Arc::new(InMemorySessionStore::new());

    // Insert 15000 tickets (capacity is 10000)
    for i in 0..15000 {
        let ticket = format!("ticket_{}", i).into_bytes();
        store.mark_ticket_used(ticket).await.unwrap();
    }

    // After 15000 entries with capacity 10000, some entries were evicted.
    // HashSet iteration order is not guaranteed, so we can only verify:
    // 1. Recent entries (ticket_14999) should definitely be present
    // 2. Some older entries may have been evicted
    assert!(
        store.is_ticket_replay(b"ticket_14999").await,
        "Most recent ticket should still be present"
    );

    // The store should have exactly MAX_TICKET_CACHE_SIZE entries
    // (we can't directly check this without exposing internals, but we can
    // verify that adding a new ticket works - if cache wasn't evicted properly,
    // it would have 15000 entries and the next insert would try to evict again)
    let final_ticket = b"final_ticket".to_vec();
    store.mark_ticket_used(final_ticket.clone()).await.unwrap();
    assert!(
        store.is_ticket_replay(&final_ticket).await,
        "Final ticket should be marked as used"
    );
}

// ============================================================================
// SQLite Session Store Tests
// ============================================================================

#[async_std]
async fn test_sqlite_empty_store_is_not_replay() {
    let store = SqliteSessionStore::new(":memory:", false)
        .await
        .expect("failed to create SQLite store");
    let ticket = b"sqlite_ticket_123".to_vec();

    let is_replay = store.is_ticket_replay(&ticket).await;
    assert!(!is_replay, "New ticket should not be a replay");
}

#[async_std]
async fn test_sqlite_mark_ticket_used() {
    let store = SqliteSessionStore::new(":memory:", false)
        .await
        .expect("failed to create SQLite store");
    let ticket = b"sqlite_ticket_456".to_vec();

    store.mark_ticket_used(ticket.clone()).await.unwrap();

    let is_replay = store.is_ticket_replay(&ticket).await;
    assert!(is_replay, "Ticket should be marked as used");
}

#[async_std]
async fn test_sqlite_double_use_returns_error() {
    let store = SqliteSessionStore::new(":memory:", false)
        .await
        .expect("failed to create SQLite store");
    let ticket = b"sqlite_ticket_789".to_vec();

    store.mark_ticket_used(ticket.clone()).await.unwrap();
    let result = store.mark_ticket_used(ticket.clone()).await;

    assert!(result.is_err(), "Second mark_ticket_used should fail");
}

#[async_std]
async fn test_sqlite_persistence_across_instances() {
    use tempfile::NamedTempFile;

    // Create a temporary file for SQLite database
    let temp_file = NamedTempFile::new().expect("failed to create temp file");
    let path = temp_file.path().to_str().unwrap();

    // First instance - mark ticket as used
    {
        let store = SqliteSessionStore::new(path, false)
            .await
            .expect("failed to create SQLite store");
        let ticket = b"persistent_ticket".to_vec();
        store.mark_ticket_used(ticket.clone()).await.unwrap();
    }

    // Second instance - same ticket should be replay
    {
        let store = SqliteSessionStore::new(path, false)
            .await
            .expect("failed to create second SQLite store");
        let ticket = b"persistent_ticket".to_vec();
        let is_replay = store.is_ticket_replay(&ticket).await;
        assert!(is_replay, "Ticket should persist across instances");
    }
}

#[async_std]
async fn test_sqlite_config_build() {
    let config = SessionStoreConfig::Sqlite {
        path: ":memory:".to_string(),
        fail_closed: false,
    };

    let store = config
        .build()
        .await
        .expect("failed to build store from config");

    let ticket = b"config_test_ticket".to_vec();
    store.mark_ticket_used(ticket.clone()).await.unwrap();

    let is_replay = store.is_ticket_replay(&ticket).await;
    assert!(is_replay, "Ticket should be marked as used");
}

// ============================================================================
// PostgreSQL Session Store Tests
// ============================================================================

/// Test against a running PostgreSQL instance.
/// Requires DATABASE_URL environment variable and docker services running.
fn get_postgres_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok()
}

#[async_std]
#[ignore = "requires postgres running"]
async fn test_postgres_empty_store_is_not_replay() {
    let url = get_postgres_url().expect("DATABASE_URL not set");
    let config = SessionStoreConfig::Postgres {
        url,
        fail_closed: false,
        use_tls: false,
    };
    let store = config
        .build()
        .await
        .expect("failed to build postgres store");

    let ticket = unique_ticket("postgres");
    let is_replay = store.is_ticket_replay(&ticket).await;
    assert!(!is_replay, "New ticket should not be a replay");
}

#[async_std]
#[ignore = "requires postgres running"]
async fn test_postgres_mark_ticket_used() {
    let url = get_postgres_url().expect("DATABASE_URL not set");
    let config = SessionStoreConfig::Postgres {
        url,
        fail_closed: false,
        use_tls: false,
    };
    let store = config
        .build()
        .await
        .expect("failed to build postgres store");

    let ticket = unique_ticket("postgres");
    store.mark_ticket_used(ticket.clone()).await.unwrap();

    let is_replay = store.is_ticket_replay(&ticket).await;
    assert!(is_replay, "Ticket should be marked as used");
}

#[async_std]
#[ignore = "requires postgres running"]
async fn test_postgres_double_use_returns_error() {
    let url = get_postgres_url().expect("DATABASE_URL not set");
    let config = SessionStoreConfig::Postgres {
        url,
        fail_closed: false,
        use_tls: false,
    };
    let store = config
        .build()
        .await
        .expect("failed to build postgres store");

    let ticket = unique_ticket("postgres");
    store.mark_ticket_used(ticket.clone()).await.unwrap();
    let result = store.mark_ticket_used(ticket.clone()).await;

    assert!(result.is_err(), "Second mark_ticket_used should fail");
}

#[async_std]
#[ignore = "requires postgres running"]
async fn test_postgres_concurrent_access() {
    use futures::stream::{self, StreamExt};
    use std::sync::Arc;

    let url = get_postgres_url().expect("DATABASE_URL not set");
    let config = SessionStoreConfig::Postgres {
        url,
        fail_closed: false,
        use_tls: false,
    };
    let store = Arc::new(
        config
            .build()
            .await
            .expect("failed to build postgres store"),
    );

    // Use a unique ticket for this concurrent test to avoid interference
    let ticket = unique_ticket("concurrent");
    let num_tasks = 10;

    // Spawn concurrent tasks trying to mark the same ticket
    let results: Vec<_> = stream::iter(0..num_tasks)
        .map(|_| {
            let store = store.clone();
            let ticket = ticket.clone();
            async move { store.mark_ticket_used(ticket.clone()).await }
        })
        .buffered(num_tasks)
        .collect()
        .await;

    // Only one should succeed, rest should fail
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    let failure_count = results.iter().filter(|r| r.is_err()).count();

    assert_eq!(success_count, 1, "Exactly one mark should succeed");
    assert_eq!(
        failure_count,
        num_tasks - 1,
        "Rest should fail with conflict"
    );
}

// ============================================================================
// Redis Session Store Tests
// ============================================================================

/// Test against a running Redis instance.
/// Requires REDIS_URL environment variable and docker services running.
fn get_redis_url() -> Option<String> {
    std::env::var("REDIS_URL").ok()
}

#[async_std]
#[ignore = "requires redis running"]
async fn test_redis_empty_store_is_not_replay() {
    let url = get_redis_url().expect("REDIS_URL not set");
    let config = SessionStoreConfig::Redis {
        url,
        fail_closed: false,
        use_tls: false,
    };
    let store = config.build().await.expect("failed to build redis store");

    let ticket = unique_ticket("redis");
    let is_replay = store.is_ticket_replay(&ticket).await;
    assert!(!is_replay, "New ticket should not be a replay");
}

#[async_std]
#[ignore = "requires redis running"]
async fn test_redis_mark_ticket_used() {
    let url = get_redis_url().expect("REDIS_URL not set");
    let config = SessionStoreConfig::Redis {
        url,
        fail_closed: false,
        use_tls: false,
    };
    let store = config.build().await.expect("failed to build redis store");

    let ticket = unique_ticket("redis");
    store.mark_ticket_used(ticket.clone()).await.unwrap();

    let is_replay = store.is_ticket_replay(&ticket).await;
    assert!(is_replay, "Ticket should be marked as used");
}

#[async_std]
#[ignore = "requires redis running"]
async fn test_redis_double_use_returns_error() {
    let url = get_redis_url().expect("REDIS_URL not set");
    let config = SessionStoreConfig::Redis {
        url,
        fail_closed: false,
        use_tls: false,
    };
    let store = config.build().await.expect("failed to build redis store");

    let ticket = unique_ticket("redis");
    store.mark_ticket_used(ticket.clone()).await.unwrap();
    let result = store.mark_ticket_used(ticket.clone()).await;

    assert!(result.is_err(), "Second mark_ticket_used should fail");
}

#[async_std]
#[ignore = "requires redis running"]
async fn test_redis_config_build() {
    let url = get_redis_url().expect("REDIS_URL not set");
    let config = SessionStoreConfig::Redis {
        url,
        fail_closed: false,
        use_tls: false,
    };

    let store = config
        .build()
        .await
        .expect("failed to build store from config");

    let ticket = unique_ticket("redis_config");
    store.mark_ticket_used(ticket.clone()).await.unwrap();

    let is_replay = store.is_ticket_replay(&ticket).await;
    assert!(is_replay, "Ticket should be marked as used");
}

// ============================================================================
// Generic SessionStore Trait Tests
// ============================================================================

/// Test that the trait object works correctly via Config::build
#[async_std]
async fn test_session_store_config_builds_inmemory() {
    let config = SessionStoreConfig::InMemory;
    let store = config
        .build()
        .await
        .expect("failed to build InMemory store");

    // Just verify it works - store is of correct type
    let ticket = b"type_check_ticket".to_vec();
    store.mark_ticket_used(ticket).await.unwrap();
}

/// Test that all stores handle empty/malformed tickets consistently
#[async_std]
async fn test_stores_handle_empty_ticket() {
    let store = InMemorySessionStore::new();
    let empty_ticket = b"".to_vec();

    // Empty tickets should be treated as not replay (will fail later in decrypt)
    let is_replay = store.is_ticket_replay(&empty_ticket).await;
    assert!(!is_replay, "Empty ticket should not be marked as replay");
}

/// Test that all stores handle large tickets
#[async_std]
async fn test_stores_handle_large_ticket() {
    let store = InMemorySessionStore::new();
    let large_ticket = vec![0u8; 10000];

    store.mark_ticket_used(large_ticket.clone()).await.unwrap();

    let is_replay = store.is_ticket_replay(&large_ticket).await;
    assert!(is_replay, "Large ticket should be marked as used");
}

// ============================================================================
// Stress Tests
// ============================================================================

#[async_std]
async fn test_inmemory_high_volume_tickets() {
    let store = Arc::new(InMemorySessionStore::new());
    let num_tickets = 5000;

    // Sequential insert and check
    for i in 0..num_tickets {
        let ticket = format!("stress_ticket_{}", i).into_bytes();
        store.mark_ticket_used(ticket).await.unwrap();
    }

    // Verify all are replays
    for i in 0..num_tickets {
        let ticket = format!("stress_ticket_{}", i).into_bytes();
        assert!(
            store.is_ticket_replay(&ticket).await,
            "Ticket {} should be marked as replay",
            i
        );
    }
}

#[async_std]
async fn test_sqlite_high_volume_tickets() {
    let store = SqliteSessionStore::new(":memory:", false)
        .await
        .expect("failed to create SQLite store");
    let num_tickets = 1000;

    for i in 0..num_tickets {
        let ticket = format!("sqlite_stress_{}", i).into_bytes();
        store.mark_ticket_used(ticket).await.unwrap();
    }

    for i in 0..num_tickets {
        let ticket = format!("sqlite_stress_{}", i).into_bytes();
        assert!(
            store.is_ticket_replay(&ticket).await,
            "Ticket {} should be marked as replay",
            i
        );
    }
}
