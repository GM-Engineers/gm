//! Database operations

use crate::cert::{Certificate, CrlEntry};
use crate::error::CaError;
use sqlx::AnyPool;
use sqlx::Row;
use sqlx::types::chrono::{DateTime, Utc};

pub struct DbStore {
    pool: AnyPool,
}

impl DbStore {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub async fn get_certificate(
        &self,
        serial_number: &str,
    ) -> Result<Option<Certificate>, CaError> {
        let row = sqlx::query("SELECT * FROM certificates WHERE serial_number = $1")
            .bind(serial_number)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(row_to_certificate(&row)?)),
            None => Ok(None),
        }
    }

    /// Insert a newly issued certificate into the database.
    pub async fn insert_certificate(
        &self,
        serial_number: &str,
        certificate_pem: &str,
        issuer_cn: &str,
        subject_cn: &str,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
    ) -> Result<(), CaError> {
        sqlx::query(
            r#"
            INSERT INTO certificates
                (serial_number, certificate_pem, issuer_cn, subject_cn, not_before, not_after, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'active')
            "#,
        )
        .bind(serial_number)
        .bind(certificate_pem)
        .bind(issuer_cn)
        .bind(subject_cn)
        .bind(not_before.to_rfc3339())
        .bind(not_after.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn revoke_certificate(
        &self,
        serial_number: &str,
        reason: i32,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), CaError> {
        let result = sqlx::query(
            r#"
            UPDATE certificates
            SET status = 'revoked', revoked_at = $2, revocation_reason = $3, updated_at = $4
            WHERE serial_number = $1 AND status = 'active'
            "#,
        )
        .bind(serial_number)
        .bind(revoked_at.to_rfc3339())
        .bind(reason)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(CaError::CertificateNotFound(
                "Certificate not found or already revoked".to_string(),
            ));
        }

        Ok(())
    }

    pub async fn get_revoked_certificates(
        &self,
        issuer_cn: &str,
    ) -> Result<Vec<CrlEntry>, CaError> {
        let rows = sqlx::query(
            r#"
            SELECT serial_number, revoked_at, revocation_reason as reason
            FROM certificates
            WHERE issuer_cn = $1 AND status = 'revoked'
            "#,
        )
        .bind(issuer_cn)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row_to_crl_entry(&row)?);
        }

        Ok(entries)
    }

    pub async fn init_schema(&self) -> Result<(), CaError> {
        if self.is_postgres().await {
            self.init_schema_postgres().await?;
        } else {
            self.init_schema_sqlite().await?;
        }

        Ok(())
    }

    /// Check if the backend is PostgreSQL
    async fn is_postgres(&self) -> bool {
        sqlx::query("SELECT version()")
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten()
            .and_then(|row| row.try_get::<String, _>(0).ok())
            .map(|v| v.to_lowercase().contains("postgresql"))
            .unwrap_or(false)
    }

    async fn init_schema_postgres(&self) -> Result<(), CaError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS certificates (
                id BIGSERIAL PRIMARY KEY,
                serial_number VARCHAR(64) NOT NULL UNIQUE,
                certificate_pem TEXT NOT NULL,
                issuer_cn VARCHAR(256) NOT NULL,
                subject_cn VARCHAR(256) NOT NULL,
                not_before TIMESTAMPTZ NOT NULL,
                not_after TIMESTAMPTZ NOT NULL,
                status VARCHAR(32) NOT NULL DEFAULT 'active',
                revoked_at TIMESTAMPTZ,
                revocation_reason INTEGER,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_number)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_certificates_issuer ON certificates(issuer_cn)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status)")
            .execute(&self.pool)
            .await
            .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn init_schema_sqlite(&self) -> Result<(), CaError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_number TEXT NOT NULL UNIQUE,
                certificate_pem TEXT NOT NULL,
                issuer_cn TEXT NOT NULL,
                subject_cn TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                revoked_at TEXT,
                revocation_reason INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_number)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_certificates_issuer ON certificates(issuer_cn)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status)")
            .execute(&self.pool)
            .await
            .map_err(|e| CaError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Ping the database to verify connectivity. Used for health checks.
    pub async fn ping(&self) -> Result<(), CaError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| CaError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

/// Parse a timestamp string from the database (RFC3339 or SQLite datetime format)
fn parse_db_timestamp(s: &str) -> Result<DateTime<Utc>, CaError> {
    // Try RFC3339 first
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            // Try SQLite datetime format: "2024-01-15 10:30:00"
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .map(|naive| DateTime::from_naive_utc_and_offset(naive, Utc))
        })
        .map_err(|e| CaError::DatabaseError(format!("Invalid timestamp '{}': {}", s, e)))
}

/// Convert an AnyRow to Certificate
fn row_to_certificate(row: &sqlx::any::AnyRow) -> Result<Certificate, CaError> {
    Ok(Certificate {
        id: row
            .try_get("id")
            .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        serial_number: row
            .try_get("serial_number")
            .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        certificate_pem: row
            .try_get("certificate_pem")
            .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        issuer_cn: row
            .try_get("issuer_cn")
            .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        subject_cn: row
            .try_get("subject_cn")
            .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        not_before: parse_db_timestamp(
            &row.try_get::<String, _>("not_before")
                .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        )?,
        not_after: parse_db_timestamp(
            &row.try_get::<String, _>("not_after")
                .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        )?,
        status: row
            .try_get("status")
            .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        revoked_at: row
            .try_get::<String, _>("revoked_at")
            .ok()
            .map(|s| parse_db_timestamp(&s))
            .transpose()?,
        revocation_reason: row.try_get("revocation_reason").ok(),
        created_at: parse_db_timestamp(
            &row.try_get::<String, _>("created_at")
                .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        )?,
        updated_at: parse_db_timestamp(
            &row.try_get::<String, _>("updated_at")
                .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        )?,
    })
}

/// Convert an AnyRow to CrlEntry
fn row_to_crl_entry(row: &sqlx::any::AnyRow) -> Result<CrlEntry, CaError> {
    Ok(CrlEntry {
        serial_number: row
            .try_get("serial_number")
            .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        revoked_at: parse_db_timestamp(
            &row.try_get::<String, _>("revoked_at")
                .map_err(|e| CaError::DatabaseError(e.to_string()))?,
        )?,
        reason: row
            .try_get("reason")
            .map_err(|e| CaError::DatabaseError(e.to_string()))?,
    })
}
