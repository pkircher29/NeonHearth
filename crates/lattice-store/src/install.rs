use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallState {
    pub install_id: Uuid,
    pub first_run_at: DateTime<Utc>,
    pub schema_version: i64,
}

#[derive(Clone)]
pub struct InstallRepository {
    pool: SqlitePool,
}

impl InstallRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn load(&self) -> anyhow::Result<Option<InstallState>> {
        let row: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT install_id, first_run_at, schema_version FROM install_state WHERE singleton = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(install_id, first_run_at, schema_version)| {
            Ok(InstallState {
                install_id: Uuid::parse_str(&install_id).context("invalid persisted install ID")?,
                first_run_at: DateTime::parse_from_rfc3339(&first_run_at)
                    .context("invalid persisted first-run timestamp")?
                    .with_timezone(&Utc),
                schema_version,
            })
        })
        .transpose()
    }

    pub async fn initialize(&self, now: DateTime<Utc>) -> anyhow::Result<InstallState> {
        if let Some(existing) = self.load().await? {
            return Ok(existing);
        }
        let install_id = Uuid::now_v7();
        sqlx::query(
            "INSERT OR IGNORE INTO install_state (singleton, install_id, first_run_at, schema_version) VALUES (1, ?, ?, 7)",
        )
        .bind(install_id.to_string())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        self.load()
            .await?
            .context("install state missing after initialization")
    }
}
