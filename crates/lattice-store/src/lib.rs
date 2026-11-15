//! Persistence interfaces and implementations for NeonHearth.

mod advisory;
mod audit_log;
mod camera;
mod checkpoint;
mod device_labels;
mod flow;
mod home;
mod install;
mod maintenance;
mod maintenance_db;
mod policy;
mod remote_access;
mod w6;

pub use advisory::*;
use anyhow::Context;
pub use audit_log::*;
pub use camera::*;
pub use checkpoint::*;
pub use device_labels::*;
pub use flow::{CompactionPolicy, FlowIngestor, FlowRepository, FlowStoreError};
use fs2::FileExt;
pub use home::*;
pub use install::{InstallRepository, InstallState, latest_migration_version};
pub use maintenance::*;
pub use maintenance_db::*;
pub use policy::{
    ActuationAttempt, ActuationReservation, CLOCK_BACKWARD_TOLERANCE, ClockStatus, MAX_EXTENSION,
    MAX_PLAUSIBLE_CLOCK_GAP, MIN_PLAUSIBLE_CLOCK_UNIX, PendingDecision, PolicyRepository,
    SkippedPolicyRow, decision_fingerprint,
};
pub use remote_access::*;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{path::PathBuf, str::FromStr, time::Duration};
pub use w6::{W6Attempt, W6PriorStateRepository};

pub async fn connect(url: &str) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(url)
        .with_context(|| format!("parse SQLite URL {url}"))?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    connect_options(options).await
}

pub async fn connect_path(path: impl AsRef<std::path::Path>) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path.as_ref())
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    connect_options(options).await
}

async fn connect_options(options: SqliteConnectOptions) -> anyhow::Result<SqlitePool> {
    let lock_path = PathBuf::from(format!("{}.migrate.lock", options.get_filename().display()));
    let lock = tokio::task::spawn_blocking(move || {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("open migration lock file {}", lock_path.display()))?;
        file.lock_exclusive()
            .with_context(|| format!("acquire migration lock {}", lock_path.display()))?;
        Ok::<_, anyhow::Error>(file)
    })
    .await
    .context("join migration lock task")??;
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .context("open SQLite database")?;
    sqlx::migrate!()
        .run(&pool)
        .await
        .context("run SQLite migrations")?;
    lock.unlock().context("release migration lock")?;
    Ok(pool)
}

/// Begins a write transaction that reserves the database writer up front.
///
/// Every transaction that reads before it writes must use this instead of
/// `pool.begin()`. A deferred transaction that upgrades from a read snapshot
/// fails immediately with `SQLITE_BUSY(_SNAPSHOT)` when another connection
/// wrote in between, and `busy_timeout` is never consulted for that case.
/// `BEGIN IMMEDIATE` waits for the writer lock (honouring `busy_timeout`)
/// before any snapshot is taken.
pub async fn begin_write(
    pool: &SqlitePool,
) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, sqlx::Error> {
    pool.begin_with("BEGIN IMMEDIATE").await
}

/// True for SQLITE_BUSY / SQLITE_LOCKED style failures that are worth retrying.
pub fn is_busy_error(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database| {
        let code = database.code();
        // Primary codes: 5 BUSY, 6 LOCKED; extended codes keep the low byte.
        code.as_deref()
            .and_then(|c| c.parse::<i64>().ok())
            .is_some_and(|c| matches!(c & 0xff, 5 | 6))
            || database.message().contains("database is locked")
            || database.message().contains("database table is locked")
    })
}

/// Runs `operation` again (bounded, with backoff) while it fails with a busy error.
pub(crate) async fn retry_busy<T, F, Fut>(mut operation: F) -> Result<T, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    let mut attempt: u32 = 0;
    loop {
        match operation().await {
            Err(error) if is_busy_error(&error) && attempt < 6 => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(25 * u64::from(attempt))).await;
            }
            other => return other,
        }
    }
}

pub async fn connect_memory() -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str("sqlite::memory:")?
        .filename(":memory:")
        .foreign_keys(true)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}
