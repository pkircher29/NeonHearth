//! Persistence interfaces and implementations for NeonHearth.

mod advisory;
mod audit_log;
mod camera;
mod checkpoint;
mod flow;
mod home;
mod install;
mod maintenance_db;
mod policy;
mod w6;

pub use advisory::*;
use anyhow::Context;
pub use audit_log::*;
pub use camera::*;
pub use checkpoint::*;
pub use flow::{CompactionPolicy, FlowIngestor, FlowRepository, FlowStoreError};
use fs2::FileExt;
pub use home::*;
pub use install::{InstallRepository, InstallState};
pub use maintenance_db::*;
pub use policy::{ActuationAttempt, ActuationReservation, PendingDecision, PolicyRepository};
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
