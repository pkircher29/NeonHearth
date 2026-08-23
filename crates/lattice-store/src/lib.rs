//! Persistence interfaces and implementations for NeonHearth.

mod install;

use anyhow::Context;
use fs2::FileExt;
pub use install::{InstallRepository, InstallState};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{path::PathBuf, str::FromStr, time::Duration};

pub async fn connect(url: &str) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(url)
        .with_context(|| format!("parse SQLite URL {url}"))?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
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
