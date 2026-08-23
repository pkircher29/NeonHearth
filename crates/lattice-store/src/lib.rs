//! Persistence interfaces and implementations for NeonHearth.

mod install;

pub use install::{InstallRepository, InstallState};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

pub async fn connect(url: &str) -> anyhow::Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect(url)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}

pub async fn connect_memory() -> anyhow::Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}
