use chrono::{DateTime, Utc};
use lattice_store::{InstallRepository, connect_memory};
use std::path::PathBuf;
use tempfile::tempdir;

fn database_url(path: PathBuf) -> String {
    format!("sqlite://{}", path.display())
}

#[tokio::test]
async fn connect_creates_a_missing_database_file() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("state.db");
    assert!(!path.exists());

    let pool = lattice_store::connect(&database_url(path.clone())).await?;
    assert!(path.exists());
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM install_state")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count.0, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_connects_serialize_first_migration() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let url = database_url(directory.path().join("state.db"));
    let (left, right) = tokio::join!(lattice_store::connect(&url), lattice_store::connect(&url));
    let left = left?;
    let right = right?;
    for pool in [&left, &right] {
        let migrations: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(pool)
            .await?;
        let sequences: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM event_sequence")
            .fetch_one(pool)
            .await?;
        assert_eq!(migrations.0, 7);
        assert_eq!(sequences.0, 1);
    }
    Ok(())
}

#[tokio::test]
async fn foreign_keys_are_enabled_for_pooled_connections() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let pool = lattice_store::connect(&database_url(directory.path().join("state.db"))).await?;
    let result = sqlx::query("INSERT INTO evidence (device_id, family, source, fact_key, fact_value, confidence, observed_at) VALUES ('missing', 'family', 'source', 'key', 'value', 0.5, '2026-08-23T10:00:00Z')")
        .execute(&pool)
        .await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn initialize_preserves_original_first_run_time_and_install_id() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = InstallRepository::new(pool);
    let first: DateTime<Utc> = "2026-08-23T10:00:00Z".parse()?;
    let later: DateTime<Utc> = "2026-08-30T10:00:00Z".parse()?;

    let initial = repository.initialize(first).await?;
    let repeated = repository.initialize(later).await?;

    assert_eq!(initial.first_run_at, first);
    assert_eq!(initial.schema_version, 7);
    assert_eq!(initial.install_id, repeated.install_id);
    assert_eq!(initial.first_run_at, repeated.first_run_at);
    assert_eq!(repeated.schema_version, 7);
    Ok(())
}

#[tokio::test]
async fn devices_use_owner_type_column() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let names: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('devices') ORDER BY cid")
            .fetch_all(&pool)
            .await?;

    assert!(names.iter().any(|name| name == "owner_type"));
    assert!(!names.iter().any(|name| name == "type"));
    Ok(())
}

#[tokio::test]
async fn initialize_is_safe_under_concurrent_first_calls() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = InstallRepository::new(pool.clone());
    let first: DateTime<Utc> = "2026-08-23T10:00:00Z".parse()?;
    let later: DateTime<Utc> = "2026-08-30T10:00:00Z".parse()?;

    let (left, right) = tokio::join!(repository.initialize(first), repository.initialize(later));
    let left = left?;
    let right = right?;

    assert_eq!(left.install_id, right.install_id);
    assert_eq!(left.first_run_at, right.first_run_at);
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM install_state")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}
