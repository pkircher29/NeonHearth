use chrono::{DateTime, Utc};
use lattice_store::{InstallRepository, connect_memory};

#[tokio::test]
async fn initialize_preserves_original_first_run_time_and_install_id() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = InstallRepository::new(pool);
    let first: DateTime<Utc> = "2026-08-23T10:00:00Z".parse()?;
    let later: DateTime<Utc> = "2026-08-30T10:00:00Z".parse()?;

    let initial = repository.initialize(first).await?;
    let repeated = repository.initialize(later).await?;

    assert_eq!(initial.first_run_at, first);
    assert_eq!(initial.schema_version, 1);
    assert_eq!(initial.install_id, repeated.install_id);
    assert_eq!(initial.first_run_at, repeated.first_run_at);
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
