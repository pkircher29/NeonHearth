//! Finding 2: read-then-write transactions must reserve the writer up front.
//! The in-memory pool has one connection, so these tests use a file database
//! with several pooled connections.
use chrono::{TimeZone, Utc};
use lattice_domain::DeviceId;
use lattice_store::{M2StateRepository, connect_path};
use tempfile::tempdir;

async fn add_device(pool: &sqlx::SqlitePool, id: DeviceId) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at) VALUES(?,?,?)")
        .bind(id.to_string())
        .bind("2026-01-01T00:00:00+00:00")
        .bind("2026-01-01T00:00:00+00:00")
        .execute(pool)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_verified_blocks_all_succeed_with_unique_ids() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let pool = connect_path(directory.path().join("contention.db")).await?;
    let repository = M2StateRepository::new(pool.clone());
    let mut ids = Vec::new();
    for _ in 0..32 {
        let id = DeviceId::new();
        add_device(&pool, id).await?;
        ids.push(id);
    }
    let at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    let mut tasks = Vec::new();
    for id in ids.clone() {
        let repository = repository.clone();
        tasks.push(tokio::spawn(async move {
            repository.record_verified_block(id, at).await
        }));
    }
    for task in tasks {
        task.await??;
    }
    let (rows, distinct): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(DISTINCT transition_id) FROM presence_transitions WHERE transition_id<0",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!((rows, distinct), (32, 32));
    for id in ids {
        assert!(repository.verified_control_blocked(id).await?);
    }
    Ok(())
}

#[tokio::test]
async fn repeated_unblock_records_once() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let pool = connect_path(directory.path().join("unblock.db")).await?;
    let repository = M2StateRepository::new(pool.clone());
    let id = DeviceId::new();
    add_device(&pool, id).await?;
    let t = |s: i64| Utc.timestamp_opt(1_800_000_000 + s, 0).unwrap();
    repository.record_verified_block(id, t(0)).await?;
    repository.record_verified_unblock(id, t(1)).await?;
    repository.record_verified_unblock(id, t(2)).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM presence_transitions WHERE trigger_kind='enforcement_unblocked'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(count, 1);
    assert!(!repository.verified_control_blocked(id).await?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flow_apply_and_blocks_do_not_fail_under_contention() -> anyhow::Result<()> {
    use lattice_domain::{ByteCount, Coverage};
    use lattice_sensor::flow::{
        DestinationCategory, Protocol, Resolution, Rollup, RollupChange, RollupKey,
    };
    let directory = tempdir()?;
    let pool = connect_path(directory.path().join("flow-contention.db")).await?;
    let repository = M2StateRepository::new(pool.clone());
    let flow = repository.flow_repository(64)?;
    let blocked = DeviceId::new();
    add_device(&pool, blocked).await?;
    let at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    let mut tasks: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = Vec::new();
    for n in 0..24i64 {
        let flow = flow.clone();
        tasks.push(tokio::spawn(async move {
            let device = DeviceId::new();
            let rollup = Rollup {
                key: RollupKey {
                    resolution: Resolution::Second,
                    bucket: Utc.timestamp_opt(1_800_000_000 + n, 0).unwrap(),
                    device_id: device,
                    protocol: Protocol::Tcp,
                    destination: DestinationCategory::Internet,
                    interface: 1,
                    metadata: None,
                },
                bytes: ByteCount {
                    upload: 1,
                    download: 2,
                },
                coverage: Coverage::Complete,
                metadata: None,
            };
            flow.apply(&[RollupChange::Upsert(rollup)], at).await?;
            Ok(())
        }));
        let repository = repository.clone();
        tasks.push(tokio::spawn(async move {
            repository.record_verified_block(blocked, at).await?;
            Ok(())
        }));
    }
    for task in tasks {
        task.await??;
    }
    Ok(())
}
