use chrono::{DateTime, TimeZone, Utc};
use lattice_store::{
    AuditActor, AuditCategory, AuditFilter, AuditLog, AuditPage, ChainScope, DbMaintenance,
    MaintenanceError, NewAuditEntry, RetentionJob, connect_path,
};
use serde_json::json;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::tempdir;

fn at(second: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(second, 0).single().unwrap()
}

fn entry_at(index: i64, second: i64) -> NewAuditEntry {
    NewAuditEntry {
        occurred_at: at(second),
        actor: AuditActor::Service,
        category: AuditCategory::Enforcement,
        action: format!("enforce.{index}"),
        subject: None,
        detail: json!({"index": index, "padding": "p".repeat(512)}),
    }
}

async fn seeded_db(path: &Path, entries: i64) -> anyhow::Result<sqlx::SqlitePool> {
    let pool = connect_path(path).await?;
    let log = AuditLog::new(pool.clone());
    for index in 0..entries {
        log.append(entry_at(index, 1_700_000_000 + index)).await?;
    }
    Ok(pool)
}

#[tokio::test]
async fn integrity_check_is_ok_on_a_healthy_database() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("state.db");
    let pool = seeded_db(&path, 5).await?;
    let maintenance = DbMaintenance::new(pool, &path);

    let report = maintenance.integrity_check().await?;
    assert!(report.ok, "unexpected report: {report:?}");
    assert!(report.integrity_errors.is_empty());
    assert!(report.foreign_key_violations.is_empty());
    Ok(())
}

#[tokio::test]
async fn corrupted_file_copy_is_detected() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("state.db");
    let pool = seeded_db(&path, 40).await?;
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await?;
    pool.close().await;

    let copy = directory.path().join("corrupt.db");
    std::fs::copy(&path, &copy)?;
    let len = std::fs::metadata(&copy)?.len();
    assert!(len > 16 * 4096);
    // Smash whole pages at the quarter points of the file (header intact) so
    // the file still opens but fails integrity checking.
    let mut file = std::fs::OpenOptions::new().write(true).open(&copy)?;
    for quarter in 1..=3u64 {
        let offset = (len * quarter / 4) / 4096 * 4096;
        file.seek(SeekFrom::Start(offset.max(4096)))?;
        file.write_all(&[0xFF; 4096])?;
    }
    file.sync_all()?;
    drop(file);

    let error = DbMaintenance::verify_backup(&copy).await.unwrap_err();
    assert!(
        matches!(error, MaintenanceError::BackupInvalid(_)),
        "unexpected: {error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn backup_verify_restore_round_trip_preserves_data() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("state.db");
    let pool = seeded_db(&path, 10).await?;
    let maintenance = DbMaintenance::new(pool.clone(), &path);
    let source_version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await?;

    let backup_path = directory.path().join("backups").join("snapshot.db");
    std::fs::create_dir_all(backup_path.parent().unwrap())?;
    let backup = maintenance.backup_to(&backup_path).await?;
    assert!(backup.size_bytes > 0);
    assert!(!backup_path.with_extension("db.tmp").exists());

    let verification = DbMaintenance::verify_backup(&backup_path).await?;
    assert_eq!(verification.migration_version, source_version);

    // Diverge the live database after the snapshot.
    let log = AuditLog::new(pool.clone());
    for index in 10..14 {
        log.append(entry_at(index, 1_700_000_000 + index)).await?;
    }
    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await?;
    assert_eq!(live, 14);

    // Restore consumes the maintenance handle (and with it the open pool).
    let report = maintenance.restore_from(&backup_path).await?;
    assert_eq!(report.verification.migration_version, source_version);
    assert!(report.previous_database.is_some());

    let pool = connect_path(&path).await?;
    let restored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await?;
    assert_eq!(restored, 10);
    let chain = AuditLog::new(pool).verify_chain(ChainScope::All).await?;
    assert!(chain.is_valid());
    assert_eq!(chain.checked, 10);
    Ok(())
}

#[tokio::test]
async fn restore_refuses_an_unverifiable_file() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("state.db");
    let pool = seeded_db(&path, 3).await?;
    let maintenance = DbMaintenance::new(pool, &path);

    let fake = directory.path().join("fake.db");
    std::fs::write(&fake, b"definitely not a sqlite database")?;
    let error = maintenance.restore_from(&fake).await.unwrap_err();
    assert!(
        matches!(error, MaintenanceError::RestoreRefused(_)),
        "unexpected: {error:?}"
    );

    // The live database was never touched.
    let pool = connect_path(&path).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 3);
    assert!(
        AuditLog::new(pool)
            .verify_chain(ChainScope::All)
            .await?
            .is_valid()
    );
    Ok(())
}

#[tokio::test]
async fn retention_prune_keeps_the_chain_verifiable_from_the_anchor() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("state.db");
    let pool = seeded_db(&path, 10).await?;
    let maintenance = DbMaintenance::new(pool.clone(), &path);
    let log = AuditLog::new(pool.clone());

    // Entries occurred at t+0..t+9; prune everything older than 3600s as of
    // t+4+3600, i.e. entries 1..=4.
    let now = at(1_700_000_004 + 3_600);
    let report = maintenance
        .retention(
            RetentionJob {
                max_age_seconds: Some(3_600),
                max_rows: None,
            },
            now,
        )
        .await?;
    assert_eq!(report.pruned_rows, 4);
    assert_eq!(report.remaining_rows, 6);
    assert_eq!(report.pruned_through_id, Some(4));
    assert_eq!(report.kept_out_of_order_rows, 0);

    let (anchor_id, anchor_hash): (i64, String) = sqlx::query_as(
        "SELECT pruned_through_id, pruned_through_hash FROM audit_log_anchor WHERE singleton = 1",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(anchor_id, 4);
    assert_eq!(
        report.pruned_through_hash.as_deref(),
        Some(anchor_hash.as_str())
    );

    // Verification restarts from the anchor and stays valid.
    let chain = log.verify_chain(ChainScope::All).await?;
    assert!(chain.is_valid(), "chain broke: {chain:?}");
    assert!(chain.anchored);
    assert_eq!(chain.start_id, Some(5));
    assert_eq!(chain.checked, 6);

    // The surviving head row's prev_hash equals the anchor hash.
    let first_kept = log
        .list(
            &AuditFilter::default(),
            AuditPage {
                after_id: None,
                limit: 1,
            },
        )
        .await?;
    assert_eq!(first_kept[0].id, 5);
    assert_eq!(first_kept[0].prev_hash, anchor_hash);

    // Appends continue on the same chain and still verify.
    log.append(entry_at(99, 1_700_000_050)).await?;
    let chain = log.verify_chain(ChainScope::All).await?;
    assert!(chain.is_valid());
    assert_eq!(chain.checked, 7);

    // The forbid-delete trigger was re-created inside the prune transaction.
    let delete = sqlx::query("DELETE FROM audit_log WHERE id = 6")
        .execute(&pool)
        .await;
    assert!(delete.unwrap_err().to_string().contains("append-only"));
    Ok(())
}

#[tokio::test]
async fn retention_refuses_non_oldest_side_cuts() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("state.db");
    let pool = connect_path(&path).await?;
    let log = AuditLog::new(pool.clone());
    // Out-of-order occurred_at: id 2 is newer than the cutoff, id 3 is older.
    log.append(entry_at(1, 1_700_000_100)).await?;
    log.append(entry_at(2, 1_700_001_000)).await?;
    log.append(entry_at(3, 1_700_000_200)).await?;
    log.append(entry_at(4, 1_700_002_000)).await?;

    let report = log
        .retention_prune(Some(at(1_700_000_500)), None, at(1_700_005_000))
        .await?;
    // Only the contiguous oldest prefix below the cutoff (id 1) is pruned;
    // id 3 is old enough but sits mid-chain, so the cut refuses it.
    assert_eq!(report.pruned_rows, 1);
    assert_eq!(report.pruned_through_id, Some(1));
    assert_eq!(report.kept_out_of_order_rows, 1);

    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM audit_log ORDER BY id")
        .fetch_all(&pool)
        .await?;
    assert_eq!(ids, vec![2, 3, 4]);
    let chain = log.verify_chain(ChainScope::All).await?;
    assert!(chain.is_valid(), "chain broke: {chain:?}");
    assert_eq!(chain.start_id, Some(2));
    Ok(())
}

#[tokio::test]
async fn retention_max_rows_prunes_oldest_and_keeps_chain() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("state.db");
    let pool = seeded_db(&path, 10).await?;
    let maintenance = DbMaintenance::new(pool.clone(), &path);

    let report = maintenance
        .retention(
            RetentionJob {
                max_age_seconds: None,
                max_rows: Some(3),
            },
            at(1_700_009_000),
        )
        .await?;
    assert_eq!(report.pruned_rows, 7);
    assert_eq!(report.remaining_rows, 3);
    assert_eq!(report.pruned_through_id, Some(7));

    let chain = AuditLog::new(pool).verify_chain(ChainScope::All).await?;
    assert!(chain.is_valid());
    assert_eq!(chain.start_id, Some(8));
    assert_eq!(chain.checked, 3);

    // An empty job is a typed error, not a silent no-op.
    assert!(matches!(
        maintenance
            .retention(RetentionJob::default(), at(1_700_009_001))
            .await,
        Err(MaintenanceError::InvalidJob(_))
    ));
    Ok(())
}

#[tokio::test]
async fn repeated_prunes_advance_the_anchor_monotonically() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("state.db");
    let pool = seeded_db(&path, 6).await?;
    let log = AuditLog::new(pool.clone());

    let first = log
        .retention_prune(None, Some(4), at(1_700_009_000))
        .await?;
    assert_eq!(first.pruned_through_id, Some(2));
    let second = log
        .retention_prune(None, Some(2), at(1_700_009_001))
        .await?;
    assert_eq!(second.pruned_through_id, Some(4));
    assert_eq!(second.pruned_rows, 2);

    // A prune with nothing to do leaves the anchor alone.
    let idle = log
        .retention_prune(None, Some(100), at(1_700_009_002))
        .await?;
    assert_eq!(idle.pruned_rows, 0);
    assert_eq!(idle.pruned_through_id, None);
    let anchor_id: i64 =
        sqlx::query_scalar("SELECT pruned_through_id FROM audit_log_anchor WHERE singleton = 1")
            .fetch_one(&pool)
            .await?;
    assert_eq!(anchor_id, 4);

    let chain = log.verify_chain(ChainScope::All).await?;
    assert!(chain.is_valid());
    assert_eq!(chain.checked, 2);
    Ok(())
}

#[tokio::test]
async fn disk_pressure_report_math_is_exact() -> anyhow::Result<()> {
    let directory = tempdir()?;

    let relaxed = DbMaintenance::disk_pressure(directory.path(), 1)?;
    assert!(relaxed.available_bytes > 0);
    assert!(!relaxed.low);
    assert_eq!(relaxed.shortfall_bytes, 0);

    let floor = u64::MAX;
    let pressured = DbMaintenance::disk_pressure(directory.path(), floor)?;
    assert!(pressured.low);
    assert_eq!(pressured.shortfall_bytes, floor - pressured.available_bytes);
    assert_eq!(pressured.min_free_bytes, floor);

    let missing = DbMaintenance::disk_pressure(&directory.path().join("nope"), 1);
    assert!(matches!(missing, Err(MaintenanceError::Io(_))));
    Ok(())
}
