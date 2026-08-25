use chrono::{DateTime, TimeZone, Utc};
use lattice_store::{
    AppendedEntry, AuditActor, AuditCategory, AuditFilter, AuditLog, AuditLogError, AuditPage,
    ChainBreakKind, ChainScope, MAX_ACTION_BYTES, MAX_DETAIL_BYTES, NewAuditEntry, connect_memory,
    connect_path, genesis_hash,
};
use serde_json::json;
use tempfile::tempdir;

fn at(second: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(second, 0).single().unwrap()
}

fn entry(index: i64) -> NewAuditEntry {
    NewAuditEntry {
        occurred_at: at(1_700_000_000 + index),
        actor: AuditActor::Service,
        category: AuditCategory::Scan,
        action: format!("scan.completed.{index}"),
        subject: Some(format!("subnet-{}", index % 3)),
        detail: json!({"index": index, "hosts": index * 2}),
    }
}

const RECREATE_UPDATE_TRIGGER: &str = "CREATE TRIGGER audit_log_no_update \
     BEFORE UPDATE ON audit_log BEGIN \
     SELECT RAISE(ABORT, 'audit_log is append-only'); END";

#[tokio::test]
async fn chain_verifies_over_many_entries_and_reopen() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("audit.db");
    let pool = connect_path(&path).await?;
    let log = AuditLog::new(pool.clone());

    let mut previous_hash = genesis_hash();
    for index in 0..60 {
        let appended = log.append(entry(index)).await?;
        assert_eq!(appended.id, index + 1);
        assert_eq!(appended.prev_hash, previous_hash);
        previous_hash = appended.entry_hash.clone();
    }

    let report = log.verify_chain(ChainScope::All).await?;
    assert!(report.is_valid());
    assert!(report.anchored);
    assert_eq!(report.checked, 60);
    assert_eq!(report.start_id, Some(1));
    assert_eq!(report.end_id, Some(60));

    // A tail window verifies without reaching the trusted root.
    let tail = log.verify_chain(ChainScope::Tail(10)).await?;
    assert!(tail.is_valid());
    assert!(!tail.anchored);
    assert_eq!(tail.checked, 10);
    assert_eq!(tail.start_id, Some(51));

    // A tail wider than the log falls back to the trusted root.
    let wide = log.verify_chain(ChainScope::Tail(1_000)).await?;
    assert!(wide.is_valid());
    assert!(wide.anchored);
    assert_eq!(wide.checked, 60);

    // The chain survives a reopen.
    pool.close().await;
    let pool = connect_path(&path).await?;
    let log = AuditLog::new(pool);
    let report = log.verify_chain(ChainScope::All).await?;
    assert!(report.is_valid());
    assert_eq!(report.checked, 60);
    Ok(())
}

#[tokio::test]
async fn update_and_delete_are_refused_at_the_sql_layer() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let log = AuditLog::new(pool.clone());
    for index in 0..3 {
        log.append(entry(index)).await?;
    }

    let update = sqlx::query("UPDATE audit_log SET action = 'tampered' WHERE id = 1")
        .execute(&pool)
        .await;
    assert!(
        update
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("append-only"),
        "unexpected: {update:?}"
    );
    let delete = sqlx::query("DELETE FROM audit_log WHERE id = 2")
        .execute(&pool)
        .await;
    assert!(
        delete
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("append-only"),
        "unexpected: {delete:?}"
    );

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 3);
    assert!(log.verify_chain(ChainScope::All).await?.is_valid());
    Ok(())
}

#[tokio::test]
async fn tampered_detail_is_detected_at_the_right_break_index() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let log = AuditLog::new(pool.clone());
    for index in 0..10 {
        log.append(entry(index)).await?;
    }

    // Simulate out-of-band tampering: drop the guard trigger, edit row 5,
    // restore the trigger.
    sqlx::query("DROP TRIGGER audit_log_no_update")
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE audit_log SET detail = '{\"index\":999}' WHERE id = 5")
        .execute(&pool)
        .await?;
    sqlx::query(RECREATE_UPDATE_TRIGGER).execute(&pool).await?;

    let report = log.verify_chain(ChainScope::All).await?;
    assert!(!report.is_valid());
    let broke = report.first_break.unwrap();
    assert_eq!(broke.id, 5);
    assert_eq!(broke.kind, ChainBreakKind::EntryHashMismatch);
    assert_eq!(report.checked, 4);
    Ok(())
}

#[tokio::test]
async fn recomputed_entry_hash_still_breaks_the_next_link() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let log = AuditLog::new(pool.clone());
    for index in 0..6 {
        log.append(entry(index)).await?;
    }

    // A smarter tamperer rewrites the row's own entry_hash to something
    // internally consistent-looking; the successor's prev_hash then fails.
    sqlx::query("DROP TRIGGER audit_log_no_update")
        .execute(&pool)
        .await?;
    let fake_hash = "0".repeat(64);
    sqlx::query("UPDATE audit_log SET entry_hash = ? WHERE id = 3")
        .bind(&fake_hash)
        .execute(&pool)
        .await?;
    sqlx::query(RECREATE_UPDATE_TRIGGER).execute(&pool).await?;

    let report = log.verify_chain(ChainScope::All).await?;
    let broke = report.first_break.unwrap();
    // Row 3 itself no longer matches its recomputed hash.
    assert_eq!(broke.id, 3);
    assert_eq!(broke.kind, ChainBreakKind::EntryHashMismatch);
    Ok(())
}

#[tokio::test]
async fn copied_database_with_edited_row_fails_verification() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let source = directory.path().join("audit.db");
    let pool = connect_path(&source).await?;
    let log = AuditLog::new(pool.clone());
    for index in 0..8 {
        log.append(entry(index)).await?;
    }
    // Flush WAL so the copied file is complete on its own.
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await?;
    pool.close().await;

    let copy = directory.path().join("copy.db");
    std::fs::copy(&source, &copy)?;
    let pool = connect_path(&copy).await?;
    sqlx::query("DROP TRIGGER audit_log_no_update")
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE audit_log SET action = 'rewritten-history' WHERE id = 2")
        .execute(&pool)
        .await?;
    sqlx::query(RECREATE_UPDATE_TRIGGER).execute(&pool).await?;

    let report = AuditLog::new(pool).verify_chain(ChainScope::All).await?;
    let broke = report.first_break.unwrap();
    assert_eq!(broke.id, 2);
    assert_eq!(broke.kind, ChainBreakKind::EntryHashMismatch);

    // The original database is untouched and still verifies.
    let pool = connect_path(&source).await?;
    assert!(
        AuditLog::new(pool)
            .verify_chain(ChainScope::All)
            .await?
            .is_valid()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_appends_keep_a_valid_chain() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let pool = connect_path(directory.path().join("audit.db")).await?;
    let log = AuditLog::new(pool.clone());

    let mut tasks = Vec::new();
    for task in 0..8i64 {
        let log = log.clone();
        tasks.push(tokio::spawn(async move {
            let mut ids = Vec::new();
            for step in 0..5i64 {
                let appended = log.append(entry(task * 100 + step)).await?;
                ids.push(appended.id);
            }
            Ok::<_, AuditLogError>(ids)
        }));
    }
    let mut all_ids = Vec::new();
    for task in tasks {
        all_ids.extend(task.await??);
    }
    all_ids.sort_unstable();
    assert_eq!(all_ids, (1..=40).collect::<Vec<i64>>());

    let report = log.verify_chain(ChainScope::All).await?;
    assert!(report.is_valid(), "chain broke: {report:?}");
    assert_eq!(report.checked, 40);
    Ok(())
}

#[tokio::test]
async fn filters_and_keyset_paging_work() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let log = AuditLog::new(pool);
    for index in 0..9 {
        let mut e = entry(index);
        e.actor = if index % 2 == 0 {
            AuditActor::Owner
        } else {
            AuditActor::Module
        };
        e.category = if index % 3 == 0 {
            AuditCategory::Approval
        } else {
            AuditCategory::Enforcement
        };
        log.append(e).await?;
    }

    // Category filter with paging: ids 1, 4, 7 are approvals.
    let approvals = |after| AuditPage {
        after_id: after,
        limit: 2,
    };
    let filter = AuditFilter {
        category: Some(AuditCategory::Approval),
        ..AuditFilter::default()
    };
    let first: Vec<i64> = log
        .list(&filter, approvals(None))
        .await?
        .iter()
        .map(|e| e.id)
        .collect();
    assert_eq!(first, vec![1, 4]);
    let second: Vec<i64> = log
        .list(&filter, approvals(Some(4)))
        .await?
        .iter()
        .map(|e| e.id)
        .collect();
    assert_eq!(second, vec![7]);

    // Actor + subject filters compose.
    let owner_subnet0 = log
        .list(
            &AuditFilter {
                actor: Some(AuditActor::Owner),
                subject: Some("subnet-0".into()),
                ..AuditFilter::default()
            },
            AuditPage {
                after_id: None,
                limit: 100,
            },
        )
        .await?;
    // Owner entries are the even indices (ids 1,3,5,7,9); subnet-0 entries
    // are indices divisible by three (ids 1,4,7); the intersection is 1 and 7.
    assert_eq!(
        owner_subnet0.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![1, 7]
    );
    assert!(
        owner_subnet0
            .iter()
            .all(|e: &AppendedEntry| e.actor == AuditActor::Owner)
    );

    // Time range is inclusive-since, exclusive-until.
    let window = log
        .list(
            &AuditFilter {
                since: Some(at(1_700_000_003)),
                until: Some(at(1_700_000_006)),
                ..AuditFilter::default()
            },
            AuditPage {
                after_id: None,
                limit: 100,
            },
        )
        .await?;
    assert_eq!(
        window.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![4, 5, 6]
    );

    // Page limit bounds are typed errors.
    assert!(matches!(
        log.list(
            &AuditFilter::default(),
            AuditPage {
                after_id: None,
                limit: 0
            }
        )
        .await,
        Err(AuditLogError::Invalid(_))
    ));
    Ok(())
}

#[tokio::test]
async fn oversized_fields_are_rejected_before_any_write() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let log = AuditLog::new(pool.clone());

    let mut bad = entry(0);
    bad.action = "x".repeat(MAX_ACTION_BYTES + 1);
    assert!(matches!(
        log.append(bad).await,
        Err(AuditLogError::Invalid(_))
    ));

    let mut bad = entry(0);
    bad.detail = json!({ "blob": "x".repeat(MAX_DETAIL_BYTES) });
    assert!(matches!(
        log.append(bad).await,
        Err(AuditLogError::Invalid(_))
    ));

    let mut bad = entry(0);
    bad.subject = Some(String::new());
    assert!(matches!(
        log.append(bad).await,
        Err(AuditLogError::Invalid(_))
    ));

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 0);
    Ok(())
}
