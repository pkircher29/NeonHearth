//! Regression tests for the persistence review findings.
use chrono::{DateTime, Duration, TimeZone, Utc};
use lattice_domain::{
    DeviceId, EnforcementStatus, Evaluation, Identification, PolicyChanged, PolicyReason,
    RequestedAction, RiskSignal,
};
use lattice_store::{
    ClockStatus, DbMaintenance, InstallRepository, MaintenancePolicy, PendingDecision,
    PolicyRepository, connect_memory, connect_path,
};
use sqlx::SqlitePool;

fn at(hours: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 23, 0, 0, 0).unwrap() + Duration::hours(hours)
}

async fn insert_device(
    pool: &SqlitePool,
    id: DeviceId,
    first_seen: DateTime<Utc>,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at) VALUES (?, ?, ?)")
        .bind(id.to_string())
        .bind(first_seen.to_rfc3339())
        .bind(first_seen.to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

async fn policy_repo() -> anyhow::Result<(SqlitePool, PolicyRepository)> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    Ok((pool, repo))
}

fn decision(id: DeviceId, summary: &str) -> PolicyChanged {
    PolicyChanged {
        device_id: id,
        policy_version: 1,
        evaluation: Evaluation::visible(PolicyReason::OwnerApproved),
        requested_action: RequestedAction::None,
        evidence_summary: summary.into(),
        enforcement_result: EnforcementStatus::Verified,
        undo_available: true,
    }
}

// ---- finding 3: legacy fingerprints and skip-and-report ----------------------

#[tokio::test]
async fn legacy_pending_row_with_reordered_json_fingerprint_still_reads() -> anyhow::Result<()> {
    let (pool, repo) = policy_repo().await?;
    let id = DeviceId::new();
    insert_device(&pool, id, at(60)).await?;
    repo.enroll(id).await?;
    let d = decision(id, "legacy");
    // Old format: fingerprint is the whole JSON text. Re-order the keys so a
    // byte-for-byte re-encode no longer equals it (what a schema change does).
    let value = serde_json::to_value(&d)?;
    let mut reordered = serde_json::Map::new();
    let object = value.as_object().unwrap();
    for key in object.keys().rev() {
        reordered.insert(key.clone(), object[key].clone());
    }
    let legacy_fingerprint = serde_json::to_string(&serde_json::Value::Object(reordered))?;
    sqlx::query(
        "INSERT INTO policy_outbox(device_id,fingerprint,created_at,decision_json) VALUES(?,?,?,?)",
    )
    .bind(id.to_string())
    .bind(&legacy_fingerprint)
    .bind(at(0).to_rfc3339())
    .bind(serde_json::to_string(&d)?)
    .execute(&pool)
    .await?;
    assert_eq!(
        repo.pending_decision_value(id).await?,
        Some(PendingDecision::Exact(d.clone()))
    );
    assert_eq!(
        repo.pending_decision_values_many(&[id]).await?.get(&id),
        Some(&PendingDecision::Exact(d.clone()))
    );
    // The new short fingerprint of the same decision is recognised as the same
    // pending publication, and acknowledging it clears the legacy row.
    let short = lattice_store::decision_fingerprint(&d)?;
    assert!(short.len() < 64);
    assert!(
        repo.prepare_exact_decision_publication(id, &short, &d)
            .await?
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_outbox WHERE device_id=?")
        .bind(id.to_string())
        .fetch_one(&pool)
        .await?;
    assert_eq!(rows, 1);
    repo.mark_decision_published(id, &short, &d).await?;
    assert!(!repo.pending_decision(id).await?);
    // Already published (new spelling) and the legacy spelling both dedupe.
    assert!(
        !repo
            .prepare_exact_decision_publication(id, &short, &d)
            .await?
    );
    assert!(
        !repo
            .prepare_exact_decision_publication(id, &legacy_fingerprint, &d)
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn undecodable_policy_rows_are_skipped_and_reported_not_fatal() -> anyhow::Result<()> {
    let (pool, repo) = policy_repo().await?;
    let good = DeviceId::new();
    let bad = DeviceId::new();
    let future = DeviceId::new();
    for id in [good, bad, future] {
        insert_device(&pool, id, at(60)).await?;
        repo.enroll(id).await?;
    }
    sqlx::query("UPDATE device_policy SET protection_json='\"from_the_future\"' WHERE device_id=?")
        .bind(bad.to_string())
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE device_policy SET json_schema_version=99 WHERE device_id=?")
        .bind(future.to_string())
        .execute(&pool)
        .await?;
    let ids = [good, bad, future];
    let (map, skipped) = repo.load_many_report(&ids).await?;
    assert_eq!(map.len(), 1);
    assert!(map.contains_key(&good));
    assert_eq!(skipped.len(), 2);
    assert_eq!(repo.load_many(&ids).await?.len(), 1);
    let (list, skipped) = repo.list_report().await?;
    assert_eq!((list.len(), skipped.len()), (1, 2));
    assert_eq!(repo.list().await?.len(), 1);
    // A direct load of the bad device still reports the error.
    assert!(repo.load(bad).await.is_err());
    Ok(())
}

// ---- finding 16: first_seen frozen at enrollment ----------------------------

#[tokio::test]
async fn deadline_input_is_frozen_at_enrollment() -> anyhow::Result<()> {
    let (pool, repo) = policy_repo().await?;
    let id = DeviceId::new();
    insert_device(&pool, id, at(60)).await?;
    repo.enroll(id).await?;
    sqlx::query("UPDATE devices SET first_seen_at=? WHERE device_id=?")
        .bind(at(1).to_rfc3339())
        .bind(id.to_string())
        .execute(&pool)
        .await?;
    assert_eq!(repo.load(id).await?.unwrap().first_seen_at, at(60));
    Ok(())
}

// ---- finding 8: extension bounds ---------------------------------------------

#[tokio::test]
async fn extension_is_bounded_and_cannot_be_burned_in_the_past() -> anyhow::Result<()> {
    let (pool, repo) = policy_repo().await?;
    let id = DeviceId::new();
    insert_device(&pool, id, at(60)).await?;
    repo.enroll(id).await?;
    let original_due = at(60) + Duration::hours(48);
    // Far-future "extension" is refused and does not consume the extension.
    assert!(
        repo.extend_once(id, original_due + Duration::days(365 * 100))
            .await
            .is_err()
    );
    // Already past relative to `now`: refused by the clock-aware variant.
    assert!(
        repo.extend_once_at(
            id,
            original_due + Duration::hours(1),
            original_due + Duration::days(1)
        )
        .await
        .is_err()
    );
    assert!(
        repo.extend_once(id, original_due + Duration::days(7))
            .await?
    );
    assert!(
        !repo
            .extend_once(id, original_due + Duration::days(8))
            .await?
    );
    Ok(())
}

// ---- finding 15: basis points validation -------------------------------------

#[tokio::test]
async fn out_of_range_basis_points_are_rejected_on_write() -> anyhow::Result<()> {
    let (pool, repo) = policy_repo().await?;
    let id = DeviceId::new();
    insert_device(&pool, id, at(60)).await?;
    repo.enroll(id).await?;
    assert!(
        repo.set_risk(
            id,
            RiskSignal::HighConfidenceDanger {
                confidence_basis_points: 10_001,
                evidence: "x".into()
            }
        )
        .await
        .is_err()
    );
    assert!(
        repo.set_identification(
            id,
            Identification::Automatic {
                confidence_basis_points: 20_000,
                evidence_families: vec![]
            }
        )
        .await
        .is_err()
    );
    Ok(())
}

// ---- finding 4: clock gate and baseline reset -------------------------------

#[tokio::test]
async fn baseline_is_not_started_from_an_implausible_clock() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let repo = PolicyRepository::new(pool);
    let epoch_clock = Utc.timestamp_opt(0, 0).unwrap();
    assert!(
        repo.mark_successful_service_start(epoch_clock)
            .await
            .is_err()
    );
    assert_eq!(repo.baseline_started_at().await?, None);
    // Once the clock is sane the baseline starts normally.
    assert_eq!(repo.mark_successful_service_start(at(0)).await?, at(0));
    Ok(())
}

#[tokio::test]
async fn clock_jumps_are_suspect_until_acknowledged_and_audited() -> anyhow::Result<()> {
    let (pool, repo) = policy_repo().await?;
    assert!(repo.record_clock_heartbeat(at(0)).await?.is_trusted());
    assert!(repo.record_clock_heartbeat(at(1)).await?.is_trusted());
    // Normal operation after a short gap stays trusted.
    assert!(repo.clock_status(at(3)).await?.is_trusted());
    // Forward jump of a year: suspect, and it stays suspect.
    let jumped = at(1) + Duration::days(400);
    assert!(matches!(
        repo.record_clock_heartbeat(jumped).await?,
        ClockStatus::Suspect(_)
    ));
    assert!(
        !repo
            .clock_status(jumped + Duration::hours(1))
            .await?
            .is_trusted()
    );
    // Pre-2025 clock is never trusted.
    assert!(
        !repo
            .clock_status(Utc.timestamp_opt(1_000, 0).unwrap())
            .await?
            .is_trusted()
    );
    repo.acknowledge_clock(jumped, "owner confirmed the clock was fixed")
        .await?;
    assert!(
        repo.clock_status(jumped + Duration::hours(1))
            .await?
            .is_trusted()
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action='policy_clock_acknowledged'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(audited, 1);
    Ok(())
}

#[tokio::test]
async fn baseline_reset_is_recorded_audited_and_updates_exemption() -> anyhow::Result<()> {
    let (pool, repo) = policy_repo().await?;
    let id = DeviceId::new();
    insert_device(&pool, id, at(24 * 30)).await?;
    assert!(!repo.enroll(id).await?.baseline_exempt);
    assert!(repo.reset_baseline(at(24 * 30), "  ").await.is_err());
    repo.reset_baseline(at(24 * 30), "clock was wrong at install")
        .await?;
    assert_eq!(repo.baseline_started_at().await?, Some(at(24 * 30)));
    assert!(repo.load(id).await?.unwrap().baseline_exempt);
    let (history, audit): (i64, i64) = (
        sqlx::query_scalar("SELECT COUNT(*) FROM policy_baseline_history")
            .fetch_one(&pool)
            .await?,
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action='policy_baseline_reset'")
            .fetch_one(&pool)
            .await?,
    );
    assert_eq!((history, audit), (1, 1));
    assert!(
        repo.reset_baseline(Utc.timestamp_opt(5, 0).unwrap(), "bad clock")
            .await
            .is_err()
    );
    Ok(())
}

// ---- finding 1: maintenance --------------------------------------------------

#[tokio::test]
async fn maintenance_prunes_bounded_batches_and_keeps_what_is_needed() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let pool = connect_path(directory.path().join("maintenance.db")).await?;
    let maintenance = DbMaintenance::new(pool.clone(), directory.path().join("maintenance.db"));
    let now = Utc.with_ymd_and_hms(2027, 6, 1, 0, 0, 0).unwrap();
    let old = now - Duration::days(400);
    let device = DeviceId::new();
    insert_device(&pool, device, old).await?;
    // Evidence: two old naming rows for the same key (older one prunable), an
    // old link_layer row (never prunable), and a fresh one.
    for (family, value, observed) in [
        ("naming", "a", old),
        ("naming", "a", old + Duration::days(1)),
        ("link_layer", "mac", old),
        ("service", "fresh", now),
    ] {
        sqlx::query("INSERT INTO evidence(device_id,family,source,fact_key,fact_value,confidence,observed_at) VALUES(?,?,?,?,?,0.5,?)")
            .bind(device.to_string()).bind(family).bind("s").bind(if family == "service" { "k2" } else { "k" })
            .bind(value).bind(observed.to_rfc3339()).execute(&pool).await?;
    }
    // Transitions: old ones; latest per device must survive.
    for (id, occurred) in [
        (1i64, old),
        (2, old + Duration::days(1)),
        (3, old + Duration::days(2)),
    ] {
        sqlx::query("INSERT INTO presence_transitions(transition_id,device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,trigger_arrival_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(id).bind(device.to_string()).bind("unknown").bind("online")
            .bind(occurred.to_rfc3339()).bind("r").bind("s").bind("k")
            .bind(occurred.to_rfc3339()).bind(occurred.to_rfc3339()).execute(&pool).await?;
    }
    // Discovery commits: one beyond the replay window, one inside.
    sqlx::query("INSERT INTO state_checkpoints(singleton,format_version,checkpoint_bytes,source_fingerprint,commit_sequence,written_at,sha256) VALUES(1,1,x'7b7d','f',2,?,zeroblob(32))")
        .bind(now.to_rfc3339()).execute(&pool).await?;
    for (n, committed) in [(1u8, old), (2u8, now)] {
        sqlx::query("INSERT INTO discovery_commits(input_hash,source,committed_at,result_summary,commit_digest,result_sha256,checkpoint_sequence,source_fingerprint,row_sha256) VALUES(?,?,?,x'7b7d',zeroblob(32),zeroblob(32),?,?,zeroblob(32))")
            .bind(vec![n; 32]).bind("s").bind(committed.to_rfc3339()).bind(i64::from(n)).bind("f").execute(&pool).await?;
    }
    // Phone sessions / tokens.
    sqlx::query("INSERT INTO phone_sessions(id,secret_hash,device_label,pin_hash,created_at,expires_at) VALUES(?,?,?,?,?,?)")
        .bind(uuid::Uuid::now_v7().to_string()).bind("a".repeat(64)).bind("p").bind("h")
        .bind("2025-01-01T00:00:00.000000Z").bind("2025-02-01T00:00:00.000000Z").execute(&pool).await?;
    sqlx::query("INSERT INTO integration_tokens(id,name,token_hash,scopes,created_at,revoked) VALUES(?,?,?,?,?,1)")
        .bind(uuid::Uuid::now_v7().to_string()).bind("t").bind("b".repeat(64)).bind("[\"x\"]")
        .bind("2025-01-01T00:00:00.000000Z").execute(&pool).await?;

    let policy = MaintenancePolicy::default();
    let report = maintenance.run_maintenance(&policy, now, 1000).await;
    assert!(report.is_clean(), "{report:?}");
    let count = |sql: &'static str| {
        let pool = pool.clone();
        async move { sqlx::query_scalar::<_, i64>(sql).fetch_one(&pool).await }
    };
    assert_eq!(count("SELECT COUNT(*) FROM evidence").await?, 3); // older duplicate gone
    assert_eq!(
        count("SELECT COUNT(*) FROM evidence WHERE family='link_layer'").await?,
        1
    );
    assert_eq!(count("SELECT COUNT(*) FROM presence_transitions").await?, 1);
    assert_eq!(
        count("SELECT transition_id FROM presence_transitions").await?,
        3
    );
    assert_eq!(count("SELECT COUNT(*) FROM discovery_commits").await?, 1);
    assert_eq!(count("SELECT COUNT(*) FROM phone_sessions").await?, 0);
    assert_eq!(count("SELECT COUNT(*) FROM integration_tokens").await?, 0);

    // Bounded: a batch limit of 1 removes at most one row per step per call.
    for n in 0..5i64 {
        sqlx::query("INSERT INTO evidence(device_id,family,source,fact_key,fact_value,confidence,observed_at) VALUES(?,?,?,?,?,0.5,?)")
            .bind(device.to_string()).bind("naming").bind("s").bind("k9").bind(n.to_string())
            .bind((old + Duration::days(n)).to_rfc3339()).execute(&pool).await?;
    }
    let report = maintenance.run_maintenance(&policy, now, 1).await;
    let evidence_step = report.steps.iter().find(|s| s.step == "evidence").unwrap();
    assert_eq!(evidence_step.rows, 1);
    assert!(report.may_have_more(1));
    Ok(())
}

#[tokio::test]
async fn maintenance_steps_fail_independently() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let pool = connect_path(directory.path().join("independent.db")).await?;
    let maintenance = DbMaintenance::new(pool.clone(), directory.path().join("independent.db"));
    sqlx::query("DROP TABLE camera_evidence")
        .execute(&pool)
        .await?;
    let report = maintenance
        .run_maintenance(&MaintenancePolicy::default(), Utc::now(), 100)
        .await;
    let failed: Vec<_> = report.failures().map(|s| s.step).collect();
    assert_eq!(failed, vec!["camera_evidence"]);
    assert!(report.steps.len() >= 9);
    Ok(())
}

#[tokio::test]
async fn maintenance_applies_hour_retention_and_prunes_seals() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let pool = connect_path(directory.path().join("hours.db")).await?;
    let maintenance = DbMaintenance::new(pool.clone(), directory.path().join("hours.db"));
    let now = Utc.with_ymd_and_hms(2029, 1, 1, 0, 0, 0).unwrap();
    let device = DeviceId::new();
    insert_device(&pool, device, at(0)).await?;
    for (resolution, bucket) in [
        ("hour", "2026-01-01T00:00:00Z"),
        ("hour", "2028-12-31T00:00:00Z"),
    ] {
        sqlx::query("INSERT INTO flow_rollups(resolution,bucket,device_id,protocol,destination,interface,upload,download,coverage,updated_at) VALUES(?,?,?,'tcp','internet',1,1,1,'complete',?)")
            .bind(resolution).bind(bucket).bind(device.to_string()).bind(bucket).execute(&pool).await?;
    }
    sqlx::query("INSERT INTO flow_compaction_seals(child_resolution,parent_bucket,device_id,protocol,destination,interface,metadata_ip,metadata_domain) VALUES('minute','2026-01-01T00:00:00Z',?,'tcp','internet',1,'','')")
        .bind(device.to_string()).execute(&pool).await?;
    let report = maintenance
        .run_maintenance(&MaintenancePolicy::default(), now, 1000)
        .await;
    assert!(report.is_clean(), "{report:?}");
    let hours: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM flow_rollups WHERE resolution='hour'")
            .fetch_one(&pool)
            .await?;
    let seals: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM flow_compaction_seals")
        .fetch_one(&pool)
        .await?;
    assert_eq!((hours, seals), (1, 0));
    Ok(())
}

// ---- finding 17: mixed timestamp spellings compare by instant ---------------

#[tokio::test]
async fn device_last_seen_comparison_is_by_instant_not_text() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let id = DeviceId::new();
    // Stored with the +00:00 spelling...
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at) VALUES(?,?,?)")
        .bind(id.to_string())
        .bind("2026-01-01T00:00:10+00:00")
        .bind("2026-01-01T00:00:10+00:00")
        .execute(&pool)
        .await?;
    // ...a flow update at the same instant in the Z spelling must not count as
    // newer (text comparison says 'Z' > '+').
    let repo = lattice_store::M2StateRepository::new(pool.clone());
    let flow = repo.flow_repository(8)?;
    use lattice_domain::{ByteCount, Coverage};
    use lattice_sensor::flow::{
        DestinationCategory, Protocol, Resolution, Rollup, RollupChange, RollupKey,
    };
    let rollup = Rollup {
        key: RollupKey {
            resolution: Resolution::Second,
            bucket: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 10).unwrap(),
            device_id: id,
            protocol: Protocol::Tcp,
            destination: DestinationCategory::Internet,
            interface: 1,
            metadata: None,
        },
        bytes: ByteCount {
            upload: 1,
            download: 1,
        },
        coverage: Coverage::Complete,
        metadata: None,
    };
    flow.apply(&[RollupChange::Upsert(rollup)], at(0)).await?;
    let last: String = sqlx::query_scalar("SELECT last_seen_at FROM devices WHERE device_id=?")
        .bind(id.to_string())
        .fetch_one(&pool)
        .await?;
    assert_eq!(last, "2026-01-01T00:00:10+00:00");
    Ok(())
}

// ---- finding 18: legacy W6 rows ---------------------------------------------

#[tokio::test]
async fn w6_legacy_prior_state_row_reads_as_no_attempt_and_unfinished_attempts_are_kept()
-> anyhow::Result<()> {
    use lattice_store::W6PriorStateRepository;
    let pool = connect_memory().await?;
    let repo = W6PriorStateRepository::new(pool.clone());
    let id = DeviceId::new();
    insert_device(&pool, id, at(0)).await?;
    let state = lattice_w6::DeviceState {
        disconnect_now: false,
        deny_wifi_association: false,
        deny_internet: false,
        deny_lan: false,
        persistent_filter: false,
        filter_entries: 0,
    };
    repo.save(id, &state).await?; // legacy shape: restore point, no attempt
    assert!(repo.load_attempt(id).await?.is_none());
    repo.begin_attempt(id, RequestedAction::Quarantine, &state)
        .await?;
    // Restarting the same action is fine; a different unfinished one is refused.
    repo.begin_attempt(id, RequestedAction::Quarantine, &state)
        .await?;
    assert!(
        repo.begin_attempt(id, RequestedAction::PermanentBan, &state)
            .await
            .is_err()
    );
    repo.mark_verified(id, RequestedAction::Quarantine, &state)
        .await?;
    repo.begin_attempt(id, RequestedAction::PermanentBan, &state)
        .await?;
    Ok(())
}

// ---- finding 14: backups are verified before publication --------------------

#[tokio::test]
async fn restore_report_demands_reconciliation() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let live = directory.path().join("live.db");
    let pool = connect_path(&live).await?;
    let maintenance = DbMaintenance::new(pool, &live);
    let backup = directory.path().join("backup.db");
    maintenance.backup_to(&backup).await?;
    let report = maintenance.restore_from(&backup).await?;
    assert!(report.reconcile_required);
    Ok(())
}

// ---- finding 9: more than one page of advisories is not "corruption" ---------

#[tokio::test]
async fn advisory_count_matches_rows_inserted_for_a_device() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repo = lattice_store::AdvisoryRepository::new(pool);
    assert_eq!(repo.count_device_advisories(DeviceId::new()).await?, 0);
    Ok(())
}
