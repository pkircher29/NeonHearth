use chrono::{DateTime, TimeZone, Utc};
use lattice_domain::{Coverage, DeviceId, EvidenceFamily, PresenceState};
use lattice_store::{
    CheckpointError, M2StateConfig, M2StateRepository, MAX_SNAPSHOT_DEVICES, connect_path,
};
use tempfile::tempdir;

fn at(second: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(second, 0).single().unwrap()
}
fn id(value: &str) -> DeviceId {
    DeviceId::parse(value).unwrap()
}
fn ids() -> [DeviceId; 3] {
    [
        id("018f47a0-9b5c-7a22-8a33-112233445501"),
        id("018f47a0-9b5c-7a22-8a33-112233445502"),
        id("018f47a0-9b5c-7a22-8a33-112233445503"),
    ]
}
async fn insert_device(
    pool: &sqlx::SqlitePool,
    device: &DeviceId,
    first: i64,
    last: i64,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_name,owner_type,owner_confirmed) VALUES(?,?,?,?,?,?)")
        .bind(device.to_string()).bind(at(first).to_rfc3339()).bind(at(last).to_rfc3339())
        .bind("Paul").bind("resident").bind(1_i64).execute(pool).await?;
    Ok(())
}
fn corrupt(error: Result<Vec<lattice_store::StoredDeviceSnapshot>, CheckpointError>) {
    assert!(
        matches!(error, Err(CheckpointError::Corrupt(_))),
        "expected corrupt, got {error:?}"
    );
}

#[tokio::test]
async fn snapshot_limits_order_keyset_and_reopen_are_stable() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("snapshots.db");
    let pool = connect_path(&path).await?;
    let repo = M2StateRepository::with_config(
        pool.clone(),
        M2StateConfig {
            max_snapshot_devices: 3,
            ..Default::default()
        },
    )?;
    assert!(repo.list_device_snapshots(1, None).await?.is_empty());
    assert!(matches!(
        repo.list_device_snapshots(0, None).await,
        Err(CheckpointError::Invalid(_))
    ));
    assert!(matches!(
        repo.list_device_snapshots(4, None).await,
        Err(CheckpointError::Capacity(_))
    ));
    let default_repo = M2StateRepository::new(pool.clone());
    assert!(
        default_repo
            .list_device_snapshots(MAX_SNAPSHOT_DEVICES, None)
            .await?
            .is_empty()
    );
    assert!(matches!(
        M2StateRepository::with_config(
            pool.clone(),
            M2StateConfig {
                max_snapshot_devices: MAX_SNAPSHOT_DEVICES + 1,
                ..Default::default()
            }
        ),
        Err(CheckpointError::Invalid(_))
    ));
    let [a, b, c] = ids();
    for device in [&c, &a, &b] {
        insert_device(&pool, device, 10, 20).await?;
    }
    let first = repo.list_device_snapshots(2, None).await?;
    assert_eq!(
        first.iter().map(|x| x.device_id).collect::<Vec<_>>(),
        vec![a, b]
    );
    assert!(first.iter().all(|x| x.first_seen_at == at(10)
        && x.last_seen_at == at(20)
        && x.owner_name.as_deref() == Some("Paul")
        && x.owner_type.as_deref() == Some("resident")
        && x.owner_confirmed));
    let second = repo
        .list_device_snapshots(2, Some(first[1].device_id))
        .await?;
    assert_eq!(
        second.iter().map(|x| x.device_id).collect::<Vec<_>>(),
        vec![c]
    );
    let joined: Vec<_> = first.iter().chain(&second).map(|x| x.device_id).collect();
    assert_eq!(joined, vec![a, b, c]);
    drop(repo);
    drop(pool);
    let reopened = M2StateRepository::new(connect_path(&path).await?);
    assert_eq!(
        reopened
            .list_device_snapshots(3, None)
            .await?
            .iter()
            .map(|x| x.device_id)
            .collect::<Vec<_>>(),
        joined
    );
    Ok(())
}

#[tokio::test]
async fn snapshot_rejects_parseable_noncanonical_device_ids_before_keyset_pagination()
-> anyhow::Result<()> {
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    let [first, _, last] = ids();
    insert_device(&pool, &first, 1, 2).await?;
    insert_device(&pool, &last, 1, 2).await?;
    let noncanonical = format!("{{{last}}}");
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at) VALUES(?,?,?)")
        .bind(&noncanonical)
        .bind(at(1).to_rfc3339())
        .bind(at(2).to_rfc3339())
        .execute(&pool)
        .await?;
    corrupt(repo.list_device_snapshots(3, None).await);
    corrupt(repo.list_device_snapshots(3, Some(first)).await);
    Ok(())
}

#[tokio::test]
async fn snapshot_selects_latest_presence_and_reports_corrupt_presence() -> anyhow::Result<()> {
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    let device = ids()[0];
    insert_device(&pool, &device, 1, 9).await?;
    for (transition_id, state, occurred_at, source, kind) in [
        (1, "online", 5, "a", "first"),
        (2, "quiet", 6, "b", "second"),
        (3, "offline", 6, "c", "winner"),
    ] {
        sqlx::query("INSERT INTO presence_transitions(transition_id,device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,trigger_arrival_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(transition_id).bind(device.to_string()).bind("unknown").bind(state).bind(at(occurred_at).to_rfc3339()).bind("test").bind(source).bind(kind).bind(at(occurred_at).to_rfc3339()).bind(at(occurred_at).to_rfc3339()).execute(&pool).await?;
    }
    let presence = repo.list_device_snapshots(1, None).await?[0]
        .presence
        .clone()
        .unwrap();
    assert_eq!(presence.to_state, PresenceState::Offline);
    assert_eq!(presence.occurred_at, at(6));
    assert_eq!(presence.trigger_source, "c");
    assert_eq!(presence.trigger_kind, "winner");
    for (column, value) in [
        ("to_state", "invalid"),
        ("occurred_at", "invalid"),
        ("trigger_source", ""),
        ("trigger_kind", ""),
    ] {
        sqlx::query("UPDATE presence_transitions SET to_state='offline', occurred_at=?, trigger_source='good', trigger_kind='good' WHERE transition_id=3").bind(at(6).to_rfc3339()).execute(&pool).await?;
        sqlx::query(&format!(
            "UPDATE presence_transitions SET {column}=? WHERE transition_id=3"
        ))
        .bind(value)
        .execute(&pool)
        .await?;
        corrupt(repo.list_device_snapshots(1, None).await);
    }
    sqlx::query("UPDATE presence_transitions SET trigger_source=? WHERE transition_id=3")
        .bind("x".repeat(4097))
        .execute(&pool)
        .await?;
    corrupt(repo.list_device_snapshots(1, None).await);
    Ok(())
}

#[tokio::test]
async fn snapshot_selects_evidence_without_secret_fields_and_keeps_expiry() -> anyhow::Result<()> {
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    let device = ids()[0];
    insert_device(&pool, &device, 1, 9).await?;
    for (family, source, key, value, confidence, observed, expires) in [
        ("naming", "old", "key", "secret-old", 0.8, 5, None),
        (
            "addressing",
            "newer",
            "mac",
            "02:aa:bb:cc:dd:ee",
            0.9,
            6,
            None,
        ),
        (
            "service",
            "winner",
            "token",
            "synthetic-secret",
            0.9,
            6,
            Some(9),
        ),
    ] {
        sqlx::query("INSERT INTO evidence(device_id,family,source,fact_key,fact_value,confidence,observed_at,expires_at) VALUES(?,?,?,?,?,?,?,?)").bind(device.to_string()).bind(family).bind(source).bind(key).bind(value).bind(confidence).bind(at(observed).to_rfc3339()).bind(expires.map(|x| at(x).to_rfc3339())).execute(&pool).await?;
    }
    let evidence = repo.list_device_snapshots(1, None).await?[0]
        .evidence
        .clone()
        .unwrap();
    assert_eq!(evidence.family, EvidenceFamily::Service);
    assert_eq!(evidence.source, "winner");
    assert_eq!(evidence.confidence, 0.9);
    assert_eq!(evidence.observed_at, at(6));
    assert_eq!(evidence.expires_at, Some(at(9)));
    let debug = format!("{evidence:?}");
    assert!(
        !debug.contains("synthetic-secret") && !debug.contains("token") && !debug.contains("02:aa")
    );
    sqlx::query("PRAGMA ignore_check_constraints=ON")
        .execute(&pool)
        .await?;
    for (column, value) in [
        ("family", "invalid"),
        ("confidence", "2"),
        ("observed_at", "invalid"),
        ("source", ""),
    ] {
        sqlx::query("UPDATE evidence SET family='service', confidence=.9, observed_at=?, source='good' WHERE evidence_id=3").bind(at(6).to_rfc3339()).execute(&pool).await?;
        sqlx::query(&format!(
            "UPDATE evidence SET {column}=? WHERE evidence_id=3"
        ))
        .bind(value)
        .execute(&pool)
        .await?;
        corrupt(repo.list_device_snapshots(1, None).await);
    }
    sqlx::query("UPDATE evidence SET source=? WHERE evidence_id=3")
        .bind("x".repeat(4097))
        .execute(&pool)
        .await?;
    corrupt(repo.list_device_snapshots(1, None).await);
    Ok(())
}

#[tokio::test]
async fn snapshot_aggregates_only_latest_second_bucket() -> anyhow::Result<()> {
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    let device = ids()[0];
    insert_device(&pool, &device, 1, 9).await?;
    assert_eq!(
        repo.list_device_snapshots(1, None).await?[0].bandwidth,
        None
    );
    for (resolution, bucket, interface, up, down, coverage) in [
        ("second", 4, 1, 99, 99, "complete"),
        ("second", 5, 1, 10, 20, "complete"),
        ("second", 5, 2, 30, 40, "local-only"),
        ("minute", 6, 1, 500, 600, "complete"),
        ("hour", 7, 1, 700, 800, "complete"),
    ] {
        sqlx::query("INSERT INTO flow_rollups(resolution,bucket,device_id,protocol,destination,interface,upload,download,coverage,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(resolution).bind(at(bucket).to_rfc3339()).bind(device.to_string()).bind("tcp").bind("lan").bind(interface).bind(up).bind(down).bind(coverage).bind(at(bucket).to_rfc3339()).execute(&pool).await?;
    }
    let bw = repo.list_device_snapshots(1, None).await?[0]
        .bandwidth
        .clone()
        .unwrap();
    assert_eq!(
        (bw.upload, bw.download, bw.coverage, bw.observed_at),
        (40, 60, Coverage::Estimated, at(5))
    );
    sqlx::query("UPDATE flow_rollups SET bucket=? WHERE resolution='second' AND interface=2")
        .bind(at(6).to_rfc3339())
        .execute(&pool)
        .await?;
    let bw = repo.list_device_snapshots(1, None).await?[0]
        .bandwidth
        .clone()
        .unwrap();
    assert_eq!(
        (bw.upload, bw.download, bw.coverage, bw.observed_at),
        (30, 40, Coverage::LocalOnly, at(6))
    );
    sqlx::query("PRAGMA ignore_check_constraints=ON")
        .execute(&pool)
        .await?;
    for (column, value) in [
        ("coverage", "invalid"),
        ("bucket", "invalid"),
        ("upload", "-1"),
    ] {
        sqlx::query("UPDATE flow_rollups SET coverage='complete', bucket=?, upload=1 WHERE resolution='second' AND interface=2").bind(at(6).to_rfc3339()).execute(&pool).await?;
        sqlx::query(&format!(
            "UPDATE flow_rollups SET {column}=? WHERE resolution='second' AND interface=2"
        ))
        .bind(value)
        .execute(&pool)
        .await?;
        corrupt(repo.list_device_snapshots(1, None).await);
    }
    // SQLite INTEGER is signed, so a u64 sum overflow cannot be inserted; checked_add still guards aggregate conversion.
    Ok(())
}

#[tokio::test]
async fn snapshot_corrupt_base_rows_and_migration_indexes_are_detected() -> anyhow::Result<()> {
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    let device = ids()[0];
    insert_device(&pool, &device, 1, 9).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT MAX(version) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await?,
        14
    );
    for index in ["presence_transitions_snapshot_idx", "evidence_snapshot_idx"] {
        assert!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pragma_index_list(?) WHERE name=?")
                .bind(if index.starts_with("presence") {
                    "presence_transitions"
                } else {
                    "evidence"
                })
                .bind(index)
                .fetch_one(&pool)
                .await?
                == 1
        );
    }
    sqlx::query("PRAGMA ignore_check_constraints=ON")
        .execute(&pool)
        .await?;
    for (column, value) in [
        ("device_id", "bad"),
        ("first_seen_at", "invalid"),
        ("last_seen_at", "invalid"),
        ("owner_confirmed", "2"),
        ("owner_name", ""),
        ("owner_type", ""),
    ] {
        sqlx::query("UPDATE devices SET device_id=?, first_seen_at=?, last_seen_at=?, owner_confirmed=1, owner_name='Paul', owner_type='resident'").bind(device.to_string()).bind(at(1).to_rfc3339()).bind(at(9).to_rfc3339()).execute(&pool).await?;
        sqlx::query(&format!("UPDATE devices SET {column}=?"))
            .bind(value)
            .execute(&pool)
            .await?;
        corrupt(repo.list_device_snapshots(1, None).await);
    }
    sqlx::query("UPDATE devices SET first_seen_at=?, last_seen_at=?, owner_name='Paul', owner_type='resident', owner_confirmed=1")
        .bind(at(10).to_rfc3339())
        .bind(at(9).to_rfc3339())
        .execute(&pool)
        .await?;
    corrupt(repo.list_device_snapshots(1, None).await);
    sqlx::query("UPDATE devices SET first_seen_at=?, last_seen_at=?, owner_name='Paul', owner_type='resident', owner_confirmed=1")
        .bind(at(1).to_rfc3339())
        .bind(at(9).to_rfc3339())
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE devices SET owner_name=?")
        .bind("x".repeat(4097))
        .execute(&pool)
        .await?;
    corrupt(repo.list_device_snapshots(1, None).await);
    Ok(())
}
