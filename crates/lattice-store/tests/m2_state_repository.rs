use chrono::{TimeZone, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily, PresenceChanged, PresenceState};
use lattice_store::{
    CheckpointError, CheckpointInput, CommitInput, DeviceProjection, DiscoveryCommit,
    EvidenceProjection, M2StateRepository, connect_path,
};
use tempfile::tempdir;

fn time(second: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(second, 0).single().unwrap()
}
fn device() -> DeviceId {
    DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445599").unwrap()
}
fn input(sequence: i64, hash: [u8; 32]) -> CommitInput {
    let at = time(1_700_000_000 + sequence);
    CommitInput {
        checkpoint: CheckpointInput {
            format_version: 1,
            bytes: br#"{"version":1}"#.to_vec(),
            source_fingerprint: "sensor-config-v1".into(),
            commit_sequence: sequence,
            written_at: at,
        },
        devices: vec![DeviceProjection {
            device_id: device(),
            first_seen_at: time(1_699_999_000),
            last_seen_at: at,
            owner_name: Some("Paul".into()),
            owner_type: Some("resident".into()),
            owner_confirmed: true,
        }],
        evidence: vec![EvidenceProjection {
            device_id: device(),
            fact: EvidenceFact {
                family: EvidenceFamily::LinkLayer,
                source: "mdns".into(),
                key: "mac".into(),
                value: "00:11:22:33:44:55".into(),
                confidence: 0.9,
                observed_at: at,
                expires_at: None,
                owner_confirmed: false,
            },
        }],
        transitions: vec![PresenceChanged {
            transition_id: sequence as u64,
            device_id: device(),
            from: PresenceState::Unknown,
            to: PresenceState::Online,
            occurred_at: at,
            reason: "observed".into(),
            trigger_source: "mdns".into(),
            trigger_kind: "alive".into(),
            evidence_observed_at: at,
            evidence_valid_until: None,
            trigger_arrival_at: at,
            correction_of: None,
        }],
        discovery: Some(DiscoveryCommit {
            input_hash: hash,
            source: "mdns".into(),
            result_summary: br#"{"devices":1}"#.to_vec(),
            committed_at: at,
        }),
    }
}

#[tokio::test]
async fn save_close_reopen_loads_exact_checkpoint_and_projections() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("m2.db");
    let pool = connect_path(&path).await?;
    let repo = M2StateRepository::new(pool.clone());
    let commit = input(1, [7; 32]);
    repo.commit(commit.clone()).await?;
    drop(repo);
    drop(pool);
    let reopened = M2StateRepository::new(connect_path(&path).await?);
    let loaded = reopened.load("sensor-config-v1").await?.unwrap();
    assert_eq!(loaded.bytes, commit.checkpoint.bytes);
    assert_eq!(loaded.commit_sequence, 1);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM evidence")
        .fetch_one(&connect_path(&path).await?)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn identical_retry_is_idempotent_but_changed_payload_conflicts() -> anyhow::Result<()> {
    let repo = M2StateRepository::new(lattice_store::connect_memory().await?);
    let original = input(1, [8; 32]);
    repo.commit(original.clone()).await?;
    repo.commit(original.clone()).await?;
    let mut changed = original;
    changed.discovery.as_mut().unwrap().result_summary = br#"{"devices":2}"#.to_vec();
    assert!(matches!(
        repo.commit(changed).await,
        Err(CheckpointError::Conflict(_))
    ));
    Ok(())
}

#[tokio::test]
async fn sequential_checkpoint_cas_advances_and_preserves_projections() -> anyhow::Result<()> {
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    repo.commit(input(1, [21; 32])).await?;
    repo.commit(input(2, [22; 32])).await?;
    assert_eq!(
        repo.load("sensor-config-v1")
            .await?
            .unwrap()
            .commit_sequence,
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM presence_transitions")
            .fetch_one(&pool)
            .await?,
        2
    );
    Ok(())
}

#[tokio::test]
async fn retry_detects_a_corrupt_or_diverged_checkpoint() -> anyhow::Result<()> {
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    let commit = input(1, [23; 32]);
    repo.commit(commit.clone()).await?;
    sqlx::query("UPDATE state_checkpoints SET checkpoint_bytes=x'7b7d'")
        .execute(&pool)
        .await?;
    assert!(matches!(
        repo.commit(commit).await,
        Err(CheckpointError::Corrupt(_))
    ));
    Ok(())
}

#[tokio::test]
async fn projections_have_owner_precedence_and_canonical_retry_order() -> anyhow::Result<()> {
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    let mut original = input(1, [24; 32]);
    let second = DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445598").unwrap();
    let mut second_device = original.devices[0].clone();
    second_device.device_id = second;
    let mut second_evidence = original.evidence[0].clone();
    second_evidence.device_id = second;
    let mut second_transition = original.transitions[0].clone();
    second_transition.device_id = second;
    second_transition.transition_id = 99;
    original.devices.push(second_device);
    original.evidence.push(second_evidence);
    original.transitions.push(second_transition);
    repo.commit(original.clone()).await?;
    let mut retry = original.clone();
    retry.devices.reverse();
    retry.evidence.reverse();
    retry.transitions.reverse();
    repo.commit(retry).await?;
    let mut next = input(2, [25; 32]);
    next.devices[0].owner_name = Some("Mallory".into());
    next.devices[0].owner_confirmed = false;
    repo.commit(next).await?;
    let owner: String = sqlx::query_scalar("SELECT owner_name FROM devices WHERE device_id=?")
        .bind(device().to_string())
        .fetch_one(&pool)
        .await?;
    assert_eq!(owner, "Paul");
    Ok(())
}

#[tokio::test]
async fn rejects_duplicate_and_impossible_projection_values_before_mutation() -> anyhow::Result<()>
{
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool);
    let mut duplicate = input(1, [26; 32]);
    duplicate.devices.push(duplicate.devices[0].clone());
    assert!(matches!(
        repo.commit(duplicate).await,
        Err(CheckpointError::Invalid(_))
    ));
    let mut impossible = input(1, [27; 32]);
    impossible.transitions[0].from = PresenceState::Online;
    impossible.transitions[0].to = PresenceState::Online;
    impossible.transitions[0].correction_of = Some(1);
    assert!(matches!(
        repo.commit(impossible).await,
        Err(CheckpointError::Invalid(_))
    ));
    Ok(())
}

#[tokio::test]
async fn corrupt_checksum_fingerprint_version_json_and_timestamp_fail_closed() -> anyhow::Result<()>
{
    for (column, value) in [
        ("sha256", "zeroblob(32)"),
        ("format_version", "99"),
        ("checkpoint_bytes", "x'6e6f7065'"),
        ("written_at", "'not-a-time'"),
    ] {
        let pool = lattice_store::connect_memory().await?;
        let repo = M2StateRepository::new(pool.clone());
        repo.commit(input(1, [9; 32])).await?;
        sqlx::query(&format!("UPDATE state_checkpoints SET {column}={value}"))
            .execute(&pool)
            .await?;
        assert!(matches!(
            repo.load("sensor-config-v1").await,
            Err(CheckpointError::Corrupt(_))
        ));
    }
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    repo.commit(input(1, [9; 32])).await?;
    sqlx::query("UPDATE state_checkpoints SET source_fingerprint='wrong'")
        .execute(&pool)
        .await?;
    assert!(matches!(
        repo.load("sensor-config-v1").await,
        Err(CheckpointError::Corrupt(_))
    ));
    Ok(())
}

#[tokio::test]
async fn invalid_commit_rolls_back_checkpoint_and_all_projections() -> anyhow::Result<()> {
    let pool = lattice_store::connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    repo.commit(input(1, [1; 32])).await?;
    let mut invalid = input(2, [2; 32]);
    invalid.evidence[0].fact.confidence = 2.0;
    assert!(matches!(
        repo.commit(invalid).await,
        Err(CheckpointError::Invalid(_))
    ));
    assert_eq!(
        repo.load("sensor-config-v1")
            .await?
            .unwrap()
            .commit_sequence,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM presence_transitions")
            .fetch_one(&pool)
            .await?,
        1
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_first_sequences_return_a_typed_conflict() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let pool = connect_path(dir.path().join("concurrent.db")).await?;
    let repo = M2StateRepository::new(pool);
    let (left, right) = tokio::join!(
        repo.commit(input(1, [3; 32])),
        repo.commit(input(1, [4; 32]))
    );
    assert!(left.is_ok() ^ right.is_ok());
    let loser = if left.is_ok() { right } else { left };
    assert!(matches!(loser, Err(CheckpointError::Conflict(_))));
    Ok(())
}

#[tokio::test]
async fn migration_sets_current_version_and_enforces_m2_foreign_keys_and_indexes()
-> anyhow::Result<()> {
    let pool = lattice_store::connect_memory().await?;
    let install = lattice_store::InstallRepository::new(pool.clone())
        .initialize(time(0))
        .await?;
    assert_eq!(install.schema_version, 3);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT schema_version FROM install_state WHERE singleton=1")
            .fetch_one(&pool)
            .await?,
        3
    );
    let indexes: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_index_list('evidence')")
        .fetch_all(&pool)
        .await?;
    assert!(
        indexes
            .iter()
            .any(|name| name == "evidence_semantic_identity_idx")
    );
    let fk = sqlx::query("INSERT INTO presence_transitions(transition_id,device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,trigger_arrival_at) VALUES(99,'missing','unknown','online','2026-08-23T00:00:00Z','test','test','test','2026-08-23T00:00:00Z','2026-08-23T00:00:00Z')").execute(&pool).await;
    assert!(fk.is_err());
    Ok(())
}
