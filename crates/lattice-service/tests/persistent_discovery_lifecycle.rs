use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{ByteCount, Coverage, DeviceId, EvidenceFact, EvidenceFamily, PresenceState};
use lattice_intelligence::presence::PresenceEvidenceKind;
use lattice_sensor::flow::{
    DestinationCategory, Protocol, Resolution, Rollup, RollupChange, RollupKey,
};
use lattice_service::discovery::{
    CommittedDiscovery, DiscoveryObservation, DiscoveryPipelineOutcome, DiscoverySources,
    PersistentDiscoveryPipeline,
};
use lattice_store::{M2StateRepository, connect_path};
use tempfile::tempdir;

fn at(second: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(second, 0).single().unwrap()
}

fn id(n: u8) -> DeviceId {
    DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}

fn sources() -> DiscoverySources {
    DiscoverySources::sensor(
        7,
        "registered-sensor",
        vec![
            EvidenceFamily::LinkLayer,
            EvidenceFamily::Naming,
            EvidenceFamily::Service,
        ],
    )
    .unwrap()
}

fn discovery_observation(t: chrono::DateTime<Utc>, suffix: &str) -> DiscoveryObservation {
    DiscoveryObservation {
        source_id: 7,
        candidate: None,
        facts: vec![
            EvidenceFact {
                family: EvidenceFamily::LinkLayer,
                source: "registered-sensor".into(),
                key: "mac".into(),
                value: format!("00:11:22:33:44:{suffix}"),
                confidence: 0.96,
                observed_at: t,
                expires_at: Some(t + Duration::minutes(10)),
                owner_confirmed: false,
            },
            EvidenceFact {
                family: EvidenceFamily::Service,
                source: "registered-sensor".into(),
                key: "onvif_uuid".into(),
                value: format!("camera-{suffix}"),
                confidence: 0.96,
                observed_at: t,
                expires_at: Some(t + Duration::minutes(10)),
                owner_confirmed: false,
            },
            EvidenceFact {
                family: EvidenceFamily::Naming,
                source: "registered-sensor".into(),
                key: "vendor".into(),
                value: "Acme".into(),
                confidence: 0.96,
                observed_at: t,
                expires_at: Some(t + Duration::minutes(10)),
                owner_confirmed: false,
            },
            EvidenceFact {
                family: EvidenceFamily::Service,
                source: "registered-sensor".into(),
                key: "class".into(),
                value: "camera".into(),
                confidence: 0.96,
                observed_at: t,
                expires_at: Some(t + Duration::minutes(10)),
                owner_confirmed: false,
            },
        ],
        presence_source: "registered-sensor".into(),
        presence_kind: PresenceEvidenceKind::Traffic,
        observed_at: t,
        valid_until: Some(t + Duration::seconds(30)),
    }
}

fn presence_observation(
    device_id: DeviceId,
    kind: PresenceEvidenceKind,
    observed_at: chrono::DateTime<Utc>,
) -> DiscoveryObservation {
    DiscoveryObservation {
        source_id: 7,
        candidate: Some(device_id),
        facts: vec![],
        presence_source: "registered-sensor".into(),
        presence_kind: kind,
        observed_at,
        valid_until: Some(observed_at + Duration::seconds(30)),
    }
}

fn rollup(device_id: DeviceId, t: chrono::DateTime<Utc>) -> RollupChange {
    RollupChange::Upsert(Rollup {
        key: RollupKey {
            resolution: Resolution::Second,
            bucket: t,
            device_id,
            protocol: Protocol::Tcp,
            destination: DestinationCategory::Internet,
            interface: 2,
            metadata: None,
        },
        bytes: ByteCount {
            upload: 12,
            download: 24,
        },
        coverage: Coverage::LocalOnly,
        metadata: None,
    })
}

async fn open(
    pool: sqlx::SqlitePool,
    ids: impl Iterator<Item = DeviceId> + Send,
) -> anyhow::Result<PersistentDiscoveryPipeline> {
    Ok(PersistentDiscoveryPipeline::open(
        M2StateRepository::new(pool),
        sources(),
        ids,
        Default::default(),
        32,
        32,
    )
    .await?)
}

async fn commit(
    pipeline: &mut PersistentDiscoveryPipeline,
    observation: DiscoveryObservation,
    changes: &[RollupChange],
    arrival: chrono::DateTime<Utc>,
) -> anyhow::Result<Box<CommittedDiscovery>> {
    match pipeline
        .observe_with_flow(observation, changes, 0, arrival)
        .await?
    {
        DiscoveryPipelineOutcome::Committed(committed) => Ok(committed),
        DiscoveryPipelineOutcome::Duplicate(_) => anyhow::bail!("unexpected duplicate"),
    }
}

#[tokio::test]
async fn stable_identity_confidence_and_online_state_survive_a_real_reopen() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("lifecycle.db");
    let t = at(1_700_001_000);
    let device_id;
    {
        let pool = connect_path(&path).await?;
        let mut pipeline = open(pool.clone(), [id(1), id(2)].into_iter()).await?;
        let first = commit(
            &mut pipeline,
            discovery_observation(t, "55"),
            &[rollup(id(1), t)],
            t,
        )
        .await?;
        device_id = first.result.device_id;
        let second = commit(
            &mut pipeline,
            discovery_observation(t + Duration::seconds(1), "55"),
            &[rollup(device_id, t + Duration::seconds(1))],
            t + Duration::seconds(1),
        )
        .await?;
        assert_eq!(second.result.device_id, device_id);
        assert!(
            second
                .result
                .identification
                .is_some_and(|x| x.confidence >= 0.85)
        );
        assert_eq!(
            pipeline.presence_state(device_id),
            Some(PresenceState::Online)
        );
        let committed_sources: Vec<String> =
            sqlx::query_scalar("SELECT source FROM discovery_commits ORDER BY committed_at")
                .fetch_all(&pool)
                .await?;
        assert_eq!(
            committed_sources,
            vec!["registered-sensor", "registered-sensor"]
        );
        let coverage: Vec<String> =
            sqlx::query_scalar("SELECT coverage FROM flow_rollups ORDER BY bucket")
                .fetch_all(&pool)
                .await?;
        assert_eq!(coverage, vec!["local-only", "local-only"]);
    }

    let pool = connect_path(&path).await?;
    let mut reopened = open(pool, [id(9)].into_iter()).await?;
    assert_eq!(reopened.commit_sequence(), 2);
    assert_eq!(
        reopened.presence_state(device_id),
        Some(PresenceState::Online)
    );
    let later = commit(
        &mut reopened,
        discovery_observation(t + Duration::seconds(10), "55"),
        &[rollup(device_id, t + Duration::seconds(10))],
        t + Duration::seconds(10),
    )
    .await?;
    assert_eq!(later.result.device_id, device_id);
    assert!(
        later
            .result
            .identification
            .is_some_and(|x| x.confidence >= 0.85)
    );
    Ok(())
}

#[tokio::test]
async fn departure_reopen_and_late_evidence_preserve_exact_correction_lineage() -> anyhow::Result<()>
{
    let dir = tempdir()?;
    let path = dir.path().join("correction.db");
    let t = at(1_700_002_000);
    let device_id;
    let departure_id;
    {
        let pool = connect_path(&path).await?;
        let mut pipeline = open(pool, [id(1), id(2)].into_iter()).await?;
        device_id = commit(
            &mut pipeline,
            discovery_observation(t, "55"),
            &[rollup(id(1), t)],
            t,
        )
        .await?
        .result
        .device_id;
        commit(
            &mut pipeline,
            discovery_observation(t + Duration::seconds(1), "55"),
            &[rollup(device_id, t + Duration::seconds(1))],
            t + Duration::seconds(1),
        )
        .await?;
        commit(
            &mut pipeline,
            presence_observation(
                device_id,
                PresenceEvidenceKind::ConfirmationFailure,
                t + Duration::seconds(40),
            ),
            &[],
            t + Duration::seconds(40),
        )
        .await?;
        let departure = commit(
            &mut pipeline,
            presence_observation(
                device_id,
                PresenceEvidenceKind::ConfirmationFailure,
                t + Duration::seconds(41),
            ),
            &[],
            t + Duration::seconds(41),
        )
        .await?;
        let transition = departure
            .result
            .presence
            .iter()
            .find(|transition| transition.to == PresenceState::Offline)
            .expect("second failure records departure");
        departure_id = transition.transition_id;
        assert_eq!(
            pipeline.presence_state(device_id),
            Some(PresenceState::Offline)
        );
    }

    let pool = connect_path(&path).await?;
    let mut reopened = open(pool.clone(), [id(9)].into_iter()).await?;
    assert_eq!(
        reopened.presence_state(device_id),
        Some(PresenceState::Offline)
    );
    let correction = commit(
        &mut reopened,
        presence_observation(
            device_id,
            PresenceEvidenceKind::Traffic,
            t + Duration::seconds(20),
        ),
        &[],
        t + Duration::seconds(42),
    )
    .await?;
    let transition = correction
        .result
        .presence
        .iter()
        .find(|transition| transition.correction_of == Some(departure_id))
        .expect("late traffic records a correction");
    assert_eq!(transition.to, PresenceState::Online);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT correction_of FROM presence_transitions WHERE transition_id=?"
        )
        .bind(transition.transition_id as i64)
        .fetch_one(&pool)
        .await?,
        departure_id as i64
    );
    Ok(())
}

#[tokio::test]
async fn invalid_flow_and_duplicate_retries_leave_durable_and_live_state_inert()
-> anyhow::Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("rollback.db");
    let pool = connect_path(&path).await?;
    let mut pipeline = open(pool.clone(), [id(1), id(2)].into_iter()).await?;
    let t = at(1_700_003_000);
    assert!(
        pipeline
            .observe_with_flow(discovery_observation(t, "55"), &[rollup(id(2), t)], 0, t,)
            .await
            .is_err()
    );
    assert_eq!(pipeline.commit_sequence(), 0);
    let first = commit(
        &mut pipeline,
        discovery_observation(t, "55"),
        &[rollup(id(1), t)],
        t,
    )
    .await?;
    assert_eq!(first.result.device_id, id(1));
    let second_observation = discovery_observation(t + Duration::seconds(1), "55");
    let second_changes = [rollup(id(1), t + Duration::seconds(1))];
    commit(
        &mut pipeline,
        second_observation.clone(),
        &second_changes,
        t + Duration::seconds(1),
    )
    .await?;
    let transition_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM presence_transitions")
        .fetch_one(&pool)
        .await?;
    let flow_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM flow_rollups")
        .fetch_one(&pool)
        .await?;
    let flow_bytes: (i64, i64) =
        sqlx::query_as("SELECT SUM(upload),SUM(download) FROM flow_rollups")
            .fetch_one(&pool)
            .await?;
    let duplicate = pipeline
        .observe_with_flow(
            second_observation,
            &second_changes,
            250,
            t + Duration::milliseconds(1250),
        )
        .await?;
    assert!(matches!(duplicate, DiscoveryPipelineOutcome::Duplicate(_)));
    assert_eq!(pipeline.commit_sequence(), 2);
    assert_eq!(pipeline.presence_state(id(1)), Some(PresenceState::Online));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM presence_transitions")
            .fetch_one(&pool)
            .await?,
        transition_count
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM flow_rollups")
            .fetch_one(&pool)
            .await?,
        flow_count
    );
    assert_eq!(
        sqlx::query_as::<_, (i64, i64)>("SELECT SUM(upload),SUM(download) FROM flow_rollups")
            .fetch_one(&pool)
            .await?,
        flow_bytes
    );
    Ok(())
}

#[tokio::test]
async fn stale_pipeline_cas_failure_requires_reopen_but_does_not_leak_staged_state()
-> anyhow::Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("stale.db");
    let pool = connect_path(&path).await?;
    let mut winner = open(pool.clone(), [id(1), id(2)].into_iter()).await?;
    let mut stale = open(pool.clone(), [id(1), id(2)].into_iter()).await?;
    let t = at(1_700_004_000);
    commit(
        &mut winner,
        discovery_observation(t, "55"),
        &[rollup(id(1), t)],
        t,
    )
    .await?;
    let stale_input = discovery_observation(t + Duration::seconds(1), "66");
    let stale_flow = [rollup(id(1), t + Duration::seconds(1))];
    assert!(
        stale
            .observe_with_flow(
                stale_input.clone(),
                &stale_flow,
                0,
                t + Duration::seconds(1),
            )
            .await
            .is_err()
    );
    assert_eq!(stale.commit_sequence(), 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM discovery_commits")
            .fetch_one(&pool)
            .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM flow_rollups")
            .fetch_one(&pool)
            .await?,
        1
    );
    drop(stale);
    let mut recovered = open(pool.clone(), [id(9)].into_iter()).await?;
    let recovered_commit = commit(
        &mut recovered,
        stale_input,
        &[rollup(id(2), t + Duration::seconds(1))],
        t + Duration::seconds(1),
    )
    .await?;
    assert_eq!(recovered_commit.result.device_id, id(2));
    assert_eq!(recovered.commit_sequence(), 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM discovery_commits")
            .fetch_one(&pool)
            .await?,
        2
    );
    Ok(())
}
