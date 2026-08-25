use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{ByteCount, Coverage, DeviceId, EvidenceFact, EvidenceFamily};
use lattice_intelligence::presence::PresenceEvidenceKind;
use lattice_sensor::flow::{
    DestinationCategory, Protocol, Resolution, Rollup, RollupChange, RollupKey,
};
use lattice_service::discovery::{
    DiscoveryObservation, DiscoveryPipelineOutcome, DiscoverySources, PersistentDiscoveryPipeline,
};
use lattice_store::connect_path;
use lattice_store::{M2StateRepository, connect_memory};
use tempfile::tempdir;

fn at(second: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(second, 0).single().unwrap()
}
fn id(n: u8) -> DeviceId {
    DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}
fn observation(t: chrono::DateTime<Utc>) -> DiscoveryObservation {
    DiscoveryObservation {
        source_id: 1,
        candidate: None,
        facts: vec![
            EvidenceFact {
                family: EvidenceFamily::LinkLayer,
                source: "sensor-a".into(),
                key: "mac".into(),
                value: "00:11:22:33:44:55".into(),
                confidence: 0.96,
                observed_at: t,
                expires_at: Some(t + Duration::seconds(30)),
                owner_confirmed: false,
            },
            EvidenceFact {
                family: EvidenceFamily::Service,
                source: "sensor-a".into(),
                key: "class".into(),
                value: "camera".into(),
                confidence: 0.96,
                observed_at: t,
                expires_at: Some(t + Duration::seconds(30)),
                owner_confirmed: false,
            },
        ],
        presence_source: "sensor-a".into(),
        presence_kind: PresenceEvidenceKind::Traffic,
        observed_at: t,
        valid_until: Some(t + Duration::seconds(30)),
    }
}

#[tokio::test]
async fn reopen_restores_checkpoint_and_duplicate_is_still_inert() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("persistent.db");
    let sources = || {
        DiscoverySources::sensor(
            1,
            "sensor-a",
            vec![EvidenceFamily::LinkLayer, EvidenceFamily::Service],
        )
    };
    let t = at(1_700_000_100);
    {
        let pool = connect_path(&path).await?;
        let repo = M2StateRepository::new(pool.clone());
        let mut pipeline = PersistentDiscoveryPipeline::open(
            repo,
            sources()?,
            [id(1), id(2)].into_iter(),
            Default::default(),
            32,
            32,
        )
        .await?;
        assert!(matches!(
            pipeline
                .observe_with_flow(observation(t), &[rollup(id(1), t)], 0, t)
                .await?,
            DiscoveryPipelineOutcome::Committed(_)
        ));
    }
    let pool = connect_path(&path).await?;
    let repo = M2StateRepository::new(pool.clone());
    let mut reopened = PersistentDiscoveryPipeline::open(
        repo.clone(),
        sources()?,
        [id(9)].into_iter(),
        Default::default(),
        32,
        32,
    )
    .await?;
    assert_eq!(reopened.commit_sequence(), 1);
    assert!(matches!(
        reopened
            .observe_with_flow(
                observation(t),
                &[rollup(id(1), t)],
                250,
                t + Duration::milliseconds(250)
            )
            .await?,
        DiscoveryPipelineOutcome::Duplicate(_)
    ));
    assert_eq!(
        repo.load(&reopened.source_fingerprint())
            .await?
            .unwrap()
            .commit_sequence,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM flow_rollups")
            .fetch_one(&pool)
            .await?,
        1
    );
    Ok(())
}

#[tokio::test]
async fn corrupt_checkpoint_and_source_mismatch_refuse_open() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    let mut pipeline = PersistentDiscoveryPipeline::open(
        repo,
        DiscoverySources::sensor(
            1,
            "sensor-a",
            vec![EvidenceFamily::LinkLayer, EvidenceFamily::Service],
        )?,
        [id(1)].into_iter(),
        Default::default(),
        32,
        32,
    )
    .await?;
    let t = at(1_700_000_200);
    pipeline
        .observe_with_flow(observation(t), &[rollup(id(1), t)], 0, t)
        .await?;
    sqlx::query("UPDATE state_checkpoints SET sha256=zeroblob(32)")
        .execute(&pool)
        .await?;
    let err = PersistentDiscoveryPipeline::open(
        M2StateRepository::new(pool.clone()),
        DiscoverySources::sensor(
            1,
            "sensor-a",
            vec![EvidenceFamily::LinkLayer, EvidenceFamily::Service],
        )?,
        [id(2)].into_iter(),
        Default::default(),
        32,
        32,
    )
    .await;
    assert!(err.is_err());
    let pool = connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    let mut pipeline = PersistentDiscoveryPipeline::open(
        repo,
        DiscoverySources::sensor(
            1,
            "sensor-a",
            vec![EvidenceFamily::LinkLayer, EvidenceFamily::Service],
        )?,
        [id(1)].into_iter(),
        Default::default(),
        32,
        32,
    )
    .await?;
    pipeline
        .observe_with_flow(observation(t), &[rollup(id(1), t)], 0, t)
        .await?;
    let mismatch = PersistentDiscoveryPipeline::open(
        M2StateRepository::new(pool.clone()),
        DiscoverySources::sensor(
            1,
            "renamed-sensor",
            vec![EvidenceFamily::LinkLayer, EvidenceFamily::Service],
        )?,
        [id(2)].into_iter(),
        Default::default(),
        32,
        32,
    )
    .await;
    assert!(mismatch.is_err());
    Ok(())
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

#[tokio::test]
async fn persistent_pipeline_commits_and_duplicate_does_not_advance() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repo = M2StateRepository::new(pool.clone());
    let mut pipeline = PersistentDiscoveryPipeline::open(
        repo.clone(),
        DiscoverySources::sensor(
            1,
            "sensor-a",
            vec![EvidenceFamily::LinkLayer, EvidenceFamily::Service],
        )?,
        [id(1), id(2)].into_iter(),
        Default::default(),
        32,
        32,
    )
    .await?;
    let t = at(1_700_000_000);
    let first = pipeline
        .observe_with_flow(observation(t), &[rollup(id(1), t)], 0, t)
        .await?;
    assert!(matches!(first, DiscoveryPipelineOutcome::Committed(_)));
    let second = pipeline
        .observe_with_flow(
            observation(t),
            &[rollup(id(1), t)],
            10,
            t + Duration::milliseconds(10),
        )
        .await?;
    assert!(matches!(second, DiscoveryPipelineOutcome::Duplicate(_)));
    assert_eq!(
        repo.load(&pipeline.source_fingerprint())
            .await?
            .unwrap()
            .commit_sequence,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM flow_rollups")
            .fetch_one(&pool)
            .await?,
        1
    );
    Ok(())
}
