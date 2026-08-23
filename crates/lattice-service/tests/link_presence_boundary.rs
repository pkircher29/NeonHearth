use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{ByteCount, Coverage, EvidenceFamily, PresenceState};
use lattice_sensor::flow::{
    DestinationCategory, Protocol, Resolution, Rollup, RollupChange, RollupKey,
};
use lattice_sensor::neighbor::LinkAddress;
use lattice_service::discovery::{
    DiscoveryError, DiscoveryPipelineOutcome, DiscoverySource, DiscoverySources, LinkPresenceKind,
    LinkPresenceObservation, PersistentDiscoveryPipeline,
};
use lattice_store::{M2StateRepository, connect_memory, connect_path};
use tempfile::tempdir;

fn at(s: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(s, 0).single().unwrap()
}
fn link(n: u8) -> LinkAddress {
    LinkAddress::try_from([2, 0, 0, 0, 0, n]).unwrap()
}
fn id(n: u8) -> lattice_domain::DeviceId {
    lattice_domain::DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}
async fn pipeline() -> (
    sqlx::SqlitePool,
    M2StateRepository,
    PersistentDiscoveryPipeline,
) {
    let pool = connect_memory().await.unwrap();
    let repo = M2StateRepository::new(pool.clone());
    let sources =
        DiscoverySources::sensor(1, "synthetic", vec![EvidenceFamily::LinkLayer]).unwrap();
    let pipeline = PersistentDiscoveryPipeline::open(
        repo.clone(),
        sources,
        [id(1), id(2), id(3)].into_iter(),
        Default::default(),
        16,
        16,
    )
    .await
    .unwrap();
    (pool, repo, pipeline)
}
fn present(source_id: u64, mac: LinkAddress, t: chrono::DateTime<Utc>) -> LinkPresenceObservation {
    LinkPresenceObservation {
        source_id,
        link_address: mac,
        observed_at: t,
        kind: LinkPresenceKind::Present {
            valid_until: t + Duration::seconds(30),
        },
    }
}

#[tokio::test]
async fn present_allocates_then_reuses_exact_binding_without_new_evidence() {
    let (pool, _repo, mut p) = pipeline().await;
    let t = at(1_700_000_000);
    let first = p
        .observe_link_presence_with_flow(present(1, link(1), t), &[], 0, t)
        .await
        .unwrap();
    let committed = match first {
        DiscoveryPipelineOutcome::Committed(x) => x,
        _ => panic!(),
    };
    let device = committed.result.device_id;
    assert_eq!(device, id(1));
    let evidence: (String, String, String, String, f64, Option<String>, i64) = sqlx::query_as(
        "SELECT family,fact_key,source,fact_value,confidence,expires_at,owner_confirmed FROM evidence",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(evidence.0, "link_layer");
    assert_eq!(evidence.1, "mac");
    assert_eq!(evidence.2, "synthetic");
    assert_eq!(evidence.3, link(1).to_string());
    assert!((evidence.4 - 0.9).abs() < 0.000_001);
    assert_eq!(evidence.5, None);
    assert_eq!(evidence.6, 0);
    assert!(committed.payload.is_none());
    assert!(committed.result.presence.is_empty());
    assert!(committed.result.identification.is_none());
    let second = p
        .observe_link_presence_with_flow(
            present(1, link(1), t + Duration::seconds(1)),
            &[],
            0,
            t + Duration::seconds(1),
        )
        .await
        .unwrap();
    assert!(matches!(second, DiscoveryPipelineOutcome::Committed(_)));
    assert_eq!(p.presence_state(device), Some(PresenceState::Quiet));
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM evidence WHERE family='link_layer' AND fact_key='mac'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn distinct_links_and_registered_sources_have_independent_bindings() {
    let pool = connect_memory().await.unwrap();
    let repo = M2StateRepository::new(pool.clone());
    let sources = DiscoverySources::new(vec![
        lattice_service::discovery::DiscoverySource {
            id: 1,
            name: "source-one".into(),
            families: vec![EvidenceFamily::LinkLayer],
            presence: true,
        },
        lattice_service::discovery::DiscoverySource {
            id: 2,
            name: "source-two".into(),
            families: vec![EvidenceFamily::LinkLayer],
            presence: true,
        },
    ])
    .unwrap();
    let mut p = PersistentDiscoveryPipeline::open(
        repo,
        sources,
        [id(1), id(2), id(3), id(4)].into_iter(),
        Default::default(),
        16,
        16,
    )
    .await
    .unwrap();
    let t = at(1_700_000_200);
    let get = |source_id, mac, time| LinkPresenceObservation {
        source_id,
        link_address: mac,
        observed_at: time,
        kind: LinkPresenceKind::Present {
            valid_until: time + Duration::seconds(30),
        },
    };
    let device = |outcome: DiscoveryPipelineOutcome| match outcome {
        DiscoveryPipelineOutcome::Committed(x) => x.result.device_id,
        _ => panic!(),
    };
    assert_ne!(
        device(
            p.observe_link_presence_with_flow(get(1, link(3), t), &[], 0, t)
                .await
                .unwrap()
        ),
        device(
            p.observe_link_presence_with_flow(
                get(1, link(4), t + Duration::seconds(1)),
                &[],
                0,
                t + Duration::seconds(1)
            )
            .await
            .unwrap()
        )
    );
    let first = device(
        p.observe_link_presence_with_flow(
            get(1, link(5), t + Duration::seconds(2)),
            &[],
            0,
            t + Duration::seconds(2),
        )
        .await
        .unwrap(),
    );
    let second = device(
        p.observe_link_presence_with_flow(
            get(2, link(5), t + Duration::seconds(3)),
            &[],
            0,
            t + Duration::seconds(3),
        )
        .await
        .unwrap(),
    );
    assert_ne!(first, second);
    let bindings: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM evidence WHERE fact_value=? AND fact_key='mac'")
            .bind(link(5).to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bindings, 2);
}

#[tokio::test]
async fn expired_support_needs_two_misses_to_depart() {
    let (_pool, _repo, mut p) = pipeline().await;
    let t = at(1_700_000_300);
    let mut observation = present(1, link(6), t);
    observation.kind = LinkPresenceKind::Present {
        valid_until: t + Duration::seconds(2),
    };
    let device = match p
        .observe_link_presence_with_flow(observation, &[], 0, t)
        .await
        .unwrap()
    {
        DiscoveryPipelineOutcome::Committed(x) => x.result.device_id,
        _ => panic!(),
    };
    let confirmation = LinkPresenceObservation {
        source_id: 1,
        link_address: link(6),
        observed_at: t + Duration::seconds(1),
        kind: LinkPresenceKind::Present {
            valid_until: t + Duration::seconds(2),
        },
    };
    p.observe_link_presence_with_flow(confirmation, &[], 0, t + Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(p.presence_state(device), Some(PresenceState::Quiet));
    let missed = |time| LinkPresenceObservation {
        source_id: 1,
        link_address: link(6),
        observed_at: time,
        kind: LinkPresenceKind::Missed,
    };
    let first = p
        .observe_link_presence_with_flow(
            missed(t + Duration::seconds(3)),
            &[],
            0,
            t + Duration::seconds(3),
        )
        .await
        .unwrap();
    assert!(
        matches!(first, DiscoveryPipelineOutcome::Committed(x) if x.result.presence.is_empty())
    );
    assert_eq!(p.presence_state(device), Some(PresenceState::Quiet));
    let second = p
        .observe_link_presence_with_flow(
            missed(t + Duration::seconds(4)),
            &[],
            0,
            t + Duration::seconds(4),
        )
        .await
        .unwrap();
    assert!(
        matches!(second, DiscoveryPipelineOutcome::Committed(x) if x.result.presence.iter().any(|transition| transition.to == PresenceState::Offline))
    );
    assert_eq!(p.presence_state(device), Some(PresenceState::Offline));
}

#[tokio::test]
async fn exact_link_presence_retry_is_duplicate_even_after_binding_resolution() {
    let (pool, _repo, mut p) = pipeline().await;
    let t = at(1_700_000_100);
    let first = p
        .observe_link_presence_with_flow(present(1, link(8), t), &[], 0, t)
        .await
        .unwrap();
    let sequence = p.commit_sequence();
    assert!(matches!(first, DiscoveryPipelineOutcome::Committed(_)));
    let retry = p
        .observe_link_presence_with_flow(present(1, link(8), t), &[], 0, t)
        .await
        .unwrap();
    assert!(matches!(retry, DiscoveryPipelineOutcome::Duplicate(_)));
    assert_eq!(p.commit_sequence(), sequence);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM discovery_commits")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn file_backed_reopen_reuses_link_binding_without_extra_evidence() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("link-presence.db");
    let t = at(1_700_000_150);
    let sources =
        || DiscoverySources::sensor(1, "synthetic", vec![EvidenceFamily::LinkLayer]).unwrap();
    let first_id;
    {
        let pool = connect_path(&path).await.unwrap();
        let mut p = PersistentDiscoveryPipeline::open(
            M2StateRepository::new(pool),
            sources(),
            [id(1), id(2)].into_iter(),
            Default::default(),
            16,
            16,
        )
        .await
        .unwrap();
        first_id = match p
            .observe_link_presence_with_flow(present(1, link(12), t), &[], 0, t)
            .await
            .unwrap()
        {
            DiscoveryPipelineOutcome::Committed(x) => x.result.device_id,
            _ => panic!(),
        };
    }
    let pool = connect_path(&path).await.unwrap();
    let mut p = PersistentDiscoveryPipeline::open(
        M2StateRepository::new(pool.clone()),
        sources(),
        [id(2)].into_iter(),
        Default::default(),
        16,
        16,
    )
    .await
    .unwrap();
    let third = p
        .observe_link_presence_with_flow(
            present(1, link(12), t + Duration::seconds(2)),
            &[],
            0,
            t + Duration::seconds(2),
        )
        .await
        .unwrap();
    assert!(
        matches!(third, DiscoveryPipelineOutcome::Committed(x) if x.result.device_id == first_id)
    );
    let evidence: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM evidence WHERE family='link_layer' AND fact_key='mac'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(evidence, 1);
}

#[tokio::test]
async fn missed_before_binding_is_typed_and_inert_and_subseconds_are_rejected() {
    let (pool, _repo, mut p) = pipeline().await;
    let t = at(1_700_000_000);
    let err = p
        .observe_link_presence_with_flow(
            LinkPresenceObservation {
                source_id: 1,
                link_address: link(2),
                observed_at: t,
                kind: LinkPresenceKind::Missed,
            },
            &[],
            0,
            t,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DiscoveryError::UnboundLink));
    let err = p
        .observe_link_presence_with_flow(
            LinkPresenceObservation {
                source_id: 1,
                link_address: link(2),
                observed_at: t + Duration::milliseconds(1),
                kind: LinkPresenceKind::Missed,
            },
            &[],
            0,
            t,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DiscoveryError::InvalidSource));
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn debug_redacts_link_address() {
    let observation = present(1, link(7), at(1_700_000_000));
    let text = format!("{observation:?}");
    assert!(!text.contains("02:00:00:00:00:07"));
}

#[tokio::test]
async fn invalid_link_inputs_and_sources_are_inert() {
    let (pool, _repo, mut p) = pipeline().await;
    let t = at(1_700_000_400);
    for observation in [
        LinkPresenceObservation {
            source_id: 99,
            link_address: link(9),
            observed_at: t,
            kind: LinkPresenceKind::Missed,
        },
        LinkPresenceObservation {
            source_id: 1,
            link_address: link(9),
            observed_at: t + Duration::milliseconds(1),
            kind: LinkPresenceKind::Present {
                valid_until: t + Duration::seconds(30),
            },
        },
        LinkPresenceObservation {
            source_id: 1,
            link_address: link(9),
            observed_at: t,
            kind: LinkPresenceKind::Present { valid_until: t },
        },
        LinkPresenceObservation {
            source_id: 1,
            link_address: link(9),
            observed_at: t,
            kind: LinkPresenceKind::Present {
                valid_until: t + Duration::milliseconds(1),
            },
        },
    ] {
        assert!(matches!(
            p.observe_link_presence_with_flow(observation, &[], 0, t)
                .await,
            Err(DiscoveryError::InvalidSource)
        ));
    }
    assert!(matches!(
        p.observe_link_presence_with_flow(
            present(1, link(9), t),
            &[],
            0,
            t + Duration::milliseconds(1)
        )
        .await,
        Err(DiscoveryError::InvalidSource)
    ));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);

    let sources = DiscoverySources::new(vec![
        DiscoverySource {
            id: 1,
            name: "not-presence".into(),
            families: vec![EvidenceFamily::LinkLayer],
            presence: false,
        },
        DiscoverySource {
            id: 2,
            name: "not-link".into(),
            families: vec![EvidenceFamily::Naming],
            presence: true,
        },
    ])
    .unwrap();
    let repo = M2StateRepository::new(connect_memory().await.unwrap());
    let mut p = PersistentDiscoveryPipeline::open(
        repo,
        sources,
        [id(1)].into_iter(),
        Default::default(),
        16,
        16,
    )
    .await
    .unwrap();
    for source_id in [1, 2] {
        assert!(matches!(
            p.observe_link_presence_with_flow(present(source_id, link(9), t), &[], 0, t)
                .await,
            Err(DiscoveryError::InvalidSource)
        ));
    }
}

#[tokio::test]
async fn ambiguous_binding_fails_closed_without_mutation_or_leakage() {
    let (pool, _repo, mut p) = pipeline().await;
    let t = at(1_700_000_500);
    for device in [id(1), id(2)] {
        sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at) VALUES(?,?,?)")
            .bind(device.to_string())
            .bind(t.to_rfc3339())
            .bind(t.to_rfc3339())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO evidence(device_id,family,source,fact_key,fact_value,confidence,observed_at) VALUES(?,?,?,?,?,?,?)").bind(device.to_string()).bind("link_layer").bind("synthetic").bind("mac").bind(link(10).to_string()).bind(0.9).bind(t.to_rfc3339()).execute(&pool).await.unwrap();
    }
    let before: (i64, i64, i64) = (
        sqlx::query_scalar("SELECT COUNT(*) FROM devices")
            .fetch_one(&pool)
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT COUNT(*) FROM evidence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT COUNT(*) FROM discovery_commits")
            .fetch_one(&pool)
            .await
            .unwrap(),
    );
    for observation in [
        present(1, link(10), t),
        LinkPresenceObservation {
            source_id: 1,
            link_address: link(10),
            observed_at: t,
            kind: LinkPresenceKind::Missed,
        },
    ] {
        let error = p
            .observe_link_presence_with_flow(observation, &[], 0, t)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DiscoveryError::Checkpoint(lattice_store::CheckpointError::Corrupt(_))
        ));
        let text = format!("{error:?}");
        assert!(!text.contains("02:00:00:00:00:0a") && !text.contains("synthetic"));
    }
    let after: (i64, i64, i64) = (
        sqlx::query_scalar("SELECT COUNT(*) FROM devices")
            .fetch_one(&pool)
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT COUNT(*) FROM evidence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT COUNT(*) FROM discovery_commits")
            .fetch_one(&pool)
            .await
            .unwrap(),
    );
    assert_eq!(after, before);
}

#[tokio::test]
async fn mismatched_flow_is_atomic_after_link_binding() {
    let (pool, _repo, mut p) = pipeline().await;
    let t = at(1_700_000_600);
    let bound = match p
        .observe_link_presence_with_flow(present(1, link(11), t), &[], 0, t)
        .await
        .unwrap()
    {
        DiscoveryPipelineOutcome::Committed(x) => x.result.device_id,
        _ => panic!(),
    };
    let before = (
        p.commit_sequence(),
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM evidence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM flow_rollups")
            .fetch_one(&pool)
            .await
            .unwrap(),
    );
    let change = RollupChange::Upsert(Rollup {
        key: RollupKey {
            resolution: Resolution::Second,
            bucket: t + Duration::seconds(1),
            device_id: id(2),
            protocol: Protocol::Tcp,
            destination: DestinationCategory::Internet,
            interface: 1,
            metadata: None,
        },
        bytes: ByteCount {
            upload: 1,
            download: 1,
        },
        coverage: Coverage::LocalOnly,
        metadata: None,
    });
    assert!(matches!(
        p.observe_link_presence_with_flow(
            present(1, link(11), t + Duration::seconds(1)),
            &[change],
            0,
            t + Duration::seconds(1)
        )
        .await,
        Err(DiscoveryError::InvalidSource)
    ));
    let after = (
        p.commit_sequence(),
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM evidence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM flow_rollups")
            .fetch_one(&pool)
            .await
            .unwrap(),
    );
    assert_eq!(after, before);
    assert_eq!(p.presence_state(bound), Some(PresenceState::Unknown));
}
