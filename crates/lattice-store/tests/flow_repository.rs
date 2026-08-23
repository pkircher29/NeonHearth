use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{ByteCount, Coverage, DeviceId};
use lattice_sensor::flow::*;
use lattice_sensor::live::LiveConfig;
use lattice_store::{CompactionPolicy, FlowIngestor, FlowRepository, connect_memory};
fn t(s: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(s, 0).single().unwrap()
}
fn d() -> DeviceId {
    DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445501").unwrap()
}
fn roll(res: Resolution, sec: i64, up: u64, cov: Coverage) -> Rollup {
    let key = RollupKey {
        resolution: res,
        bucket: t(sec),
        device_id: d(),
        protocol: Protocol::Tcp,
        destination: DestinationCategory::Internet,
        interface: 2,
        metadata: None,
    };
    Rollup {
        key,
        bytes: ByteCount {
            upload: up,
            download: up,
        },
        coverage: cov,
        metadata: None,
    }
}
#[tokio::test]
async fn upsert_correction_query_and_cache_retire_are_idempotent() {
    let pool = connect_memory().await.unwrap();
    let repo = FlowRepository::new(pool, 20).unwrap();
    repo.apply(
        &[RollupChange::Upsert(roll(
            Resolution::Second,
            1,
            2,
            Coverage::LocalOnly,
        ))],
        t(2),
    )
    .await
    .unwrap();
    repo.apply(
        &[RollupChange::Correction(roll(
            Resolution::Second,
            1,
            7,
            Coverage::Complete,
        ))],
        t(3),
    )
    .await
    .unwrap();
    repo.apply(
        &[RollupChange::Retire(Retirement {
            key: roll(Resolution::Second, 1, 0, Coverage::Complete).key,
            cache_only: true,
        })],
        t(4),
    )
    .await
    .unwrap();
    let x = repo
        .range(Resolution::Second, t(0), t(5), 10)
        .await
        .unwrap();
    assert_eq!(
        (x.len(), x[0].bytes.upload, x[0].coverage),
        (1, 7, Coverage::Complete)
    );
}
#[tokio::test]
async fn batch_overflow_and_limit_roll_back_atomically() {
    let pool = connect_memory().await.unwrap();
    let repo = FlowRepository::new(pool, 2).unwrap();
    let ok = roll(Resolution::Second, 1, 2, Coverage::Complete);
    let bad = roll(Resolution::Second, 2, u64::MAX, Coverage::Complete);
    assert!(
        repo.apply(&[RollupChange::Upsert(ok), RollupChange::Upsert(bad)], t(3))
            .await
            .is_err()
    );
    assert!(
        repo.range(Resolution::Second, t(0), t(4), 2)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.apply(
            &[
                RollupChange::Upsert(roll(Resolution::Second, 1, 1, Coverage::Complete)),
                RollupChange::Upsert(roll(Resolution::Second, 2, 1, Coverage::Complete)),
                RollupChange::Upsert(roll(Resolution::Second, 3, 1, Coverage::Complete)),
            ],
            t(3)
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn privacy_metadata_and_dimensions_round_trip_deterministically() {
    let pool = connect_memory().await.unwrap();
    let repo = FlowRepository::new(pool, 10).unwrap();
    let mut r = roll(Resolution::Minute, -60, 4, Coverage::RouterReported);
    r.key.protocol = Protocol::Udp;
    r.key.destination = DestinationCategory::Lan;
    r.metadata = Some(DestinationMetadata {
        ip: Some("192.0.2.1".parse().unwrap()),
        domain: Some("example.com".into()),
    });
    r.key.metadata = r.metadata.clone();
    repo.apply(&[RollupChange::Upsert(r.clone())], t(0))
        .await
        .unwrap();
    assert_eq!(
        repo.range(Resolution::Minute, t(-100), t(0), 10)
            .await
            .unwrap(),
        vec![r]
    );
}
#[test]
fn retention_defaults_and_validation_are_exact() {
    let p = CompactionPolicy::default();
    assert_eq!(p.seconds, Duration::hours(24));
    assert_eq!(p.minutes, Duration::days(90));
    assert_eq!(p.hours, None);
    assert!(p.validate().is_ok());
    let mut bad = p;
    bad.seconds = Duration::zero();
    assert!(bad.validate().is_err());
}
#[tokio::test]
async fn compaction_conserves_seconds_to_minutes_to_hours_and_is_repeatable() {
    let pool = connect_memory().await.unwrap();
    let repo = FlowRepository::new(pool, 100).unwrap();
    repo.apply(
        &[
            RollupChange::Upsert(roll(Resolution::Second, 0, 2, Coverage::Complete)),
            RollupChange::Upsert(roll(Resolution::Second, 1, 3, Coverage::LocalOnly)),
        ],
        t(2),
    )
    .await
    .unwrap();
    let p = CompactionPolicy {
        seconds: Duration::seconds(60),
        minutes: Duration::seconds(120),
        hours: None,
        max_rows: 100,
    };
    repo.compact(t(4000), &p).await.unwrap();
    repo.compact(t(4000), &p).await.unwrap();
    assert!(
        repo.range(Resolution::Second, t(-1), t(5000), 100)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.range(Resolution::Minute, t(-1), t(5000), 100)
            .await
            .unwrap()
            .is_empty()
    );
    let h = repo
        .range(Resolution::Hour, t(-1), t(5000), 100)
        .await
        .unwrap();
    assert_eq!(
        (h.len(), h[0].bytes.upload, h[0].coverage),
        (1, 5, Coverage::Estimated)
    );
    assert!(
        repo.apply(
            &[RollupChange::Correction(roll(
                Resolution::Second,
                0,
                99,
                Coverage::Complete
            ))],
            t(4001)
        )
        .await
        .is_err()
    );
    assert_eq!(
        repo.range(Resolution::Hour, t(-1), t(5000), 100)
            .await
            .unwrap()[0]
            .bytes
            .upload,
        5
    );
}
#[tokio::test]
async fn compaction_cutoff_is_full_parent_inclusive_and_hours_live_forever() {
    let pool = connect_memory().await.unwrap();
    let repo = FlowRepository::new(pool, 100).unwrap();
    repo.apply(
        &[
            RollupChange::Upsert(roll(Resolution::Second, 60, 9, Coverage::Complete)),
            RollupChange::Upsert(roll(Resolution::Hour, -3600, 11, Coverage::Complete)),
        ],
        t(61),
    )
    .await
    .unwrap();
    let p = CompactionPolicy {
        seconds: Duration::seconds(60),
        minutes: Duration::seconds(120),
        hours: None,
        max_rows: 100,
    };
    repo.compact(t(180), &p).await.unwrap();
    assert_eq!(
        repo.range(Resolution::Second, t(0), t(200), 100)
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        repo.range(Resolution::Hour, t(-4000), t(0), 100)
            .await
            .unwrap()
            .len(),
        1
    );
}
#[tokio::test]
async fn compaction_capacity_failure_is_atomic() {
    let pool = connect_memory().await.unwrap();
    let repo = FlowRepository::new(pool, 100).unwrap();
    repo.apply(
        &[
            RollupChange::Upsert(roll(Resolution::Second, 0, 2, Coverage::Complete)),
            RollupChange::Upsert(roll(Resolution::Second, 1, 3, Coverage::Complete)),
        ],
        t(2),
    )
    .await
    .unwrap();
    let p = CompactionPolicy {
        seconds: Duration::seconds(60),
        minutes: Duration::seconds(120),
        hours: None,
        max_rows: 1,
    };
    assert!(repo.compact(t(4000), &p).await.is_err());
    assert_eq!(
        repo.range(Resolution::Second, t(-1), t(10), 100)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn schema_constraints_and_query_index_are_enforced() {
    let pool = connect_memory().await.unwrap();
    let bad=sqlx::query("INSERT INTO flow_rollups(resolution,bucket,device_id,protocol,destination,interface,upload,download,coverage,updated_at) VALUES('second','1970-01-01T00:00:00Z','missing','tcp','internet',1,1,1,'bogus','1970-01-01T00:00:00Z')").execute(&pool).await;
    assert!(bad.is_err());
    let plan:Vec<(i64,i64,i64,String)>=sqlx::query_as("EXPLAIN QUERY PLAN SELECT * FROM flow_rollups WHERE resolution='second' AND bucket>='1970-01-01T00:00:00Z' AND device_id='x'").fetch_all(&pool).await.unwrap();
    assert!(
        plan.iter()
            .any(|x| x.3.contains("flow_rollups_range_idx") || x.3.contains("sqlite_autoindex"))
    );
}

#[tokio::test]
async fn integration_applies_durable_and_emits_replayable_frame() {
    let pool = connect_memory().await.unwrap();
    let repo = FlowRepository::new(pool.clone(), 10).unwrap();
    let mut ingest = FlowIngestor::new(repo, LiveConfig::default(), 10).unwrap();
    let payload = ingest
        .apply(
            &[RollupChange::Upsert(roll(
                Resolution::Second,
                1,
                4,
                Coverage::Complete,
            ))],
            0,
            t(2),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        payload,
        lattice_domain::EventPayload::BandwidthFrame(_)
    ));
    let persisted = FlowRepository::new(pool, 10)
        .unwrap()
        .range(Resolution::Second, t(0), t(2), 10)
        .await
        .unwrap();
    assert_eq!(persisted[0].bytes.upload, 4);
}
