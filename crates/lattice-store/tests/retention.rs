use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{ByteCount, Coverage, DeviceId};
use lattice_sensor::flow::{
    DestinationCategory, Protocol, Resolution, Rollup, RollupChange, RollupKey,
};
use lattice_store::{CompactionPolicy, FlowRepository, connect_memory};

fn roll(bucket: chrono::DateTime<Utc>, upload: u64) -> Rollup {
    Rollup {
        key: RollupKey {
            resolution: Resolution::Second,
            bucket,
            device_id: DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445501").unwrap(),
            protocol: Protocol::Tcp,
            destination: DestinationCategory::Internet,
            interface: 2,
            metadata: None,
        },
        bytes: ByteCount {
            upload,
            download: upload * 2,
        },
        coverage: Coverage::LocalOnly,
        metadata: None,
    }
}

#[tokio::test]
async fn defaults_retain_24h_seconds_90d_minutes_and_conserve_compacted_bytes() {
    let policy = CompactionPolicy::default();
    assert_eq!(policy.seconds, Duration::hours(24));
    assert_eq!(policy.minutes, Duration::days(90));
    assert_eq!(policy.hours, None);
    let pool = connect_memory().await.unwrap();
    let repo = FlowRepository::new(pool, 100).unwrap();
    let now = Utc.timestamp_opt(2_000_000, 0).single().unwrap();
    let old = now
        - Duration::hours(25)
        - Duration::seconds((now - Duration::hours(25)).timestamp().rem_euclid(60));
    repo.apply(
        &[
            RollupChange::Upsert(roll(old, 7)),
            RollupChange::Upsert(roll(old + Duration::seconds(1), 11)),
        ],
        now,
    )
    .await
    .unwrap();
    assert_eq!(repo.compact(now, &policy).await.unwrap(), 2);
    let minutes = repo
        .range(Resolution::Minute, old, old + Duration::minutes(1), 10)
        .await
        .unwrap();
    assert_eq!(minutes.len(), 1);
    assert_eq!(
        minutes[0].bytes,
        ByteCount {
            upload: 18,
            download: 36
        }
    );
    assert_eq!(minutes[0].coverage, Coverage::LocalOnly);
    assert!(
        repo.range(Resolution::Second, old, old + Duration::minutes(1), 10)
            .await
            .unwrap()
            .is_empty()
    );
}
