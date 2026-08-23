use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{ByteCount, Coverage, DeviceId};
use lattice_sensor::flow::{
    DestinationCategory, Protocol, Resolution, Rollup, RollupChange, RollupKey,
};
use lattice_store::{CompactionPolicy, FlowRepository, connect_memory};

fn roll(bucket: chrono::DateTime<Utc>, upload: u64) -> Rollup {
    roll_at(Resolution::Second, bucket, upload)
}
fn roll_at(resolution: Resolution, bucket: chrono::DateTime<Utc>, upload: u64) -> Rollup {
    Rollup {
        key: RollupKey {
            resolution,
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
    let now = Utc.timestamp_opt(1_998_000, 0).single().unwrap();
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

#[tokio::test]
async fn ninety_day_minute_boundary_compacts_to_hour_and_is_repeatable() {
    let pool = connect_memory().await.unwrap();
    let repo = FlowRepository::new(pool, 100).unwrap();
    let now = Utc.timestamp_opt(1_998_000, 0).single().unwrap();
    let old = now - Duration::days(91);
    let hour = old - Duration::seconds(old.timestamp().rem_euclid(3600));
    repo.apply(
        &[
            RollupChange::Upsert(roll_at(Resolution::Minute, hour, 5)),
            RollupChange::Upsert(roll_at(Resolution::Minute, hour + Duration::minutes(1), 7)),
        ],
        now,
    )
    .await
    .unwrap();
    assert_eq!(
        repo.compact(now, &CompactionPolicy::default())
            .await
            .unwrap(),
        2
    );
    let hours = repo.range(Resolution::Hour, hour, hour, 10).await.unwrap();
    assert_eq!(
        hours[0].bytes,
        ByteCount {
            upload: 12,
            download: 24
        }
    );
    assert_eq!(hours[0].coverage, Coverage::LocalOnly);
    assert_eq!(
        repo.compact(now, &CompactionPolicy::default())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn default_ninety_day_cutoff_includes_complete_hours_but_not_bisected_parents() {
    let pool = connect_memory().await.unwrap();
    let repo = FlowRepository::new(pool, 100).unwrap();
    let now = Utc.timestamp_opt(1_998_000, 0).single().unwrap();
    let cutoff = now - CompactionPolicy::default().minutes;
    let full_hour = cutoff - Duration::hours(1);
    let bisected_hour = cutoff;
    repo.apply(
        &[
            RollupChange::Upsert(roll_at(Resolution::Minute, full_hour, 3)),
            RollupChange::Upsert(roll_at(
                Resolution::Minute,
                full_hour + Duration::minutes(59),
                4,
            )),
            RollupChange::Upsert(roll_at(
                Resolution::Minute,
                bisected_hour + Duration::minutes(1),
                9,
            )),
        ],
        now,
    )
    .await
    .unwrap();
    repo.compact(now, &CompactionPolicy::default())
        .await
        .unwrap();
    let full = repo
        .range(Resolution::Hour, full_hour, full_hour, 10)
        .await
        .unwrap();
    assert_eq!(
        full[0].bytes,
        ByteCount {
            upload: 7,
            download: 14
        }
    );
    assert!(
        repo.range(
            Resolution::Minute,
            full_hour,
            full_hour + Duration::hours(1),
            10
        )
        .await
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        repo.range(Resolution::Hour, bisected_hour, bisected_hour, 10)
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        repo.range(
            Resolution::Minute,
            bisected_hour,
            bisected_hour + Duration::hours(1),
            10
        )
        .await
        .unwrap()
        .len(),
        1
    );
    let later = now + Duration::hours(2);
    repo.compact(later, &CompactionPolicy::default())
        .await
        .unwrap();
    let bisected = repo
        .range(Resolution::Hour, bisected_hour, bisected_hour, 10)
        .await
        .unwrap();
    assert_eq!(
        bisected[0].bytes,
        ByteCount {
            upload: 9,
            download: 18
        }
    );
    assert!(
        repo.range(
            Resolution::Minute,
            bisected_hour,
            bisected_hour + Duration::hours(1),
            10
        )
        .await
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        repo.compact(later, &CompactionPolicy::default())
            .await
            .unwrap(),
        0
    );
}
