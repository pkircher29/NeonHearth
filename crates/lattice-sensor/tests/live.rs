use chrono::{TimeZone, Utc};
use lattice_domain::{ByteCount, Coverage, DeviceId, EventPayload};
use lattice_sensor::{flow::*, live::*};
fn t(s: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(s, 0).single().unwrap()
}
fn d(n: u8) -> DeviceId {
    DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}
fn s(n: u8, u: u64) -> LiveSample {
    LiveSample {
        device_id: d(n),
        delta: ByteCount {
            upload: u,
            download: u.saturating_add(1),
        },
        coverage: Coverage::Complete,
        observed_at: t(1),
    }
}
#[test]
fn exact_four_hz_boundary_and_idle_flush() {
    let mut c = LiveCoalescer::new(LiveConfig::default()).unwrap();
    c.replace(0, vec![s(1, 25)]).unwrap();
    assert!(c.flush(0, t(1)).unwrap().is_some());
    c.replace(1, vec![s(1, 50)]).unwrap();
    assert!(c.flush(249, t(1)).unwrap().is_none());
    let x = c.flush(250, t(1)).unwrap().unwrap();
    assert_eq!(
        (x.interval_ms, x.samples[0].upload_bytes_per_second),
        (250, 200)
    );
}
#[test]
fn burst_replaces_pending_latest() {
    let mut c = LiveCoalescer::new(LiveConfig::default()).unwrap();
    c.replace(0, vec![s(1, 1)]).unwrap();
    c.replace(1, vec![s(1, 9)]).unwrap();
    assert_eq!(
        c.flush(1, t(1)).unwrap().unwrap().samples[0].delta.upload,
        9
    );
}
#[test]
fn rollback_bounds_and_overflow_are_atomic() {
    let cfg = LiveConfig {
        max_devices: 1,
        max_pending: 1,
        max_work: 1,
        ..LiveConfig::default()
    };
    let mut c = LiveCoalescer::new(cfg).unwrap();
    c.replace(10, vec![s(1, 1)]).unwrap();
    assert_eq!(c.replace(9, vec![s(1, 2)]), Err(LiveError::Clock));
    assert_eq!(c.replace(10, vec![s(2, 2)]), Err(LiveError::Capacity));
    let mut big = s(1, u64::MAX);
    big.delta.download = 0;
    c.replace(10, vec![big]).unwrap();
    assert_eq!(c.flush(10, t(1)), Err(LiveError::Overflow));
}
#[test]
fn config_rejects_faster_than_four_hz() {
    let c = LiveConfig {
        min_interval_ms: 249,
        ..LiveConfig::default()
    };
    assert!(matches!(LiveCoalescer::new(c), Err(LiveError::Config)));
}
fn roll(up: u64) -> Rollup {
    let key = RollupKey {
        resolution: Resolution::Second,
        bucket: t(1),
        device_id: d(1),
        protocol: Protocol::Tcp,
        destination: DestinationCategory::Internet,
        interface: 1,
        metadata: None,
    };
    Rollup {
        key,
        bytes: ByteCount {
            upload: up,
            download: 0,
        },
        coverage: Coverage::RouterReported,
        metadata: None,
    }
}
#[test]
fn corrections_replace_and_retire_is_not_traffic() {
    let mut a = FlowLiveAdapter::new(LiveConfig::default(), 4).unwrap();
    a.apply(
        0,
        &[
            RollupChange::Upsert(roll(3)),
            RollupChange::Correction(roll(7)),
        ],
    )
    .unwrap();
    let p = a.flush_payload(0, t(2)).unwrap().unwrap();
    let EventPayload::BandwidthFrame(f) = p else {
        panic!()
    };
    assert_eq!(f.samples[0].delta.upload, 7);
    let retire = Retirement {
        key: roll(7).key,
        cache_only: true,
    };
    a.apply(250, &[RollupChange::Retire(retire)]).unwrap();
    assert!(a.flush_payload(250, t(2)).unwrap().is_none());
}
#[test]
fn deterministic_frame_serde_and_coverage() {
    let mut c = LiveCoalescer::new(LiveConfig::default()).unwrap();
    let mut x = s(2, 2);
    x.coverage = Coverage::LocalOnly;
    c.replace(0, vec![x, s(1, 1)]).unwrap();
    let f = c.flush(0, t(2)).unwrap().unwrap();
    assert_eq!(f.samples[0].device_id, d(1));
    let j = serde_json::to_string(&EventPayload::BandwidthFrame(f)).unwrap();
    assert!(j.contains("bandwidth_frame") && j.contains("local-only"));
}

#[test]
fn adapter_failure_is_atomic_and_retire_recovers_capacity() {
    let mut a = FlowLiveAdapter::new(LiveConfig::default(), 1).unwrap();
    a.apply(10, &[RollupChange::Upsert(roll(3))]).unwrap();
    let before = a.cached_rollups();
    assert_eq!(
        a.apply(9, &[RollupChange::Correction(roll(8))]),
        Err(LiveError::Clock)
    );
    assert_eq!(a.cached_rollups(), before);
    let old = roll(3).key;
    a.apply(
        10,
        &[RollupChange::Retire(Retirement {
            key: old,
            cache_only: true,
        })],
    )
    .unwrap();
    assert!(a.cached_rollups().is_empty());
    let mut other = roll(4);
    other.key.interface = 9;
    a.apply(10, &[RollupChange::Upsert(other)]).unwrap();
    assert_eq!(a.cached_rollups().len(), 1);
}

#[test]
fn each_device_uses_its_own_latest_bucket() {
    let mut a = FlowLiveAdapter::new(LiveConfig::default(), 4).unwrap();
    let old = roll(3);
    let mut newer = roll(5);
    newer.key.device_id = d(2);
    newer.key.bucket = t(2);
    a.apply(0, &[RollupChange::Upsert(old), RollupChange::Upsert(newer)])
        .unwrap();
    let EventPayload::BandwidthFrame(f) = a.flush_payload(0, t(3)).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(f.samples.len(), 2);
}

#[test]
fn retire_before_flush_cancels_stale_sample_but_preserves_other_devices() {
    let mut a = FlowLiveAdapter::new(LiveConfig::default(), 4).unwrap();
    let one = roll(3);
    let mut two = roll(5);
    two.key.device_id = d(2);
    a.apply(0, &[RollupChange::Upsert(one.clone())]).unwrap();
    a.apply(
        1,
        &[RollupChange::Retire(Retirement {
            key: one.key,
            cache_only: true,
        })],
    )
    .unwrap();
    assert!(a.flush_payload(250, t(2)).unwrap().is_none());
    let one = roll(3);
    a.apply(
        300,
        &[RollupChange::Upsert(one.clone()), RollupChange::Upsert(two)],
    )
    .unwrap();
    a.apply(
        301,
        &[RollupChange::Retire(Retirement {
            key: one.key,
            cache_only: true,
        })],
    )
    .unwrap();
    let EventPayload::BandwidthFrame(f) = a.flush_payload(550, t(3)).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(
        f.samples.iter().map(|s| s.device_id).collect::<Vec<_>>(),
        vec![d(2)]
    );
}

#[test]
fn absent_and_nonsecond_retire_do_not_cancel_valid_pending_sample() {
    let mut a = FlowLiveAdapter::new(LiveConfig::default(), 4).unwrap();
    let valid = roll(3);
    a.apply(0, &[RollupChange::Upsert(valid.clone())]).unwrap();
    let mut absent = valid.key.clone();
    absent.interface = 99;
    a.apply(
        1,
        &[RollupChange::Retire(Retirement {
            key: absent,
            cache_only: true,
        })],
    )
    .unwrap();
    let EventPayload::BandwidthFrame(f) = a.flush_payload(250, t(2)).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(f.samples[0].delta.upload, 3);
    let mut b = FlowLiveAdapter::new(LiveConfig::default(), 4).unwrap();
    b.apply(0, &[RollupChange::Upsert(valid.clone())]).unwrap();
    let mut minute = valid.key;
    minute.resolution = Resolution::Minute;
    minute.bucket = t(0);
    b.apply(
        1,
        &[RollupChange::Retire(Retirement {
            key: minute,
            cache_only: true,
        })],
    )
    .unwrap();
    let EventPayload::BandwidthFrame(f) = b.flush_payload(250, t(2)).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(f.samples[0].delta.upload, 3);
}

#[test]
fn emitted_cumulative_replacements_only_report_growth_and_reset_safely() {
    let mut a = FlowLiveAdapter::new(LiveConfig::default(), 4).unwrap();
    a.apply(0, &[RollupChange::Upsert(roll(100))]).unwrap();
    let EventPayload::BandwidthFrame(first) = a.flush_payload(0, t(2)).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(first.samples[0].delta.upload, 100);

    a.apply(250, &[RollupChange::Correction(roll(150))])
        .unwrap();
    let EventPayload::BandwidthFrame(growth) = a.flush_payload(250, t(3)).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(growth.samples[0].delta.upload, 50);

    a.apply(500, &[RollupChange::Correction(roll(40))]).unwrap();
    assert!(a.flush_payload(500, t(4)).unwrap().is_none());
    a.apply(750, &[RollupChange::Correction(roll(70))]).unwrap();
    let EventPayload::BandwidthFrame(after_reset) = a.flush_payload(750, t(5)).unwrap().unwrap()
    else {
        panic!()
    };
    assert_eq!(after_reset.samples[0].delta.upload, 30);
}

#[test]
fn adapter_prunes_superseded_seconds_but_keeps_latest_dimensions() {
    let mut a = FlowLiveAdapter::new(LiveConfig::default(), 2).unwrap();
    for second in 1..=8 {
        let mut tcp = roll(second as u64);
        tcp.key.bucket = t(second);
        let mut udp = tcp.clone();
        udp.key.protocol = Protocol::Udp;
        udp.bytes.upload = 1;
        a.apply(
            (second as u64 - 1) * 250,
            &[RollupChange::Upsert(tcp), RollupChange::Upsert(udp)],
        )
        .unwrap();
        let EventPayload::BandwidthFrame(frame) = a
            .flush_payload((second as u64 - 1) * 250, t(second + 1))
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(frame.samples[0].delta.upload, second as u64 + 1);
        assert_eq!(a.cached_rollups().len(), 2);
        assert!(
            a.cached_rollups()
                .iter()
                .all(|row| row.key.bucket == t(second))
        );
    }
}

#[test]
fn mixed_direction_corrections_reset_each_baseline_before_pending_flush() {
    let mut a = FlowLiveAdapter::new(LiveConfig::default(), 4).unwrap();
    let mut initial = roll(100);
    initial.bytes.download = 100;
    a.apply(0, &[RollupChange::Upsert(initial)]).unwrap();
    a.flush_payload(0, t(2)).unwrap().unwrap();

    let mut upload_reset = roll(40);
    upload_reset.bytes.download = 150;
    a.apply(1, &[RollupChange::Correction(upload_reset)])
        .unwrap();
    let mut upload_growth = roll(70);
    upload_growth.bytes.download = 150;
    a.apply(250, &[RollupChange::Correction(upload_growth)])
        .unwrap();
    let EventPayload::BandwidthFrame(frame) = a.flush_payload(250, t(3)).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(
        frame.samples[0].delta,
        ByteCount {
            upload: 30,
            download: 50
        }
    );

    let mut b = FlowLiveAdapter::new(LiveConfig::default(), 4).unwrap();
    let mut initial = roll(100);
    initial.bytes.download = 100;
    b.apply(0, &[RollupChange::Upsert(initial)]).unwrap();
    b.flush_payload(0, t(2)).unwrap().unwrap();
    let mut download_reset = roll(150);
    download_reset.bytes.download = 40;
    b.apply(1, &[RollupChange::Correction(download_reset)])
        .unwrap();
    let mut download_growth = roll(150);
    download_growth.bytes.download = 70;
    b.apply(250, &[RollupChange::Correction(download_growth)])
        .unwrap();
    let EventPayload::BandwidthFrame(frame) = b.flush_payload(250, t(3)).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(
        frame.samples[0].delta,
        ByteCount {
            upload: 50,
            download: 30
        }
    );
}
