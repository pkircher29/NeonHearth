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
