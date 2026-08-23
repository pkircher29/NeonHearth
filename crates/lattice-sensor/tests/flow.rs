use chrono::{TimeZone, Utc};
use lattice_domain::{Coverage, DeviceId};
use lattice_sensor::flow::{
    DestinationCategory, FlowEngine, FlowEngineConfig, FlowObservation, Protocol, SourceKind,
};

fn device(n: u8) -> DeviceId {
    DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}
fn obs(id: u64, sec: i64, bytes: u64) -> FlowObservation {
    FlowObservation {
        observation_id: id,
        observed_at: Utc.timestamp_opt(sec, 0).unwrap(),
        device_id: device(1),
        upload: bytes,
        download: 0,
        protocol: Protocol::Tcp,
        destination: DestinationCategory::Internet,
        interface: 2,
        source: SourceKind::CollectorCapture,
        coverage: Coverage::LocalOnly,
    }
}

#[test]
fn seconds_and_minutes_conserve_bytes_and_are_deterministic() {
    let mut e = FlowEngine::new(FlowEngineConfig::default()).unwrap();
    e.observe(obs(1, 100, 3)).unwrap();
    e.observe(obs(2, 101, 4)).unwrap();
    let out = e
        .finalize_until(Utc.timestamp_opt(160, 0).unwrap())
        .unwrap();
    assert_eq!(out.seconds.iter().map(|r| r.bytes.upload).sum::<u64>(), 7);
    assert_eq!(out.minutes.iter().map(|r| r.bytes.upload).sum::<u64>(), 7);
    assert!(out.seconds.windows(2).all(|w| w[0].bucket <= w[1].bucket));
}

#[test]
fn rejects_unverified_source_and_replay_atomically() {
    let mut e = FlowEngine::new(FlowEngineConfig::default()).unwrap();
    let mut x = obs(1, 100, 3);
    x.source = SourceKind::Inferred;
    assert!(e.observe(x).is_err());
    assert!(e.observe(obs(1, 100, 3)).is_ok());
    assert!(e.observe(obs(1, 100, 3)).is_err());
}
