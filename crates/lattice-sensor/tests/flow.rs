use chrono::{DateTime, Duration, TimeZone, Utc};
use lattice_domain::{Coverage, DeviceId};
use lattice_sensor::flow::*;
use std::{collections::BTreeMap, net::IpAddr};

fn t(s: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(s, 0).single().unwrap()
}
fn device(n: u8) -> DeviceId {
    DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}
fn sources() -> Vec<SourceRegistration> {
    vec![
        SourceRegistration::verified_gateway(FlowSourceId(1)),
        SourceRegistration::verified_bridge(FlowSourceId(2)),
        SourceRegistration::verified_mirror(FlowSourceId(3)),
        SourceRegistration::verified_router_counter(FlowSourceId(4)),
        SourceRegistration::collector_local(FlowSourceId(5)),
        SourceRegistration::configured_inference(FlowSourceId(6)),
    ]
}
fn cfg() -> FlowEngineConfig {
    FlowEngineConfig::default()
}
fn engine() -> FlowEngine {
    FlowEngine::new(cfg(), sources()).unwrap()
}
fn obs(id: u128, event: i64, arrival: i64, up: u64) -> FlowObservation {
    FlowObservation {
        replay_id: ReplayId(id),
        event_time: t(event),
        arrival_time: t(arrival),
        device_id: device(1),
        upload: up,
        download: up.saturating_add(1),
        protocol: Protocol::Tcp,
        destination: DestinationCategory::Internet,
        interface: 2,
        source: FlowSourceId(1),
        metadata: None,
    }
}
fn advance(e: &mut FlowEngine, s: i64) -> Vec<RollupChange> {
    e.advance_watermark_at(t(s), t(s)).unwrap()
}
fn ups(changes: &[RollupChange], r: Resolution) -> Vec<&Rollup> {
    changes
        .iter()
        .filter_map(|c| match c {
            RollupChange::Upsert(x) | RollupChange::Correction(x) if x.key.resolution == r => {
                Some(x)
            }
            _ => None,
        })
        .collect()
}
fn apply_durable(state: &mut BTreeMap<RollupKey, Rollup>, changes: &[RollupChange]) {
    for change in changes {
        match change {
            RollupChange::Upsert(r) | RollupChange::Correction(r) => {
                state.insert(r.key.clone(), r.clone());
            }
            RollupChange::Retire(r) => assert!(r.cache_only),
        }
    }
}

#[test]
fn source_registry_is_closed_and_maps_every_coverage_kind() {
    for (id, expected) in [
        (1, Coverage::Complete),
        (2, Coverage::Complete),
        (3, Coverage::Complete),
        (4, Coverage::RouterReported),
        (5, Coverage::LocalOnly),
        (6, Coverage::Estimated),
    ] {
        let mut e = engine();
        let mut o = obs(id, 10, 10, 1);
        o.source = FlowSourceId(id as u64);
        e.observe(o).unwrap();
        let got = advance(&mut e, 11);
        assert_eq!(ups(&got, Resolution::Second)[0].coverage, expected);
    }
    let mut e = engine();
    let mut o = obs(99, 20, 20, 1);
    o.source = FlowSourceId(99);
    assert_eq!(e.observe(o), Err(FlowError::UnknownSource));
}

#[test]
fn duplicate_source_and_source_capacity_are_configuration_errors() {
    let mut c = cfg();
    c.max_sources = 1;
    assert_eq!(
        FlowEngine::new(c.clone(), vec![sources()[0].clone(), sources()[0].clone()]).unwrap_err(),
        FlowError::Config
    );
    assert_eq!(
        FlowEngine::new(c, vec![sources()[0].clone(), sources()[1].clone()]).unwrap_err(),
        FlowError::Capacity
    );
}

#[test]
fn all_dimensions_directions_and_devices_are_distinct_and_ordered() {
    let mut e = engine();
    let mut a = obs(1, 0, 0, 3);
    a.download = 7;
    let mut b = obs(2, 0, 0, 11);
    b.device_id = device(2);
    b.protocol = Protocol::Udp;
    b.destination = DestinationCategory::Lan;
    b.interface = 9;
    e.observe(b).unwrap();
    e.observe(a).unwrap();
    let x = advance(&mut e, 1);
    let r = ups(&x, Resolution::Second);
    assert_eq!(r.len(), 2);
    assert_eq!((r[0].bytes.upload, r[0].bytes.download), (3, 7));
    assert!(r[0].key < r[1].key);
}

#[test]
fn exact_second_minute_hour_edges_conserve_without_early_close() {
    let mut e = engine();
    e.observe(obs(1, 59, 59, 2)).unwrap();
    assert!(advance(&mut e, 59).is_empty());
    let x = advance(&mut e, 60);
    assert_eq!(
        ups(&x, Resolution::Second)
            .iter()
            .map(|x| x.bytes.upload)
            .sum::<u64>(),
        2
    );
    assert_eq!(ups(&x, Resolution::Minute).len(), 1);
    e.observe(obs(2, 60, 60, 3)).unwrap();
    e.observe(obs(3, 3599, 3599, 5)).unwrap();
    let x = advance(&mut e, 3600);
    assert_eq!(
        ups(&x, Resolution::Hour)
            .iter()
            .map(|x| x.bytes.upload)
            .sum::<u64>(),
        10
    );
}

#[test]
fn watermark_is_monotonic_idempotent_and_future_bounded() {
    let mut e = engine();
    e.observe(obs(1, 10, 10, 1)).unwrap();
    assert!(!advance(&mut e, 11).is_empty());
    assert!(advance(&mut e, 11).is_empty());
    assert_eq!(e.advance_watermark_at(t(10), t(11)), Err(FlowError::Time));
    assert!(
        advance(&mut e, 100)
            .iter()
            .all(|c| matches!(c, RollupChange::Retire(_)))
    );
    assert!(advance(&mut e, 100).is_empty());
}

#[test]
fn late_event_corrects_second_and_parent_rollups_once() {
    let mut e = engine();
    e.observe(obs(1, 10, 10, 2)).unwrap();
    advance(&mut e, 11);
    e.observe(obs(2, 10, 12, 3)).unwrap();
    let x = advance(&mut e, 12);
    assert!(x.iter().any(|c|matches!(c,RollupChange::Correction(r) if r.key.resolution==Resolution::Second && r.bytes.upload==5)));
    assert!(x.iter().any(|c|matches!(c,RollupChange::Correction(r) if r.key.resolution==Resolution::Minute && r.bytes.upload==5)));
    assert!(advance(&mut e, 12).is_empty());
}

#[test]
fn too_late_is_rejected_atomically() {
    let mut e = engine();
    e.observe(obs(1, 10, 10, 2)).unwrap();
    advance(&mut e, 20);
    let before = e.snapshot();
    assert_eq!(e.observe(obs(2, 10, 20, 3)), Err(FlowError::TooLate));
    assert_eq!(e.snapshot(), before);
}

#[test]
fn replay_window_rejects_then_evicts_but_old_event_remains_too_late() {
    let mut c = cfg();
    c.replay_ttl = Duration::seconds(6);
    c.lateness = Duration::seconds(5);
    c.max_replay_ids = 1;
    let mut e = FlowEngine::new(c, sources()).unwrap();
    e.observe(obs(1, 10, 10, 2)).unwrap();
    assert_eq!(e.observe(obs(1, 10, 11, 2)), Err(FlowError::Replay));
    advance(&mut e, 20);
    assert_eq!(e.observe(obs(1, 10, 20, 2)), Err(FlowError::TooLate));
    let mut fresh = obs(1, 20, 20, 2);
    fresh.event_time = t(20);
    e.observe(fresh).unwrap();
}

#[test]
fn expired_replay_without_watermark_cannot_double_count_old_event() {
    let mut c = cfg();
    c.replay_ttl = Duration::seconds(6);
    c.lateness = Duration::seconds(5);
    c.max_replay_ids = 1;
    let mut e = FlowEngine::new(c, sources()).unwrap();
    e.observe(obs(1, 10, 10, 2)).unwrap();
    assert_eq!(e.observe(obs(1, 10, 20, 2)), Err(FlowError::TooLate));
    e.observe(obs(1, 20, 20, 3)).unwrap();
}

#[test]
fn watermark_uses_monotonic_trusted_clock_and_supports_idle_advance() {
    let mut e = engine();
    e.observe(obs(1, 10, 10, 1)).unwrap();
    assert_eq!(
        e.advance_watermark_at(t(20), t(19)),
        Err(FlowError::FutureSkew)
    );
    assert!(!e.advance_watermark_at(t(11), t(11)).unwrap().is_empty());
    assert_eq!(e.advance_watermark_at(t(10), t(10)), Err(FlowError::Time));
    assert!(
        e.advance_watermark_at(t(20), t(20))
            .unwrap()
            .iter()
            .all(|c| matches!(c, RollupChange::Retire(_)))
    );
}

#[test]
fn parallel_visibility_sources_choose_one_authoritative_winner() {
    let mut e = engine();
    let mut gateway = obs(1, 1, 1, 7);
    gateway.download = 0;
    let mut router = obs(2, 1, 1, 7);
    router.download = 0;
    router.source = FlowSourceId(4);
    let mut local = obs(3, 1, 1, 7);
    local.download = 0;
    local.source = FlowSourceId(5);
    e.observe(local).unwrap();
    e.observe(router).unwrap();
    e.observe(gateway).unwrap();
    let changes = advance(&mut e, 2);
    let r = ups(&changes, Resolution::Second)[0];
    assert_eq!(r.bytes.upload, 7);
    assert_eq!(r.coverage, Coverage::Complete);
}

#[test]
fn higher_authority_source_switch_replaces_instead_of_adding() {
    let mut e = engine();
    let mut local = obs(1, 1, 1, 7);
    local.download = 0;
    local.source = FlowSourceId(5);
    e.observe(local).unwrap();
    advance(&mut e, 2);
    let mut gateway = obs(2, 1, 3, 7);
    gateway.download = 0;
    e.observe(gateway).unwrap();
    let x = advance(&mut e, 3);
    assert!(x.iter().any(|c|matches!(c,RollupChange::Correction(r) if r.key.resolution==Resolution::Second&&r.bytes.upload==7&&r.coverage==Coverage::Complete)));
    assert!(x.iter().any(|c|matches!(c,RollupChange::Correction(r) if r.key.resolution==Resolution::Minute&&r.bytes.upload==7)));
}

#[test]
fn cache_retirement_never_subtracts_durable_parent_totals() {
    let mut c = cfg();
    c.correction_retention = Duration::seconds(5);
    let mut e = FlowEngine::new(c, sources()).unwrap();
    e.observe(obs(1, 59, 59, 2)).unwrap();
    let first = advance(&mut e, 60);
    let minute = ups(&first, Resolution::Minute)[0].clone();
    let mut durable = BTreeMap::new();
    apply_durable(&mut durable, &first);
    let retirement = advance(&mut e, 66);
    apply_durable(&mut durable, &retirement);
    assert!(retirement.iter().any(|c|matches!(c,RollupChange::Retire(r) if r.key.resolution==Resolution::Second && r.cache_only)));
    assert!(!retirement.iter().any(|c|matches!(c,RollupChange::Correction(r) if r.key.resolution!=Resolution::Second && r.bytes.upload<minute.bytes.upload)));
    let mut later = obs(2, 66, 66, 3);
    later.download = 0;
    e.observe(later).unwrap();
    let x = advance(&mut e, 67);
    apply_durable(&mut durable, &x);
    let x = advance(&mut e, 3606);
    apply_durable(&mut durable, &x);
    assert_eq!(
        durable
            .values()
            .filter(|r| r.key.resolution == Resolution::Hour && r.key.bucket == t(0))
            .map(|r| r.bytes.upload)
            .sum::<u64>(),
        5
    );
}

#[test]
fn inactive_device_capacity_recovers_after_state_retirement() {
    let mut c = cfg();
    c.max_devices = 1;
    c.correction_retention = Duration::seconds(5);
    c.replay_ttl = Duration::seconds(5);
    let mut e = FlowEngine::new(c, sources()).unwrap();
    e.observe(obs(1, 1, 1, 1)).unwrap();
    advance(&mut e, 10);
    let mut x = obs(2, 10, 10, 1);
    x.device_id = device(2);
    e.observe(x).unwrap();
}

#[test]
fn coverage_merge_is_conservative() {
    for (a, b, want) in [
        (1, 2, Coverage::Complete),
        (4, 4, Coverage::RouterReported),
        (5, 5, Coverage::LocalOnly),
        (4, 5, Coverage::RouterReported),
        (1, 4, Coverage::Complete),
        (1, 6, Coverage::Complete),
    ] {
        let mut e = engine();
        let mut x = obs(1, 1, 1, 1);
        x.source = FlowSourceId(a);
        let mut y = obs(2, 1, 1, 1);
        y.source = FlowSourceId(b);
        e.observe(x).unwrap();
        e.observe(y).unwrap();
        assert_eq!(
            ups(&advance(&mut e, 2), Resolution::Second)[0].coverage,
            want
        );
    }
}

#[test]
fn nonoverlapping_source_intervals_make_parent_coverage_conservative() {
    let mut e = engine();
    let mut a = obs(1, 1, 1, 1);
    a.source = FlowSourceId(4);
    let mut b = obs(2, 2, 2, 1);
    b.source = FlowSourceId(5);
    e.observe(a).unwrap();
    e.observe(b).unwrap();
    let x = advance(&mut e, 3);
    assert_eq!(ups(&x, Resolution::Minute)[0].coverage, Coverage::Estimated);
}

#[test]
fn privacy_off_strips_metadata_and_privacy_on_retains_it() {
    let meta = DestinationMetadata {
        ip: Some("192.0.2.1".parse::<IpAddr>().unwrap()),
        domain: Some("Example.COM".into()),
    };
    let mut off = engine();
    let mut x = obs(1, 1, 1, 1);
    x.metadata = Some(meta.clone());
    off.observe(x).unwrap();
    let r = ups(&advance(&mut off, 2), Resolution::Second)[0].clone();
    assert_eq!(r.metadata, None);
    assert!(!serde_json::to_string(&r).unwrap().contains("192.0.2.1"));
    assert!(
        !serde_json::to_string(&off.snapshot())
            .unwrap()
            .contains("192.0.2.1")
    );
    let mut c = cfg();
    c.retain_destination_metadata = true;
    let mut on = FlowEngine::new(c, sources()).unwrap();
    let mut x = obs(2, 1, 1, 1);
    x.metadata = Some(meta);
    on.observe(x).unwrap();
    let r = ups(&advance(&mut on, 2), Resolution::Second)[0].clone();
    assert_eq!(r.metadata.unwrap().domain.as_deref(), Some("example.com"));
}

#[test]
fn malformed_and_oversized_metadata_reject_atomically() {
    let mut c = cfg();
    c.retain_destination_metadata = true;
    c.max_domain_bytes = 64;
    let mut e = FlowEngine::new(c, sources()).unwrap();
    let before = e.snapshot();
    let mut x = obs(1, 1, 1, 1);
    x.metadata = Some(DestinationMetadata {
        ip: None,
        domain: Some("bad domain".into()),
    });
    assert_eq!(e.observe(x), Err(FlowError::Metadata));
    assert_eq!(e.snapshot(), before);
    let mut c = cfg();
    c.retain_destination_metadata = true;
    c.max_domain_bytes = 8;
    let mut e = FlowEngine::new(c, sources()).unwrap();
    let mut x = obs(2, 1, 1, 1);
    x.metadata = Some(DestinationMetadata {
        ip: None,
        domain: Some("toolong.example".into()),
    });
    assert_eq!(e.observe(x), Err(FlowError::Capacity));
}

#[test]
fn device_dimension_replay_open_row_and_finalized_row_bounds_are_atomic() {
    let mut c = cfg();
    c.max_devices = 1;
    c.max_open_rows = 1;
    c.max_replay_ids = 1;
    c.max_finalized_rows = 2;
    let mut e = FlowEngine::new(c, sources()).unwrap();
    e.observe(obs(1, 1, 1, 1)).unwrap();
    let snap = e.snapshot();
    let mut x = obs(2, 1, 1, 1);
    x.device_id = device(2);
    assert_eq!(e.observe(x), Err(FlowError::Capacity));
    assert_eq!(e.snapshot(), snap);
    let mut x = obs(2, 1, 1, 1);
    x.protocol = Protocol::Udp;
    assert_eq!(e.observe(x), Err(FlowError::Capacity));
    assert_eq!(e.snapshot(), snap);
    assert_eq!(e.observe(obs(2, 2, 1, 1)), Err(FlowError::Capacity));
    assert_eq!(e.snapshot(), snap);
    assert_eq!(e.advance_watermark_at(t(2), t(2)), Err(FlowError::Capacity));
    assert_eq!(e.snapshot(), snap);
}

#[test]
fn output_and_work_limits_are_preflighted_atomically() {
    let mut c = cfg();
    c.max_outputs_per_call = 1;
    let mut e = FlowEngine::new(c, sources()).unwrap();
    e.observe(obs(1, 1, 1, 1)).unwrap();
    let s = e.snapshot();
    assert_eq!(
        e.advance_watermark_at(t(2), t(2)),
        Err(FlowError::OutputLimit)
    );
    assert_eq!(e.snapshot(), s);
    let mut c = cfg();
    c.max_work_per_call = 1;
    let mut e = FlowEngine::new(c, sources()).unwrap();
    e.observe(obs(1, 1, 1, 1)).unwrap();
    let s = e.snapshot();
    assert_eq!(
        e.advance_watermark_at(t(2), t(2)),
        Err(FlowError::WorkLimit)
    );
    assert_eq!(e.snapshot(), s);
}

#[test]
fn correction_retention_evicts_old_in_memory_rows_and_recovers_capacity() {
    let mut c = cfg();
    c.correction_retention = Duration::seconds(5);
    c.max_open_rows = 1;
    let mut e = FlowEngine::new(c, sources()).unwrap();
    e.observe(obs(1, 1, 1, 1)).unwrap();
    advance(&mut e, 2);
    advance(&mut e, 10);
    assert_eq!(e.snapshot().open_row_count, 0);
    e.observe(obs(2, 10, 10, 2)).unwrap();
}

#[test]
fn byte_overflow_and_zero_interface_reject_atomically() {
    let mut e = engine();
    let mut a = obs(1, 1, 1, u64::MAX);
    a.download = 0;
    e.observe(a).unwrap();
    let before = e.snapshot();
    let mut b = obs(2, 1, 1, 1);
    b.download = 0;
    assert_eq!(e.observe(b), Err(FlowError::Overflow));
    assert_eq!(e.snapshot(), before);
    let mut z = obs(3, 2, 2, 1);
    z.interface = 0;
    assert_eq!(e.observe(z), Err(FlowError::Interface));
}

#[test]
fn future_event_and_arrival_regression_reject() {
    let mut e = engine();
    assert_eq!(e.observe(obs(1, 20, 10, 1)), Err(FlowError::FutureSkew));
    e.observe(obs(2, 10, 10, 1)).unwrap();
    assert_eq!(e.observe(obs(3, 10, 9, 1)), Err(FlowError::Time));
}

#[test]
fn invalid_durations_and_all_zero_bounds_reject() {
    let mut variants = Vec::new();
    macro_rules! z {
        ($f:ident) => {{
            let mut c = cfg();
            c.$f = 0;
            variants.push(c)
        }};
    }
    z!(max_devices);
    z!(max_sources);
    z!(max_open_rows);
    z!(max_replay_ids);
    z!(max_finalized_rows);
    z!(max_outputs_per_call);
    z!(max_work_per_call);
    z!(max_domain_bytes);
    for c in variants {
        assert_eq!(
            FlowEngine::new(c, sources()).unwrap_err(),
            FlowError::Config
        );
    }
    let mut c = cfg();
    c.lateness = Duration::seconds(-1);
    assert_eq!(
        FlowEngine::new(c, sources()).unwrap_err(),
        FlowError::Config
    );
    let mut c = cfg();
    c.replay_ttl = Duration::seconds(4);
    c.lateness = Duration::seconds(5);
    assert_eq!(
        FlowEngine::new(c, sources()).unwrap_err(),
        FlowError::Config
    );
}

#[test]
fn negative_epoch_and_extreme_times_never_panic_and_bucket_correctly() {
    let mut e = engine();
    e.observe(obs(1, -1, -1, 1)).unwrap();
    let changes = advance(&mut e, 0);
    let r = ups(&changes, Resolution::Second)[0];
    assert_eq!(r.key.bucket, t(-1));
    let mut e = engine();
    let mut x = obs(1, 0, 0, 1);
    x.event_time = DateTime::<Utc>::MIN_UTC;
    x.arrival_time = DateTime::<Utc>::MIN_UTC;
    assert!(matches!(
        e.observe(x),
        Err(FlowError::Time | FlowError::Overflow)
    ));
}

#[test]
fn public_json_is_stable_snake_case_and_order_independent() {
    let mut a = engine();
    let mut b = engine();
    for x in [obs(2, 2, 2, 2), obs(1, 1, 2, 1)] {
        a.observe(x).unwrap();
    }
    for x in [obs(1, 1, 2, 1), obs(2, 2, 2, 2)] {
        b.observe(x).unwrap();
    }
    advance(&mut a, 3);
    advance(&mut b, 3);
    assert_eq!(
        serde_json::to_string(&a.snapshot()).unwrap(),
        serde_json::to_string(&b.snapshot()).unwrap()
    );
    assert_eq!(serde_json::to_string(&Protocol::Icmp).unwrap(), "\"icmp\"");
}
