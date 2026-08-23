use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, PresenceState};
use lattice_intelligence::presence::*;
fn id() -> DeviceId {
    DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445501").unwrap()
}
fn t(s: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + s, 0).unwrap()
}
fn ev(kind: PresenceEvidenceKind, at: i64, until: Option<i64>) -> PresenceEvidence {
    PresenceEvidence {
        device_id: id(),
        source: "sensor-a".into(),
        kind,
        observed_at: t(at),
        valid_until: until.map(t),
        trusted: true,
        verified: false,
    }
}
fn eng() -> PresenceEngine {
    PresenceEngine::new(PresenceConfig {
        online_window: Duration::seconds(10),
        correction_window: Duration::seconds(30),
        retention: Duration::hours(1),
        join_confirmations: 2,
        departure_confirmations: 2,
        max_devices: 4,
        max_evidence_per_device: 16,
        max_history_per_device: 16,
        max_source_len: 64,
        future_skew: Duration::seconds(2),
    })
    .unwrap()
}

#[test]
fn exact_state_boundaries_and_hysteresis() {
    let mut e = eng();
    assert!(
        e.ingest(ev(PresenceEvidenceKind::Traffic, 0, None), t(0))
            .unwrap()
            .is_none()
    );
    let j = e
        .ingest(ev(PresenceEvidenceKind::Traffic, 1, None), t(1))
        .unwrap()
        .unwrap();
    assert_eq!(j.to, PresenceState::Online);
    assert_eq!(
        e.evaluate(id(), t(11)).unwrap().unwrap().to,
        PresenceState::Unknown
    );
    let mut lease = ev(PresenceEvidenceKind::Lease, 2, Some(20));
    assert!(e.ingest(lease.clone(), t(11)).unwrap().is_none());
    assert_eq!(
        e.ingest(
            ev(PresenceEvidenceKind::RouterAssociation, 3, Some(20)),
            t(12)
        )
        .unwrap()
        .unwrap()
        .to,
        PresenceState::Quiet
    );
    assert!(e.evaluate(id(), t(20)).unwrap().is_none());
    assert_eq!(
        e.ingest(
            ev(PresenceEvidenceKind::ConfirmationFailure, 21, None),
            t(21)
        )
        .unwrap()
        .unwrap()
        .to,
        PresenceState::Unknown
    );
    assert_eq!(
        e.ingest(
            ev(PresenceEvidenceKind::ConfirmationFailure, 22, None),
            t(22)
        )
        .unwrap()
        .unwrap()
        .to,
        PresenceState::Offline
    );
    lease.valid_until = Some(t(30));
    assert!(e.ingest(lease, t(23)).unwrap().is_none());
    assert_eq!(
        e.ingest(
            ev(PresenceEvidenceKind::RouterAssociation, 24, Some(30)),
            t(24)
        )
        .unwrap()
        .unwrap()
        .to,
        PresenceState::Quiet
    )
}
#[test]
fn probe_only_never_fabricates_presence() {
    let mut e = eng();
    e.ingest(ev(PresenceEvidenceKind::ProbeSuccess, 0, Some(20)), t(0))
        .unwrap();
    e.ingest(ev(PresenceEvidenceKind::ProbeSuccess, 1, Some(20)), t(1))
        .unwrap();
    assert_eq!(e.state(id()), Some(PresenceState::Unknown));
}
#[test]
fn verified_block_and_unblock_override_association() {
    let mut e = eng();
    e.ingest(ev(PresenceEvidenceKind::Traffic, 0, None), t(0))
        .unwrap();
    e.ingest(ev(PresenceEvidenceKind::Traffic, 1, None), t(1))
        .unwrap();
    let mut b = ev(PresenceEvidenceKind::EnforcementBlocked, 2, None);
    b.verified = true;
    assert_eq!(
        e.ingest(b, t(2)).unwrap().unwrap().to,
        PresenceState::Blocked
    );
    assert!(
        e.ingest(ev(PresenceEvidenceKind::Traffic, 3, None), t(3))
            .unwrap()
            .is_none()
    );
    assert!(
        e.ingest(ev(PresenceEvidenceKind::SensorImpaired, 3, None), t(3))
            .unwrap()
            .is_none()
    );
    let mut u = ev(PresenceEvidenceKind::EnforcementUnblocked, 4, None);
    u.verified = true;
    assert_eq!(
        e.ingest(u, t(4)).unwrap().unwrap().to,
        PresenceState::Unknown
    );
    assert_eq!(
        e.ingest(ev(PresenceEvidenceKind::SensorRecovered, 5, None), t(5))
            .unwrap()
            .unwrap()
            .to,
        PresenceState::Online
    )
}

#[test]
fn failures_before_or_at_support_expiry_do_not_count() {
    let mut e = eng();
    e.ingest(ev(PresenceEvidenceKind::Lease, 0, Some(10)), t(0))
        .unwrap();
    e.ingest(
        ev(PresenceEvidenceKind::RouterAssociation, 1, Some(10)),
        t(1),
    )
    .unwrap();
    e.ingest(ev(PresenceEvidenceKind::ConfirmationFailure, 9, None), t(9))
        .unwrap();
    e.ingest(
        ev(PresenceEvidenceKind::ConfirmationFailure, 10, None),
        t(10),
    )
    .unwrap();
    assert_ne!(e.state(id()), Some(PresenceState::Offline));
    e.ingest(
        ev(PresenceEvidenceKind::ConfirmationFailure, 11, None),
        t(11),
    )
    .unwrap();
    assert_ne!(e.state(id()), Some(PresenceState::Offline));
    assert_eq!(
        e.ingest(
            ev(PresenceEvidenceKind::ConfirmationFailure, 12, None),
            t(12)
        )
        .unwrap()
        .unwrap()
        .to,
        PresenceState::Offline
    );
}
#[test]
fn impaired_and_contradictory_never_fabricate_offline() {
    let mut e = eng();
    e.ingest(ev(PresenceEvidenceKind::Traffic, 0, None), t(0))
        .unwrap();
    e.ingest(ev(PresenceEvidenceKind::Traffic, 1, None), t(1))
        .unwrap();
    assert_eq!(
        e.ingest(ev(PresenceEvidenceKind::SensorImpaired, 2, None), t(2))
            .unwrap()
            .unwrap()
            .to,
        PresenceState::Unknown
    );
    assert!(
        e.ingest(ev(PresenceEvidenceKind::ConfirmationFailure, 3, None), t(3))
            .unwrap()
            .is_none()
    );
    assert!(
        e.ingest(ev(PresenceEvidenceKind::ConfirmationFailure, 4, None), t(4))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        e.ingest(ev(PresenceEvidenceKind::SensorRecovered, 5, None), t(5))
            .unwrap()
            .unwrap()
            .to,
        PresenceState::Online
    );
    assert_eq!(
        e.ingest(ev(PresenceEvidenceKind::Contradiction, 6, None), t(6))
            .unwrap()
            .unwrap()
            .to,
        PresenceState::Unknown
    );
    assert_eq!(
        e.ingest(
            ev(PresenceEvidenceKind::ContradictionCleared, 7, None),
            t(7)
        )
        .unwrap()
        .unwrap()
        .to,
        PresenceState::Online
    )
}
#[test]
fn late_evidence_corrects_only_recent_departure() {
    let mut e = eng();
    e.ingest(ev(PresenceEvidenceKind::Lease, 0, Some(5)), t(0))
        .unwrap();
    e.ingest(ev(PresenceEvidenceKind::Lease, 1, Some(5)), t(1))
        .unwrap();
    e.ingest(ev(PresenceEvidenceKind::ConfirmationFailure, 6, None), t(6))
        .unwrap();
    let d = e
        .ingest(ev(PresenceEvidenceKind::ConfirmationFailure, 7, None), t(7))
        .unwrap()
        .unwrap();
    let c = e
        .ingest(ev(PresenceEvidenceKind::Traffic, 6, None), t(20))
        .unwrap()
        .unwrap();
    assert_eq!(c.correction_of, Some(d.transition_id));
    assert_eq!(c.from, PresenceState::Offline);
    let mut old = eng();
    old.ingest(ev(PresenceEvidenceKind::Lease, 0, Some(5)), t(0))
        .unwrap();
    old.ingest(ev(PresenceEvidenceKind::Lease, 1, Some(5)), t(1))
        .unwrap();
    old.ingest(ev(PresenceEvidenceKind::ConfirmationFailure, 6, None), t(6))
        .unwrap();
    old.ingest(ev(PresenceEvidenceKind::ConfirmationFailure, 7, None), t(7))
        .unwrap();
    assert!(
        old.ingest(ev(PresenceEvidenceKind::Traffic, 6, None), t(40))
            .unwrap()
            .is_none()
    )
}
#[test]
fn rejects_bad_inputs_and_clock_rollback_atomically() {
    let mut e = eng();
    let before = e.snapshot();
    let mut bad = ev(PresenceEvidenceKind::Traffic, 10, None);
    bad.trusted = false;
    assert!(e.ingest(bad, t(10)).is_err());
    assert_eq!(before, e.snapshot());
    assert!(
        e.ingest(ev(PresenceEvidenceKind::Traffic, 20, None), t(10))
            .is_err()
    );
    assert_eq!(before, e.snapshot());
    e.ingest(ev(PresenceEvidenceKind::Traffic, 0, None), t(0))
        .unwrap();
    let snap = e.snapshot();
    assert!(e.evaluate(id(), t(-1)).is_err());
    assert_eq!(snap, e.snapshot())
}
#[test]
fn capacity_retention_metadata_and_serialization_are_deterministic() {
    let mut e = PresenceEngine::new(PresenceConfig {
        max_evidence_per_device: 2,
        ..PresenceConfig::default()
    })
    .unwrap();
    let a = ev(PresenceEvidenceKind::Traffic, 0, None);
    e.ingest(a.clone(), t(0)).unwrap();
    e.ingest(ev(PresenceEvidenceKind::Lease, 1, Some(100)), t(1))
        .unwrap();
    let snap = e.snapshot();
    assert!(
        e.ingest(
            ev(PresenceEvidenceKind::RouterAssociation, 2, Some(100)),
            t(2)
        )
        .is_err()
    );
    assert_eq!(snap, e.snapshot());
    let mut retained = PresenceEngine::new(PresenceConfig {
        retention: Duration::seconds(40),
        correction_window: Duration::seconds(30),
        max_evidence_per_device: 2,
        ..PresenceConfig::default()
    })
    .unwrap();
    retained
        .ingest(ev(PresenceEvidenceKind::Traffic, 0, None), t(0))
        .unwrap();
    retained
        .ingest(ev(PresenceEvidenceKind::Lease, 1, Some(2)), t(1))
        .unwrap();
    assert!(
        retained
            .ingest(ev(PresenceEvidenceKind::Traffic, 50, None), t(50))
            .is_ok()
    );
    assert!(retained.snapshot().evidence <= 2);
    let mut h = eng();
    h.ingest(ev(PresenceEvidenceKind::Traffic, 0, None), t(0))
        .unwrap();
    let tr = h
        .ingest(ev(PresenceEvidenceKind::Traffic, 1, None), t(1))
        .unwrap()
        .unwrap();
    assert_eq!(tr.trigger.source, "sensor-a");
    assert_eq!(tr.trigger.observed_at, t(1));
    assert_eq!(tr.trigger.kind, PresenceEvidenceKind::Traffic);
    let one = serde_json::to_string(&tr).unwrap();
    let two = serde_json::to_string(&tr).unwrap();
    assert_eq!(one, two);
}
