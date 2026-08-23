use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily, PresenceState};
use lattice_intelligence::{
    Decision, IdentityConfig, IdentityEngine, IdentityError, ProposalStatus,
    presence::{
        PresenceCheckpoint, PresenceConfig, PresenceEngine, PresenceError, PresenceEvidence,
        PresenceEvidenceKind,
    },
};

fn id(n: u8) -> DeviceId {
    DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap()
}

fn identity() -> IdentityEngine {
    IdentityEngine::new(IdentityConfig::default(), (1..20).map(id)).unwrap()
}

fn fact(family: EvidenceFamily, key: &str, value: &str) -> EvidenceFact {
    EvidenceFact {
        family,
        source: "sensor-a".into(),
        key: key.into(),
        value: value.into(),
        confidence: 0.95,
        observed_at: at(0),
        expires_at: None,
        owner_confirmed: false,
    }
}

fn presence_config() -> PresenceConfig {
    PresenceConfig {
        online_window: Duration::seconds(10),
        correction_window: Duration::seconds(30),
        retention: Duration::hours(1),
        future_skew: Duration::seconds(2),
        confirmation_window: Duration::seconds(30),
        trusted_sources: vec!["sensor-a".into()],
        join_confirmations: 2,
        departure_confirmations: 2,
        max_devices: 4,
        max_evidence_per_device: 16,
        max_history_per_device: 2,
        max_source_len: 64,
    }
}

fn evidence(device_id: DeviceId, kind: PresenceEvidenceKind, observed: i64) -> PresenceEvidence {
    PresenceEvidence {
        device_id,
        source: "sensor-a".into(),
        kind,
        observed_at: at(observed),
        valid_until: None,
    }
}

fn online_then_offline(engine: &mut PresenceEngine, device: DeviceId) -> u64 {
    engine
        .ingest(evidence(device, PresenceEvidenceKind::Traffic, 0), at(0))
        .unwrap();
    engine
        .ingest(evidence(device, PresenceEvidenceKind::Traffic, 1), at(1))
        .unwrap();
    engine
        .ingest(
            evidence(device, PresenceEvidenceKind::ConfirmationFailure, 12),
            at(12),
        )
        .unwrap();
    engine
        .ingest(
            evidence(device, PresenceEvidenceKind::ConfirmationFailure, 13),
            at(13),
        )
        .unwrap()
        .unwrap()
        .transition_id
}

#[test]
fn identity_checkpoint_json_and_restore_continue_stable_matching() {
    let mut engine = identity();
    let first = engine
        .observe(
            None,
            vec![
                fact(EvidenceFamily::LinkLayer, "mac", "00:11:22:33:44:55"),
                fact(EvidenceFamily::Addressing, "dhcp_client_id", "client-a"),
            ],
        )
        .unwrap();
    let checkpoint = engine.checkpoint();
    assert_eq!(
        serde_json::to_string(&checkpoint).unwrap(),
        serde_json::to_string(&engine.checkpoint()).unwrap()
    );
    let mut restored =
        IdentityEngine::from_checkpoint(IdentityConfig::default(), checkpoint).unwrap();
    assert_eq!(
        restored
            .observe(
                None,
                vec![
                    fact(EvidenceFamily::LinkLayer, "mac", "00:11:22:33:44:55"),
                    fact(EvidenceFamily::Addressing, "dhcp_client_id", "client-a"),
                ],
            )
            .unwrap(),
        first
    );
    assert_eq!(restored.observe(None, vec![]).unwrap(), id(2));
}

#[test]
fn identity_checkpoint_restores_owner_precedence_and_accept_undo_audit() {
    let mut engine = identity();
    let left = engine.observe(None, vec![]).unwrap();
    let right = engine.observe(None, vec![]).unwrap();
    engine
        .set_owner_fact(left, "vendor", "Mine", at(1))
        .unwrap();
    engine
        .set_owner_fact(left, "class", "camera", at(2))
        .unwrap();
    let proposal = engine
        .propose_merge(
            left,
            right,
            0.9,
            vec![EvidenceFamily::Service],
            vec!["owner".into()],
        )
        .unwrap();
    engine.decide(proposal, Decision::Accept).unwrap();
    engine.undo(proposal).unwrap();
    let restored =
        IdentityEngine::from_checkpoint(IdentityConfig::default(), engine.checkpoint()).unwrap();
    assert_eq!(restored.resolve(left).unwrap(), left);
    assert_eq!(restored.resolve(right).unwrap(), right);
    assert_eq!(
        restored.identification(left).unwrap().unwrap().vendor,
        "Mine"
    );
    assert_eq!(restored.audit().len(), 2);
}

#[test]
fn identity_checkpoint_rejects_non_runtime_owner_and_audit_states() {
    let mut engine = identity();
    let left = engine.observe(None, vec![]).unwrap();
    let right = engine.observe(None, vec![]).unwrap();
    let proposal = engine
        .propose_merge(
            left,
            right,
            0.9,
            vec![EvidenceFamily::Service],
            vec!["x".into()],
        )
        .unwrap();
    let mut checkpoint = engine.checkpoint();
    checkpoint.proposals[0].status = ProposalStatus::Accepted;
    assert!(matches!(
        IdentityEngine::from_checkpoint(IdentityConfig::default(), checkpoint),
        Err(IdentityError::InvalidCheckpoint(_))
    ));

    let mut checkpoint = engine.checkpoint();
    checkpoint
        .owners
        .push(lattice_intelligence::OwnerAuditRecord {
            sequence: checkpoint.next_owner,
            device_id: id(19),
            key: "vendor".into(),
            value: Some("Mine".into()),
            recorded_at: at(5),
        });
    checkpoint.next_owner += 1;
    assert!(matches!(
        IdentityEngine::from_checkpoint(IdentityConfig::default(), checkpoint),
        Err(IdentityError::InvalidCheckpoint(_))
    ));
    let _ = proposal;
}

#[test]
fn identity_checkpoint_rejects_version_capacity_duplicates_and_dangling_edges() {
    let mut engine = identity();
    let left = engine.observe(None, vec![]).unwrap();
    let right = engine.observe(None, vec![]).unwrap();
    let proposal = engine
        .propose_merge(
            left,
            right,
            0.9,
            vec![EvidenceFamily::Service],
            vec!["x".into()],
        )
        .unwrap();

    let mut checkpoint = engine.checkpoint();
    checkpoint.version = 99;
    assert!(IdentityEngine::from_checkpoint(IdentityConfig::default(), checkpoint).is_err());

    let mut checkpoint = engine.checkpoint();
    checkpoint.ids.push(id(3));
    assert!(IdentityEngine::from_checkpoint(IdentityConfig::default(), checkpoint).is_err());

    let mut checkpoint = engine.checkpoint();
    checkpoint
        .edges
        .push(lattice_intelligence::IdentityCheckpointEdge {
            proposal_id: proposal,
            left,
            right: id(19),
            active: true,
        });
    assert!(IdentityEngine::from_checkpoint(IdentityConfig::default(), checkpoint).is_err());

    let config = IdentityConfig {
        max_proposals: 1,
        ..IdentityConfig::default()
    };
    let mut checkpoint = engine.checkpoint();
    checkpoint.proposals.push(checkpoint.proposals[0].clone());
    assert!(IdentityEngine::from_checkpoint(config, checkpoint).is_err());
}

#[test]
fn presence_checkpoint_restores_offline_state_and_monotonic_next_transition() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    let departure = online_then_offline(&mut engine, id(1));
    let mut restored =
        PresenceEngine::from_checkpoint(presence_config(), engine.checkpoint()).unwrap();
    assert_eq!(restored.state(id(1)), Some(PresenceState::Offline));
    let next = restored
        .record_verified_enforcement(id(1), true, "sensor-a", at(14), at(14))
        .unwrap()
        .unwrap();
    assert!(next.transition_id > departure);
    assert!(PresenceEngine::from_checkpoint(presence_config(), restored.checkpoint()).is_ok());
}

#[test]
fn presence_checkpoint_json_is_deterministic() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(2));
    online_then_offline(&mut engine, id(1));
    assert_eq!(
        serde_json::to_string(&engine.checkpoint()).unwrap(),
        serde_json::to_string(&engine.checkpoint()).unwrap()
    );
}

#[test]
fn presence_checkpoint_restores_late_correction_for_exact_departure() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    let departure = online_then_offline(&mut engine, id(1));
    let mut restored =
        PresenceEngine::from_checkpoint(presence_config(), engine.checkpoint()).unwrap();
    let corrections = restored
        .ingest_events(
            PresenceEvidence {
                device_id: id(1),
                source: "sensor-a".into(),
                kind: PresenceEvidenceKind::Lease,
                observed_at: at(10),
                valid_until: Some(at(30)),
            },
            at(14),
        )
        .unwrap();
    assert!(
        corrections
            .iter()
            .any(|transition| transition.correction_of == Some(departure))
    );
}

#[test]
fn presence_checkpoint_rejects_dangling_cross_device_and_non_departure_corrections() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    online_then_offline(&mut engine, id(2));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[1].history[1].correction_of =
        Some(checkpoint.devices[0].history[1].transition_id);
    assert!(matches!(
        PresenceEngine::from_checkpoint(presence_config(), checkpoint),
        Err(PresenceError::InvalidCheckpoint(_))
    ));

    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[0].history[1].correction_of =
        Some(checkpoint.devices[0].history[0].transition_id);
    assert!(matches!(
        PresenceEngine::from_checkpoint(presence_config(), checkpoint),
        Err(PresenceError::InvalidCheckpoint(_))
    ));
}

#[test]
fn presence_checkpoint_rejects_invalid_trigger_flags_and_cursor() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[0].history[0].trigger.kind = PresenceEvidenceKind::Evaluation;
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());

    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[0].history[0].trigger.kind = PresenceEvidenceKind::EnforcementBlocked;
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());

    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    engine
        .record_verified_enforcement(id(1), true, "sensor-a", at(14), at(14))
        .unwrap();
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[0].blocked = false;
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());

    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[0].blocked = true;
    checkpoint.devices[0].enforcement_clock = None;
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());

    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[0].evicted_through = Some(checkpoint.next_transition);
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());
}

#[test]
fn presence_checkpoint_rejects_evaluation_and_unproven_enforcement_evidence() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[0].evidence.push(PresenceEvidence {
        device_id: id(1),
        source: "sensor-a".into(),
        kind: PresenceEvidenceKind::Evaluation,
        observed_at: at(13),
        valid_until: None,
    });
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());

    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[0].evidence.push(PresenceEvidence {
        device_id: id(1),
        source: "sensor-a".into(),
        kind: PresenceEvidenceKind::EnforcementBlocked,
        observed_at: at(13),
        valid_until: None,
    });
    checkpoint.devices[0].blocked = true;
    checkpoint.devices[0].enforcement_clock = Some(at(13));
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());
}

#[test]
fn presence_checkpoint_accepts_verified_enforcement_after_its_transition_is_evicted() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    engine
        .record_verified_enforcement(id(1), true, "sensor-a", at(14), at(14))
        .unwrap();
    engine
        .record_verified_enforcement(id(1), false, "sensor-a", at(15), at(15))
        .unwrap();
    engine
        .ingest(evidence(id(1), PresenceEvidenceKind::Traffic, 16), at(16))
        .unwrap();
    engine
        .ingest(evidence(id(1), PresenceEvidenceKind::Traffic, 17), at(17))
        .unwrap();
    engine
        .ingest(
            evidence(id(1), PresenceEvidenceKind::ConfirmationFailure, 28),
            at(28),
        )
        .unwrap();
    engine
        .ingest(
            evidence(id(1), PresenceEvidenceKind::ConfirmationFailure, 29),
            at(29),
        )
        .unwrap();
    let checkpoint = engine.checkpoint();
    assert!(checkpoint.devices[0].evicted_through.is_some());
    assert!(!checkpoint.devices[0].history.iter().any(|transition| {
        transition.trigger.kind == PresenceEvidenceKind::EnforcementUnblocked
    }));
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_ok());
}

#[test]
fn presence_checkpoint_rejects_version_duplicate_ids_and_duplicate_transition_ids() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.version = 2;
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());

    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices.push(checkpoint.devices[0].clone());
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());

    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    online_then_offline(&mut engine, id(2));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[1].history[0].transition_id = checkpoint.devices[0].history[0].transition_id;
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());
}

#[test]
fn presence_checkpoint_rejects_oversize_bad_evidence_and_impossible_chain() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[0].evidence[0].source = "attacker".into();
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());

    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    let mut checkpoint = engine.checkpoint();
    checkpoint.devices[0].history[1].from = PresenceState::Unknown;
    assert!(PresenceEngine::from_checkpoint(presence_config(), checkpoint).is_err());

    let config = PresenceConfig {
        max_history_per_device: 1,
        ..presence_config()
    };
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    assert!(PresenceEngine::from_checkpoint(config, engine.checkpoint()).is_err());
}

#[test]
fn presence_checkpoint_preserves_per_device_eviction_boundary() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    online_then_offline(&mut engine, id(1));
    engine
        .record_verified_enforcement(id(1), true, "sensor-a", at(14), at(14))
        .unwrap();
    let checkpoint: PresenceCheckpoint = engine.checkpoint();
    let evicted = checkpoint.devices[0].evicted_through.unwrap();
    let restored = PresenceEngine::from_checkpoint(presence_config(), checkpoint).unwrap();
    assert_eq!(
        restored.domain_events_since(id(1), evicted - 1),
        Err(PresenceError::CursorExpired)
    );
}

#[test]
fn presence_checkpoint_eviction_keeps_devices_and_cursors_independent() {
    let mut engine = PresenceEngine::new(presence_config()).unwrap();
    let d1_departure = online_then_offline(&mut engine, id(1));
    let d2_departure = online_then_offline(&mut engine, id(2));
    let corrections = engine
        .ingest_events(
            PresenceEvidence {
                device_id: id(1),
                source: "sensor-a".into(),
                kind: PresenceEvidenceKind::Lease,
                observed_at: at(10),
                valid_until: Some(at(30)),
            },
            at(14),
        )
        .unwrap();
    assert!(
        corrections
            .iter()
            .any(|transition| transition.correction_of == Some(d1_departure))
    );
    let d1_live = engine
        .record_verified_enforcement(id(1), true, "sensor-a", at(15), at(15))
        .unwrap()
        .unwrap();
    let restored = PresenceEngine::from_checkpoint(presence_config(), engine.checkpoint()).unwrap();
    assert_eq!(
        restored.domain_events_since(id(1), d1_departure),
        Err(PresenceError::CursorExpired)
    );
    assert_eq!(
        restored
            .domain_events_since(id(1), d1_live.transition_id - 1)
            .unwrap()
            .iter()
            .map(|event| event.transition_id)
            .collect::<Vec<_>>(),
        vec![d1_live.transition_id]
    );
    assert!(
        restored
            .domain_events_since(id(1), d1_live.transition_id)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        restored
            .domain_events_since(id(2), 0)
            .unwrap()
            .iter()
            .map(|event| event.transition_id)
            .collect::<Vec<_>>(),
        vec![d2_departure - 1, d2_departure]
    );
}
