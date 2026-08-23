use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily, PresenceState};
use lattice_intelligence::presence::PresenceEvidenceKind;
use lattice_service::discovery::{DiscoveryObservation, DiscoveryPipeline};

fn id(n: u8) -> DeviceId {
    DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}
fn fact(family: EvidenceFamily, key: &str, value: &str, at: chrono::DateTime<Utc>) -> EvidenceFact {
    EvidenceFact {
        family,
        source: "sensor-a".into(),
        key: key.into(),
        value: value.into(),
        confidence: 0.96,
        observed_at: at,
        expires_at: Some(at + Duration::hours(1)),
        owner_confirmed: false,
    }
}
fn obs(at: chrono::DateTime<Utc>, kind: PresenceEvidenceKind) -> DiscoveryObservation {
    DiscoveryObservation {
        candidate: None,
        facts: vec![
            fact(EvidenceFamily::LinkLayer, "mac", "00:11:22:33:44:55", at),
            fact(EvidenceFamily::Service, "onvif_uuid", "uuid-camera-1", at),
            fact(EvidenceFamily::Naming, "vendor", "Acme", at),
            fact(EvidenceFamily::Service, "class", "camera", at),
        ],
        presence_source: "sensor-a".into(),
        presence_kind: kind,
        observed_at: at,
        valid_until: Some(at + Duration::seconds(30)),
    }
}

#[test]
fn fixture_join_has_stable_identity_confidence_and_evidence_families() {
    let start = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    let mut pipeline = DiscoveryPipeline::new([id(1), id(2)].into_iter()).unwrap();
    let first = pipeline
        .observe(obs(start, PresenceEvidenceKind::Traffic), start)
        .unwrap();
    let second = pipeline
        .observe(
            obs(
                start + Duration::seconds(1),
                PresenceEvidenceKind::ProbeSuccess,
            ),
            start + Duration::seconds(1),
        )
        .unwrap();
    let _ = pipeline
        .observe(
            obs(start + Duration::seconds(2), PresenceEvidenceKind::Traffic),
            start + Duration::seconds(2),
        )
        .unwrap();
    assert_eq!(first.device_id, second.device_id);
    let identification = second
        .identification
        .expect("two independent fixture families identify");
    assert!(identification.confidence >= 0.85);
    assert!(identification.families.contains(&EvidenceFamily::Naming));
    assert!(identification.families.contains(&EvidenceFamily::Service));
    assert_eq!(
        pipeline.presence_state(second.device_id),
        Some(PresenceState::Online)
    );
}

#[test]
fn departure_requires_hysteresis_and_late_evidence_corrects_it() {
    let start = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    let mut pipeline = DiscoveryPipeline::new([id(1), id(2)].into_iter()).unwrap();
    let _ = pipeline
        .observe(obs(start, PresenceEvidenceKind::Traffic), start)
        .unwrap();
    let joined = pipeline
        .observe(
            obs(start + Duration::seconds(1), PresenceEvidenceKind::Traffic),
            start + Duration::seconds(1),
        )
        .unwrap();
    let device = joined.device_id;
    let departed_at = start + Duration::seconds(40);
    let _ = pipeline.evaluate(device, departed_at).unwrap();
    let _ = pipeline
        .observe(
            DiscoveryObservation {
                candidate: Some(device),
                facts: vec![],
                presence_source: "sensor-a".into(),
                presence_kind: PresenceEvidenceKind::ConfirmationFailure,
                observed_at: departed_at + Duration::seconds(1),
                valid_until: None,
            },
            departed_at + Duration::seconds(1),
        )
        .unwrap();
    let departed = pipeline
        .observe(
            DiscoveryObservation {
                candidate: Some(device),
                facts: vec![],
                presence_source: "sensor-a".into(),
                presence_kind: PresenceEvidenceKind::ConfirmationFailure,
                observed_at: departed_at + Duration::seconds(2),
                valid_until: None,
            },
            departed_at + Duration::seconds(2),
        )
        .unwrap();
    assert!(
        departed
            .presence
            .iter()
            .any(|t| t.to == PresenceState::Offline)
    );
    let late = pipeline
        .observe(
            obs(
                departed_at + Duration::seconds(2),
                PresenceEvidenceKind::Traffic,
            ),
            departed_at + Duration::seconds(2),
        )
        .unwrap();
    assert!(late.presence.iter().any(|t| t.correction_of.is_some()));
}
