use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily, PresenceState};
use lattice_intelligence::presence::PresenceEvidenceKind;
use lattice_sensor::flow::{
    DestinationCategory, Protocol, Resolution, Rollup, RollupChange, RollupKey,
};
use lattice_service::discovery::{
    DiscoveryObservation, DiscoveryPipeline, DiscoverySource, DiscoverySources,
};
use lattice_store::{FlowIngestor, FlowRepository, connect_memory};

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
        source_id: 1,
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
                source_id: 1,
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
                source_id: 1,
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

#[tokio::test]
async fn flow_boundary_emits_honest_local_only_bandwidth() {
    let start = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    let mut pipeline = DiscoveryPipeline::new([id(1), id(2)].into_iter()).unwrap();
    let joined = pipeline
        .observe(obs(start, PresenceEvidenceKind::Traffic), start)
        .unwrap();
    let device = joined.device_id;
    let roll = Rollup {
        key: RollupKey {
            resolution: Resolution::Second,
            bucket: start,
            device_id: device,
            protocol: Protocol::Tcp,
            destination: DestinationCategory::Internet,
            interface: 2,
            metadata: None,
        },
        bytes: lattice_domain::ByteCount {
            upload: 12,
            download: 24,
        },
        coverage: lattice_domain::Coverage::LocalOnly,
        metadata: None,
    };
    let mut flow = FlowIngestor::new(
        FlowRepository::new(connect_memory().await.unwrap(), 20).unwrap(),
        Default::default(),
        20,
    )
    .unwrap();
    let (_, payload) = pipeline
        .observe_with_flow(
            obs(
                start + Duration::seconds(1),
                PresenceEvidenceKind::ProbeSuccess,
            ),
            &[RollupChange::Upsert(roll)],
            0,
            start + Duration::seconds(1),
            &mut flow,
        )
        .await
        .unwrap();
    let frame = payload.expect("live bandwidth frame");
    match frame {
        lattice_domain::EventPayload::BandwidthFrame(frame) => assert!(
            frame
                .samples
                .iter()
                .all(|s| s.coverage == lattice_domain::Coverage::LocalOnly)
        ),
        _ => panic!("unexpected event"),
    }
}

#[test]
fn source_provenance_and_router_family_are_rejected_before_mutation() {
    let sources = DiscoverySources::new(vec![
        DiscoverySource {
            id: 1,
            name: "sensor".into(),
            families: vec![EvidenceFamily::LinkLayer],
            presence: true,
        },
        DiscoverySource {
            id: 9,
            name: "router".into(),
            families: vec![EvidenceFamily::RouterHint],
            presence: false,
        },
    ])
    .unwrap();
    let mut p = DiscoveryPipeline::with_sources([id(1), id(2)].into_iter(), sources).unwrap();
    let at = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    let mut input = obs(at, PresenceEvidenceKind::Traffic);
    input.source_id = 9;
    input.presence_source = "spoof".into();
    assert!(p.observe(input, at).is_err());
    assert_eq!(p.presence_state(id(1)), None);
}

#[test]
fn candidate_binding_cannot_poison_identity_with_unrelated_facts() {
    let mut p = DiscoveryPipeline::new([id(1), id(2)].into_iter()).unwrap();
    let at = Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();
    let mut input = obs(at, PresenceEvidenceKind::Traffic);
    input.candidate = Some(id(2));
    assert!(p.observe(input, at).is_err());
    assert_eq!(p.presence_state(id(2)), None);
}
