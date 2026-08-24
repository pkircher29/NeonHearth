use lattice_camera::{CameraId, CameraKind, Confidence, EvidenceInput};

#[test]
fn camera_contracts_are_bounded_and_serializable() {
    let id = CameraId::from_uuid(uuid::Uuid::nil());
    let input = EvidenceInput::new(
        CameraKind::Onvif,
        "ws-discovery",
        "camera",
        Confidence::new(0.9).unwrap(),
    )
    .unwrap();
    assert_eq!(id.to_string(), "00000000-0000-0000-0000-000000000000");
    assert!(serde_json::to_string(&input).unwrap().len() < 512);
}

#[test]
fn camera_contracts_reject_invalid_values() {
    for value in [-0.1, 1.1, f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        assert!(Confidence::new(value).is_err());
    }
    for source in ["", "   ", &"x".repeat(129)] {
        assert!(
            EvidenceInput::new(
                CameraKind::Onvif,
                source,
                "camera",
                Confidence::new(0.9).unwrap()
            )
            .is_err()
        );
    }
    for fact in ["", "   ", &"x".repeat(257)] {
        assert!(
            EvidenceInput::new(
                CameraKind::Onvif,
                "source",
                fact,
                Confidence::new(0.9).unwrap()
            )
            .is_err()
        );
    }
    for json in ["-0.1", "1.1", "null", "1e999"] {
        assert!(serde_json::from_str::<Confidence>(json).is_err());
    }
    assert!(
        serde_json::from_str::<EvidenceInput>(
            r#"{"kind":"onvif","source":" ","fact":"camera","confidence":0.9}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<EvidenceInput>(&format!(
            r#"{{"kind":"onvif","source":"{}","fact":"camera","confidence":0.9}}"#,
            "x".repeat(129)
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<EvidenceInput>(&format!(
            r#"{{"kind":"onvif","source":"source","fact":"{}","confidence":0.9}}"#,
            "x".repeat(257)
        ))
        .is_err()
    );
}

#[test]
fn camera_contracts_round_trip_through_json() {
    let id = CameraId::from_uuid(uuid::Uuid::new_v4());
    let kind = CameraKind::Onvif;
    let confidence = Confidence::new(0.9).unwrap();
    let evidence = EvidenceInput::new(kind, "ws-discovery", "camera", confidence).unwrap();
    assert_eq!(
        serde_json::from_str::<CameraId>(&serde_json::to_string(&id).unwrap()).unwrap(),
        id
    );
    assert_eq!(
        serde_json::from_str::<CameraKind>(&serde_json::to_string(&kind).unwrap()).unwrap(),
        kind
    );
    assert_eq!(
        serde_json::from_str::<Confidence>(&serde_json::to_string(&confidence).unwrap()).unwrap(),
        confidence
    );
    assert_eq!(
        serde_json::from_str::<EvidenceInput>(&serde_json::to_string(&evidence).unwrap()).unwrap(),
        evidence
    );
}
