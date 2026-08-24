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
