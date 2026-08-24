use chrono::{Duration, Utc};
use lattice_camera::{
    CameraClassification, CameraEvidence, CameraEvidenceFamily, CameraId, classify_candidate,
};
use uuid::Uuid;

fn evidence(family: CameraEvidenceFamily, fact: &str) -> CameraEvidence {
    CameraEvidence::new(family, "fixture", fact, 0.8, Utc::now(), None).unwrap()
}

#[test]
fn onvif_profile_is_strong_but_discovery_alone_is_possible() {
    let id = CameraId::from_uuid(Uuid::nil());
    let now = Utc::now();
    let strong = classify_candidate(
        id,
        [evidence(
            CameraEvidenceFamily::Onvif,
            "onvif_camera_profile",
        )],
        now,
    )
    .unwrap();
    assert_eq!(strong.classification, CameraClassification::Camera);
    let possible = classify_candidate(
        id,
        [evidence(
            CameraEvidenceFamily::WsDiscovery,
            "ws_discovery_scope",
        )],
        now,
    )
    .unwrap();
    assert_eq!(
        possible.classification,
        CameraClassification::PossibleCamera
    );
}

#[test]
fn duplicate_expired_and_secret_evidence_is_bounded_and_redacted() {
    let id = CameraId::from_uuid(Uuid::nil());
    let now = Utc::now();
    let expired = CameraEvidence::new(
        CameraEvidenceFamily::Rtsp,
        "old",
        "rtsp_camera",
        1.0,
        now - Duration::hours(2),
        Some(now - Duration::hours(1)),
    )
    .unwrap();
    let secret = evidence(
        CameraEvidenceFamily::Http,
        "http://user:password@example.test/body",
    );
    let candidate = classify_candidate(
        id,
        [
            evidence(CameraEvidenceFamily::Rtsp, "rtsp_camera"),
            evidence(CameraEvidenceFamily::Rtsp, "rtsp_camera"),
            expired,
            secret,
        ],
        now,
    )
    .unwrap();
    assert_eq!(candidate.evidence.len(), 1);
    let json = serde_json::to_string(&candidate).unwrap();
    assert!(!json.contains("password") && !json.contains("http://"));
}
