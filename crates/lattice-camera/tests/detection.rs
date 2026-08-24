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
    assert!(CameraEvidence::new(
        CameraEvidenceFamily::Http,
        "fixture",
        "http://user:password@example.test/body",
        0.8,
        now,
        None,
    )
    .is_err());
    let candidate = classify_candidate(
        id,
        [
            evidence(CameraEvidenceFamily::Rtsp, "rtsp_camera"),
            evidence(CameraEvidenceFamily::Rtsp, "rtsp_camera"),
            expired,
        ],
        now,
    )
    .unwrap();
    assert_eq!(candidate.evidence.len(), 1);
    let json = serde_json::to_string(&candidate).unwrap();
    assert!(!json.contains("password") && !json.contains("http://"));
}

#[test]
fn evidence_rejects_case_insensitive_secrets_and_unsafe_source_or_fact() {
    let now = Utc::now();
    for (source, fact) in [
        ("Bearer token", "camera_web"),
        ("fixture", "HTTP://camera.invalid/live"),
        ("fixture", "Authorization: Basic secret"),
        ("fixture", "BODY=raw response"),
        ("fixture", "Header=Set-Cookie"),
    ] {
        assert!(CameraEvidence::new(
            CameraEvidenceFamily::Http,
            source,
            fact,
            0.5,
            now,
            None,
        )
        .is_err());
    }
}

#[test]
fn evidence_serde_preserves_bounds_for_plain_and_escaped_input() {
    let oversized_source = "x".repeat(129);
    let oversized_fact = "x".repeat(257);
    for payload in [
        format!(r#"{{"family":"http","source":"{oversized_source}","fact":"camera_web","confidence":0.5,"observed_at":"2026-08-24T00:00:00Z","expires_at":null}}"#),
        format!(r#"{{"family":"http","source":"{}","fact":"camera_web","confidence":0.5,"observed_at":"2026-08-24T00:00:00Z","expires_at":null}}"#, oversized_source.replace('x', "\\u0078")),
        format!(r#"{{"family":"http","source":"fixture","fact":"{}","confidence":0.5,"observed_at":"2026-08-24T00:00:00Z","expires_at":null}}"#, oversized_fact.replace('x', "\\u0078")),
        r#"{"family":"http","source":"Password=leak","fact":"camera_web","confidence":0.5,"observed_at":"2026-08-24T00:00:00Z","expires_at":null}"#.to_owned(),
    ] {
        assert!(serde_json::from_str::<serde_json::Value>(&payload).is_ok(), "invalid fixture: {payload}");
        assert!(serde_json::from_str::<CameraEvidence>(&payload).is_err(), "{payload}");
    }
}

#[test]
fn evidence_constructor_accepts_exact_bounds_and_rejects_too_long_values() {
    let now = Utc::now();
    assert!(CameraEvidence::new(
        CameraEvidenceFamily::Http,
        "s".repeat(128),
        "camera_web",
        0.5,
        now,
        None,
    )
    .is_ok());
    assert!(CameraEvidence::new(
        CameraEvidenceFamily::Http,
        "s".repeat(129),
        "camera_web",
        0.5,
        now,
        None,
    )
    .is_err());
    assert!(CameraEvidence::new(
        CameraEvidenceFamily::Http,
        "fixture",
        format!("vendor:{}", "x".repeat(249)),
        0.5,
        now,
        None,
    )
    .is_ok());
    assert!(CameraEvidence::new(
        CameraEvidenceFamily::Http,
        "fixture",
        format!("vendor:{}", "x".repeat(250)),
        0.5,
        now,
        None,
    )
    .is_err());
}

#[test]
fn weak_evidence_requires_independent_families_and_does_not_inflate_score() {
    let id = CameraId::from_uuid(Uuid::nil());
    let now = Utc::now();
    let one = classify_candidate(
        id,
        [evidence(CameraEvidenceFamily::Rtsp, "rtsp_camera")],
        now,
    )
    .unwrap();
    assert_eq!(one.classification, CameraClassification::PossibleCamera);
    assert!(one.confidence.get() < 0.5);

    let repeated = classify_candidate(
        id,
        [
            evidence(CameraEvidenceFamily::Rtsp, "rtsp_camera"),
            CameraEvidence::new(CameraEvidenceFamily::Rtsp, "other", "rtsp_camera", 0.9, now, None).unwrap(),
        ],
        now,
    )
    .unwrap();
    assert_eq!(repeated.classification, CameraClassification::PossibleCamera);
    assert!(repeated.confidence.get() < 0.5);

    let independent = classify_candidate(
        id,
        [
            evidence(CameraEvidenceFamily::Rtsp, "rtsp_camera"),
            evidence(CameraEvidenceFamily::Http, "camera_web"),
        ],
        now,
    )
    .unwrap();
    assert_eq!(independent.classification, CameraClassification::Camera);
    assert_eq!(independent.confidence.get(), 1.0);
}

#[test]
fn metadata_markers_are_limited_to_metadata_families() {
    let now = Utc::now();
    for family in [
        CameraEvidenceFamily::Onvif,
        CameraEvidenceFamily::Upnp,
        CameraEvidenceFamily::Http,
        CameraEvidenceFamily::Tls,
    ] {
        assert!(CameraEvidence::new(family, "fixture", "vendor:axis", 0.4, now, None).is_ok());
    }
    for family in [
        CameraEvidenceFamily::WsDiscovery,
        CameraEvidenceFamily::Rtsp,
        CameraEvidenceFamily::Service,
        CameraEvidenceFamily::Behavior,
    ] {
        assert!(CameraEvidence::new(family, "fixture", "model:q3536", 0.4, now, None).is_err());
    }
}

#[test]
fn normalized_metadata_marker_is_retained_by_candidate_classification() {
    let now = Utc::now();
    let id = CameraId::from_uuid(Uuid::nil());
    let marker = CameraEvidence::new(
        CameraEvidenceFamily::Http,
        "fixture",
        "Vendor:Axis-Q3536",
        0.4,
        now,
        None,
    )
    .unwrap();
    assert!(CameraEvidence::new(
        CameraEvidenceFamily::Service,
        "fixture",
        "vendor:axis-q3536",
        0.4,
        now,
        None,
    )
    .is_err());

    let candidate = classify_candidate(id, [marker], now).unwrap();
    assert_eq!(candidate.evidence.len(), 1);
    assert_eq!(candidate.evidence[0].fact(), "vendor:axis-q3536");
}

#[test]
fn weak_families_need_independent_qualifying_confidence() {
    let id = CameraId::from_uuid(Uuid::nil());
    let now = Utc::now();
    for confidence in [0.0, 0.1] {
        let candidate = classify_candidate(
            id,
            [
                CameraEvidence::new(CameraEvidenceFamily::Rtsp, "rtsp", "rtsp_camera", confidence, now, None).unwrap(),
                CameraEvidence::new(CameraEvidenceFamily::Http, "http", "camera_web", confidence, now, None).unwrap(),
            ],
            now,
        )
        .unwrap();
        assert_ne!(candidate.classification, CameraClassification::Camera);
        assert!(candidate.confidence.get() < 0.5);
    }
}

#[test]
fn supports_every_family_with_bounded_vendor_model_and_contradictions() {
    let id = CameraId::from_uuid(Uuid::nil());
    let now = Utc::now();
    let families = [
        (CameraEvidenceFamily::Onvif, "onvif_namespace"),
        (CameraEvidenceFamily::WsDiscovery, "ws_discovery_type"),
        (CameraEvidenceFamily::WsDiscovery, "ws_discovery_scope"),
        (CameraEvidenceFamily::Rtsp, "rtsp_camera"),
        (CameraEvidenceFamily::Upnp, "upnp_camera"),
        (CameraEvidenceFamily::Http, "camera_web"),
        (CameraEvidenceFamily::Tls, "tls_camera"),
        (CameraEvidenceFamily::Service, "camera_service"),
        (CameraEvidenceFamily::Behavior, "camera_behavior"),
        (CameraEvidenceFamily::Http, "vendor:axis"),
        (CameraEvidenceFamily::Http, "model:q3536-lve"),
    ];
    for (family, fact) in families {
        assert!(CameraEvidence::new(family, "fixture", fact, 0.4, now, None).is_ok(), "{fact}");
    }
    assert!(CameraEvidence::new(CameraEvidenceFamily::Http, "fixture", format!("vendor:{}", "x".repeat(257)), 0.4, now, None).is_err());

    let contradiction = classify_candidate(
        id,
        [
            evidence(CameraEvidenceFamily::Rtsp, "rtsp_camera"),
            evidence(CameraEvidenceFamily::Onvif, "camera_contradiction"),
        ],
        now,
    )
    .unwrap();
    assert_eq!(contradiction.classification, CameraClassification::Unknown);
    assert_eq!(contradiction.confidence.get(), 0.0);
}

#[test]
fn exact_expiry_capacity_ordering_and_onvif_confidence_are_deterministic() {
    let id = CameraId::from_uuid(Uuid::nil());
    let now = Utc::now();
    let expired_now = CameraEvidence::new(CameraEvidenceFamily::Rtsp, "a", "rtsp_camera", 1.0, now, Some(now)).unwrap();
    let low_onvif = CameraEvidence::new(CameraEvidenceFamily::Onvif, "z", "onvif_camera_profile", 0.0, now, None).unwrap();
    let candidate = classify_candidate(id, [expired_now, low_onvif], now).unwrap();
    assert_eq!(candidate.evidence.len(), 1);
    assert_eq!(candidate.classification, CameraClassification::PossibleCamera);
    assert_eq!(candidate.confidence.get(), 0.0);

    let input = (0..65).map(|number| CameraEvidence::new(
        CameraEvidenceFamily::Service,
        format!("source-{number:02}"),
        "camera_service",
        0.1,
        now,
        None,
    ).unwrap());
    let capped = classify_candidate(id, input, now).unwrap();
    assert_eq!(capped.evidence.len(), 64);
    assert!(capped.evidence.windows(2).all(|pair| pair[0].source() <= pair[1].source()));
}
