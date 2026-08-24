use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{TimeZone, Utc};
use lattice_advisory::{
    AdvisoryInput, AdvisorySource, Confidence, DeviceIdentity, Exploitability, Exposure, Freshness,
    NormalizedAdvisory, Remediation, Severity, SourceTrust, VersionConstraint, match_advisory,
};
use lattice_domain::DeviceId;
use lattice_service::{AppState, app};
use lattice_store::{AdvisoryRepository, connect_memory};
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
fn at(s: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(s, 0).single().unwrap()
}
fn advisory(id: &str, freshness: Freshness) -> NormalizedAdvisory {
    NormalizedAdvisory::new(AdvisoryInput {
        source: AdvisorySource::Nvd,
        source_id: id.into(),
        source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1".into(),
        title: "Camera security update".into(),
        vendor: "Acme".into(),
        model: Some("Cam-1".into()),
        firmware: VersionConstraint::Exact("1.2".into()),
        published_at: at(1),
        modified_at: at(2),
        retrieved_at: at(3),
        cache_expires_at: at(if freshness == Freshness::Fresh {
            300
        } else {
            2
        }),
        freshness,
        source_trust: SourceTrust::OfficialApi,
        severity: Severity::High,
        exploitability: Exploitability::ActiveKnownExploitation,
        exposure: Exposure::Exposed,
        confidence: Confidence::High,
        remediation: Remediation::Upgrade,
    })
    .unwrap()
}
async fn fixture() -> (Router, DeviceId) {
    let pool = connect_memory().await.unwrap();
    let state = AppState::new(TOKEN, lattice_store::M2StateRepository::new(pool.clone())).unwrap();
    let device = DeviceId::parse("018f0000-0000-7000-8000-00000000abcd").unwrap();
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at) VALUES(?,?,?)")
        .bind(device.to_string())
        .bind(at(1).to_rfc3339())
        .bind(at(2).to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();
    let repo = AdvisoryRepository::new(pool);
    let value = advisory("CVE-2026-0001", Freshness::Fresh);
    let id = repo.upsert_advisory(&value).await.unwrap();
    let matching = match_advisory(
        Some(&DeviceIdentity::known("Acme", "Cam-1", "1.2").unwrap()),
        &value,
    )
    .unwrap();
    repo.record_match(
        id,
        device,
        &matching,
        lattice_advisory::RiskDimensions {
            severity: Severity::High,
            exploitability: Exploitability::ActiveKnownExploitation,
            exposure: Exposure::Exposed,
            confidence: Confidence::High,
            remediation: Remediation::Upgrade,
        },
    )
    .await
    .unwrap();
    (app(state), device)
}
#[tokio::test]
async fn advisories_require_authentication_before_invalid_path_or_query() {
    let (router, _) = fixture().await;
    for uri in [
        "/api/v1/devices/not-a-device/advisories?limit=0",
        "/api/v1/devices/NOT-A-DEVICE/advisories?limit=nope",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
#[tokio::test]
async fn authorized_listing_is_device_scoped_and_has_independent_sanitized_risk() {
    let (router, device) = fixture().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/devices/{device}/advisories?limit=1"))
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["matches"][0]["label"], "exact");
    for field in [
        "severity",
        "exploitability",
        "exposure",
        "confidence",
        "remediation",
    ] {
        assert!(
            json["matches"][0]["risk"][field].is_string(),
            "missing {field}"
        );
    }
    assert!(json.to_string().contains("services.nvd.nist.gov"));
    assert!(!json.to_string().contains("192.168.") && !json.to_string().contains("AA:BB"));
}
#[tokio::test]
async fn listing_rejects_noncanonical_unknown_ids_and_invalid_limits() {
    let (router, device) = fixture().await;
    for uri in [
        format!(
            "/api/v1/devices/{}/advisories",
            device.to_string().to_uppercase()
        ),
        format!("/api/v1/devices/{}/advisories?limit=0", device),
        format!("/api/v1/devices/{}/advisories?limit=129", device),
        "/api/v1/devices/00000000-0000-0000-0000-000000000099/advisories".into(),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                response.status(),
                StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
            ),
            "{uri}: {}",
            response.status()
        );
    }
}
#[tokio::test]
async fn openapi_documents_advisory_route_and_security() {
    let (router, _) = fixture().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let operation = &doc["paths"]["/api/v1/devices/{device_id}/advisories"]["get"];
    assert!(operation["security"].is_array());
    assert!(
        operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "limit")
    );
}
