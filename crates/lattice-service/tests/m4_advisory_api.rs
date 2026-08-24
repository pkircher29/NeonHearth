use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{TimeZone, Utc};
use chrono::Duration;
use lattice_advisory::{
    AdvisoryInput, AdvisorySource, Confidence, DeviceIdentity, Exploitability, Exposure, Freshness,
    NormalizedAdvisory, Remediation, Severity, SourceTrust, VersionConstraint, match_advisory,
};
use lattice_domain::DeviceId;
use lattice_service::{AppState, app};
use lattice_store::{AdvisoryRepository, connect_memory};
use tower::ServiceExt;
use sqlx::SqlitePool;

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
        modified_at: if freshness == Freshness::FutureDated { Utc::now() + Duration::days(1) } else { at(2) },
        retrieved_at: if freshness == Freshness::FutureDated { Utc::now() } else { at(3) },
        cache_expires_at: if freshness == Freshness::Fresh { at(300) } else if freshness == Freshness::FutureDated { Utc::now() + Duration::days(3) } else { at(4) },
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

async fn response_json(router: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(Request::builder().uri(uri).header("authorization", format!("Bearer {TOKEN}")).body(Body::empty()).unwrap())
        .await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
}

async fn fixture_with_pool() -> (Router, SqlitePool, DeviceId) {
    let pool = connect_memory().await.unwrap();
    let state = AppState::new(TOKEN, lattice_store::M2StateRepository::new(pool.clone())).unwrap();
    let device = DeviceId::parse("018f0000-0000-7000-8000-00000000abcd").unwrap();
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at) VALUES(?,?,?)").bind(device.to_string()).bind(at(1).to_rfc3339()).bind(at(2).to_rfc3339()).execute(&pool).await.unwrap();
    (app(state), pool, device)
}

async fn add_match(pool: &SqlitePool, device: DeviceId, value: &NormalizedAdvisory, identity: Option<&DeviceIdentity>) {
    let repo = AdvisoryRepository::new(pool.clone());
    let id = repo.upsert_advisory(value).await.unwrap();
    let matching = match_advisory(identity, value).unwrap();
    repo.record_match(id, device, &matching, lattice_advisory::RiskDimensions { severity: value.input().severity, exploitability: value.input().exploitability, exposure: value.input().exposure, confidence: value.input().confidence, remediation: value.input().remediation }).await.unwrap();
}

#[tokio::test]
async fn invalid_queries_are_exactly_bad_request_and_unknown_canonical_is_not_found() {
    let (router, _, device) = fixture_with_pool().await;
    let base = format!("/api/v1/devices/{device}/advisories");
    for query in ["?limit=0", "?limit=129", "?limit=nope", "?unexpected=1", "?limit=1&limit=2"] {
        let (status, _) = response_json(&router, &format!("{base}{query}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
    }
    let (status, _) = response_json(&router, "/api/v1/devices/018f0000-0000-7000-8000-00000000abce/advisories").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn listing_isolated_deterministic_and_bounded() {
    let (router, pool, device) = fixture_with_pool().await;
    let other = DeviceId::parse("018f0000-0000-7000-8000-00000000abce").unwrap();
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at) VALUES(?,?,?)").bind(other.to_string()).bind(at(1).to_rfc3339()).bind(at(2).to_rfc3339()).execute(&pool).await.unwrap();
    let identity = DeviceIdentity::known("Acme", "Cam-1", "1.2").unwrap();
    for (id, modified) in [("CVE-2026-0001", 300), ("CVE-2026-0002", 200), ("CVE-2026-0003", 100)] {
        let mut value = advisory(id, Freshness::Fresh);
        let mut input = value.input().clone(); input.modified_at = at(modified); input.retrieved_at = at(modified); input.cache_expires_at = at(modified + 300); value = NormalizedAdvisory::new(input).unwrap();
        add_match(&pool, device, &value, Some(&identity)).await;
    }
    let mut other_value = advisory("CVE-OTHER", Freshness::Fresh);
    let mut input = other_value.input().clone(); input.modified_at = at(400); input.retrieved_at = at(400); input.cache_expires_at = at(700); other_value = NormalizedAdvisory::new(input).unwrap();
    add_match(&pool, other, &other_value, Some(&identity)).await;
    let (status, json) = response_json(&router, &format!("/api/v1/devices/{device}/advisories?limit=2")).await;
    assert_eq!(status, StatusCode::OK);
    let matches = json["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0]["source_id"], "CVE-2026-0001");
    assert_eq!(matches[1]["source_id"], "CVE-2026-0002");
    let (_, other_json) = response_json(&router, &format!("/api/v1/devices/{other}/advisories")).await;
    assert_eq!(other_json["matches"].as_array().unwrap().len(), 1);
    assert_eq!(other_json["matches"][0]["source_id"], "CVE-OTHER");
}

#[tokio::test]
async fn projection_has_exact_possible_labels_and_sanitizes_untrusted_values() {
    let (router, pool, device) = fixture_with_pool().await;
    let identity = DeviceIdentity::known("Acme", "Cam-1", "1.2").unwrap();
    add_match(&pool, device, &advisory("CVE-EXACT", Freshness::Fresh), Some(&identity)).await;
    let mut possible = advisory("CVE-POSSIBLE", Freshness::Fresh);
    let mut input = possible.input().clone(); input.firmware = VersionConstraint::Any; input.source_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?secret=URL_SECRET&ip=192.0.2.1&mac=AA:BB&serial=SERIAL_SECRET".into(); possible = NormalizedAdvisory::new(input).unwrap();
    add_match(&pool, device, &possible, Some(&identity)).await;
    let (status, json) = response_json(&router, &format!("/api/v1/devices/{device}/advisories")).await;
    assert_eq!(status, StatusCode::OK);
    let text = json.to_string();
    assert!(!text.contains("URL_SECRET") && !text.contains("192.0.2.1") && !text.contains("AA:BB") && !text.contains("SERIAL_SECRET"));
    let labels: Vec<_> = json["matches"].as_array().unwrap().iter().map(|m| m["label"].as_str().unwrap()).collect();
    assert!(labels.contains(&"exact") && labels.contains(&"possible"));
    let exact = json["matches"].as_array().unwrap().iter().find(|m| m["source_id"] == "CVE-EXACT").unwrap();
    assert_eq!(exact["matched_fields"], serde_json::json!(["vendor", "model", "firmware"]));
    assert_eq!(exact["confidence"], "high");
    assert_eq!(exact["explanation"], "all advisory identity fields match");
}

#[tokio::test]
async fn freshness_and_corruption_are_projected_as_contractual_statuses() {
    let (router, pool, device) = fixture_with_pool().await;
    let now = Utc::now();
    for (id, freshness, modified, retrieved, expires) in [
        ("CVE-FRESH", Freshness::Fresh, now - Duration::days(2), now - Duration::hours(1), now + Duration::hours(1)),
        ("CVE-STALE", Freshness::Stale, now - Duration::days(4), now - Duration::days(3), now - Duration::days(2)),
        ("CVE-FUTURE", Freshness::FutureDated, now + Duration::days(1), now, now + Duration::days(2)),
    ] {
        let mut value = advisory(id, freshness);
        let mut input = value.input().clone(); input.modified_at = modified; input.published_at = modified; input.retrieved_at = retrieved; input.cache_expires_at = expires; value = NormalizedAdvisory::new(input).unwrap();
        add_match(&pool, device, &value, Some(&DeviceIdentity::known("Acme", "Cam-1", "1.2").unwrap())).await;
    }
    let (status, json) = response_json(&router, &format!("/api/v1/devices/{device}/advisories")).await;
    assert_eq!(status, StatusCode::OK);
    for (id, expected) in [("CVE-FRESH", "fresh"), ("CVE-STALE", "stale"), ("CVE-FUTURE", "future_dated")] {
        let row = json["matches"].as_array().unwrap().iter().find(|m| m["source_id"] == id).unwrap();
        assert_eq!(row["freshness"], expected);
        assert_eq!(row["source"], "nvd");
        assert_eq!(row["source_trust"], "official_api");
        assert_eq!(row["risk"]["severity"], "high");
        assert_eq!(row["risk"]["exploitability"], "active_known_exploitation");
        assert_eq!(row["risk"]["exposure"], "exposed");
    }
    sqlx::query("UPDATE advisories SET provenance_sha256=replace(hex(zeroblob(32)), '00', 'ff') WHERE source_id='CVE-FRESH'").execute(&pool).await.unwrap();
    let (status, json) = response_json(&router, &format!("/api/v1/devices/{device}/advisories")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!json.to_string().contains("provenance"));
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
    assert_eq!(json["matches"][0]["vendor"], "Acme");
    assert_eq!(json["matches"][0]["model"], "Cam-1");
    assert_eq!(json["matches"][0]["firmware"], "1.2");
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
    assert_eq!(
        json["matches"][0]["source_url"],
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
    );
    assert!(!json.to_string().contains("cveId=CVE-1"));
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
    assert!(operation["responses"]["400"].is_object());
    assert!(operation["responses"]["401"].is_object());
    assert!(operation["responses"]["503"].is_object());
    assert!(
        operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "limit")
    );
    assert!(operation["responses"]["404"].is_object());
    let params = operation["parameters"].as_array().unwrap();
    let limit = params.iter().find(|p| p["name"] == "limit").unwrap();
    assert_eq!(limit["schema"]["maximum"], 128);
    let projection = &doc["components"]["schemas"]["AdvisoryProjection"];
    assert_eq!(projection["properties"]["source"]["maxLength"], 32);
    assert!(projection["properties"]["source"]["pattern"].is_string());
    assert_eq!(projection["properties"]["provenance_sha256"]["maxLength"], 64);
    assert!(projection["properties"]["advisory_id"]["pattern"].is_string());
}
