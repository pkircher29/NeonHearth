use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use lattice_camera::{
    BoundedMetadata, BoundedSerial, CameraClassification, CameraHealth, CameraId, Confidence,
    OnvifHealth,
};
use lattice_service::{AppState, app};
use lattice_store::{CameraRecord, CameraRepository, connect_memory};
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

async fn fixture() -> (Router, CameraId) {
    let pool = connect_memory().await.unwrap();
    let state_repo = lattice_store::M2StateRepository::new(pool.clone());
    let state = AppState::new(TOKEN, state_repo).unwrap();
    let id = CameraId::from_uuid(uuid::Uuid::from_u128(1));
    let repo = CameraRepository::new(pool);
    repo.upsert_camera(&CameraRecord {
        id,
        classification: CameraClassification::Camera,
        confidence: Confidence::new(0.9).unwrap(),
        health: CameraHealth::Healthy,
        observed_at: Utc::now(),
    })
    .await
    .unwrap();
    repo.replace_inventory(
        id,
        &lattice_store::CameraInventoryRecord {
            manufacturer: Some(BoundedMetadata::new("Neon Camera").unwrap()),
            model: Some(BoundedMetadata::new("Hearth-1").unwrap()),
            firmware: None,
            serial: Some(BoundedSerial::new("OWNER-SERIAL-42").unwrap()),
            capabilities: vec![BoundedMetadata::new("snapshot").unwrap()],
            health: OnvifHealth::Healthy,
        },
    )
    .await
    .unwrap();
    (app(state), id)
}

#[tokio::test]
async fn camera_detail_includes_sanitized_stored_inventory() {
    let (router, id) = fixture().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/cameras/{id}"))
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
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["inventory"],
        serde_json::json!({
            "manufacturer": "Neon Camera", "model": "Hearth-1", "firmware": null,
            "serial": "OWNER-SERIAL-42", "capabilities": ["snapshot"], "health": "healthy"
        })
    );
}

#[tokio::test]
async fn openapi_truthfully_documents_camera_and_media_routes() {
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let list = &doc["paths"]["/api/v1/cameras"]["get"];
    assert_eq!(
        list["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/CameraList"
    );
    assert!(
        list["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "limit")
    );
    assert!(
        list["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "after")
    );
    for path in [
        "/api/v1/cameras/{id}/snapshot",
        "/api/v1/cameras/{id}/sessions",
        "/api/v1/camera-sessions/{id}",
        "/api/v1/camera-sessions/{id}/playlist.m3u8",
        "/api/v1/camera-sessions/{id}/segments/{segment}",
    ] {
        assert!(doc["paths"].get(path).is_some(), "missing {path}");
    }
}

#[tokio::test]
async fn camera_list_requires_auth_before_query_validation() {
    let (router, _) = fixture().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/cameras?limit=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authenticated_camera_projection_is_sanitized_and_bounded() {
    let (router, id) = fixture().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/cameras?limit=1")
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
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["items"][0]["camera_id"], id.to_string());
    assert!(value["items"][0]["confidence"].as_f64().unwrap() <= 1.0);
    let text = String::from_utf8_lossy(&body);
    for secret in ["password", "rtsp://", "SOAP", "192.0.2.17"] {
        assert!(!text.contains(secret));
    }
}
