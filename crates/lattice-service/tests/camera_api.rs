use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use lattice_camera::{CameraClassification, CameraHealth, CameraId, Confidence};
use lattice_service::{AppState, app};
use lattice_store::{CameraRecord, CameraRepository, connect_memory};
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

async fn fixture() -> (Router, CameraId) {
    let pool = connect_memory().await.unwrap();
    let state_repo = lattice_store::M2StateRepository::new(pool.clone());
    let state = AppState::new(TOKEN, state_repo).unwrap();
    let id = CameraId::from_uuid(uuid::Uuid::from_u128(1));
    CameraRepository::new(pool)
        .upsert_camera(&CameraRecord {
            id,
            classification: CameraClassification::Camera,
            confidence: Confidence::new(0.9).unwrap(),
            health: CameraHealth::Healthy,
            observed_at: Utc::now(),
        })
        .await
        .unwrap();
    (app(state), id)
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
