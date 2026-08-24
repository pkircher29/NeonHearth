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

async fn response(router: &Router, uri: String) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
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

#[test]
fn owner_inventory_serial_is_bounded_but_export_and_debug_are_redacted() {
    let inventory = lattice_service::api::CameraInventoryProjection {
        manufacturer: Some("Neon Camera".into()),
        model: None,
        firmware: None,
        serial: Some("OWNER-SERIAL-42".into()),
        capabilities: vec!["snapshot".into()],
        health: "healthy".into(),
    };
    assert!(
        serde_json::to_string(&inventory)
            .unwrap()
            .contains("OWNER-SERIAL-42")
    );
    assert!(
        !serde_json::to_string(&inventory.redacted_for_export())
            .unwrap()
            .contains("OWNER-SERIAL-42")
    );
    assert!(!format!("{inventory:?}").contains("OWNER-SERIAL-42"));
}

#[tokio::test]
async fn camera_routes_authenticate_before_rejecting_malformed_inputs() {
    let (router, _) = fixture().await;
    for request in [
        Request::builder()
            .uri("/api/v1/cameras?limit=0")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/api/v1/cameras/not-a-uuid")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/api/v1/cameras/not-a-uuid/health")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/api/v1/cameras/not-a-uuid/inventory")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/api/v1/cameras/not-a-uuid/snapshot?stream_id=nope")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/api/v1/cameras/not-a-uuid/sessions")
            .header("content-type", "application/json")
            .body(Body::from("{malformed"))
            .unwrap(),
        Request::builder()
            .method("DELETE")
            .uri("/api/v1/camera-sessions/not-a-uuid")
            .body(Body::empty())
            .unwrap(),
    ] {
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn camera_list_cursor_is_deterministic_across_more_than_two_pages() {
    let (_router, _) = fixture().await;
    let ids = (2..=7)
        .map(|number| CameraId::from_uuid(uuid::Uuid::from_u128(number)))
        .collect::<Vec<_>>();
    // The test fixture's in-memory database is only reachable through the app state, so
    // pagination is exercised with the persisted rows prepared before router construction.
    // A separate fixture is used here to retain that handle.
    let pool = connect_memory().await.unwrap();
    let repo = CameraRepository::new(pool.clone());
    for id in &ids {
        repo.upsert_camera(&CameraRecord {
            id: *id,
            classification: CameraClassification::Camera,
            confidence: Confidence::new(0.5).unwrap(),
            health: CameraHealth::Healthy,
            observed_at: Utc::now(),
        })
        .await
        .unwrap();
    }
    let state = AppState::new(TOKEN, lattice_store::M2StateRepository::new(pool)).unwrap();
    let router = app(state);
    let mut after = None;
    let mut seen = Vec::new();
    for page in 0..3 {
        let uri = format!(
            "/api/v1/cameras?limit=2{}",
            after
                .as_ref()
                .map(|cursor| format!("&after={cursor}"))
                .unwrap_or_default()
        );
        let body = axum::body::to_bytes(response(&router, uri).await.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        seen.extend(
            value["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["camera_id"].as_str().unwrap().to_owned()),
        );
        after = value["next_after"].as_str().map(str::to_owned);
        if page < 2 {
            assert!(after.is_some());
        }
    }
    assert_eq!(seen.len(), 6);
    assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(after.is_none());
    assert_eq!(
        response(&router, "/api/v1/cameras?limit=0".into())
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        response(&router, "/api/v1/cameras?after=not-a-uuid".into())
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn camera_owner_responses_never_serialize_secret_like_fixture_values() {
    let (router, id) = fixture().await;
    let secret_fixture = [
        "rtsp://192.0.2.17/live",
        "camera-user",
        "camera-password",
        "<SOAP-ENV:Envelope>",
        "Authorization: Digest raw-header",
        "00:11:22:33:44:55",
        "opaque-source-ref",
    ];
    for uri in [
        format!("/api/v1/cameras/{id}"),
        format!("/api/v1/cameras/{id}/inventory"),
        "/api/v1/cameras".into(),
    ] {
        let body = axum::body::to_bytes(response(&router, uri).await.into_body(), 64 * 1024)
            .await
            .unwrap();
        let serialized = String::from_utf8(body.to_vec()).unwrap();
        for secret in secret_fixture {
            assert!(!serialized.contains(secret), "leaked {secret}");
        }
    }
}

#[tokio::test]
async fn authenticated_camera_routes_have_the_documented_status_semantics() {
    let (router, id) = fixture().await;
    let stream = uuid::Uuid::from_u128(9);
    for (method, uri, expected) in [
        ("GET", format!("/api/v1/cameras/{id}"), StatusCode::OK),
        (
            "GET",
            format!("/api/v1/cameras/{id}/health"),
            StatusCode::OK,
        ),
        (
            "GET",
            format!("/api/v1/cameras/{id}/inventory"),
            StatusCode::OK,
        ),
        (
            "GET",
            format!("/api/v1/cameras/{id}/snapshot?stream_id={stream}"),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "GET",
            format!("/api/v1/camera-sessions/{stream}/playlist.m3u8"),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "GET",
            format!("/api/v1/camera-sessions/{stream}/segments/segment0.ts"),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "DELETE",
            format!("/api/v1/camera-sessions/{stream}"),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/cameras/{id}/sessions"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"stream_id":"{stream}"}}"#)))
        .unwrap();
    assert_eq!(
        router.oneshot(request).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
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
