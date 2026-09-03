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
                .header("authorization", format!("Bearer {TOKEN}"))
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
    for path in [
        "/api/v1/cameras/{id}/snapshot",
        "/api/v1/camera-sessions/{id}/segments/{segment}",
    ] {
        let content = &doc["paths"][path]["get"]["responses"]["200"]["content"];
        let media = if path.contains("segments") {
            "video/mp2t"
        } else {
            "image/jpeg"
        };
        let schema = &content[media]["schema"];
        let resolved = schema["$ref"]
            .as_str()
            .map(|reference| {
                let name = reference.rsplit('/').next().unwrap();
                &doc["components"]["schemas"][name]
            })
            .unwrap_or(schema);
        assert_eq!(resolved["type"], "string");
        assert_eq!(resolved["format"], "binary");
    }
    let camera = &doc["components"]["schemas"]["CameraSummary"];
    assert_eq!(camera["properties"]["camera_id"]["format"], "uuid");
    assert_eq!(camera["properties"]["camera_id"]["minLength"], 36);
    assert_eq!(camera["properties"]["confidence"]["minimum"], 0.0);
    assert_eq!(camera["properties"]["confidence"]["maximum"], 1.0);
    let inventory = &doc["components"]["schemas"]["CameraInventoryProjection"];
    assert_eq!(inventory["properties"]["serial"]["maxLength"], 128);
    assert_eq!(inventory["properties"]["capabilities"]["maxItems"], 32);
    let session_request =
        &doc["components"]["schemas"]["CameraSessionRequest"]["properties"]["stream_id"];
    assert_eq!(session_request["format"], "uuid");
    assert_eq!(session_request["minLength"], 36);
    let after = list["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|parameter| parameter["name"] == "after")
        .unwrap();
    assert_eq!(after["schema"]["format"], "uuid");
    assert_eq!(after["schema"]["minLength"], 36);
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
        !lattice_service::api::serialize_camera_inventory_for_support_export(&inventory)
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
async fn camera_query_rejects_unknown_fields_after_authentication() {
    let (router, _) = fixture().await;
    assert_eq!(
        response(&router, "/api/v1/cameras?unexpected=value".into())
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn camera_cursor_requires_lowercase_canonical_uuid_after_authentication() {
    let (router, _) = fixture().await;
    assert_eq!(
        response(
            &router,
            "/api/v1/cameras?after=00000000-0000-0000-0000-000000000001".into()
        )
        .await
        .status(),
        StatusCode::OK
    );
    for cursor in [
        "ABCDEF01-2345-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000001%20",
    ] {
        assert_eq!(
            response(&router, format!("/api/v1/cameras?after={cursor}"))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/cameras?after=ABCDEF01-2345-0000-0000-000000000001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
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

#[tokio::test]
async fn canonical_version_zero_ids_are_accepted_but_noncanonical_ids_are_rejected() {
    let (router, id) = fixture().await;
    assert_eq!(id.to_string(), "00000000-0000-0000-0000-000000000001");
    for uri in [
        format!("/api/v1/cameras/{id}"),
        format!("/api/v1/cameras/{id}/health"),
        format!("/api/v1/cameras/{id}/inventory"),
        format!("/api/v1/cameras/{id}/snapshot?stream_id={id}"),
    ] {
        assert_ne!(
            response(&router, uri).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    let uppercase = "ABCDEF01-2345-0000-0000-000000000001";
    for value in [
        "not-a-uuid",                              // malformed
        "00000000-0000-0000-0000-000000000001%20", // trailing space
        uppercase,
    ] {
        assert_eq!(
            response(&router, format!("/api/v1/cameras/{value}"))
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "{value}"
        );
    }
}

#[tokio::test]
async fn camera_openapi_schema_has_all_boundary_constraints() {
    let (router, _) = fixture().await;
    let body = axum::body::to_bytes(
        response(&router, "/api/v1/openapi.json".into())
            .await
            .into_body(),
        512 * 1024,
    )
    .await
    .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let uuid_pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
    let session_pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
    for path in [
        "/api/v1/cameras",
        "/api/v1/cameras/{id}",
        "/api/v1/cameras/{id}/health",
        "/api/v1/cameras/{id}/inventory",
        "/api/v1/cameras/{id}/snapshot",
        "/api/v1/cameras/{id}/sessions",
        "/api/v1/camera-sessions/{id}",
        "/api/v1/camera-sessions/{id}/playlist.m3u8",
        "/api/v1/camera-sessions/{id}/segments/{segment}",
    ] {
        let operation = doc["paths"][path]
            .get("get")
            .or_else(|| doc["paths"][path].get("post"))
            .or_else(|| doc["paths"][path].get("delete"))
            .unwrap();
        for parameter in operation["parameters"].as_array().unwrap_or(&vec![]) {
            let schema = &parameter["schema"];
            if parameter["name"] == "id"
                || parameter["name"] == "after"
                || parameter["name"] == "stream_id"
            {
                let expected = if path.contains("camera-sessions") && parameter["name"] == "id" {
                    session_pattern
                } else {
                    uuid_pattern
                };
                assert_eq!(schema["pattern"], expected);
                assert_eq!(schema["minLength"], 36);
                assert_eq!(schema["maxLength"], 36);
            }
        }
    }
    let schemas = &doc["components"]["schemas"];
    for name in ["CameraSummary", "CameraDetail"] {
        assert_eq!(schemas[name]["properties"]["confidence"]["minimum"], 0.0);
        assert_eq!(schemas[name]["properties"]["confidence"]["maximum"], 1.0);
    }
    assert_eq!(
        schemas["CameraHealth"]["properties"]["confidence"]["minimum"],
        0.0
    );
    assert_eq!(
        schemas["CameraHealth"]["properties"]["confidence"]["maximum"],
        1.0
    );
    for field in ["manufacturer", "model", "firmware", "serial"] {
        assert_eq!(
            schemas["CameraInventoryProjection"]["properties"][field]["maxLength"],
            128
        );
    }
    assert_eq!(
        schemas["CameraInventoryProjection"]["properties"]["capabilities"]["maxItems"],
        32
    );
    let items = &schemas["CameraInventoryProjection"]["properties"]["capabilities"]["items"];
    let item_schema = items["$ref"]
        .as_str()
        .and_then(|reference| reference.rsplit('/').next())
        .map(|name| &schemas[name])
        .unwrap_or(items);
    assert_eq!(item_schema["maxLength"], 128);
    assert!(
        schemas["CameraSummary"]["properties"]["classification"]["pattern"]
            .as_str()
            .unwrap()
            .contains("possible_camera")
    );
}
