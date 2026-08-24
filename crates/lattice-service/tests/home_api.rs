use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use lattice_service::{AppState, app, ws::ServerMessage};
use lattice_store::{M2StateRepository, connect_memory};
use sqlx::SqlitePool;
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
const HOME_ID: &str = "018f47a0-9b5c-7a22-8a33-112233445566";
const FLOOR_ID: &str = "018f47a0-9b5c-7a22-8a33-112233445567";
const DEVICE_ID: &str = "018f0000-0000-7000-8000-00000000abcd";

async fn fixture() -> (Router, AppState, SqlitePool) {
    let pool = connect_memory().await.unwrap();
    let state = AppState::new(TOKEN, M2StateRepository::new(pool.clone())).unwrap();
    (app(state.clone()), state, pool)
}

fn sample_plan(name: &str) -> serde_json::Value {
    serde_json::json!({
        "home_id": HOME_ID,
        "version": 0,
        "name": name,
        "floors": [{
            "floor_id": FLOOR_ID,
            "level": 0,
            "name": "Ground",
            "ceiling_height_m": 2.4,
            "walls": [{
                "wall_id": "018f47a0-9b5c-7a22-8a33-112233445568",
                "start": {"x": 0.0, "y": 0.0},
                "end": {"x": 4.2, "y": 0.0},
                "openings": [{
                    "opening_id": "018f47a0-9b5c-7a22-8a33-112233445569",
                    "kind": "door",
                    "offset_m": 0.8,
                    "width_m": 0.9
                }]
            }],
            "rooms": [{
                "room_id": "018f47a0-9b5c-7a22-8a33-11223344556a",
                "name": "Kitchen",
                "polygon": [
                    {"x": 0.0, "y": 0.0}, {"x": 4.0, "y": 0.0},
                    {"x": 4.0, "y": 3.0}, {"x": 0.0, "y": 3.0}
                ]
            }]
        }]
    })
}

fn save_request(expected_version: u32, plan: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "expected_version": expected_version, "plan": plan })
}

fn placement_body() -> serde_json::Value {
    serde_json::json!({
        "floor_id": FLOOR_ID,
        "x": 1.5,
        "y": 2.0,
        "height_m": 1.1,
        "mounting": "wall"
    })
}

async fn send(
    router: &Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> axum::response::Response {
    send_raw(
        router,
        method,
        uri,
        body.map(|value| value.to_string().into_bytes()),
        true,
    )
    .await
}

async fn send_raw(
    router: &Router,
    method: &str,
    uri: &str,
    body: Option<Vec<u8>>,
    authorized: bool,
) -> axum::response::Response {
    let mut request = Request::builder().method(method).uri(uri);
    if authorized {
        request = request.header("authorization", format!("Bearer {TOKEN}"));
    }
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    router
        .clone()
        .oneshot(request.body(Body::from(body.unwrap_or_default())).unwrap())
        .await
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn save_plan(router: &Router, expected_version: u32, name: &str) -> serde_json::Value {
    let response = send(
        router,
        "PUT",
        "/api/v1/home/plan",
        Some(save_request(expected_version, sample_plan(name))),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

#[tokio::test]
async fn every_home_route_rejects_unauthenticated_requests() {
    let (router, _, _) = fixture().await;
    let body = save_request(0, sample_plan("Home"))
        .to_string()
        .into_bytes();
    for (method, uri, payload) in [
        ("GET", "/api/v1/home", None),
        ("PUT", "/api/v1/home/plan", Some(body.clone())),
        (
            "PUT",
            "/api/v1/home/placements/018f0000-0000-7000-8000-00000000abcd",
            Some(placement_body().to_string().into_bytes()),
        ),
        (
            "DELETE",
            "/api/v1/home/placements/018f0000-0000-7000-8000-00000000abcd",
            None,
        ),
        ("GET", "/api/v1/home/draft", None),
        ("PUT", "/api/v1/home/draft", Some(b"{}".to_vec())),
        ("DELETE", "/api/v1/home/draft", None),
    ] {
        let response = send_raw(&router, method, uri, payload, false).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
    }
}

#[tokio::test]
async fn empty_state_serves_a_default_plan_not_a_404() {
    let (router, _, _) = fixture().await;
    let response = send(&router, "GET", "/api/v1/home", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot = json_body(response).await;
    assert_eq!(snapshot["plan"]["version"], 0);
    assert_eq!(snapshot["plan"]["floors"], serde_json::json!([]));
    assert_eq!(snapshot["placements"], serde_json::json!([]));
    assert_eq!(snapshot["estimates"], serde_json::json!([]));
    assert_eq!(snapshot["recovered"], false);
    // The first-run identity is stable across requests so the editor can key
    // drafts against it before the first committed save.
    let again = json_body(send(&router, "GET", "/api/v1/home", None).await).await;
    assert_eq!(snapshot["plan"]["home_id"], again["plan"]["home_id"]);
}

#[tokio::test]
async fn committed_save_round_trips_through_the_snapshot() {
    let (router, _, _) = fixture().await;
    let saved = save_plan(&router, 0, "Home").await;
    assert_eq!(saved, serde_json::json!({ "version": 1 }));
    let snapshot = json_body(send(&router, "GET", "/api/v1/home", None).await).await;
    assert_eq!(snapshot["plan"]["home_id"], HOME_ID);
    assert_eq!(snapshot["plan"]["version"], 1);
    assert_eq!(snapshot["plan"]["name"], "Home");
    assert_eq!(snapshot["plan"]["floors"][0]["floor_id"], FLOOR_ID);
    assert_eq!(snapshot["recovered"], false);
}

#[tokio::test]
async fn stale_writer_gets_409_with_actual_version_and_recovers_by_refetching() {
    let (router, _, _) = fixture().await;
    save_plan(&router, 0, "Home").await;
    let response = send(
        &router,
        "PUT",
        "/api/v1/home/plan",
        Some(save_request(0, sample_plan("Stale"))),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await,
        serde_json::json!({ "actual_version": 1 })
    );
    // The stale writer refetches, adopts the stored version, and succeeds.
    let snapshot = json_body(send(&router, "GET", "/api/v1/home", None).await).await;
    let actual = u32::try_from(snapshot["plan"]["version"].as_u64().unwrap()).unwrap();
    assert_eq!(actual, 1);
    let saved = save_plan(&router, actual, "Recovered").await;
    assert_eq!(saved, serde_json::json!({ "version": 2 }));
}

#[tokio::test]
async fn invalid_plans_and_malformed_bodies_are_rejected_with_400() {
    let (router, _, _) = fixture().await;
    let mut invalid = sample_plan("Home");
    invalid["floors"][0]["ceiling_height_m"] = serde_json::json!(1.0);
    let response = send(
        &router,
        "PUT",
        "/api/v1/home/plan",
        Some(save_request(0, invalid)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let reason = json_body(response).await;
    assert!(
        reason["error"].as_str().unwrap().contains("ceiling height"),
        "{reason}"
    );
    for body in [
        b"{malformed".to_vec(),
        serde_json::json!({ "expected_version": 0, "plan": sample_plan("Home"), "extra": 1 })
            .to_string()
            .into_bytes(),
    ] {
        let response = send_raw(&router, "PUT", "/api/v1/home/plan", Some(body), true).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    // Nothing was committed by any rejected write.
    let snapshot = json_body(send(&router, "GET", "/api/v1/home", None).await).await;
    assert_eq!(snapshot["plan"]["version"], 0);
}

#[tokio::test]
async fn placement_upsert_and_delete_round_trip_and_delete_is_idempotent() {
    let (router, state, _) = fixture().await;
    save_plan(&router, 0, "Home").await;
    let uri = format!("/api/v1/home/placements/{DEVICE_ID}");
    let response = send(&router, "PUT", &uri, Some(placement_body())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let stored = json_body(response).await;
    assert_eq!(stored["device_id"], DEVICE_ID);
    assert_eq!(stored["floor_id"], FLOOR_ID);
    assert!(stored["placement_id"].is_string());

    let snapshot = json_body(send(&router, "GET", "/api/v1/home", None).await).await;
    assert_eq!(snapshot["placements"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["placements"][0]["device_id"], DEVICE_ID);
    assert_eq!(snapshot["placements"][0]["x"], 1.5);
    assert_eq!(snapshot["placements"][0]["mounting"], "wall");

    let response = send(&router, "DELETE", &uri, None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let snapshot = json_body(send(&router, "GET", "/api/v1/home", None).await).await;
    assert_eq!(snapshot["placements"], serde_json::json!([]));

    // Idempotent: a second delete succeeds and emits no further event.
    let before = state.events().current_sequence().await;
    let response = send(&router, "DELETE", &uri, None).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(state.events().current_sequence().await, before);
}

#[tokio::test]
async fn placement_inputs_are_validated_via_the_domain_types() {
    let (router, _, _) = fixture().await;
    let uri = format!("/api/v1/home/placements/{DEVICE_ID}");
    let mut out_of_range = placement_body();
    out_of_range["x"] = serde_json::json!(2000.0);
    let mut bad_mounting = placement_body();
    bad_mounting["mounting"] = serde_json::json!("roof");
    let mut bad_height = placement_body();
    bad_height["height_m"] = serde_json::json!(-1.0);
    for body in [out_of_range, bad_mounting, bad_height] {
        let response = send(&router, "PUT", &uri, Some(body)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    for device in ["not-a-uuid", "018F0000-0000-7000-8000-00000000ABCD"] {
        let response = send(
            &router,
            "PUT",
            &format!("/api/v1/home/placements/{device}"),
            Some(placement_body()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{device}");
        let response = send(
            &router,
            "DELETE",
            &format!("/api/v1/home/placements/{device}"),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{device}");
    }
}

#[tokio::test]
async fn draft_lifecycle_204_when_missing_round_trip_and_idempotent_delete() {
    let (router, _, _) = fixture().await;
    assert_eq!(
        send(&router, "GET", "/api/v1/home/draft", None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let blob = serde_json::json!({ "editor": "wip", "walls": [1, 2, 3] });
    let response = send_raw(
        &router,
        "PUT",
        "/api/v1/home/draft",
        Some(blob.to_string().into_bytes()),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = send(&router, "GET", "/api/v1/home/draft", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"].to_str().unwrap(),
        "application/json"
    );
    assert_eq!(json_body(response).await, blob);
    assert_eq!(
        send(&router, "DELETE", "/api/v1/home/draft", None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(&router, "GET", "/api/v1/home/draft", None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(&router, "DELETE", "/api/v1/home/draft", None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    // Non-JSON drafts are refused rather than stored.
    let response = send_raw(
        &router,
        "PUT",
        "/api/v1/home/draft",
        Some(b"not-json".to_vec()),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_drafts_are_rejected_with_413() {
    let (router, _, _) = fixture().await;
    let padding = "a".repeat(lattice_store::MAX_DRAFT_BYTES);
    let oversized = format!("{{\"pad\":\"{padding}\"}}");
    assert!(oversized.len() > lattice_store::MAX_DRAFT_BYTES);
    let response = send_raw(
        &router,
        "PUT",
        "/api/v1/home/draft",
        Some(oversized.into_bytes()),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        send(&router, "GET", "/api/v1/home/draft", None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn corrupt_stored_draft_is_reported_once_and_discarded() {
    let (router, _, pool) = fixture().await;
    save_plan(&router, 0, "Home").await;
    sqlx::query("INSERT INTO home_drafts(home_id, draft, updated_at) VALUES(?, 'not-json', ?)")
        .bind(HOME_ID)
        .bind("2026-08-24T00:00:00.000000000Z")
        .execute(&pool)
        .await
        .unwrap();
    let response = send(&router, "GET", "/api/v1/home/draft", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await,
        serde_json::json!({ "corrupt": true })
    );
    // The store discarded the corrupt blob; the next read is simply empty.
    assert_eq!(
        send(&router, "GET", "/api/v1/home/draft", None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn corrupt_current_plan_is_recovered_from_history_and_flagged() {
    let (router, _, pool) = fixture().await;
    save_plan(&router, 0, "Home").await;
    save_plan(&router, 1, "Home v2").await;
    sqlx::query("UPDATE home_plans SET plan='{}' WHERE singleton = 1")
        .execute(&pool)
        .await
        .unwrap();
    let response = send(&router, "GET", "/api/v1/home", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot = json_body(response).await;
    assert_eq!(snapshot["recovered"], true);
    assert_eq!(snapshot["plan"]["version"], 2);
    assert_eq!(snapshot["plan"]["name"], "Home v2");
}

async fn start_server(state: AppState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    format!("ws://{address}/api/v1/events")
}

async fn issue_ticket(router: &Router) -> String {
    let response = send(router, "POST", "/api/v1/events/ticket", None).await;
    json_body(response).await["ticket"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn next_event(
    socket: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
) -> serde_json::Value {
    let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .expect("event before timeout")
        .unwrap()
        .unwrap();
    let Message::Text(text) = message else {
        panic!("expected text event, got {message:?}");
    };
    serde_json::from_str(&text).unwrap()
}

#[tokio::test]
async fn home_changed_events_flow_to_websocket_clients_with_the_contract_shape() {
    let (router, state, _) = fixture().await;
    let address = start_server(state.clone()).await;
    let ticket = issue_ticket(&router).await;
    let (mut socket, _) = connect_async(format!("{address}?ticket={ticket}&after_sequence=0"))
        .await
        .unwrap();

    save_plan(&router, 0, "Home").await;
    let uri = format!("/api/v1/home/placements/{DEVICE_ID}");
    assert_eq!(
        send(&router, "PUT", &uri, Some(placement_body()))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&router, "DELETE", &uri, None).await.status(),
        StatusCode::NO_CONTENT
    );

    for (version, summary) in [
        (1, "plan saved"),
        (1, "placement updated"),
        (1, "placement removed"),
    ] {
        let event = next_event(&mut socket).await;
        assert_eq!(event["type"], "event");
        let payload = &event["data"]["payload"];
        assert_eq!(payload["type"], "home_changed", "{event}");
        let data = payload["data"].as_object().unwrap();
        assert_eq!(
            data.len(),
            3,
            "HomeChanged must carry exactly home_id/version/summary: {event}"
        );
        assert_eq!(data["home_id"], HOME_ID);
        assert_eq!(data["version"], version);
        assert_eq!(data["summary"], summary);
    }
}

#[tokio::test]
async fn drafts_emit_no_events_and_no_event_ever_embeds_the_draft_blob() {
    let (router, state, _) = fixture().await;
    let marker = "DRAFT-BLOB-SECRET-MARKER";
    let blob = serde_json::json!({ "secret": marker }).to_string();

    let before = state.events().current_sequence().await;
    let response = send_raw(
        &router,
        "PUT",
        "/api/v1/home/draft",
        Some(blob.into_bytes()),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        send(&router, "GET", "/api/v1/home/draft", None)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&router, "DELETE", "/api/v1/home/draft", None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        state.events().current_sequence().await,
        before,
        "draft operations must not publish events"
    );

    // Even with a draft present, committed writes emit summaries only.
    let response = send_raw(
        &router,
        "PUT",
        "/api/v1/home/draft",
        Some(
            serde_json::json!({ "secret": marker })
                .to_string()
                .into_bytes(),
        ),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    save_plan(&router, 0, "Home").await;
    let uri = format!("/api/v1/home/placements/{DEVICE_ID}");
    assert_eq!(
        send(&router, "PUT", &uri, Some(placement_body()))
            .await
            .status(),
        StatusCode::OK
    );
    for message in lattice_service::ws::resume_messages(state.events(), 0).await {
        let ServerMessage::Event(event) = message else {
            panic!("unexpected resync in a small stream");
        };
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(
            !serialized.contains(marker),
            "event embeds draft blob: {serialized}"
        );
        assert!(
            !serialized.contains("polygon") && !serialized.contains("\"x\""),
            "event embeds geometry: {serialized}"
        );
    }
}

#[tokio::test]
async fn openapi_documents_all_home_routes_and_schemas() {
    let (router, _, _) = fixture().await;
    let response = send_raw(&router, "GET", "/api/v1/openapi.json", None, false).await;
    assert_eq!(response.status(), StatusCode::OK);
    let doc = json_body(response).await;
    for (path, methods) in [
        ("/api/v1/home", vec!["get"]),
        ("/api/v1/home/plan", vec!["put"]),
        ("/api/v1/home/placements/{device_id}", vec!["put", "delete"]),
        ("/api/v1/home/draft", vec!["get", "put", "delete"]),
    ] {
        for method in methods {
            let operation = &doc["paths"][path][method];
            assert!(operation.is_object(), "missing {method} {path}");
            assert!(
                operation["security"].is_array(),
                "{method} {path} must document bearer auth"
            );
            assert!(
                operation["responses"]["401"].is_object(),
                "{method} {path} must document 401"
            );
        }
    }
    let put_plan = &doc["paths"]["/api/v1/home/plan"]["put"];
    assert!(put_plan["responses"]["409"].is_object());
    assert!(put_plan["responses"]["400"].is_object());
    assert!(doc["paths"]["/api/v1/home/draft"]["put"]["responses"]["413"].is_object());
    assert_eq!(
        doc["paths"]["/api/v1/home"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
            ["$ref"],
        "#/components/schemas/HomeSnapshot"
    );
    let schemas = &doc["components"]["schemas"];
    for name in [
        "HomeSnapshot",
        "SavePlanRequest",
        "SavePlanResponse",
        "PlanVersionConflict",
        "PlanRejected",
        "PlacementRequest",
        "DraftCorrupt",
        "HomePlan",
        "Floor",
        "Wall",
        "Room",
        "Opening",
        "Point",
        "OwnerPlacement",
        "LocationEstimate",
        "Mounting",
    ] {
        assert!(schemas[name].is_object(), "missing schema {name}");
    }
    let device_parameter = doc["paths"]["/api/v1/home/placements/{device_id}"]["put"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|parameter| parameter["name"] == "device_id")
        .unwrap()
        .clone();
    assert_eq!(device_parameter["schema"]["format"], "uuid");
    assert_eq!(device_parameter["schema"]["minLength"], 36);
    assert_eq!(device_parameter["schema"]["maxLength"], 36);
}

#[tokio::test]
async fn snapshot_includes_estimates_alongside_authoritative_placements() {
    let (router, _, pool) = fixture().await;
    save_plan(&router, 0, "Home").await;
    let repository = lattice_store::HomeRepository::new(pool);
    repository
        .upsert_estimate(&lattice_domain::LocationEstimate {
            device_id: lattice_domain::DeviceId::parse(DEVICE_ID).unwrap(),
            floor_id: Some(lattice_domain::FloorId::parse(FLOOR_ID).unwrap()),
            room_id: None,
            confidence: 0.42,
            evidence: vec!["w6-rssi".to_owned()],
            estimated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let snapshot = json_body(send(&router, "GET", "/api/v1/home", None).await).await;
    assert_eq!(snapshot["estimates"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["estimates"][0]["device_id"], DEVICE_ID);
    assert_eq!(snapshot["placements"], serde_json::json!([]));
    // The body must never mistake an estimate for an owner placement.
    assert!((snapshot["estimates"][0]["confidence"].as_f64().unwrap() - 0.42).abs() < 1e-6);
}

#[tokio::test]
async fn responses_use_bytes_that_serde_accepts_after_body_collect() {
    // Regression guard for the harness itself: BodyExt::collect and
    // axum::body::to_bytes agree on the same payload.
    let (router, _, _) = fixture().await;
    let response = send(&router, "GET", "/api/v1/home", None).await;
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value["plan"].is_object());
}
