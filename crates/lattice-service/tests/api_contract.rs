use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use chrono::Utc;
use http_body_util::BodyExt;
use lattice_domain::{EventPayload, ServiceStatus};
use lattice_event_bus::Resume;
use lattice_sensor::InterfaceInventory;
use lattice_service::{
    AppState, ServiceRuntimeStatus, app,
    runtime::{StartupResult, build_from_inventory},
};
use lattice_store::{M2StateRepository, connect_memory};
use tower::ServiceExt;
const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
async fn test_state() -> AppState {
    AppState::new(
        TOKEN,
        M2StateRepository::new(connect_memory().await.unwrap()),
    )
    .unwrap()
}

async fn body(response: Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

fn authorized_state(path: &str) -> Request<Body> {
    Request::get(path)
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn health_is_public_and_reports_v1() {
    let response = app(test_state().await)
        .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body(response).await,
        serde_json::json!({"status":"ok","api_version":"v1"})
    );
}

#[tokio::test]
async fn snapshot_requires_exact_bearer_token() {
    for auth in [
        None,
        Some("Bearer wrong"),
        Some("Basic owner-token-0123456789abcdefghijkl"),
        Some("Bearer "),
        Some("Bearer"),
        Some("bearer owner-token-0123456789abcdefghijkl"),
        Some(" Bearer owner-token-0123456789abcdefghijkl"),
    ] {
        let mut request = Request::get("/api/v1/state");
        if let Some(auth) = auth {
            request = request.header("authorization", auth);
        }
        let response = app(test_state().await)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("www-authenticate").unwrap(),
            "Bearer"
        );
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&bytes).contains("owner-token"));
    }
    let mut duplicate = Request::get("/api/v1/state").body(Body::empty()).unwrap();
    duplicate.headers_mut().append(
        "authorization",
        "Bearer owner-token-0123456789abcdefghijkl".parse().unwrap(),
    );
    duplicate.headers_mut().append(
        "authorization",
        "Bearer owner-token-0123456789abcdefghijkl".parse().unwrap(),
    );
    let response = app(test_state().await).oneshot(duplicate).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        "Bearer"
    );
    let response = app(test_state().await)
        .oneshot(
            Request::get("/api/v1/state")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body(response).await,
        serde_json::json!({"sequence":0,"devices":[],"next_after":null,"service_status":"ready"})
    );
}

#[tokio::test]
async fn snapshot_uses_current_event_watermark() {
    let state = test_state().await;
    state
        .events()
        .publish(
            Utc::now(),
            EventPayload::ServiceStatus(ServiceStatus {
                state: "ready".into(),
                detail: "test".into(),
            }),
        )
        .await;
    let response = app(state)
        .oneshot(
            Request::get("/api/v1/state")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body(response).await["sequence"], 1);
}

#[tokio::test]
async fn state_exposes_runtime_degraded_status() {
    let state = test_state().await;
    state
        .transition_service_status(ServiceRuntimeStatus::Degraded, Utc::now())
        .await;
    let response = app(state)
        .oneshot(authorized_state("/api/v1/state"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await["service_status"], "degraded");
}

#[tokio::test]
async fn snapshot_projects_empty_device_into_typed_unavailable_fields() {
    let pool = connect_memory().await.unwrap();
    let id = "018f47a0-9b5c-7a22-8a33-112233445599";
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_name,owner_type,owner_confirmed) VALUES(?,?,?,?,?,?)")
        .bind(id).bind("2026-01-01T00:00:00Z").bind("2026-01-01T00:00:01Z").bind("Alice").bind("laptop").bind(1i64)
        .execute(&pool).await.unwrap();
    let response = app(AppState::new(TOKEN, M2StateRepository::new(pool)).unwrap())
        .oneshot(
            Request::get("/api/v1/state")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body(response).await["devices"][0],
        serde_json::json!({
            "device_id":id,"first_seen_at":"2026-01-01T00:00:00Z","last_seen_at":"2026-01-01T00:00:01Z",
            "owner_name":"Alice","owner_type":"laptop","owner_confirmed":true,
            "presence":{"state":"unknown","observed_at":null,"source":null,"kind":null},"evidence":null,
            "identity":{"available":false,"classification":null,"confidence":null},
            "policy":null,
            "bandwidth":{"available":false,"upload":null,"download":null,"coverage":null,"observed_at":null}
        })
    );
}

#[tokio::test]
async fn snapshot_projects_safe_evidence_latest_unknown_presence_and_latest_bandwidth() {
    let pool = connect_memory().await.unwrap();
    let id = "018f47a0-9b5c-7a22-8a33-112233445511";
    sqlx::query(
        "INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_confirmed) VALUES(?,?,?,?)",
    )
    .bind(id)
    .bind("2026-01-01T00:00:00Z")
    .bind("2026-01-01T00:00:09Z")
    .bind(0i64)
    .execute(&pool)
    .await
    .unwrap();
    for (transition_id, to_state, occurred_at, source, kind) in [
        (1i64, "online", "2026-01-01T00:00:02Z", "probe", "reply"),
        (
            2,
            "unknown",
            "2026-01-01T00:00:03Z",
            "sensor",
            "contradiction",
        ),
    ] {
        sqlx::query("INSERT INTO presence_transitions(transition_id,device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,trigger_arrival_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(transition_id).bind(id).bind("online").bind(to_state).bind(occurred_at).bind("synthetic").bind(source).bind(kind).bind(occurred_at).bind(occurred_at)
            .execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO evidence(device_id,family,source,fact_key,fact_value,confidence,observed_at,expires_at) VALUES(?,?,?,?,?,?,?,?)")
        .bind(id).bind("link_layer").bind("synthetic-neighbor").bind("synthetic_fact_key").bind("synthetic-secret-value").bind(0.75).bind("2026-01-01T00:00:04Z").bind("2026-01-01T00:01:04Z")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO evidence(device_id,family,source,fact_key,fact_value,confidence,observed_at,expires_at) VALUES(?,?,?,?,?,?,?,?)")
        .bind(id).bind("link_layer").bind("synthetic-mac").bind("mac").bind("02:aa:bb:cc:dd:ee").bind(0.5).bind("2026-01-01T00:00:01Z").bind(Option::<String>::None)
        .execute(&pool).await.unwrap();
    for (resolution, bucket, interface, upload, download, coverage) in [
        (
            "second",
            "2026-01-01T00:00:04Z",
            1i64,
            99i64,
            99i64,
            "complete",
        ),
        ("minute", "2026-01-01T00:01:00Z", 1, 500, 600, "complete"),
        ("second", "2026-01-01T00:00:05Z", 1, 10, 20, "complete"),
        ("second", "2026-01-01T00:00:05Z", 2, 30, 40, "local-only"),
    ] {
        sqlx::query("INSERT INTO flow_rollups(resolution,bucket,device_id,protocol,destination,interface,upload,download,coverage,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(resolution).bind(bucket).bind(id).bind("tcp").bind("lan").bind(interface).bind(upload).bind(download).bind(coverage).bind(bucket)
            .execute(&pool).await.unwrap();
    }

    let response = app(AppState::new(TOKEN, M2StateRepository::new(pool)).unwrap())
        .oneshot(authorized_state("/api/v1/state"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = body(response).await;
    assert_eq!(
        value["devices"][0]["presence"],
        serde_json::json!({"state":"unknown","observed_at":"2026-01-01T00:00:03Z","source":"sensor","kind":"contradiction"})
    );
    assert_eq!(
        value["devices"][0]["evidence"],
        serde_json::json!({"family":"link_layer","source":"synthetic-neighbor","confidence":0.75,"observed_at":"2026-01-01T00:00:04Z","expires_at":"2026-01-01T00:01:04Z"})
    );
    assert_eq!(
        value["devices"][0]["bandwidth"],
        serde_json::json!({"available":true,"upload":40,"download":60,"coverage":"estimated","observed_at":"2026-01-01T00:00:05Z"})
    );
    let serialized = value.to_string();
    for secret in [
        "02:aa:bb:cc:dd:ee",
        "synthetic_fact_key",
        "synthetic-secret-value",
    ] {
        assert!(!serialized.contains(secret), "snapshot leaked {secret}");
    }
}

#[tokio::test]
async fn snapshot_paginates_deterministically_and_authenticates_before_bad_queries() {
    let pool = connect_memory().await.unwrap();
    let ids = [
        "018f47a0-9b5c-7a22-8a33-112233445521",
        "018f47a0-9b5c-7a22-8a33-112233445522",
        "018f47a0-9b5c-7a22-8a33-112233445523",
    ];
    for id in ids {
        sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_confirmed) VALUES(?,?,?,?)")
            .bind(id).bind("2026-01-01T00:00:00Z").bind("2026-01-01T00:00:01Z").bind(0i64)
            .execute(&pool).await.unwrap();
    }
    let app = app(AppState::new(TOKEN, M2StateRepository::new(pool)).unwrap());
    let first = app
        .clone()
        .oneshot(authorized_state("/api/v1/state?limit=2"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first = body(first).await;
    assert_eq!(
        first["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["device_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ids[..2]
    );
    assert_eq!(first["next_after"], ids[1]);
    let second = app
        .clone()
        .oneshot(authorized_state(&format!(
            "/api/v1/state?limit=2&after={}",
            ids[1]
        )))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second = body(second).await;
    assert_eq!(
        second["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["device_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ids[2..]
    );
    assert_eq!(second["next_after"], serde_json::Value::Null);
    assert_eq!(
        app.clone()
            .oneshot(authorized_state("/api/v1/state?limit=0"))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.clone()
            .oneshot(authorized_state("/api/v1/state?limit=257"))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.clone()
            .oneshot(authorized_state("/api/v1/state?after=not-a-uuid"))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.oneshot(
            Request::get("/api/v1/state?limit=0")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn snapshot_maps_corrupt_selected_rows_to_sanitized_service_unavailable() {
    for (raw_id, last_seen_at, corrupt_presence, secret) in [
        (
            "invalid-synthetic-device-id",
            "2026-01-01T00:00:01Z",
            false,
            "invalid-synthetic-device-id",
        ),
        (
            "018f47a0-9b5c-7a22-8a33-112233445531",
            "invalid-synthetic-timestamp",
            false,
            "invalid-synthetic-timestamp",
        ),
        (
            "018f47a0-9b5c-7a22-8a33-112233445532",
            "2026-01-01T00:00:01Z",
            true,
            "invalid-synthetic-presence",
        ),
    ] {
        let pool = connect_memory().await.unwrap();
        sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_confirmed) VALUES(?,?,?,?)")
            .bind(raw_id).bind("2026-01-01T00:00:00Z").bind(last_seen_at).bind(0i64)
            .execute(&pool).await.unwrap();
        if corrupt_presence {
            sqlx::query("INSERT INTO presence_transitions(transition_id,device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,trigger_arrival_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(1i64).bind(raw_id).bind("online").bind(secret).bind("2026-01-01T00:00:01Z").bind("synthetic").bind("sensor").bind("contradiction").bind("2026-01-01T00:00:01Z").bind("2026-01-01T00:00:01Z")
                .execute(&pool).await.unwrap();
        }
        let response = app(AppState::new(TOKEN, M2StateRepository::new(pool)).unwrap())
            .oneshot(authorized_state("/api/v1/state"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body =
            String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
                .into_owned();
        assert!(!body.contains(secret));
        assert!(!body.contains(raw_id));
    }
}

#[tokio::test]
async fn event_ticket_requires_bearer_and_is_a_uuid() {
    for authorization in [None, Some("Bearer wrong")] {
        let mut request = Request::post("/api/v1/events/ticket");
        if let Some(authorization) = authorization {
            request = request.header("authorization", authorization);
        }
        let response = app(test_state().await)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let response = app(test_state().await)
        .oneshot(
            Request::post("/api/v1/events/ticket")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let ticket = body(response).await;
    assert_eq!(ticket["expires_in_seconds"], 30);
    assert!(uuid::Uuid::parse_str(ticket["ticket"].as_str().unwrap()).is_ok());
    assert!(!ticket["ticket"].as_str().unwrap().contains(TOKEN));
}

#[tokio::test]
async fn event_ticket_limit_is_rate_limited() {
    let app = app(test_state().await);
    for _ in 0..64 {
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v1/events/ticket")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = app
        .oneshot(
            Request::post("/api/v1/events/ticket")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
}

#[tokio::test]
async fn openapi_describes_public_and_protected_routes() {
    let response = app(test_state().await)
        .oneshot(
            Request::get("/api/v1/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let doc = body(response).await;
    assert!(doc["paths"]["/api/v1/health"].is_object());
    assert!(doc["paths"]["/api/v1/state"].is_object());
    assert!(doc["paths"]["/api/v1/events/ticket"].is_object());
    assert!(
        doc["paths"]["/api/v1/events/ticket"]["post"]["security"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["bearer_auth"].is_array())
    );
    let state = &doc["paths"]["/api/v1/state"]["get"];
    assert!(
        state["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "limit")
    );
    assert!(
        state["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "after")
    );
    for status in ["400", "401", "503"] {
        assert!(state["responses"][status].is_object());
    }
    assert_eq!(
        state["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/Snapshot"
    );
    assert_eq!(
        doc["components"]["schemas"]["Snapshot"]["properties"]["devices"]["items"]["$ref"],
        "#/components/schemas/DeviceSnapshot"
    );
    for schema in [
        "DeviceSnapshot",
        "Presence",
        "Evidence",
        "Identity",
        "Bandwidth",
    ] {
        assert!(doc["components"]["schemas"][schema].is_object());
    }
    for field in ["upload", "download", "coverage", "observed_at"] {
        let schema = &doc["components"]["schemas"]["Bandwidth"]["properties"][field];
        assert!(schema.is_object());
        assert!(
            schema["nullable"] == true
                || schema["type"]
                    .as_array()
                    .is_some_and(|types| types.iter().any(|ty| ty == "null"))
                || schema["oneOf"].as_array().is_some_and(|variants| variants
                    .iter()
                    .any(|variant| variant["type"] == "null")),
            "bandwidth {field} was not nullable: {schema}"
        );
    }
    assert!(doc["paths"]["/api/v1/events/ticket"]["post"]["responses"]["429"].is_object());
    assert!(
        doc["paths"]["/api/v1/state"]["get"]["security"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["bearer_auth"].is_array())
    );
    assert_eq!(
        doc["components"]["securitySchemes"]["bearer_auth"]["type"],
        "http"
    );
}

#[tokio::test]
async fn service_token_configuration_is_validated() {
    for token in [
        "",
        " ",
        "short",
        " leading________________________________",
        "trailing________________________________ ",
        "ümlaut________________________________",
    ] {
        assert!(
            AppState::new(
                token,
                M2StateRepository::new(connect_memory().await.unwrap())
            )
            .is_err()
        );
    }
    assert!(test_state().await.events().current_sequence().await == 0);
}

#[tokio::test]
async fn no_eligible_startup_is_degraded_once_and_replays_before_state_snapshot() {
    let pool = connect_memory().await.unwrap();
    let repo = M2StateRepository::new(pool);
    let state = AppState::new(TOKEN, repo.clone()).unwrap();
    assert!(matches!(
        build_from_inventory(state.clone(), repo.clone(), InterfaceInventory::default()).await,
        StartupResult::Degraded
    ));
    assert_eq!(state.service_status().await, "degraded");
    assert!(
        matches!(state.events().resume_after(0).await, Resume::Events(ref events) if matches!(events.as_slice(), [event] if matches!(event.payload, EventPayload::ServiceStatus(ref status) if status.state == "degraded")))
    );
    assert!(matches!(
        build_from_inventory(state.clone(), repo, InterfaceInventory::default()).await,
        StartupResult::Degraded
    ));
    assert_eq!(state.events().current_sequence().await, 1);
    let response = app(state)
        .oneshot(authorized_state("/api/v1/state"))
        .await
        .unwrap();
    let snapshot = body(response).await;
    assert_eq!(snapshot["sequence"], 1);
    assert_eq!(snapshot["service_status"], "degraded");
    assert!(!snapshot.to_string().contains("adapter-"));
}
