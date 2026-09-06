//! Integrations contract tests (M6 I1–I2): scoped token minting/listing/
//! revocation, per-scope gating of the versioned read surface, the filtered
//! events long-poll, and the hard exclusions keeping integration tokens off
//! every other surface.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use lattice_domain::{EventPayload, PresenceChanged, PresenceState, ServiceStatus};
use lattice_service::{AppState, app};
use lattice_store::{
    AuditCategory, AuditFilter, AuditLog, AuditPage, M2StateRepository, PolicyRepository,
    connect_memory,
};
use sqlx::SqlitePool;
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
const DEVICE_ID: &str = "018f0000-0000-7000-8000-00000000abcd";

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

struct Fixture {
    router: Router,
    state: AppState,
    pool: SqlitePool,
}

async fn fixture() -> Fixture {
    let pool = connect_memory().await.unwrap();
    let state = AppState::new(TOKEN, M2StateRepository::new(pool.clone())).unwrap();
    Fixture {
        router: app(state.clone()),
        state,
        pool,
    }
}

#[derive(Clone)]
enum Auth {
    None,
    Owner,
    Bearer(String),
    Phone(String),
}

async fn send(
    router: &Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
    auth: &Auth,
) -> axum::response::Response {
    let mut request = Request::builder().method(method).uri(uri);
    match auth {
        Auth::None => {}
        Auth::Owner => {
            request = request.header("authorization", format!("Bearer {TOKEN}"));
        }
        Auth::Bearer(token) => {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        Auth::Phone(credentials) => {
            request = request.header("authorization", format!("PhoneSession {credentials}"));
        }
    }
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let body = body
        .map(|value| value.to_string().into_bytes())
        .unwrap_or_default();
    router
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// Mints an integration token with the given scopes and returns (id, token).
async fn mint(fixture: &Fixture, name: &str, scopes: &[&str]) -> (String, String) {
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/integrations/tokens",
        Some(serde_json::json!({ "name": name, "scopes": scopes })),
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    (
        body["id"].as_str().unwrap().to_owned(),
        body["token"].as_str().unwrap().to_owned(),
    )
}

async fn seed_device(pool: &SqlitePool) {
    sqlx::query(
        "INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_name,owner_type,owner_confirmed) VALUES(?,?,?,?,?,?)",
    )
    .bind(DEVICE_ID)
    .bind("2026-01-01T00:00:00Z")
    .bind("2026-01-02T00:00:00Z")
    .bind("Alice")
    .bind("laptop")
    .bind(1i64)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO presence_transitions(transition_id,device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,evidence_valid_until,trigger_arrival_at,correction_of) VALUES(1,?,?,?,?,?,?,?,?,NULL,?,NULL)",
    )
    .bind(DEVICE_ID)
    .bind("unknown")
    .bind("online")
    .bind("2026-01-02T00:00:00Z")
    .bind("seen")
    .bind("sensor")
    .bind("arp")
    .bind("2026-01-02T00:00:00Z")
    .bind("2026-01-02T00:00:00Z")
    .execute(pool)
    .await
    .unwrap();
}

async fn approval_audit_actions(pool: &SqlitePool) -> Vec<String> {
    AuditLog::new(pool.clone())
        .list(
            &AuditFilter {
                category: Some(AuditCategory::Approval),
                ..Default::default()
            },
            AuditPage {
                after_id: None,
                limit: 64,
            },
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.action)
        .collect()
}

// ---------------------------------------------------------------------------
// I1: token management.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_management_requires_the_owner_bearer() {
    let fixture = fixture().await;
    for (method, uri, body) in [
        (
            "POST",
            "/api/v1/integrations/tokens",
            Some(serde_json::json!({ "name": "ha", "scopes": ["devices:read"] })),
        ),
        ("GET", "/api/v1/integrations/tokens", None),
        (
            "DELETE",
            "/api/v1/integrations/tokens/018f47a0-9b5c-7a22-8a33-112233445566",
            None,
        ),
    ] {
        let response = send(&fixture.router, method, uri, body, &Auth::None).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
    }
}

#[tokio::test]
async fn minting_listing_and_revoking_tokens_is_hash_stored_and_audited() {
    let fixture = fixture().await;
    let (id, token) = mint(
        &fixture,
        "home-assistant",
        &["devices:read", "presence:read"],
    )
    .await;
    assert_eq!(token.len(), 64);
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

    // Only the SHA-256 of the token is stored.
    let (token_hash,): (String,) = sqlx::query_as("SELECT token_hash FROM integration_tokens")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_ne!(token_hash, token);

    // The list never serves the token value.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/tokens",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let list = json_body(response).await;
    assert_eq!(list["items"][0]["name"], "home-assistant");
    assert_eq!(
        list["items"][0]["scopes"],
        serde_json::json!(["devices:read", "presence:read"])
    );
    assert_eq!(list["items"][0]["revoked"], false);
    assert!(!list.to_string().contains(&token));

    // Revoke, list shows it, second revoke of an unknown id is 404.
    let response = send(
        &fixture.router,
        "DELETE",
        &format!("/api/v1/integrations/tokens/{id}"),
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let list = json_body(
        send(
            &fixture.router,
            "GET",
            "/api/v1/integrations/tokens",
            None,
            &Auth::Owner,
        )
        .await,
    )
    .await;
    assert_eq!(list["items"][0]["revoked"], true);
    let response = send(
        &fixture.router,
        "DELETE",
        "/api/v1/integrations/tokens/018f47a0-9b5c-7a22-8a33-112233445599",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    assert_eq!(
        approval_audit_actions(&fixture.pool).await,
        ["integration_token_minted", "integration_token_revoked"]
    );
}

#[tokio::test]
async fn minting_rejects_unknown_empty_or_malformed_scopes() {
    let fixture = fixture().await;
    for body in [
        serde_json::json!({ "name": "x", "scopes": [] }),
        serde_json::json!({ "name": "x", "scopes": ["vault:read"] }),
        serde_json::json!({ "name": "x", "scopes": ["devices:write"] }),
        serde_json::json!({ "name": "x", "scopes": ["devices:read", "audit:read"] }),
        serde_json::json!({ "name": "", "scopes": ["devices:read"] }),
        serde_json::json!({ "name": "x" }),
        serde_json::json!({ "name": "x", "scopes": ["devices:read"], "extra": 1 }),
    ] {
        let response = send(
            &fixture.router,
            "POST",
            "/api/v1/integrations/tokens",
            Some(body.clone()),
            &Auth::Owner,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }
}

// ---------------------------------------------------------------------------
// I1: the read surface, gated per scope.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn each_scope_gates_exactly_its_projection() {
    let fixture = fixture().await;
    seed_device(&fixture.pool).await;
    let (_, devices_token) = mint(&fixture, "devices-only", &["devices:read"]).await;
    let (_, policy_token) = mint(&fixture, "policy-only", &["policy:read"]).await;

    let devices_auth = Auth::Bearer(devices_token);
    let policy_auth = Auth::Bearer(policy_token);

    // devices:read serves the device projection…
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/devices",
        None,
        &devices_auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(
        body["items"][0],
        serde_json::json!({
            "device_id": DEVICE_ID,
            "first_seen_at": "2026-01-01T00:00:00Z",
            "last_seen_at": "2026-01-02T00:00:00Z",
            "owner_name": "Alice",
            "owner_type": "laptop",
            "owner_confirmed": true
        })
    );
    // …and nothing else.
    for uri in [
        "/api/v1/integrations/v1/presence",
        "/api/v1/integrations/v1/bandwidth",
        "/api/v1/integrations/v1/policy",
    ] {
        let response = send(&fixture.router, "GET", uri, None, &devices_auth).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
    }

    // policy:read serves policy and nothing else.
    lattice_store::InstallRepository::new(fixture.pool.clone())
        .initialize(Utc::now())
        .await
        .unwrap();
    let repo = PolicyRepository::new(fixture.pool.clone());
    repo.mark_successful_service_start(Utc::now())
        .await
        .unwrap();
    let device = lattice_domain::DeviceId::parse(DEVICE_ID).unwrap();
    repo.enroll(device).await.unwrap();
    repo.set_owner_decision(device, lattice_domain::OwnerDecision::Approved)
        .await
        .unwrap();
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/policy",
        None,
        &policy_auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["items"][0]["device_id"], DEVICE_ID);
    assert_eq!(body["items"][0]["owner_decision"], "approved");
    for uri in [
        "/api/v1/integrations/v1/devices",
        "/api/v1/integrations/v1/presence",
        "/api/v1/integrations/v1/bandwidth",
    ] {
        let response = send(&fixture.router, "GET", uri, None, &policy_auth).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
    }
}

#[tokio::test]
async fn presence_and_bandwidth_projections_serve_scoped_state_only() {
    let fixture = fixture().await;
    seed_device(&fixture.pool).await;
    let (_, token) = mint(&fixture, "sensors", &["presence:read", "bandwidth:read"]).await;
    let auth = Auth::Bearer(token);

    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/presence",
        None,
        &auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(
        body["items"][0],
        serde_json::json!({
            "device_id": DEVICE_ID,
            "state": "online",
            "observed_at": "2026-01-02T00:00:00Z"
        })
    );
    // No owner metadata leaks through the presence projection.
    assert!(!body.to_string().contains("Alice"));

    // Bandwidth: no flow rollups seeded, so the list is empty but the scope
    // is honored.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/bandwidth",
        None,
        &auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["items"], serde_json::json!([]));

    // But not devices.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/devices",
        None,
        &auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_read_surface_accepts_only_live_integration_tokens() {
    let fixture = fixture().await;
    let (id, token) = mint(&fixture, "ha", &["devices:read"]).await;

    // The owner bearer is NOT an integration principal.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/devices",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // Nor is garbage, or nothing.
    for auth in [Auth::Bearer("bogus".into()), Auth::None] {
        let response = send(
            &fixture.router,
            "GET",
            "/api/v1/integrations/v1/devices",
            None,
            &auth,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // A live token works until revoked.
    let auth = Auth::Bearer(token);
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/devices",
        None,
        &auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(
        &fixture.router,
        "DELETE",
        &format!("/api/v1/integrations/tokens/{id}"),
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/devices",
        None,
        &auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// I1: events long-poll.
// ---------------------------------------------------------------------------

fn presence_event() -> EventPayload {
    EventPayload::PresenceChanged(PresenceChanged {
        transition_id: 1,
        device_id: lattice_domain::DeviceId::parse(DEVICE_ID).unwrap(),
        from: PresenceState::Unknown,
        to: PresenceState::Online,
        occurred_at: Utc::now(),
        reason: "seen".into(),
        trigger_source: "sensor".into(),
        trigger_kind: "arp".into(),
        evidence_observed_at: Utc::now(),
        evidence_valid_until: None,
        trigger_arrival_at: Utc::now(),
        correction_of: None,
    })
}

fn service_event() -> EventPayload {
    EventPayload::ServiceStatus(ServiceStatus {
        state: "ready".into(),
        detail: "test".into(),
    })
}

#[tokio::test]
async fn events_feed_filters_to_scoped_payload_types_and_keeps_raw_sequences() {
    let fixture = fixture().await;
    let (_, token) = mint(&fixture, "ha", &["presence:read"]).await;
    let auth = Auth::Bearer(token);

    fixture
        .state
        .events()
        .publish(Utc::now(), service_event())
        .await;
    fixture
        .state
        .events()
        .publish(Utc::now(), presence_event())
        .await;
    fixture
        .state
        .events()
        .publish(Utc::now(), service_event())
        .await;

    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/events?after_sequence=0",
        None,
        &auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["resync"], false);
    // Only the presence envelope is served; the cursor still advances over
    // the filtered-out events.
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["sequence"], 2);
    assert_eq!(events[0]["payload"]["type"], "presence_changed");
    assert_eq!(body["next_after"], 3);

    // Resuming past the head requires a resync.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/events?after_sequence=999",
        None,
        &auth,
    )
    .await;
    let body = json_body(response).await;
    assert_eq!(body["resync"], true);
    assert_eq!(body["events"], serde_json::json!([]));
}

#[tokio::test]
async fn events_long_poll_wakes_on_a_scoped_event_and_times_out_otherwise() {
    let fixture = fixture().await;
    let (_, token) = mint(&fixture, "ha", &["presence:read"]).await;
    let auth = Auth::Bearer(token);

    // A pending long-poll returns as soon as a scoped event is published.
    let router = fixture.router.clone();
    let poll_auth = auth.clone();
    let poll = tokio::spawn(async move {
        send(
            &router,
            "GET",
            "/api/v1/integrations/v1/events?after_sequence=0&wait_ms=10000",
            None,
            &poll_auth,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // An unscoped event does not complete the poll…
    fixture
        .state
        .events()
        .publish(Utc::now(), service_event())
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!poll.is_finished());
    // …a scoped one does.
    fixture
        .state
        .events()
        .publish(Utc::now(), presence_event())
        .await;
    let response = poll.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["payload"]["type"], "presence_changed");
    assert_eq!(body["next_after"], 2);

    // With no events at all, a short wait times out with an empty page.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/events?after_sequence=2&wait_ms=100",
        None,
        &auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["events"], serde_json::json!([]));
    assert_eq!(body["next_after"], 2);
}

// ---------------------------------------------------------------------------
// I2: hard exclusions.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn integration_tokens_are_rejected_on_every_surface_outside_their_own() {
    let fixture = fixture().await;
    let (_, token) = mint(
        &fixture,
        "greedy",
        &[
            "devices:read",
            "presence:read",
            "bandwidth:read",
            "policy:read",
        ],
    )
    .await;
    let auth = Auth::Bearer(token);
    let camera = "018f0000-0000-7000-8000-00000000abcd";
    for (method, uri, body) in [
        // Reads of owner state.
        ("GET", "/api/v1/state", None),
        ("GET", "/api/v1/home", None),
        ("GET", "/api/v1/home/draft", None),
        (
            "GET",
            "/api/v1/devices/018f0000-0000-7000-8000-00000000abcd/advisories",
            None,
        ),
        // Every mutating route.
        (
            "POST",
            "/api/v1/policy/action",
            Some(serde_json::json!({
                "device_id": "018f0000-0000-7000-8000-00000000abcd",
                "action": "approve"
            })),
        ),
        ("PUT", "/api/v1/home/plan", Some(serde_json::json!({}))),
        (
            "PUT",
            "/api/v1/home/placements/018f0000-0000-7000-8000-00000000abcd",
            Some(serde_json::json!({})),
        ),
        (
            "DELETE",
            "/api/v1/home/placements/018f0000-0000-7000-8000-00000000abcd",
            None,
        ),
        ("PUT", "/api/v1/home/draft", Some(serde_json::json!({}))),
        ("DELETE", "/api/v1/home/draft", None),
        // Doctor routes.
        ("POST", "/api/v1/doctor/run", None),
        ("GET", "/api/v1/doctor/report", None),
        (
            "POST",
            "/api/v1/doctor/approvals",
            Some(serde_json::json!({ "diagnosis_kind": { "kind": "router_fault" } })),
        ),
        (
            "POST",
            "/api/v1/doctor/repair",
            Some(serde_json::json!({ "diagnosis_kind": { "kind": "router_fault" } })),
        ),
        // Camera credential / stream surfaces.
        ("GET", "/api/v1/cameras", None),
        (
            "POST",
            &format!("/api/v1/cameras/{camera}/sessions"),
            Some(serde_json::json!({ "stream_id": camera })),
        ),
        ("GET", &format!("/api/v1/cameras/{camera}/snapshot"), None),
        (
            "DELETE",
            "/api/v1/camera-sessions/018f0000-0000-7000-8000-00000000abcd",
            None,
        ),
        // The owner event stream: the ticket is the only WS entry point.
        ("POST", "/api/v1/events/ticket", None),
        // Remote access management.
        (
            "POST",
            "/api/v1/remote/pair",
            Some(serde_json::json!({ "device_label": "x", "pin": "123456" })),
        ),
        ("GET", "/api/v1/remote/sessions", None),
        ("POST", "/api/v1/remote/serve", None),
        ("GET", "/api/v1/remote/status", None),
        // Token management itself.
        (
            "POST",
            "/api/v1/integrations/tokens",
            Some(serde_json::json!({ "name": "x", "scopes": ["devices:read"] })),
        ),
        ("GET", "/api/v1/integrations/tokens", None),
    ] {
        let response = send(&fixture.router, method, uri, body, &auth).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} must reject integration tokens"
        );
    }
}

#[tokio::test]
async fn phone_sessions_are_rejected_on_the_integration_surface() {
    let fixture = fixture().await;
    // Pair a real phone session through the owner.
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/remote/pair",
        Some(serde_json::json!({ "device_label": "pixel", "pin": "123456" })),
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let credentials = format!(
        "{}:{}",
        body["session_id"].as_str().unwrap(),
        body["secret"].as_str().unwrap()
    );
    let phone = Auth::Phone(credentials);
    for uri in [
        "/api/v1/integrations/v1/devices",
        "/api/v1/integrations/v1/presence",
        "/api/v1/integrations/v1/bandwidth",
        "/api/v1/integrations/v1/policy",
        "/api/v1/integrations/v1/events?after_sequence=0",
    ] {
        let response = send(&fixture.router, "GET", uri, None, &phone).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
}

// ---------------------------------------------------------------------------
// OpenAPI registration.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openapi_documents_the_integration_routes() {
    let fixture = fixture().await;
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/openapi.json",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let doc = json_body(response).await;
    for (path, method) in [
        ("/api/v1/integrations/tokens", "post"),
        ("/api/v1/integrations/tokens", "get"),
        ("/api/v1/integrations/tokens/{id}", "delete"),
        ("/api/v1/integrations/v1/devices", "get"),
        ("/api/v1/integrations/v1/presence", "get"),
        ("/api/v1/integrations/v1/bandwidth", "get"),
        ("/api/v1/integrations/v1/policy", "get"),
        ("/api/v1/integrations/v1/events", "get"),
    ] {
        assert!(
            doc["paths"][path][method].is_object(),
            "missing {method} {path}"
        );
    }
}

/// A token may hold a bounded number of long-polls open; a misbehaving
/// client cannot pile up parked broadcast receivers.
#[tokio::test]
async fn a_token_may_hold_at_most_four_long_polls_open() {
    let fixture = fixture().await;
    let (_, token) = mint(&fixture, "ha", &["presence:read"]).await;
    let auth = Auth::Bearer(token);
    let waiting = "/api/v1/integrations/v1/events?after_sequence=0&wait_ms=1500";
    let polls: Vec<_> = (0..4)
        .map(|_| {
            let router = fixture.router.clone();
            let poll_auth = auth.clone();
            tokio::spawn(async move { send(&router, "GET", waiting, None, &poll_auth).await })
        })
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // The fifth waiting poll is refused; an immediate read still works.
    let response = send(&fixture.router, "GET", waiting, None, &auth).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/events?after_sequence=0",
        None,
        &auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Another token has its own budget.
    let (_, other) = mint(&fixture, "other", &["presence:read"]).await;
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/events?after_sequence=0&wait_ms=100",
        None,
        &Auth::Bearer(other),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // The parked polls time out normally and release their permits.
    for poll in polls {
        assert_eq!(poll.await.unwrap().status(), StatusCode::OK);
    }
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/events?after_sequence=0&wait_ms=100",
        None,
        &auth,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}
