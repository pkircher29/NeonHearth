//! Remote phone access contract tests (M6 T1–T4): Tailscale Serve
//! configuration, Funnel refusal, forwarded-identity header stripping,
//! phone session pairing/expiry/step-up/rate-limit, and command replay
//! dedup — all through the real routes with a fake tailscale control and a
//! deterministic clock injected via `RemoteAccessState::with_parts`.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use futures_util::StreamExt;
use lattice_doctor::Clock;
use lattice_service::tailscale::{
    FakeTailscaleControl, RemoteAccessState, ServeMapping, ServeState, TailscaleControl,
    TailscaleDaemon, TailscaleError,
};
use lattice_service::{AppState, app_with_remote_access};
use lattice_store::{
    AuditCategory, AuditFilter, AuditLog, AuditPage, M2StateRepository, connect_memory,
};
use sqlx::SqlitePool;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
const LOOPBACK_PORT: u16 = 58120;

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

/// Adjustable deterministic clock for expiry/step-up/rate-limit tests.
#[derive(Debug)]
struct TestClock(Mutex<DateTime<Utc>>);

impl TestClock {
    fn starting_at(at: DateTime<Utc>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(at)))
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

fn epoch() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap()
}

struct Fixture {
    router: Router,
    state: AppState,
    pool: SqlitePool,
    clock: Arc<TestClock>,
    tailscale: Arc<FakeTailscaleControl>,
    remote: RemoteAccessState,
}

async fn fixture() -> Fixture {
    fixture_at(epoch()).await
}

async fn fixture_at(start: DateTime<Utc>) -> Fixture {
    let clock = TestClock::starting_at(start);
    let pool = connect_memory().await.unwrap();
    fixture_on(pool, clock).await
}

/// A service instance over an existing database: a second call with the same
/// pool is a "restarted" service (fresh in-memory state, same durable state).
async fn fixture_on(pool: SqlitePool, clock: Arc<TestClock>) -> Fixture {
    let state = AppState::new(TOKEN, M2StateRepository::new(pool.clone())).unwrap();
    let tailscale = Arc::new(FakeTailscaleControl::new());
    let remote = RemoteAccessState::with_parts(
        &state,
        Arc::clone(&tailscale) as Arc<dyn TailscaleControl>,
        clock.clone(),
        LOOPBACK_PORT,
    );
    Fixture {
        router: app_with_remote_access(state.clone(), remote.clone()),
        state,
        pool,
        clock,
        tailscale,
        remote,
    }
}

#[derive(Clone)]
enum Auth {
    None,
    Owner,
    Phone(String, String),
}

async fn send_with_headers(
    router: &Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
    auth: &Auth,
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mut request = Request::builder().method(method).uri(uri);
    match auth {
        Auth::None => {}
        Auth::Owner => {
            request = request.header("authorization", format!("Bearer {TOKEN}"));
        }
        Auth::Phone(id, secret) => {
            request = request.header("authorization", format!("PhoneSession {id}:{secret}"));
        }
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
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

async fn send(
    router: &Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
    auth: &Auth,
) -> axum::response::Response {
    send_with_headers(router, method, uri, body, auth, &[]).await
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn approval_audit_rows(pool: &SqlitePool) -> Vec<lattice_store::AppendedEntry> {
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
}

/// Pairs a phone and returns its (session_id, secret).
async fn pair(fixture: &Fixture, label: &str, pin: &str) -> (String, String) {
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/remote/pair",
        Some(serde_json::json!({ "device_label": label, "pin": pin })),
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    (
        body["session_id"].as_str().unwrap().to_owned(),
        body["secret"].as_str().unwrap().to_owned(),
    )
}

async fn stepup(fixture: &Fixture, auth: &Auth, pin: &str) -> axum::response::Response {
    send(
        &fixture.router,
        "POST",
        "/api/v1/remote/stepup",
        Some(serde_json::json!({ "pin": pin })),
        auth,
    )
    .await
}

fn empty_plan_save(expected_version: u32) -> serde_json::Value {
    serde_json::json!({
        "expected_version": expected_version,
        "plan": {
            "home_id": "018f47a0-9b5c-7a22-8a33-112233445566",
            "version": 0,
            "name": "Home",
            "floors": []
        }
    })
}

// ---------------------------------------------------------------------------
// Authentication of the remote management routes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn remote_management_routes_reject_unauthenticated_requests() {
    let fixture = fixture().await;
    for (method, uri, body) in [
        ("POST", "/api/v1/remote/serve", None),
        ("GET", "/api/v1/remote/status", None),
        (
            "POST",
            "/api/v1/remote/pair",
            Some(serde_json::json!({ "device_label": "phone", "pin": "123456" })),
        ),
        ("GET", "/api/v1/remote/sessions", None),
        (
            "DELETE",
            "/api/v1/remote/sessions/018f47a0-9b5c-7a22-8a33-112233445566",
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
    // Step-up is phone-principal-only: without a phone session it is refused
    // even with the owner bearer.
    let response = stepup(&fixture, &Auth::None, "123456").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = stepup(&fixture, &Auth::Owner, "123456").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// T1: Serve configuration.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn configure_serve_applies_the_loopback_mapping_idempotently_and_audits() {
    let fixture = fixture().await;
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/remote/serve",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["configured"], true);
    assert_eq!(body["changed"], true);
    assert_eq!(body["https_port"], 443);
    assert_eq!(body["target"], format!("http://127.0.0.1:{LOOPBACK_PORT}"));
    assert_eq!(body["dns_name"], "neonhearth.tailnet.ts.net");
    assert_eq!(
        fixture.tailscale.applied(),
        vec![ServeMapping {
            https_port: 443,
            target: format!("http://127.0.0.1:{LOOPBACK_PORT}"),
        }]
    );

    // Idempotent: the second call changes nothing and applies nothing new.
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/remote/serve",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["changed"], false);
    assert_eq!(fixture.tailscale.applied().len(), 1);

    let rows = approval_audit_rows(&fixture.pool).await;
    let actions: Vec<_> = rows.iter().map(|row| row.action.as_str()).collect();
    assert_eq!(
        actions,
        ["tailscale_serve_configured", "tailscale_serve_configured"]
    );
    assert_eq!(rows[0].detail["changed"], true);
    assert_eq!(rows[1].detail["changed"], false);

    // Status reflects the configured mapping.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/remote/status",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let status = json_body(response).await;
    assert_eq!(status["serve_configured"], true);
    assert_eq!(status["funnel_conflict"], false);
    assert_eq!(status["loopback_port"], LOOPBACK_PORT);
    assert_eq!(status["daemon"]["running"], true);
}

#[tokio::test]
async fn serve_reports_daemon_unavailable_and_unconfigured_binary_as_503() {
    let fixture = fixture().await;
    fixture.tailscale.set_daemon(Ok(TailscaleDaemon {
        running: false,
        backend_state: "Stopped".to_owned(),
        dns_name: None,
    }));
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/remote/serve",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(fixture.tailscale.applied().is_empty());

    fixture
        .tailscale
        .set_daemon(Err(TailscaleError::NotConfigured));
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/remote/serve",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Status stays 200 and reports the daemon error honestly.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/remote/status",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let status = json_body(response).await;
    assert!(status["daemon"].is_null());
    assert!(
        status["daemon_error"]
            .as_str()
            .unwrap()
            .contains("not configured")
    );
}

// ---------------------------------------------------------------------------
// T2: Funnel refusal.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn serve_refuses_when_funnel_is_enabled_for_the_port_and_reports_it() {
    let fixture = fixture().await;
    fixture.tailscale.enable_funnel(443);
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/remote/serve",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = json_body(response).await;
    assert!(body["error"].as_str().unwrap().contains("funnel"));
    // Nothing was applied: the refusal happened before any configuration.
    assert!(fixture.tailscale.applied().is_empty());

    let rows = approval_audit_rows(&fixture.pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "tailscale_serve_refused_funnel");

    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/remote/status",
        None,
        &Auth::Owner,
    )
    .await;
    let status = json_body(response).await;
    assert_eq!(status["funnel_conflict"], true);
    assert_eq!(status["serve_configured"], false);
}

#[tokio::test]
async fn serve_refuses_when_funnel_exposes_the_loopback_target_on_another_port() {
    let fixture = fixture().await;
    fixture.tailscale.set_serve(Ok(ServeState {
        mappings: vec![ServeMapping {
            https_port: 8443,
            target: format!("http://127.0.0.1:{LOOPBACK_PORT}"),
        }],
        funnel_ports: vec![8443],
    }));
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/remote/serve",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(fixture.tailscale.applied().is_empty());
}

// ---------------------------------------------------------------------------
// T2: forwarded-identity headers are stripped and never authorize.
// ---------------------------------------------------------------------------

const SPOOFED_HEADERS: &[(&str, &str)] = &[
    ("tailscale-user-login", "owner@example.com"),
    ("tailscale-user-name", "Owner"),
    ("x-forwarded-for", "100.64.0.7"),
    ("x-forwarded-proto", "https"),
    ("x-forwarded-host", "neonhearth.tailnet.ts.net"),
];

#[tokio::test]
async fn forwarded_identity_headers_gain_nothing() {
    let fixture = fixture().await;
    // Unauthenticated requests carrying tailnet identity headers stay 401 on
    // reads and stepped-up-only routes alike: header identity never
    // authorizes anything.
    for (method, uri) in [
        ("GET", "/api/v1/state"),
        ("GET", "/api/v1/home"),
        ("POST", "/api/v1/doctor/run"),
        ("GET", "/api/v1/remote/status"),
    ] {
        let response = send_with_headers(
            &fixture.router,
            method,
            uri,
            None,
            &Auth::None,
            SPOOFED_HEADERS,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
    }
}

#[tokio::test]
async fn forwarded_identity_headers_lose_nothing_legitimate() {
    let fixture = fixture().await;
    // A legitimate owner request carrying the same headers succeeds.
    let response = send_with_headers(
        &fixture.router,
        "GET",
        "/api/v1/state",
        None,
        &Auth::Owner,
        SPOOFED_HEADERS,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // A legitimate phone request carrying them succeeds on reads and stays
    // step-up-gated on high-impact routes (headers change neither outcome).
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);
    let response = send_with_headers(
        &fixture.router,
        "GET",
        "/api/v1/state",
        None,
        &phone,
        SPOOFED_HEADERS,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send_with_headers(
        &fixture.router,
        "POST",
        "/api/v1/policy/action",
        Some(serde_json::json!({
            "device_id": "018f0000-0000-7000-8000-00000000abcd",
            "action": "approve"
        })),
        &phone,
        SPOOFED_HEADERS,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// T3: pairing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pairing_mints_a_session_with_a_one_time_secret_and_audits() {
    let fixture = fixture().await;
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/remote/pair",
        Some(serde_json::json!({ "device_label": "pixel-9", "pin": "123456" })),
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let secret = body["secret"].as_str().unwrap();
    assert_eq!(secret.len(), 64);
    assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
    let expires_at: DateTime<Utc> = body["expires_at"].as_str().unwrap().parse().unwrap();
    assert_eq!(expires_at, epoch() + Duration::days(30));

    // Only the SHA-256 of the secret is stored, and no PIN text anywhere.
    let (secret_hash, pin_hash): (String, String) =
        sqlx::query_as("SELECT secret_hash, pin_hash FROM phone_sessions")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_ne!(secret_hash, *secret);
    assert!(pin_hash.starts_with("$argon2id$"));
    assert!(!pin_hash.contains("123456"));

    // The session list serves labels and timestamps, never secrets.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/remote/sessions",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let list = json_body(response).await;
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["device_label"], "pixel-9");
    assert_eq!(items[0]["revoked"], false);
    assert!(!list.to_string().contains(secret));

    let rows = approval_audit_rows(&fixture.pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "phone_session_paired");
    assert_eq!(
        rows[0].subject.as_deref(),
        Some(body["session_id"].as_str().unwrap())
    );
    assert!(!rows[0].detail.to_string().contains(secret));
}

#[tokio::test]
async fn pairing_rejects_bad_labels_and_bad_pins() {
    let fixture = fixture().await;
    for body in [
        serde_json::json!({ "device_label": "phone", "pin": "12345" }),
        serde_json::json!({ "device_label": "phone", "pin": "1234567" }),
        serde_json::json!({ "device_label": "phone", "pin": "12345a" }),
        serde_json::json!({ "device_label": "", "pin": "123456" }),
        serde_json::json!({ "device_label": "phone" }),
        serde_json::json!({ "device_label": "phone", "pin": "123456", "extra": 1 }),
    ] {
        let response = send(
            &fixture.router,
            "POST",
            "/api/v1/remote/pair",
            Some(body.clone()),
            &Auth::Owner,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }
}

// ---------------------------------------------------------------------------
// T3: phone principal route matrix.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn phone_sessions_read_but_never_touch_owner_only_or_unsteppedup_high_impact_routes() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);

    // Reads succeed with the session alone.
    for uri in ["/api/v1/state", "/api/v1/home", "/api/v1/cameras"] {
        let response = send(&fixture.router, "GET", uri, None, &phone).await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
    }
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/doctor/report",
        None,
        &phone,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/events/ticket",
        None,
        &phone,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // High-impact routes are 403 without a live step-up grace.
    for (method, uri, body) in [
        (
            "POST",
            "/api/v1/policy/action",
            Some(serde_json::json!({
                "device_id": "018f0000-0000-7000-8000-00000000abcd",
                "action": "approve"
            })),
        ),
        ("POST", "/api/v1/doctor/run", None),
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
        ("PUT", "/api/v1/home/plan", Some(empty_plan_save(0))),
        (
            "PUT",
            "/api/v1/home/placements/018f0000-0000-7000-8000-00000000abcd",
            Some(serde_json::json!({
                "floor_id": "018f47a0-9b5c-7a22-8a33-112233445567",
                "x": 1.0,
                "y": 1.0
            })),
        ),
        ("PUT", "/api/v1/home/draft", Some(serde_json::json!({}))),
        ("DELETE", "/api/v1/home/draft", None),
    ] {
        let response = send(&fixture.router, method, uri, body, &phone).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
    }

    // Owner-only surfaces are always refused for phones, step-up or not.
    let granted = stepup(&fixture, &phone, "123456").await;
    assert_eq!(granted.status(), StatusCode::OK);
    for (method, uri, body) in [
        (
            "POST",
            "/api/v1/remote/pair",
            Some(serde_json::json!({ "device_label": "other", "pin": "123456" })),
        ),
        ("GET", "/api/v1/remote/sessions", None),
        (
            "DELETE",
            "/api/v1/remote/sessions/018f47a0-9b5c-7a22-8a33-112233445566",
            None,
        ),
        ("POST", "/api/v1/remote/serve", None),
        (
            "POST",
            "/api/v1/integrations/tokens",
            Some(serde_json::json!({ "name": "x", "scopes": ["devices:read"] })),
        ),
        ("GET", "/api/v1/integrations/tokens", None),
        (
            "POST",
            "/api/v1/cameras/018f0000-0000-7000-8000-00000000abcd/sessions",
            Some(serde_json::json!({ "stream_id": "018f0000-0000-7000-8000-00000000abce" })),
        ),
        (
            "GET",
            "/api/v1/cameras/018f0000-0000-7000-8000-00000000abcd/snapshot",
            None,
        ),
    ] {
        let response = send(&fixture.router, method, uri, body, &phone).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
    }

    // The integrations read surface accepts only integration tokens.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/integrations/v1/devices",
        None,
        &phone,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_revoked_or_expired_phone_credentials_are_rejected() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;

    // Wrong secret, unknown session, malformed credentials: 401.
    let wrong = Auth::Phone(id.clone(), "0".repeat(64));
    let response = send(&fixture.router, "GET", "/api/v1/state", None, &wrong).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let unknown = Auth::Phone(
        "018f47a0-9b5c-7a22-8a33-112233445599".to_owned(),
        secret.clone(),
    );
    let response = send(&fixture.router, "GET", "/api/v1/state", None, &unknown).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = send_with_headers(
        &fixture.router,
        "GET",
        "/api/v1/state",
        None,
        &Auth::None,
        &[("authorization", "PhoneSession malformed")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The real credentials work, and expiry slides with use: 29 days later
    // the session still authenticates, twice over.
    let phone = Auth::Phone(id.clone(), secret.clone());
    for _ in 0..2 {
        fixture.clock.advance(Duration::days(29));
        let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    // 31 unused days later the session has expired.
    fixture.clock.advance(Duration::days(31));
    let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn owner_revocation_cuts_off_a_live_phone_session_and_audits() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id.clone(), secret);
    let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = send(
        &fixture.router,
        "DELETE",
        &format!("/api/v1/remote/sessions/{id}"),
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Unknown session: 404.
    let response = send(
        &fixture.router,
        "DELETE",
        "/api/v1/remote/sessions/018f47a0-9b5c-7a22-8a33-112233445599",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let rows = approval_audit_rows(&fixture.pool).await;
    let actions: Vec<_> = rows.iter().map(|row| row.action.as_str()).collect();
    assert_eq!(actions, ["phone_session_paired", "phone_session_revoked"]);
}

// ---------------------------------------------------------------------------
// T3: step-up.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stepup_grants_a_five_minute_grace_for_high_impact_routes() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);

    // Without step-up: 403 on a plan write.
    let response = send(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // A wrong PIN does not grant, and is audited.
    let response = stepup(&fixture, &phone, "654321").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // The correct PIN grants a 5-minute grace.
    let response = stepup(&fixture, &phone, "123456").await;
    assert_eq!(response.status(), StatusCode::OK);
    let grant = json_body(response).await;
    let expires_at: DateTime<Utc> = grant["expires_at"].as_str().unwrap().parse().unwrap();
    assert_eq!(expires_at, fixture.clock.now() + Duration::minutes(5));

    let response = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
        &[("x-command-id", "018f47a0-9b5c-7a22-8a33-1122334455a0")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["version"], 1);

    // After the grace expires the same route is 403 again; reads still work.
    fixture.clock.advance(Duration::minutes(6));
    let response = send(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(1)),
        &phone,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = send(&fixture.router, "GET", "/api/v1/home", None, &phone).await;
    assert_eq!(response.status(), StatusCode::OK);

    // The owner bearer never needs step-up.
    let response = send(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(1)),
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let rows = approval_audit_rows(&fixture.pool).await;
    let actions: Vec<_> = rows.iter().map(|row| row.action.as_str()).collect();
    assert_eq!(
        actions,
        ["phone_session_paired", "stepup_failed", "stepup_granted"]
    );
    assert_eq!(rows[1].detail["failures_in_window"], 1);
    assert_eq!(rows[1].detail["locked"], false);
}

#[tokio::test]
async fn five_pin_failures_in_a_window_lock_the_session_and_audit() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);

    for attempt in 1..=4 {
        let response = stepup(&fixture, &phone, "000000").await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "attempt {attempt}"
        );
    }
    // The fifth failure locks.
    let response = stepup(&fixture, &phone, "000000").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // While locked, even the correct PIN is refused without verification.
    let response = stepup(&fixture, &phone, "123456").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    let rows = approval_audit_rows(&fixture.pool).await;
    let failures: Vec<_> = rows
        .iter()
        .filter(|row| row.action == "stepup_failed")
        .collect();
    assert_eq!(failures.len(), 5);
    assert_eq!(failures[4].detail["locked"], true);
    assert_eq!(failures[4].detail["failures_in_window"], 5);

    // After the lock expires the correct PIN works again.
    fixture.clock.advance(Duration::minutes(16));
    let response = stepup(&fixture, &phone, "123456").await;
    assert_eq!(response.status(), StatusCode::OK);

    // Reads were never blocked by the PIN lock.
    let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
    assert_eq!(response.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// T4: command replay dedup.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_replayed_command_id_returns_the_original_result_without_reexecuting() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);
    assert_eq!(
        stepup(&fixture, &phone, "123456").await.status(),
        StatusCode::OK
    );

    let command_id = "018f47a0-9b5c-7a22-8a33-1122334455aa";
    let first = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
        &[("x-command-id", command_id)],
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    assert!(first.headers().get("x-command-replayed").is_none());
    assert_eq!(json_body(first).await["version"], 1);

    // The identical double-send returns the stored result. A re-execution
    // would 409 (expected_version 0 vs stored 1) — it must not.
    let replay = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
        &[("x-command-id", command_id)],
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.headers().get("x-command-replayed").unwrap(), "true");
    assert_eq!(json_body(replay).await["version"], 1);

    // A fresh command id executes for real — and now conflicts, proving the
    // replay above did not re-execute.
    let fresh = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
        &[("x-command-id", "018f47a0-9b5c-7a22-8a33-1122334455ab")],
    )
    .await;
    assert_eq!(fresh.status(), StatusCode::CONFLICT);

    // A malformed command id is refused outright.
    let malformed = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(1)),
        &phone,
        &[("x-command-id", "not-a-uuid")],
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn command_ids_are_scoped_per_session() {
    let fixture = fixture().await;
    let (id_a, secret_a) = pair(&fixture, "phone-a", "123456").await;
    let (id_b, secret_b) = pair(&fixture, "phone-b", "222333").await;
    let phone_a = Auth::Phone(id_a, secret_a);
    let phone_b = Auth::Phone(id_b, secret_b);
    assert_eq!(
        stepup(&fixture, &phone_a, "123456").await.status(),
        StatusCode::OK
    );
    assert_eq!(
        stepup(&fixture, &phone_b, "222333").await.status(),
        StatusCode::OK
    );

    let command_id = "018f47a0-9b5c-7a22-8a33-1122334455aa";
    let first = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone_a,
        &[("x-command-id", command_id)],
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    // The same command id from a different session is NOT a replay: it
    // executes for real (and conflicts, because the plan already advanced).
    let other = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone_b,
        &[("x-command-id", command_id)],
    )
    .await;
    assert_eq!(other.status(), StatusCode::CONFLICT);
    assert!(other.headers().get("x-command-replayed").is_none());
}

// ---------------------------------------------------------------------------
// T4: WebSocket reconnect resumes by sequence and re-delivers nothing.
// ---------------------------------------------------------------------------

fn payload() -> lattice_domain::EventPayload {
    lattice_domain::EventPayload::ServiceStatus(lattice_domain::ServiceStatus {
        state: "ready".to_owned(),
        detail: "test".to_owned(),
    })
}

#[tokio::test]
async fn websocket_reconnect_with_resume_redelivers_and_reexecutes_nothing() {
    let fixture = fixture().await;
    let state = fixture.state.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = fixture.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let ws_base = format!("ws://{address}/api/v1/events");

    state.events().publish(Utc::now(), payload()).await;
    state.events().publish(Utc::now(), payload()).await;

    let ticket = |response: serde_json::Value| response["ticket"].as_str().unwrap().to_owned();
    let first_ticket = ticket(
        json_body(
            send(
                &fixture.router,
                "POST",
                "/api/v1/events/ticket",
                None,
                &Auth::Owner,
            )
            .await,
        )
        .await,
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "{ws_base}?ticket={first_ticket}&after_sequence=0"
    ))
    .await
    .unwrap();
    let mut received = Vec::new();
    for _ in 0..2 {
        let message = socket.next().await.unwrap().unwrap();
        let tokio_tungstenite::tungstenite::Message::Text(text) = message else {
            panic!("expected text event");
        };
        let event: serde_json::Value = serde_json::from_str(&text).unwrap();
        received.push(event["data"]["sequence"].as_u64().unwrap());
    }
    assert_eq!(received, [1, 2]);
    socket.close(None).await.unwrap();

    // Reconnect resuming after sequence 2: nothing is re-delivered; the next
    // message is the newly published sequence 3, exactly once.
    let second_ticket = ticket(
        json_body(
            send(
                &fixture.router,
                "POST",
                "/api/v1/events/ticket",
                None,
                &Auth::Owner,
            )
            .await,
        )
        .await,
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "{ws_base}?ticket={second_ticket}&after_sequence=2"
    ))
    .await
    .unwrap();
    state.events().publish(Utc::now(), payload()).await;
    let message = socket.next().await.unwrap().unwrap();
    let tokio_tungstenite::tungstenite::Message::Text(text) = message else {
        panic!("expected text event");
    };
    let event: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["type"], "event");
    assert_eq!(event["data"]["sequence"], 3);

    // The resumed stream carried events only — no command was executed by
    // reconnecting: the event bus sequence did not advance beyond the three
    // published events.
    assert_eq!(state.events().current_sequence().await, 3);
}

// ---------------------------------------------------------------------------
// OpenAPI registration.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openapi_documents_the_remote_routes() {
    let fixture = fixture().await;
    // The route map is served to principals only: once Serve is on, every
    // tailnet peer can reach this listener.
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/openapi.json",
        None,
        &Auth::None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
        ("/api/v1/remote/serve", "post"),
        ("/api/v1/remote/status", "get"),
        ("/api/v1/remote/pair", "post"),
        ("/api/v1/remote/sessions", "get"),
        ("/api/v1/remote/sessions/{id}", "delete"),
        ("/api/v1/remote/stepup", "post"),
    ] {
        assert!(
            doc["paths"][path][method].is_object(),
            "missing {method} {path}"
        );
    }
}

// ---------------------------------------------------------------------------
// Concurrency: the PIN budget and the replay window under parallel requests.
// ---------------------------------------------------------------------------

/// M-1: five wrong guesses in flight at once are five failures. A
/// read-modify-write counter would charge them as one and leave the
/// budget almost untouched.
#[tokio::test]
async fn concurrent_pin_failures_are_each_charged_against_the_budget() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);

    let (a, b, c, d, e) = tokio::join!(
        stepup(&fixture, &phone, "000000"),
        stepup(&fixture, &phone, "000000"),
        stepup(&fixture, &phone, "000000"),
        stepup(&fixture, &phone, "000000"),
        stepup(&fixture, &phone, "000000"),
    );
    let mut statuses: Vec<u16> = [&a, &b, &c, &d, &e]
        .iter()
        .map(|response| response.status().as_u16())
        .collect();
    statuses.sort_unstable();
    assert_eq!(statuses, [403, 403, 403, 403, 429]);

    // The session is locked: even the correct PIN is refused.
    let response = stepup(&fixture, &phone, "123456").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // Every failure was charged with a distinct running count.
    let rows = approval_audit_rows(&fixture.pool).await;
    let mut counts: Vec<u64> = rows
        .iter()
        .filter(|row| row.action == "stepup_failed")
        .map(|row| row.detail["failures_in_window"].as_u64().unwrap())
        .collect();
    counts.sort_unstable();
    assert_eq!(counts, [1, 2, 3, 4, 5]);
}

/// M-2: a duplicate that arrives while the first send is still executing
/// waits for it and replays the settled result; it never runs twice.
#[tokio::test]
async fn a_concurrent_duplicate_command_waits_and_replays_instead_of_executing() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);
    assert_eq!(
        stepup(&fixture, &phone, "123456").await.status(),
        StatusCode::OK
    );

    let headers = [("x-command-id", "018f47a0-9b5c-7a22-8a33-1122334455cc")];
    let save = || {
        send_with_headers(
            &fixture.router,
            "PUT",
            "/api/v1/home/plan",
            Some(empty_plan_save(0)),
            &phone,
            &headers,
        )
    };
    let (first, second) = tokio::join!(save(), save());
    // A second execution would 409 (expected_version 0 vs stored 1).
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    let replayed = [&first, &second]
        .iter()
        .filter(|response| response.headers().get("x-command-replayed").is_some())
        .count();
    assert_eq!(replayed, 1, "exactly one of the pair is a replay");
    assert_eq!(json_body(first).await["version"], 1);
    assert_eq!(json_body(second).await["version"], 1);
}

/// T4 hardening: a high-impact phone command without a replay id cannot be
/// made idempotent, so it is refused instead of silently run unprotected.
#[tokio::test]
async fn high_impact_phone_commands_must_carry_a_command_id() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);
    assert_eq!(
        stepup(&fixture, &phone, "123456").await.status(),
        StatusCode::OK
    );

    let response = send(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Nothing executed: the same save succeeds once it carries an id.
    let response = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
        &[("x-command-id", "018f47a0-9b5c-7a22-8a33-1122334455dd")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["version"], 1);

    // Reads and step-up itself never need one; the owner bearer never does.
    let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(1)),
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// The sliding expiry is written back once a minute, not on every read, so
/// phone polling does not turn into SQLite write traffic.
#[tokio::test]
async fn session_last_use_is_written_once_a_minute_not_per_request() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);
    async fn last_used(fixture: &Fixture) -> Option<DateTime<Utc>> {
        let response = send(
            &fixture.router,
            "GET",
            "/api/v1/remote/sessions",
            None,
            &Auth::Owner,
        )
        .await;
        json_body(response).await["items"][0]["last_used_at"]
            .as_str()
            .map(|value| value.parse::<DateTime<Utc>>().unwrap())
    }
    assert_eq!(last_used(&fixture).await, None);

    let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(last_used(&fixture).await, Some(epoch()));

    // Thirty seconds later a read authenticates without touching the row.
    fixture.clock.advance(Duration::seconds(30));
    let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(last_used(&fixture).await, Some(epoch()));

    // Past the minute the next read slides the window again.
    fixture.clock.advance(Duration::seconds(31));
    let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        last_used(&fixture).await,
        Some(epoch() + Duration::seconds(61))
    );

    // A denied route never costs a write either.
    fixture.clock.advance(Duration::minutes(5));
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/remote/sessions",
        None,
        &phone,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        last_used(&fixture).await,
        Some(epoch() + Duration::seconds(61))
    );
}

// ---------------------------------------------------------------------------
// Review fixes: PIN budget, replay durability, principals, session lifetime.
// ---------------------------------------------------------------------------

/// Review finding 1: the budget bounds the verifications performed, not just
/// their outcome. Before the fix every request that loaded the session before
/// the first failure committed was evaluated, so 60 racing guesses cost 60
/// Argon2 runs (and a correct one among them won).
#[tokio::test]
async fn sixty_concurrent_pin_guesses_verify_at_most_the_budget() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);

    let guesses = (0..60).map(|index| {
        // The correct PIN is deliberately last in line: it must not win
        // merely because it raced the lock.
        let pin = if index == 59 {
            "123456".to_owned()
        } else {
            format!("{:06}", index + 1)
        };
        let fixture = &fixture;
        let phone = &phone;
        async move { stepup(fixture, phone, &pin).await.status() }
    });
    let statuses = futures_util::future::join_all(guesses).await;
    assert_eq!(
        fixture.remote.pin_verifications(),
        5,
        "only the 5-attempt budget may ever be verified"
    );
    assert!(
        statuses
            .iter()
            .all(|status| { *status == StatusCode::FORBIDDEN || *status == StatusCode::TOO_MANY_REQUESTS })
    );
    assert!(!statuses.contains(&StatusCode::OK), "no guess may succeed");
}

/// A correct PIN arriving after the budget is spent is refused, and does not
/// even reach verification.
#[tokio::test]
async fn a_correct_pin_during_a_lock_is_refused_unverified() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);
    for _ in 0..5 {
        stepup(&fixture, &phone, "000000").await;
    }
    assert_eq!(fixture.remote.pin_verifications(), 5);
    let response = stepup(&fixture, &phone, "123456").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(fixture.remote.pin_verifications(), 5);
    // And no step-up grace exists: high-impact routes stay closed.
    let denied = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
        &[("x-command-id", "018f47a0-9b5c-7a22-8a33-1122334455aa")],
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

/// Review finding 6: a command that already ran is never re-executed by a
/// restarted service, and an id reused for a different request is a conflict.
#[tokio::test]
async fn replays_survive_a_restart_and_ids_bind_to_their_request() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);
    assert_eq!(
        stepup(&fixture, &phone, "123456").await.status(),
        StatusCode::OK
    );
    let command_id = "018f47a0-9b5c-7a22-8a33-1122334455aa";
    let first = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
        &[("x-command-id", command_id)],
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    // "Restart": a brand-new service over the same database.
    let restarted = fixture_on(fixture.pool.clone(), fixture.clock.clone()).await;
    let replay = send_with_headers(
        &restarted.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
        &[("x-command-id", command_id)],
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.headers().get("x-command-replayed").unwrap(), "true");
    assert_eq!(json_body(replay).await["version"], 1);

    // Same id, different body: refused, not replayed and not executed.
    let different = send_with_headers(
        &restarted.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(1)),
        &phone,
        &[("x-command-id", command_id)],
    )
    .await;
    assert_eq!(different.status(), StatusCode::CONFLICT);
    assert!(different.headers().get("x-command-replayed").is_none());
}

/// A command whose handler never completed (crash, timeout, client
/// disconnect) stays claimed: the retry is refused instead of running the
/// command a second time.
#[tokio::test]
async fn an_unfinished_command_is_never_executed_again() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id.clone(), secret);
    assert_eq!(
        stepup(&fixture, &phone, "123456").await.status(),
        StatusCode::OK
    );
    let command_id = "018f47a0-9b5c-7a22-8a33-1122334455cc";
    // The first attempt claimed the id and died before completing.
    let repo = lattice_store::RemoteAccessRepository::new(fixture.pool.clone());
    repo.claim_command(
        uuid::Uuid::parse_str(&id).unwrap(),
        uuid::Uuid::parse_str(command_id).unwrap(),
        &"0".repeat(64),
        epoch(),
    )
    .await
    .unwrap();
    let retry = send_with_headers(
        &fixture.router,
        "PUT",
        "/api/v1/home/plan",
        Some(empty_plan_save(0)),
        &phone,
        &[("x-command-id", command_id)],
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    // The plan was never saved by the retry.
    let home = send(&fixture.router, "GET", "/api/v1/home", None, &phone).await;
    assert_eq!(json_body(home).await["plan"]["version"], 0);
}

/// Review finding 5: phone-initiated audit rows are attributed to the phone.
#[tokio::test]
async fn phone_actions_are_audited_as_the_phone_session() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id.clone(), secret);
    stepup(&fixture, &phone, "000000").await;
    stepup(&fixture, &phone, "123456").await;
    let rows = approval_audit_rows(&fixture.pool).await;
    for action in ["stepup_failed", "stepup_granted"] {
        let row = rows.iter().find(|row| row.action == action).unwrap();
        assert_eq!(row.actor, lattice_store::AuditActor::Phone, "{action}");
        assert_eq!(row.detail["principal"]["phone_session"], id.as_str());
    }
    // Owner-driven rows stay attributed to the owner.
    let paired = rows
        .iter()
        .find(|row| row.action == "phone_session_paired")
        .unwrap();
    assert_eq!(paired.actor, lattice_store::AuditActor::Owner);
}

/// Review finding 10: sliding expiry stops at an absolute age.
#[tokio::test]
async fn a_session_dies_at_its_absolute_lifetime_however_often_it_is_used() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);
    for _ in 0..6 {
        fixture.clock.advance(Duration::days(29));
        let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    // Day 174 of 180 is alive and sliding; day 181 is past the cap even
    // though the last use was a week earlier.
    fixture.clock.advance(Duration::days(7));
    let response = send(&fixture.router, "GET", "/api/v1/state", None, &phone).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Review finding 4: tickets are quota'd per principal, so a phone session
/// cannot starve the owner.
#[tokio::test]
async fn a_phone_session_cannot_exhaust_the_owners_event_tickets() {
    let fixture = fixture().await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id, secret);
    let mut refused = false;
    for _ in 0..20 {
        let response = send(&fixture.router, "POST", "/api/v1/events/ticket", None, &phone).await;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            refused = true;
            break;
        }
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert!(refused, "the phone's own quota must run out");
    let owner = send(
        &fixture.router,
        "POST",
        "/api/v1/events/ticket",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(owner.status(), StatusCode::OK);
}

/// Review finding 3: revoking a session closes the socket it already holds.
#[tokio::test]
async fn revoking_a_phone_session_closes_its_live_event_socket() {
    use tokio_tungstenite::tungstenite::Message;
    let fixture = fixture_at(Utc::now()).await;
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id.clone(), secret);
    let ticket = json_body(send(&fixture.router, "POST", "/api/v1/events/ticket", None, &phone).await)
        .await["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = fixture.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{address}/api/v1/events?ticket={ticket}&after_sequence=0"
    ))
    .await
    .unwrap();

    let revoked = send(
        &fixture.router,
        "DELETE",
        &format!("/api/v1/remote/sessions/{id}"),
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return true,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .expect("the socket must close promptly after revocation");
    assert!(closed);
}

/// Review finding 3 (backstop): even with no revoke announcement, a socket
/// notices a dead session at its next storage re-check.
#[tokio::test]
async fn a_socket_rechecks_its_session_when_no_revocation_was_announced() {
    use tokio_tungstenite::tungstenite::Message;
    let fixture = fixture_at(Utc::now()).await;
    let state = fixture.state.clone().with_socket_limits(lattice_service::SocketLimits {
        session_recheck: std::time::Duration::from_millis(100),
        ..Default::default()
    });
    let remote = RemoteAccessState::with_parts(
        &state,
        Arc::clone(&fixture.tailscale) as Arc<dyn TailscaleControl>,
        fixture.clock.clone(),
        LOOPBACK_PORT,
    );
    let router = app_with_remote_access(state, remote);
    let (id, secret) = pair(&fixture, "pixel", "123456").await;
    let phone = Auth::Phone(id.clone(), secret);
    let ticket = json_body(send(&router, "POST", "/api/v1/events/ticket", None, &phone).await)
        .await["ticket"]
        .as_str()
        .unwrap()
        .to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{address}/api/v1/events?ticket={ticket}&after_sequence=0"
    ))
    .await
    .unwrap();
    // Revoke straight in storage: nothing is announced.
    lattice_store::RemoteAccessRepository::new(fixture.pool.clone())
        .revoke_phone_session(uuid::Uuid::parse_str(&id).unwrap())
        .await
        .unwrap();
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return true,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .expect("the periodic re-check must close the socket");
    assert!(closed);
}

/// Reports `funnel_conflict` for a Funnel on 8443 proxying to `target`.
async fn funnel_conflict_for(fixture: &Fixture, target: String) -> bool {
    fixture.tailscale.set_serve(Ok(ServeState {
        mappings: vec![ServeMapping {
            https_port: 8443,
            target,
        }],
        funnel_ports: vec![8443],
    }));
    let response = send(
        &fixture.router,
        "GET",
        "/api/v1/remote/status",
        None,
        &Auth::Owner,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await["funnel_conflict"]
        .as_bool()
        .unwrap()
}

/// Review finding 11: the status route reports a Funnel conflict however the
/// operator spelled the loopback target (`localhost` is the same listener as
/// `127.0.0.1`), and not for a different port.
#[tokio::test]
async fn status_reports_funnel_conflicts_whatever_the_loopback_spelling() {
    let fixture = fixture().await;
    for ours in [
        format!("http://127.0.0.1:{LOOPBACK_PORT}"),
        format!("http://localhost:{LOOPBACK_PORT}"),
        format!("localhost:{LOOPBACK_PORT}"),
        format!("http://[::1]:{LOOPBACK_PORT}"),
    ] {
        assert!(funnel_conflict_for(&fixture, ours.clone()).await, "{ours}");
    }
    assert!(
        !funnel_conflict_for(&fixture, format!("http://localhost:{}", LOOPBACK_PORT + 1)).await
    );
}
