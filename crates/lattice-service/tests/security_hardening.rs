//! Security-review regression tests: the Host allowlist and Funnel refusal,
//! event WebSocket resource limits, owner-token rotation, and a walk over
//! every registered route proving each has an explicit phone-session verdict.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use futures_util::{SinkExt, StreamExt};
use lattice_service::{AppState, SocketLimits, app, app_with_remote_access, tailscale};
use lattice_store::{M2StateRepository, connect_memory};
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

async fn state() -> AppState {
    AppState::new(
        TOKEN,
        M2StateRepository::new(connect_memory().await.unwrap()),
    )
    .unwrap()
}

async fn status(router: &Router, request: Request<Body>) -> StatusCode {
    router.clone().oneshot(request).await.unwrap().status()
}

fn health(headers: &[(&str, &str)]) -> Request<Body> {
    let mut request = Request::get("/api/v1/health");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(Body::empty()).unwrap()
}

// ---------------------------------------------------------------------------
// Host allowlist (DNS rebinding) and Funnel refusal.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn host_allowlist_accepts_only_names_the_owner_uses() {
    let state = state().await;
    state.set_bound_port(58121);
    let router = app(state);
    for host in [
        "127.0.0.1:58121",
        "localhost:58121",
        "[::1]:58121",
        // The Vite dev server and preview forward the browser's own Host.
        "localhost:5173",
        "127.0.0.1:4173",
    ] {
        assert_eq!(
            status(&router, health(&[("host", host)])).await,
            StatusCode::OK,
            "{host}"
        );
    }
    // Requests with no Host at all are not browsers and stay served.
    assert_eq!(status(&router, health(&[])).await, StatusCode::OK);
    for host in [
        "evil.example",
        "evil.example:58121",
        "127.0.0.1:58120",
        "localhost",
        "127.0.0.1.evil.example:58121",
    ] {
        assert_eq!(
            status(&router, health(&[("host", host)])).await,
            StatusCode::FORBIDDEN,
            "{host}"
        );
    }
}

/// A rebinding page controls both Host and Origin, so the same-origin check
/// alone passes it; the Host allowlist is what stops it.
#[tokio::test]
async fn dns_rebinding_with_a_matching_origin_is_refused() {
    let state = state().await;
    state.set_bound_port(58121);
    let router = app(state);
    let rebound = health(&[
        ("host", "attacker.example:58121"),
        ("origin", "http://attacker.example:58121"),
    ]);
    assert_eq!(status(&router, rebound).await, StatusCode::FORBIDDEN);
    // The legitimate dev-proxy shape (Host and Origin both the dev server).
    let dev = health(&[
        ("host", "localhost:5173"),
        ("origin", "http://localhost:5173"),
    ]);
    assert_eq!(status(&router, dev).await, StatusCode::OK);
}

#[tokio::test]
async fn the_tailnet_name_is_served_once_known_and_never_before() {
    let state = state().await;
    state.set_bound_port(58121);
    let control = Arc::new(tailscale::FakeTailscaleControl::new());
    let remote = tailscale::RemoteAccessState::with_parts(
        &state,
        control,
        Arc::new(lattice_doctor::SystemClock),
        58121,
    );
    let router = app_with_remote_access(state, remote.clone());
    let host = [("host", "neonhearth.tailnet.ts.net")];
    assert_eq!(status(&router, health(&host)).await, StatusCode::FORBIDDEN);
    remote.prime_host_policy().await;
    assert_eq!(status(&router, health(&host)).await, StatusCode::OK);
    assert_eq!(
        status(&router, health(&[("host", "other.tailnet.ts.net")])).await,
        StatusCode::FORBIDDEN
    );
}

/// UNVERIFIED against real Funnel traffic: the marker header name is taken
/// from Tailscale's documentation.
#[tokio::test]
async fn requests_carrying_the_funnel_marker_are_refused() {
    let router = app(state().await);
    let request = Request::get("/api/v1/state")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("tailscale-funnel-request", "?1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status(&router, request).await, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Event socket resource limits.
// ---------------------------------------------------------------------------

async fn ticket(router: &Router) -> String {
    let response = router
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
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["ticket"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("ws://{address}/api/v1/events")
}

type Client =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(
    router: &Router,
    base: &str,
) -> Result<Client, tokio_tungstenite::tungstenite::Error> {
    let ticket = ticket(router).await;
    tokio_tungstenite::connect_async(format!("{base}?ticket={ticket}&after_sequence=0"))
        .await
        .map(|(socket, _)| socket)
}

async fn closes_within(socket: &mut Client, seconds: u64) -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(seconds), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn the_socket_cap_refuses_the_next_connection_and_frees_on_close() {
    let router = app(state().await);
    let base = serve(router.clone()).await;
    let mut open = Vec::new();
    for _ in 0..32 {
        open.push(connect(&router, &base).await.expect("under the cap"));
    }
    let refused = connect(&router, &base).await;
    assert!(
        matches!(
            refused,
            Err(tokio_tungstenite::tungstenite::Error::Http(ref response))
                if response.status() == StatusCode::TOO_MANY_REQUESTS
        ),
        "the 33rd socket must be refused with 429"
    );
    let mut first = open.remove(0);
    first.close(None).await.unwrap();
    assert!(closes_within(&mut first, 5).await);
    // The permit is released once the server task ends.
    let mut admitted = false;
    for _ in 0..50 {
        if connect(&router, &base).await.is_ok() {
            admitted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(admitted, "a closed socket must free its slot");
}

#[tokio::test]
async fn an_idle_client_that_never_answers_pings_is_closed() {
    let state = state().await.with_socket_limits(SocketLimits {
        ping_interval: std::time::Duration::from_millis(50),
        idle_timeout: std::time::Duration::from_millis(300),
        ..SocketLimits::default()
    });
    let router = app(state);
    let base = serve(router.clone()).await;
    let mut socket = connect(&router, &base).await.unwrap();
    // The client does not read (so tungstenite never auto-answers a ping)
    // for longer than the idle timeout.
    tokio::time::sleep(std::time::Duration::from_millis(900)).await;
    assert!(closes_within(&mut socket, 5).await);
}

#[tokio::test]
async fn a_socket_is_closed_at_its_maximum_lifetime() {
    let state = state().await.with_socket_limits(SocketLimits {
        max_lifetime: std::time::Duration::from_millis(400),
        ..SocketLimits::default()
    });
    let router = app(state);
    let base = serve(router.clone()).await;
    let mut socket = connect(&router, &base).await.unwrap();
    assert!(closes_within(&mut socket, 5).await);
}

#[tokio::test]
async fn an_oversized_client_message_closes_the_socket() {
    let router = app(state().await);
    let base = serve(router.clone()).await;
    let mut socket = connect(&router, &base).await.unwrap();
    let _ = socket
        .send(Message::Binary(vec![0u8; 64 * 1024].into()))
        .await;
    assert!(closes_within(&mut socket, 5).await);
}

// ---------------------------------------------------------------------------
// Owner-token rotation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rotating_the_owner_token_replaces_it_and_is_owner_only() {
    let router = app(state().await);
    let rotate = |auth: String| {
        let router = router.clone();
        async move {
            router
                .oneshot(
                    Request::post("/api/v1/service/token/rotate")
                        .header("authorization", auth)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };
    assert_eq!(
        rotate("Bearer wrong".to_owned()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = rotate(format!("Bearer {TOKEN}")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let new = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(new.len(), 64);
    // The previous token is dead immediately; the new one works.
    assert_eq!(
        status(
            &router,
            Request::get("/api/v1/state")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap()
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(
            &router,
            Request::get("/api/v1/state")
                .header("authorization", format!("Bearer {new}"))
                .body(Body::empty())
                .unwrap()
        )
        .await,
        StatusCode::OK
    );
}

// ---------------------------------------------------------------------------
// Every registered route has an explicit phone-session verdict.
// ---------------------------------------------------------------------------

/// Route registrations are found by scanning these sources for
/// `.route("/api/v1/...")` (axum offers no way to enumerate a built router, so
/// this is a SOURCE SCAN, not a walk of the live router). Every file here
/// exists (`include_str!` fails the build otherwise); a route registered in a
/// file that is not listed would be missed, so add new route modules here.
const ROUTE_SOURCES: [&str; 10] = [
    include_str!("../src/lib.rs"),
    include_str!("../src/audit_api.rs"),
    include_str!("../src/automation/mod.rs"),
    include_str!("../src/device_labels.rs"),
    include_str!("../src/doctor.rs"),
    include_str!("../src/host_monitor/api.rs"),
    include_str!("../src/network_monitor/api.rs"),
    include_str!("../src/network_scan.rs"),
    include_str!("../src/network_scan/capture.rs"),
    include_str!("../src/home.rs"),
];

/// Every `/api/v1/...` path registered through `.route("...")` in the listed
/// sources (a literal first argument is required; computed paths are not seen).
fn registered_paths() -> std::collections::BTreeSet<String> {
    let mut paths = std::collections::BTreeSet::new();
    for source in ROUTE_SOURCES {
        let mut rest = source;
        while let Some(index) = rest.find(".route(") {
            rest = &rest[index + ".route(".len()..];
            let trimmed = rest.trim_start();
            if let Some(after) = trimmed.strip_prefix('"')
                && let Some(end) = after.find('"')
                && after[..end].starts_with("/api/v1/")
            {
                paths.insert(after[..end].to_owned());
            }
        }
    }
    paths
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    /// Allowed with a live session alone.
    Read,
    /// Allowed only inside a live PIN step-up.
    HighImpact,
    /// Owner bearer only: a phone session gets 403.
    Denied,
    /// Integration tokens only: a phone session gets 401.
    IntegrationOnly,
}

/// The reviewed phone-access table. A route that is not listed here is
/// `Denied`, so adding a route can never make it phone-accessible silently:
/// widening access means editing this table AND the service's allowlist.
fn expected(method: &str, path: &str) -> Verdict {
    use Verdict::{Denied, HighImpact, IntegrationOnly, Read};
    if path.starts_with("/api/v1/integrations/v1/") {
        return IntegrationOnly;
    }
    if path.starts_with("/api/v1/audit") {
        return HighImpact;
    }
    match (method, path) {
        (
            "GET",
            "/api/v1/health" | "/api/v1/state" | "/api/v1/cameras" | "/api/v1/openapi.json",
        )
        | ("GET", "/api/v1/cameras/{id}")
        | ("GET", "/api/v1/cameras/{id}/health" | "/api/v1/cameras/{id}/inventory")
        | ("GET", "/api/v1/devices/{device_id}/advisories")
        | ("GET", "/api/v1/home" | "/api/v1/home/draft")
        | ("GET", "/api/v1/doctor/report")
        | ("GET", "/api/v1/remote/status")
        | ("GET", "/api/v1/events")
        | ("POST", "/api/v1/remote/stepup" | "/api/v1/events/ticket") => Read,
        ("POST", "/api/v1/policy/action")
        | ("POST", "/api/v1/doctor/run" | "/api/v1/doctor/approvals" | "/api/v1/doctor/repair")
        | ("PUT", "/api/v1/home/plan")
        | ("PUT" | "DELETE", "/api/v1/home/placements/{device_id}")
        | ("PUT" | "DELETE", "/api/v1/home/draft") => HighImpact,
        _ => Denied,
    }
}

fn concrete(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let end = rest[start..].find('}').unwrap() + start;
        out.push_str(if rest[start..end].contains("segment") {
            "segment.ts"
        } else {
            "00000000-0000-0000-0000-000000000000"
        });
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Source scan plus the reviewed verdict table (`expected`), exercised against
/// the real router: for every scanned path and method the phone-session
/// outcome must match the table, and anything the table does not list must be
/// refused. It cannot enumerate routes the scan does not see.
///
/// Safe by construction: requests carry an invalid JSON body, so every
/// JSON-taking handler rejects before doing work, `doctor/run` is skipped, and
/// the remaining reachable handlers are reads or deletes of a nonexistent id.
#[tokio::test]
async fn every_scanned_route_has_an_explicit_phone_verdict() {
    let paths = registered_paths();
    assert!(
        paths.len() > 50,
        "route scan looks broken: found {} paths",
        paths.len()
    );
    let state = state().await;
    let router = app(state);

    // Pair a phone and open a step-up grace.
    let pair = router
        .clone()
        .oneshot(
            Request::post("/api/v1/remote/pair")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"device_label": "walk", "pin": "123456"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pair.status(), StatusCode::OK);
    let pair: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(pair.into_body(), 4096).await.unwrap())
            .unwrap();
    let credential = format!(
        "PhoneSession {}:{}",
        pair["session_id"].as_str().unwrap(),
        pair["secret"].as_str().unwrap()
    );
    let stepup = router
        .clone()
        .oneshot(
            Request::post("/api/v1/remote/stepup")
                .header("authorization", &credential)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"pin":"123456"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stepup.status(), StatusCode::OK);

    // Every table entry must name a real route (the table cannot drift).
    for (method, path) in [
        ("GET", "/api/v1/health"),
        ("GET", "/api/v1/cameras/{id}"),
        ("PUT", "/api/v1/home/plan"),
        ("POST", "/api/v1/doctor/repair"),
        ("POST", "/api/v1/events/ticket"),
    ] {
        assert!(paths.contains(path), "{method} {path} is not registered");
    }

    for path in &paths {
        for method in ["GET", "POST", "PUT", "DELETE"] {
            let verdict = expected(method, path);
            // A permitted POST /doctor/run would start a real network
            // diagnostic; its phone gating is covered by the step-up sweep
            // below and by the doctor tests.
            if verdict == Verdict::HighImpact && path.ends_with("/doctor/run") {
                continue;
            }
            let request = Request::builder()
                .method(method)
                .uri(concrete(path))
                .header("authorization", &credential)
                .header("content-type", "application/json")
                // Distinct command ids so replay never masks a verdict.
                .header("x-command-id", uuid::Uuid::new_v4().to_string());
            // Malformed JSON: a handler that reads a body rejects it before
            // doing any work.
            let response = router
                .clone()
                .oneshot(request.body(Body::from("{")).unwrap())
                .await
                .unwrap();
            let got = response.status();
            match verdict {
                Verdict::Denied => assert_eq!(
                    got,
                    StatusCode::FORBIDDEN,
                    "{method} {path} must be refused for a phone session"
                ),
                Verdict::IntegrationOnly => assert_eq!(
                    got,
                    StatusCode::UNAUTHORIZED,
                    "{method} {path} accepts integration tokens only"
                ),
                // The event socket answers 401 itself when no ticket is
                // supplied, so for it only "not refused by the phone
                // allowlist" can be asserted.
                Verdict::Read if path == "/api/v1/events" => assert_ne!(
                    got,
                    StatusCode::FORBIDDEN,
                    "{method} {path} must pass the phone allowlist"
                ),
                // (A handler may itself answer 403, e.g. a missing approval
                // token, so only 401 is asserted here.)
                Verdict::Read | Verdict::HighImpact => assert_ne!(
                    got,
                    StatusCode::UNAUTHORIZED,
                    "{method} {path} must authenticate a phone session"
                ),
            }
        }
    }

    // Without step-up, every high-impact route is closed to the same phone.
    let fresh = router
        .clone()
        .oneshot(
            Request::post("/api/v1/remote/pair")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"device_label": "no-stepup", "pin": "654321"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let fresh: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(fresh.into_body(), 4096).await.unwrap())
            .unwrap();
    let credential = format!(
        "PhoneSession {}:{}",
        fresh["session_id"].as_str().unwrap(),
        fresh["secret"].as_str().unwrap()
    );
    for path in &paths {
        for method in ["GET", "POST", "PUT", "DELETE"] {
            if expected(method, path) != Verdict::HighImpact {
                continue;
            }
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(concrete(path))
                        .header("authorization", &credential)
                        .header("x-command-id", uuid::Uuid::new_v4().to_string())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{method} {path} needs a live step-up"
            );
        }
    }
}
