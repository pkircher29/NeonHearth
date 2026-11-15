use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use lattice_service::{
    AppState, app,
    automation::ha::{allowed_address, project, validate_url},
};
use lattice_store::{M2StateRepository, connect_memory};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tower::ServiceExt;
const OWNER: &str = "owner-token-0123456789abcdefghijkl";
const SECRET: &str = "fixture-ha-credential-never-return-this";
const TIME: &str = "2026-09-06T10:00:00+00:00";

#[tokio::test]
async fn integration_contract_declares_owner_auth_and_write_only_credentials() {
    let (router, _) = setup().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/openapi.json")
                .header("authorization", format!("Bearer {OWNER}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let spec: Value = serde_json::from_slice(&bytes).unwrap();
    for (path, method) in [
        ("", "get"),
        ("/network", "get"),
        ("/connect", "post"),
        ("/disconnect", "post"),
        ("/permissions", "put"),
        ("/commands", "post"),
    ] {
        assert_eq!(
            spec["paths"][format!("/api/v1/automation{path}")][method]["security"][0],
            json!({"bearer_auth":[]})
        );
    }
    assert_eq!(
        spec["components"]["schemas"]["AutomationConnectRequest"]["properties"]["access_token"]["writeOnly"],
        true
    );
    assert!(
        spec["components"]["schemas"]["AutomationSnapshot"]["properties"]
            .get("access_token")
            .is_none()
    );
}

fn states() -> Value {
    json!([
        {"entity_id":"light.desk","state":"off","last_changed":TIME,"last_updated":TIME,"attributes":{"friendly_name":"Desk lamp","secret":SECRET}},
        {"entity_id":"light.everything","state":"off","last_changed":TIME,"last_updated":TIME,"attributes":{"entity_id":["light.desk"]}},
        {"entity_id":"lock.front","state":"locked","last_changed":TIME,"last_updated":TIME,"attributes":{"friendly_name":"Front lock"}}
    ])
}
fn areas() -> Value {
    json!([{"area_id":"office","name":"Office"}])
}
fn devices() -> Value {
    json!([{"id":"desk","name":"Desk lamp","manufacturer":"Test maker","model":"Fixture","area_id":"office","connections":[["mac","AA:BB:CC:DD:EE:FF"]],"configuration_url":"https://secret.invalid/token"}])
}
fn registry() -> Value {
    json!([{"entity_id":"light.desk","device_id":"desk","platform":"mqtt"},{"entity_id":"light.everything","platform":"group"}])
}
fn services() -> Value {
    json!({"light":{"turn_on":{},"turn_off":{}},"lock":{"unlock":{}}})
}
struct HaFixture {
    url: String,
    calls: Arc<Mutex<Vec<Value>>>,
    /// Permits released here let held `call_service` requests complete.
    gate: Arc<tokio::sync::Semaphore>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for HaFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn ha_fixture() -> HaFixture {
    ha_fixture_with(false, true, false).await
}
/// `hold_calls` makes every `call_service` wait for a permit on the fixture's
/// gate (no timing involved); `mutate` says whether the call changes the
/// entity (and so its `last_changed`); `huge_states` answers `get_states`
/// with a message over the adapter's size cap.
async fn ha_fixture_with(hold_calls: bool, mutate: bool, huge_states: bool) -> HaFixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let calls = Arc::new(Mutex::new(vec![]));
    let saved = calls.clone();
    let gate_outer = Arc::new(tokio::sync::Semaphore::new(0));
    let gate_saved = gate_outer.clone();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let calls = saved.clone();
            let gate = gate_saved.clone();
            tokio::spawn(async move {
                let mut socket = accept_async(stream).await.unwrap();
                socket
                    .send(Message::Text(
                        json!({"type":"auth_required"}).to_string().into(),
                    ))
                    .await
                    .unwrap();
                let auth = socket.next().await.unwrap().unwrap();
                let auth: Value = serde_json::from_str(auth.to_text().unwrap()).unwrap();
                let valid = auth["access_token"] == SECRET;
                socket
                    .send(Message::Text(
                        json!({"type":if valid {"auth_ok"} else {"auth_invalid"}})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
                if !valid {
                    return;
                }
                let mut current = states();
                let mut subscription = json!(0);
                while let Some(Ok(Message::Text(message))) = socket.next().await {
                    let request: Value = serde_json::from_str(&message).unwrap();
                    let result = match request["type"].as_str().unwrap() {
                        "subscribe_events" => {
                            subscription = request["id"].clone();
                            Value::Null
                        }
                        "config/area_registry/list" => areas(),
                        "config/device_registry/list" => devices(),
                        "config/entity_registry/list" => registry(),
                        "get_states" if huge_states => {
                            // One message past the adapter's 32 MiB cap.
                            json!([{"entity_id":"sensor.big","state":"1","last_changed":TIME,"last_updated":TIME,"attributes":{"blob":"a".repeat(33 * 1024 * 1024)}}])
                        }
                        "get_states" => current.clone(),
                        "get_services" => services(),
                        "call_service" => {
                            calls.lock().unwrap().push(request.clone());
                            if hold_calls {
                                gate.acquire().await.unwrap().forget();
                            }
                            if !mutate {
                                if socket
                                    .send(Message::Text(json!({"id":request["id"],"type":"result","success":true,"result":{"context":{"id":"fixture"}}}).to_string().into()))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                                continue;
                            }
                            current[0]["state"] = json!(if request["service"] == "turn_on" {
                                "on"
                            } else {
                                "off"
                            });
                            current[0]["last_changed"] = json!(Utc::now().to_rfc3339());
                            current[0]["last_updated"] = current[0]["last_changed"].clone();
                            let event = json!({"id":subscription,"type":"event","event":{"data":{"entity_id":"light.desk","new_state":current[0]}}});
                            if socket
                                .send(Message::Text(event.to_string().into()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            json!({"context":{"id":"fixture"}})
                        }
                        "ping" => {
                            if socket
                                .send(Message::Text(
                                    json!({"id":request["id"],"type":"pong"}).to_string().into(),
                                ))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            continue;
                        }
                        other => panic!("unexpected HA request {other}"),
                    };
                    if socket.send(Message::Text(json!({"id":request["id"],"type":"result","success":true,"result":result}).to_string().into())).await.is_err() { return; }
                }
            });
        }
    });
    HaFixture {
        url,
        calls,
        gate: gate_outer,
        task,
    }
}
async fn setup() -> (Router, AppState) {
    let state = AppState::new(
        OWNER,
        M2StateRepository::new(connect_memory().await.unwrap()),
    )
    .unwrap();
    (app(state.clone()), state)
}
async fn call(
    router: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("/api/v1/automation{path}"));
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}
async fn connect(router: &Router, state: &AppState, ha: &HaFixture) {
    assert_eq!(
        call(
            router,
            "POST",
            "/connect",
            Some(json!({"url":ha.url,"access_token":SECRET})),
            Some(OWNER)
        )
        .await
        .0,
        StatusCode::ACCEPTED
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if state.automation().snapshot().await.unwrap().status == "connected" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
fn command() -> Value {
    json!({"command_id":uuid::Uuid::new_v4(),"entity_id":"light.desk","action":"turn_on","expected_last_changed":TIME,"issued_at":Utc::now(),"confirmed":true})
}

#[test]
fn only_explicit_private_secure_destinations_and_safe_entities() {
    for url in [
        "http://192.168.1.2:8123",
        "http://localhost:8123",
        "https://user:secret@home.local",
        "https://home.local/other",
        "https://home.local/#token=secret",
        "file:///x",
    ] {
        assert!(validate_url(url).is_err(), "{url}");
    }
    assert_eq!(
        validate_url("https://homeassistant.local:8123")
            .unwrap()
            .as_str(),
        "wss://homeassistant.local:8123/api/websocket"
    );
    assert!(validate_url("http://127.0.0.1:8123").is_ok());
    for ip in [
        "8.8.8.8",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "::ffff:127.0.0.1",
        "fe80::1",
    ] {
        assert!(!allowed_address(ip.parse().unwrap()));
    }
    for ip in [
        "127.0.0.1",
        "192.168.1.2",
        "100.100.1.1",
        "fd7a:115c:a1e0::1",
    ] {
        assert!(allowed_address(ip.parse().unwrap()));
    }
    let (devices, names) =
        project(&areas(), &devices(), &registry(), &states(), &services()).unwrap();
    assert_eq!(names, vec!["Office"]);
    let lamp = devices.iter().find(|d| d.upstream_id == "desk").unwrap();
    assert_eq!(lamp.area.as_deref(), Some("Office"));
    assert!(lamp.entities[0].power_capable);
    assert!(
        devices
            .iter()
            .flat_map(|d| &d.entities)
            .filter(|e| e.entity_id != "light.desk")
            .all(|e| !e.power_capable)
    );
    let encoded = serde_json::to_string(&devices).unwrap();
    assert!(!encoded.contains(SECRET));
    assert!(!encoded.contains("configuration_url"));
    assert!(project(&areas(), &json!([]), &registry(), &json!({}), &services()).is_err());
}
#[tokio::test]
async fn every_route_rejects_unpaired_and_foreign_tokens() {
    let (router, _) = setup().await;
    for (method, path) in [
        ("GET", ""),
        ("GET", "/network"),
        ("POST", "/connect"),
        ("POST", "/disconnect"),
        ("PUT", "/permissions"),
        ("POST", "/commands"),
    ] {
        for token in [None, Some("scoped-read-token-0123456789abcdef")] {
            assert_eq!(
                call(&router, method, path, Some(json!({})), token).await.0,
                StatusCode::UNAUTHORIZED
            );
        }
    }
}
#[tokio::test]
async fn malicious_browser_origin_is_denied_even_with_bearer_and_security_headers_are_present() {
    let (router, _) = setup().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/automation")
                .header("authorization", format!("Bearer {OWNER}"))
                .header("host", "127.0.0.1:58120")
                .header("origin", "https://attacker.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
}
#[tokio::test]
async fn imports_live_inventory_controls_one_entity_and_never_replays() {
    let ha = ha_fixture().await;
    let (router, state) = setup().await;
    connect(&router, &state, &ha).await;
    let before = state.automation().snapshot().await.unwrap();
    assert_eq!(before.devices.len(), 3);
    assert!(!serde_json::to_string(&before).unwrap().contains(SECRET));
    assert_eq!(
        call(&router, "POST", "/commands", Some(command()), Some(OWNER))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &router,
            "PUT",
            "/permissions",
            Some(json!({"entity_ids":["light.everything"]})),
            Some(OWNER)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &router,
            "PUT",
            "/permissions",
            Some(json!({"entity_ids":["light.desk"]})),
            Some(OWNER)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let mut stale = command();
    stale["expected_last_changed"] = json!("old");
    assert_eq!(
        call(&router, "POST", "/commands", Some(stale), Some(OWNER))
            .await
            .0,
        StatusCode::CONFLICT
    );
    let request = command();
    let (status, receipt) = call(
        &router,
        "POST",
        "/commands",
        Some(request.clone()),
        Some(OWNER),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["status"], "accepted");
    assert_eq!(
        call(
            &router,
            "POST",
            "/commands",
            Some(request.clone()),
            Some(OWNER)
        )
        .await
        .0,
        StatusCode::OK
    );
    let mut conflict = request;
    conflict["action"] = json!("turn_off");
    assert_eq!(
        call(&router, "POST", "/commands", Some(conflict), Some(OWNER))
            .await
            .0,
        StatusCode::CONFLICT
    );
    let calls = ha.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["target"], json!({"entity_id":"light.desk"}));
    assert_eq!(calls[0]["domain"], "light");
    let after = state.automation().snapshot().await.unwrap();
    assert_eq!(
        after
            .devices
            .iter()
            .find(|d| d.upstream_id == "desk")
            .unwrap()
            .entities[0]
            .state,
        "on"
    );
    state.automation().disconnect().await.unwrap();
    assert!(
        state
            .automation()
            .snapshot()
            .await
            .unwrap()
            .devices
            .iter()
            .flat_map(|d| &d.entities)
            .all(|e| !e.control_enabled)
    );
    assert_eq!(
        call(&router, "POST", "/commands", Some(command()), Some(OWNER))
            .await
            .0,
        StatusCode::CONFLICT
    );
}
#[tokio::test]
async fn invalid_credentials_never_import_or_enable_controls() {
    let ha = ha_fixture().await;
    let (router, state) = setup().await;
    call(
        &router,
        "POST",
        "/connect",
        Some(json!({"url":ha.url,"access_token":"invalid-fixture-credential"})),
        Some(OWNER),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if state.automation().snapshot().await.unwrap().status == "authentication_failed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        state
            .automation()
            .snapshot()
            .await
            .unwrap()
            .devices
            .is_empty()
    );
    assert!(ha.calls.lock().unwrap().is_empty());
}

async fn setup_with_pool() -> (Router, AppState, sqlx::SqlitePool) {
    let pool = connect_memory().await.unwrap();
    let state = AppState::new(OWNER, M2StateRepository::new(pool.clone())).unwrap();
    (app(state.clone()), state, pool)
}

async fn break_audit(pool: &sqlx::SqlitePool) {
    sqlx::query(
        "CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn grant_desk(router: &Router) {
    assert_eq!(
        call(
            router,
            "PUT",
            "/permissions",
            Some(json!({"entity_ids":["light.desk"]})),
            Some(OWNER)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
}

async fn response_with_headers(
    router: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, bool) {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("/api/v1/automation{path}"))
        .header("authorization", format!("Bearer {OWNER}"));
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    (
        response.status(),
        response.headers().contains_key("x-audit-warning"),
    )
}

#[tokio::test]
async fn disconnect_takes_effect_even_when_the_audit_log_is_down() {
    let ha = ha_fixture().await;
    let (router, state, pool) = setup_with_pool().await;
    connect(&router, &state, &ha).await;
    grant_desk(&router).await;
    break_audit(&pool).await;
    let (status, warned) = response_with_headers(&router, "POST", "/disconnect", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        warned,
        "the unrecorded revocation is surfaced to the caller"
    );
    let snapshot = state.automation().snapshot().await.unwrap();
    assert_eq!(snapshot.status, "disconnected");
    assert!(
        snapshot
            .devices
            .iter()
            .flat_map(|d| &d.entities)
            .all(|e| !e.control_enabled)
    );
    assert_eq!(
        call(&router, "POST", "/commands", Some(command()), Some(OWNER))
            .await
            .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn clearing_permissions_takes_effect_but_granting_stays_audit_first() {
    let ha = ha_fixture().await;
    let (router, state, pool) = setup_with_pool().await;
    connect(&router, &state, &ha).await;
    grant_desk(&router).await;
    break_audit(&pool).await;
    // Narrowing to nothing is applied and audited best-effort.
    let (status, warned) = response_with_headers(
        &router,
        "PUT",
        "/permissions",
        Some(json!({"entity_ids":[]})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(warned);
    assert!(
        state
            .automation()
            .snapshot()
            .await
            .unwrap()
            .devices
            .iter()
            .flat_map(|d| &d.entities)
            .all(|e| !e.control_enabled)
    );
    // Granting authority is refused while it cannot be recorded.
    let (status, _) = response_with_headers(
        &router,
        "PUT",
        "/permissions",
        Some(json!({"entity_ids":["light.desk"]})),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        state
            .automation()
            .snapshot()
            .await
            .unwrap()
            .devices
            .iter()
            .flat_map(|d| &d.entities)
            .all(|e| !e.control_enabled)
    );
}

#[tokio::test]
async fn a_queued_command_whose_caller_gave_up_is_never_sent_to_home_assistant() {
    // Every call_service is held at HA until the gate is opened.
    let ha = ha_fixture_with(true, false, false).await;
    let (router, state) = setup().await;
    connect(&router, &state, &ha).await;
    grant_desk(&router).await;
    let hub = state.automation().clone();
    hub.set_command_timeout(Duration::from_millis(250));
    let first: lattice_service::automation::CommandRequest =
        serde_json::from_value(command()).unwrap();
    let second: lattice_service::automation::CommandRequest =
        serde_json::from_value(command()).unwrap();
    let first_hub = hub.clone();
    let first_task = tokio::spawn(async move { first_hub.command(first).await });
    // Wait until the first command is actually held at HA.
    tokio::time::timeout(Duration::from_secs(30), async {
        while ha.calls.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Queued behind the held command; its caller gives up.
    assert_eq!(
        hub.command(second).await.unwrap_err(),
        StatusCode::GATEWAY_TIMEOUT
    );
    assert_eq!(
        first_task.await.unwrap().unwrap_err(),
        StatusCode::GATEWAY_TIMEOUT
    );
    // Open the gate, then send a fresh command: it queues behind the abandoned
    // one, so once it completes the abandoned one has been handled (dropped).
    ha.gate.add_permits(16);
    hub.set_command_timeout(Duration::from_secs(60));
    let third: lattice_service::automation::CommandRequest =
        serde_json::from_value(command()).unwrap();
    hub.command(third).await.unwrap();
    assert_eq!(
        ha.calls.lock().unwrap().len(),
        2,
        "the abandoned command must not be sent after its caller was told it failed"
    );
}

#[tokio::test]
async fn a_slow_database_never_stalls_the_session_lock() {
    let (_, state, pool) = setup_with_pool().await;
    // Take every pooled connection so the stored-inventory read has to wait.
    let mut held = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        held.push(pool.acquire().await.unwrap());
    }
    let hub = state.automation().clone();
    let reader = tokio::spawn(async move { hub.snapshot().await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::timeout(
        // Generous: the failure mode is blocking until the pool is released.
        Duration::from_secs(20),
        state.automation().mqtt_status("connected", "probe"),
    )
    .await
    .expect("a snapshot waiting on the database must not hold the session lock");
    drop(held);
    reader.await.unwrap().unwrap();
}

fn many_states(count: usize) -> Value {
    let mut states: Vec<Value> = (0..count)
        .map(|index| {
            json!({"entity_id":format!("sensor.s{index}"),"state":"1","last_changed":TIME,"last_updated":TIME,"attributes":{}})
        })
        .collect();
    // The controllable entity sits past the cut.
    states.push(
        json!({"entity_id":"light.desk","state":"off","last_changed":TIME,"last_updated":TIME,"attributes":{"friendly_name":"Desk lamp"}}),
    );
    Value::Array(states)
}

#[test]
fn an_oversized_inventory_is_truncated_and_flagged_instead_of_rejected() {
    use lattice_service::automation::ha::project_bounded;
    let states = many_states(5000);
    // The legacy entry point no longer fails either.
    let (devices, _) = project(&areas(), &devices(), &registry(), &states, &services()).unwrap();
    assert!(devices.len() <= 4096);
    let projection = project_bounded(
        &areas(),
        &devices_value(),
        &registry(),
        &states,
        &services(),
    )
    .unwrap();
    assert!(projection.devices.len() <= 4096);
    let note = projection.truncated.expect("truncation is reported");
    assert!(note.contains("4096") && note.contains("5001"), "{note}");
    // Controllable entities survive the cut.
    assert!(
        projection
            .devices
            .iter()
            .flat_map(|d| &d.entities)
            .any(|e| e.entity_id == "light.desk" && e.power_capable)
    );
}

fn devices_value() -> Value {
    devices()
}

#[tokio::test]
async fn an_inventory_over_the_message_cap_stops_with_a_specific_status_and_no_retry_loop() {
    let ha = ha_fixture_with(false, true, true).await;
    let (router, state) = setup().await;
    assert_eq!(
        call(
            &router,
            "POST",
            "/connect",
            Some(json!({"url":ha.url,"access_token":SECRET})),
            Some(OWNER)
        )
        .await
        .0,
        StatusCode::ACCEPTED
    );
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if state.automation().snapshot().await.unwrap().status == "inventory_too_large" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the oversized inventory is reported, not retried as a generic failure");
    let snapshot = state.automation().snapshot().await.unwrap();
    assert!(snapshot.detail.contains("32 MiB"), "{}", snapshot.detail);
    assert!(
        snapshot
            .devices
            .iter()
            .flat_map(|d| &d.entities)
            .all(|e| !e.control_enabled)
    );
}

#[tokio::test]
async fn more_than_the_evidence_bound_no_longer_makes_the_network_endpoint_unavailable() {
    let (router, _, pool) = setup_with_pool().await;
    let mut tx = pool.begin().await.unwrap();
    for index in 0..4097_u32 {
        let device = format!("018f0000-0000-7000-8000-{index:012x}");
        let mac = format!("02:00:00:00:{:02x}:{:02x}", index >> 8, index & 0xff);
        sqlx::query(
            "INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_confirmed) VALUES(?,?,?,0)",
        )
        .bind(&device)
        .bind(TIME)
        .bind(TIME)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO evidence(device_id,family,source,fact_key,fact_value,confidence,observed_at) VALUES(?,'link_layer','test','mac',?,1.0,?)",
        )
        .bind(&device)
        .bind(&mac)
        .bind(TIME)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    let (status, body) = call(&router, "GET", "/network", None, Some(OWNER)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["devices"].as_array().unwrap().len(), 4096);
    assert_ne!(
        body["status"], "ready",
        "a cut answer is never reported as complete"
    );
}

#[tokio::test]
async fn rejected_request_bodies_get_the_problem_shape_and_their_own_status() {
    let (router, _) = setup().await;
    for (method, path) in [
        ("POST", "/connect"),
        ("PUT", "/permissions"),
        ("POST", "/commands"),
    ] {
        // Syntactically broken JSON.
        let request = Request::builder()
            .method(method)
            .uri(format!("/api/v1/automation{path}"))
            .header("authorization", format!("Bearer {OWNER}"))
            .header("content-type", "application/json")
            .body(Body::from("{not json"))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(body["error"].is_string(), "{path}: {body}");
        // Missing content type.
        let request = Request::builder()
            .method(method)
            .uri(format!("/api/v1/automation{path}"))
            .header("authorization", format!("Bearer {OWNER}"))
            .body(Body::from("{}"))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{path}"
        );
    }
}

#[tokio::test]
async fn connect_audits_without_holding_the_session_lock() {
    let ha = ha_fixture().await;
    let (_, state, pool) = setup_with_pool().await;
    let mut held = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        held.push(pool.acquire().await.unwrap());
    }
    let hub = state.automation().clone();
    let request: lattice_service::automation::ConnectRequest =
        serde_json::from_value(json!({"url":ha.url,"access_token":SECRET})).unwrap();
    let connecting = tokio::spawn(async move { hub.connect(request).await });
    // The connect audit is now waiting for a database connection.
    tokio::time::timeout(
        Duration::from_secs(20),
        state.automation().mqtt_status("connected", "probe"),
    )
    .await
    .expect("a connect waiting on the audit write must not hold the session lock");
    drop(held);
    connecting.await.unwrap().unwrap();
}
