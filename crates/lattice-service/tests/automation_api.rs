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
    task: tokio::task::JoinHandle<()>,
}
impl Drop for HaFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn ha_fixture() -> HaFixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let calls = Arc::new(Mutex::new(vec![]));
    let saved = calls.clone();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let calls = saved.clone();
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
                        "get_states" => current.clone(),
                        "get_services" => services(),
                        "call_service" => {
                            calls.lock().unwrap().push(request.clone());
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
    HaFixture { url, calls, task }
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
