use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use lattice_service::{AppState, app};
use lattice_store::{M2StateRepository, connect_memory};
use tower::ServiceExt;

const TOKEN: &str = "network-scan-owner-012345678901234567890123456789";
async fn fixture() -> (tempfile::TempDir, axum::Router) {
    let dir = tempfile::tempdir().unwrap();
    let pool = connect_memory().await.unwrap();
    let state = AppState::new(TOKEN, M2StateRepository::new(pool)).unwrap();
    (dir, app(state))
}
#[tokio::test]
async fn scan_api_requires_owner_and_rejects_unknown_scope_and_credentials() {
    let (_dir, app) = fixture().await;
    for path in [
        "/api/v1/network/scan",
        "/api/v1/network/capabilities",
        "/api/v1/network/capture",
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for body in [
        r#"{"port_mode":"custom","ports":[0]}"#,
        r#"{"device_ids":["11111111-1111-4111-8111-111111111111"]}"#,
        r#"{"protocols":["snmp"],"snmp":{"version":"v3","username":"owner"}}"#,
        r#"{"targets":["8.8.8.8"]}"#,
    ] {
        let request = Request::post("/api/v1/network/scan")
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
        ));
    }
}
#[tokio::test]
async fn lldp_import_preserves_capture_time_and_never_creates_a_device() {
    let (_dir, app) = fixture().await;
    let mut frame = vec![1, 0x80, 0xc2, 0, 0, 14, 2, 1, 2, 3, 4, 5, 0x88, 0xcc];
    for (kind, value) in [
        (1u16, b"\x07Fixture switch".as_slice()),
        (2, b"\x05Gi1".as_slice()),
        (3, b"\x00\x00".as_slice()),
        (5, b"Test switch".as_slice()),
    ] {
        frame.extend(((kind << 9) | value.len() as u16).to_be_bytes());
        frame.extend(value);
    }
    frame.extend([0, 0]);
    let mut pcap = vec![];
    pcap.extend(0xa1b2c3d4u32.to_le_bytes());
    pcap.extend(2u16.to_le_bytes());
    pcap.extend(4u16.to_le_bytes());
    for word in [
        0u32,
        0,
        65535,
        1,
        1700000000,
        0,
        frame.len() as u32,
        frame.len() as u32,
    ] {
        pcap.extend(word.to_le_bytes());
    }
    pcap.extend(frame);
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/network/capture")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/vnd.tcpdump.pcap")
                .body(Body::from(pcap))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(value["findings"][0]["status"], "withdrawn");
    assert!(value["findings"][0]["device_id"].is_null());
    assert_eq!(value["findings"][0]["facts"]["system_name"], "Test switch");
    assert!(
        value["findings"][0]["observed_at"]
            .as_str()
            .unwrap()
            .starts_with("2023-11-14")
    );
    let response = app
        .oneshot(
            Request::get("/api/v1/state")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(value["devices"].as_array().unwrap().len(), 0);
}
