use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use lattice_service::{AppState, app};
use lattice_store::{M2StateRepository, connect_memory};
use tower::ServiceExt;
const TOKEN: &str = "host-monitor-test-owner-01234567890123456789";
#[tokio::test]
async fn host_information_and_controls_require_owner_and_bounded_requests() {
    let state = AppState::new(
        TOKEN,
        M2StateRepository::new(connect_memory().await.unwrap()),
    )
    .unwrap();
    let app = app(state);
    for path in ["snapshot", "history", "settings", "firewall"] {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/host/{path}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for query in [
        "minutes=0",
        "minutes=4294967295",
        "minutes=60&app_id=somewhere",
        "minutes=60&path=/etc/passwd",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/host/history?{query}"))
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let response=app.clone().oneshot(Request::post("/api/v1/host/firewall").header("authorization",format!("Bearer {TOKEN}")).header("content-type","application/json").body(Body::from(serde_json::json!({"app_id":"a".repeat(64),"direction":"outbound","blocked":true,"expected_blocked":false,"confirmed":true,"executable":"C:/Windows/System32/svchost.exe"}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let response = app
        .oneshot(
            Request::get("/api/v1/host/history?minutes=60")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
