use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use chrono::Utc;
use http_body_util::BodyExt;
use lattice_domain::{EventPayload, ServiceStatus};
use lattice_service::{AppState, app};
use tower::ServiceExt;
const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

async fn body(response: Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn health_is_public_and_reports_v1() {
    let response = app(AppState::new(TOKEN).expect("valid token"))
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
        let response = app(AppState::new(TOKEN).expect("valid token"))
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
    let response = app(AppState::new(TOKEN).expect("valid token"))
        .oneshot(duplicate)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        "Bearer"
    );
    let response = app(AppState::new(TOKEN).expect("valid token"))
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
        serde_json::json!({"sequence":0,"devices":[],"service_status":"ready"})
    );
}

#[tokio::test]
async fn snapshot_uses_current_event_watermark() {
    let state = AppState::new(TOKEN).expect("valid token");
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
async fn event_ticket_requires_bearer_and_is_a_uuid() {
    for authorization in [None, Some("Bearer wrong")] {
        let mut request = Request::post("/api/v1/events/ticket");
        if let Some(authorization) = authorization {
            request = request.header("authorization", authorization);
        }
        let response = app(AppState::new(TOKEN).expect("valid token"))
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let response = app(AppState::new(TOKEN).expect("valid token"))
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
async fn openapi_describes_public_and_protected_routes() {
    let response = app(AppState::new(TOKEN).expect("valid token"))
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

#[test]
fn service_token_configuration_is_validated() {
    for token in [
        "",
        " ",
        "short",
        " leading________________________________",
        "trailing________________________________ ",
        "ümlaut________________________________",
    ] {
        assert!(AppState::new(token).is_err());
    }
    assert!(AppState::new(TOKEN).is_ok());
}
