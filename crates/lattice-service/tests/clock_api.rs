//! Owner path for a suspect policy clock: visible in `/api/v1/state`, cleared
//! only by an owner-only, audited acknowledgement.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use lattice_service::{AppState, app};
use lattice_store::{
    AuditCategory, AuditFilter, AuditLog, AuditPage, M2StateRepository, PolicyRepository,
    connect_memory,
};
use sqlx::SqlitePool;
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

async fn body(response: Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

/// A service whose last recorded heartbeat is 60 days ago, so the real current
/// time is a far-forward jump and the clock is suspect.
async fn suspect_fixture() -> (Router, SqlitePool) {
    let pool = connect_memory().await.unwrap();
    let state = AppState::new(TOKEN, M2StateRepository::new(pool.clone())).unwrap();
    let long_ago = Utc::now() - Duration::days(60);
    assert!(
        PolicyRepository::new(pool.clone())
            .record_clock_heartbeat(long_ago)
            .await
            .unwrap()
            .is_trusted()
    );
    (app(state), pool)
}

async fn clock_in_state(router: &Router) -> serde_json::Value {
    let response = router
        .clone()
        .oneshot(
            Request::get("/api/v1/state")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body(response).await["clock"].clone()
}

fn acknowledge(authorization: String) -> Request<Body> {
    Request::post("/api/v1/clock/acknowledge")
        .header("authorization", authorization)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn a_clock_jump_is_visible_and_the_owner_can_acknowledge_it() {
    let (router, pool) = suspect_fixture().await;
    let before = clock_in_state(&router).await;
    assert_eq!(before["status"], "suspect");
    assert!(before["detail"].as_str().is_some_and(|d| !d.is_empty()));

    let response = router
        .clone()
        .oneshot(acknowledge(format!("Bearer {TOKEN}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await["status"], "trusted");
    assert_eq!(clock_in_state(&router).await["status"], "trusted");
    assert_eq!(
        clock_in_state(&router).await["detail"],
        serde_json::Value::Null
    );

    let rows = AuditLog::new(pool)
        .list(
            &AuditFilter {
                category: Some(AuditCategory::Approval),
                ..Default::default()
            },
            AuditPage {
                after_id: None,
                limit: 16,
            },
        )
        .await
        .unwrap();
    assert!(
        rows.iter()
            .any(|row| row.action == "policy_clock_acknowledged")
    );
}

#[tokio::test]
async fn acknowledging_requires_the_owner_credential() {
    let (router, _pool) = suspect_fixture().await;
    let unauthenticated = router
        .clone()
        .oneshot(
            Request::post("/api/v1/clock/acknowledge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

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
    let pair = body(pair).await;
    let credential = format!(
        "PhoneSession {}:{}",
        pair["session_id"].as_str().unwrap(),
        pair["secret"].as_str().unwrap()
    );
    let phone = router
        .clone()
        .oneshot(acknowledge(credential))
        .await
        .unwrap();
    assert_eq!(phone.status(), StatusCode::FORBIDDEN);
    assert_eq!(clock_in_state(&router).await["status"], "suspect");
}

#[tokio::test]
async fn a_failed_audit_append_leaves_the_clock_suspect() {
    let (router, pool) = suspect_fixture().await;
    sqlx::query("DROP TABLE audit_log")
        .execute(&pool)
        .await
        .unwrap();
    let response = router
        .clone()
        .oneshot(acknowledge(format!("Bearer {TOKEN}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(clock_in_state(&router).await["status"], "suspect");
}
