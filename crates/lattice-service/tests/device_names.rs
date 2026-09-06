use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use lattice_service::{AppState, app};
use lattice_store::{AuditLog, ChainScope, M2StateRepository, connect_memory};
use tower::ServiceExt;
const TOKEN: &str = "device-name-owner-012345678901234567890123456789";
const ID: &str = "11111111-1111-4111-8111-111111111111";
fn request(body: serde_json::Value, authorized: bool) -> Request<Body> {
    let mut request = Request::put(format!("/api/v1/devices/{ID}/name"))
        .header("content-type", "application/json");
    if authorized {
        request = request.header("authorization", format!("Bearer {TOKEN}"));
    }
    request.body(Body::from(body.to_string())).unwrap()
}
#[tokio::test]
async fn confirmation_requires_owner_checks_stale_labels_and_preserves_policy() {
    let pool = connect_memory().await.unwrap();
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at) VALUES(?,?,?)")
        .bind(ID)
        .bind("2026-09-06T00:00:00Z")
        .bind("2026-09-06T00:00:00Z")
        .execute(&pool)
        .await
        .unwrap();
    let app = app(AppState::new(TOKEN, M2StateRepository::new(pool.clone())).unwrap());
    let body =
        serde_json::json!({"name":"Kitchen light","expected_name":null,"expected_confirmed":false});
    assert_eq!(
        app.clone()
            .oneshot(request(body.clone(), false))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = app
        .clone()
        .oneshot(request(body.clone(), true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(result["owner_name"], "Kitchen light");
    assert_eq!(result["owner_confirmed"], true);
    assert_eq!(
        app.clone()
            .oneshot(request(body, true))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let unknown = serde_json::json!({"name":"Another name","expected_name":"Kitchen light","expected_confirmed":true,"approve":true});
    assert_eq!(
        app.clone()
            .oneshot(request(unknown, true))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    for name in ["", "\nBad name", "\u{202e}spoofed", &"x".repeat(129)] {
        let response=app.clone().oneshot(request(serde_json::json!({"name":name,"expected_name":"Kitchen light","expected_confirmed":true}),true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action='device.name_confirmed'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(events, 1);
    let policies: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_policy")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(policies, 0);
    assert!(
        AuditLog::new(pool)
            .verify_chain(ChainScope::All)
            .await
            .is_ok()
    );
}
#[tokio::test]
async fn name_and_audit_rollback_together_when_the_audit_cannot_be_written() {
    let pool = connect_memory().await.unwrap();
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at) VALUES(?,?,?)")
        .bind(ID)
        .bind("2026-09-06T00:00:00Z")
        .bind("2026-09-06T00:00:00Z")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER deny_fixture_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'fixture failure'); END").execute(&pool).await.unwrap();
    let app = app(AppState::new(TOKEN, M2StateRepository::new(pool.clone())).unwrap());
    assert_eq!(app.oneshot(request(serde_json::json!({"name":"Kitchen light","expected_name":null,"expected_confirmed":false}),true)).await.unwrap().status(),StatusCode::SERVICE_UNAVAILABLE);
    let saved: Option<String> =
        sqlx::query_scalar("SELECT owner_name FROM devices WHERE device_id=?")
            .bind(ID)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(saved.is_none());
}
