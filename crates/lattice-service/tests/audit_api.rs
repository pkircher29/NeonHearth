//! History routes: newest-first paging, filters, cursor, and chain verification.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{TimeZone, Utc};
use http_body_util::BodyExt;
use lattice_service::AppState;
use lattice_store::{
    AuditActor, AuditCategory, AuditLog, M2StateRepository, NewAuditEntry, connect_memory,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "test-token-with-at-least-32-characters-ok";

async fn app_with_entries(count: u32) -> Router {
    let pool = connect_memory().await.unwrap();
    let log = AuditLog::new(pool.clone());
    for index in 0..count {
        let category = if index % 2 == 0 {
            AuditCategory::Approval
        } else {
            AuditCategory::DoctorAction
        };
        log.append(NewAuditEntry {
            occurred_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, index).unwrap(),
            actor: AuditActor::Owner,
            category,
            action: format!("test.action.{index}"),
            subject: Some(format!("subject-{index}")),
            detail: json!({ "index": index }),
        })
        .await
        .expect("append");
    }
    let state = AppState::new(TOKEN, M2StateRepository::new(pool)).unwrap();
    lattice_service::app(state)
}

async fn get_json(app: &Router, uri: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

fn ids(page: &Value) -> Vec<i64> {
    page["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_i64().unwrap())
        .collect()
}

#[tokio::test]
async fn pages_newest_first_with_cursor_and_head() {
    let app = app_with_entries(7).await;
    let (status, page) = get_json(&app, "/api/v1/audit?limit=3").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&page), vec![7, 6, 5]);
    assert_eq!(page["next_before"], json!(5));
    assert_eq!(page["head"]["id"], json!(7));
    assert_eq!(page["head"]["entry_hash"].as_str().unwrap().len(), 64);

    let (status, page) = get_json(&app, "/api/v1/audit?limit=3&before=5").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&page), vec![4, 3, 2]);
    assert_eq!(page["next_before"], json!(2));

    let (status, page) = get_json(&app, "/api/v1/audit?limit=3&before=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&page), vec![1]);
    assert_eq!(page["next_before"], Value::Null);
}

#[tokio::test]
async fn filters_by_category_and_rejects_unknown_values() {
    let app = app_with_entries(6).await;
    let (status, page) = get_json(&app, "/api/v1/audit?category=doctor_action").await;
    assert_eq!(status, StatusCode::OK);
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert!(
        entries
            .iter()
            .all(|entry| entry["category"] == json!("doctor_action"))
    );

    for uri in [
        "/api/v1/audit?category=nope",
        "/api/v1/audit?actor=robot",
        "/api/v1/audit?limit=0",
        "/api/v1/audit?limit=513",
        "/api/v1/audit?before=0",
        "/api/v1/audit?before=abc",
    ] {
        let (status, _) = get_json(&app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
    }
}

#[tokio::test]
async fn empty_chain_pages_cleanly() {
    let app = app_with_entries(0).await;
    let (status, page) = get_json(&app, "/api/v1/audit").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["entries"], json!([]));
    assert_eq!(page["head"], Value::Null);
    assert_eq!(page["next_before"], Value::Null);

    let (status, verify) = get_json(&app, "/api/v1/audit/verify").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verify["valid"], json!(true));
    assert_eq!(verify["report"]["checked"], json!(0));
}

#[tokio::test]
async fn verify_reports_a_healthy_tail_and_rejects_bad_windows() {
    let app = app_with_entries(5).await;
    let (status, verify) = get_json(&app, "/api/v1/audit/verify?tail=3").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verify["valid"], json!(true));
    assert_eq!(verify["report"]["checked"], json!(3));
    assert_eq!(verify["report"]["anchored"], json!(false));
    assert_eq!(verify["head"]["id"], json!(5));

    let (status, verify) = get_json(&app, "/api/v1/audit/verify").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verify["report"]["anchored"], json!(true));
    assert_eq!(verify["report"]["checked"], json!(5));

    for uri in [
        "/api/v1/audit/verify?tail=0",
        "/api/v1/audit/verify?tail=10001",
    ] {
        let (status, _) = get_json(&app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
    }
}

#[tokio::test]
async fn requires_the_owner_bearer() {
    let app = app_with_entries(1).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
