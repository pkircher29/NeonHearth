use super::*;
use crate::{AppState, automation::LocalOwner};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use utoipa::OpenApi;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryQuery {
    pub minutes: Option<u32>,
    pub app_id: Option<String>,
}
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/host/snapshot", get(snapshot))
        .route("/api/v1/host/history", get(history))
        .route("/api/v1/host/settings", get(settings).put(update_settings))
        .route("/api/v1/host/alerts/{id}/acknowledge", post(acknowledge))
        .route("/api/v1/host/firewall", get(firewall).post(firewall_action))
        .layer(DefaultBodyLimit::max(8192))
}
fn respond<T: Serialize>(result: Result<T, sqlx::Error>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
#[utoipa::path(get,path="/api/v1/host/snapshot",responses((status=200,body=HostSnapshot),(status=401)),security(("bearer_auth"=[])))]
async fn snapshot(_: LocalOwner, State(state): State<AppState>) -> Json<HostSnapshot> {
    Json(state.host_monitor().snapshot().await)
}
#[utoipa::path(get,path="/api/v1/host/history",params(("minutes"=Option<u32>,Query),("app_id"=Option<String>,Query)),responses((status=200),(status=400),(status=401)),security(("bearer_auth"=[])))]
async fn history(
    _: LocalOwner,
    State(state): State<AppState>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let minutes = q.minutes.unwrap_or(60);
    if ![5, 60, 360, 1440, 10080, 43200].contains(&minutes)
        || q.app_id
            .as_ref()
            .is_some_and(|id| id.len() != 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    respond(
        state
            .host_monitor()
            .history(minutes, q.app_id.as_deref())
            .await,
    )
}
#[utoipa::path(get,path="/api/v1/host/settings",responses((status=200,body=HostSettings),(status=401)),security(("bearer_auth"=[])))]
async fn settings(_: LocalOwner, State(state): State<AppState>) -> Response {
    respond(state.host_monitor().settings().await)
}
#[utoipa::path(put,path="/api/v1/host/settings",request_body=HostSettings,responses((status=200),(status=400),(status=401)),security(("bearer_auth"=[])))]
async fn update_settings(
    _: LocalOwner,
    State(state): State<AppState>,
    Json(input): Json<HostSettings>,
) -> Response {
    if !(1..=365).contains(&input.retention_days)
        || input
            .monthly_budget_bytes
            .is_some_and(|b| b == 0 || b > 1_000_000_000_000_000)
        || input.snooze_until.as_ref().is_some_and(|v| {
            chrono::DateTime::parse_from_rfc3339(v).map_or(true, |d| {
                d > Utc::now() + chrono::Duration::days(1) || d < Utc::now()
            })
        })
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.host_monitor().update_settings(&input).await {
        Ok(()) => Json(input).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
#[utoipa::path(post,path="/api/v1/host/alerts/{id}/acknowledge",params(("id"=i64,Path)),responses((status=200),(status=401),(status=404)),security(("bearer_auth"=[])))]
async fn acknowledge(
    _: LocalOwner,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Response {
    match state.host_monitor().acknowledge(id).await {
        Ok(true) => Json(json!({"acknowledged":true})).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
#[utoipa::path(get,path="/api/v1/host/firewall",responses((status=200),(status=401),(status=501)),security(("bearer_auth"=[])))]
async fn firewall(_: LocalOwner, State(state): State<AppState>) -> Response {
    match state.host_monitor().firewall_rules().await {
        Ok(v) => Json(v).into_response(),
        Err(s) => s.into_response(),
    }
}
#[utoipa::path(post,path="/api/v1/host/firewall",request_body=firewall::FirewallInput,responses((status=200),(status=400),(status=401),(status=403),(status=409),(status=423)),security(("bearer_auth"=[])))]
async fn firewall_action(
    _: LocalOwner,
    State(state): State<AppState>,
    Json(input): Json<firewall::FirewallInput>,
) -> Response {
    match state.host_monitor().firewall_action(input).await {
        Ok(v) => Json(v).into_response(),
        Err(s) => s.into_response(),
    }
}
#[derive(OpenApi)]
#[openapi(
    paths(
        snapshot,
        history,
        settings,
        update_settings,
        acknowledge,
        firewall,
        firewall_action
    ),
    components(schemas(
        HostSnapshot,
        HostSettings,
        Application,
        Connection,
        InterfaceCounter,
        firewall::FirewallInput
    ))
)]
pub struct HostApiDoc;
