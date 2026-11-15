use super::*;
use crate::{AppState, automation::LocalOwner};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use utoipa::OpenApi;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    minutes: Option<u32>,
}
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/network/monitor", get(snapshot))
        .route(
            "/api/v1/network/monitor/settings",
            get(settings).put(update_settings),
        )
        .route("/api/v1/network/discover", post(discover))
        .route("/api/v1/network/discover/cancel", post(cancel))
        .layer(DefaultBodyLimit::max(4096))
}
fn result<T: Serialize>(value: Result<T, sqlx::Error>) -> Response {
    match value {
        Ok(v) => Json(v).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
#[utoipa::path(get,path="/api/v1/network/monitor",params(("minutes"=Option<u32>,Query)),responses((status=200,body=Snapshot),(status=401)),security(("bearer_auth"=[])))]
async fn snapshot(
    _: LocalOwner,
    State(state): State<AppState>,
    Query(range): Query<Range>,
) -> Response {
    let minutes = range.minutes.unwrap_or(5);
    if ![5, 60, 1440].contains(&minutes) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    result(state.network_monitor().snapshot(minutes).await)
}
#[utoipa::path(get,path="/api/v1/network/monitor/settings",responses((status=200,body=Settings),(status=401)),security(("bearer_auth"=[])))]
async fn settings(_: LocalOwner, State(state): State<AppState>) -> Response {
    result(state.network_monitor().settings().await)
}
#[utoipa::path(put,path="/api/v1/network/monitor/settings",request_body=Settings,responses((status=200),(status=400),(status=401)),security(("bearer_auth"=[])))]
async fn update_settings(
    _: LocalOwner,
    State(state): State<AppState>,
    Json(settings): Json<Settings>,
) -> Response {
    if !(60..=3600).contains(&settings.interval_seconds)
        || settings.router_port == 0
        || settings.router_ip.as_ref().is_some_and(|ip| {
            ip.parse::<std::net::Ipv4Addr>()
                .ok()
                .filter(|v| v.to_string() == *ip)
                .and_then(lan::local_target)
                .is_none()
        })
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state
        .network_monitor()
        .update_settings(settings.clone())
        .await
    {
        Ok(()) => Json(settings).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
#[utoipa::path(post,path="/api/v1/network/discover",responses((status=202),(status=401),(status=409)),security(("bearer_auth"=[])))]
async fn discover(_: LocalOwner, State(state): State<AppState>) -> Response {
    match state.network_monitor().discover().await {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"state":"running"})),
        )
            .into_response(),
        Err(_) => StatusCode::CONFLICT.into_response(),
    }
}
#[utoipa::path(post,path="/api/v1/network/discover/cancel",responses((status=200),(status=401)),security(("bearer_auth"=[])))]
async fn cancel(_: LocalOwner, State(state): State<AppState>) -> Json<serde_json::Value> {
    state.network_monitor().cancel();
    Json(serde_json::json!({"requested":true}))
}
#[derive(OpenApi)]
#[openapi(
    paths(snapshot, settings, update_settings, discover, cancel),
    components(schemas(
        Settings,
        Snapshot,
        RouterReading,
        Discovery,
        Presence,
        PresenceEvent,
        Point
    ))
)]
pub struct NetworkMonitorApiDoc;
