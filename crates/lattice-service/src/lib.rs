pub mod api;
mod auth;
pub mod cameras;
pub mod discovery;
pub mod platform;
pub mod policy;
pub mod runtime;
mod state;
pub mod vault;
pub mod ws;
use axum::{
    Router,
    extract::{Query, State, WebSocketUpgrade, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
pub use platform::{Platform, PlatformPaths, platform_paths};
use serde::Deserialize;
pub use state::{AppState, InvalidServiceToken, ServiceRuntimeStatus};
pub use vault::{CredentialRef, FakeVault, KeyringVault, Vault, VaultCapability, VaultError};
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(api::health))
        .route("/api/v1/state", get(api::state))
        .route("/api/v1/cameras", get(api::cameras))
        .route("/api/v1/cameras/{id}", get(api::camera))
        .route("/api/v1/cameras/{id}/health", get(api::camera_health))
        .route("/api/v1/cameras/{id}/inventory", get(api::camera_inventory))
        .route("/api/v1/policy/action", post(api::policy_action))
        .route("/api/v1/events/ticket", post(api::event_ticket))
        .route("/api/v1/events", get(events_socket))
        .route(
            "/api/v1/cameras/{id}/sessions",
            post(cameras::start_session_route),
        )
        .route(
            "/api/v1/cameras/{id}/snapshot",
            get(cameras::snapshot_route),
        )
        .route(
            "/api/v1/camera-sessions/{id}/playlist.m3u8",
            get(cameras::playlist_route),
        )
        .route(
            "/api/v1/camera-sessions/{id}/segments/{segment}",
            get(cameras::segment_route),
        )
        .route(
            "/api/v1/camera-sessions/{id}",
            delete(cameras::close_session_route),
        )
        .route("/api/v1/openapi.json", get(api::openapi))
        .with_state(state)
}

#[derive(Deserialize)]
struct EventQuery {
    ticket: String,
    after_sequence: u64,
}

async fn events_socket(
    State(state): State<AppState>,
    query: Result<Query<EventQuery>, QueryRejection>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let Ok(Query(query)) = query else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state
        .consume_event_ticket(&query.ticket, tokio::time::Instant::now())
        .await
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let events = state.events().clone();
    upgrade.on_upgrade(move |socket| ws::serve_socket(socket, events, query.after_sequence))
}
