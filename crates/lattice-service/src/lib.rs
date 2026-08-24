mod api;
mod auth;
pub mod discovery;
pub mod platform;
mod state;
pub mod ws;
use axum::{
    Router,
    extract::{Query, State, WebSocketUpgrade, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
pub use platform::{Platform, PlatformPaths, platform_paths};
use serde::Deserialize;
pub use state::{AppState, InvalidServiceToken, ServiceRuntimeStatus};
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(api::health))
        .route("/api/v1/state", get(api::state))
        .route("/api/v1/events/ticket", post(api::event_ticket))
        .route("/api/v1/events", get(events_socket))
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
