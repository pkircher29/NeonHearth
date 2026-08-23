mod api;
mod auth;
mod state;
use axum::{Router, routing::get};
pub use state::{AppState, InvalidServiceToken};
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(api::health))
        .route("/api/v1/state", get(api::state))
        .route("/api/v1/openapi.json", get(api::openapi))
        .with_state(state)
}
