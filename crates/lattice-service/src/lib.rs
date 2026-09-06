pub mod api;
pub mod audit_api;
mod auth;
pub mod automation;
pub mod cameras;
pub mod device_labels;
pub mod discovery;
pub mod doctor;
pub mod home;
pub mod host_monitor;
pub mod integrations;
pub mod mac_vendor;
pub mod mqtt;
pub mod network_scan;
pub mod platform;
pub mod policy;
pub mod runtime;
mod security;
mod state;
pub mod tailscale;
pub mod vault;
pub mod ws;
use axum::{
    Router,
    extract::{Query, State, WebSocketUpgrade, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
pub use platform::{Platform, PlatformPaths, platform_paths};
use serde::Deserialize;
pub use state::{AppState, InvalidServiceToken, ServiceRuntimeStatus};
use tower_http::timeout::TimeoutLayer;
pub use vault::{
    CredentialRef, FakeVault, FileVault, KeyringVault, Vault, VaultBackend, VaultCapability,
    VaultError, platform_vault,
};

/// Upper bound on any single request. Comfortably above the 25s integration
/// long-poll cap; everything else answers in milliseconds. A stalled handler
/// (a wedged store, a client that never finishes sending) is answered with
/// 408 instead of holding its task forever.
const REQUEST_TIMEOUT_SECS: u64 = 60;
pub fn app(state: AppState) -> Router {
    let doctor = doctor::DoctorState::for_service(&state);
    app_with_doctor(state, doctor)
}

/// Attach the built UI bundle (the Vite output the installer stages under
/// `ui\`) as the router's fallback so the service serves the dashboard at `/`.
///
/// Contract (docs/architecture/privilege-boundary.md still holds):
/// - Static assets are served WITHOUT bearer auth: the bundle is public build
///   output, not a secret, and the listener is loopback-only. Every `/api/*`
///   and `/ws` route keeps its existing auth untouched because routed paths
///   never reach a fallback.
/// - Unknown non-API paths fall back to `index.html` so client-side routes
///   deep-link correctly (SPA behavior).
/// - `ServeDir` percent-decodes and rejects `..` traversal, never renders
///   directory listings, and sets Content-Type from the file extension.
///
/// Only called when `LATTICE_UI_DIR` is configured (main.rs); without it the
/// service keeps its historical API-only surface and the Vite dev proxy flow
/// is unchanged.
pub fn with_ui_assets(router: Router, ui_dir: &std::path::Path) -> Router {
    let index = tower_http::services::ServeFile::new(ui_dir.join("index.html"));
    router
        .fallback_service(tower_http::services::ServeDir::new(ui_dir).fallback(index))
        .layer(axum::middleware::from_fn(security::browser_boundary))
}

/// Like [`app`], but with an explicitly assembled Doctor state — the seam
/// tests use to inject fake probe/repair transports and clocks.
pub fn app_with_doctor(state: AppState, doctor: doctor::DoctorState) -> Router {
    let remote = tailscale::RemoteAccessState::for_service(&state);
    app_with_parts(state, doctor, remote)
}

/// Like [`app`], but with an explicitly assembled remote-access state — the
/// seam tests use to inject fake tailscale controls and clocks.
pub fn app_with_remote_access(state: AppState, remote: tailscale::RemoteAccessState) -> Router {
    let doctor = doctor::DoctorState::for_service(&state);
    app_with_parts(state, doctor, remote)
}

/// The fully assembled router with every injectable seam explicit.
pub fn app_with_parts(
    state: AppState,
    doctor: doctor::DoctorState,
    remote: tailscale::RemoteAccessState,
) -> Router {
    let audit = audit_api::AuditApiState::for_service(&state);
    Router::new()
        .merge(device_labels::routes())
        .merge(host_monitor::api::routes())
        .route("/api/v1/health", get(api::health))
        .route("/api/v1/state", get(api::state))
        .route("/api/v1/cameras", get(api::cameras))
        .route("/api/v1/cameras/{id}", get(api::camera))
        .route("/api/v1/cameras/{id}/health", get(api::camera_health))
        .route("/api/v1/cameras/{id}/inventory", get(api::camera_inventory))
        .route(
            "/api/v1/devices/{device_id}/advisories",
            get(api::device_advisories),
        )
        .route("/api/v1/home", get(home::home_snapshot))
        .route("/api/v1/home/plan", put(home::save_plan_route))
        .route(
            "/api/v1/home/placements/{device_id}",
            put(home::upsert_placement_route).delete(home::delete_placement_route),
        )
        .route(
            "/api/v1/home/draft",
            get(home::get_draft_route)
                .put(home::put_draft_route)
                .delete(home::delete_draft_route),
        )
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
        .route("/api/v1/remote/serve", post(tailscale::serve_route))
        .route("/api/v1/remote/status", get(tailscale::status_route))
        .route("/api/v1/remote/pair", post(tailscale::pair_route))
        .route("/api/v1/remote/sessions", get(tailscale::sessions_route))
        .route(
            "/api/v1/remote/sessions/{id}",
            delete(tailscale::revoke_session_route),
        )
        .route("/api/v1/remote/stepup", post(tailscale::stepup_route))
        .route(
            "/api/v1/integrations/tokens",
            post(integrations::mint_token_route).get(integrations::list_tokens_route),
        )
        .route(
            "/api/v1/integrations/tokens/{id}",
            delete(integrations::revoke_token_route),
        )
        .route(
            "/api/v1/integrations/v1/devices",
            get(integrations::devices_route),
        )
        .route(
            "/api/v1/integrations/v1/presence",
            get(integrations::presence_route),
        )
        .route(
            "/api/v1/integrations/v1/bandwidth",
            get(integrations::bandwidth_route),
        )
        .route(
            "/api/v1/integrations/v1/policy",
            get(integrations::policy_route),
        )
        .route(
            "/api/v1/integrations/v1/events",
            get(integrations::events_route),
        )
        .merge(doctor::routes(doctor))
        .merge(automation::routes())
        .merge(network_scan::routes())
        .merge(audit_api::routes(audit))
        .layer(axum::Extension(remote.clone()))
        .layer(axum::middleware::from_fn_with_state(
            remote,
            tailscale::remote_access_layer,
        ))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
        ))
        .with_state(state)
        .layer(axum::middleware::from_fn(security::browser_boundary))
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
