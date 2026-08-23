use crate::{AppState, auth::Authorized};
use axum::{Json, extract::State};
use serde::Serialize;
use utoipa::{Modify, OpenApi, ToSchema};
#[derive(Serialize, ToSchema)]
pub struct Health {
    pub status: &'static str,
    pub api_version: &'static str,
}
#[derive(Serialize, ToSchema)]
pub struct Snapshot {
    pub sequence: u64,
    pub devices: Vec<serde_json::Value>,
    pub service_status: &'static str,
}
#[utoipa::path(get, path = "/api/v1/health", responses((status = 200, body = Health)))]
pub async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        api_version: "v1",
    })
}
#[utoipa::path(get, path = "/api/v1/state", security(("bearer_auth" = [])), responses((status = 200, body = Snapshot), (status = 401)))]
pub async fn state(_: Authorized, State(state): State<AppState>) -> Json<Snapshot> {
    Json(Snapshot {
        sequence: state.events().current_sequence().await,
        devices: Vec::new(),
        service_status: "ready",
    })
}
#[derive(OpenApi)]
#[openapi(paths(health, state), components(schemas(Health, Snapshot)), modifiers(&SecurityAddon))]
pub struct ApiDoc;
struct SecurityAddon;
impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::Http::new(
                        utoipa::openapi::security::HttpAuthScheme::Bearer,
                    ),
                ),
            );
    }
}
pub async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}
