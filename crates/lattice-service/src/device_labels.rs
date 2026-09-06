use crate::{AppState, automation::LocalOwner};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, put},
};
use lattice_domain::DeviceId;
use lattice_store::{DeviceLabel, DeviceLabelError};
use serde::Deserialize;
use utoipa::{OpenApi, ToSchema};

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmDeviceName {
    pub name: String,
    pub expected_name: Option<String>,
    pub expected_confirmed: bool,
}
fn failure(error: DeviceLabelError) -> Response {
    let status = match error {
        DeviceLabelError::Invalid => StatusCode::BAD_REQUEST,
        DeviceLabelError::NotFound => StatusCode::NOT_FOUND,
        DeviceLabelError::Conflict => StatusCode::CONFLICT,
        DeviceLabelError::Storage => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, Json(serde_json::json!({"error":error.to_string()}))).into_response()
}
#[utoipa::path(get, path="/api/v1/devices/labels", responses((status=200,body=Vec<DeviceLabel>),(status=401),(status=503)), security(("bearer_auth"=[])))]
async fn labels(_: LocalOwner, State(state): State<AppState>) -> Response {
    match state.state_repository().device_labels().await {
        Ok(labels) => Json(labels).into_response(),
        Err(error) => failure(error),
    }
}
#[utoipa::path(put, path="/api/v1/devices/{device_id}/name", params(("device_id"=String,Path)), request_body=ConfirmDeviceName, responses((status=200,body=DeviceLabel),(status=400),(status=401),(status=404),(status=409),(status=503)), security(("bearer_auth"=[])))]
async fn confirm(
    _: LocalOwner,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<ConfirmDeviceName>,
) -> Response {
    let Ok(id) = DeviceId::parse(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state
        .state_repository()
        .confirm_device_name(
            id,
            input.name,
            input.expected_name,
            input.expected_confirmed,
        )
        .await
    {
        Ok(label) => Json(label).into_response(),
        Err(error) => failure(error),
    }
}
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/devices/labels", get(labels))
        .route("/api/v1/devices/{device_id}/name", put(confirm))
        .layer(DefaultBodyLimit::max(8192))
}
#[derive(OpenApi)]
#[openapi(
    paths(labels, confirm),
    components(schemas(DeviceLabel, ConfirmDeviceName))
)]
pub struct DeviceLabelsApiDoc;
