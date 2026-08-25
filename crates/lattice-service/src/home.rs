//! Home twin service API (M5): plan snapshot, committed plan saves with
//! optimistic concurrency, owner placements, and the opaque editor draft.
//!
//! Contract: docs/architecture/m5-home-twin-contracts.md ("Service API").

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path as AxumPath, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use lattice_domain::{
    DeviceId, EventPayload, FloorId, HomeChanged, HomeId, HomePlan, LocationEstimate, Mounting,
    OwnerPlacement, PlacementId,
};
use lattice_store::{HomeRepository, HomeStoreError, MAX_DRAFT_BYTES};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{AppState, auth::Authorized};

/// The full home projection: committed plan plus location truth. Owner
/// placements are authoritative; estimates are advisory and stored separately
/// (H4, H5).
#[derive(Serialize, ToSchema)]
pub struct HomeSnapshot {
    pub plan: HomePlan,
    pub placements: Vec<OwnerPlacement>,
    pub estimates: Vec<LocationEstimate>,
    /// True when the committed plan row was corrupt and the plan body was
    /// recovered from the newest valid history row (H3). Never hidden.
    pub recovered: bool,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SavePlanRequest {
    /// The version the writer last observed; 0 for a first save.
    pub expected_version: u32,
    pub plan: HomePlan,
}

#[derive(Serialize, ToSchema)]
pub struct SavePlanResponse {
    pub version: u32,
}

/// 409 body: the stored version the stale writer must refetch.
#[derive(Serialize, ToSchema)]
pub struct PlanVersionConflict {
    pub actual_version: u32,
}

/// 400 body: why the submitted plan failed [`HomePlan::validate`].
#[derive(Serialize, ToSchema)]
pub struct PlanRejected {
    #[schema(max_length = 512)]
    pub error: String,
}

/// Owner placement upsert body. `device_id` comes from the path; a missing
/// `placement_id` mints a new one.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlacementRequest {
    pub placement_id: Option<PlacementId>,
    pub floor_id: FloorId,
    pub x: f64,
    pub y: f64,
    #[serde(default)]
    pub height_m: Option<f64>,
    #[serde(default)]
    pub mounting: Option<Mounting>,
}

/// 200 body for a draft the store found corrupt and already discarded — the
/// editor falls back to the committed plan, never a silent merge.
#[derive(Serialize, ToSchema)]
pub struct DraftCorrupt {
    pub corrupt: bool,
}

fn repository(state: &AppState) -> HomeRepository {
    HomeRepository::new(state.state_repository().pool().clone())
}

/// The stable placeholder identity served before any plan is committed. The
/// first-run editor is an empty editor, not a 404; the first committed save
/// establishes the real (client-chosen) home id.
fn unset_home_id() -> HomeId {
    HomeId::parse("00000000-0000-0000-0000-000000000000").expect("nil uuid is canonical")
}

fn default_plan() -> HomePlan {
    HomePlan {
        home_id: unset_home_id(),
        version: 0,
        name: "Home".to_owned(),
        floors: Vec::new(),
    }
}

/// Loads the committed plan, substituting the empty default when none was ever
/// saved. Recovery from history is surfaced, never hidden (H3).
async fn current_plan(repository: &HomeRepository) -> Result<(HomePlan, bool), HomeStoreError> {
    match repository.load_plan().await? {
        Some(loaded) => {
            if loaded.recovered_from_history {
                tracing::warn!(
                    home_id = %loaded.plan.home_id,
                    version = loaded.plan.version,
                    "home plan recovered from history after corrupt current row"
                );
            }
            Ok((loaded.plan, loaded.recovered_from_history))
        }
        None => Ok((default_plan(), false)),
    }
}

async fn publish_home_changed(state: &AppState, home_id: HomeId, version: u32, summary: &str) {
    state
        .events()
        .publish(
            Utc::now(),
            EventPayload::HomeChanged(HomeChanged {
                home_id,
                version,
                summary: summary.to_owned(),
            }),
        )
        .await;
}

fn parse_canonical_device_id(value: &str) -> Option<DeviceId> {
    let device_id = DeviceId::parse(value).ok()?;
    (device_id.to_string() == value).then_some(device_id)
}

fn storage_status(error: &HomeStoreError) -> StatusCode {
    match error {
        HomeStoreError::VersionConflict { .. } => StatusCode::CONFLICT,
        HomeStoreError::InvalidPlan(_) | HomeStoreError::Invalid => StatusCode::BAD_REQUEST,
        HomeStoreError::DraftTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        HomeStoreError::DraftCorrupt | HomeStoreError::Corrupt | HomeStoreError::Storage => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[utoipa::path(get, path = "/api/v1/home", responses((status = 200, body = HomeSnapshot), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn home_snapshot(_: Authorized, State(state): State<AppState>) -> Response {
    let repository = repository(&state);
    let (plan, recovered) = match current_plan(&repository).await {
        Ok(value) => value,
        Err(error) => return storage_status(&error).into_response(),
    };
    let placements = match repository.list_placements().await {
        Ok(value) => value,
        Err(error) => return storage_status(&error).into_response(),
    };
    let estimates = match repository.list_estimates().await {
        Ok(value) => value,
        Err(error) => return storage_status(&error).into_response(),
    };
    Json(HomeSnapshot {
        plan,
        placements,
        estimates,
        recovered,
    })
    .into_response()
}

#[utoipa::path(put, path = "/api/v1/home/plan", request_body = SavePlanRequest, responses((status = 200, body = SavePlanResponse), (status = 400, body = PlanRejected), (status = 401), (status = 409, body = PlanVersionConflict), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn save_plan_route(
    _: Authorized,
    State(state): State<AppState>,
    body: Result<Json<SavePlanRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = body else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if let Err(reason) = request.plan.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PlanRejected {
                error: reason.to_string(),
            }),
        )
            .into_response();
    }
    let repository = repository(&state);
    match repository
        .save_plan(request.expected_version, &request.plan, Utc::now())
        .await
    {
        Ok(version) => {
            // Durable commit precedes publication, matching every other event
            // source: a replay can duplicate, never hide, the update.
            publish_home_changed(&state, request.plan.home_id, version, "plan saved").await;
            Json(SavePlanResponse { version }).into_response()
        }
        Err(HomeStoreError::VersionConflict { actual, .. }) => (
            StatusCode::CONFLICT,
            Json(PlanVersionConflict {
                actual_version: actual,
            }),
        )
            .into_response(),
        Err(HomeStoreError::InvalidPlan(reason)) => (
            StatusCode::BAD_REQUEST,
            Json(PlanRejected {
                error: reason.to_string(),
            }),
        )
            .into_response(),
        Err(error) => storage_status(&error).into_response(),
    }
}

#[utoipa::path(put, path = "/api/v1/home/placements/{device_id}", params(("device_id" = String, Path, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")), request_body = PlacementRequest, responses((status = 200, body = OwnerPlacement), (status = 400), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn upsert_placement_route(
    _: Authorized,
    State(state): State<AppState>,
    path: Result<AxumPath<String>, axum::extract::rejection::PathRejection>,
    body: Result<Json<PlacementRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let (Ok(AxumPath(device_id)), Ok(Json(request))) = (path, body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(device_id) = parse_canonical_device_id(&device_id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let placement = OwnerPlacement {
        placement_id: request.placement_id.unwrap_or_default(),
        device_id,
        floor_id: request.floor_id,
        x: request.x,
        y: request.y,
        height_m: request.height_m,
        mounting: request.mounting,
    };
    let repository = repository(&state);
    match repository.upsert_placement(&placement).await {
        Ok(()) => {
            emit_placement_change(&state, &repository, "placement updated").await;
            Json(placement).into_response()
        }
        Err(error) => storage_status(&error).into_response(),
    }
}

#[utoipa::path(delete, path = "/api/v1/home/placements/{device_id}", params(("device_id" = String, Path, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")), responses((status = 204), (status = 400), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn delete_placement_route(
    _: Authorized,
    State(state): State<AppState>,
    path: Result<AxumPath<String>, axum::extract::rejection::PathRejection>,
) -> Response {
    let Ok(AxumPath(device_id)) = path else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(device_id) = parse_canonical_device_id(&device_id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let repository = repository(&state);
    match repository.delete_placement(device_id).await {
        Ok(removed) => {
            if removed {
                emit_placement_change(&state, &repository, "placement removed").await;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => storage_status(&error).into_response(),
    }
}

/// Placement changes stamp the event with the current committed plan identity
/// (version is the plan version; placements do not bump it). The event carries
/// no coordinates — clients refetch (contract).
async fn emit_placement_change(state: &AppState, repository: &HomeRepository, summary: &str) {
    match current_plan(repository).await {
        Ok((plan, _)) => publish_home_changed(state, plan.home_id, plan.version, summary).await,
        Err(_) => {
            tracing::warn!(
                summary,
                "placement change committed but plan load failed; event skipped"
            );
        }
    }
}

#[utoipa::path(get, path = "/api/v1/home/draft", responses((status = 200, content_type = "application/json", body = String), (status = 204), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn get_draft_route(_: Authorized, State(state): State<AppState>) -> Response {
    let repository = repository(&state);
    let (plan, _) = match current_plan(&repository).await {
        Ok(value) => value,
        Err(error) => return storage_status(&error).into_response(),
    };
    match repository.get_draft(plan.home_id).await {
        Ok(Some(draft)) => draft_response(draft),
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        // The store already discarded the corrupt blob; report it so the
        // editor falls back to the committed plan (contract: never merged).
        Err(HomeStoreError::DraftCorrupt) => Json(DraftCorrupt { corrupt: true }).into_response(),
        Err(error) => storage_status(&error).into_response(),
    }
}

#[utoipa::path(put, path = "/api/v1/home/draft", request_body(content = String, content_type = "application/json"), responses((status = 204), (status = 400), (status = 401), (status = 413), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn put_draft_route(
    _: Authorized,
    State(state): State<AppState>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    // A body the framework refused to buffer can only exceed limits far above
    // the draft cap, so it is reported the same way.
    let Ok(body) = body else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    if body.len() > MAX_DRAFT_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Ok(draft) = std::str::from_utf8(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let repository = repository(&state);
    let (plan, _) = match current_plan(&repository).await {
        Ok(value) => value,
        Err(error) => return storage_status(&error).into_response(),
    };
    match repository.put_draft(plan.home_id, draft, Utc::now()).await {
        // Drafts are uncommitted editor state: no HomeChanged is emitted and
        // the blob never enters the event pipeline.
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => storage_status(&error).into_response(),
    }
}

#[utoipa::path(delete, path = "/api/v1/home/draft", responses((status = 204), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn delete_draft_route(_: Authorized, State(state): State<AppState>) -> Response {
    let repository = repository(&state);
    let (plan, _) = match current_plan(&repository).await {
        Ok(value) => value,
        Err(error) => return storage_status(&error).into_response(),
    };
    match repository.delete_draft(plan.home_id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => storage_status(&error).into_response(),
    }
}

fn draft_response(draft: String) -> Response {
    let mut response = Body::from(draft).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
