use crate::{AppState, auth::Authorized, state::EVENT_TICKET_TTL};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use lattice_advisory::{
    AdvisorySource, Confidence, Exploitability, Exposure, Freshness, MatchLabel, Remediation,
    Severity, SourceTrust,
};
use lattice_domain::{Coverage, DeviceId, EvidenceFamily, OwnerDecision, PresenceState};
use lattice_store::{PendingDecision, PolicyRepository, StoredDeviceSnapshot};
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use tokio::time::Instant;
use utoipa::{Modify, OpenApi, PartialSchema, ToSchema};

fn parse_canonical_camera_id(value: &str) -> Result<lattice_camera::CameraId, StatusCode> {
    if value.len() != 36 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| StatusCode::BAD_REQUEST)?;
    (uuid.hyphenated().to_string() == value)
        .then(|| lattice_camera::CameraId::from_uuid(uuid))
        .ok_or(StatusCode::BAD_REQUEST)
}
#[derive(Serialize, ToSchema)]
pub struct Health {
    pub status: &'static str,
    pub api_version: &'static str,
}
#[derive(Serialize, ToSchema)]
pub struct CameraSummary {
    #[schema(value_type = String, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
    pub camera_id: String,
    #[schema(pattern = "^(camera|possible_camera|unknown)$")]
    pub classification: String,
    #[schema(minimum = 0, maximum = 1)]
    pub confidence: f32,
    #[schema(pattern = "^(healthy|degraded|unknown)$")]
    pub health: String,
    pub observed_at: DateTime<Utc>,
}
#[derive(Serialize, ToSchema)]
pub struct CameraList {
    pub items: Vec<CameraSummary>,
    #[schema(value_type = Option<String>, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
    pub next_after: Option<String>,
}
#[derive(Serialize, ToSchema)]
pub struct CameraDetail {
    #[schema(value_type = String, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
    pub camera_id: String,
    pub classification: String,
    #[schema(minimum = 0, maximum = 1)]
    pub confidence: f32,
    pub health: String,
    pub observed_at: DateTime<Utc>,
    pub inventory: Option<CameraInventoryProjection>,
    #[schema(max_items = 64)]
    pub streams: Vec<CameraStreamProjection>,
}
#[derive(Serialize, ToSchema)]
pub struct CameraStreamProjection {
    #[schema(value_type = String, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
    pub stream_id: String,
}
#[derive(Serialize, ToSchema)]
pub struct CameraHealth {
    #[schema(pattern = "^(healthy|degraded|unknown)$")]
    pub health: String,
    #[schema(minimum = 0, maximum = 1)]
    pub confidence: f32,
}
#[derive(Serialize, ToSchema)]
pub struct CameraInventoryProjection {
    #[schema(max_length = 128)]
    pub manufacturer: Option<String>,
    #[schema(max_length = 128)]
    pub model: Option<String>,
    #[schema(max_length = 128)]
    pub firmware: Option<String>,
    #[schema(max_length = 128)]
    pub serial: Option<String>,
    #[schema(max_items = 32, value_type = Vec<BoundedCapability>)]
    pub capabilities: Vec<String>,
    #[schema(pattern = "^(healthy|degraded)$")]
    pub health: String,
}

#[derive(Serialize, ToSchema)]
pub struct AdvisoryList {
    #[schema(max_items = 128)]
    pub matches: Vec<AdvisoryProjection>,
}
#[derive(Serialize, ToSchema)]
pub struct AdvisoryProjection {
    #[schema(max_length = 36)]
    pub advisory_id: String,
    #[schema(max_length = 32)]
    pub source: String,
    #[schema(max_length = 512)]
    pub source_id: String,
    #[schema(max_length = 64)]
    pub provenance_sha256: String,
    #[schema(max_length = 512)]
    pub source_url: String,
    #[schema(max_length = 512)]
    pub title: String,
    #[schema(max_length = 32)]
    pub freshness: String,
    pub source_trust: String,
    pub retrieved_at: DateTime<Utc>,
    pub cache_expires_at: DateTime<Utc>,
    pub label: String,
    #[schema(max_items = 8)]
    pub matched_fields: Vec<String>,
    #[schema(max_length = 512)]
    pub explanation: String,
    pub confidence: String,
    pub risk: AdvisoryRisk,
}
#[derive(Serialize, ToSchema)]
pub struct AdvisoryRisk {
    pub severity: String,
    pub exploitability: String,
    pub exposure: String,
    pub confidence: String,
    pub remediation: String,
}
fn advisory_source(v: AdvisorySource) -> String {
    match v {
        AdvisorySource::Nvd => "nvd",
        AdvisorySource::CisaKev => "cisa_kev",
        AdvisorySource::Vendor => "vendor",
    }
    .into()
}
fn freshness_name(v: Freshness) -> String {
    match v {
        Freshness::Fresh => "fresh",
        Freshness::Stale => "stale",
        Freshness::FutureDated => "future_dated",
    }
    .into()
}
fn source_trust_name(v: SourceTrust) -> String {
    match v {
        SourceTrust::OfficialApi => "official_api",
        SourceTrust::VerifiedSignature => "verified_signature",
        SourceTrust::RegisteredHttps => "registered_https",
        SourceTrust::Invalid => "invalid",
    }
    .into()
}
fn match_label(v: MatchLabel) -> String {
    match v {
        MatchLabel::Exact => "exact",
        MatchLabel::Possible => "possible",
        MatchLabel::Contradicted => "contradicted",
        MatchLabel::Unknown => "unknown",
    }
    .into()
}
fn confidence_name(v: Confidence) -> String {
    match v {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
    .into()
}
fn severity_name(v: Severity) -> String {
    match v {
        Severity::None => "none",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
        Severity::Unknown => "unknown",
    }
    .into()
}
fn exploitability_name(v: Exploitability) -> String {
    match v {
        Exploitability::None => "none",
        Exploitability::ProofOfConcept => "proof_of_concept",
        Exploitability::ActiveKnownExploitation => "active_known_exploitation",
        Exploitability::Unknown => "unknown",
    }
    .into()
}
fn exposure_name(v: Exposure) -> String {
    match v {
        Exposure::NotExposed => "not_exposed",
        Exposure::PotentiallyExposed => "potentially_exposed",
        Exposure::Exposed => "exposed",
        Exposure::Unknown => "unknown",
    }
    .into()
}
fn remediation_name(v: Remediation) -> String {
    match v {
        Remediation::Upgrade => "upgrade",
        Remediation::Mitigate => "mitigate",
        Remediation::Monitor => "monitor",
        Remediation::None => "none",
        Remediation::Unknown => "unknown",
    }
    .into()
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryQuery {
    pub limit: Option<usize>,
}

#[utoipa::path(get, path = "/api/v1/devices/{device_id}/advisories", params(("device_id" = String, Path, format = Uuid), ("limit" = Option<usize>, Query, minimum = 1, maximum = 128)), responses((status = 200, body = AdvisoryList), (status = 400), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub async fn device_advisories(
    _: Authorized,
    State(state): State<AppState>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
    query: Result<Query<AdvisoryQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<AdvisoryList>, StatusCode> {
    let raw_device_id = device_id.clone();
    let device_id =
        lattice_domain::DeviceId::parse(&device_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    if raw_device_id != device_id.to_string() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let Query(query) = query.map_err(|_| StatusCode::BAD_REQUEST)?;
    let limit = query.limit.unwrap_or(128);
    if !(1..=128).contains(&limit) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let exists: Option<String> =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE device_id=?")
            .bind(device_id.to_string())
            .fetch_optional(state.state_repository().pool())
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if exists.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    let repo = lattice_store::AdvisoryRepository::new(state.state_repository().pool().clone());
    let rows = repo
        .list_device_advisories(device_id, Utc::now())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let matches = rows
        .into_iter()
        .take(limit)
        .map(|row| {
            let input = row.advisory.input();
            AdvisoryProjection {
                advisory_id: row.advisory_id.to_string(),
                source: advisory_source(input.source),
                source_id: input.source_id.clone(),
                provenance_sha256: row.advisory.provenance_sha256().to_owned(),
                source_url: input.source_url.clone(),
                title: input.title.clone(),
                freshness: freshness_name(row.freshness),
                source_trust: source_trust_name(input.source_trust),
                retrieved_at: input.retrieved_at,
                cache_expires_at: input.cache_expires_at,
                label: match_label(row.matching.label()),
                matched_fields: row
                    .matching
                    .matched_fields()
                    .iter()
                    .map(|f| format!("{:?}", f).to_lowercase())
                    .collect(),
                explanation: row.matching.explanation().to_owned(),
                confidence: confidence_name(row.matching.confidence()),
                risk: AdvisoryRisk {
                    severity: severity_name(row.risk.severity),
                    exploitability: exploitability_name(row.risk.exploitability),
                    exposure: exposure_name(row.risk.exposure),
                    confidence: confidence_name(row.risk.confidence),
                    remediation: remediation_name(row.risk.remediation),
                },
            }
        })
        .collect();
    Ok(Json(AdvisoryList { matches }))
}

pub struct BoundedCapability;
impl PartialSchema for BoundedCapability {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .max_length(Some(128))
            .into()
    }
}
impl ToSchema for BoundedCapability {}

/// A deliberately serial-free representation for exports and structured logs.
/// The owner UI receives [`CameraInventoryProjection`] only after authentication.
#[derive(Serialize)]
pub struct CameraInventoryExportProjection {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub capabilities: Vec<String>,
    pub health: String,
}

impl CameraInventoryProjection {
    #[must_use]
    pub fn redacted_for_export(&self) -> CameraInventoryExportProjection {
        CameraInventoryExportProjection {
            manufacturer: self.manufacturer.clone(),
            model: self.model.clone(),
            firmware: self.firmware.clone(),
            capabilities: self.capabilities.clone(),
            health: self.health.clone(),
        }
    }

    pub fn to_redacted_export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.redacted_for_export())
    }
}

/// Authoritative support-export serialization seam. No support-export endpoint
/// exists yet; callers must use this serial-free projection serializer.
pub fn serialize_camera_inventory_for_support_export(
    inventory: &CameraInventoryProjection,
) -> Result<String, serde_json::Error> {
    inventory.to_redacted_export_json()
}

impl fmt::Debug for CameraInventoryProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CameraInventoryProjection")
            .field("manufacturer", &self.manufacturer)
            .field("model", &self.model)
            .field("firmware", &self.firmware)
            .field("serial", &"[redacted]")
            .field("capabilities", &self.capabilities)
            .field("health", &self.health)
            .finish()
    }
}

impl From<lattice_store::CameraInventoryRecord> for CameraInventoryProjection {
    fn from(value: lattice_store::CameraInventoryRecord) -> Self {
        let inventory = Self {
            manufacturer: value.manufacturer.map(|value| value.as_str().to_owned()),
            model: value.model.map(|value| value.as_str().to_owned()),
            firmware: value.firmware.map(|value| value.as_str().to_owned()),
            serial: value.serial.map(|value| value.as_str().to_owned()),
            capabilities: value
                .capabilities
                .into_iter()
                .map(|value| value.as_str().to_owned())
                .collect(),
            health: format!("{:?}", value.health).to_lowercase(),
        };
        tracing::debug!(inventory = ?inventory, "projected camera inventory for owner response");
        inventory
    }
}
#[derive(Serialize, ToSchema)]
pub struct CameraSessionResponse {
    #[schema(value_type = String, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
    pub session_id: String,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CameraSessionRequest {
    #[schema(value_type = String, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
    pub stream_id: String,
}
pub struct BinaryMedia;

impl PartialSchema for BinaryMedia {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .format(Some(utoipa::openapi::SchemaFormat::KnownFormat(
                utoipa::openapi::KnownFormat::Binary,
            )))
            .into()
    }
}

impl ToSchema for BinaryMedia {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CameraQuery {
    pub limit: Option<usize>,
    pub after: Option<String>,
}

#[utoipa::path(get, path = "/api/v1/cameras", params(("limit" = Option<usize>, Query, minimum = 1, maximum = 256), ("after" = Option<String>, Query, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")), responses((status = 200, body = CameraList), (status = 400), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub async fn cameras(
    _: Authorized,
    State(state): State<AppState>,
    query: Result<Query<CameraQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<CameraList>, StatusCode> {
    let Query(query) = query.map_err(|_| StatusCode::BAD_REQUEST)?;
    let limit = query.limit.unwrap_or(128);
    if !(1..=256).contains(&limit) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let after = query
        .after
        .as_deref()
        .map(parse_canonical_camera_id)
        .transpose()?;
    let repo = lattice_store::CameraRepository::new(state.state_repository().pool().clone());
    let (rows, has_more) = repo
        .list_cameras(limit, after)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let items = rows
        .into_iter()
        .map(|r| CameraSummary {
            camera_id: r.id.to_string(),
            classification: format!("{:?}", r.classification).to_lowercase(),
            confidence: r.confidence.get(),
            health: format!("{:?}", r.health).to_lowercase(),
            observed_at: r.observed_at,
        })
        .collect::<Vec<_>>();
    Ok(Json(CameraList {
        next_after: has_more
            .then(|| items.last().map(|item| item.camera_id.clone()))
            .flatten(),
        items,
    }))
}
#[utoipa::path(get, path = "/api/v1/cameras/{id}", params(("id" = String, Path, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")), responses((status = 200, body = CameraDetail), (status = 400), (status = 401), (status = 404), (status = 503)), security(("bearer_auth" = [])))]
pub async fn camera(
    _: Authorized,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<CameraDetail>, StatusCode> {
    let id = parse_canonical_camera_id(&id)?;
    let repo = lattice_store::CameraRepository::new(state.state_repository().pool().clone());
    let r = repo
        .load_camera(id)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(CameraDetail {
        camera_id: r.id.to_string(),
        classification: format!("{:?}", r.classification).to_lowercase(),
        confidence: r.confidence.get(),
        health: format!("{:?}", r.health).to_lowercase(),
        observed_at: r.observed_at,
        inventory: repo
            .load_inventory(id)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .map(CameraInventoryProjection::from),
        streams: repo
            .load_stream_refs(id)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .into_iter()
            .map(|profile| CameraStreamProjection {
                stream_id: profile.stream_id().to_string(),
            })
            .collect(),
    }))
}
#[utoipa::path(get, path = "/api/v1/cameras/{id}/health", params(("id" = String, Path, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")), responses((status = 200, body = CameraHealth), (status = 400), (status = 401), (status = 404), (status = 503)), security(("bearer_auth" = [])))]
pub async fn camera_health(
    _: Authorized,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<CameraHealth>, StatusCode> {
    let id = parse_canonical_camera_id(&id)?;
    let repo = lattice_store::CameraRepository::new(state.state_repository().pool().clone());
    let r = repo
        .load_camera(id)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(CameraHealth {
        health: format!("{:?}", r.health).to_lowercase(),
        confidence: r.confidence.get(),
    }))
}
#[utoipa::path(get, path = "/api/v1/cameras/{id}/inventory", params(("id" = String, Path, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")), responses((status = 200, body = Option<CameraInventoryProjection>), (status = 400), (status = 401), (status = 404), (status = 503)), security(("bearer_auth" = [])))]
pub async fn camera_inventory(
    _: Authorized,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<Option<CameraInventoryProjection>>, StatusCode> {
    let id = parse_canonical_camera_id(&id)?;
    let repo = lattice_store::CameraRepository::new(state.state_repository().pool().clone());
    if repo
        .load_camera(id)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .is_none()
    {
        return Err(StatusCode::NOT_FOUND);
    }
    let r = repo
        .load_inventory(id)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(r.map(CameraInventoryProjection::from)))
}
#[derive(Serialize, ToSchema)]
pub struct Snapshot {
    pub sequence: u64,
    pub devices: Vec<DeviceSnapshot>,
    pub next_after: Option<DeviceId>,
    pub service_status: String,
}
#[derive(Serialize, ToSchema)]
pub struct DeviceSnapshot {
    pub device_id: DeviceId,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub owner_name: Option<String>,
    pub owner_type: Option<String>,
    pub owner_confirmed: bool,
    pub presence: Presence,
    pub evidence: Option<Evidence>,
    pub identity: Identity,
    pub bandwidth: Bandwidth,
    pub policy: Option<PolicyProjection>,
}
#[derive(Serialize, ToSchema)]
pub struct PolicyProjection {
    pub owner_decision: OwnerDecision,
    pub protection: lattice_domain::Protection,
    pub evaluation: lattice_domain::Evaluation,
    pub enforcement_result: lattice_domain::EnforcementStatus,
    pub undo_available: bool,
    pub delivery_pending: bool,
}
#[derive(Serialize, ToSchema)]
pub struct Presence {
    pub state: PresenceState,
    pub observed_at: Option<DateTime<Utc>>,
    pub source: Option<String>,
    pub kind: Option<String>,
}
#[derive(Serialize, ToSchema)]
pub struct Evidence {
    pub family: EvidenceFamily,
    pub source: String,
    pub confidence: f32,
    pub observed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}
#[derive(Serialize, ToSchema)]
pub struct Identity {
    pub available: bool,
    pub classification: Option<String>,
    pub confidence: Option<f32>,
}
#[derive(Serialize, ToSchema)]
pub struct Bandwidth {
    pub available: bool,
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub coverage: Option<Coverage>,
    pub observed_at: Option<DateTime<Utc>>,
}
#[derive(Deserialize)]
pub struct StateQuery {
    pub limit: Option<usize>,
    pub after: Option<DeviceId>,
}

/// Captures the replay boundary before querying durable projections.
///
/// Durable state commits must happen before their event publication. An event
/// published while the projection is read can therefore be replayed after this
/// snapshot, producing a duplicate but never hiding a durable update.
async fn snapshot_watermark(state: &AppState) -> u64 {
    state.events().current_sequence().await
}

#[derive(Serialize, ToSchema)]
pub struct EventTicket {
    pub ticket: String,
    pub expires_in_seconds: u64,
}
#[utoipa::path(get, path = "/api/v1/health", responses((status = 200, body = Health)))]
pub async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        api_version: "v1",
    })
}
#[utoipa::path(get, path = "/api/v1/state", params(("limit" = Option<usize>, Query), ("after" = Option<DeviceId>, Query)), security(("bearer_auth" = [])), responses((status = 200, body = Snapshot), (status = 400), (status = 401), (status = 503)))]
pub async fn state(
    _: Authorized,
    State(state): State<AppState>,
    query: Result<Query<StateQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Snapshot>, StatusCode> {
    let Query(query) = query.map_err(|_| StatusCode::BAD_REQUEST)?;
    let limit = query.limit.unwrap_or(128);
    if limit == 0 || limit > lattice_store::MAX_SNAPSHOT_DEVICES {
        return Err(StatusCode::BAD_REQUEST);
    }
    let sequence = snapshot_watermark(&state).await;
    let devices = state
        .state_repository()
        .list_device_snapshots(limit, query.after)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let next_after = (devices.len() == limit)
        .then(|| devices.last().map(|d| d.device_id))
        .flatten();
    let policy = PolicyRepository::new(state.state_repository().pool().clone());
    let mut mapped = Vec::with_capacity(devices.len());
    for device in devices {
        let policy_projection = match (
            policy.load(device.device_id).await,
            policy.pending_decision_value(device.device_id).await,
            policy.published_decision(device.device_id).await,
        ) {
            (Ok(Some(policy_row)), Ok(Some(PendingDecision::Exact(value))), _) => {
                Some(PolicyProjection::pending_exact(policy_row, value))
            }
            (Ok(Some(policy_row)), Ok(Some(PendingDecision::Legacy)), _) => {
                Some(PolicyProjection::pending_legacy(policy_row))
            }
            (Ok(Some(policy_row)), Ok(None), Ok(Some(value))) => {
                Some(PolicyProjection::from((policy_row, value)))
            }
            (Ok(_), Ok(None), Ok(None)) => None,
            _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
        };
        mapped.push(map_device(device, policy_projection));
    }
    Ok(Json(Snapshot {
        sequence,
        devices: mapped,
        next_after,
        service_status: state.service_status().await,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_domain::{EventPayload, ServiceStatus};
    use lattice_store::connect_memory;

    const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

    #[tokio::test]
    async fn snapshot_watermark_precedes_events_published_after_capture() {
        let state = AppState::new(
            TOKEN,
            lattice_store::M2StateRepository::new(connect_memory().await.unwrap()),
        )
        .unwrap();
        let watermark = snapshot_watermark(&state).await;
        state
            .events()
            .publish(
                Utc::now(),
                EventPayload::ServiceStatus(ServiceStatus {
                    state: "ready".into(),
                    detail: "test".into(),
                }),
            )
            .await;

        assert_eq!(watermark, 0);
        assert_eq!(state.events().current_sequence().await, 1);
    }
}
impl From<(lattice_domain::DevicePolicy, lattice_domain::PolicyChanged)> for PolicyProjection {
    fn from(
        (policy, value): (lattice_domain::DevicePolicy, lattice_domain::PolicyChanged),
    ) -> Self {
        Self {
            owner_decision: policy.owner_decision,
            protection: policy.protection,
            evaluation: value.evaluation,
            enforcement_result: value.enforcement_result,
            undo_available: value.undo_available,
            delivery_pending: false,
        }
    }
}
impl PolicyProjection {
    fn pending_exact(
        policy: lattice_domain::DevicePolicy,
        decision: lattice_domain::PolicyChanged,
    ) -> Self {
        Self {
            owner_decision: policy.owner_decision,
            protection: policy.protection,
            evaluation: decision.evaluation,
            enforcement_result: decision.enforcement_result,
            undo_available: decision.undo_available,
            delivery_pending: true,
        }
    }

    fn pending_legacy(policy: lattice_domain::DevicePolicy) -> Self {
        let evaluation =
            lattice_policy::PolicyEngine::new(policy.first_seen_at).evaluate(&policy, Utc::now());
        Self {
            owner_decision: policy.owner_decision,
            protection: policy.protection,
            evaluation,
            enforcement_result: lattice_domain::EnforcementStatus::ManualRequired,
            // A legacy row has no exact event. Never imply that enforcement
            // completed or that a reversible owner action still exists.
            undo_available: false,
            delivery_pending: true,
        }
    }
}
fn map_device(d: StoredDeviceSnapshot, policy: Option<PolicyProjection>) -> DeviceSnapshot {
    DeviceSnapshot {
        device_id: d.device_id,
        first_seen_at: d.first_seen_at,
        last_seen_at: d.last_seen_at,
        owner_name: d.owner_name,
        owner_type: d.owner_type,
        owner_confirmed: d.owner_confirmed,
        presence: d.presence.map_or(
            Presence {
                state: PresenceState::Unknown,
                observed_at: None,
                source: None,
                kind: None,
            },
            |p| Presence {
                state: p.to_state,
                observed_at: Some(p.occurred_at),
                source: Some(p.trigger_source),
                kind: Some(p.trigger_kind),
            },
        ),
        evidence: d.evidence.map(|e| Evidence {
            family: e.family,
            source: e.source,
            confidence: e.confidence,
            observed_at: e.observed_at,
            expires_at: e.expires_at,
        }),
        identity: Identity {
            available: false,
            classification: None,
            confidence: None,
        },
        bandwidth: d.bandwidth.map_or(
            Bandwidth {
                available: false,
                upload: None,
                download: None,
                coverage: None,
                observed_at: None,
            },
            |b| Bandwidth {
                available: true,
                upload: Some(b.upload),
                download: Some(b.download),
                coverage: Some(b.coverage),
                observed_at: Some(b.observed_at),
            },
        ),
        policy,
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OwnerAction {
    Approve,
    Reject,
    Quarantine,
    ExtendOnce { until: DateTime<Utc> },
}
#[derive(Deserialize, ToSchema)]
pub struct PolicyActionRequest {
    pub device_id: DeviceId,
    pub action: OwnerAction,
}
#[derive(Serialize, ToSchema)]
pub struct PolicyActionResponse {
    pub evaluation: lattice_domain::Evaluation,
    pub enforcement_result: lattice_domain::EnforcementStatus,
}
#[utoipa::path(post, path = "/api/v1/policy/action", security(("bearer_auth" = [])), request_body = PolicyActionRequest, responses((status = 200, body = PolicyActionResponse), (status = 400), (status = 401), (status = 503)))]
pub async fn policy_action(
    _: Authorized,
    State(state): State<AppState>,
    Json(request): Json<PolicyActionRequest>,
) -> Result<Json<PolicyActionResponse>, StatusCode> {
    let coordinator = crate::policy::PolicyCoordinator::with_state(
        PolicyRepository::new(state.state_repository().pool().clone()),
        Some(state.events().clone()),
        state.state_repository().clone(),
    );
    let now = Utc::now();
    let result = match request.action {
        OwnerAction::Approve => coordinator.approve(request.device_id, now).await,
        OwnerAction::Reject => coordinator.reject(request.device_id, now).await,
        OwnerAction::Quarantine => coordinator.quarantine(request.device_id, now).await,
        OwnerAction::ExtendOnce { until } => {
            coordinator.extend_once(request.device_id, until, now).await
        }
    }
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(PolicyActionResponse {
        evaluation: result.evaluation,
        enforcement_result: result.enforcement,
    }))
}
#[utoipa::path(post, path = "/api/v1/events/ticket", security(("bearer_auth" = [])), responses((status = 200, body = EventTicket), (status = 401), (status = 429)))]
pub async fn event_ticket(
    _: Authorized,
    State(state): State<AppState>,
) -> Result<Json<EventTicket>, StatusCode> {
    let ticket = state
        .issue_event_ticket(Instant::now())
        .await
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    Ok(Json(EventTicket {
        ticket,
        expires_in_seconds: EVENT_TICKET_TTL.as_secs(),
    }))
}
#[derive(OpenApi)]
#[openapi(paths(health, state, policy_action, event_ticket, cameras, camera, camera_health, camera_inventory, device_advisories, crate::cameras::start_session_route, crate::cameras::snapshot_route, crate::cameras::playlist_route, crate::cameras::segment_route, crate::cameras::close_session_route), components(schemas(Health, Snapshot, DeviceSnapshot, PolicyProjection, Presence, Evidence, Identity, Bandwidth, EventTicket, PolicyActionRequest, PolicyActionResponse, OwnerAction, CameraSummary, CameraList, CameraDetail, CameraStreamProjection, CameraHealth, CameraInventoryProjection, CameraSessionRequest, CameraSessionResponse, BinaryMedia, AdvisoryList, AdvisoryProjection, AdvisoryRisk)), modifiers(&SecurityAddon))]
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
