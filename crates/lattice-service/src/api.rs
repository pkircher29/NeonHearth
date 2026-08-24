use crate::{AppState, auth::Authorized, state::EVENT_TICKET_TTL};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use lattice_domain::{Coverage, DeviceId, EvidenceFamily, PresenceState};
use lattice_store::StoredDeviceSnapshot;
use serde::Deserialize;
use serde::Serialize;
use tokio::time::Instant;
use utoipa::{Modify, OpenApi, ToSchema};
#[derive(Serialize, ToSchema)]
pub struct Health {
    pub status: &'static str,
    pub api_version: &'static str,
}
#[derive(Serialize, ToSchema)]
pub struct Snapshot {
    pub sequence: u64,
    pub devices: Vec<DeviceSnapshot>,
    pub next_after: Option<DeviceId>,
    pub service_status: &'static str,
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
    Ok(Json(Snapshot {
        sequence,
        devices: devices.into_iter().map(map_device).collect(),
        next_after,
        service_status: "ready",
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
fn map_device(d: StoredDeviceSnapshot) -> DeviceSnapshot {
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
    }
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
#[openapi(paths(health, state, event_ticket), components(schemas(Health, Snapshot, DeviceSnapshot, Presence, Evidence, Identity, Bandwidth, EventTicket)), modifiers(&SecurityAddon))]
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
