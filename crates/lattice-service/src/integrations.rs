//! M6 integrations (I1–I2): scoped read-only integration tokens and the
//! versioned read surface they are confined to.
//!
//! Contract: docs/architecture/m6-remote-access-contracts.md.
//!
//! Integration tokens are the third principal: hash-stored bearer tokens
//! minted by the owner with an explicit scope set from {`devices:read`,
//! `presence:read`, `bandwidth:read`, `policy:read`}. They are accepted ONLY
//! under [`SURFACE_PREFIX`] — the remote-access layer authenticates them
//! there and rejects every other credential; everywhere else an integration
//! token is just a wrong bearer value and fails owner auth. MQTT publication
//! is out of scope for this release and recorded as pending in the contract.

use crate::tailscale::{RemoteAccessState, sha256_hex};
use crate::{AppState, auth::Authorized};
use axum::{
    Json,
    extract::{FromRequestParts, Path as AxumPath, Query, Request, State},
    http::{StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use lattice_domain::{Coverage, DeviceId, EventEnvelope, EventPayload, PresenceState};
use lattice_event_bus::Resume;
use lattice_store::{
    AuditActor, AuditCategory, AuditLog, NewAuditEntry, NewIntegrationToken, PolicyRepository,
    RemoteAccessRepository,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The only path prefix where integration tokens are accepted.
pub const SURFACE_PREFIX: &str = "/api/v1/integrations/v1/";

/// Longest long-poll wait the events feed grants.
const MAX_EVENT_WAIT_MS: u64 = 25_000;

// ---------------------------------------------------------------------------
// Scopes.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationScope {
    DevicesRead,
    PresenceRead,
    BandwidthRead,
    PolicyRead,
}

impl IntegrationScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DevicesRead => "devices:read",
            Self::PresenceRead => "presence:read",
            Self::BandwidthRead => "bandwidth:read",
            Self::PolicyRead => "policy:read",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "devices:read" => Some(Self::DevicesRead),
            "presence:read" => Some(Self::PresenceRead),
            "bandwidth:read" => Some(Self::BandwidthRead),
            "policy:read" => Some(Self::PolicyRead),
            _ => None,
        }
    }
}

/// The authenticated integration principal, inserted by
/// [`authorize_integration`] for requests under [`SURFACE_PREFIX`] only.
#[derive(Clone, Debug)]
pub struct IntegrationAuthorized {
    pub token_id: Uuid,
    pub scopes: Vec<IntegrationScope>,
}

/// Extractor for the read-surface handlers; absent principal means the
/// request bypassed the layer somehow, and is refused.
pub struct IntegrationPrincipal(pub IntegrationAuthorized);

impl<S: Send + Sync> FromRequestParts<S> for IntegrationPrincipal {
    type Rejection = Response;
    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let principal = parts.extensions.get::<IntegrationAuthorized>().cloned();
        async move {
            principal.map(Self).ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "Bearer")]).into_response()
            })
        }
    }
}

impl IntegrationPrincipal {
    /// 403 when the token's scope set does not include `scope`.
    fn require(&self, scope: IntegrationScope) -> Result<(), StatusCode> {
        if self.0.scopes.contains(&scope) {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// Authenticates the integration surface: exactly one `Bearer` token whose
/// SHA-256 matches a live integration token row. Owner bearers and phone
/// sessions are rejected here — this surface accepts ONLY integration
/// tokens (I1), and integration tokens are accepted ONLY here (I2).
pub(crate) async fn authorize_integration(
    remote: &RemoteAccessState,
    mut request: Request,
    next: Next,
) -> Response {
    let unauthorized =
        || (StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "Bearer")]).into_response();
    let values: Vec<_> = request
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .collect();
    let token = if values.len() == 1 {
        values[0]
            .to_str()
            .ok()
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    } else {
        None
    };
    let Some(token) = token else {
        return unauthorized();
    };
    let repository = RemoteAccessRepository::new(remote.pool().clone());
    let row = match repository.find_integration_token(&sha256_hex(&token)).await {
        Ok(Some(row)) => row,
        Ok(None) => return unauthorized(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if row.revoked {
        return unauthorized();
    }
    let scopes: Vec<IntegrationScope> = row
        .scopes
        .iter()
        .filter_map(|scope| IntegrationScope::parse(scope))
        .collect();
    request.extensions_mut().insert(IntegrationAuthorized {
        token_id: row.id,
        scopes,
    });
    next.run(request).await
}

// ---------------------------------------------------------------------------
// Token management (owner bearer only).
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MintTokenRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub name: String,
    /// Non-empty subset of {devices:read, presence:read, bandwidth:read, policy:read}.
    #[schema(min_items = 1, max_items = 4)]
    pub scopes: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct MintTokenResponse {
    #[schema(value_type = String, format = Uuid)]
    pub id: Uuid,
    #[schema(max_length = 128)]
    pub name: String,
    pub scopes: Vec<String>,
    /// Shown exactly once; only its SHA-256 is stored.
    #[schema(min_length = 64, max_length = 64)]
    pub token: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationTokenProjection {
    #[schema(value_type = String, format = Uuid)]
    pub id: Uuid,
    #[schema(max_length = 128)]
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationTokenList {
    pub items: Vec<IntegrationTokenProjection>,
}

fn random_token_hex() -> Result<String, ()> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0xf), 16).unwrap_or('0'));
    }
    Ok(out)
}

async fn append_token_audit(
    remote: &RemoteAccessState,
    action: &str,
    subject: String,
    detail: serde_json::Value,
) -> Result<(), ()> {
    let audit = AuditLog::new(remote.pool().clone());
    match audit
        .append(NewAuditEntry {
            occurred_at: Utc::now(),
            actor: AuditActor::Owner,
            category: AuditCategory::Approval,
            action: action.to_owned(),
            subject: Some(subject),
            detail,
        })
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => {
            tracing::error!(%error, action, "integration token audit append failed");
            Err(())
        }
    }
}

#[utoipa::path(post, path = "/api/v1/integrations/tokens", request_body = MintTokenRequest, responses((status = 200, body = MintTokenResponse), (status = 400), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn mint_token_route(
    _: Authorized,
    axum::Extension(remote): axum::Extension<RemoteAccessState>,
    body: Result<Json<MintTokenRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = body else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if request.name.is_empty() || request.name.len() > 128 || request.scopes.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let mut scopes = Vec::with_capacity(request.scopes.len());
    for scope in &request.scopes {
        let Some(parsed) = IntegrationScope::parse(scope) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        if !scopes.contains(&parsed) {
            scopes.push(parsed);
        }
    }
    let Ok(token) = random_token_hex() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let record = NewIntegrationToken {
        id: Uuid::new_v4(),
        name: request.name.clone(),
        token_hash: sha256_hex(&token),
        scopes: scopes
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect(),
        created_at: Utc::now(),
    };
    let repository = RemoteAccessRepository::new(remote.pool().clone());
    if repository.insert_integration_token(&record).await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let audited = append_token_audit(
        &remote,
        "integration_token_minted",
        record.id.to_string(),
        serde_json::json!({ "name": record.name, "scopes": record.scopes }),
    )
    .await;
    if audited.is_err() {
        // An unaudited token must not exist: withdraw it.
        let _ = repository.revoke_integration_token(record.id).await;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(MintTokenResponse {
        id: record.id,
        name: record.name,
        scopes: record.scopes,
        token,
        created_at: record.created_at,
    })
    .into_response()
}

#[utoipa::path(get, path = "/api/v1/integrations/tokens", responses((status = 200, body = IntegrationTokenList), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn list_tokens_route(
    _: Authorized,
    axum::Extension(remote): axum::Extension<RemoteAccessState>,
) -> Response {
    let repository = RemoteAccessRepository::new(remote.pool().clone());
    match repository.list_integration_tokens().await {
        Ok(rows) => Json(IntegrationTokenList {
            items: rows
                .into_iter()
                .map(|row| IntegrationTokenProjection {
                    id: row.id,
                    name: row.name,
                    scopes: row.scopes,
                    created_at: row.created_at,
                    revoked: row.revoked,
                })
                .collect(),
        })
        .into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[utoipa::path(delete, path = "/api/v1/integrations/tokens/{id}", params(("id" = String, Path, format = Uuid)), responses((status = 204), (status = 400), (status = 401), (status = 404), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn revoke_token_route(
    _: Authorized,
    axum::Extension(remote): axum::Extension<RemoteAccessState>,
    path: Result<AxumPath<String>, axum::extract::rejection::PathRejection>,
) -> Response {
    let Ok(AxumPath(id)) = path else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let repository = RemoteAccessRepository::new(remote.pool().clone());
    match repository.revoke_integration_token(id).await {
        Ok(true) => {
            // Revocation only removes access; it stands even if the audit
            // append fails, surfaced as 503.
            let audited = append_token_audit(
                &remote,
                "integration_token_revoked",
                id.to_string(),
                serde_json::json!({}),
            )
            .await;
            if audited.is_err() {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Read surface (integration tokens only, per-scope).
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct IntegrationDevice {
    pub device_id: DeviceId,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    #[schema(max_length = 256)]
    pub owner_name: Option<String>,
    #[schema(max_length = 64)]
    pub owner_type: Option<String>,
    pub owner_confirmed: bool,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationDeviceList {
    pub items: Vec<IntegrationDevice>,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationPresence {
    pub device_id: DeviceId,
    pub state: PresenceState,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationPresenceList {
    pub items: Vec<IntegrationPresence>,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationBandwidth {
    pub device_id: DeviceId,
    pub upload: u64,
    pub download: u64,
    pub coverage: Coverage,
    pub observed_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationBandwidthList {
    pub items: Vec<IntegrationBandwidth>,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationPolicy {
    pub device_id: DeviceId,
    pub owner_decision: lattice_domain::OwnerDecision,
    pub protection: lattice_domain::Protection,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationPolicyList {
    pub items: Vec<IntegrationPolicy>,
}

async fn snapshots(state: &AppState) -> Result<Vec<lattice_store::StoredDeviceSnapshot>, Response> {
    state
        .state_repository()
        .list_device_snapshots(lattice_store::MAX_SNAPSHOT_DEVICES, None)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())
}

#[utoipa::path(get, path = "/api/v1/integrations/v1/devices", responses((status = 200, body = IntegrationDeviceList), (status = 401), (status = 403), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn devices_route(
    principal: IntegrationPrincipal,
    State(state): State<AppState>,
) -> Response {
    if let Err(status) = principal.require(IntegrationScope::DevicesRead) {
        return status.into_response();
    }
    let devices = match snapshots(&state).await {
        Ok(devices) => devices,
        Err(response) => return response,
    };
    Json(IntegrationDeviceList {
        items: devices
            .into_iter()
            .map(|device| IntegrationDevice {
                device_id: device.device_id,
                first_seen_at: device.first_seen_at,
                last_seen_at: device.last_seen_at,
                owner_name: device.owner_name,
                owner_type: device.owner_type,
                owner_confirmed: device.owner_confirmed,
            })
            .collect(),
    })
    .into_response()
}

#[utoipa::path(get, path = "/api/v1/integrations/v1/presence", responses((status = 200, body = IntegrationPresenceList), (status = 401), (status = 403), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn presence_route(
    principal: IntegrationPrincipal,
    State(state): State<AppState>,
) -> Response {
    if let Err(status) = principal.require(IntegrationScope::PresenceRead) {
        return status.into_response();
    }
    let devices = match snapshots(&state).await {
        Ok(devices) => devices,
        Err(response) => return response,
    };
    Json(IntegrationPresenceList {
        items: devices
            .into_iter()
            .map(|device| match device.presence {
                Some(presence) => IntegrationPresence {
                    device_id: device.device_id,
                    state: presence.to_state,
                    observed_at: Some(presence.occurred_at),
                },
                None => IntegrationPresence {
                    device_id: device.device_id,
                    state: PresenceState::Unknown,
                    observed_at: None,
                },
            })
            .collect(),
    })
    .into_response()
}

#[utoipa::path(get, path = "/api/v1/integrations/v1/bandwidth", responses((status = 200, body = IntegrationBandwidthList), (status = 401), (status = 403), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn bandwidth_route(
    principal: IntegrationPrincipal,
    State(state): State<AppState>,
) -> Response {
    if let Err(status) = principal.require(IntegrationScope::BandwidthRead) {
        return status.into_response();
    }
    let devices = match snapshots(&state).await {
        Ok(devices) => devices,
        Err(response) => return response,
    };
    Json(IntegrationBandwidthList {
        items: devices
            .into_iter()
            .filter_map(|device| {
                device.bandwidth.map(|bandwidth| IntegrationBandwidth {
                    device_id: device.device_id,
                    upload: bandwidth.upload,
                    download: bandwidth.download,
                    coverage: bandwidth.coverage,
                    observed_at: bandwidth.observed_at,
                })
            })
            .collect(),
    })
    .into_response()
}

#[utoipa::path(get, path = "/api/v1/integrations/v1/policy", responses((status = 200, body = IntegrationPolicyList), (status = 401), (status = 403), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn policy_route(
    principal: IntegrationPrincipal,
    State(state): State<AppState>,
) -> Response {
    if let Err(status) = principal.require(IntegrationScope::PolicyRead) {
        return status.into_response();
    }
    let devices = match snapshots(&state).await {
        Ok(devices) => devices,
        Err(response) => return response,
    };
    let policy = PolicyRepository::new(state.state_repository().pool().clone());
    let mut items = Vec::with_capacity(devices.len());
    for device in devices {
        match policy.load(device.device_id).await {
            Ok(Some(row)) => items.push(IntegrationPolicy {
                device_id: device.device_id,
                owner_decision: row.owner_decision,
                protection: row.protection,
            }),
            Ok(None) => {}
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }
    Json(IntegrationPolicyList { items }).into_response()
}

// ---------------------------------------------------------------------------
// Events long-poll.
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationEventsQuery {
    pub after_sequence: u64,
    /// Long-poll wait when no scoped events are pending (capped at 25s).
    pub wait_ms: Option<u64>,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationEvents {
    /// True when the cursor predates the replay window; the client must
    /// refetch snapshots and resume from `next_after`.
    pub resync: bool,
    #[schema(value_type = Vec<Object>)]
    pub events: Vec<EventEnvelope>,
    pub next_after: u64,
}

fn scope_allows(scopes: &[IntegrationScope], payload: &EventPayload) -> bool {
    match payload {
        EventPayload::PresenceChanged(_) => scopes.contains(&IntegrationScope::PresenceRead),
        EventPayload::BandwidthFrame(_) => scopes.contains(&IntegrationScope::BandwidthRead),
        EventPayload::PolicyChanged(_) => scopes.contains(&IntegrationScope::PolicyRead),
        // Service/home events are not part of the integration surface.
        EventPayload::ServiceStatus(_) | EventPayload::HomeChanged(_) => false,
    }
}

#[utoipa::path(get, path = "/api/v1/integrations/v1/events", params(("after_sequence" = u64, Query), ("wait_ms" = Option<u64>, Query, maximum = 25000)), responses((status = 200, body = IntegrationEvents), (status = 400), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn events_route(
    principal: IntegrationPrincipal,
    State(state): State<AppState>,
    query: Result<Query<IntegrationEventsQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    // Any valid integration token may long-poll; each envelope is filtered
    // to the token's scopes, so an out-of-scope payload is never serialized.
    let Ok(Query(query)) = query else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let scopes = principal.0.scopes.clone();
    let bus = state.events().clone();
    // Subscribe before replay so no event is lost between the two reads.
    let mut receiver = bus.subscribe();
    let (mut visible, mut next_after) = match bus.resume_after(query.after_sequence).await {
        Resume::SnapshotRequired => {
            return Json(IntegrationEvents {
                resync: true,
                events: Vec::new(),
                next_after: bus.current_sequence().await,
            })
            .into_response();
        }
        Resume::Events(events) => {
            let mut next_after = query.after_sequence;
            let mut visible = Vec::new();
            for event in events {
                next_after = event.sequence;
                if scope_allows(&scopes, &event.payload) {
                    visible.push(event);
                }
            }
            (visible, next_after)
        }
    };
    let wait = std::time::Duration::from_millis(query.wait_ms.unwrap_or(0).min(MAX_EVENT_WAIT_MS));
    if visible.is_empty() && !wait.is_zero() {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let event = match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Err(_) => break,
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                    return Json(IntegrationEvents {
                        resync: true,
                        events: Vec::new(),
                        next_after: bus.current_sequence().await,
                    })
                    .into_response();
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
                Ok(Ok(event)) => event,
            };
            if event.sequence <= next_after {
                continue;
            }
            next_after = event.sequence;
            if scope_allows(&scopes, &event.payload) {
                visible.push(event);
                break;
            }
        }
    }
    Json(IntegrationEvents {
        resync: false,
        events: visible,
        next_after,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_round_trip_and_reject_unknown_values() {
        for scope in [
            IntegrationScope::DevicesRead,
            IntegrationScope::PresenceRead,
            IntegrationScope::BandwidthRead,
            IntegrationScope::PolicyRead,
        ] {
            assert_eq!(IntegrationScope::parse(scope.as_str()), Some(scope));
        }
        assert_eq!(IntegrationScope::parse("vault:read"), None);
        assert_eq!(IntegrationScope::parse("devices:write"), None);
    }

    #[test]
    fn event_scope_filter_only_serves_scoped_payload_types() {
        use lattice_domain::ServiceStatus;
        let all = [
            IntegrationScope::DevicesRead,
            IntegrationScope::PresenceRead,
            IntegrationScope::BandwidthRead,
            IntegrationScope::PolicyRead,
        ];
        let service_status = EventPayload::ServiceStatus(ServiceStatus {
            state: "ready".into(),
            detail: "test".into(),
        });
        // Service status and home events never reach integrations, even with
        // every scope granted.
        assert!(!scope_allows(&all, &service_status));
        let bandwidth = EventPayload::BandwidthFrame(lattice_domain::BandwidthFrame {
            interval_ms: 1000,
            observed_at: Utc::now(),
            emitted_at: Utc::now(),
            samples: Vec::new(),
        });
        assert!(scope_allows(&all, &bandwidth));
        assert!(!scope_allows(&[IntegrationScope::PolicyRead], &bandwidth));
    }
}
