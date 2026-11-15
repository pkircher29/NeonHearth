//! Bounded home-automation boundary. LAN presence and HA availability are distinct.
pub mod ha;
pub mod network;

use crate::AppState;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequestParts, State, rejection::JsonRejection},
    http::{HeaderValue, StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use chrono::{DateTime, Utc};
use lattice_store::{AuditActor, AuditCategory, AuditLog, NewAuditEntry};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
use std::{collections::BTreeSet, sync::Arc};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

const MAX_DEVICES: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[schema(as = AutomationEntity)]
pub struct Entity {
    pub entity_id: String,
    pub name: String,
    pub state: String,
    pub last_changed: Option<String>,
    pub last_updated: Option<String>,
    pub area: Option<String>,
    pub platform: Option<String>,
    pub power_capable: bool,
    #[serde(default)]
    pub control_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[schema(as = AutomationDevice)]
pub struct Device {
    pub device_id: String,
    pub upstream_id: String,
    pub name: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub area: Option<String>,
    pub mac_addresses: Vec<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub entities: Vec<Entity>,
}

#[derive(Clone, Serialize, ToSchema)]
#[schema(as = AutomationSnapshot)]
pub struct Snapshot {
    pub mqtt: crate::mqtt::MqttStatus,
    pub status: String,
    pub detail: String,
    pub source: Option<String>,
    pub updated_at: Option<String>,
    pub devices: Vec<Device>,
    pub areas: Vec<String>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            mqtt: crate::mqtt::MqttStatus::default(),
            status: "disconnected".into(),
            detail: "Connect Home Assistant to import devices and rooms.".into(),
            source: None,
            updated_at: None,
            devices: vec![],
            areas: vec![],
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(ToSchema)]
#[schema(as = AutomationConnectRequest)]
pub struct ConnectRequest {
    pub url: String,
    #[serde(deserialize_with = "read_secret")]
    #[schema(value_type = String, write_only = true)]
    pub access_token: SecretString,
}
fn read_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretString, D::Error> {
    String::deserialize(deserializer).map(SecretString::from)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(ToSchema)]
#[schema(as = AutomationPermissionRequest)]
pub struct PermissionRequest {
    pub entity_ids: Vec<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(ToSchema)]
#[schema(as = AutomationCommandRequest)]
pub struct CommandRequest {
    pub command_id: Uuid,
    pub entity_id: String,
    pub action: PowerAction,
    pub expected_last_changed: String,
    pub issued_at: DateTime<Utc>,
    pub confirmed: bool,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[derive(ToSchema)]
pub enum PowerAction {
    TurnOn,
    TurnOff,
}
impl PowerAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TurnOn => "turn_on",
            Self::TurnOff => "turn_off",
        }
    }
}
#[derive(Clone, Debug, Serialize, ToSchema)]
#[schema(as = AutomationReceipt)]
pub struct Receipt {
    pub command_id: Uuid,
    pub status: String,
    pub detail: String,
}
pub(crate) struct QueuedCommand {
    pub request: CommandRequest,
    pub result: oneshot::Sender<Result<Receipt, StatusCode>>,
}

struct Session {
    snapshot: Snapshot,
    permissions: BTreeSet<String>,
    cancel: CancellationToken,
    commands: Option<mpsc::Sender<QueuedCommand>>,
    last_connect: Option<tokio::time::Instant>,
    /// Set when the last import had to drop records to stay within bounds.
    truncated: Option<String>,
}
#[derive(Clone)]
pub struct AutomationHub {
    pub(crate) pool: SqlitePool,
    session: Arc<Mutex<Session>>,
    configuration: Arc<Mutex<()>>,
    network_cache: Arc<Mutex<Option<network::CachedNetwork>>>,
    command_timeout_ms: Arc<std::sync::atomic::AtomicU64>,
}
impl AutomationHub {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            session: Arc::new(Mutex::new(Session {
                snapshot: Snapshot::default(),
                permissions: BTreeSet::new(),
                cancel: CancellationToken::new(),
                commands: None,
                last_connect: None,
                truncated: None,
            })),
            configuration: Arc::new(Mutex::new(())),
            network_cache: Arc::new(Mutex::new(None)),
            command_timeout_ms: Arc::new(std::sync::atomic::AtomicU64::new(20_000)),
        }
    }
    /// How long a caller waits for an appliance command before giving up. A
    /// command whose caller gave up is dropped, never sent late.
    #[doc(hidden)]
    pub fn set_command_timeout(&self, timeout: std::time::Duration) {
        let millis = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.command_timeout_ms
            .store(millis, std::sync::atomic::Ordering::Relaxed);
    }
    pub async fn snapshot(&self) -> Result<Snapshot, StatusCode> {
        let (mut snapshot, permissions, truncated) = {
            let state = self.session.lock().await;
            (
                state.snapshot.clone(),
                state.permissions.clone(),
                state.truncated.clone(),
            )
        };
        if snapshot.devices.is_empty() && snapshot.source.is_none() {
            // The stored-inventory fallback is read without the session lock
            // so a slow database never stalls live state events or commands.
            let rows = sqlx::query(
                "SELECT metadata FROM automation_inventory ORDER BY last_seen_at DESC LIMIT 4096",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            for row in rows {
                // One unreadable stored row must not hide the rest.
                let Ok(mut device) = serde_json::from_str::<Device>(row.get::<&str, _>("metadata"))
                else {
                    tracing::warn!("skipping unreadable stored automation inventory row");
                    continue;
                };
                for entity in &mut device.entities {
                    entity.control_enabled = false;
                }
                snapshot.devices.push(device);
            }
            if !snapshot.devices.is_empty() {
                snapshot.detail =
                    "Disconnected. Showing the last imported inventory; availability is unknown."
                        .into();
            }
        }
        if let Some(note) = truncated {
            snapshot.detail = format!("{} {note}", snapshot.detail);
        }
        for device in &mut snapshot.devices {
            for entity in &mut device.entities {
                entity.control_enabled =
                    snapshot.status == "connected" && permissions.contains(&entity.entity_id);
            }
        }
        Ok(snapshot)
    }
    pub async fn connect(&self, request: ConnectRequest) -> Result<(), StatusCode> {
        use secrecy::ExposeSecret;
        let url = ha::validate_url(&request.url).map_err(|_| StatusCode::BAD_REQUEST)?;
        let secret = request.access_token.expose_secret();
        if !(16..=4096).contains(&secret.len()) || secret.chars().any(char::is_control) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let _configuration = self
            .configuration
            .try_lock()
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        if self
            .session
            .lock()
            .await
            .last_connect
            .is_some_and(|last| last.elapsed().as_secs() < 5)
        {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        // Granting authority is audit-first, and the audit write happens
        // without the session lock held. The configuration lock keeps other
        // connect/disconnect/permission changes out meanwhile.
        self.audit(
            "automation.connect",
            None,
            json!({"transport":"home_assistant"}),
        )
        .await?;
        let mut state = self.session.lock().await;
        state.cancel.cancel();
        let cancel = CancellationToken::new();
        let (sender, receiver) = mpsc::channel(16);
        state.snapshot = Snapshot {
            mqtt: state.snapshot.mqtt.clone(),
            status: "connecting".into(),
            detail: "Authenticating and importing Home Assistant inventory.".into(),
            source: Some(url.to_string()),
            ..Snapshot::default()
        };
        state.permissions.clear();
        state.truncated = None;
        state.commands = Some(sender);
        state.cancel = cancel.clone();
        state.last_connect = Some(tokio::time::Instant::now());
        drop(state);
        tokio::spawn(ha::run(
            self.clone(),
            url,
            request.access_token,
            cancel,
            receiver,
        ));
        Ok(())
    }
    /// Disconnects and revokes every appliance permission. Revocation is
    /// applied first and unconditionally; the audit entry is best-effort so an
    /// unhealthy audit store can never keep control authority alive. Returns
    /// whether the audit entry was recorded.
    pub async fn disconnect_audited(&self) -> bool {
        let _configuration = self.configuration.lock().await;
        {
            let mut state = self.session.lock().await;
            state.cancel.cancel();
            state.commands = None;
            state.permissions.clear();
            state.snapshot.status = "disconnected".into();
            state.snapshot.detail =
                "Disconnected. Last imported values are historical; availability is unknown."
                    .into();
        }
        let recorded = self
            .audit("automation.disconnect", None, json!({}))
            .await
            .is_ok();
        if !recorded {
            tracing::error!(
                "automation disconnect applied but its audit entry could not be recorded"
            );
            self.session.lock().await.snapshot.detail =
                "Disconnected. The audit entry for this change could not be recorded; check the audit log health."
                    .into();
        }
        recorded
    }
    pub async fn disconnect(&self) -> Result<(), StatusCode> {
        self.disconnect_audited().await;
        Ok(())
    }
    pub async fn mqtt_status(&self, status: &str, detail: &str) {
        self.session.lock().await.snapshot.mqtt = crate::mqtt::MqttStatus {
            status: status.into(),
            detail: detail.into(),
        };
    }
    pub async fn permissions(&self, request: PermissionRequest) -> Result<(), StatusCode> {
        self.permissions_audited(request).await.map(|_| ())
    }
    /// Replaces the set of controllable entities. Narrowing (or clearing) the
    /// set is applied first and audited best-effort; granting any new entity
    /// is audit-first. Returns whether the audit entry was recorded.
    pub async fn permissions_audited(
        &self,
        request: PermissionRequest,
    ) -> Result<bool, StatusCode> {
        let _configuration = self.configuration.lock().await;
        if request.entity_ids.len() > 256 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let next: BTreeSet<_> = request.entity_ids.into_iter().collect();
        let validate = |state: &Session| -> Result<bool, StatusCode> {
            if state.snapshot.status != "connected" {
                return Err(StatusCode::CONFLICT);
            }
            if !next.iter().all(|id| {
                state
                    .snapshot
                    .devices
                    .iter()
                    .flat_map(|d| &d.entities)
                    .any(|e| &e.entity_id == id && e.power_capable)
            }) {
                return Err(StatusCode::BAD_REQUEST);
            }
            Ok(next.iter().all(|id| state.permissions.contains(id)))
        };
        let narrowing = {
            let mut state = self.session.lock().await;
            let narrowing = validate(&state)?;
            if narrowing {
                state.permissions = next.clone();
            }
            narrowing
        };
        if narrowing {
            let recorded = self
                .audit("automation.permissions", None, json!({"entities":next}))
                .await
                .is_ok();
            if !recorded {
                tracing::error!(
                    "automation permissions narrowed but the audit entry could not be recorded"
                );
            }
            return Ok(recorded);
        }
        self.audit("automation.permissions", None, json!({"entities":next}))
            .await?;
        let mut state = self.session.lock().await;
        // The inventory may have refreshed while the audit entry was written.
        validate(&state)?;
        state.permissions = next;
        Ok(true)
    }
    pub async fn command(&self, request: CommandRequest) -> Result<Receipt, StatusCode> {
        let age = Utc::now()
            .signed_duration_since(request.issued_at)
            .num_seconds();
        if !request.confirmed
            || !(-5..=60).contains(&age)
            || !ha::valid_entity_id(&request.entity_id)
            || request.expected_last_changed.len() > 64
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let state = self.session.lock().await;
        if state.snapshot.status != "connected" {
            return Err(StatusCode::CONFLICT);
        }
        let sender = state.commands.as_ref().ok_or(StatusCode::CONFLICT)?.clone();
        drop(state);
        let (result, receive) = oneshot::channel();
        sender
            .try_send(QueuedCommand { request, result })
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        tokio::time::timeout(
            std::time::Duration::from_millis(
                self.command_timeout_ms
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
            receive,
        )
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    }
    pub(crate) async fn audit(
        &self,
        action: &str,
        subject: Option<String>,
        detail: Value,
    ) -> Result<(), StatusCode> {
        AuditLog::new(self.pool.clone())
            .append(NewAuditEntry {
                occurred_at: Utc::now(),
                actor: AuditActor::Owner,
                category: AuditCategory::Approval,
                action: action.into(),
                subject,
                detail,
            })
            .await
            .map(|_| ())
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }
    pub(crate) async fn set_status(&self, cancel: &CancellationToken, status: &str, detail: &str) {
        let mut state = self.session.lock().await;
        if cancel.is_cancelled() {
            return;
        }
        state.snapshot.status = status.into();
        state.snapshot.detail = detail.into();
        if status != "connected" {
            state.permissions.clear();
        }
    }
    pub(crate) async fn import(
        &self,
        cancel: &CancellationToken,
        source: &str,
        mut devices: Vec<Device>,
        areas: Vec<String>,
        truncated: Option<String>,
    ) -> Result<(), ()> {
        if devices.len() > MAX_DEVICES || cancel.is_cancelled() {
            return Err(());
        }
        // Persist first, without the session lock: a slow or busy database
        // must not stall live state events, snapshots or appliance commands.
        let mut tx = self.pool.begin().await.map_err(|_| ())?;
        for device in &mut devices {
            let previous: Option<(String, String)> = sqlx::query_as("SELECT device_id,first_seen_at FROM automation_inventory WHERE source=? AND upstream_id=?").bind(source).bind(&device.upstream_id).fetch_optional(&mut *tx).await.map_err(|_| ())?;
            if let Some((id, first)) = previous {
                device.device_id = id;
                device.first_seen_at = first;
            }
            sqlx::query("INSERT INTO automation_inventory(source,upstream_id,device_id,first_seen_at,last_seen_at,metadata) VALUES(?,?,?,?,?,?) ON CONFLICT(source,upstream_id) DO UPDATE SET last_seen_at=excluded.last_seen_at,metadata=excluded.metadata")
                .bind(source).bind(&device.upstream_id).bind(&device.device_id).bind(&device.first_seen_at).bind(&device.last_seen_at).bind(serde_json::to_string(device).map_err(|_| ())?).execute(&mut *tx).await.map_err(|_| ())?;
        }
        tx.commit().await.map_err(|_| ())?;
        let mut state = self.session.lock().await;
        if cancel.is_cancelled() {
            return Err(());
        }
        // A registry remap must not carry an old permission to a new device.
        let safe_permissions: BTreeSet<String> = state
            .permissions
            .iter()
            .filter(|id| {
                let old = state.snapshot.devices.iter().find_map(|d| {
                    d.entities
                        .iter()
                        .find(|e| &e.entity_id == *id)
                        .map(|e| (&d.device_id, &e.platform))
                });
                let new = devices.iter().find_map(|d| {
                    d.entities
                        .iter()
                        .find(|e| &e.entity_id == *id && e.power_capable)
                        .map(|e| (&d.device_id, &e.platform))
                });
                old.is_some() && old == new
            })
            .cloned()
            .collect();
        state.permissions = safe_permissions;
        state.snapshot.devices = devices;
        state.snapshot.areas = areas;
        state.snapshot.updated_at = Some(Utc::now().to_rfc3339());
        state.truncated = truncated;
        Ok(())
    }
    pub(crate) async fn state_event(&self, cancel: &CancellationToken, event: &Value) {
        let data = &event["event"]["data"];
        let Some(id) = data["entity_id"].as_str() else {
            return;
        };
        let next = &data["new_state"];
        let mut state = self.session.lock().await;
        if cancel.is_cancelled() {
            return;
        }
        for device in &mut state.snapshot.devices {
            for entity in &mut device.entities {
                if entity.entity_id == id {
                    let updated = ha::text(&next["last_updated"], 64);
                    if let (Some(old), Some(new)) = (&entity.last_updated, &updated)
                        && let (Ok(old), Ok(new)) = (
                            DateTime::parse_from_rfc3339(old),
                            DateTime::parse_from_rfc3339(new),
                        )
                        && new < old
                    {
                        continue;
                    }
                    entity.state =
                        ha::text(&next["state"], 128).unwrap_or_else(|| "unavailable".into());
                    entity.last_changed = ha::text(&next["last_changed"], 64);
                    entity.last_updated = updated;
                    device.last_seen_at = Utc::now().to_rfc3339();
                }
            }
        }
        state.snapshot.updated_at = Some(Utc::now().to_rfc3339());
    }
    pub(crate) async fn authorize_command(
        &self,
        request: &CommandRequest,
        verify_observation: bool,
    ) -> Result<String, StatusCode> {
        let state = self.session.lock().await;
        if state.snapshot.status != "connected" || !state.permissions.contains(&request.entity_id) {
            return Err(StatusCode::FORBIDDEN);
        }
        let entity = state
            .snapshot
            .devices
            .iter()
            .flat_map(|d| &d.entities)
            .find(|e| e.entity_id == request.entity_id)
            .ok_or(StatusCode::NOT_FOUND)?;
        if !entity.power_capable
            || (verify_observation
                && (!matches!(entity.state.as_str(), "on" | "off")
                    || entity.last_changed.as_deref()
                        != Some(request.expected_last_changed.as_str())))
        {
            return Err(StatusCode::CONFLICT);
        }
        state.snapshot.source.clone().ok_or(StatusCode::CONFLICT)
    }
}

/// Local owner authority only. Phone and integration principals cannot reconfigure
/// integrations or switch appliances through an implicit privilege upgrade.
pub(crate) struct LocalOwner;
impl FromRequestParts<AppState> for LocalOwner {
    type Rejection = StatusCode;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let values: Vec<_> = parts.headers.get_all("authorization").iter().collect();
        if values.len() == 1
            && values[0]
                .to_str()
                .ok()
                .and_then(|v| v.strip_prefix("Bearer "))
                .is_some_and(|v| state.token_matches(v))
        {
            Ok(Self)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/automation", get(snapshot_route))
        .route("/api/v1/automation/network", get(network::network_route))
        .route("/api/v1/automation/connect", post(connect_route))
        .route("/api/v1/automation/disconnect", post(disconnect_route))
        .route("/api/v1/automation/permissions", put(permissions_route))
        .route("/api/v1/automation/commands", post(command_route))
        .layer(DefaultBodyLimit::max(16 * 1024))
}
#[utoipa::path(get, path = "/api/v1/automation", responses((status=200,body=Snapshot),(status=401)), security(("bearer_auth"=[])))]
pub(crate) async fn snapshot_route(_: LocalOwner, State(state): State<AppState>) -> Response {
    match state.automation().snapshot().await {
        Ok(value) => Json(value).into_response(),
        Err(status) => status.into_response(),
    }
}
/// Problem body for a request body the extractor refused (bad JSON, wrong
/// content type, oversize): the rejection's own status with a stable shape.
pub(crate) fn body_rejection(rejection: &JsonRejection) -> Response {
    (
        rejection.status(),
        Json(json!({"error": "the request body was rejected"})),
    )
        .into_response()
}

/// Response header set when a revoking change was applied but its audit entry
/// could not be recorded.
pub const AUDIT_WARNING_HEADER: &str = "x-audit-warning";

fn with_audit_warning(status: StatusCode, recorded: bool) -> Response {
    let mut response = status.into_response();
    if !recorded {
        response.headers_mut().insert(
            AUDIT_WARNING_HEADER,
            HeaderValue::from_static("change-applied-audit-unavailable"),
        );
    }
    response
}

#[utoipa::path(post, path = "/api/v1/automation/connect", request_body=ConnectRequest, responses((status=202),(status=400),(status=401),(status=429)), security(("bearer_auth"=[])))]
pub(crate) async fn connect_route(
    _: LocalOwner,
    State(state): State<AppState>,
    body: Result<Json<ConnectRequest>, JsonRejection>,
) -> Response {
    let request = match body {
        Ok(Json(request)) => request,
        Err(rejection) => return body_rejection(&rejection),
    };
    match state.automation().connect(request).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(status) => status.into_response(),
    }
}
#[utoipa::path(post, path = "/api/v1/automation/disconnect", responses((status=204),(status=401)), security(("bearer_auth"=[])))]
pub(crate) async fn disconnect_route(_: LocalOwner, State(state): State<AppState>) -> Response {
    let recorded = state.automation().disconnect_audited().await;
    with_audit_warning(StatusCode::NO_CONTENT, recorded)
}
#[utoipa::path(put, path = "/api/v1/automation/permissions", request_body=PermissionRequest, responses((status=204),(status=400),(status=401),(status=409)), security(("bearer_auth"=[])))]
pub(crate) async fn permissions_route(
    _: LocalOwner,
    State(state): State<AppState>,
    body: Result<Json<PermissionRequest>, JsonRejection>,
) -> Response {
    let request = match body {
        Ok(Json(request)) => request,
        Err(rejection) => return body_rejection(&rejection),
    };
    match state.automation().permissions_audited(request).await {
        Ok(recorded) => with_audit_warning(StatusCode::NO_CONTENT, recorded),
        Err(status) => status.into_response(),
    }
}
#[utoipa::path(post, path = "/api/v1/automation/commands", request_body=CommandRequest, responses((status=200,body=Receipt),(status=400),(status=401),(status=403),(status=409)), security(("bearer_auth"=[])))]
pub(crate) async fn command_route(
    _: LocalOwner,
    State(state): State<AppState>,
    body: Result<Json<CommandRequest>, JsonRejection>,
) -> Response {
    let request = match body {
        Ok(Json(request)) => request,
        Err(rejection) => return body_rejection(&rejection),
    };
    match state.automation().command(request).await {
        Ok(value) => Json(value).into_response(),
        Err(status) => status.into_response(),
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        snapshot_route,
        network::network_route,
        connect_route,
        disconnect_route,
        permissions_route,
        command_route
    ),
    components(schemas(
        Snapshot,
        Device,
        Entity,
        ConnectRequest,
        PermissionRequest,
        CommandRequest,
        PowerAction,
        Receipt,
        crate::mqtt::MqttStatus,
        network::NetworkDetails,
        network::NetworkDeviceDetails,
        network::NetworkIdentityHint
    ))
)]
pub struct AutomationApiDoc;
