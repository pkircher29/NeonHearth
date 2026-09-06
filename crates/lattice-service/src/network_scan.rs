//! Owner-started read-only discovery of addresses freshly correlated to local neighbors.
//! Advertisements and open ports never grant identity, ownership, or control permissions.
use crate::{AppState, automation::LocalOwner};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::Utc;
use futures_util::{StreamExt, stream};
use lattice_sensor::{
    Address, InterfaceId, SystemInterfaceManager, TargetApproval, TargetGuard,
    active::{
        self, ActiveEngine, ProbeCredential, ProbeMode, ProbeOutcome, ProbeRequest,
        SnmpAuthProtocol, SnmpAuthentication, SnmpPrivProtocol, SnmpPrivacy, SystemTransport,
    },
    neighbor::{NeighborSnapshotSource, SystemNeighborSnapshotSource},
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Mutex, time::Instant};
use tokio_util::sync::CancellationToken;
use utoipa::ToSchema;
use zeroize::Zeroize;

const MAX_DEVICES: usize = 1024;
mod avahi;
mod capture;
const MAX_FINDINGS: usize = 4096;
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 88, 110, 135, 139, 143, 443, 445, 465, 515, 554, 587, 631, 800,
    993, 995, 1025, 1433, 1883, 1900, 2000, 3000, 3306, 3389, 5000, 5001, 5002, 5357, 5432, 5671,
    5672, 5683, 5800, 5900, 6000, 6379, 6443, 7000, 7001, 8000, 8008, 8009, 8080, 8081, 8088, 8090,
    8123, 8181, 8200, 8443, 8554, 8883, 8888, 9000, 9090, 9100, 9443, 10000, 27017, 32400,
];

#[derive(Clone, Copy, Deserialize, Serialize, ToSchema, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Icmp,
    Mdns,
    Smb,
    Netbios,
    Snmp,
}
#[derive(Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PortMode {
    #[default]
    Common,
    All,
    Custom,
    None,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    #[serde(default)]
    pub device_ids: Vec<String>,
    #[serde(default)]
    pub port_mode: PortMode,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub protocols: Vec<Protocol>,
    pub snmp: Option<SnmpInput>,
}
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SnmpInput {
    pub version: String,
    #[serde(default)]
    #[schema(write_only)]
    pub community: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    #[schema(write_only)]
    pub authentication_password: String,
    #[serde(default)]
    #[schema(write_only)]
    pub privacy_password: String,
}
impl Drop for SnmpInput {
    fn drop(&mut self) {
        self.community.zeroize();
        self.username.zeroize();
        self.authentication_password.zeroize();
        self.privacy_password.zeroize();
    }
}
impl SnmpInput {
    fn credential(&self) -> Result<ProbeCredential, StatusCode> {
        let bounded =
            |s: &str, min| s.len() >= min && s.len() <= 128 && !s.chars().any(char::is_control);
        match self.version.as_str() {
            "v2c" if bounded(&self.community, 1) => Ok(ProbeCredential::SnmpV2c {
                community: self.community.clone().into(),
            }),
            "v3" if bounded(&self.username, 1)
                && bounded(&self.authentication_password, 8)
                && bounded(&self.privacy_password, 8) =>
            {
                Ok(ProbeCredential::SnmpV3 {
                    username: self.username.clone().into(),
                    authentication: Some(SnmpAuthentication {
                        protocol: SnmpAuthProtocol::Sha256,
                        password: self.authentication_password.clone().into(),
                    }),
                    privacy: Some(SnmpPrivacy {
                        protocol: SnmpPrivProtocol::Aes128,
                        password: self.privacy_password.clone().into(),
                    }),
                })
            }
            _ => Err(StatusCode::BAD_REQUEST),
        }
    }
}
impl ScanRequest {
    fn port_list(&self) -> Result<Vec<u16>, StatusCode> {
        if self.device_ids.len() > MAX_DEVICES
            || self
                .device_ids
                .iter()
                .any(|id| uuid::Uuid::parse_str(id).is_err())
            || self.ports.len() > 4096
            || self.ports.contains(&0)
            || self.protocols.len() > 5
            || self.protocols.iter().collect::<BTreeSet<_>>().len() != self.protocols.len()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let ports = match self.port_mode {
            PortMode::Common => COMMON_PORTS.to_vec(),
            PortMode::All => (1..=u16::MAX).collect(),
            PortMode::Custom => self
                .ports
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            PortMode::None => vec![],
        };
        if ports.is_empty() && self.protocols.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(ports)
    }
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct Finding {
    pub device_id: Option<String>,
    pub address: String,
    pub protocol: String,
    pub port: Option<u16>,
    pub status: String,
    pub service_hint: Option<String>,
    pub facts: BTreeMap<String, String>,
    pub observed_at: String,
}
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanStatus {
    pub job_id: Option<String>,
    pub state: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub devices: usize,
    pub skipped_devices: usize,
    pub total: usize,
    pub completed: usize,
    pub open_ports: usize,
    pub refused: usize,
    pub no_response: usize,
    pub errors: usize,
    pub findings: Vec<Finding>,
    pub results_truncated: bool,
    pub detail: String,
}
impl Default for ScanStatus {
    fn default() -> Self {
        Self {
            job_id: None,
            state: "idle".into(),
            started_at: None,
            finished_at: None,
            devices: 0,
            skipped_devices: 0,
            total: 0,
            completed: 0,
            open_ports: 0,
            refused: 0,
            no_response: 0,
            errors: 0,
            findings: vec![],
            results_truncated: false,
            detail: "Scan the observed devices to identify their services.".into(),
        }
    }
}
struct Running {
    status: ScanStatus,
    cancel: CancellationToken,
}
#[derive(Clone)]
pub struct ScanHub {
    pool: SqlitePool,
    inner: Arc<Mutex<Running>>,
    start_lock: Arc<Mutex<()>>,
}
#[derive(Clone)]
struct Target {
    device: String,
    ip: IpAddr,
    interface: InterfaceId,
    guard: Arc<TargetGuard>,
}

impl ScanHub {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            inner: Arc::new(Mutex::new(Running {
                status: ScanStatus::default(),
                cancel: CancellationToken::new(),
            })),
            start_lock: Arc::new(Mutex::new(())),
        }
    }
    pub async fn status(&self) -> Result<ScanStatus, StatusCode> {
        let mut current = self.inner.lock().await;
        if current.status.job_id.is_none() {
            let saved: Option<(String,)> = sqlx::query_as("SELECT payload FROM network_discovery_snapshots WHERE kind='scan' AND length(payload)<=8388608").fetch_optional(&self.pool).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if let Some((saved,)) = saved {
                current.status =
                    serde_json::from_str(&saved).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                if matches!(current.status.state.as_str(), "running" | "cancelling") {
                    current.status.state = "interrupted".into();
                    current.status.detail =
                        "The service restarted. Start a new scan to refresh these results.".into();
                }
            }
        }
        Ok(current.status.clone())
    }
    async fn targets(&self, requested: &[String]) -> Result<(Vec<Target>, usize), StatusCode> {
        let evidence: Vec<(String,String,String)> = sqlx::query_as("SELECT DISTINCT device_id,source,fact_value FROM evidence WHERE family='link_layer' AND fact_key='mac' AND length(fact_value)=17 AND length(source)<128 AND length(device_id)=36 LIMIT 4097").fetch_all(&self.pool).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if evidence.len() > 4096 {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let mut identities: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        let mut known = BTreeSet::new();
        for (id, source, mac) in evidence {
            if uuid::Uuid::parse_str(&id).is_err() {
                continue;
            }
            if requested.is_empty() || requested.contains(&id) {
                known.insert(id.clone());
            }
            identities
                .entry((source, mac.to_ascii_uppercase()))
                .or_default()
                .insert(id);
        }
        if requested.iter().any(|id| !known.contains(id)) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let inventory = tokio::task::spawn_blocking(|| SystemInterfaceManager.snapshot())
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let config = crate::runtime::plan_inventory(&inventory)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .snapshot_config()
            .clone();
        let neighbors = SystemNeighborSnapshotSource::new(config)
            .snapshot()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let mut targets: BTreeMap<String, Target> = BTreeMap::new();
        for row in neighbors {
            let key = (
                format!("neighbor-interface-{}", row.interface().get()),
                row.link_address().to_string().to_ascii_uppercase(),
            );
            let Some(ids) = identities.get(&key) else {
                continue;
            };
            if ids.len() != 1 {
                continue;
            }
            let Some(id) = ids.first().filter(|id| known.contains(*id)) else {
                continue;
            };
            if inventory
                .interfaces()
                .any(|i| i.addresses.iter().any(|a| a.ip == row.ip()))
            {
                continue;
            }
            let Ok(guard) = TargetGuard::new(
                inventory.clone(),
                [],
                [TargetApproval {
                    interface: row.interface(),
                    prefix: Address {
                        ip: row.ip(),
                        prefix: if row.ip().is_ipv4() { 32 } else { 128 },
                    },
                }],
            ) else {
                continue;
            };
            let target = Target {
                device: id.clone(),
                ip: row.ip(),
                interface: row.interface(),
                guard: Arc::new(guard),
            };
            if targets
                .get(id)
                .is_none_or(|old| (old.ip.is_ipv6(), old.ip) > (target.ip.is_ipv6(), target.ip))
            {
                targets.insert(id.clone(), target);
            }
        }
        if targets.len() > MAX_DEVICES {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let skipped = known.len().saturating_sub(targets.len());
        let approvals = targets.values().map(|t| TargetApproval {
            interface: t.interface,
            prefix: Address {
                ip: t.ip,
                prefix: if t.ip.is_ipv4() { 32 } else { 128 },
            },
        });
        let guard = Arc::new(
            TargetGuard::new(inventory, [], approvals)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        );
        let mut targets: Vec<_> = targets.into_values().collect();
        for target in &mut targets {
            target.guard = guard.clone();
        }
        Ok((targets, skipped))
    }
    pub async fn start(&self, input: ScanRequest) -> Result<ScanStatus, StatusCode> {
        let _start = self
            .start_lock
            .try_lock()
            .map_err(|_| StatusCode::CONFLICT)?;
        let ports = Arc::new(input.port_list()?);
        let credential = if input.protocols.contains(&Protocol::Snmp) {
            Some(Arc::new(
                input
                    .snmp
                    .as_ref()
                    .ok_or(StatusCode::BAD_REQUEST)?
                    .credential()?,
            ))
        } else {
            None
        };
        if matches!(
            self.inner.lock().await.status.state.as_str(),
            "running" | "cancelling"
        ) {
            return Err(StatusCode::CONFLICT);
        }
        let (targets, skipped) = self.targets(&input.device_ids).await?;
        if targets.is_empty() {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        let cancel = CancellationToken::new();
        let status = ScanStatus { job_id: Some(uuid::Uuid::new_v4().to_string()), state: "running".into(), started_at: Some(Utc::now().to_rfc3339()), devices: targets.len(), skipped_devices: skipped, total: targets.len() * (ports.len() + input.protocols.len()), detail: "Scanning observed local addresses. Service labels are hints; no device settings are changed.".into(), ..Default::default() };
        self.persist(&status).await?;
        *self.inner.lock().await = Running {
            status: status.clone(),
            cancel: cancel.clone(),
        };
        let hub = self.clone();
        tokio::spawn(async move {
            hub.run(targets, ports, input.protocols, credential, cancel)
                .await;
        });
        Ok(status)
    }
    async fn persist(&self, status: &ScanStatus) -> Result<(), StatusCode> {
        let json = serde_json::to_string(status).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        sqlx::query("INSERT INTO network_discovery_snapshots(kind,payload,updated_at) VALUES('scan',?,?) ON CONFLICT(kind) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at").bind(json).bind(Utc::now().to_rfc3339()).execute(&self.pool).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        Ok(())
    }
    async fn run(
        &self,
        targets: Vec<Target>,
        ports: Arc<Vec<u16>>,
        protocols: Vec<Protocol>,
        credential: Option<Arc<ProbeCredential>>,
        cancel: CancellationToken,
    ) {
        if protocols.contains(&Protocol::Mdns) {
            #[cfg(target_os = "linux")]
            {
                let findings = avahi::browse(&targets, &cancel).await;
                self.inner
                    .lock()
                    .await
                    .status
                    .findings
                    .extend(findings.into_iter().take(MAX_FINDINGS));
            }
            let mut interfaces = BTreeSet::new();
            let mut failed_interfaces = BTreeSet::new();
            let mut found = BTreeMap::new();
            for target in &targets {
                if !target.ip.is_ipv4() || !interfaces.insert(target.interface) {
                    continue;
                }
                let replies = tokio::select! { biased; () = cancel.cancelled() => break, r = active::mdns_discovery::browse(&target.guard,target.interface,target.ip) => r };
                if let Ok(replies) = replies {
                    for reply in replies {
                        found.insert((target.interface, reply.address), reply.facts);
                    }
                } else {
                    failed_interfaces.insert(target.interface);
                }
            }
            for target in &targets {
                if cancel.is_cancelled() {
                    break;
                }
                if !target.ip.is_ipv4() || failed_interfaces.contains(&target.interface) {
                    self.record(
                        target,
                        "mdns_bonjour",
                        None,
                        Err(active::ActiveError::Unavailable),
                    )
                    .await;
                    continue;
                }
                let values = found.remove(&(target.interface, target.ip));
                let mut inner = self.inner.lock().await;
                inner.status.completed += 1;
                if let Some(values) = values {
                    if inner.status.findings.len() < MAX_FINDINGS {
                        inner.status.findings.push(Finding {
                            device_id: Some(target.device.clone()),
                            address: target.ip.to_string(),
                            protocol: "mdns_bonjour".into(),
                            port: Some(5353),
                            status: "responded".into(),
                            service_hint: None,
                            facts: values
                                .into_iter()
                                .take(8)
                                .map(|(key, value)| (key, bounded_text(&value)))
                                .collect(),
                            observed_at: Utc::now().to_rfc3339(),
                        });
                    } else {
                        inner.status.results_truncated = true;
                    }
                } else {
                    inner.status.no_response += 1;
                }
            }
        }
        let rate = Arc::new(Mutex::new(Instant::now()));
        let deadline = Instant::now() + Duration::from_secs(24 * 3600);
        stream::iter(targets).for_each_concurrent(12, |target| {
            let ports = ports.clone(); let rate = rate.clone(); let cancel = cancel.clone(); let credential = credential.clone(); let protocols = &protocols;
            async move {
                let Ok(catalog) = active::catalog() else { return; };
                let engine = ActiveEngine::new(target.guard.clone(), Arc::new(SystemTransport), catalog);
                let extra = protocols.iter().filter(|p| **p != Protocol::Mdns).map(|p| match p { Protocol::Icmp => if target.ip.is_ipv4() {"icmp.echo.v4"} else {"icmp.echo.v6"}, Protocol::Mdns => "udp.mdns.5353", Protocol::Smb => "tcp.smb.445", Protocol::Netbios => "udp.nbns.137", Protocol::Snmp => "udp.snmp.161" }.to_owned());
                let probes = extra.chain(ports.iter().map(|port| format!("full.tcp.{port}")));
                for probe in probes {
                    let due = { let mut next = rate.lock().await; let due = (*next).max(Instant::now()); *next = due + Duration::from_millis(25); due };
                    tokio::select! { biased; () = cancel.cancelled() => break, () = tokio::time::sleep_until(deadline) => break, () = tokio::time::sleep_until(due) => {} }
                    let port = probe.strip_prefix("full.tcp.").and_then(|p| p.parse::<u16>().ok());
                    let request = ProbeRequest { interface: target.interface, target: target.ip, probe_id: probe.clone(), mode: if port.is_some() {ProbeMode::OwnerFullPort} else {ProbeMode::OwnerInventory}, owner_approved: true };
                    let result = tokio::select! { biased; () = cancel.cancelled() => break, result = tokio::time::timeout(Duration::from_millis(if port.is_some() {750} else {3500}), engine.execute(request,credential.as_deref())) => result.unwrap_or(Ok(ProbeOutcome::Timeout { source: probe.clone() })) };
                    self.record(&target, &probe, port, result).await;
                }
            }
        }).await;
        // Serialize completion persistence against admission of the next scan.
        let _finish = self.start_lock.lock().await;
        let status = {
            let mut running = self.inner.lock().await;
            running.status.state = if cancel.is_cancelled() {
                "cancelled"
            } else if Instant::now() >= deadline {
                "time_limit"
            } else {
                "complete"
            }
            .into();
            running.status.finished_at = Some(Utc::now().to_rfc3339());
            running.status.detail = "Results describe this scan only. A timeout does not prove a device or service is absent. Port-based names are hints, not verified device identities.".into();
            running.status.clone()
        };
        if self.persist(&status).await.is_err() {
            self.inner.lock().await.status.detail =
                "Scan finished, but results could not be saved. They remain visible until restart."
                    .into();
        }
    }
    async fn record(
        &self,
        target: &Target,
        probe: &str,
        port: Option<u16>,
        result: Result<ProbeOutcome, active::ActiveError>,
    ) {
        let mut inner = self.inner.lock().await;
        let status = &mut inner.status;
        status.completed += 1;
        let (state, facts) = match result {
            Ok(ProbeOutcome::Success { facts }) => {
                if port.is_some() {
                    status.open_ports += 1;
                }
                (
                    "responded",
                    facts
                        .into_iter()
                        .take(8)
                        .map(|f| (f.key, bounded_text(&f.value)))
                        .collect(),
                )
            }
            Ok(ProbeOutcome::Refused { .. }) => {
                status.refused += 1;
                if port.is_some() {
                    return;
                }
                ("refused", BTreeMap::new())
            }
            Ok(ProbeOutcome::Timeout { .. }) => {
                status.no_response += 1;
                if port.is_some() {
                    return;
                }
                ("no_response", BTreeMap::new())
            }
            Err(error) => {
                status.errors += 1;
                if port.is_some() {
                    return;
                }
                (
                    match error {
                        active::ActiveError::PermissionDenied => "permission_required",
                        active::ActiveError::Unavailable => "unavailable",
                        _ => "failed",
                    },
                    BTreeMap::new(),
                )
            }
        };
        if status.findings.len() >= MAX_FINDINGS {
            status.results_truncated = true;
            return;
        }
        status.findings.push(Finding {
            device_id: Some(target.device.clone()),
            address: target.ip.to_string(),
            protocol: if port.is_some() {
                "tcp".into()
            } else {
                probe.into()
            },
            port,
            status: if port.is_some() {
                "open".into()
            } else {
                state.into()
            },
            service_hint: port.and_then(service_hint).map(str::to_owned),
            facts,
            observed_at: Utc::now().to_rfc3339(),
        });
    }
}
fn bounded_text(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .scan(0, |bytes, c| {
            *bytes += c.len_utf8();
            (*bytes <= 256).then_some(c)
        })
        .collect()
}
fn service_hint(port: u16) -> Option<&'static str> {
    Some(match port {
        22 => "SSH",
        23 => "Telnet",
        53 => "DNS",
        80 | 81 | 8080 | 8081 | 8000 => "Web service",
        443 | 8443 | 9443 => "HTTPS",
        139 => "NetBIOS session",
        445 => "SMB file service",
        554 | 8554 => "RTSP camera/media",
        515 | 631 | 9100 => "Printing",
        1883 => "MQTT",
        8883 => "MQTT over TLS",
        3389 => "Remote Desktop",
        5900 => "VNC",
        8123 => "Home Assistant",
        8008 | 8009 => "Cast / media",
        32400 => "Plex media",
        _ => return None,
    })
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/network/scan", get(status_route).post(start_route))
        .route("/api/v1/network/scan/cancel", post(cancel_route))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .merge(capture::routes())
}
#[utoipa::path(get,path="/api/v1/network/scan",responses((status=200,body=ScanStatus),(status=401)),security(("bearer_auth"=[])))]
pub(crate) async fn status_route(
    _: LocalOwner,
    State(state): State<AppState>,
) -> Result<Json<ScanStatus>, StatusCode> {
    state.scans().status().await.map(Json)
}
#[utoipa::path(post,path="/api/v1/network/scan",request_body=ScanRequest,responses((status=202,body=ScanStatus),(status=400),(status=401),(status=409),(status=422)),security(("bearer_auth"=[])))]
pub(crate) async fn start_route(
    _: LocalOwner,
    State(state): State<AppState>,
    Json(input): Json<ScanRequest>,
) -> Result<(StatusCode, Json<ScanStatus>), StatusCode> {
    state
        .scans()
        .start(input)
        .await
        .map(|s| (StatusCode::ACCEPTED, Json(s)))
}
#[utoipa::path(post,path="/api/v1/network/scan/cancel",responses((status=204),(status=401)),security(("bearer_auth"=[])))]
pub(crate) async fn cancel_route(_: LocalOwner, State(state): State<AppState>) -> StatusCode {
    let mut running = state.scans().inner.lock().await;
    if running.status.state == "running" {
        running.status.state = "cancelling".into();
        running.cancel.cancel();
    }
    StatusCode::NO_CONTENT
}
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        status_route,
        start_route,
        cancel_route,
        capture::capabilities_route,
        capture::read_route,
        capture::import_route
    ),
    components(schemas(
        ScanRequest,
        ScanStatus,
        Finding,
        Protocol,
        PortMode,
        SnmpInput,
        capture::CaptureReport,
        avahi::DiscoveryCapabilities
    ))
)]
pub struct ScanApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unbounded_or_unauthenticated_snmp_scan_inputs() {
        let mut request: ScanRequest =
            serde_json::from_str(r#"{"port_mode":"custom","ports":[80,443,80],"protocols":[]}"#)
                .unwrap();
        assert_eq!(request.port_list().unwrap(), vec![80, 443]);
        request.ports.push(0);
        assert_eq!(request.port_list(), Err(StatusCode::BAD_REQUEST));
        let snmp: SnmpInput =
            serde_json::from_str(r#"{"version":"v3","username":"operator"}"#).unwrap();
        assert!(snmp.credential().is_err());
        assert!(bounded_text(&"🚀".repeat(300)).len() <= 256);
    }
}
