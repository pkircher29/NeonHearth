//! Network Doctor service API (M6): bounded diagnostic runs, findings paired
//! with repair plans, single-use timed approvals, and audited repair
//! execution.
//!
//! Contract: docs/architecture/m6-doctor-contracts.md ("Routes"). The wire
//! shapes ARE the `lattice-doctor` public types; this module adds only the
//! thin envelopes the contract names ([`DoctorRun`], [`DoctorFinding`],
//! [`DoctorApproval`]) and never reshapes the domain types.
//!
//! The engine and executor stay transport-injected. The production
//! [`ServiceProbeTransport`] / [`ServiceRepairTransport`] answer only what the
//! service can honestly observe or do locally without new privileges;
//! everything else returns a typed unsupported/unavailable error so the
//! engine's skip/confidence semantics label the gap instead of guessing. Tests
//! (and a future privileged collector) inject richer transports through
//! [`DoctorState::with_parts`].

use axum::{
    Extension, Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use futures_util::future::BoxFuture;
use lattice_doctor::{
    Clock, DoctorError, SystemClock,
    check::{CheckKind, DiagnosticBudget, DiagnosticReport, Measurement, Metric, Unit},
    diagnosis::{Diagnosis, DiagnosisKind, diagnose},
    engine::{DiagnosticEngine, DoctorConfig, Thresholds},
    executor::{
        MetricDirection, RepairExecutor, RepairReport, RepairTransport, RepairTransportError,
        StateEntry, Symptom,
    },
    probe::{LeaseState, Probe, ProbeError, ProbeRequest, ProbeResponse, ProbeTransport},
    repair::{
        ApprovalId, ApprovedRepair, ExecutableRepair, RepairContext, RepairPlan, StateKey,
        plan_repair,
    },
};
use lattice_store::{AuditActor, AuditCategory, AuditLog, NewAuditEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{AppState, auth::Authorized};

/// How long a minted approval stays live (contract: 10 minutes, single-use).
const APPROVAL_TTL_MINUTES: i64 = 10;

/// Written into the engine config wherever neither the platform nor the
/// owner has supplied a real target. The probe gate refuses to dial it, so an
/// unconfigured target surfaces in the report as a probe failure with an
/// explicit reason instead of a guessed address being probed.
pub const UNCONFIGURED_TARGET: &str = "unconfigured";
/// Longest accepted interface name / probe hostname.
const MAX_SETTING_LEN: usize = 253;
/// Most configured resolvers one settings update may carry.
const MAX_RESOLVERS: usize = 8;

// ---------------------------------------------------------------------------
// Wire envelopes (the only shapes this module adds on top of lattice-doctor).
// ---------------------------------------------------------------------------

/// One diagnosis from the latest run zipped with its proposed repair plan.
#[derive(Clone, Serialize, ToSchema)]
pub struct DoctorFinding {
    pub diagnosis: Diagnosis,
    pub plan: RepairPlan,
}

/// Envelope for `POST /doctor/run` and `GET /doctor/report`.
#[derive(Clone, Serialize, ToSchema)]
pub struct DoctorRun {
    #[schema(value_type = String, format = Uuid)]
    pub run_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub report: DiagnosticReport,
    pub findings: Vec<DoctorFinding>,
}

/// `POST /doctor/approvals` body: which approval-required finding to approve.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorApprovalRequest {
    pub diagnosis_kind: DiagnosisKind,
}

/// A minted single-use approval token with its expiry.
#[derive(Serialize, ToSchema)]
pub struct DoctorApproval {
    pub approval_id: String,
    pub expires_at: DateTime<Utc>,
}

/// `POST /doctor/repair` body: which latest-run plan to execute.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorRepairRequest {
    pub diagnosis_kind: DiagnosisKind,
    #[serde(default)]
    pub approval_id: Option<String>,
}

/// `POST /doctor/repair` response envelope.
#[derive(Serialize, ToSchema)]
pub struct DoctorRepairResponse {
    pub repair: RepairReport,
}

/// Where the gateway / resolver targets currently come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetSource {
    /// Read from the host's route table / resolver configuration at startup.
    Platform,
    /// Set explicitly by the owner.
    Owner,
    /// Nothing could be derived and the owner has not set one.
    Unknown,
}

/// The owner-visible probe targets the Doctor runs against
/// (`GET`/`PUT /doctor/settings`).
///
/// Nothing here is guessed: the gateway and configured resolvers are derived
/// from the platform where possible and otherwise left unset, and no probe
/// leaves the private network until `external_probes_confirmed` is true.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DoctorSettings {
    /// Interface the collector manages.
    #[schema(min_length = 1, max_length = 253)]
    pub interface: String,
    /// Default gateway, when known.
    #[schema(max_length = 64)]
    pub gateway: Option<String>,
    pub gateway_source: TargetSource,
    /// Resolvers the host is configured to use (may be empty).
    #[schema(max_items = 8)]
    pub configured_resolvers: Vec<String>,
    /// A known-good resolver independent of local configuration.
    #[schema(max_length = 64)]
    pub independent_resolver: String,
    /// Literal IP used to test internet reachability without DNS.
    #[schema(max_length = 64)]
    pub internet_probe_address: String,
    pub internet_probe_port: u16,
    /// Name resolved during DNS checks.
    #[schema(min_length = 1, max_length = 253)]
    pub dns_probe_name: String,
    /// Until the owner confirms, probes to non-private targets are refused.
    pub external_probes_confirmed: bool,
}

/// `PUT /doctor/settings` body: every field optional, unknown fields refused.
#[derive(Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorSettingsUpdate {
    #[schema(min_length = 1, max_length = 253)]
    pub interface: Option<String>,
    /// `Some("")` clears the gateway; `Some(ip)` sets it as owner-provided.
    #[schema(max_length = 64)]
    pub gateway: Option<String>,
    #[schema(max_items = 8)]
    pub configured_resolvers: Option<Vec<String>>,
    #[schema(max_length = 64)]
    pub independent_resolver: Option<String>,
    #[schema(max_length = 64)]
    pub internet_probe_address: Option<String>,
    pub internet_probe_port: Option<u16>,
    #[schema(min_length = 1, max_length = 253)]
    pub dns_probe_name: Option<String>,
    pub external_probes_confirmed: Option<bool>,
}

/// `PUT /doctor/settings` 400 body.
#[derive(Serialize, ToSchema)]
pub struct DoctorSettingsRejected {
    #[schema(max_length = 256)]
    pub error: String,
}

impl DoctorSettings {
    /// Settings that mirror an explicit engine config (tests and any caller
    /// that already knows its targets): everything owner-provided and
    /// external probes confirmed.
    pub fn from_config(config: &DoctorConfig) -> Self {
        Self {
            interface: config.interface.clone(),
            gateway: Some(config.gateway.clone()),
            gateway_source: TargetSource::Owner,
            configured_resolvers: config.configured_resolvers.clone(),
            independent_resolver: config.independent_resolver.clone(),
            internet_probe_address: config.internet_probe_address.clone(),
            internet_probe_port: config.internet_probe_port,
            dns_probe_name: config.dns_probe_name.clone(),
            external_probes_confirmed: true,
        }
    }

    /// Settings derived from the running platform: the default route and
    /// resolver configuration where the OS exposes them, no guessed gateway,
    /// and external probes unconfirmed.
    pub fn from_platform() -> Self {
        let route = platform_default_route();
        Self {
            interface: route
                .as_ref()
                .map_or_else(|| "primary".to_owned(), |route| route.0.clone()),
            gateway_source: if route.is_some() {
                TargetSource::Platform
            } else {
                TargetSource::Unknown
            },
            gateway: route.map(|route| route.1),
            configured_resolvers: platform_resolvers(),
            independent_resolver: "9.9.9.9".to_owned(),
            internet_probe_address: "1.1.1.1".to_owned(),
            internet_probe_port: 443,
            dns_probe_name: "example.com".to_owned(),
            external_probes_confirmed: false,
        }
    }

    fn apply(&mut self, update: DoctorSettingsUpdate) {
        if let Some(interface) = update.interface {
            self.interface = interface;
        }
        if let Some(gateway) = update.gateway {
            if gateway.is_empty() {
                self.gateway = None;
                self.gateway_source = TargetSource::Unknown;
            } else {
                self.gateway = Some(gateway);
                self.gateway_source = TargetSource::Owner;
            }
        }
        if let Some(resolvers) = update.configured_resolvers {
            self.configured_resolvers = resolvers;
        }
        if let Some(resolver) = update.independent_resolver {
            self.independent_resolver = resolver;
        }
        if let Some(address) = update.internet_probe_address {
            self.internet_probe_address = address;
        }
        if let Some(port) = update.internet_probe_port {
            self.internet_probe_port = port;
        }
        if let Some(name) = update.dns_probe_name {
            self.dns_probe_name = name;
        }
        if let Some(confirmed) = update.external_probes_confirmed {
            self.external_probes_confirmed = confirmed;
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        if !valid_name(&self.interface) {
            return Err("interface must be 1..=253 printable characters");
        }
        if let Some(gateway) = &self.gateway
            && gateway.parse::<IpAddr>().is_err()
        {
            return Err("gateway must be an IP address");
        }
        if self.configured_resolvers.len() > MAX_RESOLVERS {
            return Err("at most 8 configured resolvers");
        }
        if self
            .configured_resolvers
            .iter()
            .any(|resolver| resolver.parse::<IpAddr>().is_err())
        {
            return Err("configured resolvers must be IP addresses");
        }
        if self.independent_resolver.parse::<IpAddr>().is_err() {
            return Err("independent resolver must be an IP address");
        }
        if self.internet_probe_address.parse::<IpAddr>().is_err() {
            return Err("internet probe address must be an IP address");
        }
        if self.internet_probe_port == 0 {
            return Err("internet probe port must be 1..=65535");
        }
        if !valid_hostname(&self.dns_probe_name) {
            return Err("dns probe name must be a hostname");
        }
        Ok(())
    }

    /// The engine config for one run. Unknown targets become
    /// [`UNCONFIGURED_TARGET`], which the probe gate refuses to dial.
    fn to_config(&self, profile: &ProbeProfile) -> DoctorConfig {
        DoctorConfig {
            interface: self.interface.clone(),
            gateway: self
                .gateway
                .clone()
                .unwrap_or_else(|| UNCONFIGURED_TARGET.to_owned()),
            configured_resolvers: if self.configured_resolvers.is_empty() {
                vec![UNCONFIGURED_TARGET.to_owned()]
            } else {
                self.configured_resolvers.clone()
            },
            independent_resolver: self.independent_resolver.clone(),
            internet_probe_address: self.internet_probe_address.clone(),
            internet_probe_port: self.internet_probe_port,
            dns_probe_name: self.dns_probe_name.clone(),
            ping_count: profile.ping_count,
            mtu_probe_sizes: profile.mtu_probe_sizes.clone(),
            thresholds: profile.thresholds,
        }
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SETTING_LEN
        && value.chars().all(|c| !c.is_control() && !c.is_whitespace())
}

fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SETTING_LEN
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// The probe-shape parts of the engine config that are not owner-facing
/// targets (kept from the config the state was assembled with).
#[derive(Clone)]
struct ProbeProfile {
    ping_count: u8,
    mtu_probe_sizes: Vec<u16>,
    thresholds: Thresholds,
}

// ---------------------------------------------------------------------------
// Platform target derivation (no guessing: `None`/empty when unavailable).
// ---------------------------------------------------------------------------

/// `(interface, gateway)` of the lowest-metric IPv4 default route.
fn platform_default_route() -> Option<(String, String)> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/net/route")
            .ok()
            .and_then(|table| parse_proc_net_route(&table))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The resolvers the host is configured with.
fn platform_resolvers() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/resolv.conf")
            .map(|text| parse_resolv_conf(&text))
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Parses `/proc/net/route`: picks the lowest-metric row whose destination is
/// `0.0.0.0` and whose flags carry `RTF_GATEWAY`.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_route(table: &str) -> Option<(String, String)> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    let mut best: Option<(u32, String, String)> = None;
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 || fields[1] != "00000000" {
            continue;
        }
        let Ok(flags) = u32::from_str_radix(fields[3], 16) else {
            continue;
        };
        if flags & RTF_UP == 0 || flags & RTF_GATEWAY == 0 {
            continue;
        }
        let Ok(raw) = u32::from_str_radix(fields[2], 16) else {
            continue;
        };
        let metric = fields[6].parse::<u32>().unwrap_or(u32::MAX);
        // The kernel prints the address in host byte order; Linux release
        // targets are little-endian, so the low byte is the first octet.
        let gateway = std::net::Ipv4Addr::from(raw.to_le_bytes()).to_string();
        if best.as_ref().is_none_or(|(m, _, _)| metric < *m) {
            best = Some((metric, fields[0].to_owned(), gateway));
        }
    }
    best.map(|(_, interface, gateway)| (interface, gateway))
}

/// Parses `nameserver` lines from `resolv.conf`, deduplicated and capped.
#[cfg(any(target_os = "linux", test))]
fn parse_resolv_conf(text: &str) -> Vec<String> {
    let mut resolvers: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let Some(address) = rest.split_whitespace().next() else {
            continue;
        };
        // Strip a scope id (`fe80::1%eth0`): the engine dials plain IPs.
        let address = address.split('%').next().unwrap_or(address);
        if address.parse::<IpAddr>().is_ok() && !resolvers.iter().any(|known| known == address) {
            resolvers.push(address.to_owned());
            if resolvers.len() == MAX_RESOLVERS {
                break;
            }
        }
    }
    resolvers
}

/// Whether a probe target stays inside the private network.
fn is_private_target(target: &str) -> bool {
    match target.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

/// The address a probe request would dial, if it dials one.
fn probe_target(request: &ProbeRequest) -> Option<&str> {
    match request {
        ProbeRequest::Ping { target, .. } => Some(target),
        ProbeRequest::DnsQuery { resolver, .. } => Some(resolver),
        ProbeRequest::ReachIp { address, .. } => Some(address),
        ProbeRequest::ArpProbe { address, .. } => Some(address),
        ProbeRequest::CollectorStatus
        | ProbeRequest::LinkStatus { .. }
        | ProbeRequest::IpConfig { .. }
        | ProbeRequest::WifiMetrics { .. }
        | ProbeRequest::RouteTable
        | ProbeRequest::RouterStatus => None,
    }
}

/// Enforces the target policy in front of whatever transport is injected:
/// an unconfigured target is never dialed, and nothing outside the private
/// network is dialed until the owner has confirmed external probes.
struct GatedProbes<'a> {
    inner: &'a dyn DynProbeTransport,
    allow_external: bool,
}

impl ProbeTransport for GatedProbes<'_> {
    async fn probe(&self, probe: Probe) -> Result<ProbeResponse, ProbeError> {
        if let Some(target) = probe_target(&probe.request) {
            if target == UNCONFIGURED_TARGET {
                return Err(ProbeError::Transport(
                    "target is not configured; set it in doctor settings".to_owned(),
                ));
            }
            if !self.allow_external && !is_private_target(target) {
                return Err(ProbeError::Transport(
                    "external probe targets are not confirmed by the owner".to_owned(),
                ));
            }
        }
        self.inner.dyn_probe(probe).await
    }
}

// ---------------------------------------------------------------------------
// Injectable transport seam. The lattice-doctor transport traits use RPITIT
// and are not object-safe, so the service state holds these object-safe
// mirrors; every real `ProbeTransport`/`RepairTransport` implements them for
// free via the blanket impls below.
// ---------------------------------------------------------------------------

/// Object-safe mirror of [`ProbeTransport`] for storage in service state.
pub trait DynProbeTransport: Send + Sync {
    fn dyn_probe(&self, probe: Probe) -> BoxFuture<'_, Result<ProbeResponse, ProbeError>>;
}

impl<T: ProbeTransport> DynProbeTransport for T {
    fn dyn_probe(&self, probe: Probe) -> BoxFuture<'_, Result<ProbeResponse, ProbeError>> {
        Box::pin(ProbeTransport::probe(self, probe))
    }
}

/// Object-safe mirror of [`RepairTransport`] for storage in service state.
pub trait DynRepairTransport: Send + Sync {
    fn dyn_snapshot<'a>(
        &'a self,
        keys: &'a [StateKey],
    ) -> BoxFuture<'a, Result<Vec<StateEntry>, RepairTransportError>>;
    fn dyn_apply<'a>(
        &'a self,
        repair: &'a ExecutableRepair,
    ) -> BoxFuture<'a, Result<(), RepairTransportError>>;
    fn dyn_restore<'a>(
        &'a self,
        entries: &'a [StateEntry],
    ) -> BoxFuture<'a, Result<(), RepairTransportError>>;
    fn dyn_measure(
        &self,
        check: CheckKind,
    ) -> BoxFuture<'_, Result<Vec<Measurement>, RepairTransportError>>;
}

impl<T: RepairTransport> DynRepairTransport for T {
    fn dyn_snapshot<'a>(
        &'a self,
        keys: &'a [StateKey],
    ) -> BoxFuture<'a, Result<Vec<StateEntry>, RepairTransportError>> {
        Box::pin(RepairTransport::snapshot(self, keys))
    }
    fn dyn_apply<'a>(
        &'a self,
        repair: &'a ExecutableRepair,
    ) -> BoxFuture<'a, Result<(), RepairTransportError>> {
        Box::pin(RepairTransport::apply(self, repair))
    }
    fn dyn_restore<'a>(
        &'a self,
        entries: &'a [StateEntry],
    ) -> BoxFuture<'a, Result<(), RepairTransportError>> {
        Box::pin(RepairTransport::restore(self, entries))
    }
    fn dyn_measure(
        &self,
        check: CheckKind,
    ) -> BoxFuture<'_, Result<Vec<Measurement>, RepairTransportError>> {
        Box::pin(RepairTransport::measure(self, check))
    }
}

/// Adapts the stored dyn transport back into the executor's transport trait.
struct RepairAdapter<'a>(&'a dyn DynRepairTransport);

impl RepairTransport for RepairAdapter<'_> {
    async fn snapshot(&self, keys: &[StateKey]) -> Result<Vec<StateEntry>, RepairTransportError> {
        self.0.dyn_snapshot(keys).await
    }
    async fn apply(&self, repair: &ExecutableRepair) -> Result<(), RepairTransportError> {
        self.0.dyn_apply(repair).await
    }
    async fn restore(&self, entries: &[StateEntry]) -> Result<(), RepairTransportError> {
        self.0.dyn_restore(entries).await
    }
    async fn measure(&self, check: CheckKind) -> Result<Vec<Measurement>, RepairTransportError> {
        self.0.dyn_measure(check).await
    }
}

/// Shares one `Arc<dyn Clock>` with engine and executor constructors.
#[derive(Clone, Debug)]
struct SharedClock(Arc<dyn Clock>);

impl Clock for SharedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0.now()
    }
}

// ---------------------------------------------------------------------------
// Production transports: only honestly-observable local answers.
// ---------------------------------------------------------------------------

/// Probe transport backed exclusively by service-local state.
///
/// `CollectorStatus` is answered from the service runtime status; every
/// network probe reports [`ProbeError::Unsupported`] so the engine labels
/// downstream checks as unassessed instead of receiving fabricated data. A
/// privileged transport can replace this behind [`DynProbeTransport`].
pub struct ServiceProbeTransport {
    state: AppState,
}

impl ProbeTransport for ServiceProbeTransport {
    async fn probe(&self, probe: Probe) -> Result<ProbeResponse, ProbeError> {
        match probe.request {
            ProbeRequest::CollectorStatus => {
                // "ready" means the discovery/collector pipeline is running.
                // A degraded service cannot locally distinguish a privilege
                // loss from a capture failure, so both flags conservatively
                // report unhealthy rather than pretending one of them is fine.
                let ready = self.state.service_status().await == "ready";
                Ok(ProbeResponse::CollectorStatus {
                    privileged: ready,
                    capture_ok: ready,
                    // This process is answering the probe, so the worker runs.
                    worker_running: true,
                })
            }
            _ => Err(ProbeError::Unsupported),
        }
    }
}

/// Repair transport limited to what the service can genuinely do today.
///
/// No repair action has a local execution hook yet, so `apply` always returns
/// a typed error — execution is reported as failed, never pretended
/// successful. Snapshot/restore/measure work only for the service-local state
/// keys and the collector-health check; everything else is a typed error.
pub struct ServiceRepairTransport {
    state: AppState,
    clock: Arc<dyn Clock>,
}

impl RepairTransport for ServiceRepairTransport {
    async fn snapshot(&self, keys: &[StateKey]) -> Result<Vec<StateEntry>, RepairTransportError> {
        let mut entries = Vec::with_capacity(keys.len());
        for key in keys {
            match key {
                StateKey::WorkerState | StateKey::CacheState => entries.push(StateEntry {
                    key: *key,
                    value: self.state.service_status().await,
                }),
                other => {
                    return Err(RepairTransportError::Snapshot(format!(
                        "{other:?} is not snapshotable from service state"
                    )));
                }
            }
        }
        Ok(entries)
    }

    async fn apply(&self, repair: &ExecutableRepair) -> Result<(), RepairTransportError> {
        Err(RepairTransportError::Apply(format!(
            "{} has no local execution hook in this service build",
            repair.describe()
        )))
    }

    async fn restore(&self, entries: &[StateEntry]) -> Result<(), RepairTransportError> {
        // `apply` never changes anything in this build, so restoring the
        // service-local snapshots it took is vacuously complete; keys this
        // transport could not have snapshotted are refused, not ignored.
        for entry in entries {
            match entry.key {
                StateKey::WorkerState | StateKey::CacheState => {}
                other => {
                    return Err(RepairTransportError::Restore(format!(
                        "{other:?} cannot be restored from service state"
                    )));
                }
            }
        }
        Ok(())
    }

    async fn measure(&self, check: CheckKind) -> Result<Vec<Measurement>, RepairTransportError> {
        match check {
            CheckKind::CollectorHealth => {
                let ready = self.state.service_status().await == "ready";
                let observed_at = self.clock.now();
                let flag = |metric: Metric, value: bool| Measurement {
                    metric,
                    value: if value { 1.0 } else { 0.0 },
                    unit: Unit::Boolean,
                    observed_at,
                };
                Ok(vec![
                    flag(Metric::CollectorPrivileged, ready),
                    flag(Metric::CaptureHealthy, ready),
                    flag(Metric::WorkerRunning, true),
                ])
            }
            other => Err(RepairTransportError::Measure(format!(
                "{other:?} is not measurable from service state"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Service-owned doctor state.
// ---------------------------------------------------------------------------

struct ApprovalRecord {
    /// Canonical JSON of the approved `DiagnosisKind`.
    fingerprint: String,
    expires_at: DateTime<Utc>,
    used: bool,
}

#[derive(Default)]
struct DoctorInner {
    latest: Option<DoctorRun>,
    approvals: HashMap<String, ApprovalRecord>,
}

struct DoctorShared {
    budget: DiagnosticBudget,
    profile: ProbeProfile,
    context: RepairContext,
    /// Owner-facing probe targets; the engine is rebuilt from them per run.
    settings: tokio::sync::RwLock<DoctorSettings>,
    clock: Arc<dyn Clock>,
    probes: Arc<dyn DynProbeTransport>,
    repairs: Arc<dyn DynRepairTransport>,
    /// One diagnostic or repair at a time (contract: concurrent runs get
    /// 409; repairs share the flag so a repair never interleaves with a run
    /// or another repair's snapshot/apply/restore).
    running: AtomicBool,
    inner: tokio::sync::Mutex<DoctorInner>,
}

/// Cloneable handle to the doctor's service-owned state.
#[derive(Clone)]
pub struct DoctorState {
    shared: Arc<DoctorShared>,
}

impl DoctorState {
    /// Production doctor for this service instance.
    ///
    /// Targets come from [`DoctorSettings::from_platform`]: the host's own
    /// default route and resolvers where the OS exposes them, nothing guessed
    /// otherwise, and no probe outside the private network until the owner
    /// confirms it through `PUT /doctor/settings`.
    pub fn for_service(state: &AppState) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let budget = DiagnosticBudget::new(64, 2_000).expect("default budget is valid");
        let probes: Arc<dyn DynProbeTransport> = Arc::new(ServiceProbeTransport {
            state: state.clone(),
        });
        let repairs: Arc<dyn DynRepairTransport> = Arc::new(ServiceRepairTransport {
            state: state.clone(),
            clock: Arc::clone(&clock),
        });
        let settings = DoctorSettings::from_platform();
        Self::assemble(
            settings,
            default_profile(),
            budget,
            default_context(),
            clock,
            probes,
            repairs,
        )
        .expect("default doctor configuration is valid")
    }

    /// Assemble a doctor with injected config, clock, and transports — the
    /// seam tests use to run the real routes against fake transports. The
    /// config's targets become owner-provided settings with external probes
    /// confirmed, so an injected transport sees exactly the configured
    /// requests.
    pub fn with_parts(
        config: DoctorConfig,
        budget: DiagnosticBudget,
        context: RepairContext,
        clock: Arc<dyn Clock>,
        probes: Arc<dyn DynProbeTransport>,
        repairs: Arc<dyn DynRepairTransport>,
    ) -> Result<Self, DoctorError> {
        let profile = ProbeProfile {
            ping_count: config.ping_count,
            mtu_probe_sizes: config.mtu_probe_sizes.clone(),
            thresholds: config.thresholds,
        };
        Self::assemble(
            DoctorSettings::from_config(&config),
            profile,
            budget,
            context,
            clock,
            probes,
            repairs,
        )
    }

    fn assemble(
        settings: DoctorSettings,
        profile: ProbeProfile,
        budget: DiagnosticBudget,
        context: RepairContext,
        clock: Arc<dyn Clock>,
        probes: Arc<dyn DynProbeTransport>,
        repairs: Arc<dyn DynRepairTransport>,
    ) -> Result<Self, DoctorError> {
        // Validate eagerly so a bad profile fails at assembly, not at the
        // first run.
        DiagnosticEngine::with_clock(
            settings.to_config(&profile),
            budget,
            SharedClock(Arc::clone(&clock)),
        )?;
        Ok(Self {
            shared: Arc::new(DoctorShared {
                budget,
                profile,
                context,
                settings: tokio::sync::RwLock::new(settings),
                clock,
                probes,
                repairs,
                running: AtomicBool::new(false),
                inner: tokio::sync::Mutex::new(DoctorInner::default()),
            }),
        })
    }

    /// The current owner-visible probe targets.
    pub async fn settings(&self) -> DoctorSettings {
        self.shared.settings.read().await.clone()
    }
}

/// The production probe shape: four echoes per latency sample and three
/// don't-fragment sizes.
fn default_profile() -> ProbeProfile {
    ProbeProfile {
        ping_count: 4,
        mtu_probe_sizes: vec![1472, 1400, 1200],
        thresholds: Thresholds::default(),
    }
}

/// Conservative classification facts: lease renewal is assumed to risk the
/// only management path (so it requires approval), and no known-good fallback
/// resolvers are configured (so DNS failures stay observation-only). The
/// interface is filled in from the live settings at plan time.
fn default_context() -> RepairContext {
    RepairContext {
        interface: "primary".to_owned(),
        lease_renewal_severs_only_management_path: true,
        fallback_dns_servers: Vec::new(),
    }
}

/// Clears the running flag even if the run future is dropped mid-flight.
struct RunningGuard<'a>(&'a AtomicBool);

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Routes.
// ---------------------------------------------------------------------------

pub(crate) fn routes(doctor: DoctorState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/doctor/run", post(run_route))
        .route("/api/v1/doctor/report", get(report_route))
        .route("/api/v1/doctor/approvals", post(approvals_route))
        .route("/api/v1/doctor/repair", post(repair_route))
        .route(
            "/api/v1/doctor/settings",
            get(settings_route).put(update_settings_route),
        )
        .layer(Extension(doctor))
}

#[utoipa::path(post, path = "/api/v1/doctor/run", responses((status = 200, body = DoctorRun), (status = 401), (status = 409, description = "a diagnostic run is already in progress")), security(("bearer_auth" = [])))]
pub(crate) async fn run_route(
    _: Authorized,
    Extension(doctor): Extension<DoctorState>,
) -> Response {
    let shared = &doctor.shared;
    if shared
        .running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return StatusCode::CONFLICT.into_response();
    }
    let _guard = RunningGuard(&shared.running);
    let settings = shared.settings.read().await.clone();
    let Ok(engine) = DiagnosticEngine::with_clock(
        settings.to_config(&shared.profile),
        shared.budget,
        SharedClock(Arc::clone(&shared.clock)),
    ) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let gated = GatedProbes {
        inner: shared.probes.as_ref(),
        allow_external: settings.external_probes_confirmed,
    };
    let report = engine.run(&gated).await;
    let context = RepairContext {
        interface: settings.interface.clone(),
        ..shared.context.clone()
    };
    let findings = diagnose(&report)
        .into_iter()
        .map(|diagnosis| {
            let plan = plan_repair(&diagnosis.kind, &context);
            DoctorFinding { diagnosis, plan }
        })
        .collect();
    let run = DoctorRun {
        run_id: Uuid::new_v4(),
        started_at: report.started_at,
        report,
        findings,
    };
    {
        let mut inner = shared.inner.lock().await;
        inner.latest = Some(run.clone());
        // Approvals are minted against the latest run only; a new run
        // invalidates every outstanding token.
        inner.approvals.clear();
    }
    Json(run).into_response()
}

#[utoipa::path(get, path = "/api/v1/doctor/report", responses((status = 200, body = DoctorRun), (status = 204, description = "no diagnostic has completed yet"), (status = 401)), security(("bearer_auth" = [])))]
pub(crate) async fn report_route(
    _: Authorized,
    Extension(doctor): Extension<DoctorState>,
) -> Response {
    let inner = doctor.shared.inner.lock().await;
    match &inner.latest {
        Some(run) => Json(run.clone()).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

#[utoipa::path(post, path = "/api/v1/doctor/approvals", request_body = DoctorApprovalRequest, responses((status = 200, body = DoctorApproval), (status = 400), (status = 401), (status = 404, description = "the latest run has no approval-required plan for this diagnosis"), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn approvals_route(
    _: Authorized,
    State(state): State<AppState>,
    Extension(doctor): Extension<DoctorState>,
    body: Result<Json<DoctorApprovalRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = body else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let shared = &doctor.shared;
    let Ok(fingerprint) = kind_fingerprint(&request.diagnosis_kind) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let now = shared.clock.now();
    let expires_at = now + Duration::minutes(APPROVAL_TTL_MINUTES);
    let approval_id = Uuid::new_v4().to_string();
    {
        let mut inner = shared.inner.lock().await;
        let Some(run) = &inner.latest else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let approvable = run.findings.iter().any(|finding| {
            finding.diagnosis.kind == request.diagnosis_kind
                && matches!(finding.plan, RepairPlan::ApprovalRequiredReversible { .. })
        });
        if !approvable {
            return StatusCode::NOT_FOUND.into_response();
        }
        // Expired tokens are dead weight until the next run clears them;
        // drop them here so the map is bounded by live approvals.
        inner.approvals.retain(|_, record| now < record.expires_at);
        inner.approvals.insert(
            approval_id.clone(),
            ApprovalRecord {
                fingerprint,
                expires_at,
                used: false,
            },
        );
    }
    let audited = append_audit(
        &state,
        NewAuditEntry {
            occurred_at: now,
            actor: AuditActor::Owner,
            category: AuditCategory::DoctorAction,
            action: "approval_minted".to_owned(),
            subject: Some(kind_tag(&request.diagnosis_kind).to_owned()),
            detail: serde_json::json!({
                "approval_id": approval_id,
                "diagnosis_kind": request.diagnosis_kind,
                "expires_at": expires_at,
            }),
        },
    )
    .await;
    if audited.is_err() {
        // An unaudited approval must not exist: withdraw it.
        shared.inner.lock().await.approvals.remove(&approval_id);
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(DoctorApproval {
        approval_id,
        expires_at,
    })
    .into_response()
}

#[utoipa::path(post, path = "/api/v1/doctor/repair", request_body = DoctorRepairRequest, responses((status = 200, body = DoctorRepairResponse), (status = 400, description = "guided/observation plans are never executable"), (status = 401), (status = 403, description = "missing, expired, used, or mismatched approval"), (status = 404, description = "the latest run has no plan for this diagnosis"), (status = 409, description = "a diagnostic run or another repair is in progress"), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn repair_route(
    _: Authorized,
    State(state): State<AppState>,
    Extension(doctor): Extension<DoctorState>,
    body: Result<Json<DoctorRepairRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = body else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let shared = &doctor.shared;
    // Single-flight: a repair's snapshot/apply/restore must never interleave
    // with a diagnostic run or another repair touching the same state keys.
    // Taken before the approval is consumed so a refused request keeps its
    // token.
    if shared
        .running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return StatusCode::CONFLICT.into_response();
    }
    let _guard = RunningGuard(&shared.running);
    let plan = {
        let inner = shared.inner.lock().await;
        let Some(run) = &inner.latest else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let Some(finding) = run
            .findings
            .iter()
            .find(|finding| finding.diagnosis.kind == request.diagnosis_kind)
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        finding.plan.clone()
    };
    let executable = match plan {
        RepairPlan::SafeAutomatic { action, .. } => ExecutableRepair::Safe { action },
        RepairPlan::ApprovalRequiredReversible { action, .. } => {
            let Some(approval_id) = request.approval_id.as_deref() else {
                return StatusCode::FORBIDDEN.into_response();
            };
            let Ok(fingerprint) = kind_fingerprint(&request.diagnosis_kind) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let now = shared.clock.now();
            {
                // Validate and consume under one lock so a token is never
                // spent twice.
                let mut inner = shared.inner.lock().await;
                let Some(record) = inner.approvals.get_mut(approval_id) else {
                    return StatusCode::FORBIDDEN.into_response();
                };
                if record.used || now >= record.expires_at || record.fingerprint != fingerprint {
                    return StatusCode::FORBIDDEN.into_response();
                }
                record.used = true;
            }
            let Ok(token) = ApprovalId::try_new(approval_id) else {
                return StatusCode::FORBIDDEN.into_response();
            };
            ExecutableRepair::Approved(ApprovedRepair::new(action, token))
        }
        RepairPlan::GuidedPhysical { .. } | RepairPlan::ObservationOnly { .. } => {
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let Some(symptom) = symptom_for(&request.diagnosis_kind) else {
        // Every executable plan maps to a symptom; reaching this means the
        // plan table and symptom table diverged.
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let executor = RepairExecutor::with_clock(SharedClock(Arc::clone(&shared.clock)));
    let repair = executor
        .execute(
            &RepairAdapter(shared.repairs.as_ref()),
            &executable,
            &symptom,
        )
        .await;
    let audited = append_audit(
        &state,
        NewAuditEntry {
            occurred_at: shared.clock.now(),
            actor: AuditActor::Owner,
            category: AuditCategory::DoctorAction,
            action: "repair_executed".to_owned(),
            subject: Some(kind_tag(&request.diagnosis_kind).to_owned()),
            detail: serde_json::json!({
                "diagnosis_kind": request.diagnosis_kind,
                "class": repair.class,
                "description": repair.description,
                "outcome": repair.outcome,
                "rollback": repair.rollback,
                "approval_id": request.approval_id,
            }),
        },
    )
    .await;
    if audited.is_err() {
        // The contract requires every execution to be audited; refuse to
        // report an execution the log did not record.
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(DoctorRepairResponse { repair }).into_response()
}

#[utoipa::path(get, path = "/api/v1/doctor/settings", responses((status = 200, body = DoctorSettings), (status = 401)), security(("bearer_auth" = [])))]
pub(crate) async fn settings_route(
    _: Authorized,
    Extension(doctor): Extension<DoctorState>,
) -> Response {
    Json(doctor.settings().await).into_response()
}

#[utoipa::path(put, path = "/api/v1/doctor/settings", request_body = DoctorSettingsUpdate, responses((status = 200, body = DoctorSettings), (status = 400, body = DoctorSettingsRejected), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn update_settings_route(
    _: Authorized,
    State(state): State<AppState>,
    Extension(doctor): Extension<DoctorState>,
    body: Result<Json<DoctorSettingsUpdate>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(update)) = body else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let shared = &doctor.shared;
    let now = shared.clock.now();
    let (previous, next) = {
        let mut settings = shared.settings.write().await;
        let previous = settings.clone();
        let mut next = previous.clone();
        next.apply(update);
        if let Err(error) = next.validate() {
            return (
                StatusCode::BAD_REQUEST,
                Json(DoctorSettingsRejected {
                    error: error.to_owned(),
                }),
            )
                .into_response();
        }
        *settings = next.clone();
        (previous, next)
    };
    let audited = append_audit(
        &state,
        NewAuditEntry {
            occurred_at: now,
            actor: AuditActor::Owner,
            category: AuditCategory::DoctorAction,
            action: "settings_updated".to_owned(),
            subject: Some("doctor_settings".to_owned()),
            detail: serde_json::json!({
                "previous": previous,
                "settings": next,
            }),
        },
    )
    .await;
    if audited.is_err() {
        // An unaudited change must not stand: restore the previous targets.
        *shared.settings.write().await = previous;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(next).into_response()
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Canonical JSON fingerprint of a diagnosis kind for approval matching.
fn kind_fingerprint(kind: &DiagnosisKind) -> Result<String, serde_json::Error> {
    serde_json::to_string(kind)
}

/// The serde tag of a diagnosis kind, used as the audit-log subject.
fn kind_tag(kind: &DiagnosisKind) -> &'static str {
    match kind {
        DiagnosisKind::CollectorFault { .. } => "collector_fault",
        DiagnosisKind::AdapterLinkDown => "adapter_link_down",
        DiagnosisKind::AddressMissing { .. } => "address_missing",
        DiagnosisKind::DuplicateIp { .. } => "duplicate_ip",
        DiagnosisKind::WeakWifiQuality { .. } => "weak_wifi_quality",
        DiagnosisKind::GatewayUnreachable => "gateway_unreachable",
        DiagnosisKind::RouterFault => "router_fault",
        DiagnosisKind::LossLatencyDegraded { .. } => "loss_latency_degraded",
        DiagnosisKind::MtuBlackhole { .. } => "mtu_blackhole",
        DiagnosisKind::DnsFailure { .. } => "dns_failure",
        DiagnosisKind::RouteVpnConflict { .. } => "route_vpn_conflict",
        DiagnosisKind::InternetUnreachable { .. } => "internet_unreachable",
        DiagnosisKind::DiagnosticProbeFailure { .. } => "diagnostic_probe_failure",
    }
}

/// The check/metric a repair for this diagnosis is verified against: always
/// the ORIGINAL symptom that motivated the repair.
fn symptom_for(kind: &DiagnosisKind) -> Option<Symptom> {
    use MetricDirection::{HigherIsBetter, LowerIsBetter};
    let (check, metric, direction, delta) = match kind {
        DiagnosisKind::CollectorFault {
            privileged,
            capture_ok,
            worker_running,
        } => {
            let metric = if !worker_running {
                Metric::WorkerRunning
            } else if !capture_ok {
                Metric::CaptureHealthy
            } else if !privileged {
                Metric::CollectorPrivileged
            } else {
                Metric::WorkerRunning
            };
            (CheckKind::CollectorHealth, metric, HigherIsBetter, 0.5)
        }
        DiagnosisKind::AdapterLinkDown => {
            (CheckKind::AdapterLink, Metric::LinkUp, HigherIsBetter, 0.5)
        }
        DiagnosisKind::AddressMissing { lease } => {
            let metric = match lease {
                LeaseState::Expired | LeaseState::Missing => Metric::LeaseValid,
                LeaseState::Static | LeaseState::Valid => Metric::AddressPresent,
            };
            (CheckKind::AddressDhcp, metric, HigherIsBetter, 0.5)
        }
        DiagnosisKind::DuplicateIp { .. } => (
            CheckKind::DuplicateIp,
            Metric::ConflictingMacCount,
            LowerIsBetter,
            1.0,
        ),
        DiagnosisKind::WeakWifiQuality { .. } => {
            (CheckKind::WifiQuality, Metric::RssiDbm, HigherIsBetter, 3.0)
        }
        DiagnosisKind::GatewayUnreachable => {
            (CheckKind::Gateway, Metric::LossPercent, LowerIsBetter, 1.0)
        }
        DiagnosisKind::RouterFault => (
            CheckKind::RouterHealth,
            Metric::RouterResponsive,
            HigherIsBetter,
            0.5,
        ),
        DiagnosisKind::LossLatencyDegraded { .. } => (
            CheckKind::LossLatency,
            Metric::LossPercent,
            LowerIsBetter,
            1.0,
        ),
        DiagnosisKind::MtuBlackhole { .. } => {
            (CheckKind::Mtu, Metric::PassingMtuBytes, HigherIsBetter, 1.0)
        }
        DiagnosisKind::DnsFailure { .. } => (
            CheckKind::Dns,
            Metric::ResolverFailureCount,
            LowerIsBetter,
            1.0,
        ),
        DiagnosisKind::RouteVpnConflict { .. } => (
            CheckKind::RouteVpn,
            Metric::DefaultRouteCount,
            LowerIsBetter,
            1.0,
        ),
        DiagnosisKind::InternetUnreachable { .. } => (
            CheckKind::InternetReachability,
            Metric::ReachabilitySuccess,
            HigherIsBetter,
            0.5,
        ),
        DiagnosisKind::DiagnosticProbeFailure { .. } => return None,
    };
    Symptom::new(check, metric, direction, delta).ok()
}

/// Appends one doctor audit entry; failures are logged and surfaced to the
/// caller so no doctor action goes unrecorded.
async fn append_audit(state: &AppState, entry: NewAuditEntry) -> Result<(), ()> {
    let audit = AuditLog::new(state.state_repository().pool().clone());
    match audit.append(entry).await {
        Ok(_) => Ok(()),
        Err(error) => {
            tracing::error!(%error, "doctor audit append failed");
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;

    #[test]
    fn proc_net_route_yields_the_lowest_metric_gateway_default_route() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
eth0\t00000000\tFE01A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
tun0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n";
        assert_eq!(
            parse_proc_net_route(table),
            Some(("eth0".to_owned(), "192.168.1.254".to_owned()))
        );
        assert_eq!(parse_proc_net_route("Iface\tDestination\n"), None);
        assert_eq!(parse_proc_net_route(""), None);
    }

    #[test]
    fn resolv_conf_nameservers_are_parsed_deduplicated_and_capped() {
        let text = "# generated\nsearch lan\nnameserver 192.168.1.1\nnameserver 192.168.1.1\n\
nameserver fe80::1%eth0\nnameserver not-an-ip\noptions edns0\n";
        assert_eq!(parse_resolv_conf(text), vec!["192.168.1.1", "fe80::1"]);
        let many: String = (0..20)
            .map(|n| format!("nameserver 10.0.0.{n}\n"))
            .collect();
        assert_eq!(parse_resolv_conf(&many).len(), MAX_RESOLVERS);
        assert!(parse_resolv_conf("").is_empty());
    }

    #[test]
    fn platform_settings_never_guess_and_start_unconfirmed() {
        let settings = DoctorSettings::from_platform();
        assert!(!settings.external_probes_confirmed);
        match settings.gateway_source {
            TargetSource::Platform => assert!(settings.gateway.is_some()),
            TargetSource::Unknown => assert!(settings.gateway.is_none()),
            TargetSource::Owner => panic!("platform derivation is never owner-provided"),
        }
        // Whatever was derived, the resulting engine config is valid.
        let config = settings.to_config(&default_profile());
        assert!(DiagnosticEngine::new(config, DiagnosticBudget::new(64, 1_000).unwrap()).is_ok());
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn unknown_targets_become_the_unconfigured_placeholder() {
        let mut settings = DoctorSettings::from_config(&DoctorConfig {
            interface: "eth0".to_owned(),
            gateway: "10.0.0.1".to_owned(),
            configured_resolvers: vec!["10.0.0.1".to_owned()],
            independent_resolver: "9.9.9.9".to_owned(),
            internet_probe_address: "1.1.1.1".to_owned(),
            internet_probe_port: 443,
            dns_probe_name: "example.com".to_owned(),
            ping_count: 1,
            mtu_probe_sizes: vec![1400],
            thresholds: Thresholds::default(),
        });
        settings.apply(DoctorSettingsUpdate {
            gateway: Some(String::new()),
            configured_resolvers: Some(Vec::new()),
            ..DoctorSettingsUpdate::default()
        });
        assert_eq!(settings.gateway, None);
        assert_eq!(settings.gateway_source, TargetSource::Unknown);
        let config = settings.to_config(&default_profile());
        assert_eq!(config.gateway, UNCONFIGURED_TARGET);
        assert_eq!(config.configured_resolvers, vec![UNCONFIGURED_TARGET]);
        assert!(DiagnosticEngine::new(config, DiagnosticBudget::new(64, 1_000).unwrap()).is_ok());
    }

    #[test]
    fn settings_validation_rejects_bad_targets() {
        let base = DoctorSettings::from_platform();
        let cases: [(&str, DoctorSettingsUpdate); 6] = [
            (
                "gateway",
                DoctorSettingsUpdate {
                    gateway: Some("router.local".to_owned()),
                    ..DoctorSettingsUpdate::default()
                },
            ),
            (
                "resolver",
                DoctorSettingsUpdate {
                    configured_resolvers: Some(vec!["dns".to_owned()]),
                    ..DoctorSettingsUpdate::default()
                },
            ),
            (
                "port",
                DoctorSettingsUpdate {
                    internet_probe_port: Some(0),
                    ..DoctorSettingsUpdate::default()
                },
            ),
            (
                "hostname",
                DoctorSettingsUpdate {
                    dns_probe_name: Some("-bad.example".to_owned()),
                    ..DoctorSettingsUpdate::default()
                },
            ),
            (
                "interface",
                DoctorSettingsUpdate {
                    interface: Some("eth 0".to_owned()),
                    ..DoctorSettingsUpdate::default()
                },
            ),
            (
                "too many resolvers",
                DoctorSettingsUpdate {
                    configured_resolvers: Some(vec!["10.0.0.1".to_owned(); 9]),
                    ..DoctorSettingsUpdate::default()
                },
            ),
        ];
        for (label, update) in cases {
            let mut settings = base.clone();
            settings.apply(update);
            assert!(settings.validate().is_err(), "{label}");
        }
        let mut settings = base.clone();
        settings.apply(DoctorSettingsUpdate {
            gateway: Some("10.0.0.1".to_owned()),
            dns_probe_name: Some("probe.example.net".to_owned()),
            ..DoctorSettingsUpdate::default()
        });
        assert!(settings.validate().is_ok());
        assert_eq!(settings.gateway_source, TargetSource::Owner);
    }

    /// Records every request that reaches the inner transport.
    struct Recording(std::sync::Mutex<Vec<ProbeRequest>>);

    impl DynProbeTransport for Recording {
        fn dyn_probe(&self, probe: Probe) -> BoxFuture<'_, Result<ProbeResponse, ProbeError>> {
            self.0.lock().unwrap().push(probe.request);
            async { Err(ProbeError::Unsupported) }.boxed()
        }
    }

    fn probe(request: ProbeRequest) -> Probe {
        Probe {
            request,
            timeout_ms: 100,
        }
    }

    #[tokio::test]
    async fn the_gate_refuses_unconfigured_and_unconfirmed_external_targets() {
        let inner = Recording(std::sync::Mutex::new(Vec::new()));
        let gated = GatedProbes {
            inner: &inner,
            allow_external: false,
        };
        let refused = |result: Result<ProbeResponse, ProbeError>| {
            matches!(result, Err(ProbeError::Transport(_)))
        };
        assert!(refused(
            gated
                .probe(probe(ProbeRequest::Ping {
                    target: UNCONFIGURED_TARGET.to_owned(),
                    payload_bytes: 56,
                    dont_fragment: false,
                }))
                .await
        ));
        assert!(refused(
            gated
                .probe(probe(ProbeRequest::ReachIp {
                    address: "1.1.1.1".to_owned(),
                    port: 443,
                }))
                .await
        ));
        assert!(refused(
            gated
                .probe(probe(ProbeRequest::DnsQuery {
                    resolver: "9.9.9.9".to_owned(),
                    name: "example.com".to_owned(),
                }))
                .await
        ));
        // Private targets and non-dialing probes pass straight through.
        assert!(matches!(
            gated
                .probe(probe(ProbeRequest::Ping {
                    target: "192.168.1.1".to_owned(),
                    payload_bytes: 56,
                    dont_fragment: false,
                }))
                .await,
            Err(ProbeError::Unsupported)
        ));
        assert!(matches!(
            gated.probe(probe(ProbeRequest::RouteTable)).await,
            Err(ProbeError::Unsupported)
        ));
        assert_eq!(inner.0.lock().unwrap().len(), 2);

        // Once confirmed, external targets reach the transport too.
        let confirmed = GatedProbes {
            inner: &inner,
            allow_external: true,
        };
        assert!(matches!(
            confirmed
                .probe(probe(ProbeRequest::ReachIp {
                    address: "1.1.1.1".to_owned(),
                    port: 443,
                }))
                .await,
            Err(ProbeError::Unsupported)
        ));
        // The placeholder is never dialed, confirmed or not.
        assert!(refused(
            confirmed
                .probe(probe(ProbeRequest::ArpProbe {
                    interface: "eth0".to_owned(),
                    address: UNCONFIGURED_TARGET.to_owned(),
                }))
                .await
        ));
        assert_eq!(inner.0.lock().unwrap().len(), 3);
    }
}
