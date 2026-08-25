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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{AppState, auth::Authorized};

/// How long a minted approval stays live (contract: 10 minutes, single-use).
const APPROVAL_TTL_MINUTES: i64 = 10;

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

/// Adapts the stored dyn transport back into the engine's transport trait.
struct ProbeAdapter<'a>(&'a dyn DynProbeTransport);

impl ProbeTransport for ProbeAdapter<'_> {
    async fn probe(&self, probe: Probe) -> Result<ProbeResponse, ProbeError> {
        self.0.dyn_probe(probe).await
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
    engine: DiagnosticEngine,
    context: RepairContext,
    clock: Arc<dyn Clock>,
    probes: Arc<dyn DynProbeTransport>,
    repairs: Arc<dyn DynRepairTransport>,
    /// One diagnostic at a time (contract: concurrent runs get 409).
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
    /// The placeholder network targets in the default config are inert: every
    /// network probe reports `Unsupported`, so nothing is ever dialed. They
    /// exist only to satisfy the engine's non-empty-config validation.
    pub fn for_service(state: &AppState) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let config = default_config();
        let context = default_context(&config);
        let budget = DiagnosticBudget::new(64, 2_000).expect("default budget is valid");
        let probes: Arc<dyn DynProbeTransport> = Arc::new(ServiceProbeTransport {
            state: state.clone(),
        });
        let repairs: Arc<dyn DynRepairTransport> = Arc::new(ServiceRepairTransport {
            state: state.clone(),
            clock: Arc::clone(&clock),
        });
        Self::with_parts(config, budget, context, clock, probes, repairs)
            .expect("default doctor configuration is valid")
    }

    /// Assemble a doctor with injected config, clock, and transports — the
    /// seam tests use to run the real routes against fake transports.
    pub fn with_parts(
        config: DoctorConfig,
        budget: DiagnosticBudget,
        context: RepairContext,
        clock: Arc<dyn Clock>,
        probes: Arc<dyn DynProbeTransport>,
        repairs: Arc<dyn DynRepairTransport>,
    ) -> Result<Self, DoctorError> {
        let engine = DiagnosticEngine::with_clock(config, budget, SharedClock(Arc::clone(&clock)))?;
        Ok(Self {
            shared: Arc::new(DoctorShared {
                engine,
                context,
                clock,
                probes,
                repairs,
                running: AtomicBool::new(false),
                inner: tokio::sync::Mutex::new(DoctorInner::default()),
            }),
        })
    }
}

/// Placeholder probe targets for the production config (see
/// [`DoctorState::for_service`]).
fn default_config() -> DoctorConfig {
    DoctorConfig {
        interface: "primary".to_owned(),
        gateway: "192.168.1.1".to_owned(),
        configured_resolvers: vec!["192.168.1.1".to_owned()],
        independent_resolver: "9.9.9.9".to_owned(),
        internet_probe_address: "1.1.1.1".to_owned(),
        internet_probe_port: 443,
        dns_probe_name: "example.com".to_owned(),
        ping_count: 4,
        mtu_probe_sizes: vec![1472, 1400, 1200],
        thresholds: Thresholds::default(),
    }
}

/// Conservative classification facts: lease renewal is assumed to risk the
/// only management path (so it requires approval), and no known-good fallback
/// resolvers are configured (so DNS failures stay observation-only).
fn default_context(config: &DoctorConfig) -> RepairContext {
    RepairContext {
        interface: config.interface.clone(),
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
    let report = shared
        .engine
        .run(&ProbeAdapter(shared.probes.as_ref()))
        .await;
    let findings = diagnose(&report)
        .into_iter()
        .map(|diagnosis| {
            let plan = plan_repair(&diagnosis.kind, &shared.context);
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

#[utoipa::path(post, path = "/api/v1/doctor/repair", request_body = DoctorRepairRequest, responses((status = 200, body = DoctorRepairResponse), (status = 400, description = "guided/observation plans are never executable"), (status = 401), (status = 403, description = "missing, expired, used, or mismatched approval"), (status = 404, description = "the latest run has no plan for this diagnosis"), (status = 503)), security(("bearer_auth" = [])))]
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
