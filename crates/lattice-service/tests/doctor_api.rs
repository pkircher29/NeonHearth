//! Network Doctor route contract tests (M6): envelope shapes, one-run-at-a-time,
//! approval lifecycle, repair execution, and audit-log coverage — all through
//! the real routes with fake transports injected via `DoctorState::with_parts`.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use lattice_doctor::{
    Clock,
    check::{DiagnosticBudget, DiagnosticReport, Measurement, Metric, Unit},
    diagnosis::Diagnosis,
    engine::{DoctorConfig, Thresholds},
    executor::{FakeRepairTransport, RepairReport},
    probe::{
        DnsFailureReason, FakeProbeTransport, LeaseState, Probe, ProbeError, ProbeRequest,
        ProbeResponse, ProbeTransport,
    },
    repair::{RepairContext, RepairPlan},
};
use lattice_service::{
    AppState, app_with_doctor,
    doctor::{DoctorState, DynProbeTransport, DynRepairTransport},
};
use lattice_store::{
    AuditCategory, AuditFilter, AuditLog, AuditPage, M2StateRepository, connect_memory,
};
use sqlx::SqlitePool;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

/// Adjustable deterministic clock for approval-expiry tests.
#[derive(Debug)]
struct TestClock(Mutex<DateTime<Utc>>);

impl TestClock {
    fn starting_at(at: DateTime<Utc>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(at)))
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

fn epoch() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap()
}

fn test_config() -> DoctorConfig {
    DoctorConfig {
        interface: "eth0".to_owned(),
        gateway: "10.0.0.1".to_owned(),
        configured_resolvers: vec!["10.0.0.1".to_owned()],
        independent_resolver: "9.9.9.9".to_owned(),
        internet_probe_address: "1.1.1.1".to_owned(),
        internet_probe_port: 443,
        dns_probe_name: "example.com".to_owned(),
        ping_count: 1,
        mtu_probe_sizes: vec![1400, 1200],
        thresholds: Thresholds::default(),
    }
}

fn test_context() -> RepairContext {
    RepairContext {
        interface: "eth0".to_owned(),
        lease_renewal_severs_only_management_path: true,
        fallback_dns_servers: Vec::new(),
    }
}

/// A network with five distinct faults so one run yields all four repair
/// classes: duplicate IP and an MTU blackhole (approval-required), weak Wi-Fi
/// (guided), router fault (safe-automatic), and DNS failure with no fallback
/// resolvers (observation-only).
fn mixed_fault_probes() -> FakeProbeTransport {
    FakeProbeTransport::new(|request| match request {
        ProbeRequest::CollectorStatus => Ok(ProbeResponse::CollectorStatus {
            privileged: true,
            capture_ok: true,
            worker_running: true,
        }),
        ProbeRequest::LinkStatus { .. } => Ok(ProbeResponse::LinkStatus {
            up: true,
            speed_mbps: Some(1000),
        }),
        ProbeRequest::IpConfig { .. } => Ok(ProbeResponse::IpConfig {
            address: Some("10.0.0.5".to_owned()),
            lease: LeaseState::Valid,
        }),
        ProbeRequest::ArpProbe { .. } => Ok(ProbeResponse::ArpProbe {
            responding_macs: vec![
                "aa:aa:aa:aa:aa:01".to_owned(),
                "bb:bb:bb:bb:bb:02".to_owned(),
            ],
        }),
        ProbeRequest::WifiMetrics { .. } => Ok(ProbeResponse::WifiMetrics {
            wireless: true,
            rssi_dbm: Some(-80),
            retry_percent: None,
        }),
        // The largest don't-fragment probe vanishes silently: MTU blackhole.
        ProbeRequest::Ping {
            dont_fragment: true,
            payload_bytes: 1400,
            ..
        } => Ok(ProbeResponse::PingTimeout),
        ProbeRequest::Ping { .. } => Ok(ProbeResponse::PingReply { rtt_ms: 8.0 }),
        ProbeRequest::DnsQuery { resolver, .. } if resolver == "10.0.0.1" => {
            Ok(ProbeResponse::DnsFailure {
                reason: DnsFailureReason::Timeout,
            })
        }
        ProbeRequest::DnsQuery { .. } => Ok(ProbeResponse::DnsAnswer {
            addresses: vec!["93.184.216.34".to_owned()],
            latency_ms: 20.0,
        }),
        ProbeRequest::RouterStatus => Ok(ProbeResponse::RouterStatus {
            responsive: false,
            uptime_seconds: None,
        }),
        ProbeRequest::RouteTable => Ok(ProbeResponse::RouteTable {
            default_routes: Vec::new(),
        }),
        ProbeRequest::ReachIp { .. } => Ok(ProbeResponse::Reachable { latency_ms: 30.0 }),
    })
}

struct Fixture {
    router: Router,
    pool: SqlitePool,
    clock: Arc<TestClock>,
}

async fn fixture(
    probes: Arc<dyn DynProbeTransport>,
    repairs: Arc<dyn DynRepairTransport>,
) -> Fixture {
    let clock = TestClock::starting_at(epoch());
    let pool = connect_memory().await.unwrap();
    let state = AppState::new(TOKEN, M2StateRepository::new(pool.clone())).unwrap();
    let doctor = DoctorState::with_parts(
        test_config(),
        DiagnosticBudget::new(64, 1_000).unwrap(),
        test_context(),
        clock.clone(),
        probes,
        repairs,
    )
    .unwrap();
    Fixture {
        router: app_with_doctor(state, doctor),
        pool,
        clock,
    }
}

async fn mixed_fixture() -> Fixture {
    fixture(
        Arc::new(mixed_fault_probes()),
        Arc::new(FakeRepairTransport::new()),
    )
    .await
}

fn measurement(metric: Metric, value: f64) -> Measurement {
    Measurement {
        metric,
        value,
        unit: Unit::Count,
        observed_at: epoch(),
    }
}

async fn send(
    router: &Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
    authorized: bool,
) -> axum::response::Response {
    let mut request = Request::builder().method(method).uri(uri);
    if authorized {
        request = request.header("authorization", format!("Bearer {TOKEN}"));
    }
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let body = body
        .map(|value| value.to_string().into_bytes())
        .unwrap_or_default();
    router
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn run_doctor(router: &Router) -> serde_json::Value {
    let response = send(router, "POST", "/api/v1/doctor/run", None, true).await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

/// The `diagnosis.kind` payload of the finding with the given tag.
fn finding_kind(run: &serde_json::Value, tag: &str) -> serde_json::Value {
    run["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["diagnosis"]["kind"]["kind"] == tag)
        .unwrap_or_else(|| panic!("no finding with kind {tag}: {run}"))["diagnosis"]["kind"]
        .clone()
}

async fn doctor_audit_rows(pool: &SqlitePool) -> Vec<lattice_store::AppendedEntry> {
    AuditLog::new(pool.clone())
        .list(
            &AuditFilter {
                category: Some(AuditCategory::DoctorAction),
                ..Default::default()
            },
            AuditPage {
                after_id: None,
                limit: 64,
            },
        )
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Authentication.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_doctor_route_rejects_unauthenticated_requests() {
    let fixture = mixed_fixture().await;
    let kind = serde_json::json!({ "kind": "router_fault" });
    for (method, uri, body) in [
        ("POST", "/api/v1/doctor/run", None),
        ("GET", "/api/v1/doctor/report", None),
        (
            "POST",
            "/api/v1/doctor/approvals",
            Some(serde_json::json!({ "diagnosis_kind": kind })),
        ),
        (
            "POST",
            "/api/v1/doctor/repair",
            Some(serde_json::json!({ "diagnosis_kind": kind })),
        ),
    ] {
        let response = send(&fixture.router, method, uri, body, false).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
    }
}

// ---------------------------------------------------------------------------
// Run + report envelope.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_envelope_matches_the_contract_and_round_trips_the_domain_types() {
    let fixture = mixed_fixture().await;
    let run = run_doctor(&fixture.router).await;

    // Envelope: exactly run_id/started_at/report/findings.
    let keys: Vec<_> = run.as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        ["findings", "report", "run_id", "started_at"],
        "{run}"
    );
    uuid::Uuid::parse_str(run["run_id"].as_str().unwrap()).unwrap();
    assert_eq!(run["started_at"], run["report"]["started_at"]);

    // The report and every finding deserialize losslessly into the
    // lattice-doctor types the UI's validators were derived from.
    let report: DiagnosticReport = serde_json::from_value(run["report"].clone()).unwrap();
    assert_eq!(report.checks.len(), 12);
    assert!(!report.budget_exhausted);
    let findings = run["findings"].as_array().unwrap();
    for finding in findings {
        let keys: Vec<_> = finding.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["diagnosis", "plan"]);
        let _: Diagnosis = serde_json::from_value(finding["diagnosis"].clone()).unwrap();
        let _: RepairPlan = serde_json::from_value(finding["plan"].clone()).unwrap();
    }

    // Findings are the failed checks zipped with their plans, in check order,
    // covering all four repair classes.
    let kinds_and_classes: Vec<_> = findings
        .iter()
        .map(|finding| {
            (
                finding["diagnosis"]["kind"]["kind"].as_str().unwrap(),
                finding["plan"]["class"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        kinds_and_classes,
        [
            ("duplicate_ip", "approval_required_reversible"),
            ("weak_wifi_quality", "guided_physical"),
            ("router_fault", "safe_automatic"),
            ("mtu_blackhole", "approval_required_reversible"),
            ("dns_failure", "observation_only"),
        ],
        "{run}"
    );

    // GET /report serves the same envelope.
    let response = send(&fixture.router, "GET", "/api/v1/doctor/report", None, true).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await, run);
}

#[tokio::test]
async fn report_is_204_until_a_run_completes() {
    let fixture = mixed_fixture().await;
    let response = send(&fixture.router, "GET", "/api/v1/doctor/report", None, true).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    run_doctor(&fixture.router).await;
    let response = send(&fixture.router, "GET", "/api/v1/doctor/report", None, true).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// Signals when the first probe starts, then blocks until permits arrive.
#[derive(Debug)]
struct GatedProbes {
    started: tokio::sync::mpsc::UnboundedSender<()>,
    gate: Arc<tokio::sync::Semaphore>,
}

impl ProbeTransport for GatedProbes {
    async fn probe(&self, _probe: Probe) -> Result<ProbeResponse, ProbeError> {
        let _ = self.started.send(());
        let _permit = self
            .gate
            .acquire()
            .await
            .map_err(|_| ProbeError::Transport("gate closed".to_owned()))?;
        Err(ProbeError::Unsupported)
    }
}

#[tokio::test]
async fn a_concurrent_run_is_refused_with_409_and_a_later_run_is_accepted() {
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let fixture = fixture(
        Arc::new(GatedProbes {
            started: started_tx,
            gate: Arc::clone(&gate),
        }),
        Arc::new(FakeRepairTransport::new()),
    )
    .await;

    let router = fixture.router.clone();
    let first =
        tokio::spawn(async move { send(&router, "POST", "/api/v1/doctor/run", None, true).await });
    started_rx.recv().await.expect("first run reached a probe");

    let second = send(&fixture.router, "POST", "/api/v1/doctor/run", None, true).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);

    gate.add_permits(1_000);
    let first = first.await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    // The slot is released after completion: a new run is accepted.
    let third = send(&fixture.router, "POST", "/api/v1/doctor/run", None, true).await;
    assert_eq!(third.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Approvals.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approvals_404_without_a_matching_approval_required_plan() {
    let fixture = mixed_fixture().await;

    // No run yet.
    let body = serde_json::json!({ "diagnosis_kind": { "kind": "adapter_link_down" } });
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/approvals",
        Some(body),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let run = run_doctor(&fixture.router).await;
    // A kind absent from the latest run.
    let absent = serde_json::json!({ "diagnosis_kind": { "kind": "gateway_unreachable" } });
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/approvals",
        Some(absent),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // A present kind whose plan is safe-automatic, not approval-required.
    let safe = serde_json::json!({ "diagnosis_kind": finding_kind(&run, "router_fault") });
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/approvals",
        Some(safe),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn minting_an_approval_returns_a_ten_minute_token_and_is_audited() {
    let fixture = mixed_fixture().await;
    let run = run_doctor(&fixture.router).await;
    let kind = finding_kind(&run, "duplicate_ip");
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/approvals",
        Some(serde_json::json!({ "diagnosis_kind": kind })),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let approval = json_body(response).await;
    let keys: Vec<_> = approval.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["approval_id", "expires_at"]);
    assert!(!approval["approval_id"].as_str().unwrap().is_empty());
    let expires_at: DateTime<Utc> = approval["expires_at"].as_str().unwrap().parse().unwrap();
    assert_eq!(expires_at, epoch() + Duration::minutes(10));

    let rows = doctor_audit_rows(&fixture.pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "approval_minted");
    assert_eq!(rows[0].subject.as_deref(), Some("duplicate_ip"));
    assert_eq!(
        rows[0].detail["approval_id"], approval["approval_id"],
        "{rows:?}"
    );
}

// ---------------------------------------------------------------------------
// Repair.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn safe_automatic_repair_executes_without_approval_and_is_audited() {
    let repairs = FakeRepairTransport::new()
        .push_measurements(vec![measurement(Metric::RouterResponsive, 0.0)])
        .push_measurements(vec![measurement(Metric::RouterResponsive, 1.0)]);
    let fixture = fixture(Arc::new(mixed_fault_probes()), Arc::new(repairs)).await;
    let run = run_doctor(&fixture.router).await;
    let kind = finding_kind(&run, "router_fault");
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/repair",
        Some(serde_json::json!({ "diagnosis_kind": kind })),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let keys: Vec<_> = body.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["repair"]);
    let repair: RepairReport = serde_json::from_value(body["repair"].clone()).unwrap();
    assert_eq!(repair.description, "retry_router_session");
    assert_eq!(
        body["repair"]["outcome"],
        serde_json::json!({ "outcome": "completed", "verdict": "improved" })
    );
    let verification = repair.verification.expect("verification present");
    assert_eq!(verification.before.value, 0.0);
    assert_eq!(verification.after.value, 1.0);

    let rows = doctor_audit_rows(&fixture.pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "repair_executed");
    assert_eq!(rows[0].subject.as_deref(), Some("router_fault"));
    assert_eq!(rows[0].detail["outcome"]["outcome"], "completed");
    assert_eq!(rows[0].detail["rollback"]["outcome"], "not_attempted");
}

#[tokio::test]
async fn approval_required_repair_needs_a_live_unused_matching_approval() {
    let repairs = FakeRepairTransport::new()
        .push_measurements(vec![measurement(Metric::ConflictingMacCount, 2.0)])
        .push_measurements(vec![measurement(Metric::ConflictingMacCount, 1.0)]);
    let fixture = fixture(Arc::new(mixed_fault_probes()), Arc::new(repairs)).await;
    let run = run_doctor(&fixture.router).await;
    let kind = finding_kind(&run, "duplicate_ip");

    // Without an approval id: 403.
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/repair",
        Some(serde_json::json!({ "diagnosis_kind": kind })),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // With an unknown approval id: 403.
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/repair",
        Some(serde_json::json!({ "diagnosis_kind": kind, "approval_id": "bogus" })),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Mint an approval, then execute with it.
    let approval = json_body(
        send(
            &fixture.router,
            "POST",
            "/api/v1/doctor/approvals",
            Some(serde_json::json!({ "diagnosis_kind": kind })),
            true,
        )
        .await,
    )
    .await;
    let approval_id = approval["approval_id"].clone();
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/repair",
        Some(serde_json::json!({ "diagnosis_kind": kind, "approval_id": approval_id })),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["repair"]["class"], "approval_required_reversible");
    assert_eq!(body["repair"]["outcome"]["verdict"], "improved");

    // Single-use: the same token is refused a second time.
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/repair",
        Some(serde_json::json!({ "diagnosis_kind": kind, "approval_id": approval_id })),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_expired_approval_is_refused() {
    let fixture = mixed_fixture().await;
    let run = run_doctor(&fixture.router).await;
    let kind = finding_kind(&run, "duplicate_ip");
    let approval = json_body(
        send(
            &fixture.router,
            "POST",
            "/api/v1/doctor/approvals",
            Some(serde_json::json!({ "diagnosis_kind": kind })),
            true,
        )
        .await,
    )
    .await;
    fixture
        .clock
        .advance(Duration::minutes(10) + Duration::seconds(1));
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/repair",
        Some(serde_json::json!({
            "diagnosis_kind": kind,
            "approval_id": approval["approval_id"],
        })),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_approval_for_a_different_diagnosis_does_not_authorize_this_repair() {
    let fixture = mixed_fixture().await;
    let run = run_doctor(&fixture.router).await;
    // Both kinds are approval-required in the latest run, but the token was
    // minted for the duplicate-IP repair only: its fingerprint must not
    // authorize the MTU repair.
    let approved_kind = finding_kind(&run, "duplicate_ip");
    let other_kind = finding_kind(&run, "mtu_blackhole");
    let approval = json_body(
        send(
            &fixture.router,
            "POST",
            "/api/v1/doctor/approvals",
            Some(serde_json::json!({ "diagnosis_kind": approved_kind })),
            true,
        )
        .await,
    )
    .await;
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/repair",
        Some(serde_json::json!({
            "diagnosis_kind": other_kind,
            "approval_id": approval["approval_id"],
        })),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn guided_and_observation_plans_are_never_executable() {
    let fixture = mixed_fixture().await;
    let run = run_doctor(&fixture.router).await;
    for tag in ["weak_wifi_quality", "dns_failure"] {
        let kind = finding_kind(&run, tag);
        let response = send(
            &fixture.router,
            "POST",
            "/api/v1/doctor/repair",
            Some(serde_json::json!({ "diagnosis_kind": kind })),
            true,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{tag}");
    }
}

#[tokio::test]
async fn repair_404s_without_a_matching_latest_run_plan() {
    let fixture = mixed_fixture().await;
    let body = serde_json::json!({ "diagnosis_kind": { "kind": "router_fault" } });
    // No run yet.
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/repair",
        Some(body),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    run_doctor(&fixture.router).await;
    // A kind the latest run did not diagnose.
    let absent = serde_json::json!({ "diagnosis_kind": { "kind": "gateway_unreachable" } });
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/repair",
        Some(absent),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mint_and_execution_both_append_doctor_action_audit_rows() {
    let repairs = FakeRepairTransport::new()
        .push_measurements(vec![measurement(Metric::ConflictingMacCount, 2.0)])
        .push_measurements(vec![measurement(Metric::ConflictingMacCount, 1.0)]);
    let fixture = fixture(Arc::new(mixed_fault_probes()), Arc::new(repairs)).await;
    let run = run_doctor(&fixture.router).await;
    let kind = finding_kind(&run, "duplicate_ip");
    let approval = json_body(
        send(
            &fixture.router,
            "POST",
            "/api/v1/doctor/approvals",
            Some(serde_json::json!({ "diagnosis_kind": kind })),
            true,
        )
        .await,
    )
    .await;
    let response = send(
        &fixture.router,
        "POST",
        "/api/v1/doctor/repair",
        Some(serde_json::json!({
            "diagnosis_kind": kind,
            "approval_id": approval["approval_id"],
        })),
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let rows = doctor_audit_rows(&fixture.pool).await;
    let actions: Vec<_> = rows.iter().map(|row| row.action.as_str()).collect();
    assert_eq!(actions, ["approval_minted", "repair_executed"]);
    for row in &rows {
        assert_eq!(row.category, AuditCategory::DoctorAction);
        assert_eq!(row.subject.as_deref(), Some("duplicate_ip"));
    }
    assert_eq!(rows[1].detail["approval_id"], approval["approval_id"]);
    assert!(rows[1].detail["rollback"].is_object());
}

// ---------------------------------------------------------------------------
// OpenAPI registration.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openapi_documents_all_doctor_routes_and_schemas() {
    let fixture = mixed_fixture().await;
    let response = send(&fixture.router, "GET", "/api/v1/openapi.json", None, false).await;
    assert_eq!(response.status(), StatusCode::OK);
    let doc = json_body(response).await;
    for (path, method) in [
        ("/api/v1/doctor/run", "post"),
        ("/api/v1/doctor/report", "get"),
        ("/api/v1/doctor/approvals", "post"),
        ("/api/v1/doctor/repair", "post"),
    ] {
        let operation = &doc["paths"][path][method];
        assert!(operation.is_object(), "missing {method} {path}");
        assert!(
            operation["security"].is_array(),
            "{method} {path} must document bearer auth"
        );
        assert!(
            operation["responses"]["401"].is_object(),
            "{method} {path} must document 401"
        );
    }
    assert!(doc["paths"]["/api/v1/doctor/run"]["post"]["responses"]["409"].is_object());
    assert!(doc["paths"]["/api/v1/doctor/report"]["get"]["responses"]["204"].is_object());
    assert!(doc["paths"]["/api/v1/doctor/approvals"]["post"]["responses"]["404"].is_object());
    assert!(doc["paths"]["/api/v1/doctor/repair"]["post"]["responses"]["403"].is_object());
    assert!(doc["paths"]["/api/v1/doctor/repair"]["post"]["responses"]["400"].is_object());
    let schemas = &doc["components"]["schemas"];
    for name in [
        "DoctorRun",
        "DoctorFinding",
        "DoctorApproval",
        "DoctorApprovalRequest",
        "DoctorRepairRequest",
        "DoctorRepairResponse",
        "DiagnosticReport",
        "CheckResult",
        "Measurement",
        "Diagnosis",
        "DiagnosisKind",
        "RepairPlan",
        "RepairReport",
        "Verification",
        "RollbackOutcome",
        "RepairEvent",
    ] {
        assert!(schemas[name].is_object(), "missing schema {name}");
    }
    assert_eq!(
        doc["paths"]["/api/v1/doctor/run"]["post"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["$ref"],
        "#/components/schemas/DoctorRun"
    );
}
