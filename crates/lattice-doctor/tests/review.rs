//! Regression tests for the review findings: probe errors are not packet loss,
//! MTU units, duplicate-address claimants, hung transports, settling and
//! rollback policy, and config validation.

use chrono::{TimeZone, Utc};
use lattice_doctor::FixedClock;
use lattice_doctor::check::{
    CheckDetail, CheckKind, CheckStatus, Confidence, DiagnosticBudget, Measurement, Metric, Unit,
};
use lattice_doctor::diagnosis::{DiagnosisKind, diagnose};
use lattice_doctor::engine::{DiagnosticEngine, DoctorConfig, Thresholds};
use lattice_doctor::executor::{
    FakeRepairTransport, MetricDirection, RepairExecutor, RepairOutcome, RepairTimeouts,
    RepairTransport, RepairTransportError, RollbackOutcome, RollbackSkipReason, SettlePolicy,
    StateEntry, Symptom, Verdict,
};
use lattice_doctor::probe::{
    FakeProbeTransport, LeaseState, Probe, ProbeError, ProbeRequest, ProbeResponse, ProbeTransport,
    RouteEntry,
};
use lattice_doctor::repair::{
    ApprovalAction, ApprovalId, ApprovedRepair, ExecutableRepair, RepairClass, RepairContext,
    StateKey, plan_repair,
};
use lattice_doctor::types::{InterfaceName, IpVersion, MacAddr};
use std::sync::Mutex;
use std::time::Duration;

fn config() -> DoctorConfig {
    DoctorConfig {
        interface: "eth0".into(),
        gateway: "192.168.1.1".into(),
        configured_resolvers: vec!["192.168.1.1".into()],
        independent_resolver: "1.1.1.1".into(),
        internet_probe_address: "93.184.216.34".into(),
        internet_probe_port: 443,
        dns_probe_name: "connectivity-check.example".into(),
        ping_count: 3,
        mtu_probe_sizes: vec![1472, 1400],
        thresholds: Thresholds::default(),
    }
}

fn engine(config: DoctorConfig) -> DiagnosticEngine {
    DiagnosticEngine::with_clock(
        config,
        DiagnosticBudget::new(64, 1_000).unwrap(),
        FixedClock(Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap()),
    )
    .unwrap()
}

fn healthy(request: &ProbeRequest) -> Result<ProbeResponse, ProbeError> {
    Ok(match request {
        ProbeRequest::CollectorStatus => ProbeResponse::CollectorStatus {
            privileged: true,
            capture_ok: true,
            worker_running: true,
        },
        ProbeRequest::LinkStatus { .. } => ProbeResponse::LinkStatus {
            up: true,
            speed_mbps: Some(1_000),
        },
        ProbeRequest::IpConfig { .. } => ProbeResponse::IpConfig {
            address: Some("192.168.1.50".into()),
            lease: LeaseState::Valid,
        },
        ProbeRequest::ArpProbe { .. } => ProbeResponse::ArpProbe {
            responding_macs: Vec::new(),
        },
        ProbeRequest::WifiMetrics { .. } => ProbeResponse::WifiMetrics {
            wireless: false,
            rssi_dbm: None,
            retry_percent: None,
        },
        ProbeRequest::Ping { .. } => ProbeResponse::PingReply { rtt_ms: 5.0 },
        ProbeRequest::DnsQuery { .. } => ProbeResponse::DnsAnswer {
            addresses: vec!["93.184.216.34".into()],
            latency_ms: 12.0,
        },
        ProbeRequest::RouteTable => ProbeResponse::RouteTable {
            default_routes: vec![RouteEntry {
                interface: "eth0".into(),
                gateway: "192.168.1.1".into(),
                is_vpn: false,
                metric: 100,
            }],
        },
        ProbeRequest::RouterStatus => ProbeResponse::RouterStatus {
            responsive: true,
            uptime_seconds: None,
        },
        ProbeRequest::ReachIp { .. } => ProbeResponse::Reachable { latency_ms: 20.0 },
    })
}

fn context() -> RepairContext {
    RepairContext {
        interface: "eth0".into(),
        lease_renewal_severs_only_management_path: false,
        fallback_dns_servers: Vec::new(),
    }
}

#[tokio::test]
async fn transport_errors_are_not_packet_loss_and_never_propose_a_router_reboot() {
    // Regression: a raw-socket permission error on every ping was counted as
    // 100% loss, so the gateway check "failed" with HIGH confidence and the
    // plan was RebootRouter.
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::Ping { .. } => Err(ProbeError::Transport("permission denied".into())),
        other => healthy(other),
    });
    let report = engine(config()).run(&transport).await;
    let gateway = report.check(CheckKind::Gateway).unwrap();
    assert_eq!(gateway.status, CheckStatus::Failed);
    assert_eq!(gateway.confidence, Confidence::LOW);
    assert!(matches!(
        gateway.detail,
        Some(CheckDetail::ProbeFailure { .. })
    ));
    let diagnoses = diagnose(&report);
    assert!(
        diagnoses
            .iter()
            .any(|d| matches!(d.kind, DiagnosisKind::DiagnosticProbeFailure { .. }))
    );
    for diagnosis in &diagnoses {
        assert_eq!(
            plan_repair(&diagnosis.kind, &context()).class(),
            RepairClass::ObservationOnly,
            "{:?}",
            diagnosis.kind
        );
    }
}

#[tokio::test]
async fn genuine_timeouts_still_count_as_loss() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::Ping {
            dont_fragment: false,
            ..
        } => Ok(ProbeResponse::PingTimeout),
        other => healthy(other),
    });
    let report = engine(config()).run(&transport).await;
    let gateway = report.check(CheckKind::Gateway).unwrap();
    assert_eq!(gateway.status, CheckStatus::Failed);
    assert_eq!(gateway.confidence, Confidence::HIGH);
    assert!(
        diagnose(&report)
            .iter()
            .any(|d| d.kind == DiagnosisKind::GatewayUnreachable)
    );
}

#[tokio::test]
async fn one_lost_df_echo_is_not_an_mtu_blackhole() {
    // Regression: each size was probed once, so a single dropped packet at
    // 1472 produced a blackhole diagnosis and an MTU change proposal.
    let seen = Mutex::new(0u32);
    let transport = FakeProbeTransport::new(move |request| match request {
        ProbeRequest::Ping {
            dont_fragment: true,
            payload_bytes: 1472,
            ..
        } => {
            let mut count = seen.lock().unwrap();
            *count += 1;
            Ok(if *count == 1 {
                ProbeResponse::PingTimeout
            } else {
                ProbeResponse::PingReply { rtt_ms: 9.0 }
            })
        }
        other => healthy(other),
    });
    let report = engine(config()).run(&transport).await;
    assert_eq!(
        report.check(CheckKind::Mtu).unwrap().status,
        CheckStatus::Passed
    );
}

#[tokio::test]
async fn mtu_detail_names_payload_bytes_and_ip_version() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::Ping {
            dont_fragment: true,
            payload_bytes: 1472,
            ..
        } => Ok(ProbeResponse::PingTimeout),
        other => healthy(other),
    });
    let report = engine(config()).run(&transport).await;
    let mtu = diagnose(&report)
        .into_iter()
        .find(|d| matches!(d.kind, DiagnosisKind::MtuBlackhole { .. }))
        .unwrap();
    assert_eq!(
        mtu.kind,
        DiagnosisKind::MtuBlackhole {
            largest_passing_payload_bytes: Some(1400),
            smallest_failing_payload_bytes: Some(1472),
            ip_version: IpVersion::V4,
        }
    );
}

#[tokio::test]
async fn arp_claimants_are_parsed_deduplicated_capped_and_exclude_the_host() {
    let own: MacAddr = "aa:aa:aa:aa:aa:01".parse().unwrap();
    let mut macs: Vec<String> = vec![
        "aa:aa:aa:aa:aa:01".into(),
        "not-a-mac".into(),
        "01:00:5e:00:00:01".into(),
        "ba:bb:bb:bb:bb:02".into(),
    ];
    macs.extend((0..40).map(|n| format!("cc:cc:cc:cc:cc:{n:02x}")));
    let transport = FakeProbeTransport::new(move |request| match request {
        ProbeRequest::ArpProbe { .. } => Ok(ProbeResponse::ArpProbe {
            responding_macs: macs.clone(),
        }),
        other => healthy(other),
    });
    let report = engine(config())
        .with_local_macs(vec![own])
        .run(&transport)
        .await;
    let Some(CheckDetail::DuplicateIp { macs, .. }) =
        report.check(CheckKind::DuplicateIp).unwrap().detail.clone()
    else {
        panic!("duplicate-ip detail expected");
    };
    assert!(macs.len() <= 8, "unbounded claimant list: {}", macs.len());
    assert!(!macs.contains(&own));
    // With the host's own MAC known, one other responder is already a conflict.
    let single = FakeProbeTransport::new(|request| match request {
        ProbeRequest::ArpProbe { .. } => Ok(ProbeResponse::ArpProbe {
            responding_macs: vec!["ba:bb:bb:bb:bb:02".into()],
        }),
        other => healthy(other),
    });
    let report = engine(config())
        .with_local_macs(vec![own])
        .run(&single)
        .await;
    assert_eq!(
        report.check(CheckKind::DuplicateIp).unwrap().status,
        CheckStatus::Failed
    );
}

struct HangingTransport;
impl ProbeTransport for HangingTransport {
    async fn probe(&self, _probe: Probe) -> Result<ProbeResponse, ProbeError> {
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn a_transport_that_ignores_its_timeout_cannot_hang_the_run() {
    // Regression: `send` awaited the transport with no bound of its own.
    let report = tokio::time::timeout(
        Duration::from_secs(600),
        engine(config()).run(&HangingTransport),
    )
    .await
    .expect("run must finish despite a hung transport");
    assert!(!report.checks.is_empty());
}

#[test]
fn free_text_config_values_cannot_be_option_shaped() {
    for mutate in [
        |c: &mut DoctorConfig| c.gateway = "-c1".into(),
        |c: &mut DoctorConfig| c.interface = "--rm".into(),
        |c: &mut DoctorConfig| c.configured_resolvers = vec!["9.9.9.9".into(), "-x".into()],
        |c: &mut DoctorConfig| c.independent_resolver = "a b".into(),
        |c: &mut DoctorConfig| c.internet_probe_address = "$(id)".into(),
        |c: &mut DoctorConfig| c.dns_probe_name = "--help".into(),
    ] {
        let mut bad = config();
        mutate(&mut bad);
        assert!(DiagnosticEngine::new(bad, DiagnosticBudget::new(10, 100).unwrap()).is_err());
    }
    assert!(DiagnosticEngine::new(config(), DiagnosticBudget::new(10, 100).unwrap()).is_ok());
}

// ---- executor ---------------------------------------------------------------

fn meas(value: f64) -> Measurement {
    Measurement {
        metric: Metric::LossPercent,
        value,
        unit: Unit::Percent,
        observed_at: Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap(),
    }
}

fn symptom() -> Symptom {
    Symptom::new(
        CheckKind::LossLatency,
        Metric::LossPercent,
        MetricDirection::LowerIsBetter,
        1.0,
    )
    .unwrap()
}

fn reboot() -> ExecutableRepair {
    ExecutableRepair::Approved(ApprovedRepair::new(
        ApprovalAction::RebootRouter,
        ApprovalId::try_new("approval-1").unwrap(),
    ))
}

fn dns() -> ExecutableRepair {
    ExecutableRepair::Approved(ApprovedRepair::new(
        ApprovalAction::ChangeDnsServers {
            servers: vec!["9.9.9.9".parse().unwrap()],
        },
        ApprovalId::try_new("approval-2").unwrap(),
    ))
}

fn executor() -> RepairExecutor {
    RepairExecutor::with_clock(FixedClock(
        Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap(),
    ))
}

#[tokio::test(start_paused = true)]
async fn a_router_reboot_is_judged_after_it_settles_not_while_it_is_down() {
    // Regression: the symptom was re-measured immediately, saw the outage the
    // reboot itself causes, called it a regression and "rolled back".
    let transport = FakeRepairTransport::new()
        .with_snapshot(vec![StateEntry {
            key: StateKey::RouterSession,
            value: "s".into(),
        }])
        .push_measurements(vec![meas(50.0)]) // baseline
        .push_measurements(vec![meas(100.0)]) // router still rebooting
        .push_measurements(vec![meas(100.0)])
        .push_measurements(vec![meas(2.0)]); // back up
    let report = executor().execute(&transport, &reboot(), &symptom()).await;
    assert_eq!(
        report.outcome,
        RepairOutcome::Completed {
            verdict: Verdict::Improved
        }
    );
    assert_eq!(
        report.rollback,
        RollbackOutcome::NotAttempted {
            reason: RollbackSkipReason::NotNeeded
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_reboot_that_never_recovers_is_reported_without_a_pretend_rollback() {
    let mut transport = FakeRepairTransport::new().push_measurements(vec![meas(10.0)]);
    for _ in 0..80 {
        transport = transport.push_measurements(vec![meas(100.0)]);
    }
    let report = executor().execute(&transport, &reboot(), &symptom()).await;
    assert_eq!(
        report.outcome,
        RepairOutcome::Completed {
            verdict: Verdict::Regressed
        }
    );
    // A reboot cannot be undone by writing a snapshot back.
    assert_eq!(
        report.rollback,
        RollbackOutcome::NotAttempted {
            reason: RollbackSkipReason::NotReversible
        }
    );
}

struct StuckApply;
impl RepairTransport for StuckApply {
    async fn snapshot(&self, _: &[StateKey]) -> Result<Vec<StateEntry>, RepairTransportError> {
        Ok(Vec::new())
    }
    async fn apply(&self, _: &ExecutableRepair) -> Result<(), RepairTransportError> {
        std::future::pending().await
    }
    async fn restore(&self, _: &[StateEntry]) -> Result<(), RepairTransportError> {
        Ok(())
    }
    async fn measure(&self, _: CheckKind) -> Result<Vec<Measurement>, RepairTransportError> {
        Ok(vec![meas(10.0)])
    }
}

#[tokio::test(start_paused = true)]
async fn every_transport_call_has_a_timeout() {
    // Regression: a hung `apply` stalled the executor indefinitely.
    let report = tokio::time::timeout(
        Duration::from_secs(3_600),
        executor()
            .with_timeouts(RepairTimeouts {
                apply: Duration::from_secs(5),
                ..RepairTimeouts::default()
            })
            .with_settle_policy(SettlePolicy::Immediate)
            .execute(&StuckApply, &dns(), &symptom()),
    )
    .await
    .expect("executor must not hang");
    match report.outcome {
        RepairOutcome::ApplyFailed { error } => assert!(error.contains("timed out"), "{error}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn unchanged_reversible_repairs_roll_back_only_when_asked() {
    let build = || {
        FakeRepairTransport::new()
            .push_measurements(vec![meas(10.0)])
            .push_measurements(vec![meas(10.0)])
            .push_measurements(vec![meas(10.0)])
    };
    let kept = executor()
        .with_settle_policy(SettlePolicy::Immediate)
        .execute(&build(), &dns(), &symptom())
        .await;
    assert_eq!(
        kept.rollback,
        RollbackOutcome::NotAttempted {
            reason: RollbackSkipReason::NotNeeded
        }
    );
    let reverted = executor()
        .with_settle_policy(SettlePolicy::Immediate)
        .rollback_unchanged(true)
        .execute(&build(), &dns(), &symptom())
        .await;
    assert_eq!(reverted.rollback, RollbackOutcome::Succeeded);
}

#[test]
fn symptom_deserialisation_enforces_the_constructor_rules() {
    // Regression: derived Deserialize bypassed `Symptom::new`, so a zero delta
    // made every unchanged result "Improved" and Regressed unreachable.
    let json = |delta: &str| {
        format!(
            r#"{{"check":"loss_latency","metric":"loss_percent","direction":"lower_is_better","min_meaningful_delta":{delta}}}"#
        )
    };
    assert!(serde_json::from_str::<Symptom>(&json("0.0")).is_err());
    assert!(serde_json::from_str::<Symptom>(&json("-1.0")).is_err());
    assert!(serde_json::from_str::<Symptom>(&json("1.0")).is_ok());
    let _ = InterfaceName::parse("eth0").unwrap();
}

#[tokio::test]
async fn an_undecided_reservation_is_refused_before_any_transport_call() {
    let undecided = ExecutableRepair::Approved(ApprovedRepair::new(
        ApprovalAction::SetDhcpReservation {
            address: "192.168.1.50".parse().unwrap(),
            claimants: vec!["aa:aa:aa:aa:aa:aa".parse().unwrap()],
            chosen: None,
        },
        ApprovalId::try_new("approval-3").unwrap(),
    ));
    let transport = FakeRepairTransport::new();
    let report = executor().execute(&transport, &undecided, &symptom()).await;
    assert!(matches!(report.outcome, RepairOutcome::ApplyFailed { .. }));
    assert!(transport.calls().is_empty());
}
