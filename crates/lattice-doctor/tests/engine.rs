//! Diagnostic engine tests: DAG ordering, short-circuit skipping, budget
//! exhaustion, and diagnosis mapping from synthetic probe evidence.

use chrono::{TimeZone, Utc};
use lattice_doctor::FixedClock;
use lattice_doctor::check::{
    CheckKind, CheckStatus, DiagnosticBudget, Metric, ResolverOutcome, SkipReason,
};
use lattice_doctor::diagnosis::{DiagnosisKind, diagnose};
use lattice_doctor::engine::{DiagnosticEngine, DoctorConfig, Thresholds};
use lattice_doctor::probe::{
    DnsFailureReason, FakeProbeTransport, LeaseState, ProbeError, ProbeRequest, ProbeResponse,
    RouteEntry,
};
use lattice_doctor::repair::{ApprovalAction, RepairContext, RepairPlan, plan_repair};
use std::sync::Mutex;

fn config() -> DoctorConfig {
    DoctorConfig {
        interface: "eth0".into(),
        gateway: "192.168.1.1".into(),
        configured_resolvers: vec!["192.168.1.1".into(), "9.9.9.9".into()],
        independent_resolver: "1.1.1.1".into(),
        internet_probe_address: "93.184.216.34".into(),
        internet_probe_port: 443,
        dns_probe_name: "connectivity-check.example".into(),
        ping_count: 3,
        mtu_probe_sizes: vec![1500, 1400, 1200],
        thresholds: Thresholds::default(),
    }
}

fn engine_with(max_probes: u32) -> DiagnosticEngine {
    let clock = FixedClock(Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap());
    DiagnosticEngine::with_clock(
        config(),
        DiagnosticBudget::new(max_probes, 1_000).unwrap(),
        clock,
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
            responding_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
        },
        ProbeRequest::WifiMetrics { .. } => ProbeResponse::WifiMetrics {
            wireless: true,
            rssi_dbm: Some(-55),
            retry_percent: Some(1.0),
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
            uptime_seconds: Some(86_400),
        },
        ProbeRequest::ReachIp { .. } => ProbeResponse::Reachable { latency_ms: 20.0 },
    })
}

#[tokio::test]
async fn healthy_network_passes_every_check_in_dag_order() {
    let transport = FakeProbeTransport::new(healthy);
    let report = engine_with(64).run(&transport).await;

    assert_eq!(report.checks.len(), 12);
    let order: Vec<CheckKind> = report.checks.iter().map(|check| check.kind).collect();
    assert_eq!(order, CheckKind::EXECUTION_ORDER.to_vec());
    for check in &report.checks {
        assert_eq!(check.status, CheckStatus::Passed, "{:?}", check.kind);
    }
    // collector 1 + link 1 + ip 1 + arp 1 + wifi 1 + gateway 3 + router 1
    // + loss 3 + mtu 3 + dns 3 + route 1 + internet 1
    assert_eq!(report.probes_used, 20);
    assert!(!report.budget_exhausted);
    assert_eq!(transport.probes().len(), 20);
}

#[tokio::test]
async fn adapter_down_short_circuits_descendants_without_probing_them() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::LinkStatus { .. } => Ok(ProbeResponse::LinkStatus {
            up: false,
            speed_mbps: None,
        }),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;

    assert_eq!(
        report.check(CheckKind::AdapterLink).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        report.check(CheckKind::AddressDhcp).unwrap().status,
        CheckStatus::Skipped {
            because: SkipReason::DependencyFailed {
                dependency: CheckKind::AdapterLink
            }
        }
    );
    assert_eq!(
        report.check(CheckKind::Dns).unwrap().status,
        CheckStatus::Skipped {
            because: SkipReason::DependencySkipped {
                dependency: CheckKind::Gateway
            }
        }
    );
    // Never diagnose DNS while the adapter is down: no DNS probes were sent.
    assert!(
        !transport
            .probes()
            .iter()
            .any(|probe| matches!(probe.request, ProbeRequest::DnsQuery { .. }))
    );
    // Only collector + link probes ran.
    assert_eq!(report.probes_used, 2);
    // The one failure yields the one diagnosis.
    let diagnoses = diagnose(&report);
    assert_eq!(diagnoses.len(), 1);
    assert_eq!(diagnoses[0].kind, DiagnosisKind::AdapterLinkDown);
    assert!(!diagnoses[0].evidence.is_empty());
}

#[tokio::test]
async fn budget_exhaustion_stops_cleanly_with_labeled_partial_results() {
    let transport = FakeProbeTransport::new(healthy);
    // Enough for the five 1-probe checks, not for the 3-probe gateway check.
    let report = engine_with(5).run(&transport).await;

    assert!(report.budget_exhausted);
    assert_eq!(report.probes_used, 5);
    for kind in [
        CheckKind::CollectorHealth,
        CheckKind::AdapterLink,
        CheckKind::AddressDhcp,
        CheckKind::DuplicateIp,
        CheckKind::WifiQuality,
    ] {
        assert_eq!(report.check(kind).unwrap().status, CheckStatus::Passed);
    }
    assert_eq!(
        report.check(CheckKind::Gateway).unwrap().status,
        CheckStatus::Skipped {
            because: SkipReason::BudgetExhausted
        }
    );
    // Everything downstream of the budget stop is labeled, not dropped.
    assert_eq!(report.checks.len(), 12);
    let skipped_for_budget = report
        .checks
        .iter()
        .filter(|check| {
            matches!(
                check.status,
                CheckStatus::Skipped {
                    because: SkipReason::BudgetExhausted
                } | CheckStatus::Skipped {
                    because: SkipReason::DependencySkipped { .. }
                }
            )
        })
        .count();
    assert_eq!(skipped_for_budget, 7);
}

#[tokio::test]
async fn dns_failure_carries_per_resolver_evidence() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::DnsQuery { resolver, .. } if resolver == "1.1.1.1" => {
            Ok(ProbeResponse::DnsAnswer {
                addresses: vec!["93.184.216.34".into()],
                latency_ms: 9.0,
            })
        }
        ProbeRequest::DnsQuery { .. } => Ok(ProbeResponse::DnsFailure {
            reason: DnsFailureReason::Timeout,
        }),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;

    assert_eq!(
        report.check(CheckKind::Dns).unwrap().status,
        CheckStatus::Failed
    );
    let diagnoses = diagnose(&report);
    let dns = diagnoses
        .iter()
        .find_map(|diagnosis| match &diagnosis.kind {
            DiagnosisKind::DnsFailure { resolvers } => Some(resolvers),
            _ => None,
        })
        .expect("dns diagnosis present");
    assert_eq!(dns.len(), 3);
    let configured_failed = dns
        .iter()
        .filter(|r| !r.independent)
        .all(|r| matches!(r.outcome, ResolverOutcome::Failed { .. }));
    assert!(configured_failed);
    let independent = dns.iter().find(|r| r.independent).unwrap();
    assert!(matches!(
        independent.outcome,
        ResolverOutcome::Answered { .. }
    ));
}

#[tokio::test]
async fn mtu_blackhole_is_detected_from_df_probe_sizes() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::Ping {
            dont_fragment: true,
            payload_bytes,
            ..
        } => Ok(if *payload_bytes >= 1_500 {
            ProbeResponse::PingTimeout
        } else {
            ProbeResponse::PingReply { rtt_ms: 22.0 }
        }),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;

    assert_eq!(
        report.check(CheckKind::Mtu).unwrap().status,
        CheckStatus::Failed
    );
    let diagnoses = diagnose(&report);
    let mtu = diagnoses
        .iter()
        .find(|d| matches!(d.kind, DiagnosisKind::MtuBlackhole { .. }))
        .expect("mtu diagnosis present");
    assert_eq!(
        mtu.kind,
        DiagnosisKind::MtuBlackhole {
            largest_passing_bytes: Some(1_400),
            smallest_failing_bytes: Some(1_500),
        }
    );
    assert!(
        mtu.evidence
            .iter()
            .any(|m| m.metric == Metric::PassingMtuBytes && m.value == 1_400.0)
    );
    assert!(
        mtu.evidence
            .iter()
            .any(|m| m.metric == Metric::FailingMtuBytes && m.value == 1_500.0)
    );
}

#[tokio::test]
async fn duplicate_ip_uses_the_address_learned_from_dhcp_check() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::ArpProbe { address, .. } => {
            assert_eq!(address, "192.168.1.50");
            Ok(ProbeResponse::ArpProbe {
                responding_macs: vec!["aa:aa:aa:aa:aa:aa".into(), "bb:bb:bb:bb:bb:bb".into()],
            })
        }
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;

    let diagnoses = diagnose(&report);
    assert!(diagnoses.iter().any(|d| d.kind
        == DiagnosisKind::DuplicateIp {
            address: "192.168.1.50".into(),
            macs: vec!["aa:aa:aa:aa:aa:aa".into(), "bb:bb:bb:bb:bb:bb".into()],
        }));
}

#[tokio::test]
async fn packet_loss_beyond_threshold_is_diagnosed_with_measured_values() {
    let counter = Mutex::new(0u32);
    let transport = FakeProbeTransport::new(move |request| match request {
        ProbeRequest::Ping {
            dont_fragment: false,
            ..
        } => {
            let mut n = counter.lock().unwrap();
            *n += 1;
            Ok(if (*n).is_multiple_of(2) {
                ProbeResponse::PingTimeout
            } else {
                ProbeResponse::PingReply { rtt_ms: 5.0 }
            })
        }
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;

    // Gateway still passes (>= 1 reply) but the loss check fails its threshold.
    assert_eq!(
        report.check(CheckKind::Gateway).unwrap().status,
        CheckStatus::Passed
    );
    assert_eq!(
        report.check(CheckKind::LossLatency).unwrap().status,
        CheckStatus::Failed
    );
    let diagnoses = diagnose(&report);
    let loss = diagnoses
        .iter()
        .find_map(|d| match d.kind {
            DiagnosisKind::LossLatencyDegraded { loss_percent, .. } => Some(loss_percent),
            _ => None,
        })
        .expect("loss diagnosis present");
    assert!(loss > 2.0, "measured loss {loss}");
}

#[tokio::test]
async fn weak_wifi_and_route_conflict_and_wan_isolation_are_diagnosed() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::WifiMetrics { .. } => Ok(ProbeResponse::WifiMetrics {
            wireless: true,
            rssi_dbm: Some(-85),
            retry_percent: Some(30.0),
        }),
        ProbeRequest::RouteTable => Ok(ProbeResponse::RouteTable {
            default_routes: vec![
                RouteEntry {
                    interface: "eth0".into(),
                    gateway: "192.168.1.1".into(),
                    is_vpn: false,
                    metric: 100,
                },
                RouteEntry {
                    interface: "tun0".into(),
                    gateway: "10.8.0.1".into(),
                    is_vpn: true,
                    metric: 50,
                },
            ],
        }),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;
    let diagnoses = diagnose(&report);

    assert!(
        diagnoses
            .iter()
            .any(|d| d.kind == DiagnosisKind::WeakWifiQuality { rssi_dbm: -85 })
    );
    assert!(
        diagnoses
            .iter()
            .any(|d| matches!(&d.kind, DiagnosisKind::RouteVpnConflict { default_routes } if default_routes.len() == 2))
    );
    // A route conflict is reported with its detail but gates nothing: a VPN
    // user still learns whether the WAN is reachable (M-16).
    assert_eq!(
        report
            .check(CheckKind::InternetReachability)
            .unwrap()
            .status,
        CheckStatus::Passed
    );
}

/// M-16: a DNS-only outage must not hide a healthy WAN. The internet probe
/// is by IP and runs even when every resolver fails.
#[tokio::test]
async fn dns_outage_does_not_skip_the_internet_check() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::DnsQuery { .. } => Ok(ProbeResponse::DnsFailure {
            reason: DnsFailureReason::Timeout,
        }),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;
    assert_eq!(
        report.check(CheckKind::Dns).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        report
            .check(CheckKind::InternetReachability)
            .unwrap()
            .status,
        CheckStatus::Passed
    );
}

/// M-16: with the gateway down the internet probe still runs, so the
/// "both sides down" diagnosis — and its approval-gated router reboot — is
/// reachable instead of dead code.
#[tokio::test]
async fn gateway_and_internet_both_down_plan_a_router_reboot() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::Ping {
            dont_fragment: false,
            ..
        } => Ok(ProbeResponse::PingTimeout),
        ProbeRequest::ReachIp { .. } => Ok(ProbeResponse::Unreachable),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;
    let diagnoses = diagnose(&report);
    assert!(
        diagnoses
            .iter()
            .any(|d| d.kind == DiagnosisKind::GatewayUnreachable)
    );
    let both_down = diagnoses
        .iter()
        .find(|d| d.kind == DiagnosisKind::InternetUnreachable { lan_ok: false })
        .expect("LAN-side outage is diagnosed");
    let context = RepairContext {
        interface: "eth0".into(),
        lease_renewal_severs_only_management_path: false,
        fallback_dns_servers: vec!["9.9.9.9".into()],
    };
    assert!(matches!(
        plan_repair(&both_down.kind, &context),
        RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::RebootRouter,
            ..
        }
    ));
}

#[tokio::test]
async fn internet_unreachable_with_lan_ok_isolates_the_wan_side() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::ReachIp { .. } => Ok(ProbeResponse::Unreachable),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;
    let diagnoses = diagnose(&report);
    assert!(
        diagnoses
            .iter()
            .any(|d| d.kind == DiagnosisKind::InternetUnreachable { lan_ok: true })
    );
}

#[tokio::test]
async fn transport_probe_error_fails_the_check_and_reports_the_probe() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::CollectorStatus => Err(ProbeError::Transport("collector IPC broken".into())),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;

    assert_eq!(
        report.check(CheckKind::CollectorHealth).unwrap().status,
        CheckStatus::Failed
    );
    // Everything downstream is skipped off the root failure.
    assert_eq!(
        report.check(CheckKind::AdapterLink).unwrap().status,
        CheckStatus::Skipped {
            because: SkipReason::DependencyFailed {
                dependency: CheckKind::CollectorHealth
            }
        }
    );
    let diagnoses = diagnose(&report);
    assert_eq!(diagnoses.len(), 1);
    assert!(matches!(
        &diagnoses[0].kind,
        DiagnosisKind::DiagnosticProbeFailure {
            check: CheckKind::CollectorHealth,
            error
        } if error.contains("collector IPC broken")
    ));
}

#[tokio::test]
async fn collector_fault_is_diagnosed_with_component_flags() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::CollectorStatus => Ok(ProbeResponse::CollectorStatus {
            privileged: true,
            capture_ok: true,
            worker_running: false,
        }),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;
    let diagnoses = diagnose(&report);
    assert!(diagnoses.iter().any(|d| d.kind
        == DiagnosisKind::CollectorFault {
            privileged: true,
            capture_ok: true,
            worker_running: false,
        }));
}

#[tokio::test]
async fn dhcp_failure_is_diagnosed_with_lease_state() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::IpConfig { .. } => Ok(ProbeResponse::IpConfig {
            address: None,
            lease: LeaseState::Expired,
        }),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;
    let diagnoses = diagnose(&report);
    assert!(diagnoses.iter().any(|d| d.kind
        == DiagnosisKind::AddressMissing {
            lease: LeaseState::Expired,
        }));
}

#[tokio::test]
async fn router_and_gateway_failures_are_diagnosed() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::RouterStatus => Ok(ProbeResponse::RouterStatus {
            responsive: false,
            uptime_seconds: None,
        }),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;
    let diagnoses = diagnose(&report);
    assert!(
        diagnoses
            .iter()
            .any(|d| d.kind == DiagnosisKind::RouterFault)
    );

    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::Ping {
            dont_fragment: false,
            ..
        } => Ok(ProbeResponse::PingTimeout),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;
    let diagnoses = diagnose(&report);
    assert!(
        diagnoses
            .iter()
            .any(|d| d.kind == DiagnosisKind::GatewayUnreachable)
    );
}

#[test]
fn engine_rejects_invalid_configuration() {
    let budget = DiagnosticBudget::new(10, 100).unwrap();
    let mut bad = config();
    bad.interface = String::new();
    assert!(DiagnosticEngine::new(bad, budget).is_err());
    let mut bad = config();
    bad.configured_resolvers.clear();
    assert!(DiagnosticEngine::new(bad, budget).is_err());
    let mut bad = config();
    bad.ping_count = 0;
    assert!(DiagnosticEngine::new(bad, budget).is_err());
    let mut bad = config();
    bad.mtu_probe_sizes.clear();
    assert!(DiagnosticEngine::new(bad, budget).is_err());
    let mut bad = config();
    bad.thresholds.degraded_loss_percent = -1.0;
    assert!(DiagnosticEngine::new(bad, budget).is_err());
}
