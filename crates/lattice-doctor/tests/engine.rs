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
use lattice_doctor::types::IpVersion;
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
    // + loss 3 + mtu 3 sizes x 2 samples + dns 3 + route 1 + internet 1
    assert_eq!(report.probes_used, 23);
    assert!(!report.budget_exhausted);
    assert_eq!(transport.probes().len(), 23);
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
            largest_passing_payload_bytes: Some(1_400),
            smallest_failing_payload_bytes: Some(1_500),
            ip_version: IpVersion::V4,
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
                responding_macs: vec!["aa:aa:aa:aa:aa:aa".into(), "ac:ac:ac:ac:ac:ac".into()],
            })
        }
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;

    let diagnoses = diagnose(&report);
    assert!(diagnoses.iter().any(|d| d.kind
        == DiagnosisKind::DuplicateIp {
            address: "192.168.1.50".into(),
            macs: vec![
                "aa:aa:aa:aa:aa:aa".parse().unwrap(),
                "ac:ac:ac:ac:ac:ac".parse().unwrap()
            ],
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

fn unavailable_status() -> CheckStatus {
    CheckStatus::Skipped {
        because: SkipReason::ProbeUnsupported,
    }
}

fn dependency_unavailable(dependency: CheckKind) -> CheckStatus {
    CheckStatus::Skipped {
        because: SkipReason::DependencyUnavailable { dependency },
    }
}

#[tokio::test]
async fn unsupported_probes_leave_checks_unavailable_without_a_finding() {
    // The production service shape: only the collector probe is answered.
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::CollectorStatus => healthy(request),
        _ => Err(ProbeError::Unsupported),
    });
    let report = engine_with(64).run(&transport).await;

    assert_eq!(
        report.check(CheckKind::CollectorHealth).unwrap().status,
        CheckStatus::Passed
    );
    assert_eq!(
        report.check(CheckKind::AdapterLink).unwrap().status,
        unavailable_status()
    );
    assert_eq!(
        report.check(CheckKind::AddressDhcp).unwrap().status,
        dependency_unavailable(CheckKind::AdapterLink)
    );
    assert_eq!(
        report.check(CheckKind::Gateway).unwrap().status,
        dependency_unavailable(CheckKind::AddressDhcp)
    );
    assert_eq!(
        report.check(CheckKind::Dns).unwrap().status,
        dependency_unavailable(CheckKind::Gateway)
    );
    assert_eq!(
        report
            .check(CheckKind::InternetReachability)
            .unwrap()
            .status,
        dependency_unavailable(CheckKind::AddressDhcp)
    );
    assert_eq!(report.checks.len(), 12);
    // Only the collector and link probes were attempted.
    assert_eq!(report.probes_used, 2);
    assert!(!report.budget_exhausted);
    assert!(
        diagnose(&report).is_empty(),
        "an unsupported probe is not a fault in the network"
    );
}

#[tokio::test]
async fn a_genuine_transport_error_is_still_a_failed_probe_finding() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::LinkStatus { .. } => Err(ProbeError::Transport("socket closed".into())),
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
    let diagnoses = diagnose(&report);
    assert_eq!(diagnoses.len(), 1);
    assert!(matches!(
        &diagnoses[0].kind,
        DiagnosisKind::DiagnosticProbeFailure {
            check: CheckKind::AdapterLink,
            error
        } if error.contains("socket closed")
    ));
}

#[tokio::test]
async fn unsupported_pings_make_gateway_unavailable_not_failed() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::Ping { .. } => Err(ProbeError::Unsupported),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;

    assert_eq!(
        report.check(CheckKind::Gateway).unwrap().status,
        unavailable_status()
    );
    assert_eq!(
        report.check(CheckKind::LossLatency).unwrap().status,
        dependency_unavailable(CheckKind::Gateway)
    );
    assert!(diagnose(&report).is_empty());
}

#[tokio::test]
async fn unsupported_dns_queries_make_dns_unavailable_but_a_real_error_still_fails() {
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::DnsQuery { .. } => Err(ProbeError::Unsupported),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;
    assert_eq!(
        report.check(CheckKind::Dns).unwrap().status,
        unavailable_status()
    );
    assert_eq!(
        report.check(CheckKind::RouteVpn).unwrap().status,
        dependency_unavailable(CheckKind::Dns)
    );
    assert!(diagnose(&report).is_empty());

    // A transport error on every query is a genuine, diagnosable failure.
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::DnsQuery { .. } => Err(ProbeError::Transport("resolver down".into())),
        other => healthy(other),
    });
    let report = engine_with(64).run(&transport).await;
    assert_eq!(
        report.check(CheckKind::Dns).unwrap().status,
        CheckStatus::Failed
    );
}

// ---------------------------------------------------------------------------
// Owner consent: a probe the owner has not allowed is "needs permission",
// never a failure and never a finding.
// ---------------------------------------------------------------------------

fn is_external(target: &str) -> bool {
    !target.starts_with("192.168.")
}

/// A healthy network whose probes to public addresses are refused for want of
/// the owner's permission, the way the service's consent gate refuses them.
fn consent_gated(request: &ProbeRequest) -> Result<ProbeResponse, ProbeError> {
    let target = match request {
        ProbeRequest::Ping { target, .. } => Some(target.as_str()),
        ProbeRequest::DnsQuery { resolver, .. } => Some(resolver.as_str()),
        ProbeRequest::ReachIp { address, .. } => Some(address.as_str()),
        _ => None,
    };
    match target {
        Some(target) if is_external(target) => Err(ProbeError::ConsentRequired),
        _ => healthy(request),
    }
}

fn consent_skip() -> CheckStatus {
    CheckStatus::Skipped {
        because: SkipReason::ConsentRequired,
    }
}

#[tokio::test]
async fn withheld_consent_skips_the_outside_checks_without_a_finding() {
    let transport = FakeProbeTransport::new(consent_gated);
    let report = engine_with(64).run(&transport).await;

    for kind in [CheckKind::Mtu, CheckKind::InternetReachability] {
        assert_eq!(report.check(kind).unwrap().status, consent_skip(), "{kind:?}");
    }
    // One configured resolver is on the home network and answered; the public
    // ones were not asked. DNS passes on what could be checked.
    let dns = report.check(CheckKind::Dns).unwrap();
    assert_eq!(dns.status, CheckStatus::Passed);
    let evidence = match &dns.detail {
        Some(lattice_doctor::check::CheckDetail::Dns { resolvers }) => resolvers,
        other => panic!("unexpected detail {other:?}"),
    };
    assert_eq!(
        evidence
            .iter()
            .filter(|r| r.outcome == ResolverOutcome::ConsentRequired)
            .count(),
        2
    );
    assert_eq!(
        report.check(CheckKind::RouteVpn).unwrap().status,
        CheckStatus::Passed
    );
    assert_eq!(
        report.check(CheckKind::Gateway).unwrap().status,
        CheckStatus::Passed
    );
    assert!(diagnose(&report).is_empty(), "{:?}", diagnose(&report));
}

#[tokio::test]
async fn dns_with_no_askable_resolver_is_skipped_for_consent_and_its_dependents_follow() {
    let mut config = config();
    config.configured_resolvers = vec!["8.8.8.8".into(), "1.1.1.1".into()];
    let engine = DiagnosticEngine::with_clock(
        config,
        DiagnosticBudget::new(64, 1_000).unwrap(),
        FixedClock(Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap()),
    )
    .unwrap();
    let transport = FakeProbeTransport::new(consent_gated);
    let report = engine.run(&transport).await;

    assert_eq!(report.check(CheckKind::Dns).unwrap().status, consent_skip());
    assert_eq!(
        report.check(CheckKind::RouteVpn).unwrap().status,
        CheckStatus::Skipped {
            because: SkipReason::DependencyConsentRequired {
                dependency: CheckKind::Dns
            }
        }
    );
    assert!(diagnose(&report).is_empty(), "{:?}", diagnose(&report));
}

#[tokio::test]
async fn a_genuine_dns_failure_is_still_reported_beside_resolvers_that_were_not_asked() {
    // The home resolver is asked and fails; the public ones need permission.
    let transport = FakeProbeTransport::new(|request| match request {
        ProbeRequest::DnsQuery { resolver, .. } if resolver == "192.168.1.1" => {
            Ok(ProbeResponse::DnsFailure {
                reason: DnsFailureReason::Timeout,
            })
        }
        other => consent_gated(other),
    });
    let report = engine_with(64).run(&transport).await;

    assert_eq!(
        report.check(CheckKind::Dns).unwrap().status,
        CheckStatus::Failed
    );
    let diagnoses = diagnose(&report);
    let evidence = diagnoses
        .iter()
        .find_map(|d| match &d.kind {
            DiagnosisKind::DnsFailure { resolvers } => Some(resolvers),
            _ => None,
        })
        .expect("a dns finding");
    assert!(
        evidence
            .iter()
            .any(|r| r.outcome == ResolverOutcome::ConsentRequired)
    );
    // Only the resolver that was really asked counts as failed.
    let count = report
        .check(CheckKind::Dns)
        .unwrap()
        .evidence
        .iter()
        .find(|m| m.metric == Metric::ResolverFailureCount)
        .unwrap()
        .value;
    assert_eq!(count, 1.0);
    // The consent-gated checks still produce no finding of their own.
    assert!(
        diagnoses
            .iter()
            .all(|d| !matches!(d.kind, DiagnosisKind::DiagnosticProbeFailure { .. }))
    );
}

#[tokio::test]
async fn only_the_independent_resolver_askable_decides_dns() {
    let mut config = config();
    config.configured_resolvers = vec!["8.8.8.8".into()];
    config.independent_resolver = "192.168.1.9".into();
    let engine = DiagnosticEngine::with_clock(
        config.clone(),
        DiagnosticBudget::new(64, 1_000).unwrap(),
        FixedClock(Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap()),
    )
    .unwrap();
    let report = engine.run(&FakeProbeTransport::new(consent_gated)).await;
    assert_eq!(report.check(CheckKind::Dns).unwrap().status, CheckStatus::Passed);

    // If that one resolver fails, there is a measured failure to report.
    let failing = FakeProbeTransport::new(|request| match request {
        ProbeRequest::DnsQuery { resolver, .. } if resolver == "192.168.1.9" => {
            Ok(ProbeResponse::DnsFailure {
                reason: DnsFailureReason::Timeout,
            })
        }
        other => consent_gated(other),
    });
    let engine = DiagnosticEngine::with_clock(
        config,
        DiagnosticBudget::new(64, 1_000).unwrap(),
        FixedClock(Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap()),
    )
    .unwrap();
    let report = engine.run(&failing).await;
    assert_eq!(report.check(CheckKind::Dns).unwrap().status, CheckStatus::Failed);
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
