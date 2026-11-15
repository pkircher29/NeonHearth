//! Repair classification tests: every rule, the lease-renewal management-path
//! guard, and the approval-token construction requirement.

use lattice_doctor::DoctorError;
use lattice_doctor::check::CheckKind;
use lattice_doctor::diagnosis::DiagnosisKind;
use lattice_doctor::probe::LeaseState;
use lattice_doctor::repair::{
    ApprovalAction, ApprovalId, ApprovedRepair, ExecutableRepair, GuidedAction, RepairClass,
    RepairContext, RepairPlan, SafeAction, StateKey, plan_dhcp_reservation, plan_repair,
};
use lattice_doctor::types::{InterfaceName, IpVersion, MacAddr};

fn context() -> RepairContext {
    RepairContext {
        interface: "eth0".into(),
        lease_renewal_severs_only_management_path: false,
        fallback_dns_servers: vec!["9.9.9.9".into()],
    }
}

#[test]
fn collector_fault_is_a_safe_automatic_worker_restart() {
    let plan = plan_repair(
        &DiagnosisKind::CollectorFault {
            privileged: true,
            capture_ok: true,
            worker_running: false,
        },
        &context(),
    );
    assert!(matches!(
        plan,
        RepairPlan::SafeAutomatic {
            action: SafeAction::RestartCollectorWorker,
            ..
        }
    ));
    assert_eq!(plan.class(), RepairClass::SafeAutomatic);
}

#[test]
fn adapter_link_down_requires_approval_for_adapter_reset() {
    let plan = plan_repair(&DiagnosisKind::AdapterLinkDown, &context());
    assert!(matches!(
        plan,
        RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::ResetAdapter { ref interface },
            ..
        } if interface.as_str() == "eth0"
    ));
}

#[test]
fn lease_renewal_stays_automatic_only_when_management_path_is_safe() {
    let safe_context = context();
    let plan = plan_repair(
        &DiagnosisKind::AddressMissing {
            lease: LeaseState::Expired,
        },
        &safe_context,
    );
    assert!(matches!(
        plan,
        RepairPlan::SafeAutomatic {
            action: SafeAction::RenewCollectorLease,
            ..
        }
    ));

    let mut risky_context = context();
    risky_context.lease_renewal_severs_only_management_path = true;
    let plan = plan_repair(
        &DiagnosisKind::AddressMissing {
            lease: LeaseState::Expired,
        },
        &risky_context,
    );
    assert!(matches!(
        plan,
        RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::RenewDhcpLease { ref interface },
            ..
        } if interface.as_str() == "eth0"
    ));
}

fn mac(text: &str) -> MacAddr {
    text.parse().unwrap()
}

#[test]
fn duplicate_ip_never_picks_a_claimant_for_the_owner() {
    // Regression: the plan used `macs.first()`, so whichever device answered
    // the (spoofable) ARP probe first was proposed as the reservation holder.
    let kind = DiagnosisKind::DuplicateIp {
        address: "192.168.1.50".into(),
        macs: vec![mac("aa:aa:aa:aa:aa:aa"), mac("ac:ac:ac:ac:ac:ac")],
    };
    let plan = plan_repair(&kind, &context());
    let RepairPlan::ApprovalRequiredReversible {
        action: ApprovalAction::SetDhcpReservation {
            chosen, claimants, ..
        },
        ..
    } = plan
    else {
        panic!("approval-required reservation expected");
    };
    assert_eq!(chosen, None);
    assert_eq!(claimants.len(), 2);
    // The owner chooses; the choice must be one of the observed claimants.
    let action = plan_dhcp_reservation(&kind, mac("ac:ac:ac:ac:ac:ac")).unwrap();
    assert!(matches!(
        action,
        ApprovalAction::SetDhcpReservation { chosen: Some(device), address, .. }
            if device == mac("ac:ac:ac:ac:ac:ac") && address.to_string() == "192.168.1.50"
    ));
    assert!(plan_dhcp_reservation(&kind, mac("cc:cc:cc:cc:cc:cc")).is_err());
    // An undecided reservation can never be executed.
    let undecided = ExecutableRepair::Approved(ApprovedRepair::new(
        ApprovalAction::SetDhcpReservation {
            address: "192.168.1.50".parse().unwrap(),
            claimants: vec![mac("aa:aa:aa:aa:aa:aa")],
            chosen: None,
        },
        ApprovalId::try_new("a").unwrap(),
    ));
    assert!(!undecided.is_decided());
}

#[test]
fn invalid_context_values_never_become_executable_actions() {
    let mut hostile = context();
    hostile.interface = "--help".into();
    assert_eq!(
        plan_repair(&DiagnosisKind::AdapterLinkDown, &hostile).class(),
        RepairClass::ObservationOnly
    );
    let mut hostile = context();
    hostile.fallback_dns_servers = vec!["9.9.9.9".into(), "-evil".into()];
    assert_eq!(
        plan_repair(
            &DiagnosisKind::DnsFailure {
                resolvers: Vec::new()
            },
            &hostile
        )
        .class(),
        RepairClass::ObservationOnly
    );
}

#[test]
fn only_state_restorable_repairs_are_marked_reversible() {
    let approved = |action| {
        ExecutableRepair::Approved(ApprovedRepair::new(
            action,
            ApprovalId::try_new("a").unwrap(),
        ))
    };
    let eth0 = InterfaceName::parse("eth0").unwrap();
    // Regression: every approved repair was "reversible", including a router
    // reboot, so a restored snapshot was reported as a successful rollback.
    assert!(!approved(ApprovalAction::RebootRouter).reversible());
    assert!(
        !approved(ApprovalAction::ResetAdapter {
            interface: eth0.clone()
        })
        .reversible()
    );
    assert!(!approved(ApprovalAction::RenewDhcpLease { interface: eth0 }).reversible());
    assert!(
        approved(ApprovalAction::ChangeDnsServers {
            servers: vec!["9.9.9.9".parse().unwrap()]
        })
        .reversible()
    );
}

#[test]
fn deserialising_an_approval_runs_its_validation() {
    assert!(serde_json::from_str::<ApprovalId>("\"\"").is_err());
    assert!(serde_json::from_str::<ApprovalId>("\"ok-1\"").is_ok());
    assert!(serde_json::from_str::<InterfaceName>("\"-h\"").is_err());
    assert!(serde_json::from_str::<MacAddr>("\"01:00:5e:00:00:01\"").is_err());
    assert_eq!(
        serde_json::from_str::<lattice_doctor::types::Mtu>("1400")
            .unwrap()
            .get(),
        1400
    );
    assert!(serde_json::from_str::<lattice_doctor::types::Mtu>("100").is_err());
}

#[test]
fn weak_wifi_is_guided_physical_placement() {
    let plan = plan_repair(
        &DiagnosisKind::WeakWifiQuality { rssi_dbm: -85 },
        &context(),
    );
    assert!(matches!(
        plan,
        RepairPlan::GuidedPhysical {
            action: GuidedAction::MoveHardware,
            ..
        }
    ));
}

#[test]
fn gateway_unreachable_requires_approval_for_router_reboot() {
    let plan = plan_repair(&DiagnosisKind::GatewayUnreachable, &context());
    assert!(matches!(
        plan,
        RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::RebootRouter,
            ..
        }
    ));
}

#[test]
fn router_fault_retries_the_session_automatically() {
    let plan = plan_repair(&DiagnosisKind::RouterFault, &context());
    assert!(matches!(
        plan,
        RepairPlan::SafeAutomatic {
            action: SafeAction::RetryRouterSession,
            ..
        }
    ));
}

#[test]
fn loss_latency_and_route_conflict_are_observation_only() {
    let plan = plan_repair(
        &DiagnosisKind::LossLatencyDegraded {
            loss_percent: 12.0,
            median_rtt_ms: Some(200.0),
        },
        &context(),
    );
    assert_eq!(plan.class(), RepairClass::ObservationOnly);

    let plan = plan_repair(
        &DiagnosisKind::RouteVpnConflict {
            default_routes: Vec::new(),
        },
        &context(),
    );
    assert_eq!(plan.class(), RepairClass::ObservationOnly);
}

#[test]
fn mtu_blackhole_proposes_measured_mtu_or_only_observes() {
    let plan = plan_repair(
        &DiagnosisKind::MtuBlackhole {
            largest_passing_payload_bytes: Some(1_372),
            smallest_failing_payload_bytes: Some(1_472),
            ip_version: IpVersion::V4,
        },
        &context(),
    );
    // Regression: the ICMP payload (1372) was used as the MTU; the link MTU
    // is payload + 28 for IPv4.
    assert!(matches!(
        plan,
        RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::SetInterfaceMtu { ref interface, mtu },
            ..
        } if interface.as_str() == "eth0" && mtu.get() == 1_400
    ));
    let v6 = plan_repair(
        &DiagnosisKind::MtuBlackhole {
            largest_passing_payload_bytes: Some(1_352),
            smallest_failing_payload_bytes: None,
            ip_version: IpVersion::V6,
        },
        &context(),
    );
    assert!(matches!(
        v6,
        RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::SetInterfaceMtu { mtu, .. },
            ..
        } if mtu.get() == 1_400
    ));

    let plan = plan_repair(
        &DiagnosisKind::MtuBlackhole {
            largest_passing_payload_bytes: None,
            smallest_failing_payload_bytes: Some(1_200),
            ip_version: IpVersion::V4,
        },
        &context(),
    );
    assert_eq!(plan.class(), RepairClass::ObservationOnly);
}

#[test]
fn dns_change_requires_approval_and_a_fallback_resolver() {
    let plan = plan_repair(
        &DiagnosisKind::DnsFailure {
            resolvers: Vec::new(),
        },
        &context(),
    );
    assert!(matches!(
        plan,
        RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::ChangeDnsServers { ref servers },
            ..
        } if servers == &vec!["9.9.9.9".parse::<std::net::IpAddr>().unwrap()]
    ));

    let mut no_fallback = context();
    no_fallback.fallback_dns_servers.clear();
    let plan = plan_repair(
        &DiagnosisKind::DnsFailure {
            resolvers: Vec::new(),
        },
        &no_fallback,
    );
    assert_eq!(plan.class(), RepairClass::ObservationOnly);
}

#[test]
fn wan_outage_is_guided_isp_contact_but_full_outage_asks_for_router_reboot() {
    let plan = plan_repair(
        &DiagnosisKind::InternetUnreachable { lan_ok: true },
        &context(),
    );
    assert!(matches!(
        plan,
        RepairPlan::GuidedPhysical {
            action: GuidedAction::ContactIsp,
            ..
        }
    ));

    let plan = plan_repair(
        &DiagnosisKind::InternetUnreachable { lan_ok: false },
        &context(),
    );
    assert!(matches!(
        plan,
        RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::RebootRouter,
            ..
        }
    ));
}

#[test]
fn probe_failure_is_never_repaired_automatically() {
    let plan = plan_repair(
        &DiagnosisKind::DiagnosticProbeFailure {
            check: CheckKind::Dns,
            error: "probe transport failed".into(),
        },
        &context(),
    );
    assert_eq!(plan.class(), RepairClass::ObservationOnly);
}

#[test]
fn approval_id_rejects_empty_oversized_and_control_tokens() {
    assert_eq!(ApprovalId::try_new(""), Err(DoctorError::InvalidApproval));
    assert_eq!(
        ApprovalId::try_new("a\ntoken"),
        Err(DoctorError::InvalidApproval)
    );
    assert_eq!(
        ApprovalId::try_new("x".repeat(129)),
        Err(DoctorError::InvalidApproval)
    );
    let id = ApprovalId::try_new("approval-42").unwrap();
    assert_eq!(id.as_str(), "approval-42");
}

// The type system enforces the approval requirement: `ApprovedRepair` has
// private fields, so the ONLY way to obtain one — and therefore the only way
// to build `ExecutableRepair::Approved` — is `ApprovedRepair::new`, whose
// signature demands an `ApprovalId`. Guided and observation-only plans have no
// `ExecutableRepair` form at all. This test documents the only compiling path.
#[test]
fn approval_required_repairs_only_execute_with_a_token() {
    let approval = ApprovalId::try_new("approval-42").unwrap();
    let repair = ExecutableRepair::Approved(ApprovedRepair::new(
        ApprovalAction::ChangeDnsServers {
            servers: vec!["9.9.9.9".parse().unwrap()],
        },
        approval,
    ));
    assert_eq!(repair.class(), RepairClass::ApprovalRequiredReversible);
    assert!(repair.reversible());
    assert_eq!(repair.state_keys(), vec![StateKey::DnsServers]);
    if let ExecutableRepair::Approved(approved) = &repair {
        assert_eq!(approved.approval().as_str(), "approval-42");
    } else {
        unreachable!();
    }
}

#[test]
fn safe_action_reversibility_and_state_keys_are_declared_per_action() {
    let restart = ExecutableRepair::Safe {
        action: SafeAction::RestartCollectorWorker,
    };
    assert!(!restart.reversible());
    assert_eq!(restart.state_keys(), vec![StateKey::WorkerState]);

    let refresh = ExecutableRepair::Safe {
        action: SafeAction::RefreshAppCaches,
    };
    assert!(refresh.reversible());
    assert_eq!(refresh.state_keys(), vec![StateKey::CacheState]);

    let renew = ExecutableRepair::Safe {
        action: SafeAction::RenewCollectorLease,
    };
    assert!(!renew.reversible());
    assert_eq!(renew.state_keys(), vec![StateKey::DhcpLease]);

    let approved = ExecutableRepair::Approved(ApprovedRepair::new(
        ApprovalAction::BlockDevice {
            device: mac("aa:bb:cc:dd:ee:01"),
        },
        ApprovalId::try_new("t").unwrap(),
    ));
    assert_eq!(approved.state_keys(), vec![StateKey::FirewallRules]);
    assert!(approved.reversible());
}
