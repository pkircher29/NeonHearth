//! Repair classification tests: every rule, the lease-renewal management-path
//! guard, and the approval-token construction requirement.

use lattice_doctor::DoctorError;
use lattice_doctor::check::CheckKind;
use lattice_doctor::diagnosis::DiagnosisKind;
use lattice_doctor::probe::LeaseState;
use lattice_doctor::repair::{
    ApprovalAction, ApprovalId, ApprovedRepair, ExecutableRepair, GuidedAction, RepairClass,
    RepairContext, RepairPlan, SafeAction, StateKey, plan_repair,
};

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
        } if interface == "eth0"
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
        } if interface == "eth0"
    ));
}

#[test]
fn duplicate_ip_proposes_an_approved_dhcp_reservation() {
    let plan = plan_repair(
        &DiagnosisKind::DuplicateIp {
            address: "192.168.1.50".into(),
            macs: vec!["aa:aa:aa:aa:aa:aa".into(), "bb:bb:bb:bb:bb:bb".into()],
        },
        &context(),
    );
    assert!(matches!(
        plan,
        RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::SetDhcpReservation { ref device, ref address },
            ..
        } if device == "aa:aa:aa:aa:aa:aa" && address == "192.168.1.50"
    ));
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
            largest_passing_bytes: Some(1_400),
            smallest_failing_bytes: Some(1_500),
        },
        &context(),
    );
    assert!(matches!(
        plan,
        RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::SetInterfaceMtu { ref interface, mtu: 1_400 },
            ..
        } if interface == "eth0"
    ));

    let plan = plan_repair(
        &DiagnosisKind::MtuBlackhole {
            largest_passing_bytes: None,
            smallest_failing_bytes: Some(1_200),
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
        } if servers == &vec!["9.9.9.9".to_owned()]
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
            servers: vec!["9.9.9.9".into()],
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
            device: "aa:bb".into(),
        },
        ApprovalId::try_new("t").unwrap(),
    ));
    assert_eq!(approved.state_keys(), vec![StateKey::FirewallRules]);
    assert!(approved.reversible());
}
