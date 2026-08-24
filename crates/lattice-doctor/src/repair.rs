//! Repair classification (N3).
//!
//! Every diagnosis maps to a typed [`RepairPlan`] in one of four classes.
//! An approval-required repair can only become executable through
//! [`ApprovedRepair::new`], which demands an [`ApprovalId`] token — the type
//! system guarantees no approval-required action runs unapproved. Guided and
//! observation-only plans have no executable form at all.

use crate::DoctorError;
use crate::diagnosis::DiagnosisKind;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

const MAX_APPROVAL_ID_BYTES: usize = 128;

/// Opaque owner-approval token minted by the service layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ApprovalId(String);

impl ApprovalId {
    pub fn try_new(token: impl Into<String>) -> Result<Self, DoctorError> {
        let token = token.into();
        if token.is_empty()
            || token.len() > MAX_APPROVAL_ID_BYTES
            || token.chars().any(char::is_control)
        {
            return Err(DoctorError::InvalidApproval);
        }
        Ok(Self(token))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The four repair classes from the design spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepairClass {
    SafeAutomatic,
    ApprovalRequiredReversible,
    GuidedPhysical,
    ObservationOnly,
}

/// Safe, local, automatically executable actions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum SafeAction {
    RestartCollectorWorker,
    RefreshAppCaches,
    /// Only planned when renewal cannot sever the only management path; the
    /// guard lives in [`plan_repair`].
    RenewCollectorLease,
    RetryRouterSession,
    RepairTailscaleServe,
}

/// Reversible actions that require an owner approval token to execute.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum ApprovalAction {
    ResetAdapter { interface: String },
    ChangeDnsServers { servers: Vec<String> },
    SetDhcpReservation { device: String, address: String },
    BlockDevice { device: String },
    UnblockDevice { device: String },
    RebootRouter,
    RenewDhcpLease { interface: String },
    SetInterfaceMtu { interface: String, mtu: u16 },
}

/// Physical or irreversible actions the Doctor can only guide a person through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuidedAction {
    CheckCables,
    MoveHardware,
    ContactIsp,
    FactoryReset,
    InstallFirmware,
}

/// The proposed remedy for one diagnosis, tagged by class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "class")]
pub enum RepairPlan {
    SafeAutomatic {
        action: SafeAction,
        rationale: String,
    },
    ApprovalRequiredReversible {
        action: ApprovalAction,
        rationale: String,
    },
    GuidedPhysical {
        action: GuidedAction,
        rationale: String,
    },
    ObservationOnly {
        rationale: String,
    },
}

impl RepairPlan {
    pub fn class(&self) -> RepairClass {
        match self {
            RepairPlan::SafeAutomatic { .. } => RepairClass::SafeAutomatic,
            RepairPlan::ApprovalRequiredReversible { .. } => {
                RepairClass::ApprovalRequiredReversible
            }
            RepairPlan::GuidedPhysical { .. } => RepairClass::GuidedPhysical,
            RepairPlan::ObservationOnly { .. } => RepairClass::ObservationOnly,
        }
    }
}

/// Facts about the environment the classifier needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RepairContext {
    /// Interface the collector manages.
    pub interface: String,
    /// True when renewing the collector's DHCP lease could sever the only
    /// path NeonHearth has to manage the network. This guard decides whether
    /// lease renewal stays automatic or must be approved.
    pub lease_renewal_severs_only_management_path: bool,
    /// Known-good resolvers to switch to when configured DNS fails. Empty
    /// means no safe alternative exists and the Doctor only observes.
    pub fallback_dns_servers: Vec<String>,
}

/// Classify the remedy for one diagnosis.
pub fn plan_repair(diagnosis: &DiagnosisKind, context: &RepairContext) -> RepairPlan {
    match diagnosis {
        DiagnosisKind::CollectorFault { .. } => RepairPlan::SafeAutomatic {
            action: SafeAction::RestartCollectorWorker,
            rationale: "restarting the NeonHearth worker is local, safe, and reversible".into(),
        },
        DiagnosisKind::AdapterLinkDown => RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::ResetAdapter {
                interface: context.interface.clone(),
            },
            rationale: "an adapter reset briefly disconnects the host and needs approval".into(),
        },
        DiagnosisKind::AddressMissing { .. } => {
            if context.lease_renewal_severs_only_management_path {
                RepairPlan::ApprovalRequiredReversible {
                    action: ApprovalAction::RenewDhcpLease {
                        interface: context.interface.clone(),
                    },
                    rationale: "renewing this lease could sever the only management path, \
                                so it must be approved"
                        .into(),
                }
            } else {
                RepairPlan::SafeAutomatic {
                    action: SafeAction::RenewCollectorLease,
                    rationale: "lease renewal cannot sever the management path here".into(),
                }
            }
        }
        DiagnosisKind::DuplicateIp { address, macs } => RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::SetDhcpReservation {
                device: macs.first().cloned().unwrap_or_default(),
                address: address.clone(),
            },
            rationale: "a DHCP reservation change affects another device and needs approval".into(),
        },
        DiagnosisKind::WeakWifiQuality { .. } => RepairPlan::GuidedPhysical {
            action: GuidedAction::MoveHardware,
            rationale: "signal strength is a physical placement problem the Doctor cannot \
                        change remotely"
                .into(),
        },
        DiagnosisKind::GatewayUnreachable => RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::RebootRouter,
            rationale: "a router reboot disconnects every device and needs approval".into(),
        },
        DiagnosisKind::RouterFault => RepairPlan::SafeAutomatic {
            action: SafeAction::RetryRouterSession,
            rationale: "retrying the router management session is local and harmless".into(),
        },
        DiagnosisKind::LossLatencyDegraded { .. } => RepairPlan::ObservationOnly {
            rationale: "degradation needs more samples before any disruptive change is \
                        worth proposing"
                .into(),
        },
        DiagnosisKind::MtuBlackhole {
            largest_passing_bytes: Some(mtu),
            ..
        } => RepairPlan::ApprovalRequiredReversible {
            action: ApprovalAction::SetInterfaceMtu {
                interface: context.interface.clone(),
                mtu: *mtu,
            },
            rationale: "lowering the interface MTU alters traffic for the whole host and \
                        needs approval"
                .into(),
        },
        DiagnosisKind::MtuBlackhole {
            largest_passing_bytes: None,
            ..
        } => RepairPlan::ObservationOnly {
            rationale: "no working MTU was measured, so no safe value can be proposed".into(),
        },
        DiagnosisKind::DnsFailure { .. } => {
            if context.fallback_dns_servers.is_empty() {
                RepairPlan::ObservationOnly {
                    rationale: "no known-good fallback resolver is configured".into(),
                }
            } else {
                RepairPlan::ApprovalRequiredReversible {
                    action: ApprovalAction::ChangeDnsServers {
                        servers: context.fallback_dns_servers.clone(),
                    },
                    rationale: "changing DNS servers alters resolution for the whole host and \
                                needs approval"
                        .into(),
                }
            }
        }
        DiagnosisKind::RouteVpnConflict { .. } => RepairPlan::ObservationOnly {
            rationale: "route and VPN configuration belongs to the owner; the Doctor only \
                        reports the conflict"
                .into(),
        },
        DiagnosisKind::InternetUnreachable { lan_ok: true } => RepairPlan::GuidedPhysical {
            action: GuidedAction::ContactIsp,
            rationale: "the LAN is healthy, so the outage is on the provider side".into(),
        },
        DiagnosisKind::InternetUnreachable { lan_ok: false } => {
            RepairPlan::ApprovalRequiredReversible {
                action: ApprovalAction::RebootRouter,
                rationale: "both LAN and WAN are down; a router reboot needs approval".into(),
            }
        }
        DiagnosisKind::DiagnosticProbeFailure { .. } => RepairPlan::ObservationOnly {
            rationale: "the probe itself failed; no repair can be justified from it".into(),
        },
    }
}

/// Named pieces of state a repair snapshots before it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum StateKey {
    WorkerState,
    CacheState,
    DhcpLease,
    RouterSession,
    TailscaleConfig,
    AdapterConfig,
    DnsServers,
    DhcpReservations,
    FirewallRules,
}

/// An approval-required repair that provably carries its approval token.
///
/// Fields are private: the only way to construct one is [`ApprovedRepair::new`],
/// which requires the token. Deserialization likewise fails without it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ApprovedRepair {
    action: ApprovalAction,
    approval: ApprovalId,
}

impl ApprovedRepair {
    pub fn new(action: ApprovalAction, approval: ApprovalId) -> Self {
        Self { action, approval }
    }

    pub fn action(&self) -> &ApprovalAction {
        &self.action
    }

    pub fn approval(&self) -> &ApprovalId {
        &self.approval
    }
}

/// A repair the executor is allowed to run.
///
/// Guided and observation-only plans deliberately have no variant here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ExecutableRepair {
    Safe { action: SafeAction },
    Approved(ApprovedRepair),
}

impl ExecutableRepair {
    pub fn class(&self) -> RepairClass {
        match self {
            ExecutableRepair::Safe { .. } => RepairClass::SafeAutomatic,
            ExecutableRepair::Approved(_) => RepairClass::ApprovalRequiredReversible,
        }
    }

    /// Whether restoring the pre-repair snapshot undoes this action.
    pub fn reversible(&self) -> bool {
        match self {
            ExecutableRepair::Safe { action } => matches!(
                action,
                SafeAction::RefreshAppCaches | SafeAction::RepairTailscaleServe
            ),
            ExecutableRepair::Approved(_) => true,
        }
    }

    /// State keys the executor snapshots before applying this repair.
    pub fn state_keys(&self) -> Vec<StateKey> {
        match self {
            ExecutableRepair::Safe { action } => match action {
                SafeAction::RestartCollectorWorker => vec![StateKey::WorkerState],
                SafeAction::RefreshAppCaches => vec![StateKey::CacheState],
                SafeAction::RenewCollectorLease => vec![StateKey::DhcpLease],
                SafeAction::RetryRouterSession => vec![StateKey::RouterSession],
                SafeAction::RepairTailscaleServe => vec![StateKey::TailscaleConfig],
            },
            ExecutableRepair::Approved(approved) => match approved.action() {
                ApprovalAction::ResetAdapter { .. } | ApprovalAction::SetInterfaceMtu { .. } => {
                    vec![StateKey::AdapterConfig]
                }
                ApprovalAction::ChangeDnsServers { .. } => vec![StateKey::DnsServers],
                ApprovalAction::SetDhcpReservation { .. } => vec![StateKey::DhcpReservations],
                ApprovalAction::BlockDevice { .. } | ApprovalAction::UnblockDevice { .. } => {
                    vec![StateKey::FirewallRules]
                }
                ApprovalAction::RebootRouter => vec![StateKey::RouterSession],
                ApprovalAction::RenewDhcpLease { .. } => vec![StateKey::DhcpLease],
            },
        }
    }

    /// Short human-readable description for audit events.
    pub fn describe(&self) -> String {
        match self {
            ExecutableRepair::Safe { action } => match action {
                SafeAction::RestartCollectorWorker => "restart_collector_worker".into(),
                SafeAction::RefreshAppCaches => "refresh_app_caches".into(),
                SafeAction::RenewCollectorLease => "renew_collector_lease".into(),
                SafeAction::RetryRouterSession => "retry_router_session".into(),
                SafeAction::RepairTailscaleServe => "repair_tailscale_serve".into(),
            },
            ExecutableRepair::Approved(approved) => match approved.action() {
                ApprovalAction::ResetAdapter { interface } => {
                    format!("reset_adapter {interface}")
                }
                ApprovalAction::ChangeDnsServers { servers } => {
                    format!("change_dns_servers {}", servers.join(","))
                }
                ApprovalAction::SetDhcpReservation { device, address } => {
                    format!("set_dhcp_reservation {device} -> {address}")
                }
                ApprovalAction::BlockDevice { device } => format!("block_device {device}"),
                ApprovalAction::UnblockDevice { device } => format!("unblock_device {device}"),
                ApprovalAction::RebootRouter => "reboot_router".into(),
                ApprovalAction::RenewDhcpLease { interface } => {
                    format!("renew_dhcp_lease {interface}")
                }
                ApprovalAction::SetInterfaceMtu { interface, mtu } => {
                    format!("set_interface_mtu {interface} {mtu}")
                }
            },
        }
    }
}
