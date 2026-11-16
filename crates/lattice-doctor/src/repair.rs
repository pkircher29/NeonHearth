//! Repair classification (N3).
//!
//! Every diagnosis maps to a typed [`RepairPlan`] in one of four classes.
//! An approval-required repair can only become executable through
//! [`ApprovedRepair::new`], which demands an [`ApprovalId`] token — the type
//! system guarantees no approval-required action runs unapproved. Guided and
//! observation-only plans have no executable form at all.

use crate::DoctorError;
use crate::diagnosis::DiagnosisKind;
use crate::types::{InterfaceName, MacAddr, Mtu};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use utoipa::ToSchema;

const MAX_APPROVAL_ID_BYTES: usize = 128;

/// Opaque owner-approval token minted by the service layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "String")]
pub struct ApprovalId(String);

impl TryFrom<String> for ApprovalId {
    type Error = DoctorError;
    fn try_from(token: String) -> Result<Self, DoctorError> {
        Self::try_new(token)
    }
}

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
    ResetAdapter {
        interface: InterfaceName,
    },
    ChangeDnsServers {
        #[schema(value_type = Vec<String>)]
        servers: Vec<IpAddr>,
    },
    /// `chosen` is `None` until the owner picks which claimant keeps the
    /// address; the executor refuses to run an action whose choice is open.
    SetDhcpReservation {
        #[schema(value_type = String)]
        address: IpAddr,
        claimants: Vec<MacAddr>,
        chosen: Option<MacAddr>,
    },
    BlockDevice {
        device: MacAddr,
    },
    UnblockDevice {
        device: MacAddr,
    },
    RebootRouter,
    RenewDhcpLease {
        interface: InterfaceName,
    },
    /// `mtu` is a link MTU, already converted from the ICMP payload size.
    SetInterfaceMtu {
        interface: InterfaceName,
        mtu: Mtu,
    },
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

/// Why a proposed plan cannot be executed by this build. Machine-readable
/// (snake_case on the wire); [`UnavailableReason::detail`] is the owner-facing
/// sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    /// The plan is advice (physical or observation-only); there is nothing
    /// to execute.
    GuidanceOnly,
    /// Needs a privileged change to the operating system's network
    /// configuration, which the service does not make.
    NeedsOsNetworkChange,
    /// Needs a router management API that does not exist in this build.
    NeedsRouterApi,
    /// The action exists in the contract but this build has no hook for it.
    NotWired,
    /// The action needs the discovery worker, which is not running.
    WorkerNotRunning,
}

impl UnavailableReason {
    /// One owner-facing sentence naming what is missing.
    pub fn detail(self) -> &'static str {
        match self {
            Self::GuidanceOnly => "this is guidance, not a change NeonHearth can make",
            Self::NeedsOsNetworkChange => {
                "changing the operating system's network settings needs administrator rights \
                 that NeonHearth does not hold"
            }
            Self::NeedsRouterApi => {
                "NeonHearth has no way to manage this router; the change must be made on the \
                 router itself"
            }
            Self::NotWired => "this build of NeonHearth has no way to perform this repair",
            Self::WorkerNotRunning => {
                "the discovery worker is not running, so it cannot be restarted"
            }
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
    // Repairs carry validated types. A context value that fails validation can
    // never become an executable action, so it degrades to observation.
    let interface = InterfaceName::parse(&context.interface);
    let invalid_context = || RepairPlan::ObservationOnly {
        rationale: "the configured interface name is not valid for a repair".into(),
    };
    match diagnosis {
        DiagnosisKind::CollectorFault { .. } => RepairPlan::SafeAutomatic {
            action: SafeAction::RestartCollectorWorker,
            rationale: "restarting the NeonHearth worker is local, safe, and reversible".into(),
        },
        DiagnosisKind::AdapterLinkDown => match interface {
            Ok(interface) => RepairPlan::ApprovalRequiredReversible {
                action: ApprovalAction::ResetAdapter { interface },
                rationale: "an adapter reset briefly disconnects the host and needs approval"
                    .into(),
            },
            Err(_) => invalid_context(),
        },
        DiagnosisKind::AddressMissing { .. } => {
            if context.lease_renewal_severs_only_management_path {
                match interface {
                    Ok(interface) => RepairPlan::ApprovalRequiredReversible {
                        action: ApprovalAction::RenewDhcpLease { interface },
                        rationale: "renewing this lease could sever the only management path, \
                                    so it must be approved"
                            .into(),
                    },
                    Err(_) => invalid_context(),
                }
            } else {
                RepairPlan::SafeAutomatic {
                    action: SafeAction::RenewCollectorLease,
                    rationale: "lease renewal cannot sever the management path here".into(),
                }
            }
        }
        // Which claimant keeps the address is the owner decision: probe
        // answers are spoofable, so the plan never picks one. The approval
        // carries `chosen: None`; see `plan_dhcp_reservation`.
        DiagnosisKind::DuplicateIp { address, macs } => match address.parse::<IpAddr>() {
            Ok(address) if !macs.is_empty() => RepairPlan::ApprovalRequiredReversible {
                action: ApprovalAction::SetDhcpReservation {
                    address,
                    claimants: macs.clone(),
                    chosen: None,
                },
                rationale: "several devices answer for one address; the owner must choose which device keeps it before a reservation can be applied"
                    .into(),
            },
            _ => RepairPlan::ObservationOnly {
                rationale: "the conflicting address or claimants could not be validated".into(),
            },
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
            largest_passing_payload_bytes: Some(payload),
            ip_version,
            ..
        } => match (interface, Mtu::from_icmp_payload(*payload, *ip_version)) {
            (Ok(interface), Some(mtu)) => RepairPlan::ApprovalRequiredReversible {
                action: ApprovalAction::SetInterfaceMtu { interface, mtu },
                rationale: "lowering the interface MTU alters traffic for the whole host and \
                            needs approval"
                    .into(),
            },
            _ => RepairPlan::ObservationOnly {
                rationale: "the measured payload does not imply a usable MTU".into(),
            },
        },
        DiagnosisKind::MtuBlackhole {
            largest_passing_payload_bytes: None,
            ..
        } => RepairPlan::ObservationOnly {
            rationale: "no working MTU was measured, so no safe value can be proposed".into(),
        },
        DiagnosisKind::DnsFailure { .. } => {
            let servers: Result<Vec<IpAddr>, _> = context
                .fallback_dns_servers
                .iter()
                .map(|server| server.parse::<IpAddr>())
                .collect();
            match servers {
                Ok(servers) if !servers.is_empty() => RepairPlan::ApprovalRequiredReversible {
                    action: ApprovalAction::ChangeDnsServers { servers },
                    rationale: "changing DNS servers alters resolution for the whole host and \
                                needs approval"
                        .into(),
                },
                Ok(_) => RepairPlan::ObservationOnly {
                    rationale: "no known-good fallback resolver is configured".into(),
                },
                Err(_) => RepairPlan::ObservationOnly {
                    rationale: "a configured fallback resolver is not an IP address".into(),
                },
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

/// Builds the reservation action for a duplicate-address diagnosis once the
/// owner has chosen which claimant keeps the address. The choice must be one
/// of the observed claimants.
pub fn plan_dhcp_reservation(
    diagnosis: &DiagnosisKind,
    chosen: MacAddr,
) -> Result<ApprovalAction, DoctorError> {
    let DiagnosisKind::DuplicateIp { address, macs } = diagnosis else {
        return Err(DoctorError::InvalidValue(
            "not a duplicate-address diagnosis",
        ));
    };
    if !macs.contains(&chosen) {
        return Err(DoctorError::InvalidValue("chosen device is not a claimant"));
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| DoctorError::InvalidValue("address"))?;
    Ok(ApprovalAction::SetDhcpReservation {
        address,
        claimants: macs.clone(),
        chosen: Some(chosen),
    })
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

    /// False while an owner decision the action needs is still open.
    pub fn is_decided(&self) -> bool {
        !matches!(
            self,
            ExecutableRepair::Approved(approved)
                if matches!(
                    approved.action(),
                    ApprovalAction::SetDhcpReservation { chosen: None, .. }
                )
        )
    }

    /// Whether restoring the pre-repair snapshot undoes this action.
    pub fn reversible(&self) -> bool {
        match self {
            ExecutableRepair::Safe { action } => matches!(
                action,
                SafeAction::RefreshAppCaches | SafeAction::RepairTailscaleServe
            ),
            // Only actions whose prior state a snapshot can restore. An
            // adapter bounce, a fresh lease and a router reboot cannot be
            // undone by writing a snapshot back.
            ExecutableRepair::Approved(approved) => match approved.action() {
                ApprovalAction::ChangeDnsServers { .. }
                | ApprovalAction::SetDhcpReservation { .. }
                | ApprovalAction::BlockDevice { .. }
                | ApprovalAction::UnblockDevice { .. }
                | ApprovalAction::SetInterfaceMtu { .. } => true,
                ApprovalAction::ResetAdapter { .. }
                | ApprovalAction::RenewDhcpLease { .. }
                | ApprovalAction::RebootRouter => false,
            },
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
                    let list: Vec<String> = servers.iter().map(ToString::to_string).collect();
                    format!("change_dns_servers {}", list.join(","))
                }
                ApprovalAction::SetDhcpReservation {
                    address, chosen, ..
                } => match chosen {
                    Some(device) => format!("set_dhcp_reservation {device} -> {address}"),
                    None => format!("set_dhcp_reservation (owner choice pending) -> {address}"),
                },
                ApprovalAction::BlockDevice { device } => format!("block_device {device}"),
                ApprovalAction::UnblockDevice { device } => format!("unblock_device {device}"),
                ApprovalAction::RebootRouter => "reboot_router".into(),
                ApprovalAction::RenewDhcpLease { interface } => {
                    format!("renew_dhcp_lease {interface}")
                }
                ApprovalAction::SetInterfaceMtu { interface, mtu } => {
                    format!("set_interface_mtu {interface} {}", mtu.get())
                }
            },
        }
    }
}
