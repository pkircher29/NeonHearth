//! Cross-platform interface inventory and the discovery target safety boundary.
//!
//! `pnet_datalink` is deliberately the only system-enumeration dependency here:
//! it uses platform APIs on Windows and Linux and exposes addresses, prefix lengths,
//! stable operating-system interface indices, and interface flags without invoking a
//! shell. This crate does not open sockets or send probes.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet_datalink::interfaces;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InterfaceId(u32);

impl InterfaceId {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    pub ip: IpAddr,
    pub prefix: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceClass {
    PhysicalWired,
    PhysicalWifi,
    Loopback,
    Tailscale,
    VpnTunnel,
    Container,
    VirtualMachine,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceRole {
    Corporate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interface {
    pub id: InterfaceId,
    pub name: String,
    pub description: Option<String>,
    pub up: bool,
    pub class: InterfaceClass,
    pub addresses: Vec<Address>,
    /// An owner setting. Never inferred from an adapter's name.
    pub owner_role: Option<InterfaceRole>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceOverride {
    Default,
    Enable,
}

impl Interface {
    #[must_use]
    pub fn discovery_eligible(&self, override_setting: InterfaceOverride) -> bool {
        if self.class == InterfaceClass::Loopback {
            return false;
        }
        if override_setting == InterfaceOverride::Enable {
            return true;
        }
        self.up
            && matches!(
                self.class,
                InterfaceClass::PhysicalWired | InterfaceClass::PhysicalWifi
            )
            && self.owner_role != Some(InterfaceRole::Corporate)
    }
}

/// Classifies only strong, platform-conventional identifiers. Ambiguous adapters stay
/// `Unknown` and are not discovered until their owner explicitly enables them.
#[must_use]
pub fn classify_interface(name: &str, description: Option<&str>, loopback: bool) -> InterfaceClass {
    if loopback {
        return InterfaceClass::Loopback;
    }
    let value = format!("{} {}", name, description.unwrap_or_default()).to_ascii_lowercase();
    if value.contains("tailscale") {
        InterfaceClass::Tailscale
    } else if value.contains("vethernet")
        || value.contains("hyper-v")
        || value.contains("virtualbox")
        || value.contains("vmware")
        || value.contains("virtio")
    {
        InterfaceClass::VirtualMachine
    } else if value.contains("docker")
        || value.contains("podman")
        || value.contains("container")
        || value.contains("veth")
        || value.contains("cni")
        || value.contains("br-")
    {
        InterfaceClass::Container
    } else if value == "lo" || value.starts_with("lo:") {
        InterfaceClass::Loopback
    } else if value.starts_with("wg")
        || value.starts_with("tun")
        || value.starts_with("tap")
        || value.contains("wireguard")
        || value.contains("openvpn")
        || value.contains("vpn")
        || value.contains("tunnel")
        || value.contains("ppp")
    {
        InterfaceClass::VpnTunnel
    } else if value.contains("wi-fi")
        || value.contains("wifi")
        || value.contains("wireless")
        || name.to_ascii_lowercase().starts_with("wlan")
        || name.to_ascii_lowercase().starts_with("wlp")
    {
        InterfaceClass::PhysicalWifi
    } else if value == "ethernet"
        || value.starts_with("ethernet ")
        || name.to_ascii_lowercase().starts_with("eth")
        || name.to_ascii_lowercase().starts_with("enp")
        || name.to_ascii_lowercase().starts_with("eno")
        || name.to_ascii_lowercase().starts_with("ens")
    {
        InterfaceClass::PhysicalWired
    } else {
        InterfaceClass::Unknown
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterfaceInventory {
    interfaces: BTreeMap<InterfaceId, Interface>,
}

impl InterfaceInventory {
    #[must_use]
    pub fn new(interfaces: Vec<Interface>) -> Self {
        Self {
            interfaces: interfaces
                .into_iter()
                .map(|interface| (interface.id, interface))
                .collect(),
        }
    }

    pub fn interfaces(&self) -> impl Iterator<Item = &Interface> {
        self.interfaces.values()
    }

    fn get(&self, id: InterfaceId) -> Option<&Interface> {
        self.interfaces.get(&id)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InventoryDiff {
    pub added: Vec<InterfaceId>,
    pub removed: Vec<InterfaceId>,
    pub changed: Vec<InterfaceId>,
}

#[must_use]
pub fn diff_inventory(before: &InterfaceInventory, after: &InterfaceInventory) -> InventoryDiff {
    let before_ids: BTreeSet<_> = before.interfaces.keys().copied().collect();
    let after_ids: BTreeSet<_> = after.interfaces.keys().copied().collect();
    InventoryDiff {
        added: after_ids.difference(&before_ids).copied().collect(),
        removed: before_ids.difference(&after_ids).copied().collect(),
        changed: before_ids
            .intersection(&after_ids)
            .filter(|id| before.interfaces.get(id) != after.interfaces.get(id))
            .copied()
            .collect(),
    }
}

#[derive(Debug, Error)]
pub enum InterfaceManagerError {
    #[error("system interface enumeration did not produce a usable interface index")]
    InvalidInterfaceIndex,
}

#[derive(Clone, Debug, Default)]
pub struct SystemInterfaceManager;

impl SystemInterfaceManager {
    pub fn snapshot(&self) -> Result<InterfaceInventory, InterfaceManagerError> {
        let system_interfaces = interfaces();
        if system_interfaces
            .iter()
            .any(|interface| interface.index == 0)
        {
            return Err(InterfaceManagerError::InvalidInterfaceIndex);
        }
        Ok(InterfaceInventory::new(
            system_interfaces
                .into_iter()
                .map(|interface| {
                    let description = (!interface.description.is_empty())
                        .then_some(interface.description.clone());
                    let loopback = interface.is_loopback();
                    let up = platform_interface_is_up(interface.index, interface.is_up());
                    let addresses = interface
                        .ips
                        .into_iter()
                        .map(|network| Address {
                            ip: network.ip(),
                            prefix: network.prefix(),
                        })
                        .collect();
                    Interface {
                        id: InterfaceId::new(interface.index),
                        class: classify_interface(
                            &interface.name,
                            description.as_deref(),
                            loopback,
                        ),
                        name: interface.name,
                        description,
                        up,
                        addresses,
                        owner_role: None,
                    }
                })
                .collect(),
        ))
    }
}

#[cfg(not(windows))]
fn platform_interface_is_up(_index: u32, reported_up: bool) -> bool {
    reported_up
}

#[cfg(windows)]
fn platform_interface_is_up(index: u32, _reported_up: bool) -> bool {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};
    use windows_sys::Win32::NetworkManagement::Ndis::NET_IF_OPER_STATUS_UP;

    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    // `GetIfEntry2` is the documented Windows interface-status API. It fills the
    // zero-initialized row selected by InterfaceIndex and opens no network socket.
    unsafe { GetIfEntry2(&mut row) == 0 && row.OperStatus == NET_IF_OPER_STATUS_UP }
}

#[derive(Clone, Debug)]
struct ApprovedPrefix {
    interface: InterfaceId,
    address: Address,
}

#[derive(Clone, Debug)]
pub struct TargetGuard {
    eligible: BTreeSet<InterfaceId>,
    prefixes: Vec<ApprovedPrefix>,
}

/// A homeowner-approved discovery range. Connected interface addresses are
/// inventory facts, never implicit authorization to probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetApproval {
    pub interface: InterfaceId,
    pub prefix: Address,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TargetGuardError {
    #[error("approved interface does not exist")]
    UnknownInterface,
    #[error("interface is not eligible for discovery")]
    InterfaceNotEligible,
    #[error("owner-approved prefix is invalid for {ip}/{prefix}")]
    InvalidApprovalPrefix { ip: IpAddr, prefix: u8 },
    #[error("owner-approved prefix is not permitted: {ip}/{prefix}")]
    DisallowedApproval { ip: IpAddr, prefix: u8 },
    #[error("owner-approved prefix is outside the selected interface network")]
    ApprovalOutsideInterfaceNetwork,
    #[error("target is not a permitted private or link-local address")]
    TargetNotPrivate,
    #[error("target does not belong to the approved prefix for the selected interface")]
    OutsideApprovedPrefix,
}

impl TargetGuard {
    pub fn new(
        inventory: InterfaceInventory,
        overrides: impl IntoIterator<Item = (InterfaceId, InterfaceOverride)>,
        approvals: impl IntoIterator<Item = TargetApproval>,
    ) -> Result<Self, TargetGuardError> {
        let overrides: BTreeMap<_, _> = overrides.into_iter().collect();
        let mut eligible = BTreeSet::new();
        for interface in inventory.interfaces() {
            let setting = overrides
                .get(&interface.id)
                .copied()
                .unwrap_or(InterfaceOverride::Default);
            if !interface.discovery_eligible(setting) {
                continue;
            }
            eligible.insert(interface.id);
        }
        let mut prefixes = Vec::new();
        for approval in approvals {
            let interface = inventory
                .get(approval.interface)
                .ok_or(TargetGuardError::UnknownInterface)?;
            if !eligible.contains(&approval.interface) {
                return Err(TargetGuardError::InterfaceNotEligible);
            }
            validate_prefix(&approval.prefix)?;
            if !is_permitted_approval_range(&approval.prefix) {
                return Err(TargetGuardError::DisallowedApproval {
                    ip: approval.prefix.ip,
                    prefix: approval.prefix.prefix,
                });
            }
            if !interface.addresses.iter().any(|attached| {
                validate_prefix(attached).is_ok()
                    && is_permitted_target(attached.ip)
                    && prefix_contains(attached, approval.prefix.ip)
                    && approval.prefix.prefix >= attached.prefix
            }) {
                return Err(TargetGuardError::ApprovalOutsideInterfaceNetwork);
            }
            prefixes.push(ApprovedPrefix {
                interface: approval.interface,
                address: approval.prefix,
            });
        }
        Ok(Self { eligible, prefixes })
    }

    pub fn authorize(
        &self,
        interface: InterfaceId,
        target: IpAddr,
    ) -> Result<(), TargetGuardError> {
        if !self.eligible.contains(&interface) {
            return Err(TargetGuardError::InterfaceNotEligible);
        }
        if !is_permitted_target(target) {
            return Err(TargetGuardError::TargetNotPrivate);
        }
        if self.prefixes.iter().any(|prefix| {
            prefix.interface == interface
                && prefix_contains(&prefix.address, target)
                && !is_ipv4_broadcast(&prefix.address, target)
        }) {
            Ok(())
        } else {
            Err(TargetGuardError::OutsideApprovedPrefix)
        }
    }
}

fn validate_prefix(address: &Address) -> Result<(), TargetGuardError> {
    let maximum = match address.ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if address.prefix > maximum {
        return Err(TargetGuardError::InvalidApprovalPrefix {
            ip: address.ip,
            prefix: address.prefix,
        });
    }
    Ok(())
}

fn prefix_contains(prefix: &Address, target: IpAddr) -> bool {
    match (prefix.ip, target) {
        (IpAddr::V4(network), IpAddr::V4(target)) => {
            let bits = prefix.prefix;
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            (u32::from(network) & mask) == (u32::from(target) & mask)
        }
        (IpAddr::V6(network), IpAddr::V6(target)) => {
            let bits = prefix.prefix;
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            (u128::from(network) & mask) == (u128::from(target) & mask)
        }
        _ => false,
    }
}

fn is_permitted_target(target: IpAddr) -> bool {
    match target {
        IpAddr::V4(address) => is_private_or_link_local_v4(address),
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && address.to_ipv4_mapped().is_none()
                && (is_ula(address) || address.is_unicast_link_local())
        }
    }
}

fn is_ipv4_broadcast(prefix: &Address, target: IpAddr) -> bool {
    let (IpAddr::V4(network), IpAddr::V4(target)) = (prefix.ip, target) else {
        return false;
    };
    if target == Ipv4Addr::BROADCAST {
        return true;
    }
    if prefix.prefix > 30 {
        return false;
    }
    let mask = if prefix.prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.prefix)
    };
    u32::from(target) == (u32::from(network) & mask) | !mask
}

fn is_permitted_approval_range(approval: &Address) -> bool {
    let allowed_ranges = [
        Address {
            ip: "10.0.0.0".parse().expect("valid literal"),
            prefix: 8,
        },
        Address {
            ip: "172.16.0.0".parse().expect("valid literal"),
            prefix: 12,
        },
        Address {
            ip: "192.168.0.0".parse().expect("valid literal"),
            prefix: 16,
        },
        Address {
            ip: "169.254.0.0".parse().expect("valid literal"),
            prefix: 16,
        },
        Address {
            ip: "fc00::".parse().expect("valid literal"),
            prefix: 7,
        },
        Address {
            ip: "fe80::".parse().expect("valid literal"),
            prefix: 10,
        },
    ];
    allowed_ranges
        .into_iter()
        .any(|allowed| approval.prefix >= allowed.prefix && prefix_contains(&allowed, approval.ip))
}

fn is_private_or_link_local_v4(address: Ipv4Addr) -> bool {
    address.is_private() || address.is_link_local()
}

fn is_ula(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}
