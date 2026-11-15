use crate::InterfaceId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
#[cfg(windows)]
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LinkAddress([u8; 6]);
impl TryFrom<[u8; 6]> for LinkAddress {
    type Error = NeighborError;
    fn try_from(v: [u8; 6]) -> Result<Self, Self::Error> {
        let address = Self(v);
        if !address.valid() {
            return Err(NeighborError::InvalidLinkAddress);
        }
        Ok(address)
    }
}
impl LinkAddress {
    /// True for locally administered (typically randomized or virtual) addresses.
    pub fn is_locally_administered(self) -> bool {
        self.0[0] & 2 != 0
    }
    fn valid(self) -> bool {
        self.0 != [0; 6] && self.0 != [0xff; 6] && self.0[0] & 1 == 0
    }
}
impl fmt::Display for LinkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}
impl fmt::Debug for LinkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinkAddress(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborReachability {
    Reachable,
    Stale,
    Delay,
    Probe,
    Permanent,
    Incomplete,
    Failed,
    NoArp,
    Unknown,
}
impl NeighborReachability {
    fn present(self) -> bool {
        matches!(
            self,
            Self::Reachable
                | Self::Stale
                | Self::Delay
                | Self::Probe
                | Self::Permanent
                | Self::NoArp
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct NeighborRow {
    interface: InterfaceId,
    ip: IpAddr,
    link_address: LinkAddress,
    reachability: NeighborReachability,
}
impl NeighborRow {
    pub fn new(
        interface: InterfaceId,
        ip: IpAddr,
        link_address: LinkAddress,
        reachability: NeighborReachability,
    ) -> Result<Self, NeighborError> {
        if !valid_ip(ip) {
            return Err(NeighborError::InvalidIp);
        }
        Ok(Self {
            interface,
            ip,
            link_address,
            reachability,
        })
    }
    pub fn interface(&self) -> InterfaceId {
        self.interface
    }
    pub fn ip(&self) -> IpAddr {
        self.ip
    }
    pub fn link_address(&self) -> LinkAddress {
        self.link_address
    }
    pub fn reachability(&self) -> NeighborReachability {
        self.reachability
    }
}
impl fmt::Debug for NeighborRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NeighborRow")
            .field("interface", &self.interface.get())
            .field("ip", &"<redacted>")
            .field("link_address", &self.link_address)
            .field("reachability", &self.reachability)
            .finish()
    }
}
fn valid_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(x) => {
            (x.is_private() || x.is_link_local())
                && !x.is_unspecified()
                && !x.is_loopback()
                && !x.is_multicast()
                && x != Ipv4Addr::new(255, 255, 255, 255)
        }
        IpAddr::V6(x) => {
            (x.is_unique_local() || x.is_unicast_link_local())
                && !x.is_unspecified()
                && !x.is_loopback()
                && !x.is_multicast()
        }
    }
}

#[derive(Clone, Debug)]
pub struct NeighborTrackerConfig {
    pub max_rows: usize,
    pub max_devices: usize,
    pub missed_snapshots_before_departure: usize,
}
impl Default for NeighborTrackerConfig {
    fn default() -> Self {
        Self {
            max_rows: 4096,
            max_devices: 1024,
            missed_snapshots_before_departure: 2,
        }
    }
}
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum NeighborError {
    #[error("invalid link address")]
    InvalidLinkAddress,
    #[error("invalid ip")]
    InvalidIp,
    #[error("invalid tracker config")]
    InvalidConfig,
    #[error("snapshot exceeds capacity")]
    Capacity,
    #[error("conflicting duplicate row")]
    ConflictingDuplicate,
    #[error("snapshot time moved backwards")]
    ClockRollback,
    #[error("snapshot source failure")]
    Transport,
    #[error("malformed neighbor message")]
    Malformed,
}

#[derive(Clone, Debug)]
pub struct NeighborSnapshotConfig {
    max_rows: usize,
    allowed_interfaces: BTreeSet<InterfaceId>,
    max_raw_messages: usize,
    /// Attached IPv4 networks per interface; rows naming their network or broadcast address
    /// are dropped. Empty means "unknown", which disables the check.
    networks: Vec<(InterfaceId, crate::Address)>,
}
impl NeighborSnapshotConfig {
    /// The source accepts at most four raw messages per requested output row.
    /// This bounds duplicate and irrelevant netlink input without making an
    /// otherwise valid duplicate-only stream exceed `max_rows`.
    const RAW_MESSAGES_PER_ROW: usize = 4;

    pub fn new<I>(max_rows: usize, allowed_interfaces: I) -> Result<Self, NeighborError>
    where
        I: IntoIterator<Item = InterfaceId>,
    {
        let allowed_interfaces: BTreeSet<_> = allowed_interfaces.into_iter().collect();
        let Some(max_raw_messages) = max_rows.checked_mul(Self::RAW_MESSAGES_PER_ROW) else {
            return Err(NeighborError::InvalidConfig);
        };
        if max_rows == 0
            || allowed_interfaces.is_empty()
            || allowed_interfaces.iter().any(|id| id.get() == 0)
        {
            return Err(NeighborError::InvalidConfig);
        }
        Ok(Self {
            max_rows,
            allowed_interfaces,
            max_raw_messages,
            networks: Vec::new(),
        })
    }

    /// Supplies the attached networks so subnet network/broadcast addresses are not
    /// reported as neighbors (a spoofed ARP entry for them would otherwise become a target).
    #[must_use]
    pub fn with_networks(mut self, networks: Vec<(InterfaceId, crate::Address)>) -> Self {
        self.networks = networks;
        self
    }

    fn is_network_or_broadcast(&self, interface: InterfaceId, ip: IpAddr) -> bool {
        self.networks
            .iter()
            .any(|(id, network)| *id == interface && crate::is_network_or_broadcast(network, ip))
    }

    pub fn max_raw_messages(&self) -> usize {
        self.max_raw_messages
    }

    pub fn max_rows(&self) -> usize {
        self.max_rows
    }

    pub fn allowed_interfaces(&self) -> &BTreeSet<InterfaceId> {
        &self.allowed_interfaces
    }
}

#[async_trait]
pub trait NeighborSnapshotSource: Send + Sync {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError>;
}

#[derive(Clone)]
struct RawNeighborRow {
    ifindex: u32,
    family: u16,
    address: [u8; 16],
    mac: Vec<u8>,
    reachability: NeighborReachability,
}
impl fmt::Debug for RawNeighborRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawNeighborRow")
            .field("ifindex", &self.ifindex)
            .field("family", &self.family)
            .field("address", &"<redacted>")
            .field("mac", &"<redacted>")
            .field("reachability", &self.reachability)
            .finish()
    }
}

const ADDRESS_FAMILY_INET: u16 = 2;
const ADDRESS_FAMILY_INET6: u16 = 23;

#[cfg(any(test, windows))]
fn map_windows_state_code(state: i32) -> NeighborReachability {
    match state {
        0 => NeighborReachability::Failed,
        1 => NeighborReachability::Incomplete,
        2 => NeighborReachability::Probe,
        3 => NeighborReachability::Delay,
        4 => NeighborReachability::Stale,
        5 => NeighborReachability::Reachable,
        6 => NeighborReachability::Permanent,
        _ => NeighborReachability::Unknown,
    }
}

/// Converts the bytes stored by Windows' IP address unions into the shared raw format.
/// `S_addr` is network-order bytes stored in a native integer, so `to_ne_bytes` preserves
/// the in-memory octet sequence on Windows.
#[cfg(any(test, windows))]
fn windows_address_to_raw(
    family: u16,
    ipv4_s_addr: u32,
    ipv6_bytes: [u8; 16],
) -> Result<[u8; 16], NeighborError> {
    match family {
        ADDRESS_FAMILY_INET => {
            let mut address = [0; 16];
            address[..4].copy_from_slice(&ipv4_s_addr.to_ne_bytes());
            Ok(address)
        }
        ADDRESS_FAMILY_INET6 => Ok(ipv6_bytes),
        _ => Err(NeighborError::Malformed),
    }
}

fn normalize_raw_rows(
    config: &NeighborSnapshotConfig,
    raw: impl IntoIterator<Item = RawNeighborRow>,
) -> Result<Vec<NeighborRow>, NeighborError> {
    let mut rows = Vec::new();
    let mut count = 0usize;
    for r in raw {
        count = count.saturating_add(1);
        if count > config.max_raw_messages() {
            // A flooded neighbor table must degrade, not blind discovery: keep the rows that
            // fit the raw budget and drop the rest.
            break;
        }
        if r.ifindex == 0
            || !config
                .allowed_interfaces()
                .contains(&InterfaceId::new(r.ifindex))
        {
            continue;
        }
        let ip = match r.family {
            ADDRESS_FAMILY_INET => IpAddr::V4(Ipv4Addr::from([
                r.address[0],
                r.address[1],
                r.address[2],
                r.address[3],
            ])),
            ADDRESS_FAMILY_INET6 => IpAddr::V6(Ipv6Addr::from(r.address)),
            _ => return Err(NeighborError::Malformed),
        };
        if !valid_ip(ip) || config.is_network_or_broadcast(InterfaceId::new(r.ifindex), ip) {
            continue;
        }
        if r.mac.len() != 6 {
            return Err(NeighborError::Malformed);
        }
        let mut mac = [0; 6];
        mac.copy_from_slice(&r.mac);
        // Multicast and broadcast link-layer mappings describe protocol groups,
        // not discoverable neighbor devices. A zero address remains malformed.
        if mac == [0xff; 6] || mac[0] & 1 != 0 {
            continue;
        }
        let link = LinkAddress::try_from(mac).map_err(|_| NeighborError::Malformed)?;
        rows.push(NeighborRow::new(
            InterfaceId::new(r.ifindex),
            ip,
            link,
            r.reachability,
        )?);
    }
    rows.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then(a.link_address.cmp(&b.link_address))
            .then(a.ip.cmp(&b.ip))
            .then(reachability_rank(a.reachability).cmp(&reachability_rank(b.reachability)))
    });
    rows.dedup();
    // Deterministic: rows are sorted by interface, link address, then IP.
    rows.truncate(config.max_rows());
    Ok(rows)
}

#[cfg(target_os = "linux")]
pub struct SystemNeighborSnapshotSource {
    config: NeighborSnapshotConfig,
}
#[cfg(target_os = "linux")]
impl SystemNeighborSnapshotSource {
    pub fn new(config: NeighborSnapshotConfig) -> Self {
        Self { config }
    }
}

fn reachability_rank(v: NeighborReachability) -> u8 {
    match v {
        NeighborReachability::Reachable => 0,
        NeighborReachability::Stale => 1,
        NeighborReachability::Delay => 2,
        NeighborReachability::Probe => 3,
        NeighborReachability::Permanent => 4,
        NeighborReachability::Incomplete => 5,
        NeighborReachability::Failed => 6,
        NeighborReachability::NoArp => 7,
        NeighborReachability::Unknown => 8,
    }
}

#[cfg(target_os = "linux")]
fn map_kernel_state(
    state: netlink_packet_route::neighbour::NeighbourState,
) -> NeighborReachability {
    use netlink_packet_route::neighbour::NeighbourState::*;
    match state {
        Reachable => NeighborReachability::Reachable,
        Stale => NeighborReachability::Stale,
        Delay => NeighborReachability::Delay,
        Probe => NeighborReachability::Probe,
        Permanent => NeighborReachability::Permanent,
        Incomplete => NeighborReachability::Incomplete,
        Failed => NeighborReachability::Failed,
        Noarp => NeighborReachability::NoArp,
        _ => NeighborReachability::Unknown,
    }
}
#[cfg(windows)]
pub struct SystemNeighborSnapshotSource {
    config: NeighborSnapshotConfig,
}
#[cfg(windows)]
impl SystemNeighborSnapshotSource {
    pub fn new(config: NeighborSnapshotConfig) -> Self {
        Self { config }
    }
}

#[cfg(windows)]
fn windows_snapshot(config: &NeighborSnapshotConfig) -> Result<Vec<NeighborRow>, NeighborError> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpNetTable2, MIB_IPNET_ROW2, MIB_IPNET_TABLE2,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    // SAFETY: table is an out-pointer initialized to null; successful non-null allocations are owned by guard.
    let rc = unsafe { GetIpNetTable2(AF_UNSPEC, &mut table) };
    if rc != ERROR_SUCCESS {
        return Err(NeighborError::Transport);
    }
    if table.is_null() {
        return Err(NeighborError::Malformed);
    }
    struct Guard(*mut MIB_IPNET_TABLE2);
    impl Drop for Guard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this guard is created only for a successful non-null GetIpNetTable2 allocation.
                unsafe { FreeMibTable(self.0.cast()) };
            }
        }
    }
    let _guard = Guard(table);
    // SAFETY: `table` is a successful non-null MIB_IPNET_TABLE2 allocation owned by `_guard`.
    let count = unsafe { (*table).NumEntries as usize };
    // Clamp rather than fail: an oversized table keeps its first rows.
    let count = count
        .min(config.max_raw_messages())
        .min(isize::MAX as usize / size_of::<MIB_IPNET_ROW2>());
    // SAFETY: `table` is a successful non-null MIB_IPNET_TABLE2 allocation owned by `_guard`.
    let first = unsafe { (*table).Table.as_ptr() };
    let mut raw_rows = Vec::new();
    raw_rows
        .try_reserve_exact(count)
        .map_err(|_| NeighborError::Capacity)?;
    for i in 0..count {
        // SAFETY: count is bounded by allocation-sized isize limit and Table is the first row of the table allocation.
        let row = unsafe { &*first.add(i) };
        if row.InterfaceIndex == 0
            || !config
                .allowed_interfaces()
                .contains(&InterfaceId::new(row.InterfaceIndex))
        {
            continue;
        }
        let reachability = map_windows_state_code(row.State);
        // Incomplete, unreachable, and unknown rows have no usable neighbor identity and
        // may legitimately omit a physical address. Do not inspect their payload unions.
        if !reachability.present() {
            continue;
        }
        let mac_len = row.PhysicalAddressLength as usize;
        if mac_len > row.PhysicalAddress.len() {
            return Err(NeighborError::Malformed);
        }
        let mac = row.PhysicalAddress[..mac_len].to_vec();
        // SAFETY: the row reference comes from the bounded MIB table allocation and the family field is initialized.
        let family = unsafe { row.Address.si_family };
        let address = if family == AF_INET {
            // SAFETY: `family` selects the initialized IPv4 variant of the SOCKADDR_INET union.
            let s_addr = unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr };
            windows_address_to_raw(family, s_addr, [0; 16])?
        } else if family == AF_INET6 {
            // SAFETY: `family` selects the initialized IPv6 variant of the SOCKADDR_INET union.
            let bytes = unsafe { row.Address.Ipv6.sin6_addr.u.Byte };
            windows_address_to_raw(family, 0, bytes)?
        } else {
            return Err(NeighborError::Malformed);
        };
        raw_rows.push(RawNeighborRow {
            ifindex: row.InterfaceIndex,
            family,
            address,
            mac,
            reachability,
        });
    }
    normalize_raw_rows(config, raw_rows)
}

#[cfg(windows)]
#[async_trait]
impl NeighborSnapshotSource for SystemNeighborSnapshotSource {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError> {
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || windows_snapshot(&config))
            .await
            .map_err(|_| NeighborError::Transport)?
    }
}

#[cfg(target_os = "linux")]
fn decode_linux_message_raw(
    config: &NeighborSnapshotConfig,
    message: netlink_packet_route::neighbour::NeighbourMessage,
) -> Result<Option<RawNeighborRow>, NeighborError> {
    use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};

    // Kernel ifindex 0 is not a usable interface. Treat it exactly like an
    // out-of-scope message rather than letting it enter the allowlist domain.
    if message.header.ifindex == 0 {
        return Ok(None);
    }
    let interface = InterfaceId::new(message.header.ifindex);
    if !config.allowed_interfaces().contains(&interface) {
        return Ok(None);
    }

    let mut ip = None;
    let mut link_address = None;
    for attribute in message.attributes {
        match attribute {
            NeighbourAttribute::Destination(address) => {
                if ip.is_some() {
                    return Err(NeighborError::Malformed);
                }
                ip = Some(match address {
                    NeighbourAddress::Inet(value) => IpAddr::V4(value),
                    NeighbourAddress::Inet6(value) => IpAddr::V6(value),
                    _ => return Err(NeighborError::Malformed),
                });
            }
            NeighbourAttribute::LinkLayerAddress(value) => {
                if link_address.is_some() {
                    return Err(NeighborError::Malformed);
                }
                link_address = Some(value);
            }
            _ => {}
        }
    }
    let (Some(ip), Some(link_address)) = (ip, link_address) else {
        return Ok(None);
    };
    let (family, address) = match ip {
        IpAddr::V4(address) => {
            let mut raw = [0; 16];
            raw[..4].copy_from_slice(&address.octets());
            (ADDRESS_FAMILY_INET, raw)
        }
        IpAddr::V6(address) => (ADDRESS_FAMILY_INET6, address.octets()),
    };
    Ok(Some(RawNeighborRow {
        ifindex: interface.get(),
        family,
        address,
        mac: link_address,
        reachability: map_kernel_state(message.header.state),
    }))
}

#[cfg(target_os = "linux")]
fn normalize_linux_messages<I>(
    config: &NeighborSnapshotConfig,
    messages: I,
) -> Result<Vec<NeighborRow>, NeighborError>
where
    I: IntoIterator<Item = netlink_packet_route::neighbour::NeighbourMessage>,
{
    let mut raw_count = 0usize;
    let mut raw_rows = Vec::new();
    for message in messages {
        raw_count = raw_count.saturating_add(1);
        if raw_count > config.max_raw_messages() {
            break;
        }
        if let Some(row) = decode_linux_message_raw(config, message)? {
            raw_rows.push(row);
        }
    }
    normalize_raw_rows(config, raw_rows)
}

#[cfg(target_os = "linux")]
#[async_trait]
impl NeighborSnapshotSource for SystemNeighborSnapshotSource {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError> {
        use futures_util::TryStreamExt;
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|_| NeighborError::Transport)?;
        tokio::spawn(connection);
        let mut messages = Vec::new();
        for family in [
            netlink_packet_route::AddressFamily::Inet,
            netlink_packet_route::AddressFamily::Inet6,
        ] {
            let mut stream = handle
                .neighbours()
                .get()
                .set_address_family(family)
                .execute();
            while let Some(message) = stream
                .try_next()
                .await
                .map_err(|_| NeighborError::Transport)?
            {
                if messages.len() >= self.config.max_raw_messages() {
                    // Keep draining the dump (the netlink socket must be read to its end)
                    // but retain only what the budget allows.
                    continue;
                }
                messages.push(message);
            }
        }
        normalize_linux_messages(&self.config, messages)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct NeighborDevice {
    interface: InterfaceId,
    link_address: LinkAddress,
    addresses: Vec<IpAddr>,
}
impl NeighborDevice {
    pub fn interface(&self) -> InterfaceId {
        self.interface
    }
    pub fn link_address(&self) -> LinkAddress {
        self.link_address
    }
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
}
#[derive(Clone, Eq, PartialEq)]
pub enum NeighborEvent {
    Appeared {
        device: NeighborDevice,
        observed_at: DateTime<Utc>,
    },
    Confirmed {
        device: NeighborDevice,
        observed_at: DateTime<Utc>,
    },
    Missed {
        device: NeighborDevice,
        observed_at: DateTime<Utc>,
        consecutive_misses: usize,
    },
    Departed {
        device: NeighborDevice,
        observed_at: DateTime<Utc>,
    },
}
impl fmt::Debug for NeighborEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (k, d, t) = match self {
            Self::Appeared {
                device,
                observed_at,
            } => ("Appeared", device, observed_at),
            Self::Confirmed {
                device,
                observed_at,
            } => ("Confirmed", device, observed_at),
            Self::Missed {
                device,
                observed_at,
                ..
            } => ("Missed", device, observed_at),
            Self::Departed {
                device,
                observed_at,
            } => ("Departed", device, observed_at),
        };
        f.debug_struct("NeighborEvent")
            .field("kind", &k)
            .field("interface", &d.interface.get())
            .field("address_count", &d.addresses.len())
            .field("observed_at", t)
            .field(
                "consecutive_misses",
                &match self {
                    Self::Missed {
                        consecutive_misses, ..
                    } => Some(consecutive_misses),
                    _ => None,
                },
            )
            .finish()
    }
}

#[derive(Clone)]
struct State {
    device: NeighborDevice,
    missed: usize,
    /// Consecutive snapshots in which every row for this device was only `Stale`.
    stale_streak: usize,
}

/// A device kept "present" only by `Stale` cache entries is treated as missed after this many
/// consecutive snapshots. Stale entries survive for minutes after a device leaves (Windows)
/// and are never refreshed without traffic, so they cannot prove presence indefinitely.
const MAX_STALE_SNAPSHOTS: usize = 60;

fn fresh(reachability: NeighborReachability) -> bool {
    reachability.present() && reachability != NeighborReachability::Stale
}
#[derive(Clone)]
pub struct NeighborTracker {
    cfg: NeighborTrackerConfig,
    states: BTreeMap<(InterfaceId, LinkAddress), State>,
    last_observed_at: Option<DateTime<Utc>>,
}
impl NeighborTracker {
    pub fn new(cfg: NeighborTrackerConfig) -> Result<Self, NeighborError> {
        if cfg.max_rows == 0 || cfg.max_devices == 0 || cfg.missed_snapshots_before_departure == 0 {
            return Err(NeighborError::InvalidConfig);
        }
        Ok(Self {
            cfg,
            states: BTreeMap::new(),
            last_observed_at: None,
        })
    }
    /// Observations use trusted local snapshot-completion times; equal times are accepted.
    /// No separate future-skew check is needed because callers do not supply remote timestamps.
    pub fn observe(
        &mut self,
        rows: Vec<NeighborRow>,
        observed_at: DateTime<Utc>,
    ) -> Result<Vec<NeighborEvent>, NeighborError> {
        if self.last_observed_at.is_some_and(|last| observed_at < last) {
            return Err(NeighborError::ClockRollback);
        }
        let mut rows = rows;
        // Overflow keeps the first rows in snapshot order instead of failing the cycle.
        rows.truncate(self.cfg.max_rows);
        let mut grouped: BTreeMap<(InterfaceId, LinkAddress), (Vec<IpAddr>, bool)> =
            BTreeMap::new();
        let mut ips: BTreeMap<(InterfaceId, IpAddr), LinkAddress> = BTreeMap::new();
        for r in rows {
            if !valid_ip(r.ip) {
                return Err(NeighborError::InvalidIp);
            }
            if !r.link_address.valid() {
                return Err(NeighborError::InvalidLinkAddress);
            }
            if let Some(old) = ips.insert((r.interface, r.ip), r.link_address)
                && old != r.link_address
            {
                return Err(NeighborError::ConflictingDuplicate);
            }
            if !r.reachability.present() {
                continue;
            }
            let entry = grouped
                .entry((r.interface, r.link_address))
                .or_insert_with(|| (Vec::new(), false));
            entry.0.push(r.ip);
            entry.1 |= fresh(r.reachability);
        }
        // Devices held present only by Stale entries for too long are treated as absent.
        let expired: Vec<_> = grouped
            .iter()
            .filter(|(key, (_, is_fresh))| {
                !*is_fresh
                    && self
                        .states
                        .get(key)
                        .is_some_and(|s| s.stale_streak >= MAX_STALE_SNAPSHOTS)
            })
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            grouped.remove(&key);
        }
        // Capacity: known devices always stay; new ones are admitted in key order while there
        // is room. A flood of spoofed neighbors cannot evict or blind real ones.
        let mut next = self.states.clone();
        let mut room = self.cfg.max_devices.saturating_sub(next.len());
        grouped.retain(|key, _| {
            if next.contains_key(key) {
                true
            } else if room > 0 {
                room -= 1;
                true
            } else {
                false
            }
        });
        let present: std::collections::BTreeSet<_> = grouped.keys().copied().collect();
        // Events are stable: present devices are key-sorted first, then absent devices key-sorted.
        let mut events = Vec::new();
        for (key, (mut addrs, is_fresh)) in grouped {
            addrs.sort();
            addrs.dedup();
            let device = NeighborDevice {
                interface: key.0,
                link_address: key.1,
                addresses: addrs,
            };
            match next.get_mut(&key) {
                Some(s) => {
                    s.device = device.clone();
                    s.missed = 0;
                    s.stale_streak = if is_fresh { 0 } else { s.stale_streak + 1 };
                    events.push(NeighborEvent::Confirmed {
                        device,
                        observed_at,
                    });
                }
                None => {
                    next.insert(
                        key,
                        State {
                            device: device.clone(),
                            missed: 0,
                            stale_streak: usize::from(!is_fresh),
                        },
                    );
                    events.push(NeighborEvent::Appeared {
                        device,
                        observed_at,
                    });
                }
            }
        }
        let mut departed = Vec::new();
        for (key, s) in &mut next {
            if !present.contains(key) {
                s.missed = s.missed.checked_add(1).ok_or(NeighborError::Capacity)?;
                events.push(NeighborEvent::Missed {
                    device: s.device.clone(),
                    observed_at,
                    consecutive_misses: s.missed,
                });
                if s.missed >= self.cfg.missed_snapshots_before_departure {
                    events.push(NeighborEvent::Departed {
                        device: s.device.clone(),
                        observed_at,
                    });
                    departed.push(*key);
                }
            }
        }
        for key in departed {
            next.remove(&key);
        }
        self.states = next;
        self.last_observed_at = Some(observed_at);
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn raw(
        ifindex: u32,
        family: u16,
        address: [u8; 16],
        mac: Vec<u8>,
        state: i32,
    ) -> RawNeighborRow {
        RawNeighborRow {
            ifindex,
            family,
            address,
            mac,
            reachability: map_windows_state_code(state),
        }
    }
    #[test]
    fn windows_neutral_decoder_is_bounded_deterministic_and_redacted() {
        let c = NeighborSnapshotConfig::new(2, [InterfaceId::new(2)]).unwrap();
        let mut a = [0; 16];
        a[..4].copy_from_slice(&[192, 168, 1, 2]);
        let r = raw(2, 2, a, vec![2, 0, 0, 0, 0, 1], 5);
        let rows = normalize_raw_rows(&c, [r.clone(), r.clone()]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ip(), "192.168.1.2".parse::<IpAddr>().unwrap());
        assert_eq!(
            normalize_raw_rows(&c, [raw(0, 2, a, vec![2, 0, 0, 0, 0, 1], 5)])
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            normalize_raw_rows(&c, [raw(2, 99, a, vec![2, 0, 0, 0, 0, 1], 5)]),
            Err(NeighborError::Malformed)
        );
        assert_eq!(
            normalize_raw_rows(&c, [raw(2, 2, a, vec![1, 2], 5)]),
            Err(NeighborError::Malformed)
        );
        assert!(!format!("{:?}", NeighborError::Malformed).contains("192.168"));
        // Overflow degrades to a bounded result instead of failing the whole snapshot.
        assert_eq!(
            normalize_raw_rows(&c, std::iter::repeat_n(r, c.max_raw_messages() + 1))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn windows_state_numbers_match_the_native_contract() {
        let cases = [
            (0, NeighborReachability::Failed),
            (1, NeighborReachability::Incomplete),
            (2, NeighborReachability::Probe),
            (3, NeighborReachability::Delay),
            (4, NeighborReachability::Stale),
            (5, NeighborReachability::Reachable),
            (6, NeighborReachability::Permanent),
            (7, NeighborReachability::Unknown),
            (i32::MAX, NeighborReachability::Unknown),
        ];
        for (state, expected) in cases {
            assert_eq!(map_windows_state_code(state), expected, "state {state}");
        }
    }

    #[test]
    fn windows_address_decoder_preserves_in_memory_v4_and_v6_bytes() {
        let ipv4 = u32::from_ne_bytes([192, 168, 1, 2]);
        assert_eq!(
            windows_address_to_raw(2, ipv4, [0; 16]).unwrap(),
            [192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let ula = [0xfd, 0x12, 0x34, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(windows_address_to_raw(23, 0, ula).unwrap(), ula);
        let link_local = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            windows_address_to_raw(23, 0, link_local).unwrap(),
            link_local
        );
        assert_eq!(
            windows_address_to_raw(999, ipv4, ula),
            Err(NeighborError::Malformed)
        );
    }

    #[test]
    fn raw_neighbor_row_debug_redacts_network_identifiers() {
        let row = raw(
            2,
            ADDRESS_FAMILY_INET,
            [192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![2, 0, 0, 0, 0, 1],
            5,
        );
        let debug = format!("{row:?}");
        assert!(!debug.contains("192"));
        assert!(!debug.contains("168"));
        assert!(!debug.contains("[2, 0, 0, 0, 0, 1]"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn neutral_normalizer_enforces_scope_validation_ordering_dedup_and_capacity() {
        let config = NeighborSnapshotConfig::new(2, [InterfaceId::new(2)]).unwrap();
        let v4 = |last| {
            let mut address = [0; 16];
            address[..4].copy_from_slice(&[192, 168, 1, last]);
            address
        };
        let first = raw(2, ADDRESS_FAMILY_INET, v4(2), vec![2, 0, 0, 0, 0, 2], 5);
        let second = raw(
            2,
            ADDRESS_FAMILY_INET6,
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            vec![2, 0, 0, 0, 0, 1],
            6,
        );
        let rows = normalize_raw_rows(
            &config,
            [first.clone(), second.clone(), first.clone(), second.clone()],
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].link_address(),
            LinkAddress::try_from([2, 0, 0, 0, 0, 1]).unwrap()
        );
        assert_eq!(rows[0].ip(), "fd00::1".parse::<IpAddr>().unwrap());
        assert_eq!(rows[1].ip(), "192.168.1.2".parse::<IpAddr>().unwrap());

        for ignored in [
            raw(0, ADDRESS_FAMILY_INET, v4(3), vec![], 5),
            raw(3, ADDRESS_FAMILY_INET, v4(3), vec![], 5),
            raw(
                2,
                ADDRESS_FAMILY_INET,
                {
                    let mut address = [0; 16];
                    address[..4].copy_from_slice(&[8, 8, 8, 8]);
                    address
                },
                vec![2, 0, 0, 0, 0, 3],
                5,
            ),
            raw(2, ADDRESS_FAMILY_INET, v4(255), vec![0xff; 6], 6),
            raw(2, ADDRESS_FAMILY_INET, v4(4), vec![1, 0, 0, 0, 0, 4], 6),
        ] {
            assert!(normalize_raw_rows(&config, [ignored]).unwrap().is_empty());
        }
        assert_eq!(
            normalize_raw_rows(
                &config,
                [raw(
                    2,
                    ADDRESS_FAMILY_INET,
                    v4(255),
                    vec![2, 0, 0, 0, 0, 5],
                    6,
                )],
            )
            .unwrap()[0]
                .ip(),
            "192.168.1.255".parse::<IpAddr>().unwrap()
        );

        for malformed in [
            raw(2, 999, v4(3), vec![2, 0, 0, 0, 0, 3], 5),
            raw(2, ADDRESS_FAMILY_INET, v4(3), vec![2, 0], 5),
            raw(2, ADDRESS_FAMILY_INET, v4(3), vec![0; 6], 5),
        ] {
            assert_eq!(
                normalize_raw_rows(&config, [malformed]),
                Err(NeighborError::Malformed)
            );
        }

        let third = raw(2, ADDRESS_FAMILY_INET, v4(4), vec![2, 0, 0, 0, 0, 4], 5);
        // Over max_rows the deterministic prefix is kept (this fixture previously errored).
        assert_eq!(
            normalize_raw_rows(&config, [first.clone(), second.clone(), third])
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            normalize_raw_rows(
                &config,
                std::iter::repeat_n(first, config.max_raw_messages() + 1),
            )
            .unwrap()
            .len(),
            1
        );
        assert!(!format!("{:?}", rows[0]).contains("fd00"));
        assert_eq!(
            format!("{:?}", rows[0].link_address()),
            "LinkAddress(<redacted>)"
        );
    }

    #[cfg(target_os = "linux")]
    use netlink_packet_route::neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState,
    };

    #[test]
    fn removes_departed_state_in_the_snapshot_that_emits_departure() {
        let mut tracker = NeighborTracker::new(NeighborTrackerConfig {
            max_devices: 1,
            missed_snapshots_before_departure: 1,
            ..Default::default()
        })
        .unwrap();
        let row = NeighborRow::new(
            InterfaceId::new(2),
            "192.168.1.2".parse().unwrap(),
            LinkAddress::try_from([0x02, 0, 0, 0, 0, 1]).unwrap(),
            NeighborReachability::Reachable,
        )
        .unwrap();

        tracker
            .observe(vec![row], Utc.timestamp_opt(1, 0).unwrap())
            .unwrap();
        assert!(matches!(
            tracker
                .observe(vec![], Utc.timestamp_opt(2, 0).unwrap())
                .unwrap()
                .as_slice(),
            [
                NeighborEvent::Missed {
                    consecutive_misses: 1,
                    ..
                },
                NeighborEvent::Departed { .. }
            ]
        ));
        assert!(tracker.states.is_empty());
    }

    #[test]
    fn observe_revalidates_internally_constructed_invalid_rows_atomically() {
        let mut tracker = NeighborTracker::new(NeighborTrackerConfig {
            missed_snapshots_before_departure: 2,
            ..Default::default()
        })
        .unwrap();
        let valid = NeighborRow::new(
            InterfaceId::new(2),
            "192.168.1.2".parse().unwrap(),
            LinkAddress::try_from([0x02, 0, 0, 0, 0, 1]).unwrap(),
            NeighborReachability::Reachable,
        )
        .unwrap();
        let invalid_ip = NeighborRow {
            interface: InterfaceId::new(2),
            ip: "8.8.8.8".parse().unwrap(),
            link_address: LinkAddress::try_from([0x02, 0, 0, 0, 0, 2]).unwrap(),
            reachability: NeighborReachability::Reachable,
        };
        let invalid_link_address = NeighborRow {
            interface: InterfaceId::new(2),
            ip: "192.168.1.3".parse().unwrap(),
            link_address: LinkAddress([0; 6]),
            reachability: NeighborReachability::Reachable,
        };

        tracker
            .observe(vec![valid], Utc.timestamp_opt(1, 0).unwrap())
            .unwrap();
        assert_eq!(
            tracker.observe(vec![invalid_ip], Utc.timestamp_opt(100, 0).unwrap()),
            Err(NeighborError::InvalidIp)
        );
        assert_eq!(
            tracker.observe(
                vec![invalid_link_address],
                Utc.timestamp_opt(100, 0).unwrap()
            ),
            Err(NeighborError::InvalidLinkAddress)
        );
        assert!(
            tracker
                .observe(vec![], Utc.timestamp_opt(2, 0).unwrap())
                .unwrap()
                .iter()
                .any(|event| matches!(
                    event,
                    NeighborEvent::Missed {
                        consecutive_misses: 1,
                        ..
                    }
                ))
        );
        assert!(matches!(
            tracker
                .observe(vec![], Utc.timestamp_opt(3, 0).unwrap())
                .unwrap()
                .as_slice(),
            [
                NeighborEvent::Missed {
                    consecutive_misses: 2,
                    ..
                },
                NeighborEvent::Departed { .. }
            ]
        ));
    }

    #[cfg(target_os = "linux")]
    fn message(
        ifindex: u32,
        ip: std::net::IpAddr,
        link: &[u8],
        state: NeighbourState,
    ) -> NeighbourMessage {
        let mut message = NeighbourMessage::default();
        message.header.ifindex = ifindex;
        message.header.state = state;
        message.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::from(ip)),
            NeighbourAttribute::LinkLayerAddress(link.to_vec()),
        ];
        message
    }

    #[cfg(target_os = "linux")]
    fn snapshot_config(max_rows: usize) -> NeighborSnapshotConfig {
        NeighborSnapshotConfig::new(max_rows, [InterfaceId::new(2)]).unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_normalizer_decodes_private_ipv4_ipv6_and_all_kernel_states() {
        let states = [
            (NeighbourState::Reachable, NeighborReachability::Reachable),
            (NeighbourState::Stale, NeighborReachability::Stale),
            (NeighbourState::Delay, NeighborReachability::Delay),
            (NeighbourState::Probe, NeighborReachability::Probe),
            (NeighbourState::Permanent, NeighborReachability::Permanent),
            (NeighbourState::Incomplete, NeighborReachability::Incomplete),
            (NeighbourState::Failed, NeighborReachability::Failed),
            (NeighbourState::Noarp, NeighborReachability::NoArp),
            (NeighbourState::None, NeighborReachability::Unknown),
            (NeighbourState::Other(0x400), NeighborReachability::Unknown),
        ];
        let messages = states.iter().enumerate().map(|(index, (state, _))| {
            message(
                2,
                if index % 2 == 0 {
                    format!("192.168.1.{}", index + 1).parse().unwrap()
                } else {
                    format!("fd00::{:x}", index + 1).parse().unwrap()
                },
                &[0x02, 0, 0, 0, 0, index as u8 + 1],
                *state,
            )
        });

        let rows = normalize_linux_messages(&snapshot_config(16), messages).unwrap();
        assert_eq!(rows.len(), states.len());
        assert!(
            rows.iter()
                .any(|row| row.reachability() == NeighborReachability::NoArp)
        );
        for (_, expected) in states {
            assert!(rows.iter().any(|row| row.reachability() == expected));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_normalizer_skips_missing_out_of_scope_disallowed_and_zero_interface_messages() {
        let mut missing_destination = NeighbourMessage::default();
        missing_destination.header.ifindex = 2;
        missing_destination.attributes =
            vec![NeighbourAttribute::LinkLayerAddress(vec![2, 0, 0, 0, 0, 1])];
        let mut missing_link = NeighbourMessage::default();
        missing_link.header.ifindex = 2;
        missing_link.attributes = vec![NeighbourAttribute::Destination(NeighbourAddress::Inet(
            "192.168.1.1".parse().unwrap(),
        ))];
        let rows = normalize_linux_messages(
            &snapshot_config(16),
            [
                missing_destination,
                missing_link,
                message(
                    2,
                    "8.8.8.8".parse().unwrap(),
                    &[2, 0, 0, 0, 0, 2],
                    NeighbourState::Reachable,
                ),
                message(
                    3,
                    "192.168.1.3".parse().unwrap(),
                    &[2, 0, 0, 0, 0, 3],
                    NeighbourState::Reachable,
                ),
                message(
                    0,
                    "192.168.1.4".parse().unwrap(),
                    &[2, 0, 0, 0, 0, 4],
                    NeighbourState::Reachable,
                ),
            ],
        )
        .unwrap();
        assert!(rows.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_normalizer_rejects_malformed_attributes_and_redacts_errors() {
        let mut duplicate_destination = NeighbourMessage::default();
        duplicate_destination.header.ifindex = 2;
        duplicate_destination.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet("192.168.1.1".parse().unwrap())),
            NeighbourAttribute::Destination(NeighbourAddress::Inet("192.168.1.2".parse().unwrap())),
            NeighbourAttribute::LinkLayerAddress(vec![2, 0, 0, 0, 0, 1]),
        ];
        let mut duplicate_link = message(
            2,
            "192.168.1.1".parse().unwrap(),
            &[2, 0, 0, 0, 0, 1],
            NeighbourState::Reachable,
        );
        duplicate_link
            .attributes
            .push(NeighbourAttribute::LinkLayerAddress(vec![2, 0, 0, 0, 0, 2]));
        for message in [duplicate_destination, duplicate_link] {
            let error = normalize_linux_messages(&snapshot_config(16), [message]).unwrap_err();
            assert_eq!(error, NeighborError::Malformed);
            let text = format!("{error:?} {error}");
            assert!(!text.contains("192.168.1"));
            assert!(!text.contains("02:00"));
        }
        let invalid_length = message(
            2,
            "192.168.1.1".parse().unwrap(),
            &[1, 2, 3],
            NeighbourState::Reachable,
        );
        let multicast_link = message(
            2,
            "192.168.1.1".parse().unwrap(),
            &[1, 0, 0, 0, 0, 1],
            NeighbourState::Reachable,
        );
        let broadcast_link = message(
            2,
            "192.168.1.1".parse().unwrap(),
            &[0xff; 6],
            NeighbourState::Reachable,
        );
        let zero_link = message(
            2,
            "192.168.1.1".parse().unwrap(),
            &[0; 6],
            NeighbourState::Reachable,
        );
        for message in [invalid_length, zero_link] {
            let error = normalize_linux_messages(&snapshot_config(16), [message]).unwrap_err();
            assert_eq!(error, NeighborError::Malformed);
            assert!(!format!("{error:?} {error}").contains("192.168.1"));
        }
        for message in [multicast_link, broadcast_link] {
            assert!(
                normalize_linux_messages(&snapshot_config(16), [message])
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_normalizer_deduplicates_exact_rows_sorts_and_bounds_raw_input_separately() {
        let first = message(
            2,
            "192.168.1.2".parse().unwrap(),
            &[2, 0, 0, 0, 0, 2],
            NeighbourState::Reachable,
        );
        let second = message(
            2,
            "192.168.1.1".parse().unwrap(),
            &[2, 0, 0, 0, 0, 1],
            NeighbourState::Noarp,
        );
        let config = snapshot_config(2);
        let rows = normalize_linux_messages(
            &config,
            [first.clone(), second.clone(), first.clone(), second.clone()],
        )
        .unwrap();
        assert_eq!(
            rows,
            vec![
                NeighborRow::new(
                    InterfaceId::new(2),
                    "192.168.1.1".parse().unwrap(),
                    LinkAddress::try_from([2, 0, 0, 0, 0, 1]).unwrap(),
                    NeighborReachability::NoArp,
                )
                .unwrap(),
                NeighborRow::new(
                    InterfaceId::new(2),
                    "192.168.1.2".parse().unwrap(),
                    LinkAddress::try_from([2, 0, 0, 0, 0, 2]).unwrap(),
                    NeighborReachability::Reachable,
                )
                .unwrap(),
            ]
        );
        assert!(
            normalize_linux_messages(
                &config,
                std::iter::repeat_n(first, config.max_raw_messages() + 1)
            )
            .is_ok()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_snapshot_config_rejects_zero_interface_and_raw_ceiling_overflow() {
        assert!(matches!(
            NeighborSnapshotConfig::new(1, [InterfaceId::new(0)]),
            Err(NeighborError::InvalidConfig)
        ));
        assert!(matches!(
            NeighborSnapshotConfig::new(usize::MAX, [InterfaceId::new(2)]),
            Err(NeighborError::InvalidConfig)
        ));
    }

    #[test]
    fn rows_naming_attached_network_or_broadcast_addresses_are_dropped() {
        let config = NeighborSnapshotConfig::new(8, [InterfaceId::new(2)])
            .unwrap()
            .with_networks(vec![(
                InterfaceId::new(2),
                crate::Address {
                    ip: "192.168.1.10".parse().unwrap(),
                    prefix: 24,
                },
            )]);
        let v4 = |last| {
            let mut address = [0; 16];
            address[..4].copy_from_slice(&[192, 168, 1, last]);
            address
        };
        for last in [0u8, 255] {
            assert!(
                normalize_raw_rows(
                    &config,
                    [raw(
                        2,
                        ADDRESS_FAMILY_INET,
                        v4(last),
                        vec![2, 0, 0, 0, 0, 7],
                        5
                    )]
                )
                .unwrap()
                .is_empty(),
                "{last}"
            );
        }
        assert_eq!(
            normalize_raw_rows(
                &config,
                [raw(
                    2,
                    ADDRESS_FAMILY_INET,
                    v4(77),
                    vec![2, 0, 0, 0, 0, 7],
                    5
                )]
            )
            .unwrap()
            .len(),
            1
        );
    }

    #[test]
    fn stale_only_devices_stop_counting_as_present_after_the_cap() {
        let mut tracker = NeighborTracker::new(NeighborTrackerConfig::default()).unwrap();
        let row = |state| {
            NeighborRow::new(
                InterfaceId::new(2),
                "192.168.1.2".parse().unwrap(),
                LinkAddress::try_from([0x02, 0, 0, 0, 0, 1]).unwrap(),
                state,
            )
            .unwrap()
        };
        let mut second = 0;
        let mut at = || {
            second += 1;
            Utc.timestamp_opt(second, 0).unwrap()
        };
        tracker
            .observe(vec![row(NeighborReachability::Reachable)], at())
            .unwrap();
        let mut confirmed = 0;
        let mut missed = false;
        for _ in 0..(MAX_STALE_SNAPSHOTS + 3) {
            for event in tracker
                .observe(vec![row(NeighborReachability::Stale)], at())
                .unwrap()
            {
                match event {
                    NeighborEvent::Confirmed { .. } => confirmed += 1,
                    NeighborEvent::Missed { .. } => missed = true,
                    _ => {}
                }
            }
        }
        assert_eq!(confirmed, MAX_STALE_SNAPSHOTS);
        assert!(missed, "Stale-only presence must lapse");
        // A fresh row restores it immediately.
        assert!(matches!(
            tracker
                .observe(vec![row(NeighborReachability::Reachable)], at())
                .unwrap()
                .as_slice(),
            [NeighborEvent::Confirmed { .. }]
        ));
    }
}
