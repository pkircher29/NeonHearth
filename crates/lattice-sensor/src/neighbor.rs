use crate::InterfaceId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
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
    Source,
}

#[derive(Clone, Debug)]
pub struct NeighborSnapshotConfig {
    pub max_rows: usize,
    pub allowed_interfaces: BTreeSet<InterfaceId>,
}
impl NeighborSnapshotConfig {
    pub fn new<I>(max_rows: usize, allowed_interfaces: I) -> Result<Self, NeighborError>
    where
        I: IntoIterator<Item = InterfaceId>,
    {
        let allowed_interfaces: BTreeSet<_> = allowed_interfaces.into_iter().collect();
        if max_rows == 0
            || allowed_interfaces.is_empty()
            || allowed_interfaces.iter().any(|id| id.get() == 0)
        {
            return Err(NeighborError::InvalidConfig);
        }
        Ok(Self {
            max_rows,
            allowed_interfaces,
        })
    }
}

#[async_trait]
pub trait NeighborSnapshotSource: Send + Sync {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError>;
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
#[cfg(target_os = "linux")]
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
#[async_trait]
impl NeighborSnapshotSource for SystemNeighborSnapshotSource {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError> {
        use futures_util::TryStreamExt;
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|_| NeighborError::Source)?;
        tokio::spawn(connection);
        let mut rows = Vec::new();
        for family in [
            netlink_packet_route::AddressFamily::Inet,
            netlink_packet_route::AddressFamily::Inet6,
        ] {
            let mut stream = handle
                .neighbours()
                .get()
                .set_address_family(family)
                .execute();
            while let Some(message) = stream.try_next().await.map_err(|_| NeighborError::Source)? {
                let interface = InterfaceId::new(message.header.ifindex);
                if !self.config.allowed_interfaces.contains(&interface) {
                    continue;
                }
                let mut ip = None;
                let mut ll = None;
                for attr in message.attributes {
                    match attr {
                        netlink_packet_route::neighbour::NeighbourAttribute::Destination(a) => {
                            if ip.is_some() {
                                return Err(NeighborError::Source);
                            }
                            ip = Some(match a {
                                netlink_packet_route::neighbour::NeighbourAddress::Inet(v) => {
                                    IpAddr::V4(v)
                                }
                                netlink_packet_route::neighbour::NeighbourAddress::Inet6(v) => {
                                    IpAddr::V6(v)
                                }
                                _ => return Err(NeighborError::Source),
                            });
                        }
                        netlink_packet_route::neighbour::NeighbourAttribute::LinkLayerAddress(
                            v,
                        ) => {
                            if ll.is_some() || v.len() != 6 {
                                return Err(NeighborError::Source);
                            }
                            let mut x = [0; 6];
                            x.copy_from_slice(&v);
                            ll = Some(LinkAddress::try_from(x)?);
                        }
                        _ => {}
                    }
                }
                let (Some(ip), Some(ll)) = (ip, ll) else {
                    continue;
                };
                if !valid_ip(ip) {
                    continue;
                }
                rows.push(NeighborRow::new(
                    interface,
                    ip,
                    ll,
                    map_kernel_state(message.header.state),
                )?);
                if rows.len() > self.config.max_rows {
                    return Err(NeighborError::Capacity);
                }
            }
        }
        rows.sort_by(|a, b| {
            a.interface
                .cmp(&b.interface)
                .then(a.link_address.cmp(&b.link_address))
                .then(a.ip.cmp(&b.ip))
                .then(reachability_rank(a.reachability).cmp(&reachability_rank(b.reachability)))
        });
        rows.dedup();
        Ok(rows)
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
            .finish()
    }
}

#[derive(Clone)]
struct State {
    device: NeighborDevice,
    missed: usize,
}
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
        if rows.len() > self.cfg.max_rows {
            return Err(NeighborError::Capacity);
        }
        let mut grouped: BTreeMap<(InterfaceId, LinkAddress), Vec<IpAddr>> = BTreeMap::new();
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
            grouped
                .entry((r.interface, r.link_address))
                .or_default()
                .push(r.ip);
        }
        if grouped.len() > self.cfg.max_devices {
            return Err(NeighborError::Capacity);
        }
        let present: std::collections::BTreeSet<_> = grouped.keys().copied().collect();
        let mut next = self.states.clone();
        let new_count = grouped.keys().filter(|key| !next.contains_key(key)).count();
        if next
            .len()
            .checked_add(new_count)
            .is_none_or(|n| n > self.cfg.max_devices)
        {
            return Err(NeighborError::Capacity);
        }
        // Events are stable: present devices are key-sorted first, then departures key-sorted.
        let mut events = Vec::new();
        for (key, mut addrs) in grouped {
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
            [NeighborEvent::Departed { .. }]
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
                .is_empty()
        );
        assert!(matches!(
            tracker
                .observe(vec![], Utc.timestamp_opt(3, 0).unwrap())
                .unwrap()
                .as_slice(),
            [NeighborEvent::Departed { .. }]
        ));
    }
}
