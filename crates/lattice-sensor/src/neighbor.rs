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
    Transport,
    #[error("malformed neighbor message")]
    Malformed,
}

#[derive(Clone, Debug)]
pub struct NeighborSnapshotConfig {
    pub max_rows: usize,
    pub allowed_interfaces: BTreeSet<InterfaceId>,
    max_raw_messages: usize,
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
        })
    }

    pub fn max_raw_messages(&self) -> usize {
        self.max_raw_messages
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
fn decode_linux_message(
    config: &NeighborSnapshotConfig,
    message: netlink_packet_route::neighbour::NeighbourMessage,
) -> Result<Option<NeighborRow>, NeighborError> {
    use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};

    // Kernel ifindex 0 is not a usable interface. Treat it exactly like an
    // out-of-scope message rather than letting it enter the allowlist domain.
    if message.header.ifindex == 0 {
        return Ok(None);
    }
    let interface = InterfaceId::new(message.header.ifindex);
    if !config.allowed_interfaces.contains(&interface) {
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
                if value.len() != 6 {
                    return Ok(None);
                }
                let mut bytes = [0; 6];
                bytes.copy_from_slice(&value);
                let Ok(address) = LinkAddress::try_from(bytes) else {
                    return Ok(None);
                };
                link_address = Some(address);
            }
            _ => {}
        }
    }
    let (Some(ip), Some(link_address)) = (ip, link_address) else {
        return Ok(None);
    };
    if !valid_ip(ip) {
        return Ok(None);
    }
    Ok(Some(NeighborRow::new(
        interface,
        ip,
        link_address,
        map_kernel_state(message.header.state),
    )?))
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
    let mut rows = Vec::new();
    for message in messages {
        raw_count = raw_count.checked_add(1).ok_or(NeighborError::Capacity)?;
        if raw_count > config.max_raw_messages() {
            return Err(NeighborError::Capacity);
        }
        if let Some(row) = decode_linux_message(config, message)? {
            rows.push(row);
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
    if rows.len() > config.max_rows {
        return Err(NeighborError::Capacity);
    }
    Ok(rows)
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
                    return Err(NeighborError::Capacity);
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
        assert!(
            normalize_linux_messages(&snapshot_config(16), [invalid_length, multicast_link])
                .unwrap()
                .is_empty()
        );
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
        assert_eq!(rows.len(), 2);
        assert!(rows.windows(2).all(|pair| pair[0].ip() <= pair[1].ip()));
        assert_eq!(
            normalize_linux_messages(
                &config,
                std::iter::repeat_n(first, config.max_raw_messages() + 1)
            ),
            Err(NeighborError::Capacity)
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
}
