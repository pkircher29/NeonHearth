//! Bounded, directly connected IPv4 discovery. Never derives targets from remote input.
use lattice_sensor::{InterfaceInventory, InterfaceOverride, SystemInterfaceManager};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::Ipv4Addr};

pub const MAX_TARGETS: usize = 1024;
#[derive(Clone, Debug)]
pub struct Target {
    pub interface: u32,
    pub source: Ipv4Addr,
    pub ip: Ipv4Addr,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sighting {
    pub interface: u32,
    pub ip: String,
    pub mac: String,
}
#[derive(Default)]
pub struct Plan {
    pub targets: Vec<Target>,
    pub skipped: usize,
}

pub fn plan(inventory: &InterfaceInventory) -> Plan {
    let mut out = Plan::default();
    let own: BTreeSet<_> = inventory
        .interfaces()
        .flat_map(|i| i.addresses.iter().map(|a| a.ip))
        .collect();
    let mut visited = BTreeSet::new();
    for interface in inventory
        .interfaces()
        .filter(|i| i.discovery_eligible(InterfaceOverride::Default))
    {
        for address in &interface.addresses {
            let std::net::IpAddr::V4(source) = address.ip else {
                continue;
            };
            if !source.is_private() || !(22..=30).contains(&address.prefix) {
                out.skipped += 1;
                continue;
            }
            let mask = u32::MAX << (32 - address.prefix);
            let base = u32::from(source) & mask;
            if !visited.insert((interface.id.get(), base, address.prefix)) {
                continue;
            }
            let count = (!mask - 1) as usize;
            if out.targets.len() + count > MAX_TARGETS {
                out.skipped += 1;
                continue;
            }
            for host in 1..!mask {
                let ip = Ipv4Addr::from(base + host);
                if !own.contains(&ip.into()) {
                    out.targets.push(Target {
                        interface: interface.id.get(),
                        source,
                        ip,
                    });
                }
            }
        }
    }
    out
}

pub fn local_target(ip: Ipv4Addr) -> Option<Target> {
    let inventory = SystemInterfaceManager.snapshot().ok()?;
    if !ip.is_private()
        || inventory
            .interfaces()
            .any(|i| i.addresses.iter().any(|a| a.ip == ip))
    {
        return None;
    }
    for i in inventory
        .interfaces()
        .filter(|i| i.discovery_eligible(InterfaceOverride::Default))
    {
        for a in &i.addresses {
            let std::net::IpAddr::V4(source) = a.ip else {
                continue;
            };
            if !source.is_private() || !(8..=30).contains(&a.prefix) {
                continue;
            }
            let mask = u32::MAX << (32 - a.prefix);
            let host = u32::from(ip) & !mask;
            if u32::from(source) & mask == u32::from(ip) & mask && host != 0 && host != !mask {
                return Some(Target {
                    interface: i.id.get(),
                    source,
                    ip,
                });
            }
        }
    }
    None
}

/// Targets probed concurrently per batch. A batch shares one neighbor-table snapshot on Linux.
#[cfg(windows)]
pub const BATCH: usize = 16;
#[cfg(not(windows))]
pub const BATCH: usize = 64;

/// Probes one batch of targets from a plan that was validated once for the whole sweep.
/// `names` maps interface index to adapter name (used to pin sockets on Linux).
pub async fn probe_batch(
    batch: &[Target],
    names: &std::collections::BTreeMap<u32, String>,
) -> Vec<Result<Option<Sighting>, ()>> {
    probe_batch_native(batch, names).await
}

#[cfg(windows)]
async fn probe_batch_native(
    batch: &[Target],
    _names: &std::collections::BTreeMap<u32, String>,
) -> Vec<Result<Option<Sighting>, ()>> {
    futures_util::future::join_all(batch.iter().cloned().map(probe_native)).await
}

#[cfg(windows)]
async fn probe_native(target: Target) -> Result<Option<Sighting>, ()> {
    tokio::task::spawn_blocking(move || {
        use windows_sys::Win32::{
            NetworkManagement::IpHelper::{MIB_IPNET_ROW2, ResolveIpNetEntry2},
            Networking::WinSock::{AF_INET, SOCKADDR_INET},
        };
        // Both structures are owned until the synchronous call returns. The source
        // selects the adapter; the explicit index prevents an unscoped ARP request.
        let mut row: MIB_IPNET_ROW2 = unsafe { std::mem::zeroed() };
        let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        row.InterfaceIndex = target.interface;
        row.Address.Ipv4.sin_family = AF_INET;
        row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(target.ip.octets());
        source.Ipv4.sin_family = AF_INET;
        source.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(target.source.octets());
        let result = unsafe { ResolveIpNetEntry2(&mut row, &source) };
        // ERROR_BAD_NET_NAME / ERROR_TIMEOUT mean no neighbor response, not proof of departure.
        if matches!(result, 67 | 1460) {
            return Ok(None);
        }
        if result != 0 {
            return Err(());
        }
        if row.InterfaceIndex != target.interface || row.PhysicalAddressLength != 6 {
            return Err(());
        }
        let mac = lattice_sensor::neighbor::LinkAddress::try_from(
            <[u8; 6]>::try_from(&row.PhysicalAddress[..6]).map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        Ok(Some(Sighting {
            interface: target.interface,
            ip: target.ip.to_string(),
            mac: mac.to_string().to_ascii_uppercase(),
        }))
    })
    .await
    .map_err(|_| ())?
}

#[cfg(target_os = "linux")]
async fn probe_batch_native(
    batch: &[Target],
    names: &std::collections::BTreeMap<u32, String>,
) -> Vec<Result<Option<Sighting>, ()>> {
    use lattice_sensor::{
        InterfaceId,
        active::pin_socket_to_interface,
        neighbor::{
            NeighborReachability, NeighborSnapshotConfig, NeighborSnapshotSource,
            SystemNeighborSnapshotSource,
        },
    };
    // A datagram to the discard port makes the kernel resolve the neighbor (ARP) without
    // spawning a process per target. Nothing is expected back; only the neighbor entry matters.
    let mut triggered = vec![false; batch.len()];
    for (slot, target) in triggered.iter_mut().zip(batch) {
        if !names.contains_key(&target.interface) {
            continue;
        }
        let Ok(socket) = tokio::net::UdpSocket::bind((target.source, 0)).await else {
            continue;
        };
        let binding = lattice_sensor::AuthorizedBinding {
            source: target.source.into(),
            interface_index: target.interface,
            target: target.ip.into(),
        };
        if pin_socket_to_interface(&socket, binding).is_err() {
            continue;
        }
        let _ = socket.send_to(&[0], (target.ip, 9)).await;
        *slot = true;
    }
    // One neighbor snapshot for the whole batch, after the kernel had time to resolve.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let interfaces: std::collections::BTreeSet<_> = batch
        .iter()
        .map(|t| InterfaceId::new(t.interface))
        .collect();
    let rows = match NeighborSnapshotConfig::new(4096, interfaces) {
        Ok(config) => SystemNeighborSnapshotSource::new(config).snapshot().await,
        Err(_) => Err(lattice_sensor::neighbor::NeighborError::InvalidConfig),
    };
    let Ok(rows) = rows else {
        return batch.iter().map(|_| Err(())).collect();
    };
    batch
        .iter()
        .zip(triggered)
        .map(|(target, triggered)| {
            if !triggered {
                return Err(());
            }
            Ok(rows
                .iter()
                .find(|r| {
                    r.interface().get() == target.interface
                        && r.ip() == std::net::IpAddr::V4(target.ip)
                        && r.reachability() == NeighborReachability::Reachable
                })
                .map(|r| Sighting {
                    interface: target.interface,
                    ip: target.ip.to_string(),
                    mac: r.link_address().to_string().to_ascii_uppercase(),
                }))
        })
        .collect()
}

#[cfg(not(any(windows, target_os = "linux")))]
async fn probe_batch_native(
    batch: &[Target],
    _: &std::collections::BTreeMap<u32, String>,
) -> Vec<Result<Option<Sighting>, ()>> {
    batch.iter().map(|_| Err(())).collect()
}
