//! Bounded, directly connected IPv4 discovery. Never derives targets from remote input.
#[cfg(target_os = "linux")]
use lattice_sensor::InterfaceId;
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

pub async fn probe(target: Target) -> Result<Option<Sighting>, ()> {
    // Revalidate adapter identity and source immediately before the OS operation.
    let current = SystemInterfaceManager.snapshot().map_err(|_| ())?;
    if !plan(&current)
        .targets
        .iter()
        .any(|t| t.interface == target.interface && t.source == target.source && t.ip == target.ip)
    {
        return Err(());
    }
    probe_native(target).await
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
async fn probe_native(target: Target) -> Result<Option<Sighting>, ()> {
    use lattice_sensor::neighbor::{
        NeighborReachability, NeighborSnapshotConfig, NeighborSnapshotSource,
        SystemNeighborSnapshotSource,
    };
    let inventory = SystemInterfaceManager.snapshot().map_err(|_| ())?;
    let interface = inventory
        .interfaces()
        .find(|i| i.id.get() == target.interface)
        .ok_or(())?;
    let executable = ["/usr/bin/ping", "/bin/ping"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
        .ok_or(())?;
    // OS ping binds the named adapter, has a one-second deadline and never invokes a shell.
    let status = tokio::process::Command::new(executable)
        .args([
            "-n",
            "-c",
            "1",
            "-W",
            "1",
            "-w",
            "1",
            "-I",
            &interface.name,
            &target.ip.to_string(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .status()
        .await
        .map_err(|_| ())?;
    if !matches!(status.code(), Some(0 | 1)) {
        return Err(());
    }
    let config =
        NeighborSnapshotConfig::new(4096, [InterfaceId::new(target.interface)]).map_err(|_| ())?;
    let rows = SystemNeighborSnapshotSource::new(config)
        .snapshot()
        .await
        .map_err(|_| ())?;
    Ok(rows
        .into_iter()
        .find(|r| {
            r.ip() == target.ip
                && (status.success() || r.reachability() == NeighborReachability::Reachable)
        })
        .map(|r| Sighting {
            interface: target.interface,
            ip: target.ip.to_string(),
            mac: r.link_address().to_string().to_ascii_uppercase(),
        }))
}
#[cfg(not(any(windows, target_os = "linux")))]
async fn probe_native(_: Target) -> Result<Option<Sighting>, ()> {
    Err(())
}
