//! The production [`HostOs`]: the interface inventory and the portable network
//! calls live here; everything that differs per OS is in `linux.rs`,
//! `windows.rs` or `other.rs`, reached through `platform`.

use super::decide;
use super::model::{
    DefaultRoute, EchoOutcome, EchoRequest, HostOs, Ipv4Lease, LinkInfo, LinkKind, Mac, OsError,
    UdpOutcome,
};
use super::platform;
use async_trait::async_trait;
use lattice_doctor::types::MacAddr;
use lattice_sensor::{InterfaceClass, SystemInterfaceManager};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

/// Largest datagram read back from a resolver.
const MAX_DATAGRAM: usize = 4096;

/// The host this process runs on.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemHost;

fn link_kind(class: InterfaceClass) -> LinkKind {
    match class {
        InterfaceClass::PhysicalWired => LinkKind::Wired,
        InterfaceClass::PhysicalWifi => LinkKind::Wifi,
        InterfaceClass::Loopback => LinkKind::Loopback,
        InterfaceClass::Tailscale | InterfaceClass::VpnTunnel => LinkKind::Tunnel,
        InterfaceClass::Container | InterfaceClass::VirtualMachine => LinkKind::Virtual,
        InterfaceClass::Unknown => LinkKind::Other,
    }
}

/// The interface inventory (names, state, addresses) before per-OS facts.
fn inventory_links() -> Result<Vec<LinkInfo>, OsError> {
    let inventory = SystemInterfaceManager.snapshot().map_err(|error| {
        OsError::failed(format!("the interface inventory is unavailable: {error}"))
    })?;
    Ok(inventory
        .interfaces()
        .map(|interface| {
            let mut ipv4: Vec<Ipv4Addr> = interface
                .addresses
                .iter()
                .filter_map(|address| match address.ip {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                })
                .collect();
            ipv4.sort();
            ipv4.dedup();
            LinkInfo {
                index: interface.id.get(),
                name: interface.name.clone(),
                up: interface.up,
                kind: link_kind(interface.class),
                speed_mbps: None,
                mtu: None,
                mac: None,
                ipv4,
            }
        })
        .collect())
}

/// All interfaces with the facts the OS adds on top of the inventory. Facts
/// the OS does not give stay `None`; nothing is guessed.
pub fn system_links() -> Result<Vec<LinkInfo>, OsError> {
    let mut links = inventory_links()?;
    platform::enrich_links(&mut links);
    Ok(links)
}

/// The IPv4 default routes of this machine.
pub fn system_default_routes() -> Result<Vec<DefaultRoute>, OsError> {
    let links = system_links()?;
    platform::default_routes(&links)
}

/// The hardware addresses of this machine's interfaces. The engine uses them
/// to tell "another host claims my address" from "my own reply".
pub fn system_local_macs() -> Vec<MacAddr> {
    let Ok(links) = system_links() else {
        return Vec::new();
    };
    let mut macs: Vec<MacAddr> = links
        .iter()
        .filter_map(|link| link.mac)
        .filter_map(|mac| decide::mac_string(mac).parse().ok())
        .collect();
    macs.sort();
    macs.dedup();
    macs
}

/// `(interface, gateway)` of the best IPv4 default route that has a real next
/// hop, for the Doctor's initial settings.
#[cfg(windows)]
pub fn system_default_gateway() -> Option<(String, String)> {
    let routes = system_default_routes().ok()?;
    let usable: Vec<DefaultRoute> = routes
        .into_iter()
        .filter(|route| !route.gateway.is_unspecified())
        .collect();
    let best = decide::primary_route(&usable)?;
    Some((best.interface.clone(), best.gateway.to_string()))
}

/// The DNS servers the OS is configured with.
#[cfg(windows)]
pub fn system_resolvers() -> Vec<String> {
    platform::dns_servers()
}

/// The MTU of the interface that owns the best default route, as a stand-in
/// when the OS says a packet was too big without saying what fits.
fn local_path_mtu() -> Option<u16> {
    let links = system_links().ok()?;
    let routes = platform::default_routes(&links).ok()?;
    let primary = decide::primary_route(&routes)?;
    let link = links.iter().find(|link| link.name == primary.interface)?;
    link.mtu.and_then(|mtu| u16::try_from(mtu).ok())
}

#[async_trait]
impl HostOs for SystemHost {
    fn links(&self) -> Result<Vec<LinkInfo>, OsError> {
        system_links()
    }

    fn default_routes(&self) -> Result<Vec<DefaultRoute>, OsError> {
        system_default_routes()
    }

    async fn ipv4_leases(&self, link: &LinkInfo) -> Result<Vec<Ipv4Lease>, OsError> {
        platform::ipv4_leases(link.index).await
    }

    fn wifi_rssi_dbm(&self, link: &LinkInfo) -> Result<i16, OsError> {
        platform::wifi_rssi_dbm(link)
    }

    async fn echo(&self, request: EchoRequest) -> Result<EchoOutcome, OsError> {
        let outcome = platform::echo(request).await?;
        Ok(match outcome {
            EchoOutcome::FragmentationNeeded { next_hop_mtu: None } => {
                EchoOutcome::FragmentationNeeded {
                    next_hop_mtu: local_path_mtu(),
                }
            }
            other => other,
        })
    }

    async fn arp_probe(
        &self,
        link: &LinkInfo,
        address: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Vec<Mac>, OsError> {
        platform::arp_probe(link, address, timeout).await
    }

    async fn udp_exchange(
        &self,
        server: SocketAddr,
        query: &[u8],
        timeout: Duration,
    ) -> Result<UdpOutcome, OsError> {
        let local = match server {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(local)
            .await
            .map_err(|error| OsError::failed(format!("could not open a UDP socket: {error}")))?;
        // A connected socket only accepts datagrams from the resolver itself.
        socket
            .connect(server)
            .await
            .map_err(|error| OsError::failed(format!("could not reach the resolver: {error}")))?;
        socket.send(query).await.map_err(|error| {
            OsError::failed(format!("the DNS query could not be sent: {error}"))
        })?;
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        match tokio::time::timeout(timeout, socket.recv(&mut buffer)).await {
            Err(_elapsed) => Ok(UdpOutcome::NoReply),
            Ok(Ok(length)) => {
                buffer.truncate(length);
                Ok(UdpOutcome::Reply(buffer))
            }
            // ICMP port-unreachable surfaces as a refused connection on a
            // connected UDP socket.
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                Ok(UdpOutcome::PortUnreachable)
            }
            Ok(Err(error)) => Err(OsError::failed(format!(
                "reading the DNS reply failed: {error}"
            ))),
        }
    }

    async fn tcp_connect(
        &self,
        address: SocketAddr,
        timeout: Duration,
    ) -> Result<(), std::io::Error> {
        match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
            Ok(Ok(_stream)) => Ok(()),
            Ok(Err(error)) => Err(error),
            Err(_elapsed) => Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_classes_map_to_link_kinds() {
        for (class, kind) in [
            (InterfaceClass::PhysicalWired, LinkKind::Wired),
            (InterfaceClass::PhysicalWifi, LinkKind::Wifi),
            (InterfaceClass::Loopback, LinkKind::Loopback),
            (InterfaceClass::Tailscale, LinkKind::Tunnel),
            (InterfaceClass::VpnTunnel, LinkKind::Tunnel),
            (InterfaceClass::Container, LinkKind::Virtual),
            (InterfaceClass::VirtualMachine, LinkKind::Virtual),
            (InterfaceClass::Unknown, LinkKind::Other),
        ] {
            assert_eq!(link_kind(class), kind);
        }
    }
}
