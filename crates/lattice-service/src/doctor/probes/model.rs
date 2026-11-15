//! OS-neutral data model and the single OS seam of the Doctor's real probes.
//!
//! Everything platform specific sits behind [`HostOs`]. The decision code in
//! `decide.rs` and the transport in `transport.rs` only ever see these types,
//! so every interpretation rule is testable with fixtures and a fake host.

use async_trait::async_trait;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

/// A 48-bit link-layer address.
pub type Mac = [u8; 6];

/// What kind of link an interface is, as far as the Doctor cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    Wired,
    Wifi,
    /// VPN, WireGuard, Tailscale, PPP and similar tunnels.
    Tunnel,
    /// Hypervisor and container bridges.
    Virtual,
    Loopback,
    Other,
}

/// One network interface with the link facts the OS exposes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    pub index: u32,
    pub name: String,
    /// Carrier/operational state, not merely "administratively enabled".
    pub up: bool,
    pub kind: LinkKind,
    pub speed_mbps: Option<u32>,
    pub mtu: Option<u32>,
    pub mac: Option<Mac>,
    /// IPv4 addresses configured on the interface.
    pub ipv4: Vec<Ipv4Addr>,
}

/// One IPv4 default route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultRoute {
    /// Name of the interface that owns the route.
    pub interface: String,
    /// Next hop; `0.0.0.0` for an on-link default route (typical for tunnels).
    pub gateway: Ipv4Addr,
    /// Lowest metric wins. Windows adds the interface metric to the route
    /// metric before it gets here.
    pub metric: u32,
}

/// One IPv4 address with the lifetime facts the OS keeps for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Lease {
    pub address: Ipv4Addr,
    /// Seconds the address stays valid; `u32::MAX` means forever.
    pub valid_seconds: u32,
    /// The OS marks the address as manually configured.
    pub permanent: bool,
}

/// One ICMP echo to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EchoRequest {
    pub target: Ipv4Addr,
    pub payload_bytes: u16,
    pub dont_fragment: bool,
    pub timeout: Duration,
}

/// What came of one ICMP echo.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EchoOutcome {
    Reply {
        rtt_ms: f64,
    },
    /// The echo was sent and nothing usable came back in time.
    Timeout,
    /// The local stack or a router said the packet was too big for the path
    /// with the don't-fragment bit set. The MTU is `None` when the OS does not
    /// report it.
    FragmentationNeeded {
        next_hop_mtu: Option<u16>,
    },
}

/// What came of one UDP request/response exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpOutcome {
    Reply(Vec<u8>),
    NoReply,
    /// The OS reported ICMP port-unreachable for the connected socket.
    PortUnreachable,
}

/// A failure of an OS call, or a probe the platform cannot perform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OsError {
    /// The platform (or this build of it) cannot measure this. The reason is
    /// for logs; the Doctor labels the check "not available".
    Unsupported(&'static str),
    /// An OS call failed. The text reaches the owner in the report.
    Failed(String),
}

impl OsError {
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }
}

/// Every OS-dependent operation the probes need.
///
/// The production implementation is [`super::SystemHost`]. Tests substitute a
/// fake that returns fixtures, or one that never answers, so no test ever
/// touches the real network or needs privileges.
#[async_trait]
pub trait HostOs: Send + Sync {
    /// All interfaces with link facts. Fast, read-only.
    fn links(&self) -> Result<Vec<LinkInfo>, OsError>;

    /// All IPv4 default routes.
    fn default_routes(&self) -> Result<Vec<DefaultRoute>, OsError>;

    /// The IPv4 addresses of `link` with their lifetime facts.
    async fn ipv4_leases(&self, link: &LinkInfo) -> Result<Vec<Ipv4Lease>, OsError>;

    /// Signal strength of a wireless `link` in dBm. `Unsupported` when the OS
    /// (or the driver) does not report it in dBm.
    fn wifi_rssi_dbm(&self, link: &LinkInfo) -> Result<i16, OsError>;

    /// One ICMP echo. Honors `request.timeout`.
    async fn echo(&self, request: EchoRequest) -> Result<EchoOutcome, OsError>;

    /// ARP-probe `address` (configured on `link`) and return the MACs of every
    /// other claimant that answered within `timeout`.
    async fn arp_probe(
        &self,
        link: &LinkInfo,
        address: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Vec<Mac>, OsError>;

    /// Send `query` to `server` over UDP and wait for one datagram back.
    async fn udp_exchange(
        &self,
        server: SocketAddr,
        query: &[u8],
        timeout: Duration,
    ) -> Result<UdpOutcome, OsError>;

    /// Open (and immediately drop) a TCP connection. Never reads or writes.
    async fn tcp_connect(&self, address: SocketAddr, timeout: Duration)
    -> Result<(), std::io::Error>;
}

/// Fills `buffer` from the OS random source.
pub fn random_bytes(buffer: &mut [u8]) -> Result<(), OsError> {
    getrandom::fill(buffer).map_err(|_| OsError::failed("the OS random source is unavailable"))
}

/// A random 16-bit value (DNS transaction ids, ICMP identifiers).
pub fn random_u16() -> Result<u16, OsError> {
    let mut bytes = [0u8; 2];
    random_bytes(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}
