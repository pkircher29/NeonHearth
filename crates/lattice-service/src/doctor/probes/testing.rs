//! Test doubles for [`HostOs`]: a scripted host that returns fixtures and
//! logs what reached it, and one that never answers. Compiled for tests only;
//! nothing here touches the real network.

use super::dns;
use super::model::{
    DefaultRoute, EchoOutcome, EchoRequest, HostOs, Ipv4Lease, LinkInfo, LinkKind, Mac, OsError,
    UdpOutcome,
};
use async_trait::async_trait;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

/// How the scripted resolver behaves.
#[derive(Clone, Copy, Debug)]
pub enum DnsScript {
    /// `example.com A 93.184.216.34`.
    Answer,
    /// A reply with this rcode and no answers.
    Rcode(u8),
    /// A good reply for the wrong transaction id.
    WrongTransaction,
    NoReply,
    PortUnreachable,
}

/// A host whose every answer is a fixture. The defaults describe a healthy
/// wired machine: `eth0`, 192.168.1.10/24 via 192.168.1.1.
pub struct ScriptedHost {
    pub links: Vec<LinkInfo>,
    pub routes: Vec<DefaultRoute>,
    pub leases: Vec<Ipv4Lease>,
    pub wifi: Result<i16, OsError>,
    pub echo_outcome: EchoOutcome,
    pub arp_macs: Vec<Mac>,
    pub dns: DnsScript,
    /// When set, `tcp_connect` fails with this error kind.
    pub tcp_error: Option<std::io::ErrorKind>,
    /// Every echo that reached the OS.
    pub echoes: Mutex<Vec<EchoRequest>>,
    /// Every TCP endpoint that was dialed.
    pub dials: Mutex<Vec<SocketAddr>>,
    /// Every resolver that was sent a query.
    pub exchanges: Mutex<Vec<SocketAddr>>,
}

impl Default for ScriptedHost {
    fn default() -> Self {
        Self {
            links: vec![LinkInfo {
                index: 2,
                name: "eth0".to_owned(),
                up: true,
                kind: LinkKind::Wired,
                speed_mbps: Some(1000),
                mtu: Some(1500),
                mac: Some([0x02, 0, 0, 0, 0, 0x01]),
                ipv4: vec![Ipv4Addr::new(192, 168, 1, 10)],
            }],
            routes: vec![DefaultRoute {
                interface: "eth0".to_owned(),
                gateway: Ipv4Addr::new(192, 168, 1, 1),
                metric: 100,
            }],
            leases: vec![Ipv4Lease {
                address: Ipv4Addr::new(192, 168, 1, 10),
                valid_seconds: 3600,
                permanent: false,
            }],
            wifi: Err(OsError::Unsupported("not scripted")),
            echo_outcome: EchoOutcome::Reply { rtt_ms: 1.0 },
            arp_macs: Vec::new(),
            dns: DnsScript::Answer,
            tcp_error: None,
            echoes: Mutex::new(Vec::new()),
            dials: Mutex::new(Vec::new()),
            exchanges: Mutex::new(Vec::new()),
        }
    }
}

/// A well-formed reply to `query` for the scripted behavior.
fn script_reply(script: DnsScript, query: &[u8]) -> UdpOutcome {
    let mut message = query.to_vec();
    message[2] = 0x81;
    message[3] = 0x80;
    match script {
        DnsScript::NoReply => return UdpOutcome::NoReply,
        DnsScript::PortUnreachable => return UdpOutcome::PortUnreachable,
        DnsScript::Rcode(rcode) => message[3] |= rcode,
        DnsScript::WrongTransaction => message[1] = message[1].wrapping_add(1),
        DnsScript::Answer => {
            message[6..8].copy_from_slice(&1u16.to_be_bytes());
            message.extend_from_slice(&[
                0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34,
            ]);
        }
    }
    UdpOutcome::Reply(message)
}

#[async_trait]
impl HostOs for ScriptedHost {
    fn links(&self) -> Result<Vec<LinkInfo>, OsError> {
        Ok(self.links.clone())
    }

    fn default_routes(&self) -> Result<Vec<DefaultRoute>, OsError> {
        Ok(self.routes.clone())
    }

    async fn ipv4_leases(&self, _link: &LinkInfo) -> Result<Vec<Ipv4Lease>, OsError> {
        Ok(self.leases.clone())
    }

    fn wifi_rssi_dbm(&self, _link: &LinkInfo) -> Result<i16, OsError> {
        self.wifi.clone()
    }

    async fn echo(&self, request: EchoRequest) -> Result<EchoOutcome, OsError> {
        self.echoes.lock().unwrap().push(request);
        Ok(self.echo_outcome)
    }

    async fn arp_probe(
        &self,
        _link: &LinkInfo,
        _address: Ipv4Addr,
        _timeout: Duration,
    ) -> Result<Vec<Mac>, OsError> {
        Ok(self.arp_macs.clone())
    }

    async fn udp_exchange(
        &self,
        server: SocketAddr,
        query: &[u8],
        _timeout: Duration,
    ) -> Result<UdpOutcome, OsError> {
        self.exchanges.lock().unwrap().push(server);
        // The query must be one the codec would accept.
        assert!(dns::parse_reply(query, u16::from_be_bytes([query[0], query[1]])).is_err());
        Ok(script_reply(self.dns, query))
    }

    async fn tcp_connect(
        &self,
        address: SocketAddr,
        _timeout: Duration,
    ) -> Result<(), std::io::Error> {
        self.dials.lock().unwrap().push(address);
        match self.tcp_error {
            Some(kind) => Err(std::io::Error::from(kind)),
            None => Ok(()),
        }
    }
}

/// A host whose network never answers: every call that waits on the OS
/// pends forever. Synchronous facts still come from the defaults.
#[derive(Default)]
pub struct NeverHost {
    facts: ScriptedHost,
}

#[async_trait]
impl HostOs for NeverHost {
    fn links(&self) -> Result<Vec<LinkInfo>, OsError> {
        self.facts.links()
    }

    fn default_routes(&self) -> Result<Vec<DefaultRoute>, OsError> {
        self.facts.default_routes()
    }

    async fn ipv4_leases(&self, _link: &LinkInfo) -> Result<Vec<Ipv4Lease>, OsError> {
        std::future::pending().await
    }

    fn wifi_rssi_dbm(&self, link: &LinkInfo) -> Result<i16, OsError> {
        self.facts.wifi_rssi_dbm(link)
    }

    async fn echo(&self, _request: EchoRequest) -> Result<EchoOutcome, OsError> {
        std::future::pending().await
    }

    async fn arp_probe(
        &self,
        _link: &LinkInfo,
        _address: Ipv4Addr,
        _timeout: Duration,
    ) -> Result<Vec<Mac>, OsError> {
        std::future::pending().await
    }

    async fn udp_exchange(
        &self,
        _server: SocketAddr,
        _query: &[u8],
        _timeout: Duration,
    ) -> Result<UdpOutcome, OsError> {
        std::future::pending().await
    }

    async fn tcp_connect(
        &self,
        _address: SocketAddr,
        _timeout: Duration,
    ) -> Result<(), std::io::Error> {
        std::future::pending().await
    }
}
