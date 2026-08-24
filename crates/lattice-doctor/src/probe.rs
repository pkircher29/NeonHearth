//! Probe transport abstraction.
//!
//! The diagnostic engine expresses every network observation as a typed
//! [`ProbeRequest`] and consumes typed [`ProbeResponse`] values. It never
//! opens a socket itself: the service layer supplies a [`ProbeTransport`]
//! implementation, and tests supply [`FakeProbeTransport`].

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use utoipa::ToSchema;

/// Upper bound on any single probe timeout the engine will request.
pub const MAX_PROBE_TIMEOUT_MS: u32 = 10_000;

/// One network observation the engine asks the transport to perform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProbeRequest {
    /// Collector privilege, capture, and worker health.
    CollectorStatus,
    /// Physical/virtual link state of the named interface.
    LinkStatus { interface: String },
    /// Current IP configuration and lease state of the named interface.
    IpConfig { interface: String },
    /// ARP-probe an address to detect other claimants.
    ArpProbe { interface: String, address: String },
    /// Wireless signal metrics for the named interface.
    WifiMetrics { interface: String },
    /// ICMP echo with an explicit payload size and don't-fragment flag.
    Ping {
        target: String,
        payload_bytes: u16,
        dont_fragment: bool,
    },
    /// Resolve `name` against one specific resolver.
    DnsQuery { resolver: String, name: String },
    /// Read the default-route table.
    RouteTable,
    /// Router management/API health.
    RouterStatus,
    /// TCP reachability of a literal IP endpoint (no DNS involved).
    ReachIp { address: String, port: u16 },
}

/// DHCP lease state reported by an [`ProbeResponse::IpConfig`] probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Static,
    Valid,
    Expired,
    Missing,
}

/// Why a resolver failed to answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsFailureReason {
    Timeout,
    Refused,
    ServFail,
    NoAnswer,
}

/// One default route observed in the route table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RouteEntry {
    pub interface: String,
    pub gateway: String,
    pub is_vpn: bool,
    pub metric: u32,
}

/// Typed result of a probe. Variants correspond to [`ProbeRequest`] kinds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProbeResponse {
    CollectorStatus {
        privileged: bool,
        capture_ok: bool,
        worker_running: bool,
    },
    LinkStatus {
        up: bool,
        speed_mbps: Option<u32>,
    },
    IpConfig {
        address: Option<String>,
        lease: LeaseState,
    },
    ArpProbe {
        responding_macs: Vec<String>,
    },
    WifiMetrics {
        wireless: bool,
        rssi_dbm: Option<i16>,
        retry_percent: Option<f64>,
    },
    PingReply {
        rtt_ms: f64,
    },
    /// The echo was sent and nothing came back (a measurement, not an error).
    PingTimeout,
    /// An ICMP "fragmentation needed" reply: the path signals its MTU.
    FragmentationNeeded {
        next_hop_mtu: u16,
    },
    DnsAnswer {
        addresses: Vec<String>,
        latency_ms: f64,
    },
    DnsFailure {
        reason: DnsFailureReason,
    },
    RouteTable {
        default_routes: Vec<RouteEntry>,
    },
    RouterStatus {
        responsive: bool,
        uptime_seconds: Option<u64>,
    },
    Reachable {
        latency_ms: f64,
    },
    Unreachable,
}

/// Transport-level probe failure (distinct from a negative measurement).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    #[error("probe timed out at the transport layer")]
    Timeout,
    #[error("probe kind is unsupported on this platform")]
    Unsupported,
    #[error("probe transport failed: {0}")]
    Transport(String),
}

/// A request paired with the per-probe timeout the engine grants it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub request: ProbeRequest,
    pub timeout_ms: u32,
}

/// Async transport the engine sends every probe through.
///
/// Implementations must honor `timeout_ms`; the engine itself never blocks on
/// the network.
pub trait ProbeTransport: Send + Sync {
    fn probe(
        &self,
        probe: Probe,
    ) -> impl std::future::Future<Output = Result<ProbeResponse, ProbeError>> + Send;
}

/// In-memory transport for tests: answers from a handler and logs every probe.
pub struct FakeProbeTransport {
    #[allow(clippy::type_complexity)]
    handler: Box<dyn Fn(&ProbeRequest) -> Result<ProbeResponse, ProbeError> + Send + Sync>,
    log: Mutex<Vec<Probe>>,
}

impl std::fmt::Debug for FakeProbeTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeProbeTransport").finish_non_exhaustive()
    }
}

impl FakeProbeTransport {
    pub fn new(
        handler: impl Fn(&ProbeRequest) -> Result<ProbeResponse, ProbeError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            handler: Box::new(handler),
            log: Mutex::new(Vec::new()),
        }
    }

    /// Every probe issued so far, in order.
    pub fn probes(&self) -> Vec<Probe> {
        self.log.lock().expect("fake probe log lock").clone()
    }
}

impl ProbeTransport for FakeProbeTransport {
    async fn probe(&self, probe: Probe) -> Result<ProbeResponse, ProbeError> {
        self.log
            .lock()
            .expect("fake probe log lock")
            .push(probe.clone());
        (self.handler)(&probe.request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_transport_logs_probes_in_order() {
        let fake = FakeProbeTransport::new(|_| Ok(ProbeResponse::PingTimeout));
        let first = Probe {
            request: ProbeRequest::RouteTable,
            timeout_ms: 100,
        };
        let second = Probe {
            request: ProbeRequest::CollectorStatus,
            timeout_ms: 200,
        };
        assert_eq!(
            fake.probe(first.clone()).await,
            Ok(ProbeResponse::PingTimeout)
        );
        assert_eq!(
            fake.probe(second.clone()).await,
            Ok(ProbeResponse::PingTimeout)
        );
        assert_eq!(fake.probes(), vec![first, second]);
    }

    #[tokio::test]
    async fn fake_transport_propagates_handler_errors() {
        let fake = FakeProbeTransport::new(|_| Err(ProbeError::Unsupported));
        let result = fake
            .probe(Probe {
                request: ProbeRequest::RouterStatus,
                timeout_ms: 50,
            })
            .await;
        assert_eq!(result, Err(ProbeError::Unsupported));
    }
}
