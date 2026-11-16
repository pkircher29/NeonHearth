//! The production [`ProbeTransport`]: answers every network [`ProbeRequest`]
//! from [`HostOs`] facts, or says honestly that it cannot.
//!
//! Consent and target policy are NOT decided here. The one place that refuses
//! unconfigured targets and, without the owner's confirmation, anything
//! outside the private network is `GatedProbes` in `doctor.rs`, which wraps
//! this transport. Keeping the rule in one place means no probe added here can
//! forget it.

use super::decide;
use super::dns;
use super::model::{EchoRequest, HostOs, LinkInfo, LinkKind, OsError, UdpOutcome, random_u16};
use lattice_doctor::probe::{
    DnsFailureReason, MAX_PROBE_TIMEOUT_MS, Probe, ProbeError, ProbeRequest, ProbeResponse,
    ProbeTransport,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long past its own timeout a probe may run before the transport cuts it
/// off. OS calls honor the timeout themselves; this is the backstop for one
/// that does not. It stays inside the engine's own grace period.
pub const HARD_TIMEOUT_SLACK: Duration = Duration::from_millis(250);
/// Largest echo payload accepted (an IPv4 packet is at most 65535 bytes).
const MAX_ECHO_PAYLOAD: u16 = 65_000;
const DNS_PORT: u16 = 53;

/// Probe transport backed by the host operating system.
pub struct HostProbeTransport {
    os: Arc<dyn HostOs>,
}

impl HostProbeTransport {
    pub fn new(os: Arc<dyn HostOs>) -> Self {
        Self { os }
    }

    /// The transport for this machine.
    pub fn system() -> Self {
        Self::new(Arc::new(super::SystemHost))
    }

    fn link(&self, requested: &str) -> Result<LinkInfo, ProbeError> {
        let links = self.os.links().map_err(map_os_error)?;
        let routes = if requested == decide::PRIMARY_INTERFACE {
            self.os.default_routes().map_err(map_os_error)?
        } else {
            Vec::new()
        };
        decide::resolve_link(&links, &routes, requested)
            .cloned()
            .map_err(map_os_error)
    }

    async fn dns_query(
        &self,
        resolver: &str,
        name: &str,
        budget: Duration,
    ) -> Result<ProbeResponse, ProbeError> {
        let address = parse_ip(resolver, "the resolver")?;
        let id = random_u16().map_err(map_os_error)?;
        let query =
            dns::build_query(id, name).map_err(|error| ProbeError::Transport(error.to_string()))?;
        let started = Instant::now();
        let outcome = self
            .os
            .udp_exchange(SocketAddr::new(address, DNS_PORT), &query, budget)
            .await
            .map_err(map_os_error)?;
        match outcome {
            UdpOutcome::NoReply => Ok(ProbeResponse::DnsFailure {
                reason: DnsFailureReason::Timeout,
            }),
            UdpOutcome::PortUnreachable => Ok(ProbeResponse::DnsFailure {
                reason: DnsFailureReason::Refused,
            }),
            UdpOutcome::Reply(bytes) => {
                let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
                dns::parse_reply(&bytes, id)
                    .map(|reply| dns::reply_response(reply, latency_ms))
                    .map_err(|error| ProbeError::Transport(error.to_string()))
            }
        }
    }

    async fn dispatch(
        &self,
        request: ProbeRequest,
        budget: Duration,
    ) -> Result<ProbeResponse, ProbeError> {
        match request {
            // Answered by the service itself; there is no router API to ask.
            ProbeRequest::CollectorStatus | ProbeRequest::RouterStatus => {
                Err(ProbeError::Unsupported)
            }
            ProbeRequest::LinkStatus { interface } => {
                Ok(decide::link_response(&self.link(&interface)?))
            }
            ProbeRequest::IpConfig { interface } => {
                let link = self.link(&interface)?;
                let leases = self.os.ipv4_leases(&link).await.map_err(map_os_error)?;
                Ok(decide::ip_config_response(&leases))
            }
            ProbeRequest::ArpProbe { interface, address } => {
                let link = self.link(&interface)?;
                let target = decide::arp_target(&link, &address).map_err(map_os_error)?;
                let claimants = self
                    .os
                    .arp_probe(&link, target, budget)
                    .await
                    .map_err(map_os_error)?;
                Ok(ProbeResponse::ArpProbe {
                    responding_macs: claimants.into_iter().map(decide::mac_string).collect(),
                })
            }
            ProbeRequest::WifiMetrics { interface } => {
                let link = self.link(&interface)?;
                if link.kind != LinkKind::Wifi {
                    return Ok(decide::wifi_response(false, None));
                }
                let rssi_dbm = self.os.wifi_rssi_dbm(&link).map_err(map_os_error)?;
                Ok(decide::wifi_response(true, Some(rssi_dbm)))
            }
            ProbeRequest::Ping {
                target,
                payload_bytes,
                dont_fragment,
            } => {
                // Targets are IP literals only: the transport never resolves a
                // name on its own.
                let IpAddr::V4(target) = parse_ip(&target, "the ping target")? else {
                    return Err(ProbeError::Unsupported);
                };
                if payload_bytes > MAX_ECHO_PAYLOAD {
                    return Err(ProbeError::Transport(
                        "the echo payload is larger than an IP packet can carry".to_owned(),
                    ));
                }
                let outcome = self
                    .os
                    .echo(EchoRequest {
                        target,
                        payload_bytes,
                        dont_fragment,
                        timeout: budget,
                    })
                    .await
                    .map_err(map_os_error)?;
                decide::echo_response(outcome)
            }
            ProbeRequest::DnsQuery { resolver, name } => {
                self.dns_query(&resolver, &name, budget).await
            }
            ProbeRequest::RouteTable => {
                let routes = self.os.default_routes().map_err(map_os_error)?;
                let links = self.os.links().map_err(map_os_error)?;
                Ok(decide::route_response(&routes, &links))
            }
            ProbeRequest::ReachIp { address, port } => {
                let address = parse_ip(&address, "the internet probe address")?;
                let started = Instant::now();
                let result = self
                    .os
                    .tcp_connect(SocketAddr::new(address, port), budget)
                    .await;
                decide::reach_response(result, started.elapsed())
            }
        }
    }
}

impl ProbeTransport for HostProbeTransport {
    async fn probe(&self, probe: Probe) -> Result<ProbeResponse, ProbeError> {
        let budget =
            Duration::from_millis(u64::from(probe.timeout_ms.clamp(1, MAX_PROBE_TIMEOUT_MS)));
        match tokio::time::timeout(
            budget + HARD_TIMEOUT_SLACK,
            self.dispatch(probe.request, budget),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(ProbeError::Timeout),
        }
    }
}

fn parse_ip(text: &str, what: &str) -> Result<IpAddr, ProbeError> {
    text.parse()
        .map_err(|_| ProbeError::Transport(format!("{what} must be an IP address")))
}

fn map_os_error(error: OsError) -> ProbeError {
    match error {
        OsError::Unsupported(reason) => {
            tracing::debug!(reason, "doctor probe is unsupported here");
            ProbeError::Unsupported
        }
        OsError::Failed(message) => ProbeError::Transport(message),
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{EchoOutcome, Ipv4Lease};
    use super::super::testing::{DnsScript, NeverHost, ScriptedHost};
    use super::*;
    use lattice_doctor::probe::{LeaseState, RouteEntry};
    use std::io::ErrorKind;
    use std::net::Ipv4Addr;

    fn transport(host: ScriptedHost) -> (HostProbeTransport, Arc<ScriptedHost>) {
        let host = Arc::new(host);
        (HostProbeTransport::new(host.clone()), host)
    }

    async fn ask(
        transport: &HostProbeTransport,
        request: ProbeRequest,
    ) -> Result<ProbeResponse, ProbeError> {
        transport
            .probe(Probe {
                request,
                timeout_ms: 1_000,
            })
            .await
    }

    #[tokio::test]
    async fn link_and_address_probes_answer_from_the_primary_interface() {
        let (transport, _) = transport(ScriptedHost::default());
        assert_eq!(
            ask(
                &transport,
                ProbeRequest::LinkStatus {
                    interface: "primary".to_owned()
                }
            )
            .await,
            Ok(ProbeResponse::LinkStatus {
                up: true,
                speed_mbps: Some(1000)
            })
        );
        assert_eq!(
            ask(
                &transport,
                ProbeRequest::IpConfig {
                    interface: "eth0".to_owned()
                }
            )
            .await,
            Ok(ProbeResponse::IpConfig {
                address: Some("192.168.1.10".to_owned()),
                lease: LeaseState::Valid
            })
        );
        let Err(ProbeError::Transport(message)) = ask(
            &transport,
            ProbeRequest::LinkStatus {
                interface: "missing0".to_owned(),
            },
        )
        .await
        else {
            panic!("an unknown interface must be a transport error");
        };
        assert!(message.contains("missing0"), "{message}");
    }

    #[tokio::test]
    async fn an_apipa_only_interface_reports_its_address_without_a_lease() {
        let host = ScriptedHost {
            leases: vec![Ipv4Lease {
                address: Ipv4Addr::new(169, 254, 7, 7),
                valid_seconds: u32::MAX,
                permanent: false,
            }],
            ..ScriptedHost::default()
        };
        let (transport, _) = transport(host);
        assert_eq!(
            ask(
                &transport,
                ProbeRequest::IpConfig {
                    interface: "eth0".to_owned()
                }
            )
            .await,
            Ok(ProbeResponse::IpConfig {
                address: Some("169.254.7.7".to_owned()),
                lease: LeaseState::Missing
            })
        );
    }

    #[tokio::test]
    async fn the_arp_probe_reports_claimants_but_only_for_configured_addresses() {
        let host = ScriptedHost {
            arp_macs: vec![[0x02, 0, 0, 0, 0, 0x99]],
            ..ScriptedHost::default()
        };
        let (transport, _) = transport(host);
        assert_eq!(
            ask(
                &transport,
                ProbeRequest::ArpProbe {
                    interface: "eth0".to_owned(),
                    address: "192.168.1.10".to_owned()
                }
            )
            .await,
            Ok(ProbeResponse::ArpProbe {
                responding_macs: vec!["02:00:00:00:00:99".to_owned()]
            })
        );
        assert!(matches!(
            ask(
                &transport,
                ProbeRequest::ArpProbe {
                    interface: "eth0".to_owned(),
                    address: "192.168.1.77".to_owned()
                }
            )
            .await,
            Err(ProbeError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn wifi_metrics_distinguish_wired_wireless_and_unmeasurable() {
        let mut host = ScriptedHost::default();
        host.links.push(LinkInfo {
            index: 3,
            name: "wlan0".to_owned(),
            up: true,
            kind: LinkKind::Wifi,
            speed_mbps: None,
            mtu: Some(1500),
            mac: None,
            ipv4: Vec::new(),
        });
        host.wifi = Ok(-58);
        let (transport, _) = transport(host);
        assert_eq!(
            ask(
                &transport,
                ProbeRequest::WifiMetrics {
                    interface: "eth0".to_owned()
                }
            )
            .await,
            Ok(ProbeResponse::WifiMetrics {
                wireless: false,
                rssi_dbm: None,
                retry_percent: None
            })
        );
        assert_eq!(
            ask(
                &transport,
                ProbeRequest::WifiMetrics {
                    interface: "wlan0".to_owned()
                }
            )
            .await,
            Ok(ProbeResponse::WifiMetrics {
                wireless: true,
                rssi_dbm: Some(-58),
                retry_percent: None
            })
        );

        let mut host = ScriptedHost::default();
        host.links[0].kind = LinkKind::Wifi;
        host.wifi = Err(OsError::Unsupported("no signal report"));
        let (transport, _) = self::transport(host);
        assert_eq!(
            ask(
                &transport,
                ProbeRequest::WifiMetrics {
                    interface: "eth0".to_owned()
                }
            )
            .await,
            Err(ProbeError::Unsupported)
        );
    }

    #[tokio::test]
    async fn pings_carry_the_requested_shape_and_never_resolve_names() {
        let host = ScriptedHost {
            echo_outcome: EchoOutcome::Reply { rtt_ms: 0.8 },
            ..ScriptedHost::default()
        };
        let (transport, host) = transport(host);
        assert_eq!(
            ask(
                &transport,
                ProbeRequest::Ping {
                    target: "192.168.1.1".to_owned(),
                    payload_bytes: 1472,
                    dont_fragment: true
                }
            )
            .await,
            Ok(ProbeResponse::PingReply { rtt_ms: 0.8 })
        );
        let sent = host.echoes.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].target, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(sent[0].payload_bytes, 1472);
        assert!(sent[0].dont_fragment);
        assert_eq!(sent[0].timeout, Duration::from_millis(1_000));

        for (target, payload) in [("router.lan", 56u16), ("192.168.1.1", 65_001)] {
            assert!(matches!(
                ask(
                    &transport,
                    ProbeRequest::Ping {
                        target: target.to_owned(),
                        payload_bytes: payload,
                        dont_fragment: false
                    }
                )
                .await,
                Err(ProbeError::Transport(_))
            ));
        }
        // IPv6 echo is not implemented on any platform.
        assert_eq!(
            ask(
                &transport,
                ProbeRequest::Ping {
                    target: "fd00::1".to_owned(),
                    payload_bytes: 56,
                    dont_fragment: false
                }
            )
            .await,
            Err(ProbeError::Unsupported)
        );
        assert_eq!(
            host.echoes.lock().unwrap().len(),
            1,
            "rejected pings must not reach the OS"
        );
    }

    #[tokio::test]
    async fn echo_outcomes_become_loss_mtu_signals_or_errors() {
        for (outcome, expected) in [
            (EchoOutcome::Timeout, Ok(ProbeResponse::PingTimeout)),
            (
                EchoOutcome::FragmentationNeeded {
                    next_hop_mtu: Some(1400),
                },
                Ok(ProbeResponse::FragmentationNeeded { next_hop_mtu: 1400 }),
            ),
        ] {
            let (transport, _) = transport(ScriptedHost {
                echo_outcome: outcome,
                ..ScriptedHost::default()
            });
            assert_eq!(
                ask(
                    &transport,
                    ProbeRequest::Ping {
                        target: "1.1.1.1".to_owned(),
                        payload_bytes: 1472,
                        dont_fragment: true
                    }
                )
                .await,
                expected
            );
        }
    }

    #[tokio::test]
    async fn dns_answers_failures_and_silence_are_measurements() {
        for (script, expected) in [
            (DnsScript::Answer, Some(vec!["93.184.216.34".to_owned()])),
            (DnsScript::NoReply, None),
        ] {
            let (transport, _) = transport(ScriptedHost {
                dns: script,
                ..ScriptedHost::default()
            });
            let response = ask(
                &transport,
                ProbeRequest::DnsQuery {
                    resolver: "192.168.1.1".to_owned(),
                    name: "example.com".to_owned(),
                },
            )
            .await
            .unwrap();
            match (response, expected) {
                (ProbeResponse::DnsAnswer { addresses, .. }, Some(want)) => {
                    assert_eq!(addresses, want)
                }
                (ProbeResponse::DnsFailure { reason }, None) => {
                    assert_eq!(reason, DnsFailureReason::Timeout);
                }
                (other, _) => panic!("unexpected {other:?}"),
            }
        }
        for (script, reason) in [
            (DnsScript::Rcode(3), DnsFailureReason::NoAnswer),
            (DnsScript::Rcode(5), DnsFailureReason::Refused),
            (DnsScript::Rcode(2), DnsFailureReason::ServFail),
            (DnsScript::PortUnreachable, DnsFailureReason::Refused),
        ] {
            let (transport, _) = transport(ScriptedHost {
                dns: script,
                ..ScriptedHost::default()
            });
            assert_eq!(
                ask(
                    &transport,
                    ProbeRequest::DnsQuery {
                        resolver: "192.168.1.1".to_owned(),
                        name: "example.com".to_owned()
                    }
                )
                .await,
                Ok(ProbeResponse::DnsFailure { reason })
            );
        }
        // A reply for a different transaction is an error, not an answer.
        let (transport, _) = self::transport(ScriptedHost {
            dns: DnsScript::WrongTransaction,
            ..ScriptedHost::default()
        });
        assert!(matches!(
            ask(
                &transport,
                ProbeRequest::DnsQuery {
                    resolver: "192.168.1.1".to_owned(),
                    name: "example.com".to_owned()
                }
            )
            .await,
            Err(ProbeError::Transport(_))
        ));
        // Resolvers are IP literals; names and bad probe names are errors.
        assert!(matches!(
            ask(
                &transport,
                ProbeRequest::DnsQuery {
                    resolver: "dns.example".to_owned(),
                    name: "example.com".to_owned()
                }
            )
            .await,
            Err(ProbeError::Transport(_))
        ));
        assert!(matches!(
            ask(
                &transport,
                ProbeRequest::DnsQuery {
                    resolver: "192.168.1.1".to_owned(),
                    name: "bad name".to_owned()
                }
            )
            .await,
            Err(ProbeError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn the_route_table_flags_tunnel_default_routes() {
        let mut host = ScriptedHost::default();
        host.links.push(LinkInfo {
            index: 9,
            name: "wg0".to_owned(),
            up: true,
            kind: LinkKind::Tunnel,
            speed_mbps: None,
            mtu: Some(1420),
            mac: None,
            ipv4: Vec::new(),
        });
        host.routes.push(super::super::model::DefaultRoute {
            interface: "wg0".to_owned(),
            gateway: Ipv4Addr::UNSPECIFIED,
            metric: 50,
        });
        let (transport, _) = transport(host);
        let Ok(ProbeResponse::RouteTable { default_routes }) =
            ask(&transport, ProbeRequest::RouteTable).await
        else {
            panic!("route table expected");
        };
        assert_eq!(
            default_routes,
            vec![
                RouteEntry {
                    interface: "wg0".to_owned(),
                    gateway: "0.0.0.0".to_owned(),
                    is_vpn: true,
                    metric: 50
                },
                RouteEntry {
                    interface: "eth0".to_owned(),
                    gateway: "192.168.1.1".to_owned(),
                    is_vpn: false,
                    metric: 100
                },
            ]
        );
    }

    #[tokio::test]
    async fn tcp_reachability_is_a_measurement_and_dials_the_literal_endpoint() {
        let (transport, host) = transport(ScriptedHost::default());
        let reach = ProbeRequest::ReachIp {
            address: "1.1.1.1".to_owned(),
            port: 443,
        };
        assert!(matches!(
            ask(&transport, reach.clone()).await,
            Ok(ProbeResponse::Reachable { .. })
        ));
        assert_eq!(
            host.dials.lock().unwrap().clone(),
            vec!["1.1.1.1:443".parse::<SocketAddr>().unwrap()]
        );

        let (refused, _) = self::transport(ScriptedHost {
            tcp_error: Some(ErrorKind::ConnectionRefused),
            ..ScriptedHost::default()
        });
        assert_eq!(
            ask(&refused, reach.clone()).await,
            Ok(ProbeResponse::Unreachable)
        );
        let (broken, _) = self::transport(ScriptedHost {
            tcp_error: Some(ErrorKind::PermissionDenied),
            ..ScriptedHost::default()
        });
        assert!(matches!(
            ask(&broken, reach).await,
            Err(ProbeError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn router_health_and_collector_status_are_not_probed_here() {
        let (transport, _) = transport(ScriptedHost::default());
        for request in [ProbeRequest::RouterStatus, ProbeRequest::CollectorStatus] {
            assert_eq!(ask(&transport, request).await, Err(ProbeError::Unsupported));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn every_probe_that_waits_on_the_os_is_cut_off_at_its_timeout() {
        let transport = HostProbeTransport::new(Arc::new(NeverHost::default()));
        let requests = [
            ProbeRequest::IpConfig {
                interface: "eth0".to_owned(),
            },
            ProbeRequest::ArpProbe {
                interface: "eth0".to_owned(),
                address: "192.168.1.10".to_owned(),
            },
            ProbeRequest::Ping {
                target: "192.168.1.1".to_owned(),
                payload_bytes: 56,
                dont_fragment: false,
            },
            ProbeRequest::DnsQuery {
                resolver: "192.168.1.1".to_owned(),
                name: "example.com".to_owned(),
            },
            ProbeRequest::ReachIp {
                address: "1.1.1.1".to_owned(),
                port: 443,
            },
        ];
        for request in requests {
            let started = tokio::time::Instant::now();
            let result = transport
                .probe(Probe {
                    request: request.clone(),
                    timeout_ms: 500,
                })
                .await;
            assert_eq!(result, Err(ProbeError::Timeout), "{request:?}");
            assert!(
                started.elapsed() <= Duration::from_millis(500) + HARD_TIMEOUT_SLACK,
                "{request:?} ran past its bound: {:?}",
                started.elapsed()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_requested_timeout_is_clamped_to_the_engines_maximum() {
        let transport = HostProbeTransport::new(Arc::new(NeverHost::default()));
        let started = tokio::time::Instant::now();
        let result = transport
            .probe(Probe {
                request: ProbeRequest::ReachIp {
                    address: "1.1.1.1".to_owned(),
                    port: 443,
                },
                timeout_ms: u32::MAX,
            })
            .await;
        assert_eq!(result, Err(ProbeError::Timeout));
        assert!(
            started.elapsed()
                <= Duration::from_millis(u64::from(MAX_PROBE_TIMEOUT_MS)) + HARD_TIMEOUT_SLACK
        );
    }
}
