//! Pure interpretation rules: OS facts in, typed Doctor responses out.
//!
//! Nothing here touches the OS, so every rule has a fixture test.

use super::model::{
    DefaultRoute, EchoOutcome, LinkInfo, LinkKind, Mac, Ipv4Lease, OsError,
};
use lattice_doctor::probe::{LeaseState, ProbeError, ProbeResponse, RouteEntry};
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::time::Duration;

/// The interface name the Doctor uses until the owner picks one: whichever
/// interface owns the best IPv4 default route.
pub const PRIMARY_INTERFACE: &str = "primary";

/// The default route with the lowest metric (ties broken by interface name so
/// the answer is deterministic).
pub fn primary_route(routes: &[DefaultRoute]) -> Option<&DefaultRoute> {
    routes.iter().min_by(|a, b| {
        a.metric
            .cmp(&b.metric)
            .then_with(|| a.interface.cmp(&b.interface))
    })
}

/// Finds the interface a probe is about. `"primary"` follows the best default
/// route; any other name must match an interface (exactly, else ignoring
/// ASCII case, which is how Windows treats adapter names).
pub fn resolve_link<'a>(
    links: &'a [LinkInfo],
    routes: &[DefaultRoute],
    requested: &str,
) -> Result<&'a LinkInfo, OsError> {
    let name = if requested == PRIMARY_INTERFACE {
        primary_route(routes)
            .map(|route| route.interface.as_str())
            .ok_or_else(|| {
                OsError::failed(
                    "there is no IPv4 default route, so the primary interface cannot be \
                     identified; set the interface in the Doctor settings",
                )
            })?
    } else {
        requested
    };
    links
        .iter()
        .find(|link| link.name == name)
        .or_else(|| {
            links
                .iter()
                .find(|link| link.name.eq_ignore_ascii_case(name))
        })
        .ok_or_else(|| OsError::failed(format!("interface {name} was not found")))
}

/// Adapter link answer.
pub fn link_response(link: &LinkInfo) -> ProbeResponse {
    ProbeResponse::LinkStatus {
        up: link.up,
        speed_mbps: link.speed_mbps,
    }
}

/// How the OS lifetime facts of one address map onto the Doctor's lease state.
///
/// An address the OS keeps forever (or the OS marks as manually configured) is
/// static; one with a finite lifetime is dynamic (DHCP or router assigned) and
/// valid while time remains.
pub fn lease_state(lease: &Ipv4Lease) -> LeaseState {
    if lease.permanent || lease.valid_seconds == u32::MAX {
        LeaseState::Static
    } else if lease.valid_seconds == 0 {
        LeaseState::Expired
    } else {
        LeaseState::Valid
    }
}

/// Address/DHCP answer for one interface.
///
/// A routable address wins over a link-local one. A link-local (APIPA,
/// 169.254.0.0/16) address is reported but never as a valid lease: it is what
/// the OS falls back to when DHCP failed.
pub fn ip_config_response(leases: &[Ipv4Lease]) -> ProbeResponse {
    let routable = leases.iter().find(|lease| {
        !lease.address.is_link_local()
            && !lease.address.is_unspecified()
            && !lease.address.is_loopback()
    });
    if let Some(lease) = routable {
        return ProbeResponse::IpConfig {
            address: Some(lease.address.to_string()),
            lease: lease_state(lease),
        };
    }
    match leases.iter().find(|lease| lease.address.is_link_local()) {
        Some(lease) => ProbeResponse::IpConfig {
            address: Some(lease.address.to_string()),
            lease: LeaseState::Missing,
        },
        None => ProbeResponse::IpConfig {
            address: None,
            lease: LeaseState::Missing,
        },
    }
}

/// Default-route answer. `is_vpn` is true when the owning interface is a
/// tunnel.
pub fn route_response(routes: &[DefaultRoute], links: &[LinkInfo]) -> ProbeResponse {
    let mut sorted = routes.to_vec();
    sorted.sort_by(|a, b| {
        a.metric
            .cmp(&b.metric)
            .then_with(|| a.interface.cmp(&b.interface))
    });
    ProbeResponse::RouteTable {
        default_routes: sorted
            .into_iter()
            .map(|route| RouteEntry {
                is_vpn: links
                    .iter()
                    .any(|link| link.name == route.interface && link.kind == LinkKind::Tunnel),
                interface: route.interface,
                gateway: route.gateway.to_string(),
                metric: route.metric,
            })
            .collect(),
    }
}

/// Wi-Fi answer. The retry rate is not measurable from counters alone, so it
/// is never reported.
pub fn wifi_response(wireless: bool, rssi_dbm: Option<i16>) -> ProbeResponse {
    ProbeResponse::WifiMetrics {
        wireless,
        rssi_dbm: if wireless { rssi_dbm } else { None },
        retry_percent: None,
    }
}

/// ICMP echo answer. A path that says "too big" without saying how big is a
/// transport error: reporting an invented MTU would be a fabrication.
pub fn echo_response(outcome: EchoOutcome) -> Result<ProbeResponse, ProbeError> {
    match outcome {
        EchoOutcome::Reply { rtt_ms } => Ok(ProbeResponse::PingReply { rtt_ms }),
        EchoOutcome::Timeout => Ok(ProbeResponse::PingTimeout),
        EchoOutcome::FragmentationNeeded {
            next_hop_mtu: Some(next_hop_mtu),
        } => Ok(ProbeResponse::FragmentationNeeded { next_hop_mtu }),
        EchoOutcome::FragmentationNeeded { next_hop_mtu: None } => Err(ProbeError::Transport(
            "the path reported that the packet was too big but did not report its MTU".to_owned(),
        )),
    }
}

/// TCP reachability answer. The endpoint refusing, resetting, or not being
/// reachable at all is a measurement ("not reachable"); anything else is an
/// error of the probe itself.
pub fn reach_response(
    result: Result<(), std::io::Error>,
    elapsed: Duration,
) -> Result<ProbeResponse, ProbeError> {
    match result {
        Ok(()) => Ok(ProbeResponse::Reachable {
            latency_ms: elapsed.as_secs_f64() * 1000.0,
        }),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::TimedOut
                    | ErrorKind::HostUnreachable
                    | ErrorKind::NetworkUnreachable
                    | ErrorKind::NetworkDown
            ) =>
        {
            Ok(ProbeResponse::Unreachable)
        }
        Err(error) => Err(ProbeError::Transport(format!(
            "TCP connect failed: {error}"
        ))),
    }
}

/// `aa:bb:cc:dd:ee:ff`.
pub fn mac_string(mac: Mac) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// A six-byte, non-zero hardware address, or `None`.
#[cfg(any(windows, test))]
pub fn mac_from_bytes(bytes: &[u8]) -> Option<Mac> {
    let mac: Mac = bytes.try_into().ok()?;
    (mac != [0; 6]).then_some(mac)
}

/// Link speed in whole Mbit/s from a bits-per-second figure. Zero and the
/// "unknown" all-ones value are not speeds.
#[cfg(any(windows, test))]
pub fn speed_mbps_from_bps(bits_per_second: u64) -> Option<u32> {
    if bits_per_second == 0 || bits_per_second == u64::MAX {
        return None;
    }
    let mbps = bits_per_second / 1_000_000;
    if mbps == 0 {
        return None;
    }
    Some(u32::try_from(mbps).unwrap_or(u32::MAX))
}

/// An IPv4 address from the NUL-terminated C string Windows stores in
/// `IP_ADDRESS_STRING`. Empty and unspecified entries are not addresses.
#[cfg(any(windows, test))]
pub fn parse_c_ipv4(raw: &[i8]) -> Option<Ipv4Addr> {
    let bytes: Vec<u8> = raw
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect();
    let address: Ipv4Addr = String::from_utf8(bytes).ok()?.parse().ok()?;
    (!address.is_unspecified()).then_some(address)
}

/// The address an ARP probe may target: an IPv4 address that is configured on
/// the interface. Anything else would turn the probe into an ARP scanner.
pub fn arp_target(link: &LinkInfo, address: &str) -> Result<Ipv4Addr, OsError> {
    let parsed: Ipv4Addr = address
        .parse()
        .map_err(|_| OsError::failed("the ARP probe address must be an IPv4 address"))?;
    if link.ipv4.contains(&parsed) {
        Ok(parsed)
    } else {
        Err(OsError::failed(format!(
            "{parsed} is not an address of interface {}",
            link.name
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(name: &str, kind: LinkKind) -> LinkInfo {
        LinkInfo {
            index: 2,
            name: name.to_owned(),
            up: true,
            kind,
            speed_mbps: Some(1000),
            mtu: Some(1500),
            mac: Some([2, 0, 0, 0, 0, 1]),
            ipv4: vec![Ipv4Addr::new(192, 168, 1, 10)],
        }
    }

    fn route(interface: &str, gateway: [u8; 4], metric: u32) -> DefaultRoute {
        DefaultRoute {
            interface: interface.to_owned(),
            gateway: Ipv4Addr::from(gateway),
            metric,
        }
    }

    fn lease(address: [u8; 4], valid_seconds: u32, permanent: bool) -> Ipv4Lease {
        Ipv4Lease {
            address: Ipv4Addr::from(address),
            valid_seconds,
            permanent,
        }
    }

    #[test]
    fn primary_follows_the_lowest_metric_default_route() {
        let links = [link("eth0", LinkKind::Wired), link("wlan0", LinkKind::Wifi)];
        let routes = [
            route("wlan0", [192, 168, 1, 1], 600),
            route("eth0", [192, 168, 1, 1], 100),
        ];
        assert_eq!(
            resolve_link(&links, &routes, "primary").unwrap().name,
            "eth0"
        );
        assert_eq!(
            resolve_link(&links, &routes, "wlan0").unwrap().name,
            "wlan0"
        );
        assert_eq!(resolve_link(&links, &routes, "ETH0").unwrap().name, "eth0");
    }

    #[test]
    fn primary_without_a_route_and_unknown_names_are_errors_not_guesses() {
        let links = [link("eth0", LinkKind::Wired)];
        assert!(matches!(
            resolve_link(&links, &[], "primary"),
            Err(OsError::Failed(message)) if message.contains("no IPv4 default route")
        ));
        assert!(matches!(
            resolve_link(&links, &[], "nope0"),
            Err(OsError::Failed(message)) if message.contains("nope0")
        ));
        let routes = [route("gone0", [10, 0, 0, 1], 1)];
        assert!(resolve_link(&links, &routes, "primary").is_err());
    }

    #[test]
    fn lease_state_comes_from_lifetime_facts() {
        assert_eq!(
            lease_state(&lease([192, 168, 1, 10], 3600, false)),
            LeaseState::Valid
        );
        assert_eq!(
            lease_state(&lease([192, 168, 1, 10], u32::MAX, false)),
            LeaseState::Static
        );
        assert_eq!(
            lease_state(&lease([192, 168, 1, 10], 3600, true)),
            LeaseState::Static
        );
        assert_eq!(
            lease_state(&lease([192, 168, 1, 10], 0, false)),
            LeaseState::Expired
        );
    }

    #[test]
    fn ip_config_prefers_a_routable_address_and_never_blesses_apipa() {
        let routable = lease([192, 168, 1, 10], 7200, false);
        let apipa = lease([169, 254, 3, 4], u32::MAX, false);
        assert_eq!(
            ip_config_response(&[apipa, routable]),
            ProbeResponse::IpConfig {
                address: Some("192.168.1.10".to_owned()),
                lease: LeaseState::Valid
            }
        );
        // Only an APIPA address: reported, but the lease is missing.
        assert_eq!(
            ip_config_response(&[apipa]),
            ProbeResponse::IpConfig {
                address: Some("169.254.3.4".to_owned()),
                lease: LeaseState::Missing
            }
        );
        assert_eq!(
            ip_config_response(&[]),
            ProbeResponse::IpConfig {
                address: None,
                lease: LeaseState::Missing
            }
        );
        assert_eq!(
            ip_config_response(&[lease([10, 0, 0, 5], 0, false)]),
            ProbeResponse::IpConfig {
                address: Some("10.0.0.5".to_owned()),
                lease: LeaseState::Expired
            }
        );
    }

    #[test]
    fn route_table_marks_tunnel_owned_routes_as_vpn_and_sorts_by_metric() {
        let links = [
            link("eth0", LinkKind::Wired),
            link("wg0", LinkKind::Tunnel),
        ];
        let routes = [
            route("wg0", [0, 0, 0, 0], 50),
            route("eth0", [192, 168, 1, 1], 100),
        ];
        let ProbeResponse::RouteTable { default_routes } = route_response(&routes, &links) else {
            panic!("route table response expected");
        };
        assert_eq!(default_routes.len(), 2);
        assert_eq!(default_routes[0].interface, "wg0");
        assert!(default_routes[0].is_vpn);
        assert_eq!(default_routes[0].gateway, "0.0.0.0");
        assert_eq!(default_routes[1].interface, "eth0");
        assert!(!default_routes[1].is_vpn);
        assert_eq!(default_routes[1].metric, 100);
    }

    #[test]
    fn wifi_answer_hides_signal_for_wired_interfaces() {
        assert_eq!(
            wifi_response(false, Some(-40)),
            ProbeResponse::WifiMetrics {
                wireless: false,
                rssi_dbm: None,
                retry_percent: None
            }
        );
        assert_eq!(
            wifi_response(true, Some(-61)),
            ProbeResponse::WifiMetrics {
                wireless: true,
                rssi_dbm: Some(-61),
                retry_percent: None
            }
        );
    }

    #[test]
    fn echo_outcomes_map_to_measurements_and_never_invent_an_mtu() {
        assert_eq!(
            echo_response(EchoOutcome::Reply { rtt_ms: 1.5 }),
            Ok(ProbeResponse::PingReply { rtt_ms: 1.5 })
        );
        assert_eq!(
            echo_response(EchoOutcome::Timeout),
            Ok(ProbeResponse::PingTimeout)
        );
        assert_eq!(
            echo_response(EchoOutcome::FragmentationNeeded {
                next_hop_mtu: Some(1400)
            }),
            Ok(ProbeResponse::FragmentationNeeded { next_hop_mtu: 1400 })
        );
        assert!(matches!(
            echo_response(EchoOutcome::FragmentationNeeded { next_hop_mtu: None }),
            Err(ProbeError::Transport(_))
        ));
    }

    #[test]
    fn tcp_results_separate_measurements_from_probe_errors() {
        let elapsed = Duration::from_millis(12);
        let ProbeResponse::Reachable { latency_ms } = reach_response(Ok(()), elapsed).unwrap()
        else {
            panic!("reachable expected");
        };
        assert!((latency_ms - 12.0).abs() < 0.001);
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
        ] {
            assert_eq!(
                reach_response(Err(std::io::Error::from(kind)), elapsed),
                Ok(ProbeResponse::Unreachable),
                "{kind:?}"
            );
        }
        assert!(matches!(
            reach_response(Err(std::io::Error::from(ErrorKind::PermissionDenied)), elapsed),
            Err(ProbeError::Transport(_))
        ));
    }

    #[test]
    fn hardware_facts_are_converted_without_inventing_values() {
        assert_eq!(speed_mbps_from_bps(1_000_000_000), Some(1000));
        assert_eq!(speed_mbps_from_bps(866_700_000), Some(866));
        assert_eq!(speed_mbps_from_bps(0), None);
        assert_eq!(speed_mbps_from_bps(u64::MAX), None);
        assert_eq!(speed_mbps_from_bps(999_999), None);
        assert_eq!(
            mac_from_bytes(&[2, 0, 0, 0, 0, 1]),
            Some([2, 0, 0, 0, 0, 1])
        );
        assert_eq!(mac_from_bytes(&[0; 6]), None);
        assert_eq!(mac_from_bytes(&[1, 2, 3]), None);
        assert_eq!(mac_string([0xaa, 0xbb, 0xcc, 0, 1, 2]), "aa:bb:cc:00:01:02");
    }

    #[test]
    fn windows_address_strings_parse_without_trusting_the_buffer() {
        let mut raw = [0i8; 16];
        for (slot, byte) in raw.iter_mut().zip(b"192.168.1.1") {
            *slot = *byte as i8;
        }
        assert_eq!(parse_c_ipv4(&raw), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(parse_c_ipv4(&[0i8; 16]), None);
        let mut unspecified = [0i8; 16];
        for (slot, byte) in unspecified.iter_mut().zip(b"0.0.0.0") {
            *slot = *byte as i8;
        }
        assert_eq!(parse_c_ipv4(&unspecified), None);
        // No terminator and junk bytes: rejected, not read past.
        assert_eq!(parse_c_ipv4(&[-1i8; 16]), None);
        assert_eq!(parse_c_ipv4(&[]), None);
    }

    #[test]
    fn arp_only_targets_addresses_configured_on_the_interface() {
        let link = link("eth0", LinkKind::Wired);
        assert_eq!(
            arp_target(&link, "192.168.1.10").unwrap(),
            Ipv4Addr::new(192, 168, 1, 10)
        );
        assert!(arp_target(&link, "192.168.1.11").is_err());
        assert!(arp_target(&link, "not-an-ip").is_err());
        assert!(arp_target(&link, "fe80::1").is_err());
    }
}
