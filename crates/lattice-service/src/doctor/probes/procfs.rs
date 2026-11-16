//! Parsers for the text formats Linux exposes under `/proc` and `/sys`.
//! Pure functions over strings: the file reads live in `linux.rs`.

use super::model::{DefaultRoute, Mac};
use std::net::Ipv4Addr;

const RTF_UP: u32 = 0x1;

/// Every IPv4 default route in `/proc/net/route`: destination and mask
/// `0.0.0.0`, route up. Routes without a gateway (tunnels) are included with
/// gateway `0.0.0.0`, because a VPN default route is exactly what the route
/// check must see.
pub fn parse_default_routes(table: &str) -> Vec<DefaultRoute> {
    let mut routes: Vec<DefaultRoute> = Vec::new();
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
            continue;
        }
        let Ok(flags) = u32::from_str_radix(fields[3], 16) else {
            continue;
        };
        let Ok(raw_gateway) = u32::from_str_radix(fields[2], 16) else {
            continue;
        };
        if flags & RTF_UP == 0 {
            continue;
        }
        let Ok(metric) = fields[6].parse::<u32>() else {
            continue;
        };
        // The kernel prints addresses in host byte order; the Linux release
        // targets are little-endian, so the low byte is the first octet.
        let route = DefaultRoute {
            interface: fields[0].to_owned(),
            gateway: Ipv4Addr::from(raw_gateway.to_le_bytes()),
            metric,
        };
        if !routes.contains(&route) {
            routes.push(route);
        }
    }
    routes
}

/// The signal level of `interface` in dBm from `/proc/net/wireless`.
///
/// The kernel prints the level as a signed number only when the driver reports
/// dBm; a non-negative level is a driver-specific scale and is not a dBm
/// figure, so it is not reported.
pub fn parse_wireless_level(text: &str, interface: &str) -> Option<i16> {
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() != interface {
            continue;
        }
        // Columns: status, link quality, level, noise, ...
        let level = rest.split_whitespace().nth(2)?;
        let level: i32 = level.trim_end_matches('.').parse().ok()?;
        return i16::try_from(level)
            .ok()
            .filter(|dbm| (-200..0).contains(dbm));
    }
    None
}

/// Whether the link is up from `operstate` (and `carrier` for the "unknown"
/// state virtual devices report). `None` when the files do not decide it.
pub fn link_up(operstate: &str, carrier: Option<&str>) -> Option<bool> {
    match operstate.trim() {
        "up" => Some(true),
        "down" | "lowerlayerdown" | "notpresent" | "dormant" | "testing" => Some(false),
        "unknown" => match carrier.map(str::trim) {
            Some("1") => Some(true),
            Some("0") => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// `/sys/class/net/<if>/speed`: Mbit/s, `-1` (or unreadable) when unknown.
pub fn parse_speed_mbps(text: &str) -> Option<u32> {
    let speed: i64 = text.trim().parse().ok()?;
    u32::try_from(speed).ok().filter(|speed| *speed > 0)
}

/// `/sys/class/net/<if>/mtu`.
pub fn parse_mtu(text: &str) -> Option<u32> {
    text.trim().parse().ok().filter(|mtu| *mtu > 0)
}

/// `/sys/class/net/<if>/address`: `aa:bb:cc:dd:ee:ff`; an all-zero address
/// (loopback, tunnels) is no address.
pub fn parse_mac(text: &str) -> Option<Mac> {
    let mut mac: Mac = [0; 6];
    let mut count = 0usize;
    for part in text.trim().split(':') {
        if count >= 6 || part.len() != 2 {
            return None;
        }
        mac[count] = u8::from_str_radix(part, 16).ok()?;
        count += 1;
    }
    (count == 6 && mac != [0; 6]).then_some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE_TABLE: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
eth0\t00000000\tFE01A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
tun0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n\
down0\t00000000\t0101A8C0\t0002\t0\t0\t10\t00000000\t0\t0\t0\n\
eth0\t00000000\tFE01A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";

    #[test]
    fn default_routes_include_tunnels_and_skip_down_and_non_default_rows() {
        let routes = parse_default_routes(ROUTE_TABLE);
        assert_eq!(
            routes,
            vec![
                DefaultRoute {
                    interface: "wlan0".to_owned(),
                    gateway: Ipv4Addr::new(192, 168, 1, 1),
                    metric: 600
                },
                DefaultRoute {
                    interface: "eth0".to_owned(),
                    gateway: Ipv4Addr::new(192, 168, 1, 254),
                    metric: 100
                },
                DefaultRoute {
                    interface: "tun0".to_owned(),
                    gateway: Ipv4Addr::UNSPECIFIED,
                    metric: 50
                },
            ]
        );
        assert!(parse_default_routes("Iface\tDestination\n").is_empty());
        assert!(parse_default_routes("").is_empty());
    }

    const WIRELESS: &str = "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n \
face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n \
wlan0: 0000   70.  -40.  -256        0      0      0      0      0        0\n \
wlp3s0: 0000   45.  199.  161        0      0      0      0      0        0\n";

    #[test]
    fn wireless_level_is_reported_only_when_the_driver_reports_dbm() {
        assert_eq!(parse_wireless_level(WIRELESS, "wlan0"), Some(-40));
        // A positive level is a driver scale, not dBm.
        assert_eq!(parse_wireless_level(WIRELESS, "wlp3s0"), None);
        assert_eq!(parse_wireless_level(WIRELESS, "eth0"), None);
        assert_eq!(parse_wireless_level("", "wlan0"), None);
        assert_eq!(
            parse_wireless_level("h1\nh2\nwlan0: 0000 70. -40", "wlan0"),
            Some(-40)
        );
        assert_eq!(
            parse_wireless_level("h1\nh2\nwlan0: 0000 70.", "wlan0"),
            None
        );
    }

    #[test]
    fn operstate_decides_the_link_and_carrier_settles_unknown() {
        assert_eq!(link_up("up\n", None), Some(true));
        assert_eq!(link_up("down\n", Some("1")), Some(false));
        assert_eq!(link_up("lowerlayerdown", None), Some(false));
        assert_eq!(link_up("unknown\n", Some("1\n")), Some(true));
        assert_eq!(link_up("unknown", Some("0")), Some(false));
        assert_eq!(link_up("unknown", None), None);
        assert_eq!(link_up("surprise", Some("1")), None);
    }

    #[test]
    fn sysfs_numbers_and_addresses_parse_strictly() {
        assert_eq!(parse_speed_mbps("1000\n"), Some(1000));
        assert_eq!(parse_speed_mbps("-1\n"), None);
        assert_eq!(parse_speed_mbps("0"), None);
        assert_eq!(parse_speed_mbps("fast"), None);
        assert_eq!(parse_mtu("1500\n"), Some(1500));
        assert_eq!(parse_mtu("0"), None);
        assert_eq!(
            parse_mac("aa:bb:cc:00:11:22\n"),
            Some([0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22])
        );
        assert_eq!(parse_mac("00:00:00:00:00:00\n"), None);
        assert_eq!(parse_mac("aa:bb:cc:00:11\n"), None);
        assert_eq!(parse_mac("aa:bb:cc:00:11:22:33\n"), None);
        assert_eq!(parse_mac("aa:bb:cc:00:11:zz\n"), None);
    }
}
