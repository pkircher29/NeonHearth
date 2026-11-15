//! Validated value types that repairs and diagnoses carry instead of free text.
//!
//! Anything a future transport might splice into a command line or an OS API
//! call is parsed here first: first character alphanumeric (never an option
//! dash), restricted charset, bounded length.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use utoipa::ToSchema;

use crate::DoctorError;

/// Most MAC addresses one diagnosis will carry.
pub const MAX_REPORTED_MACS: usize = 8;
const MAX_INTERFACE_LEN: usize = 64;
const MAX_TARGET_LEN: usize = 253;

/// A 48-bit unicast MAC address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ToSchema)]
#[schema(value_type = String, example = "aa:bb:cc:dd:ee:ff")]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl FromStr for MacAddr {
    type Err = DoctorError;

    /// Accepts exactly `aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff`. Multicast,
    /// broadcast and all-zero addresses are not claimants.
    fn from_str(value: &str) -> Result<Self, DoctorError> {
        let separator = if value.contains(':') { ':' } else { '-' };
        let mut octets = [0u8; 6];
        let mut count = 0usize;
        for part in value.split(separator) {
            if count >= 6 || part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(DoctorError::InvalidValue("mac address"));
            }
            octets[count] =
                u8::from_str_radix(part, 16).map_err(|_| DoctorError::InvalidValue("mac"))?;
            count += 1;
        }
        if count != 6 || octets[0] & 1 != 0 || octets == [0; 6] {
            return Err(DoctorError::InvalidValue("mac address"));
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.0;
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// An OS network interface name that cannot be mistaken for a command-line
/// option or smuggle shell/format characters.
#[derive(Clone, Debug, Eq, Hash, PartialEq, ToSchema)]
#[schema(value_type = String, example = "eth0")]
pub struct InterfaceName(String);

impl InterfaceName {
    pub fn parse(value: &str) -> Result<Self, DoctorError> {
        let first_ok = value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        // Windows adapter names such as "vEthernet (Default Switch)" contain
        // spaces and parentheses; nothing else beyond `._-:@` is allowed.
        let rest_ok = value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '@' | ' ' | '(' | ')')
        });
        if !first_ok
            || !rest_ok
            || value.len() > MAX_INTERFACE_LEN
            || value.ends_with(' ')
            || value.contains("  ")
        {
            return Err(DoctorError::InvalidValue("interface name"));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for InterfaceName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// True for a probe target string a transport may safely receive: an IP
/// literal or a hostname-shaped token whose first character is alphanumeric.
pub fn is_safe_target(value: &str) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    value.len() <= MAX_TARGET_LEN
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// Parses a MAC list from untrusted probe output: invalid and duplicate
/// entries are dropped, `exclude` (the host's own addresses) is removed, and
/// the result is capped at [`MAX_REPORTED_MACS`].
pub fn sanitize_macs(raw: &[String], exclude: &[MacAddr]) -> Vec<MacAddr> {
    let mut out: Vec<MacAddr> = Vec::new();
    for item in raw {
        let Ok(mac) = item.parse::<MacAddr>() else {
            continue;
        };
        if exclude.contains(&mac) || out.contains(&mac) {
            continue;
        }
        out.push(mac);
        if out.len() == MAX_REPORTED_MACS {
            break;
        }
    }
    out.sort();
    out
}

/// IP version of the path being probed; decides the header overhead that
/// turns an ICMP payload size into a link MTU.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    /// IP header plus ICMP header: 20 + 8 for IPv4, 40 + 8 for IPv6.
    pub const fn icmp_overhead(self) -> u16 {
        match self {
            Self::V4 => 28,
            Self::V6 => 48,
        }
    }
}

/// A link MTU in bytes (IP packet size), never an ICMP payload size.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct Mtu(u16);

impl Mtu {
    pub const MIN: u16 = 576;

    /// Converts the largest don't-fragment ICMP payload that passed into the
    /// MTU it implies. `None` when the result is outside 576..=65535.
    pub fn from_icmp_payload(payload_bytes: u16, version: IpVersion) -> Option<Self> {
        payload_bytes
            .checked_add(version.icmp_overhead())
            .filter(|mtu| *mtu >= Self::MIN)
            .map(Self)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parsing_is_strict() {
        assert!("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().is_ok());
        assert!("AA-BB-CC-DD-EE-FF".parse::<MacAddr>().is_ok());
        for bad in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "01:00:5e:00:00:01",
            "00:00:00:00:00:00",
            "-rf:bb:cc:dd:ee:ff",
            "aa:bb:cc:dd:ee:f",
            "aa:bb:cc:dd:ee:ff; reboot",
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad}");
        }
    }

    #[test]
    fn interface_names_cannot_be_option_shaped() {
        assert!(InterfaceName::parse("eth0").is_ok());
        assert!(InterfaceName::parse("vEthernet (Default Switch)").is_ok());
        for bad in [
            "",
            "-h",
            "--version",
            " eth0",
            "eth0 ",
            "eth0;rm",
            "a\nb",
            "$(x)",
            "a  b",
        ] {
            assert!(InterfaceName::parse(bad).is_err(), "{bad:?}");
        }
        assert!(InterfaceName::parse(&"a".repeat(65)).is_err());
    }

    #[test]
    fn targets_reject_option_shapes() {
        assert!(is_safe_target("10.0.0.1"));
        assert!(is_safe_target("fe80::1"));
        assert!(is_safe_target("example.com"));
        assert!(is_safe_target("unconfigured"));
        for bad in ["", "-c1", "--help", ".x", "a b", "a;b", "a/b", "$HOME"] {
            assert!(!is_safe_target(bad), "{bad:?}");
        }
    }

    #[test]
    fn mtu_adds_the_header_overhead_for_each_ip_version() {
        assert_eq!(
            Mtu::from_icmp_payload(1472, IpVersion::V4).unwrap().get(),
            1500
        );
        assert_eq!(
            Mtu::from_icmp_payload(1452, IpVersion::V6).unwrap().get(),
            1500
        );
        assert_eq!(Mtu::from_icmp_payload(10, IpVersion::V4), None);
        assert_eq!(Mtu::from_icmp_payload(u16::MAX, IpVersion::V4), None);
    }

    #[test]
    fn sanitize_drops_invalid_duplicates_self_and_caps() {
        let own: MacAddr = "aa:aa:aa:aa:aa:01".parse().unwrap();
        let mut raw: Vec<String> = vec![
            "aa:aa:aa:aa:aa:01".into(),
            "garbage".into(),
            "bb:bb:bb:bb:bb:02".into(),
            "BB:BB:BB:BB:BB:02".into(),
        ];
        raw.extend((0..20).map(|n| format!("cc:cc:cc:cc:cc:{n:02x}")));
        let out = sanitize_macs(&raw, &[own]);
        assert!(!out.contains(&own));
        assert_eq!(out.len(), MAX_REPORTED_MACS);
    }
}
