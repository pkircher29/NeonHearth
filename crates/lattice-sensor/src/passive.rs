//! Bounded, offline decoding of genuine Ethernet frames. Raw frames never escape this module.
use chrono::{DateTime, Duration, TimeZone, Utc};
use lattice_domain::{EvidenceFact, EvidenceFamily};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
pub const MAX_FRAME_BYTES: usize = 65_535;
pub const MAX_METADATA_BYTES: usize = 2_048;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassiveOptions {
    pub metadata_enabled: bool,
}
impl Default for PassiveOptions {
    fn default() -> Self {
        Self {
            metadata_enabled: true,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PassiveObservation {
    pub interface: String,
    pub observed_at: DateTime<Utc>,
    pub subject_mac: Option<String>,
    pub subject_ip: Option<IpAddr>,
    pub protocol: String,
    pub facts: Vec<EvidenceFact>,
}
pub trait PassiveAdapter: Send + Sync {
    fn normalize(
        &self,
        interface: &str,
        captured_at: DateTime<Utc>,
        frame: &[u8],
        options: &PassiveOptions,
    ) -> Result<Vec<PassiveObservation>, PassiveParseError>;
}
#[derive(Default)]
pub struct OfflinePassiveAdapter;
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PassiveParseError {
    #[error("unsupported or truncated pcap header")]
    PcapHeader,
    #[error("truncated packet")]
    Truncated,
    #[error("invalid packet length")]
    InvalidLength,
    #[error("frame exceeds limit")]
    OversizedFrame,
    #[error("malformed bounded metadata")]
    Metadata,
}
impl OfflinePassiveAdapter {
    pub fn ingest_pcap(
        &self,
        i: &str,
        b: &[u8],
        o: &PassiveOptions,
    ) -> Result<Vec<PassiveObservation>, PassiveParseError> {
        if b.len() < 24
            || b[..4] != [212, 195, 178, 161]
            || u32::from_le_bytes(b[20..24].try_into().unwrap()) != 1
        {
            return Err(PassiveParseError::PcapHeader);
        }
        let (mut at, mut r) = (24, Vec::new());
        while at < b.len() {
            if b.len() - at < 16 {
                return Err(PassiveParseError::Truncated);
            }
            let incl = u32::from_le_bytes(b[at + 8..at + 12].try_into().unwrap()) as usize;
            let orig = u32::from_le_bytes(b[at + 12..at + 16].try_into().unwrap()) as usize;
            let sec = u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
            at += 16;
            if incl > orig || incl > MAX_FRAME_BYTES {
                return Err(PassiveParseError::InvalidLength);
            }
            if b.len() - at < incl {
                return Err(PassiveParseError::Truncated);
            }
            r.extend(
                self.normalize(
                    i,
                    Utc.timestamp_opt(sec as i64, 0)
                        .single()
                        .ok_or(PassiveParseError::PcapHeader)?,
                    &b[at..at + incl],
                    o,
                )?,
            );
            at += incl
        }
        Ok(r)
    }
}
impl PassiveAdapter for OfflinePassiveAdapter {
    fn normalize(
        &self,
        i: &str,
        t: DateTime<Utc>,
        f: &[u8],
        o: &PassiveOptions,
    ) -> Result<Vec<PassiveObservation>, PassiveParseError> {
        if f.len() > MAX_FRAME_BYTES {
            return Err(PassiveParseError::OversizedFrame);
        }
        if f.len() < 14 {
            return Err(PassiveParseError::Truncated);
        }
        let mac = Some(
            f[6..12]
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        );
        match u16::from_be_bytes([f[12], f[13]]) {
            0x0806 => arp(i, t, mac, &f[14..]),
            0x0800 => ipv4(i, t, mac, &f[14..], o),
            0x86dd => ipv6(i, t, mac, &f[14..], o),
            _ => Ok(vec![]),
        }
    }
}
fn obs(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    ip: Option<IpAddr>,
    p: &str,
    vals: Vec<(&str, String, EvidenceFamily)>,
    ttl: i64,
) -> Vec<PassiveObservation> {
    let s = format!("passive.{p}");
    let mut facts = vec![fact(
        &s,
        "mac",
        m.clone().unwrap_or_default(),
        EvidenceFamily::LinkLayer,
        t,
        ttl,
    )];
    for (k, v, f) in vals {
        facts.push(fact(&s, k, v, f, t, ttl))
    }
    vec![PassiveObservation {
        interface: i.into(),
        observed_at: t,
        subject_mac: m,
        subject_ip: ip,
        protocol: p.into(),
        facts,
    }]
}
fn fact(
    s: &str,
    k: &str,
    v: String,
    f: EvidenceFamily,
    t: DateTime<Utc>,
    ttl: i64,
) -> EvidenceFact {
    EvidenceFact {
        family: f,
        source: s.into(),
        key: k.into(),
        value: v,
        confidence: 0.8,
        observed_at: t,
        expires_at: Some(t + Duration::seconds(ttl)),
        owner_confirmed: false,
    }
}
fn arp(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    p: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if p.len() < 28 || p[4] != 6 || p[5] != 4 {
        return Err(PassiveParseError::Truncated);
    }
    let ip = Ipv4Addr::new(p[14], p[15], p[16], p[17]);
    Ok(obs(
        i,
        t,
        m,
        Some(ip.into()),
        "arp",
        vec![
            ("ip", ip.to_string(), EvidenceFamily::Addressing),
            (
                "binding",
                p[8..14]
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
                EvidenceFamily::Addressing,
            ),
        ],
        300,
    ))
}
fn ipv4(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    p: &[u8],
    o: &PassiveOptions,
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return Err(PassiveParseError::Truncated);
    }
    let n = ((p[0] & 15) as usize) * 4;
    let l = u16::from_be_bytes([p[2], p[3]]) as usize;
    if n < 20 || l < n || l > p.len() {
        return Err(PassiveParseError::InvalidLength);
    }
    let ip = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    match p[9] {
        17 => udp(i, t, m, Some(ip.into()), &p[n..l], o),
        6 => tcp(i, t, m, Some(ip.into()), &p[n..l]),
        2 => {
            if l < n + 8 {
                return Err(PassiveParseError::Truncated);
            }
            Ok(obs(
                i,
                t,
                m,
                Some(ip.into()),
                "igmp",
                vec![(
                    "group",
                    Ipv4Addr::new(p[n + 4], p[n + 5], p[n + 6], p[n + 7]).to_string(),
                    EvidenceFamily::Service,
                )],
                300,
            ))
        }
        _ => Ok(vec![]),
    }
}
fn ipv6(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    p: &[u8],
    o: &PassiveOptions,
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if p.len() < 40 || p[0] >> 4 != 6 {
        return Err(PassiveParseError::Truncated);
    }
    let n = u16::from_be_bytes([p[4], p[5]]) as usize;
    if n + 40 > p.len() {
        return Err(PassiveParseError::InvalidLength);
    }
    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
    match p[6] {
        17 => udp(i, t, m, Some(ip.into()), &p[40..40 + n], o),
        58 => {
            let q = &p[40..40 + n];
            if q.len() < 8 {
                return Err(PassiveParseError::Truncated);
            }
            match q[0] {
                135 | 136 if q.len() >= 24 => Ok(obs(
                    i,
                    t,
                    m,
                    Some(ip.into()),
                    "ipv6-ndp",
                    vec![(
                        "target",
                        Ipv6Addr::from(<[u8; 16]>::try_from(&q[8..24]).unwrap()).to_string(),
                        EvidenceFamily::Addressing,
                    )],
                    300,
                )),
                131 if q.len() >= 24 => Ok(obs(
                    i,
                    t,
                    m,
                    Some(ip.into()),
                    "mld",
                    vec![(
                        "group",
                        Ipv6Addr::from(<[u8; 16]>::try_from(&q[8..24]).unwrap()).to_string(),
                        EvidenceFamily::Service,
                    )],
                    300,
                )),
                _ => Ok(vec![]),
            }
        }
        _ => Ok(vec![]),
    }
}
fn udp(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    ip: Option<IpAddr>,
    p: &[u8],
    o: &PassiveOptions,
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if p.len() < 8 {
        return Err(PassiveParseError::Truncated);
    }
    let (s, d) = (
        u16::from_be_bytes([p[0], p[1]]),
        u16::from_be_bytes([p[2], p[3]]),
    );
    let n = u16::from_be_bytes([p[4], p[5]]) as usize;
    if n < 8 || n > p.len() {
        return Err(PassiveParseError::InvalidLength);
    }
    let q = &p[8..n];
    match (s, d) {
        (67 | 68, 67 | 68) => dhcp4(i, t, m, ip, q),
        (546 | 547, 546 | 547) => Ok(obs(
            i,
            t,
            m,
            ip,
            "dhcpv6",
            vec![("client_id", hex(q), EvidenceFamily::Addressing)],
            3600,
        )),
        (53, _) | (_, 53) => dns(i, t, m, ip, q, o, "dns-query"),
        (5353, _) | (_, 5353) => dns(i, t, m, ip, q, o, "mdns-dns-sd"),
        (5355, _) | (_, 5355) => dns(i, t, m, ip, q, o, "llmnr"),
        (137, _) | (_, 137) => Ok(obs(
            i,
            t,
            m,
            ip,
            "nbns",
            vec![("name", nbns(q)?, EvidenceFamily::Naming)],
            300,
        )),
        (1900, _) | (_, 1900) => ssdp(i, t, m, ip, q),
        (3702, _) | (_, 3702) => soap(i, t, m, ip, q),
        (a, b) => Ok(obs(
            i,
            t,
            m,
            ip,
            "udp-flow",
            vec![
                (
                    "src",
                    format!("{}:{a}", ip.map_or("unknown".into(), |x| x.to_string())),
                    EvidenceFamily::Service,
                ),
                ("dst", format!("unknown:{b}"), EvidenceFamily::Service),
                ("bytes", q.len().to_string(), EvidenceFamily::Service),
            ],
            300,
        )),
    }
}
fn tcp(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    ip: Option<IpAddr>,
    p: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if p.len() < 20 {
        return Err(PassiveParseError::Truncated);
    }
    let (s, d) = (
        u16::from_be_bytes([p[0], p[1]]),
        u16::from_be_bytes([p[2], p[3]]),
    );
    Ok(obs(
        i,
        t,
        m,
        ip,
        "tcp-flow",
        vec![
            (
                "src",
                format!("{}:{s}", ip.map_or("unknown".into(), |x| x.to_string())),
                EvidenceFamily::Service,
            ),
            ("dst", format!("unknown:{d}"), EvidenceFamily::Service),
            ("bytes", p.len().to_string(), EvidenceFamily::Service),
        ],
        300,
    ))
}
fn dhcp4(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    ip: Option<IpAddr>,
    q: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if q.len() < 240 || q[236..240] != [99, 130, 83, 99] {
        return Err(PassiveParseError::Metadata);
    }
    let mut a = 240;
    let mut v = Vec::new();
    let mut ttl = 300;
    while a < q.len() {
        let k = q[a];
        a += 1;
        if k == 255 {
            break;
        }
        if a >= q.len() {
            return Err(PassiveParseError::Truncated);
        }
        let n = q[a] as usize;
        a += 1;
        if a + n > q.len() {
            return Err(PassiveParseError::Truncated);
        }
        let z = &q[a..a + n];
        a += n;
        match k {
            12 => v.push(("hostname", text(z)?, EvidenceFamily::Naming)),
            54 if n == 4 => v.push((
                "server",
                Ipv4Addr::new(z[0], z[1], z[2], z[3]).to_string(),
                EvidenceFamily::Addressing,
            )),
            51 if n == 4 => ttl = u32::from_be_bytes(z.try_into().unwrap()).min(86400) as i64,
            61 => v.push(("client_id", hex(z), EvidenceFamily::Addressing)),
            _ => {}
        }
    }
    Ok(obs(i, t, m, ip, "dhcpv4", v, ttl))
}
fn dns(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    ip: Option<IpAddr>,
    q: &[u8],
    o: &PassiveOptions,
    p: &str,
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if q.len() < 12 {
        return Err(PassiveParseError::Truncated);
    }
    let n = name(q, 12, 0)?;
    if p == "dns-query" && !o.metadata_enabled {
        return Ok(obs(i, t, m, ip, p, vec![], 300));
    }
    let ttl = if q.len() > n.1 + 10 && q[n.1] == 192 {
        u32::from_be_bytes(q[n.1 + 6..n.1 + 10].try_into().unwrap()).min(86400) as i64
    } else {
        300
    };
    Ok(obs(
        i,
        t,
        m,
        ip,
        p,
        vec![(
            if p == "dns-query" { "query" } else { "name" },
            n.0,
            EvidenceFamily::Naming,
        )],
        ttl,
    ))
}
fn name(q: &[u8], mut a: usize, mut jumps: u8) -> Result<(String, usize), PassiveParseError> {
    let mut r = String::new();
    let end = a;
    while a < q.len() {
        if jumps > 16 {
            return Err(PassiveParseError::Metadata);
        }
        let n = q[a] as usize;
        a += 1;
        if n == 0 {
            return Ok((r, if jumps == 0 { a } else { end + 2 }));
        }
        if n & 192 == 192 {
            if a >= q.len() {
                return Err(PassiveParseError::Truncated);
            }
            a = ((n & 63) << 8) | q[a] as usize;
            jumps += 1;
            continue;
        }
        if n > 63 || a + n > q.len() || r.len() + n + 1 > 255 {
            return Err(PassiveParseError::Metadata);
        }
        if !r.is_empty() {
            r.push('.')
        }
        r.push_str(text(&q[a..a + n])?.as_str());
        a += n
    }
    Err(PassiveParseError::Truncated)
}
fn nbns(q: &[u8]) -> Result<String, PassiveParseError> {
    if q.len() < 13 {
        return Err(PassiveParseError::Truncated);
    }
    text(&q[13..q.len().min(29)])
}
fn ssdp(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    ip: Option<IpAddr>,
    q: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    let x = text(q)?;
    let mut v = Vec::new();
    let mut ttl = 300;
    for l in x.split("\r\n") {
        if let Some((k, z)) = l.split_once(':') {
            match k.to_ascii_lowercase().as_str() {
                "nt" | "st" => v.push(("st", z.trim().into(), EvidenceFamily::Service)),
                "usn" => v.push(("usn", z.trim().into(), EvidenceFamily::Service)),
                "location" => v.push(("location", z.trim().into(), EvidenceFamily::Service)),
                "cache-control" => {
                    ttl = z
                        .split('=')
                        .nth(1)
                        .and_then(|x| x.parse().ok())
                        .unwrap_or(300)
                }
                _ => {}
            }
        }
    }
    Ok(obs(i, t, m, ip, "ssdp-upnp", v, ttl.min(86400)))
}
fn soap(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    ip: Option<IpAddr>,
    q: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    let x = text(q)?;
    if x.contains("<!DOCTYPE") || x.contains("<!ENTITY") {
        return Err(PassiveParseError::Metadata);
    }
    let mut v = Vec::new();
    for (k, tag) in [
        ("endpoint", "EndpointReference"),
        ("types", "Types"),
        ("scopes", "Scopes"),
        ("xaddrs", "XAddrs"),
    ] {
        if let Some(a) = x.find(&format!(">")) {
            let _ = a;
        }
        if let Some(s) = x.find(&format!("<{tag}>")) {
            let b = s + tag.len() + 2;
            if let Some(e) = x[b..].find(&format!("</{tag}>")) {
                v.push((k, x[b..b + e].into(), EvidenceFamily::Service))
            }
        }
    }
    let p = if x.contains("onvif://") {
        "onvif-discovery"
    } else {
        "ws-discovery"
    };
    Ok(obs(i, t, m, ip, p, v, 300))
}
fn text(b: &[u8]) -> Result<String, PassiveParseError> {
    if b.len() > MAX_METADATA_BYTES {
        return Err(PassiveParseError::Metadata);
    }
    let s = std::str::from_utf8(b).map_err(|_| PassiveParseError::Metadata)?;
    if s.chars()
        .any(|c| c.is_control() && c != '\r' && c != '\n' && c != '\t')
    {
        return Err(PassiveParseError::Metadata);
    }
    Ok(s.into())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
