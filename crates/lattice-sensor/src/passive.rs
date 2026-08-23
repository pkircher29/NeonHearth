//! Bounded, offline normalization of Ethernet PCAPs. Packet bodies never leave this module.
use chrono::{DateTime, Duration, TimeZone, Utc};
use hickory_proto::{op::Message, rr::RData};
use lattice_domain::{EvidenceFact, EvidenceFamily};
use pcap_file::{DataLink, pcap::PcapReader};
use quick_xml::{Reader, events::Event};
use serde::Serialize;
use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;
pub const MAX_FRAME_BYTES: usize = 65_535;
pub const MAX_METADATA_BYTES: usize = 2_048;
const DEFAULT_TTL: i64 = 300;
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
    #[error("invalid or unsupported pcap header")]
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
type Val = (&'static str, String, EvidenceFamily, i64);
impl OfflinePassiveAdapter {
    pub fn ingest_pcap(
        &self,
        i: &str,
        b: &[u8],
        o: &PassiveOptions,
    ) -> Result<Vec<PassiveObservation>, PassiveParseError> {
        let mut r = PcapReader::new(Cursor::new(b)).map_err(|_| PassiveParseError::PcapHeader)?;
        let h = r.header();
        if h.datalink != DataLink::ETHERNET
            || h.snaplen == 0
            || h.snaplen as usize > MAX_FRAME_BYTES
        {
            return Err(PassiveParseError::PcapHeader);
        }
        let mut out = Vec::new();
        while let Some(next) = r.next_packet() {
            let p = next.map_err(|_| PassiveParseError::Truncated)?;
            if p.data.len() > MAX_FRAME_BYTES
                || p.orig_len as usize > MAX_FRAME_BYTES
                || p.data.len() as u32 > p.orig_len
                || p.data.len() as u32 > h.snaplen
            {
                return Err(PassiveParseError::InvalidLength);
            }
            let secs =
                i64::try_from(p.timestamp.as_secs()).map_err(|_| PassiveParseError::PcapHeader)?;
            let t = Utc
                .timestamp_opt(secs, p.timestamp.subsec_nanos())
                .single()
                .ok_or(PassiveParseError::PcapHeader)?;
            out.extend(self.normalize(i, t, &p.data, o)?)
        }
        Ok(out)
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
        // Let a maintained wire codec validate the complete Ethernet/IP/transport
        // shape before the bounded protocol-specific extraction below.
        etherparse::SlicedPacket::from_ethernet(f).map_err(|_| PassiveParseError::InvalidLength)?;
        let mac = Some(mac(&f[6..12])?);
        match u16::from_be_bytes([f[12], f[13]]) {
            0x0806 => arp(i, t, mac, &f[14..]),
            0x0800 => ipv4(i, t, mac, &f[14..], o),
            0x86dd => ipv6(i, t, mac, &f[14..], o),
            _ => Ok(vec![]),
        }
    }
}
fn fact(
    src: &str,
    key: &str,
    value: String,
    family: EvidenceFamily,
    t: DateTime<Utc>,
    ttl: i64,
) -> EvidenceFact {
    EvidenceFact {
        family,
        source: src.into(),
        key: key.into(),
        value,
        confidence: 0.8,
        observed_at: t,
        expires_at: Some(t + Duration::seconds(ttl.clamp(1, 86400))),
        owner_confirmed: false,
    }
}
fn observation(
    i: &str,
    t: DateTime<Utc>,
    mac: Option<String>,
    ip: Option<IpAddr>,
    p: &str,
    vals: Vec<Val>,
) -> Vec<PassiveObservation> {
    let src = format!("passive.{p}");
    let mut facts = Vec::new();
    if let Some(m) = mac.clone() {
        facts.push(fact(
            &src,
            "mac",
            m,
            EvidenceFamily::LinkLayer,
            t,
            DEFAULT_TTL,
        ))
    }
    for (k, v, f, ttl) in vals {
        facts.push(fact(&src, k, v, f, t, ttl))
    }
    vec![PassiveObservation {
        interface: i.into(),
        observed_at: t,
        subject_mac: mac,
        subject_ip: ip,
        protocol: p.into(),
        facts,
    }]
}
fn mac(b: &[u8]) -> Result<String, PassiveParseError> {
    if b.len() != 6 {
        return Err(PassiveParseError::Truncated);
    }
    Ok(b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":"))
}
fn arp(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    p: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if p.len() < 28 {
        return Err(PassiveParseError::Truncated);
    }
    if p[..6] != [0, 1, 8, 0, 6, 4] {
        return Ok(vec![]);
    }
    let sip = Ipv4Addr::new(p[14], p[15], p[16], p[17]);
    let sm = mac(&p[8..14])?;
    Ok(observation(
        i,
        t,
        m,
        Some(sip.into()),
        "arp",
        vec![
            (
                "sender_ip",
                sip.to_string(),
                EvidenceFamily::Addressing,
                300,
            ),
            ("sender_mac", sm, EvidenceFamily::Addressing, 300),
        ],
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
    let ihl = usize::from(p[0] & 15) * 4;
    let len = usize::from(u16::from_be_bytes([p[2], p[3]]));
    if ihl < 20 || len < ihl || len > p.len() {
        return Err(PassiveParseError::InvalidLength);
    }
    if u16::from_be_bytes([p[6], p[7]]) & 0x3fff != 0 {
        return Ok(vec![]);
    }
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    let body = &p[ihl..len];
    match p[9] {
        17 => udp(i, t, m, src.into(), dst.into(), body, o),
        6 => tcp(i, t, m, src.into(), dst.into(), body),
        2 => igmp(i, t, m, src.into(), body),
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
    let plen = usize::from(u16::from_be_bytes([p[4], p[5]]));
    if plen > p.len() - 40 {
        return Err(PassiveParseError::InvalidLength);
    }
    let src =
        Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).map_err(|_| PassiveParseError::Truncated)?);
    let dst =
        Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).map_err(|_| PassiveParseError::Truncated)?);
    let (mut next, mut at) = (p[6], 40usize);
    let end = 40 + plen;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                if at + 2 > end {
                    return Err(PassiveParseError::Truncated);
                }
                let n = (usize::from(p[at + 1]) + 1) * 8;
                if at + n > end {
                    return Err(PassiveParseError::InvalidLength);
                }
                next = p[at];
                at += n
            }
            44 => {
                if at + 8 > end {
                    return Err(PassiveParseError::Truncated);
                }
                return Ok(vec![]);
            }
            _ => break,
        }
    }
    let body = &p[at..end];
    match next {
        17 => udp(i, t, m, src.into(), dst.into(), body, o),
        6 => tcp(i, t, m, src.into(), dst.into(), body),
        58 => icmp6(i, t, m, src.into(), body),
        _ => Ok(vec![]),
    }
}
fn udp(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    dst: IpAddr,
    p: &[u8],
    o: &PassiveOptions,
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if p.len() < 8 {
        return Err(PassiveParseError::Truncated);
    }
    let s = u16::from_be_bytes([p[0], p[1]]);
    let d = u16::from_be_bytes([p[2], p[3]]);
    let n = usize::from(u16::from_be_bytes([p[4], p[5]]));
    if n < 8 || n > p.len() {
        return Err(PassiveParseError::InvalidLength);
    }
    let q = &p[8..n];
    match (s, d) {
        (67 | 68, 67 | 68) => dhcp4(i, t, m, src, q),
        (546 | 547, 546 | 547) => dhcp6(i, t, m, src, q),
        (53, _) | (_, 53) => dns(i, t, m, src, q, o, "dns-query"),
        (5353, _) | (_, 5353) => dns(i, t, m, src, q, o, "mdns-dns-sd"),
        (5355, _) | (_, 5355) => dns(i, t, m, src, q, o, "llmnr"),
        (137, _) | (_, 137) => nbns(i, t, m, src, q),
        (1900, _) | (_, 1900) => ssdp(i, t, m, src, q),
        (3702, _) | (_, 3702) => soap(i, t, m, src, q),
        _ => Ok(observation(
            i,
            t,
            m,
            Some(src),
            "udp-flow",
            vec![
                ("src", format!("{src}:{s}"), EvidenceFamily::Service, 300),
                ("dst", format!("{dst}:{d}"), EvidenceFamily::Service, 300),
                ("bytes", q.len().to_string(), EvidenceFamily::Service, 300),
            ],
        )),
    }
}
fn tcp(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    dst: IpAddr,
    p: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if p.len() < 20 {
        return Err(PassiveParseError::Truncated);
    }
    let h = usize::from(p[12] >> 4) * 4;
    if h < 20 || h > p.len() {
        return Err(PassiveParseError::InvalidLength);
    }
    let s = u16::from_be_bytes([p[0], p[1]]);
    let d = u16::from_be_bytes([p[2], p[3]]);
    Ok(observation(
        i,
        t,
        m,
        Some(src),
        "tcp-flow",
        vec![
            ("src", format!("{src}:{s}"), EvidenceFamily::Service, 300),
            ("dst", format!("{dst}:{d}"), EvidenceFamily::Service, 300),
            (
                "bytes",
                (p.len() - h).to_string(),
                EvidenceFamily::Service,
                300,
            ),
        ],
    ))
}
fn igmp(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    p: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if p.len() < 8 {
        return Err(PassiveParseError::Truncated);
    }
    Ok(observation(
        i,
        t,
        m,
        Some(src),
        "igmp",
        vec![(
            "group",
            Ipv4Addr::new(p[4], p[5], p[6], p[7]).to_string(),
            EvidenceFamily::Service,
            300,
        )],
    ))
}
fn icmp6(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    p: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if p.len() < 8 {
        return Err(PassiveParseError::Truncated);
    }
    match p[0] {
        135 | 136 => {
            if p.len() < 24 {
                return Err(PassiveParseError::Truncated);
            }
            let target = Ipv6Addr::from(
                <[u8; 16]>::try_from(&p[8..24]).map_err(|_| PassiveParseError::Truncated)?,
            );
            let mut v = vec![(
                "target",
                target.to_string(),
                EvidenceFamily::Addressing,
                300,
            )];
            let mut at = 24;
            while at < p.len() {
                if at + 2 > p.len() {
                    return Err(PassiveParseError::Truncated);
                }
                let units = usize::from(p[at + 1]);
                if units == 0 || at + units * 8 > p.len() {
                    return Err(PassiveParseError::InvalidLength);
                }
                if matches!(p[at], 1 | 2) && units >= 1 {
                    v.push((
                        if p[at] == 1 {
                            "source_lladdr"
                        } else {
                            "target_lladdr"
                        },
                        mac(&p[at + 2..at + 8])?,
                        EvidenceFamily::Addressing,
                        300,
                    ))
                }
                at += units * 8
            }
            Ok(observation(i, t, m, Some(src), "ipv6-ndp", v))
        }
        130..=132 => {
            if p.len() < 24 {
                return Err(PassiveParseError::Truncated);
            }
            let g = Ipv6Addr::from(
                <[u8; 16]>::try_from(&p[8..24]).map_err(|_| PassiveParseError::Truncated)?,
            );
            Ok(observation(
                i,
                t,
                m,
                Some(src),
                "mld",
                vec![("group", g.to_string(), EvidenceFamily::Service, 300)],
            ))
        }
        _ => Ok(vec![]),
    }
}
fn dhcp4(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    q: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if q.len() < 240 || q[236..240] != [99, 130, 83, 99] {
        return Err(PassiveParseError::Metadata);
    }
    let ci = Ipv4Addr::new(q[12], q[13], q[14], q[15]);
    let yi = Ipv4Addr::new(q[16], q[17], q[18], q[19]);
    let hlen = usize::from(q[2]).min(16);
    if 28 + hlen > q.len() {
        return Err(PassiveParseError::Truncated);
    }
    let mut v = vec![(
        "chaddr",
        mac(&q[28..28 + hlen])?,
        EvidenceFamily::Addressing,
        300,
    )];
    if !ci.is_unspecified() {
        v.push(("ciaddr", ci.to_string(), EvidenceFamily::Addressing, 300))
    }
    if !yi.is_unspecified() {
        v.push(("yiaddr", yi.to_string(), EvidenceFamily::Addressing, 300))
    }
    let (mut at, mut lease) = (240, 300i64);
    while at < q.len() {
        let code = q[at];
        at += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            break;
        }
        if at >= q.len() {
            return Err(PassiveParseError::Truncated);
        }
        let n = usize::from(q[at]);
        at += 1;
        if at + n > q.len() {
            return Err(PassiveParseError::Truncated);
        }
        let z = &q[at..at + n];
        at += n;
        match code {
            12 => v.push(("hostname", text(z)?, EvidenceFamily::Naming, lease)),
            51 if n == 4 => {
                lease = i64::from(u32::from_be_bytes(
                    z.try_into().map_err(|_| PassiveParseError::Metadata)?,
                ))
                .clamp(1, 86400)
            }
            54 if n == 4 => v.push((
                "server_id",
                Ipv4Addr::new(z[0], z[1], z[2], z[3]).to_string(),
                EvidenceFamily::Addressing,
                lease,
            )),
            61 => v.push(("client_id", hex(z), EvidenceFamily::Addressing, lease)),
            _ => {}
        }
    }
    for x in &mut v {
        x.3 = lease
    }
    Ok(observation(i, t, m, Some(src), "dhcpv4", v))
}
fn dhcp6(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    q: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if q.len() < 4 {
        return Err(PassiveParseError::Truncated);
    }
    let mut v = Vec::new();
    parse_dhcp6_options(&q[4..], &mut v, 0)?;
    Ok(observation(i, t, m, Some(src), "dhcpv6", v))
}
fn parse_dhcp6_options(q: &[u8], v: &mut Vec<Val>, depth: u8) -> Result<(), PassiveParseError> {
    if depth > 3 {
        return Err(PassiveParseError::Metadata);
    }
    let mut at = 0;
    while at < q.len() {
        if at + 4 > q.len() {
            return Err(PassiveParseError::Truncated);
        }
        let c = u16::from_be_bytes([q[at], q[at + 1]]);
        let n = usize::from(u16::from_be_bytes([q[at + 2], q[at + 3]]));
        at += 4;
        if at + n > q.len() {
            return Err(PassiveParseError::Truncated);
        }
        let z = &q[at..at + n];
        at += n;
        match c {
            1 => v.push(("client_duid", hex(z), EvidenceFamily::Addressing, 3600)),
            2 => v.push(("server_duid", hex(z), EvidenceFamily::Addressing, 3600)),
            3 if n >= 12 => parse_dhcp6_options(&z[12..], v, depth + 1)?,
            5 if n >= 24 => {
                let a = Ipv6Addr::from(
                    <[u8; 16]>::try_from(&z[..16]).map_err(|_| PassiveParseError::Metadata)?,
                );
                let pref = u32::from_be_bytes(
                    z[16..20]
                        .try_into()
                        .map_err(|_| PassiveParseError::Metadata)?,
                );
                let valid = u32::from_be_bytes(
                    z[20..24]
                        .try_into()
                        .map_err(|_| PassiveParseError::Metadata)?,
                );
                v.push((
                    "iaaddr",
                    a.to_string(),
                    EvidenceFamily::Addressing,
                    i64::from(valid).clamp(1, 86400),
                ));
                v.push((
                    "preferred_lifetime",
                    pref.to_string(),
                    EvidenceFamily::Addressing,
                    i64::from(valid).clamp(1, 86400),
                ));
                v.push((
                    "valid_lifetime",
                    valid.to_string(),
                    EvidenceFamily::Addressing,
                    i64::from(valid).clamp(1, 86400),
                ))
            }
            39 if n > 1 => v.push((
                "fqdn",
                decode_plain_name(&z[1..])?,
                EvidenceFamily::Naming,
                3600,
            )),
            _ => {}
        }
    }
    Ok(())
}
fn dns(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    q: &[u8],
    o: &PassiveOptions,
    p: &str,
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if q.len() > MAX_METADATA_BYTES {
        return Err(PassiveParseError::Metadata);
    }
    let msg = Message::from_vec(q).map_err(|_| PassiveParseError::Metadata)?;
    let mut v = Vec::new();
    if o.metadata_enabled {
        for x in msg.queries() {
            v.push((
                "query",
                trim_name(&x.name().to_utf8()),
                EvidenceFamily::Naming,
                300,
            ))
        }
    }
    if p == "mdns-dns-sd" {
        for r in msg
            .answers()
            .iter()
            .chain(msg.name_servers())
            .chain(msg.additionals())
        {
            let ttl = i64::from(r.ttl()).clamp(1, 86400);
            let owner = trim_name(&r.name().to_utf8());
            match r.data() {
                RData::PTR(x) => v.push((
                    "service_instance",
                    format!("{owner} -> {}", trim_name(&x.0.to_utf8())),
                    EvidenceFamily::Service,
                    ttl,
                )),
                RData::SRV(x) => v.push((
                    "service_target",
                    format!("{}:{}", trim_name(&x.target().to_utf8()), x.port()),
                    EvidenceFamily::Service,
                    ttl,
                )),
                RData::TXT(x) => {
                    for z in x.iter() {
                        v.push(("txt", text(z)?, EvidenceFamily::Service, ttl))
                    }
                }
                RData::A(x) => v.push((
                    "host_address",
                    x.to_string(),
                    EvidenceFamily::Addressing,
                    ttl,
                )),
                RData::AAAA(x) => v.push((
                    "host_address",
                    x.to_string(),
                    EvidenceFamily::Addressing,
                    ttl,
                )),
                _ => {}
            }
        }
    }
    Ok(observation(i, t, m, Some(src), p, v))
}
fn nbns(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    q: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if q.len() < 46 || q[12] != 32 {
        return Err(PassiveParseError::Truncated);
    }
    let e = &q[13..45];
    let mut raw = [0u8; 16];
    for n in 0..16 {
        let a = e[n * 2];
        let b = e[n * 2 + 1];
        if !(b'A'..=b'P').contains(&a) || !(b'A'..=b'P').contains(&b) {
            return Err(PassiveParseError::Metadata);
        }
        raw[n] = (a - b'A') << 4 | (b - b'A')
    }
    let name = text(&raw[..15])?.trim_end().to_owned();
    Ok(observation(
        i,
        t,
        m,
        Some(src),
        "nbns",
        vec![
            ("name", name, EvidenceFamily::Naming, 300),
            (
                "suffix",
                format!("0x{:02x}", raw[15]),
                EvidenceFamily::Naming,
                300,
            ),
        ],
    ))
}
fn ssdp(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    q: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    let x = text(q)?;
    let mut lines = x.split("\r\n");
    let start = lines.next().ok_or(PassiveParseError::Metadata)?;
    if !(start == "M-SEARCH * HTTP/1.1"
        || start == "NOTIFY * HTTP/1.1"
        || start == "HTTP/1.1 200 OK")
    {
        return Err(PassiveParseError::Metadata);
    }
    let (mut v, mut ttl) = (Vec::new(), 300i64);
    for line in lines.take(64) {
        if line.is_empty() {
            break;
        }
        let (k, z) = line.split_once(':').ok_or(PassiveParseError::Metadata)?;
        if k.len() > 64 || z.len() > 1024 {
            return Err(PassiveParseError::Metadata);
        }
        match k.trim().to_ascii_lowercase().as_str() {
            "st" | "nt" => v.push((
                "service_type",
                z.trim().into(),
                EvidenceFamily::Service,
                ttl,
            )),
            "usn" => v.push(("usn", z.trim().into(), EvidenceFamily::Service, ttl)),
            "location" => v.push(("location", z.trim().into(), EvidenceFamily::Service, ttl)),
            "cache-control" => {
                if let Some(n) = z.to_ascii_lowercase().split(',').find_map(|x| {
                    x.trim()
                        .strip_prefix("max-age=")
                        .and_then(|x| x.parse::<i64>().ok())
                }) {
                    ttl = n.clamp(1, 86400)
                }
            }
            _ => {}
        }
    }
    for x in &mut v {
        x.3 = ttl
    }
    Ok(observation(i, t, m, Some(src), "ssdp-upnp", v))
}
fn soap(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    q: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if q.len() > MAX_METADATA_BYTES {
        return Err(PassiveParseError::Metadata);
    }
    std::str::from_utf8(q).map_err(|_| PassiveParseError::Metadata)?;
    let mut r = Reader::from_reader(q);
    r.config_mut().trim_text(true);
    let (mut depth, mut events, mut current, mut in_ep, mut envelope, mut v) = (
        0usize,
        0usize,
        None::<&'static str>,
        false,
        false,
        Vec::new(),
    );
    loop {
        events += 1;
        if events > 256 {
            return Err(PassiveParseError::Metadata);
        }
        match r.read_event() {
            Ok(Event::Start(e)) => {
                depth += 1;
                if depth > 32 {
                    return Err(PassiveParseError::Metadata);
                }
                match e.local_name().as_ref() {
                    b"Envelope" => envelope = true,
                    b"EndpointReference" => in_ep = true,
                    b"Address" if in_ep => current = Some("endpoint"),
                    b"Types" => current = Some("types"),
                    b"Scopes" => current = Some("scopes"),
                    b"XAddrs" => current = Some("xaddrs"),
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if let Some(k) = current {
                    let z = e
                        .decode()
                        .map_err(|_| PassiveParseError::Metadata)?
                        .into_owned();
                    if z.len() > 1024 {
                        return Err(PassiveParseError::Metadata);
                    }
                    v.push((k, z, EvidenceFamily::Service, 300));
                    current = None
                }
            }
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == b"EndpointReference" {
                    in_ep = false
                }
                depth = depth.checked_sub(1).ok_or(PassiveParseError::Metadata)?
            }
            Ok(Event::DocType(_) | Event::Decl(_) | Event::PI(_) | Event::GeneralRef(_)) => {
                return Err(PassiveParseError::Metadata);
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(PassiveParseError::Metadata),
        }
    }
    if !envelope || v.is_empty() {
        return Err(PassiveParseError::Metadata);
    }
    let onvif = v.iter().any(|(k, z, _, _)| {
        matches!(*k, "types" | "scopes")
            && (z.contains("NetworkVideoTransmitter")
                || z.starts_with("onvif://")
                || z.contains("www.onvif.org"))
    });
    Ok(observation(
        i,
        t,
        m,
        Some(src),
        if onvif {
            "onvif-discovery"
        } else {
            "ws-discovery"
        },
        v,
    ))
}
fn text(b: &[u8]) -> Result<String, PassiveParseError> {
    if b.len() > MAX_METADATA_BYTES {
        return Err(PassiveParseError::Metadata);
    }
    let s = std::str::from_utf8(b).map_err(|_| PassiveParseError::Metadata)?;
    if s.chars()
        .any(|c| c.is_control() && !matches!(c, '\r' | '\n' | '\t'))
    {
        return Err(PassiveParseError::Metadata);
    }
    Ok(s.into())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn trim_name(s: &str) -> String {
    let bytes = s.trim_end_matches('.').as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\'
            && at + 3 < bytes.len()
            && bytes[at + 1..at + 4].iter().all(u8::is_ascii_digit)
        {
            let value =
                (bytes[at + 1] - b'0') * 64 + (bytes[at + 2] - b'0') * 8 + bytes[at + 3] - b'0';
            out.push(value);
            at += 4;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
fn decode_plain_name(q: &[u8]) -> Result<String, PassiveParseError> {
    let (mut at, mut parts) = (0, Vec::new());
    while at < q.len() {
        let n = usize::from(q[at]);
        at += 1;
        if n == 0 {
            return Ok(parts.join("."));
        }
        if n > 63 || at + n > q.len() {
            return Err(PassiveParseError::Metadata);
        }
        parts.push(text(&q[at..at + n])?);
        at += n
    }
    Err(PassiveParseError::Truncated)
}
