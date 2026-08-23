//! Bounded, offline normalization of Ethernet PCAPs. Packet bodies never leave this module.
use chrono::{DateTime, Duration, TimeZone, Utc};
use hickory_proto::{op::Message, rr::RData};
use lattice_domain::{EvidenceFact, EvidenceFamily};
use pcap_file::{DataLink, pcap::PcapReader};
use quick_xml::{
    NsReader,
    events::Event,
    name::{Namespace, QName, ResolveResult},
};
use serde::Serialize;
use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;
pub const MAX_FRAME_BYTES: usize = 65_535;
pub const MAX_METADATA_BYTES: usize = 2_048;
pub const MAX_PCAP_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PCAP_RECORDS: usize = 4_096;
pub const MAX_OBSERVATIONS: usize = 4_096;
pub const MAX_OBSERVATIONS_PER_FRAME: usize = 16;
pub const MAX_FACTS_PER_OBSERVATION: usize = 32;
pub const MAX_VALUE_BYTES: usize = 1_024;
pub const MAX_NORMALIZED_VALUE_BYTES: usize = 1024 * 1024;
const MAX_DHCP_OPTIONS: usize = 64;
const MAX_DUID_BYTES: usize = 128;
const MAX_IAADDRS: usize = 8;
const MAX_RELAY_MESSAGE_BYTES: usize = 16 * 1024;
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
#[derive(Clone, Copy)]
struct ActiveXmlField {
    key: &'static str,
    depth: usize,
    consumed: bool,
}
impl OfflinePassiveAdapter {
    pub fn ingest_pcap(
        &self,
        i: &str,
        b: &[u8],
        o: &PassiveOptions,
    ) -> Result<Vec<PassiveObservation>, PassiveParseError> {
        if b.len() > MAX_PCAP_BYTES {
            return Err(PassiveParseError::OversizedFrame);
        }
        let mut r = PcapReader::new(Cursor::new(b)).map_err(|_| PassiveParseError::PcapHeader)?;
        let h = r.header();
        if h.datalink != DataLink::ETHERNET
            || h.snaplen == 0
            || h.snaplen as usize > MAX_FRAME_BYTES
        {
            return Err(PassiveParseError::PcapHeader);
        }
        let mut out = Vec::new();
        let mut records = 0usize;
        let mut value_bytes = 0usize;
        while let Some(next) = r.next_packet() {
            records += 1;
            if records > MAX_PCAP_RECORDS {
                return Err(PassiveParseError::Metadata);
            }
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
            let observations = self.normalize(i, t, &p.data, o)?;
            if out.len() + observations.len() > MAX_OBSERVATIONS {
                return Err(PassiveParseError::Metadata);
            }
            for one in &observations {
                value_bytes = value_bytes
                    .checked_add(one.facts.iter().map(|fact| fact.value.len()).sum::<usize>())
                    .ok_or(PassiveParseError::Metadata)?;
                if value_bytes > MAX_NORMALIZED_VALUE_BYTES {
                    return Err(PassiveParseError::Metadata);
                }
            }
            out.extend(observations)
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
        let out = match u16::from_be_bytes([f[12], f[13]]) {
            0x0806 => arp(i, t, mac, &f[14..]),
            0x0800 => ipv4(i, t, mac, &f[14..], o),
            0x86dd => ipv6(i, t, mac, &f[14..], o),
            _ => Ok(vec![]),
        }?;
        validate_normalized(&out, MAX_OBSERVATIONS_PER_FRAME)?;
        Ok(out)
    }
}
fn fact(
    src: &str,
    key: &str,
    value: String,
    family: EvidenceFamily,
    t: DateTime<Utc>,
    ttl: i64,
) -> Result<EvidenceFact, PassiveParseError> {
    if key.len() > 64 || value.len() > MAX_VALUE_BYTES {
        return Err(PassiveParseError::Metadata);
    }
    let expires_at = t
        .checked_add_signed(Duration::seconds(ttl.clamp(1, 86400)))
        .ok_or(PassiveParseError::Metadata)?;
    Ok(EvidenceFact {
        family,
        source: src.into(),
        key: key.into(),
        value,
        confidence: 0.8,
        observed_at: t,
        expires_at: Some(expires_at),
        owner_confirmed: false,
    })
}
fn observation(
    i: &str,
    t: DateTime<Utc>,
    mac: Option<String>,
    ip: Option<IpAddr>,
    p: &str,
    vals: Vec<Val>,
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if vals.len() + usize::from(mac.is_some()) > MAX_FACTS_PER_OBSERVATION
        || vals
            .iter()
            .map(|(_, value, _, _)| value.len())
            .sum::<usize>()
            > MAX_NORMALIZED_VALUE_BYTES
    {
        return Err(PassiveParseError::Metadata);
    }
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
        )?)
    }
    for (k, v, f, ttl) in vals {
        facts.push(fact(&src, k, v, f, t, ttl)?)
    }
    Ok(vec![PassiveObservation {
        interface: i.into(),
        observed_at: t,
        subject_mac: mac,
        subject_ip: ip,
        protocol: p.into(),
        facts,
    }])
}
fn validate_normalized(
    out: &[PassiveObservation],
    observation_limit: usize,
) -> Result<(), PassiveParseError> {
    if out.len() > observation_limit {
        return Err(PassiveParseError::Metadata);
    }
    let mut total = 0usize;
    for one in out {
        if one.facts.len() > MAX_FACTS_PER_OBSERVATION {
            return Err(PassiveParseError::Metadata);
        }
        for value in one.facts.iter().map(|f| &f.value) {
            if value.len() > MAX_VALUE_BYTES {
                return Err(PassiveParseError::Metadata);
            }
            total = total
                .checked_add(value.len())
                .ok_or(PassiveParseError::Metadata)?;
        }
    }
    if total > MAX_NORMALIZED_VALUE_BYTES {
        return Err(PassiveParseError::Metadata);
    }
    Ok(())
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
    observation(
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
    )
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
        )?),
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
    observation(
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
    )
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
    observation(
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
    )
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
            Ok(observation(i, t, m, Some(src), "ipv6-ndp", v)?)
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
            )?)
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
    if q[1] != 1 || q[2] != 6 {
        return Err(PassiveParseError::Metadata);
    }
    let ci = Ipv4Addr::new(q[12], q[13], q[14], q[15]);
    let yi = Ipv4Addr::new(q[16], q[17], q[18], q[19]);
    let hlen = usize::from(q[2]);
    let client_mac = mac(&q[28..28 + hlen])?;
    let mut client = vec![(
        "chaddr",
        client_mac.clone(),
        EvidenceFamily::Addressing,
        300,
    )];
    if !ci.is_unspecified() {
        client.push(("ciaddr", ci.to_string(), EvidenceFamily::Addressing, 300))
    }
    if !yi.is_unspecified() {
        client.push(("yiaddr", yi.to_string(), EvidenceFamily::Addressing, 300))
    }
    let (mut at, mut lease, mut option_count) = (240, 300i64, 0usize);
    let (mut seen_hostname, mut seen_client, mut seen_server, mut seen_lease) =
        (false, false, false, false);
    let mut server_id = None;
    while at < q.len() {
        let code = q[at];
        at += 1;
        option_count += 1;
        if option_count > MAX_DHCP_OPTIONS {
            return Err(PassiveParseError::Metadata);
        }
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
            12 if !seen_hostname => {
                seen_hostname = true;
                client.push(("hostname", text(z)?, EvidenceFamily::Naming, lease))
            }
            12 => return Err(PassiveParseError::Metadata),
            51 if n == 4 => {
                if seen_lease {
                    return Err(PassiveParseError::Metadata);
                }
                seen_lease = true;
                lease = i64::from(u32::from_be_bytes(
                    z.try_into().map_err(|_| PassiveParseError::Metadata)?,
                ))
                .clamp(1, 86400)
            }
            54 if n == 4 && !seen_server => {
                seen_server = true;
                server_id = Some(Ipv4Addr::new(z[0], z[1], z[2], z[3]));
            }
            54 => return Err(PassiveParseError::Metadata),
            61 if !seen_client && !z.is_empty() && z.len() <= MAX_DUID_BYTES => {
                seen_client = true;
                client.push(("client_id", hex(z), EvidenceFamily::Addressing, lease))
            }
            61 => return Err(PassiveParseError::Metadata),
            _ => {}
        }
    }
    for x in &mut client {
        x.3 = lease
    }
    let client_ip = if !yi.is_unspecified() {
        Some(yi.into())
    } else if !ci.is_unspecified() {
        Some(ci.into())
    } else if q[0] == 1 && !src.is_unspecified() {
        Some(src)
    } else {
        None
    };
    let mut out = observation(i, t, Some(client_mac), client_ip, "dhcpv4", client)?;
    if let Some(server_id) = server_id {
        let server_ip = IpAddr::V4(server_id);
        let server_mac = (src == server_ip).then_some(m).flatten();
        out.extend(observation(
            i,
            t,
            server_mac,
            Some(server_ip),
            "dhcpv4",
            vec![
                (
                    "server_id",
                    server_id.to_string(),
                    EvidenceFamily::Addressing,
                    lease,
                ),
                (
                    "service",
                    "dhcp_server".into(),
                    EvidenceFamily::Service,
                    lease,
                ),
            ],
        )?);
    }
    Ok(out)
}
fn dhcp6(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    q: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    let mut budget = Dhcp6Budget::default();
    decode_dhcp6(i, t, m, Some(src), q, 0, &mut budget)
}
fn decode_dhcp6(
    i: &str,
    t: DateTime<Utc>,
    link_mac: Option<String>,
    source_ip: Option<IpAddr>,
    q: &[u8],
    relay_depth: u8,
    budget: &mut Dhcp6Budget,
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    if q.len() < 4 {
        return Err(PassiveParseError::Truncated);
    }
    let message_type = q[0];
    if matches!(message_type, 12 | 13) {
        if relay_depth >= 2 || q.len() < 34 || q[1] > 32 {
            return Err(PassiveParseError::Metadata);
        }
        let mut at = 34;
        let mut relay_message = None;
        while at < q.len() {
            budget.option_count += 1;
            if budget.option_count > MAX_DHCP_OPTIONS || at + 4 > q.len() {
                return Err(PassiveParseError::Metadata);
            }
            let code = u16::from_be_bytes([q[at], q[at + 1]]);
            let len = usize::from(u16::from_be_bytes([q[at + 2], q[at + 3]]));
            at += 4;
            if at + len > q.len() {
                return Err(PassiveParseError::Truncated);
            }
            if code == 9 {
                if relay_message.is_some() || len == 0 || len > MAX_RELAY_MESSAGE_BYTES {
                    return Err(PassiveParseError::Metadata);
                }
                relay_message = Some(&q[at..at + len]);
            }
            at += len;
        }
        return decode_dhcp6(
            i,
            t,
            None,
            None,
            relay_message.ok_or(PassiveParseError::Metadata)?,
            relay_depth + 1,
            budget,
        );
    }
    let client_origin = matches!(message_type, 1 | 3 | 4 | 5 | 6 | 8 | 9 | 11);
    let server_origin = matches!(message_type, 2 | 7 | 10);
    if !client_origin && !server_origin {
        return Err(PassiveParseError::Metadata);
    }
    let mut fields = Dhcp6Fields::default();
    parse_dhcp6_options(&q[4..], &mut fields, 0, budget)?;
    let client_mac = fields
        .client_mac
        .or_else(|| client_origin.then_some(link_mac.clone()).flatten());
    let client_ip = fields
        .client_ip
        .or_else(|| client_origin.then_some(source_ip).flatten());
    let mut out = if fields.client.is_empty() {
        Vec::new()
    } else {
        observation(i, t, client_mac, client_ip, "dhcpv6", fields.client)?
    };
    if !fields.server.is_empty() {
        fields.server.push((
            "service",
            "dhcpv6_server".into(),
            EvidenceFamily::Service,
            3600,
        ));
        let (server_mac, server_ip) = if server_origin {
            (link_mac, source_ip)
        } else {
            (None, None)
        };
        out.extend(observation(
            i,
            t,
            server_mac,
            server_ip,
            "dhcpv6",
            fields.server,
        )?);
    }
    Ok(out)
}
#[derive(Default)]
struct Dhcp6Fields {
    client: Vec<Val>,
    server: Vec<Val>,
    client_mac: Option<String>,
    client_ip: Option<IpAddr>,
    seen_client: bool,
    seen_server: bool,
    seen_fqdn: bool,
}
#[derive(Default)]
struct Dhcp6Budget {
    option_count: usize,
    iaaddr_count: usize,
}
fn parse_dhcp6_options(
    q: &[u8],
    v: &mut Dhcp6Fields,
    depth: u8,
    budget: &mut Dhcp6Budget,
) -> Result<(), PassiveParseError> {
    if depth > 3 {
        return Err(PassiveParseError::Metadata);
    }
    let mut at = 0;
    while at < q.len() {
        budget.option_count += 1;
        if budget.option_count > MAX_DHCP_OPTIONS {
            return Err(PassiveParseError::Metadata);
        }
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
            1 if !v.seen_client && !z.is_empty() && z.len() <= MAX_DUID_BYTES => {
                v.seen_client = true;
                v.client_mac = duid_mac(z);
                v.client
                    .push(("client_duid", hex(z), EvidenceFamily::Addressing, 3600));
            }
            1 => return Err(PassiveParseError::Metadata),
            2 if !v.seen_server && !z.is_empty() && z.len() <= MAX_DUID_BYTES => {
                v.seen_server = true;
                v.server
                    .push(("server_duid", hex(z), EvidenceFamily::Addressing, 3600));
            }
            2 => return Err(PassiveParseError::Metadata),
            3 if n >= 12 => parse_dhcp6_options(&z[12..], v, depth + 1, budget)?,
            5 if n >= 24 => {
                budget.iaaddr_count += 1;
                if budget.iaaddr_count > MAX_IAADDRS {
                    return Err(PassiveParseError::Metadata);
                }
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
                v.client_ip.get_or_insert(a.into());
                v.client.push((
                    "iaaddr",
                    a.to_string(),
                    EvidenceFamily::Addressing,
                    i64::from(valid).clamp(1, 86400),
                ));
                v.client.push((
                    "preferred_lifetime",
                    pref.to_string(),
                    EvidenceFamily::Addressing,
                    i64::from(valid).clamp(1, 86400),
                ));
                v.client.push((
                    "valid_lifetime",
                    valid.to_string(),
                    EvidenceFamily::Addressing,
                    i64::from(valid).clamp(1, 86400),
                ))
            }
            39 if !v.seen_fqdn && n > 1 && n <= 256 => {
                v.seen_fqdn = true;
                v.client.push((
                    "fqdn",
                    decode_plain_name(&z[1..])?,
                    EvidenceFamily::Naming,
                    3600,
                ));
            }
            39 => return Err(PassiveParseError::Metadata),
            _ => {}
        }
    }
    Ok(())
}
fn duid_mac(duid: &[u8]) -> Option<String> {
    let ty = u16::from_be_bytes([*duid.first()?, *duid.get(1)?]);
    let bytes = match ty {
        1 if duid.len() >= 14 => &duid[duid.len() - 6..],
        3 if duid.len() >= 10 => &duid[duid.len() - 6..],
        _ => return None,
    };
    mac(bytes).ok()
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
    observation(i, t, m, Some(src), p, v)
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
    observation(
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
    )
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
    observation(i, t, m, Some(src), "ssdp-upnp", v)
}
fn soap(
    i: &str,
    t: DateTime<Utc>,
    m: Option<String>,
    src: IpAddr,
    q: &[u8],
) -> Result<Vec<PassiveObservation>, PassiveParseError> {
    const SOAP12: &[u8] = b"http://www.w3.org/2003/05/soap-envelope";
    const WSA: &[u8] = b"http://www.w3.org/2005/08/addressing";
    const WSD09: &[u8] = b"http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01";
    const WSD05: &[u8] = b"http://schemas.xmlsoap.org/ws/2005/04/discovery";
    const ONVIF: &[u8] = b"http://www.onvif.org/ver10/network/wsdl";
    if q.len() > MAX_METADATA_BYTES {
        return Err(PassiveParseError::Metadata);
    }
    std::str::from_utf8(q).map_err(|_| PassiveParseError::Metadata)?;
    let mut r = NsReader::from_reader(q);
    r.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let (mut depth, mut events, mut current, mut v) =
        (0usize, 0usize, None::<ActiveXmlField>, Vec::new());
    let mut qname_stack: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    let (mut envelope, mut body, mut matches_depth, mut probe, mut endpoint) =
        (None, None, None, None, None);
    let mut onvif = false;
    loop {
        events += 1;
        if events > 256 {
            return Err(PassiveParseError::Metadata);
        }
        let (resolved, event) = r
            .read_resolved_event_into(&mut buffer)
            .map_err(|_| PassiveParseError::Metadata)?;
        match event {
            Event::Start(e) => {
                if current.is_some() {
                    return Err(PassiveParseError::Metadata);
                }
                depth += 1;
                if depth > 32 {
                    return Err(PassiveParseError::Metadata);
                }
                let local = e.local_name();
                let namespace = match &resolved {
                    ResolveResult::Bound(Namespace(uri)) => Some(uri.to_vec()),
                    _ => None,
                };
                qname_stack.push((e.name().as_ref().to_vec(), namespace));
                let namespace_is = |expected: &[u8]| matches!(resolved, ResolveResult::Bound(Namespace(uri)) if uri == expected);
                let is_wsd = namespace_is(WSD09) || namespace_is(WSD05);
                match local.as_ref() {
                    b"Envelope" if depth == 1 && namespace_is(SOAP12) => envelope = Some(depth),
                    b"Body" if envelope == Some(depth - 1) && namespace_is(SOAP12) => {
                        body = Some(depth)
                    }
                    b"ProbeMatches" if body == Some(depth - 1) && is_wsd => {
                        matches_depth = Some(depth)
                    }
                    b"ProbeMatch"
                        if is_wsd
                            && (body == Some(depth - 1) || matches_depth == Some(depth - 1)) =>
                    {
                        probe = Some(depth)
                    }
                    b"EndpointReference" if probe == Some(depth - 1) && namespace_is(WSA) => {
                        endpoint = Some(depth)
                    }
                    b"Address" if endpoint == Some(depth - 1) && namespace_is(WSA) => {
                        current = Some(ActiveXmlField {
                            key: "endpoint",
                            depth,
                            consumed: false,
                        })
                    }
                    b"Types" if probe == Some(depth - 1) && is_wsd => {
                        current = Some(ActiveXmlField {
                            key: "types",
                            depth,
                            consumed: false,
                        })
                    }
                    b"Scopes" if probe == Some(depth - 1) && is_wsd => {
                        current = Some(ActiveXmlField {
                            key: "scopes",
                            depth,
                            consumed: false,
                        })
                    }
                    b"XAddrs" if probe == Some(depth - 1) && is_wsd => {
                        current = Some(ActiveXmlField {
                            key: "xaddrs",
                            depth,
                            consumed: false,
                        })
                    }
                    _ => {}
                }
            }
            Event::Text(e) => {
                if let Some(mut active) = current {
                    if active.depth != depth {
                        return Err(PassiveParseError::Metadata);
                    }
                    if active.consumed {
                        return Err(PassiveParseError::Metadata);
                    }
                    active.consumed = true;
                    current = Some(active);
                    let k = active.key;
                    let z = e
                        .decode()
                        .map_err(|_| PassiveParseError::Metadata)?
                        .into_owned();
                    if z.len() > 1024 {
                        return Err(PassiveParseError::Metadata);
                    }
                    if k == "types" {
                        onvif |= z.split_ascii_whitespace().any(|qname| {
                            matches!(
                                r.resolver().resolve_element(QName(qname.as_bytes())).0,
                                ResolveResult::Bound(Namespace(uri)) if uri == ONVIF
                            )
                        });
                    } else if k == "scopes" {
                        onvif |= z
                            .split_ascii_whitespace()
                            .any(|scope| scope.starts_with("onvif://www.onvif.org/"));
                    }
                    v.push((k, z, EvidenceFamily::Service, 300));
                }
            }
            Event::End(e) => {
                let namespace = match &resolved {
                    ResolveResult::Bound(Namespace(uri)) => Some(*uri),
                    _ => None,
                };
                let (local, start_namespace) =
                    qname_stack.pop().ok_or(PassiveParseError::Metadata)?;
                if local.as_slice() != e.name().as_ref() || start_namespace.as_deref() != namespace
                {
                    return Err(PassiveParseError::Metadata);
                }
                if current.is_some_and(|active| active.depth == depth) {
                    current = None;
                }
                if endpoint == Some(depth) {
                    endpoint = None;
                }
                if probe == Some(depth) {
                    probe = None;
                }
                if matches_depth == Some(depth) {
                    matches_depth = None;
                }
                if body == Some(depth) {
                    body = None;
                }
                depth = depth.checked_sub(1).ok_or(PassiveParseError::Metadata)?
            }
            Event::Empty(_) | Event::CData(_) if current.is_some() => {
                return Err(PassiveParseError::Metadata);
            }
            Event::DocType(_) | Event::Decl(_) | Event::PI(_) | Event::GeneralRef(_) => {
                return Err(PassiveParseError::Metadata);
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if envelope.is_none() || !qname_stack.is_empty() || depth != 0 || v.is_empty() {
        return Err(PassiveParseError::Metadata);
    }
    observation(
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
    )
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
