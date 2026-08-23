//! Offline, bounded passive observation normalization.  Input bytes are never retained.
use chrono::{DateTime, Duration, TimeZone, Utc};
use lattice_domain::{EvidenceFact, EvidenceFamily};
use serde::Serialize;
use std::{collections::BTreeMap, net::IpAddr};
use thiserror::Error;

pub const MAX_FRAME_BYTES: usize = 65_535;
pub const MAX_METADATA_BYTES: usize = 2_048;
const DEFAULT_TTL_SECONDS: i64 = 300;

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
    #[error("pcap header is truncated or unsupported")]
    PcapHeader,
    #[error("pcap packet is truncated")]
    Truncated,
    #[error("frame exceeds bounded maximum")]
    OversizedFrame,
    #[error("metadata is malformed or exceeds bounded maximum")]
    Metadata,
}

impl OfflinePassiveAdapter {
    pub fn ingest_pcap(
        &self,
        interface: &str,
        bytes: &[u8],
        options: &PassiveOptions,
    ) -> Result<Vec<PassiveObservation>, PassiveParseError> {
        if bytes.len() < 24 || bytes[..4] != [0xd4, 0xc3, 0xb2, 0xa1] {
            return Err(PassiveParseError::PcapHeader);
        }
        let mut at = 24;
        let mut result = Vec::new();
        while at < bytes.len() {
            if bytes.len() - at < 16 {
                return Err(PassiveParseError::Truncated);
            }
            let sec = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
            at += 16;
            if len > MAX_FRAME_BYTES {
                return Err(PassiveParseError::OversizedFrame);
            }
            if bytes.len() - at < len {
                return Err(PassiveParseError::Truncated);
            }
            let captured = Utc
                .timestamp_opt(i64::from(sec), 0)
                .single()
                .ok_or(PassiveParseError::PcapHeader)?;
            result.extend(self.normalize(interface, captured, &bytes[at..at + len], options)?);
            at += len;
        }
        Ok(result)
    }
}

impl PassiveAdapter for OfflinePassiveAdapter {
    fn normalize(
        &self,
        interface: &str,
        observed_at: DateTime<Utc>,
        frame: &[u8],
        options: &PassiveOptions,
    ) -> Result<Vec<PassiveObservation>, PassiveParseError> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(PassiveParseError::OversizedFrame);
        }
        if frame.len() < 14 {
            return Err(PassiveParseError::Truncated);
        }
        if frame[12..14] != [0x88, 0xb5] {
            return Ok(vec![]);
        }
        let text = std::str::from_utf8(&frame[14..]).map_err(|_| PassiveParseError::Metadata)?;
        if text.len() > MAX_METADATA_BYTES
            || text.contains("<!DOCTYPE")
            || text.contains("<!ENTITY")
        {
            return Err(PassiveParseError::Metadata);
        }
        let mut parts = text.splitn(3, '|');
        if parts.next() != Some("NH1") {
            return Err(PassiveParseError::Metadata);
        }
        let protocol = parts
            .next()
            .filter(|v| !v.is_empty() && v.len() <= 64)
            .ok_or(PassiveParseError::Metadata)?
            .to_owned();
        let data = parts.next().ok_or(PassiveParseError::Metadata)?;
        let fields: BTreeMap<_, _> = data
            .split(';')
            .filter_map(|v| v.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        if fields.is_empty()
            || fields.iter().any(|(k, v)| {
                k.len() > 64
                    || v.len() > 512
                    || !k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            })
        {
            return Err(PassiveParseError::Metadata);
        }
        if protocol == "dns-query" && !options.metadata_enabled {
            return Ok(vec![]);
        }
        let subject_mac = Some(
            frame[6..12]
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        );
        let subject_ip = fields.get("ip").and_then(|v| v.parse().ok());
        let ttl = fields
            .get("lease")
            .or_else(|| fields.get("ttl"))
            .or_else(|| fields.get("max_age"))
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| *v > 0 && *v <= 86_400)
            .unwrap_or(DEFAULT_TTL_SECONDS);
        let source = format!("passive.{protocol}");
        let mut facts = Vec::new();
        facts.push(fact(
            EvidenceFamily::LinkLayer,
            &source,
            "mac",
            subject_mac.clone().unwrap(),
            observed_at,
            ttl,
        ));
        for (key, value) in fields {
            let family = family_for(&protocol, &key);
            facts.push(fact(family, &source, &key, value, observed_at, ttl));
        }
        Ok(vec![PassiveObservation {
            interface: interface.to_owned(),
            observed_at,
            subject_mac,
            subject_ip,
            protocol,
            facts,
        }])
    }
}
fn family_for(protocol: &str, key: &str) -> EvidenceFamily {
    match (protocol, key) {
        (_, "ip") | (_, "binding") | (_, "client_id") | (_, "server") => EvidenceFamily::Addressing,
        ("dhcpv4", "hostname") | ("dhcpv6", "hostname") | (_, "name") | (_, "query") => {
            EvidenceFamily::Naming
        }
        ("ssdp-upnp", _) | ("ws-discovery", _) | ("onvif-discovery", _) | ("mdns-dns-sd", _) => {
            EvidenceFamily::Service
        }
        _ => EvidenceFamily::LinkLayer,
    }
}
fn fact(
    family: EvidenceFamily,
    source: &str,
    key: &str,
    value: String,
    observed_at: DateTime<Utc>,
    ttl: i64,
) -> EvidenceFact {
    EvidenceFact {
        family,
        source: source.to_owned(),
        key: key.to_owned(),
        value,
        confidence: 0.8,
        observed_at,
        expires_at: Some(observed_at + Duration::seconds(ttl)),
        owner_confirmed: false,
    }
}
