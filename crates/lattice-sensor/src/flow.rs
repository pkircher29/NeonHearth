//! Bounded event-time flow rollups; source verification is engine-owned.
use chrono::{DateTime, Duration, Utc};
use lattice_domain::{ByteCount, Coverage, DeviceId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum DestinationCategory {
    Local,
    Lan,
    Internet,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FlowSourceId(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum VisibilityKind {
    VerifiedGateway,
    VerifiedMirror,
    VerifiedRouterCounter,
    CollectorLocal,
    ConfiguredInference,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRegistration {
    pub id: FlowSourceId,
    pub kind: VisibilityKind,
    pub verified: bool,
}
#[derive(Clone, Debug)]
pub struct FlowObservation {
    pub observation_id: u64,
    pub observed_at: DateTime<Utc>,
    pub device_id: DeviceId,
    pub upload: u64,
    pub download: u64,
    pub protocol: Protocol,
    pub destination: DestinationCategory,
    pub interface: u32,
    pub source: FlowSourceId,
}
#[derive(Clone, Debug)]
pub struct FlowEngineConfig {
    pub lateness: Duration,
    pub future_skew: Duration,
    pub max_devices: usize,
    pub max_sources: usize,
    pub max_open_buckets: usize,
    pub max_observation_ids: usize,
    pub max_work: usize,
}
impl Default for FlowEngineConfig {
    fn default() -> Self {
        Self {
            lateness: Duration::seconds(5),
            future_skew: Duration::seconds(5),
            max_devices: 1024,
            max_sources: 64,
            max_open_buckets: 4096,
            max_observation_ids: 8192,
            max_work: 10000,
        }
    }
}
#[derive(Debug, Error, Eq, PartialEq)]
pub enum FlowError {
    #[error("invalid configuration")]
    Config,
    #[error("unknown or unverified source")]
    Source,
    #[error("replay")]
    Replay,
    #[error("too late")]
    TooLate,
    #[error("watermark time invalid")]
    Time,
    #[error("capacity")]
    Capacity,
    #[error("overflow")]
    Overflow,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Rollup {
    pub bucket: DateTime<Utc>,
    pub device_id: DeviceId,
    pub protocol: Protocol,
    pub destination: DestinationCategory,
    pub interface: u32,
    pub bytes: ByteCount,
    pub coverage: Coverage,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finalized {
    pub seconds: Vec<Rollup>,
    pub minutes: Vec<Rollup>,
    pub hours: Vec<Rollup>,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Key {
    d: String,
    p: Protocol,
    c: DestinationCategory,
    i: u32,
}
pub struct FlowEngine {
    cfg: FlowEngineConfig,
    sources: BTreeMap<FlowSourceId, SourceRegistration>,
    obs: BTreeMap<u64, FlowObservation>,
    max_seen: Option<DateTime<Utc>>,
    watermark: Option<DateTime<Utc>>,
    emitted: Finalized,
}
impl FlowEngine {
    pub fn new(c: FlowEngineConfig) -> Result<Self, FlowError> {
        if c.lateness < Duration::zero()
            || c.future_skew < Duration::zero()
            || c.max_devices == 0
            || c.max_sources == 0
            || c.max_open_buckets == 0
            || c.max_observation_ids == 0
            || c.max_work == 0
        {
            return Err(FlowError::Config);
        }
        Ok(Self {
            cfg: c,
            sources: BTreeMap::new(),
            obs: BTreeMap::new(),
            max_seen: None,
            watermark: None,
            emitted: Finalized::default(),
        })
    }
    pub fn register_source(&mut self, s: SourceRegistration) -> Result<(), FlowError> {
        if self.sources.len() >= self.cfg.max_sources && !self.sources.contains_key(&s.id) {
            return Err(FlowError::Capacity);
        }
        if !s.verified {
            return Err(FlowError::Source);
        }
        self.sources.insert(s.id, s);
        Ok(())
    }
    pub fn observe(&mut self, o: FlowObservation) -> Result<(), FlowError> {
        let s = self.sources.get(&o.source).ok_or(FlowError::Source)?;
        if !s.verified || o.interface == 0 {
            return Err(FlowError::Source);
        }
        if self.obs.contains_key(&o.observation_id) {
            return Err(FlowError::Replay);
        }
        if self.obs.len() >= self.cfg.max_observation_ids {
            return Err(FlowError::Capacity);
        }
        if o.upload.checked_add(o.download).is_none() {
            return Err(FlowError::Overflow);
        }
        if let Some(w) = self.watermark {
            if o.observed_at < w - self.cfg.lateness {
                return Err(FlowError::TooLate);
            }
        }
        self.max_seen = Some(
            self.max_seen
                .map_or(o.observed_at, |x| x.max(o.observed_at)),
        );
        self.obs.insert(o.observation_id, o);
        Ok(())
    }
    pub fn advance_watermark(&mut self, w: DateTime<Utc>) -> Result<Finalized, FlowError> {
        if let Some(old) = self.watermark {
            if w < old {
                return Err(FlowError::Time);
            }
        }
        if let Some(max) = self.max_seen {
            if w > max + self.cfg.future_skew {
                return Err(FlowError::Time);
            }
        }
        self.watermark = Some(w);
        self.build()
    }
    pub fn finalized(&self) -> &Finalized {
        &self.emitted
    }
    fn build(&mut self) -> Result<Finalized, FlowError> {
        let w = self.watermark.ok_or(FlowError::Time)?;
        let mut sec = BTreeMap::new();
        for o in self.obs.values() {
            let t = o.observed_at.timestamp();
            if t.checked_add(1).ok_or(FlowError::Overflow)? > w.timestamp() {
                continue;
            }
            let k = Key {
                d: o.device_id.to_string(),
                p: o.protocol,
                c: o.destination,
                i: o.interface,
            };
            let cov = coverage(self.sources[&o.source].kind);
            let e = sec.entry((t, k)).or_insert((
                ByteCount {
                    upload: 0,
                    download: 0,
                },
                cov,
            ));
            e.0.upload =
                e.0.upload
                    .checked_add(o.upload)
                    .ok_or(FlowError::Overflow)?;
            e.0.download =
                e.0.download
                    .checked_add(o.download)
                    .ok_or(FlowError::Overflow)?;
            e.1 = merge(e.1, cov);
        }
        let min = agg(&sec, 60)?;
        let hour = agg(&min, 60)?;
        self.emitted = Finalized {
            seconds: rows(&sec)?,
            minutes: rows(&min)?,
            hours: rows(&hour)?,
        };
        Ok(self.emitted.clone())
    }
}
fn coverage(k: VisibilityKind) -> Coverage {
    match k {
        VisibilityKind::VerifiedGateway | VisibilityKind::VerifiedMirror => Coverage::Complete,
        VisibilityKind::VerifiedRouterCounter => Coverage::RouterReported,
        VisibilityKind::CollectorLocal => Coverage::LocalOnly,
        VisibilityKind::ConfiguredInference => Coverage::Estimated,
    }
}
fn merge(a: Coverage, b: Coverage) -> Coverage {
    if a == Coverage::Estimated || b == Coverage::Estimated {
        Coverage::Estimated
    } else if a == Coverage::Complete && b == Coverage::Complete {
        Coverage::Complete
    } else if a == Coverage::RouterReported && b == Coverage::RouterReported {
        Coverage::RouterReported
    } else {
        Coverage::LocalOnly
    }
}
fn agg(
    m: &BTreeMap<(i64, Key), (ByteCount, Coverage)>,
    n: i64,
) -> Result<BTreeMap<(i64, Key), (ByteCount, Coverage)>, FlowError> {
    let mut x = BTreeMap::new();
    for ((t, k), (b, c)) in m {
        let q = t.div_euclid(n).checked_mul(n).ok_or(FlowError::Overflow)?;
        let e = x.entry((q, k.clone())).or_insert((
            ByteCount {
                upload: 0,
                download: 0,
            },
            *c,
        ));
        e.0.upload =
            e.0.upload
                .checked_add(b.upload)
                .ok_or(FlowError::Overflow)?;
        e.0.download =
            e.0.download
                .checked_add(b.download)
                .ok_or(FlowError::Overflow)?;
        e.1 = merge(e.1, *c);
    }
    Ok(x)
}
fn rows(m: &BTreeMap<(i64, Key), (ByteCount, Coverage)>) -> Result<Vec<Rollup>, FlowError> {
    m.iter()
        .map(|((t, k), (b, c))| {
            Ok(Rollup {
                bucket: DateTime::from_timestamp(*t, 0).ok_or(FlowError::Overflow)?,
                device_id: DeviceId::parse(&k.d).map_err(|_| FlowError::Config)?,
                protocol: k.p,
                destination: k.c,
                interface: k.i,
                bytes: *b,
                coverage: *c,
            })
        })
        .collect()
}
