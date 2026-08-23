//! Bounded deterministic byte-flow aggregation. Inputs contain categories only;
//! packet bodies and destination addresses are intentionally not represented.
use chrono::{DateTime, Duration, Utc};
use lattice_domain::{ByteCount, Coverage, DeviceId};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DestinationCategory {
    Local,
    Lan,
    Internet,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    VerifiedGateway,
    VerifiedMirror,
    VerifiedRouterCounter,
    CollectorCapture,
    Inferred,
}
impl SourceKind {
    fn coverage(self) -> Result<Coverage, FlowError> {
        Ok(match self {
            Self::VerifiedGateway | Self::VerifiedMirror => Coverage::Complete,
            Self::VerifiedRouterCounter => Coverage::RouterReported,
            Self::CollectorCapture => Coverage::LocalOnly,
            Self::Inferred => return Err(FlowError::UnverifiedSource),
        })
    }
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
    pub source: SourceKind,
    pub coverage: Coverage,
}
#[derive(Clone, Debug)]
pub struct FlowEngineConfig {
    pub lateness: Duration,
    pub max_devices: usize,
    pub max_open_buckets: usize,
    pub max_observation_ids: usize,
    pub max_work: usize,
}
impl Default for FlowEngineConfig {
    fn default() -> Self {
        Self {
            lateness: Duration::seconds(5),
            max_devices: 1024,
            max_open_buckets: 4096,
            max_observation_ids: 8192,
            max_work: 10000,
        }
    }
}
#[derive(Debug, Error, Eq, PartialEq)]
pub enum FlowError {
    #[error("unverified source")]
    UnverifiedSource,
    #[error("replay or observation capacity")]
    Replay,
    #[error("too late")]
    TooLate,
    #[error("future skew or clock rollback")]
    Time,
    #[error("capacity")]
    Capacity,
    #[error("byte overflow")]
    Overflow,
    #[error("invalid coverage")]
    Coverage,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Key {
    device_order: String,
    protocol: Protocol,
    destination: DestinationCategory,
    interface: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rollup {
    pub bucket: DateTime<Utc>,
    pub device_id: DeviceId,
    pub protocol: Protocol,
    pub destination: DestinationCategory,
    pub interface: u32,
    pub bytes: ByteCount,
    pub coverage: Coverage,
}
#[derive(Clone, Debug, Default)]
pub struct Finalized {
    pub seconds: Vec<Rollup>,
    pub minutes: Vec<Rollup>,
    pub hours: Vec<Rollup>,
}
pub struct FlowEngine {
    cfg: FlowEngineConfig,
    observations: BTreeMap<u64, FlowObservation>,
    max_seen: Option<DateTime<Utc>>,
    finalized: BTreeMap<(i64, Key), (ByteCount, Coverage)>,
}
impl FlowEngine {
    pub fn new(cfg: FlowEngineConfig) -> Result<Self, FlowError> {
        if cfg.max_devices == 0
            || cfg.max_open_buckets == 0
            || cfg.max_observation_ids == 0
            || cfg.max_work == 0
        {
            return Err(FlowError::Capacity);
        }
        Ok(Self {
            cfg,
            observations: BTreeMap::new(),
            max_seen: None,
            finalized: BTreeMap::new(),
        })
    }
    pub fn observe(&mut self, o: FlowObservation) -> Result<(), FlowError> {
        let cov = o.source.coverage()?;
        if o.coverage != cov {
            return Err(FlowError::Coverage);
        }
        if self.observations.contains_key(&o.observation_id) {
            return Err(FlowError::Replay);
        }
        if self.observations.len() >= self.cfg.max_observation_ids {
            return Err(FlowError::Capacity);
        }
        if let Some(max) = self.max_seen {
            if o.observed_at < max - self.cfg.lateness {
                return Err(FlowError::TooLate);
            }
        }
        if o.upload.checked_add(o.download).is_none() {
            return Err(FlowError::Overflow);
        }
        if self
            .observations
            .iter()
            .any(|(_, x)| x.device_id == o.device_id)
            == false
            && self
                .observations
                .values()
                .map(|x| x.device_id.to_string())
                .collect::<BTreeSet<_>>()
                .len()
                >= self.cfg.max_devices
        {
            return Err(FlowError::Capacity);
        }
        self.max_seen = Some(
            self.max_seen
                .map_or(o.observed_at, |x| x.max(o.observed_at)),
        );
        self.observations.insert(o.observation_id, o);
        Ok(())
    }
    pub fn finalize_until(&mut self, until: DateTime<Utc>) -> Result<Finalized, FlowError> {
        let max = self.max_seen.ok_or(FlowError::Time)?;
        if until > max + self.cfg.lateness { /* permitted */ }
        let mut sec = BTreeMap::<(i64, Key), (ByteCount, Coverage)>::new();
        for o in self.observations.values() {
            let s = o.observed_at.timestamp();
            let k = Key {
                device_order: o.device_id.to_string(),
                protocol: o.protocol,
                destination: o.destination,
                interface: o.interface,
            };
            let e = sec.entry((s, k)).or_insert((
                ByteCount {
                    upload: 0,
                    download: 0,
                },
                o.coverage,
            ));
            e.0.upload =
                e.0.upload
                    .checked_add(o.upload)
                    .ok_or(FlowError::Overflow)?;
            e.0.download =
                e.0.download
                    .checked_add(o.download)
                    .ok_or(FlowError::Overflow)?;
            e.1 = merge(e.1, o.coverage);
        }
        self.finalized = sec.clone();
        Ok(Finalized {
            seconds: rows(&sec, 1)?,
            minutes: aggregate(&sec, 60)?,
            hours: aggregate(&sec, 3600)?,
        })
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
fn rows(
    m: &BTreeMap<(i64, Key), (ByteCount, Coverage)>,
    _n: i64,
) -> Result<Vec<Rollup>, FlowError> {
    Ok(m.iter()
        .map(|((t, k), (b, c))| Rollup {
            bucket: DateTime::from_timestamp(*t, 0).unwrap(),
            device_id: DeviceId::parse(&k.device_order).unwrap(),
            protocol: k.protocol,
            destination: k.destination,
            interface: k.interface,
            bytes: *b,
            coverage: *c,
        })
        .collect())
}
fn aggregate(
    m: &BTreeMap<(i64, Key), (ByteCount, Coverage)>,
    n: i64,
) -> Result<Vec<Rollup>, FlowError> {
    let mut a = BTreeMap::new();
    for ((t, k), (b, c)) in m {
        let q = t.div_euclid(n) * n;
        let e = a.entry((q, k.clone())).or_insert((
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
    rows(&a, n)
}
