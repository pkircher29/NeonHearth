//! Bounded event-time network-flow rollups.
//!
//! Trust is established once, when the engine receives its closed source registry. Observations
//! carry only an opaque source ID and therefore cannot claim complete visibility. Seconds close
//! when `bucket + 1s <= watermark`; accepted late events revise that second and deterministically
//! revise its minute and hour parents. Replay IDs expire only after the configured replay TTL,
//! which must cover lateness; after expiry an old event is still rejected by the lateness gate,
//! while a genuinely new in-window event reusing the ID is accepted.
use chrono::{DateTime, Duration, Utc};
use lattice_domain::{ByteCount, Coverage, DeviceId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationCategory {
    Local,
    Lan,
    Internet,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FlowSourceId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisibilityKind {
    Gateway,
    Bridge,
    Mirror,
    RouterCounter,
    Local,
    Inference,
}

/// An engine-owned trust registration. Its closed constructors are the only way to create one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRegistration {
    id: FlowSourceId,
    kind: VisibilityKind,
}
impl SourceRegistration {
    pub fn verified_gateway(id: FlowSourceId) -> Self {
        Self {
            id,
            kind: VisibilityKind::Gateway,
        }
    }
    pub fn verified_bridge(id: FlowSourceId) -> Self {
        Self {
            id,
            kind: VisibilityKind::Bridge,
        }
    }
    pub fn verified_mirror(id: FlowSourceId) -> Self {
        Self {
            id,
            kind: VisibilityKind::Mirror,
        }
    }
    pub fn verified_router_counter(id: FlowSourceId) -> Self {
        Self {
            id,
            kind: VisibilityKind::RouterCounter,
        }
    }
    pub fn collector_local(id: FlowSourceId) -> Self {
        Self {
            id,
            kind: VisibilityKind::Local,
        }
    }
    pub fn configured_inference(id: FlowSourceId) -> Self {
        Self {
            id,
            kind: VisibilityKind::Inference,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReplayId(pub u128);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct DestinationMetadata {
    pub ip: Option<IpAddr>,
    pub domain: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowObservation {
    pub replay_id: ReplayId,
    pub event_time: DateTime<Utc>,
    pub arrival_time: DateTime<Utc>,
    pub device_id: DeviceId,
    pub upload: u64,
    pub download: u64,
    pub protocol: Protocol,
    pub destination: DestinationCategory,
    pub interface: u32,
    pub source: FlowSourceId,
    pub metadata: Option<DestinationMetadata>,
}

#[derive(Clone, Debug)]
pub struct FlowEngineConfig {
    pub lateness: Duration,
    pub future_skew: Duration,
    pub replay_ttl: Duration,
    pub correction_retention: Duration,
    pub retain_destination_metadata: bool,
    pub max_domain_bytes: usize,
    pub max_devices: usize,
    pub max_sources: usize,
    pub max_open_rows: usize,
    pub max_replay_ids: usize,
    pub max_finalized_rows: usize,
    pub max_outputs_per_call: usize,
    pub max_work_per_call: usize,
}
impl Default for FlowEngineConfig {
    fn default() -> Self {
        Self {
            lateness: Duration::seconds(5),
            future_skew: Duration::seconds(5),
            replay_ttl: Duration::minutes(10),
            correction_retention: Duration::hours(24),
            retain_destination_metadata: false,
            max_domain_bytes: 253,
            max_devices: 1024,
            max_sources: 64,
            max_open_rows: 4096,
            max_replay_ids: 8192,
            max_finalized_rows: 65_536,
            max_outputs_per_call: 16_384,
            max_work_per_call: 262_144,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum FlowError {
    #[error("invalid configuration")]
    Config,
    #[error("capacity exhausted")]
    Capacity,
    #[error("unknown source")]
    UnknownSource,
    #[error("replayed observation")]
    Replay,
    #[error("event is beyond the correction window")]
    TooLate,
    #[error("invalid or non-monotonic time")]
    Time,
    #[error("event exceeds allowed future skew")]
    FutureSkew,
    #[error("interface must be nonzero")]
    Interface,
    #[error("invalid destination metadata")]
    Metadata,
    #[error("checked arithmetic overflow")]
    Overflow,
    #[error("per-call output limit exceeded")]
    OutputLimit,
    #[error("per-call work limit exceeded")]
    WorkLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Second,
    Minute,
    Hour,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollupKey {
    pub resolution: Resolution,
    pub bucket: DateTime<Utc>,
    pub device_id: DeviceId,
    pub protocol: Protocol,
    pub destination: DestinationCategory,
    pub interface: u32,
    pub metadata: Option<DestinationMetadata>,
}
impl Ord for RollupKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.resolution,
            self.bucket,
            self.device_id.to_string(),
            self.protocol,
            self.destination,
            self.interface,
            &self.metadata,
        )
            .cmp(&(
                other.resolution,
                other.bucket,
                other.device_id.to_string(),
                other.protocol,
                other.destination,
                other.interface,
                &other.metadata,
            ))
    }
}
impl PartialOrd for RollupKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rollup {
    pub key: RollupKey,
    pub bytes: ByteCount,
    pub coverage: Coverage,
    pub metadata: Option<DestinationMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "rollup", rename_all = "snake_case")]
pub enum RollupChange {
    Upsert(Rollup),
    Correction(Rollup),
    Retire(Retirement),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Retirement {
    pub key: RollupKey,
    pub cache_only: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowSnapshot {
    pub watermark: Option<DateTime<Utc>>,
    pub rollups: Vec<Rollup>,
    pub open_row_count: usize,
    pub replay_ids: Vec<(ReplayId, DateTime<Utc>)>,
    pub devices: Vec<String>,
    pub last_arrival: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct SecondKey {
    epoch: i64,
    device: String,
    protocol: Protocol,
    destination: DestinationCategory,
    interface: u32,
    metadata: Option<DestinationMetadata>,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct SourceSecondKey {
    base: SecondKey,
    source: FlowSourceId,
}
#[derive(Clone, Debug)]
struct ReplayEntry {
    arrival: DateTime<Utc>,
    device: String,
}

#[derive(Clone, Debug)]
pub struct FlowEngine {
    cfg: FlowEngineConfig,
    sources: BTreeMap<FlowSourceId, VisibilityKind>,
    seconds: BTreeMap<SourceSecondKey, ByteCount>,
    replay: BTreeMap<ReplayId, ReplayEntry>,
    devices: BTreeSet<String>,
    last_arrival: Option<DateTime<Utc>>,
    watermark: Option<DateTime<Utc>>,
    emitted: BTreeMap<RollupKey, Rollup>,
}

impl FlowEngine {
    pub fn new(
        cfg: FlowEngineConfig,
        registrations: Vec<SourceRegistration>,
    ) -> Result<Self, FlowError> {
        if cfg.lateness < Duration::zero()
            || cfg.future_skew < Duration::zero()
            || cfg.replay_ttl <= Duration::zero()
            || cfg.correction_retention < cfg.lateness
            || cfg.replay_ttl < cfg.lateness
            || cfg.max_domain_bytes == 0
            || cfg.max_devices == 0
            || cfg.max_sources == 0
            || cfg.max_open_rows == 0
            || cfg.max_replay_ids == 0
            || cfg.max_finalized_rows == 0
            || cfg.max_outputs_per_call == 0
            || cfg.max_work_per_call == 0
        {
            return Err(FlowError::Config);
        }
        let mut sources = BTreeMap::new();
        for r in registrations {
            if sources.insert(r.id, r.kind).is_some() {
                return Err(FlowError::Config);
            }
        }
        if sources.len() > cfg.max_sources {
            return Err(FlowError::Capacity);
        }
        if sources.is_empty() {
            return Err(FlowError::Config);
        }
        Ok(Self {
            cfg,
            sources,
            seconds: BTreeMap::new(),
            replay: BTreeMap::new(),
            devices: BTreeSet::new(),
            last_arrival: None,
            watermark: None,
            emitted: BTreeMap::new(),
        })
    }

    pub fn observe(&mut self, mut o: FlowObservation) -> Result<(), FlowError> {
        let kind = *self
            .sources
            .get(&o.source)
            .ok_or(FlowError::UnknownSource)?;
        if o.interface == 0 {
            return Err(FlowError::Interface);
        }
        o.upload
            .checked_add(o.download)
            .ok_or(FlowError::Overflow)?;
        checked_epoch(o.event_time)?;
        checked_epoch(o.arrival_time)?;
        if let Some(last) = self.last_arrival
            && o.arrival_time < last
        {
            return Err(FlowError::Time);
        }
        let future = o
            .arrival_time
            .checked_add_signed(self.cfg.future_skew)
            .ok_or(FlowError::Overflow)?;
        if o.event_time > future {
            return Err(FlowError::FutureSkew);
        }
        let epoch = o.event_time.timestamp();
        let close = epoch.checked_add(1).ok_or(FlowError::Overflow)?;
        let late_edge = DateTime::from_timestamp(close, 0)
            .ok_or(FlowError::Overflow)?
            .checked_add_signed(self.cfg.lateness)
            .ok_or(FlowError::Overflow)?;
        if o.arrival_time > late_edge {
            return Err(FlowError::TooLate);
        }
        if let Some(w) = self.watermark
            && w > late_edge
        {
            return Err(FlowError::TooLate);
        }
        let cutoff = o
            .arrival_time
            .checked_sub_signed(self.cfg.replay_ttl)
            .ok_or(FlowError::Overflow)?;
        let observe_work = self
            .replay
            .len()
            .checked_mul(3)
            .and_then(|n| n.checked_add(self.seconds.len()))
            .and_then(|n| n.checked_add(1))
            .ok_or(FlowError::Overflow)?;
        if observe_work > self.cfg.max_work_per_call {
            return Err(FlowError::WorkLimit);
        }
        let retained_replays = self.replay.values().filter(|e| e.arrival >= cutoff).count();
        if self
            .replay
            .get(&o.replay_id)
            .is_some_and(|e| e.arrival >= cutoff)
        {
            return Err(FlowError::Replay);
        }
        if retained_replays >= self.cfg.max_replay_ids {
            return Err(FlowError::Capacity);
        }
        normalize_metadata(&mut o.metadata, &self.cfg)?;
        let device_key = o.device_id.to_string();
        let mut active_devices: BTreeSet<String> = self
            .seconds
            .keys()
            .map(|k| k.base.device.clone())
            .chain(
                self.replay
                    .values()
                    .filter(|e| e.arrival >= cutoff)
                    .map(|e| e.device.clone()),
            )
            .collect();
        let base = SecondKey {
            epoch,
            device: device_key.clone(),
            protocol: o.protocol,
            destination: o.destination,
            interface: o.interface,
            metadata: o.metadata,
        };
        let key = SourceSecondKey {
            base,
            source: o.source,
        };
        if !active_devices.contains(&device_key) && active_devices.len() >= self.cfg.max_devices {
            return Err(FlowError::Capacity);
        }
        if !self.seconds.contains_key(&key) && self.seconds.len() >= self.cfg.max_open_rows {
            return Err(FlowError::Capacity);
        }
        let old = self.seconds.get(&key).copied().unwrap_or(ByteCount {
            upload: 0,
            download: 0,
        });
        let value = ByteCount {
            upload: old
                .upload
                .checked_add(o.upload)
                .ok_or(FlowError::Overflow)?,
            download: old
                .download
                .checked_add(o.download)
                .ok_or(FlowError::Overflow)?,
        };
        value
            .upload
            .checked_add(value.download)
            .ok_or(FlowError::Overflow)?;
        let _ = kind;
        self.replay.retain(|_, e| e.arrival >= cutoff);
        self.replay.insert(
            o.replay_id,
            ReplayEntry {
                arrival: o.arrival_time,
                device: device_key.clone(),
            },
        );
        active_devices.insert(device_key);
        self.devices = active_devices;
        self.seconds.insert(key, value);
        self.last_arrival = Some(o.arrival_time);
        Ok(())
    }

    pub fn advance_watermark_at(
        &mut self,
        next: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Vec<RollupChange>, FlowError> {
        checked_epoch(next)?;
        checked_epoch(now)?;
        if next > now {
            return Err(FlowError::FutureSkew);
        }
        if self.last_arrival.is_some_and(|old| now < old) {
            return Err(FlowError::Time);
        }
        if self.watermark.is_some_and(|old| next < old) {
            return Err(FlowError::Time);
        }
        let correction_cache_horizon =
            std::cmp::min(self.cfg.correction_retention, self.cfg.lateness);
        let cutoff = next
            .checked_sub_signed(correction_cache_horizon)
            .ok_or(FlowError::Overflow)?
            .timestamp();
        // Filtering, three aggregation levels, and diffing are all charged before cloning.
        let required_work = self
            .seconds
            .len()
            .checked_mul(8)
            .and_then(|n| {
                self.emitted
                    .len()
                    .checked_mul(4)
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(FlowError::Overflow)?;
        if required_work > self.cfg.max_work_per_call {
            return Err(FlowError::WorkLimit);
        }
        let selected = select_seconds(&self.seconds, &self.sources, next)?;
        let mut proposed = self.emitted.clone();
        for (base, value) in &selected {
            let second = make_rollup(Resolution::Second, base.epoch, base, value)?;
            let old = proposed.get(&second.key).cloned();
            if old.as_ref() != Some(&second) {
                proposed.insert(second.key.clone(), second.clone());
                adjust_parent(
                    &mut proposed,
                    Resolution::Minute,
                    60,
                    base,
                    old.as_ref(),
                    &second,
                )?;
                adjust_parent(
                    &mut proposed,
                    Resolution::Hour,
                    3600,
                    base,
                    old.as_ref(),
                    &second,
                )?;
            }
        }
        proposed.retain(|k, _| !retired(k, next, self.cfg.lateness));
        if proposed.len() > self.cfg.max_finalized_rows {
            return Err(FlowError::Capacity);
        }
        let mut changes = Vec::new();
        let mut work = required_work;
        let keys: BTreeSet<_> = self
            .emitted
            .keys()
            .chain(proposed.keys())
            .cloned()
            .collect();
        for k in keys {
            work = work.checked_add(1).ok_or(FlowError::Overflow)?;
            if work > self.cfg.max_work_per_call {
                return Err(FlowError::WorkLimit);
            }
            match (self.emitted.get(&k), proposed.get(&k)) {
                (None, Some(v)) => changes.push(RollupChange::Upsert(v.clone())),
                (Some(old), Some(v)) if old != v => {
                    changes.push(RollupChange::Correction(v.clone()))
                }
                (Some(_), None) => changes.push(RollupChange::Retire(Retirement {
                    key: k,
                    cache_only: true,
                })),
                _ => {}
            }
        }
        if changes.len() > self.cfg.max_outputs_per_call {
            return Err(FlowError::OutputLimit);
        }
        let replay_cutoff = now
            .checked_sub_signed(self.cfg.replay_ttl)
            .ok_or(FlowError::Overflow)?;
        self.watermark = Some(next);
        self.emitted = proposed;
        self.seconds
            .retain(|k, _| k.base.epoch.checked_add(1).is_some_and(|x| x >= cutoff));
        self.replay.retain(|_, e| e.arrival >= replay_cutoff);
        self.devices = self
            .seconds
            .keys()
            .map(|k| k.base.device.clone())
            .chain(self.replay.values().map(|e| e.device.clone()))
            .collect();
        self.last_arrival = Some(now);
        Ok(changes)
    }

    pub fn snapshot(&self) -> FlowSnapshot {
        FlowSnapshot {
            watermark: self.watermark,
            rollups: self.emitted.values().cloned().collect(),
            open_row_count: self.seconds.len(),
            replay_ids: self.replay.iter().map(|(id, e)| (*id, e.arrival)).collect(),
            devices: self.devices.iter().cloned().collect(),
            last_arrival: self.last_arrival,
        }
    }
}

fn checked_epoch(t: DateTime<Utc>) -> Result<(), FlowError> {
    let s = t.timestamp();
    DateTime::from_timestamp(s, t.timestamp_subsec_nanos())
        .ok_or(FlowError::Time)
        .map(|_| ())
}
fn normalize_metadata(
    m: &mut Option<DestinationMetadata>,
    cfg: &FlowEngineConfig,
) -> Result<(), FlowError> {
    if !cfg.retain_destination_metadata {
        *m = None;
        return Ok(());
    }
    if let Some(x) = m
        && let Some(d) = &mut x.domain
    {
        if d.len() > cfg.max_domain_bytes {
            return Err(FlowError::Capacity);
        }
        if d.is_empty()
            || !d.is_ascii()
            || d.starts_with('.')
            || d.ends_with('.')
            || d.split('.').any(|l| {
                l.is_empty()
                    || l.len() > 63
                    || l.starts_with('-')
                    || l.ends_with('-')
                    || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(FlowError::Metadata);
        }
        d.make_ascii_lowercase();
    }
    Ok(())
}
fn coverage(k: VisibilityKind) -> Coverage {
    match k {
        VisibilityKind::Gateway | VisibilityKind::Bridge | VisibilityKind::Mirror => {
            Coverage::Complete
        }
        VisibilityKind::RouterCounter => Coverage::RouterReported,
        VisibilityKind::Local => Coverage::LocalOnly,
        VisibilityKind::Inference => Coverage::Estimated,
    }
}
/// Conservative: mixed visibility never claims completeness; router + local is estimated.
fn merge_coverage(a: Coverage, b: Coverage) -> Coverage {
    if a == b { a } else { Coverage::Estimated }
}

fn select_seconds(
    seconds: &BTreeMap<SourceSecondKey, ByteCount>,
    sources: &BTreeMap<FlowSourceId, VisibilityKind>,
    w: DateTime<Utc>,
) -> Result<BTreeMap<SecondKey, Value>, FlowError> {
    let mut out = BTreeMap::new();
    let mut winners: BTreeMap<SecondKey, (u8, FlowSourceId)> = BTreeMap::new();
    for (k, b) in seconds {
        if k.base.epoch.checked_add(1).ok_or(FlowError::Overflow)? > w.timestamp() {
            continue;
        }
        let kind = *sources.get(&k.source).ok_or(FlowError::UnknownSource)?;
        let cov = coverage(kind);
        let rank = coverage_rank(cov);
        let replace = winners
            .get(&k.base)
            .is_none_or(|(r, id)| rank > *r || (rank == *r && k.source < *id));
        if replace {
            winners.insert(k.base.clone(), (rank, k.source));
            out.insert(
                k.base.clone(),
                Value {
                    bytes: *b,
                    coverage: cov,
                },
            );
        }
    }
    Ok(out)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Value {
    bytes: ByteCount,
    coverage: Coverage,
}
fn coverage_rank(c: Coverage) -> u8 {
    match c {
        Coverage::Complete => 4,
        Coverage::RouterReported => 3,
        Coverage::LocalOnly => 2,
        Coverage::Estimated => 1,
    }
}
fn make_rollup(res: Resolution, epoch: i64, k: &SecondKey, v: &Value) -> Result<Rollup, FlowError> {
    let bucket = DateTime::from_timestamp(epoch, 0).ok_or(FlowError::Overflow)?;
    let key = RollupKey {
        resolution: res,
        bucket,
        device_id: DeviceId::parse(&k.device).map_err(|_| FlowError::Config)?,
        protocol: k.protocol,
        destination: k.destination,
        interface: k.interface,
        metadata: k.metadata.clone(),
    };
    Ok(Rollup {
        key,
        bytes: v.bytes,
        coverage: v.coverage,
        metadata: k.metadata.clone(),
    })
}
fn adjust_parent(
    out: &mut BTreeMap<RollupKey, Rollup>,
    res: Resolution,
    width: i64,
    base: &SecondKey,
    old: Option<&Rollup>,
    new: &Rollup,
) -> Result<(), FlowError> {
    let epoch = base
        .epoch
        .div_euclid(width)
        .checked_mul(width)
        .ok_or(FlowError::Overflow)?;
    let seed = Value {
        bytes: ByteCount {
            upload: 0,
            download: 0,
        },
        coverage: new.coverage,
    };
    let template = make_rollup(res, epoch, base, &seed)?;
    let p = out.entry(template.key.clone()).or_insert(template);
    let oldb = old.map_or(
        ByteCount {
            upload: 0,
            download: 0,
        },
        |r| r.bytes,
    );
    p.bytes.upload = p
        .bytes
        .upload
        .checked_sub(oldb.upload)
        .ok_or(FlowError::Overflow)?
        .checked_add(new.bytes.upload)
        .ok_or(FlowError::Overflow)?;
    p.bytes.download = p
        .bytes
        .download
        .checked_sub(oldb.download)
        .ok_or(FlowError::Overflow)?
        .checked_add(new.bytes.download)
        .ok_or(FlowError::Overflow)?;
    p.bytes
        .upload
        .checked_add(p.bytes.download)
        .ok_or(FlowError::Overflow)?;
    p.coverage = merge_coverage(p.coverage, new.coverage);
    Ok(())
}
fn retired(k: &RollupKey, w: DateTime<Utc>, lateness: Duration) -> bool {
    let width = match k.resolution {
        Resolution::Second => 1,
        Resolution::Minute => 60,
        Resolution::Hour => 3600,
    };
    k.bucket
        .checked_add_signed(Duration::seconds(width))
        .and_then(|x| x.checked_add_signed(lateness))
        .is_some_and(|edge| w > edge)
}
