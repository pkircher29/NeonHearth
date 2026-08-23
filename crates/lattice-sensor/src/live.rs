//! Deterministic live-bandwidth coalescing. Durable rollups remain the source of truth.
use crate::flow::{Resolution, Rollup, RollupChange, RollupKey};
use chrono::{DateTime, Utc};
use lattice_domain::{
    BandwidthFrame, BandwidthSample, ByteCount, Coverage, DeviceId, EventPayload,
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct LiveConfig {
    pub min_interval_ms: u64,
    pub max_devices: usize,
    pub max_pending: usize,
    pub max_work: usize,
}
impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            min_interval_ms: 250,
            max_devices: 1024,
            max_pending: 1024,
            max_work: 8192,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveSample {
    pub device_id: DeviceId,
    pub delta: ByteCount,
    pub coverage: Coverage,
    pub observed_at: DateTime<Utc>,
}
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum LiveError {
    #[error("invalid config")]
    Config,
    #[error("clock rollback")]
    Clock,
    #[error("capacity")]
    Capacity,
    #[error("work limit")]
    Work,
    #[error("overflow")]
    Overflow,
}

#[derive(Clone)]
pub struct LiveCoalescer {
    cfg: LiveConfig,
    pending: BTreeMap<String, LiveSample>,
    last_tick: Option<u64>,
    last_emit: Option<u64>,
    last_emitted_at: Option<DateTime<Utc>>,
}
impl LiveCoalescer {
    pub fn new(cfg: LiveConfig) -> Result<Self, LiveError> {
        if cfg.min_interval_ms < 250
            || cfg.max_devices == 0
            || cfg.max_pending == 0
            || cfg.max_work == 0
        {
            return Err(LiveError::Config);
        }
        Ok(Self {
            cfg,
            pending: BTreeMap::new(),
            last_tick: None,
            last_emit: None,
            last_emitted_at: None,
        })
    }
    pub fn replace(&mut self, tick_ms: u64, samples: Vec<LiveSample>) -> Result<(), LiveError> {
        if self.last_tick.is_some_and(|x| tick_ms < x) {
            return Err(LiveError::Clock);
        }
        if samples.len() > self.cfg.max_work {
            return Err(LiveError::Work);
        }
        let mut next = self.pending.clone();
        for s in samples {
            let k = s.device_id.to_string();
            if !next.contains_key(&k) && next.len() >= self.cfg.max_pending {
                return Err(LiveError::Capacity);
            }
            next.insert(k, s);
        }
        if next.len() > self.cfg.max_devices {
            return Err(LiveError::Capacity);
        }
        self.pending = next;
        self.last_tick = Some(tick_ms);
        Ok(())
    }
    fn sync_devices(&mut self, devices: &BTreeSet<String>, samples: &BTreeMap<String, LiveSample>) {
        for device in devices {
            if let Some(sample) = samples.get(device) {
                self.pending.insert(device.clone(), sample.clone());
            } else {
                self.pending.remove(device);
            }
        }
    }
    pub fn flush(
        &mut self,
        tick_ms: u64,
        emitted_at: DateTime<Utc>,
    ) -> Result<Option<BandwidthFrame>, LiveError> {
        if self.last_tick.is_some_and(|x| tick_ms < x)
            || self.last_emit.is_some_and(|x| tick_ms < x)
            || self.last_emitted_at.is_some_and(|x| emitted_at < x)
        {
            return Err(LiveError::Clock);
        }
        if self.pending.is_empty() {
            self.last_tick = Some(tick_ms);
            return Ok(None);
        }
        let interval = match self.last_emit {
            Some(last) => tick_ms.checked_sub(last).ok_or(LiveError::Clock)?,
            None => self.cfg.min_interval_ms,
        };
        if interval < self.cfg.min_interval_ms {
            return Ok(None);
        }
        if self.pending.len() > self.cfg.max_work {
            return Err(LiveError::Work);
        }
        let observed_at = self
            .pending
            .values()
            .map(|s| s.observed_at)
            .max()
            .ok_or(LiveError::Capacity)?;
        let mut samples = Vec::with_capacity(self.pending.len());
        for s in self.pending.values() {
            samples.push(BandwidthSample {
                device_id: s.device_id,
                delta: s.delta,
                upload_bytes_per_second: rate(s.delta.upload, interval)?,
                download_bytes_per_second: rate(s.delta.download, interval)?,
                coverage: s.coverage,
            });
        }
        self.pending.clear();
        self.last_tick = Some(tick_ms);
        self.last_emit = Some(tick_ms);
        self.last_emitted_at = Some(emitted_at);
        Ok(Some(BandwidthFrame {
            interval_ms: interval,
            observed_at,
            emitted_at,
            samples,
        }))
    }
}
fn rate(bytes: u64, ms: u64) -> Result<u64, LiveError> {
    bytes
        .checked_mul(1000)
        .ok_or(LiveError::Overflow)
        .map(|x| x / ms)
}

/// Replaces keyed current one-second rollups; corrections never double-add and cache retirements
/// are ignored as traffic. Source overlap was already resolved by the flow engine.
#[derive(Clone)]
pub struct FlowLiveAdapter {
    current: BTreeMap<RollupKey, Rollup>,
    emitted: BTreeMap<RollupKey, ByteCount>,
    pending_baselines: BTreeMap<RollupKey, ByteCount>,
    coalescer: LiveCoalescer,
    max_rows: usize,
}
impl FlowLiveAdapter {
    pub fn new(cfg: LiveConfig, max_rows: usize) -> Result<Self, LiveError> {
        if max_rows == 0 {
            return Err(LiveError::Config);
        }
        Ok(Self {
            current: BTreeMap::new(),
            emitted: BTreeMap::new(),
            pending_baselines: BTreeMap::new(),
            coalescer: LiveCoalescer::new(cfg)?,
            max_rows,
        })
    }
    pub fn apply(&mut self, tick_ms: u64, changes: &[RollupChange]) -> Result<(), LiveError> {
        let mut staged = self.clone();
        staged.apply_inner(tick_ms, changes)?;
        *self = staged;
        Ok(())
    }
    fn apply_inner(&mut self, tick_ms: u64, changes: &[RollupChange]) -> Result<(), LiveError> {
        if changes.len() > self.coalescer.cfg.max_work {
            return Err(LiveError::Work);
        }
        let mut next = self.current.clone();
        let mut emitted = self.emitted.clone();
        let mut pending_baselines = self.pending_baselines.clone();
        let mut traffic_changed = false;
        let mut retired_devices = BTreeSet::new();
        for c in changes {
            match c {
                RollupChange::Upsert(r) | RollupChange::Correction(r)
                    if r.key.resolution == Resolution::Second =>
                {
                    let device = r.key.device_id;
                    let latest = next
                        .keys()
                        .filter(|key| key.device_id == device)
                        .map(|key| key.bucket)
                        .max();
                    if latest.is_some_and(|bucket| r.key.bucket < bucket) {
                        continue;
                    }
                    if latest.is_some_and(|bucket| r.key.bucket > bucket) {
                        next.retain(|key, _| key.device_id != device);
                        emitted.retain(|key, _| key.device_id != device);
                        pending_baselines.retain(|key, _| key.device_id != device);
                    }
                    next.insert(r.key.clone(), r.clone());
                    traffic_changed = true;
                }
                RollupChange::Retire(r)
                    if r.cache_only
                        && r.key.resolution == Resolution::Second
                        && next.remove(&r.key).is_some() =>
                {
                    retired_devices.insert(r.key.device_id.to_string());
                    emitted.remove(&r.key);
                    pending_baselines.remove(&r.key);
                }
                _ => {}
            }
        }
        if next.len() > self.max_rows {
            return Err(LiveError::Capacity);
        }
        if !traffic_changed {
            let samples = samples_for_current(&next, &emitted)?;
            for (key, bytes) in samples.resets {
                emitted.insert(key, bytes);
            }
            self.coalescer
                .sync_devices(&retired_devices, &samples.by_device);
            self.current = next;
            self.emitted = emitted;
            self.pending_baselines = pending_baselines;
            return Ok(());
        }
        let samples = samples_for_current(&next, &emitted)?;
        for (key, bytes) in samples.resets {
            emitted.insert(key, bytes);
        }
        self.coalescer
            .replace(tick_ms, samples.by_device.values().cloned().collect())?;
        let mut affected: BTreeSet<String> =
            next.keys().map(|key| key.device_id.to_string()).collect();
        affected.extend(self.current.keys().map(|key| key.device_id.to_string()));
        self.coalescer.sync_devices(&affected, &samples.by_device);
        self.current = next;
        self.emitted = emitted;
        self.pending_baselines = samples.baselines;
        Ok(())
    }
    pub fn flush_payload(
        &mut self,
        tick_ms: u64,
        now: DateTime<Utc>,
    ) -> Result<Option<EventPayload>, LiveError> {
        let mut staged = self.clone();
        let frame = staged.coalescer.flush(tick_ms, now)?;
        if frame.is_some() {
            staged.emitted.append(&mut staged.pending_baselines);
        }
        *self = staged;
        Ok(frame.map(EventPayload::BandwidthFrame))
    }
    pub fn staged_payload(
        &self,
        tick_ms: u64,
        changes: &[RollupChange],
        now: DateTime<Utc>,
    ) -> Result<(Self, Option<EventPayload>), LiveError> {
        let mut staged = self.clone();
        staged.apply(tick_ms, changes)?;
        let payload = staged.flush_payload(tick_ms, now)?;
        Ok((staged, payload))
    }
    pub fn cached_rollups(&self) -> Vec<Rollup> {
        self.current.values().cloned().collect()
    }
}
struct CurrentSamples {
    by_device: BTreeMap<String, LiveSample>,
    baselines: BTreeMap<RollupKey, ByteCount>,
    resets: BTreeMap<RollupKey, ByteCount>,
}

fn samples_for_current(
    next: &BTreeMap<RollupKey, Rollup>,
    emitted: &BTreeMap<RollupKey, ByteCount>,
) -> Result<CurrentSamples, LiveError> {
    let mut out = BTreeMap::new();
    let mut baselines = BTreeMap::new();
    let mut resets = BTreeMap::new();
    for r in next.values() {
        let k = r.key.device_id.to_string();
        let baseline = emitted.get(&r.key).copied().unwrap_or(ByteCount {
            upload: 0,
            download: 0,
        });
        let mut reset = baseline;
        let mut reset_changed = false;
        if r.bytes.upload < baseline.upload {
            reset.upload = r.bytes.upload;
            reset_changed = true;
        }
        if r.bytes.download < baseline.download {
            reset.download = r.bytes.download;
            reset_changed = true;
        }
        if reset_changed {
            resets.insert(r.key.clone(), reset);
        }
        let delta = ByteCount {
            upload: r.bytes.upload.saturating_sub(baseline.upload),
            download: r.bytes.download.saturating_sub(baseline.download),
        };
        if delta.upload == 0 && delta.download == 0 {
            continue;
        }
        let x = out.entry(k).or_insert(LiveSample {
            device_id: r.key.device_id,
            delta: ByteCount {
                upload: 0,
                download: 0,
            },
            coverage: r.coverage,
            observed_at: r.key.bucket,
        });
        x.delta.upload = x
            .delta
            .upload
            .checked_add(delta.upload)
            .ok_or(LiveError::Overflow)?;
        x.delta.download = x
            .delta
            .download
            .checked_add(delta.download)
            .ok_or(LiveError::Overflow)?;
        x.coverage = if x.coverage == r.coverage {
            x.coverage
        } else {
            Coverage::Estimated
        };
        baselines.insert(r.key.clone(), r.bytes);
    }
    Ok(CurrentSamples {
        by_device: out,
        baselines,
        resets,
    })
}
