//! Local computer telemetry, independent of LAN discovery and Guard policy.
pub mod api;
pub mod firewall;
mod platform;
mod repository;
#[cfg(test)]
mod tests;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Instant,
};
use tokio::sync::{Mutex, watch};
use utoipa::ToSchema;

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct InterfaceCounter {
    pub id: String,
    pub name: String,
    pub physical: bool,
    pub sent_bytes: u64,
    pub received_bytes: u64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct Application {
    pub app_id: String,
    pub name: String,
    pub executable: Option<String>,
    pub pid: u32,
    pub started: String,
    pub cpu_time_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct Connection {
    pub connection_id: String,
    pub app_id: String,
    pub pid: u32,
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String,
    pub sent_bytes: Option<u64>,
    pub received_bytes: Option<u64>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct HostSnapshot {
    pub observed_at: String,
    pub status: String,
    pub detail: String,
    pub interfaces: Vec<InterfaceCounter>,
    pub applications: Vec<Application>,
    pub connections: Vec<Connection>,
    pub upload_bytes_per_second: Option<f64>,
    pub download_bytes_per_second: Option<f64>,
    pub last_interval_ms: Option<u64>,
    pub last_sent_bytes: Option<u64>,
    pub last_received_bytes: Option<u64>,
    pub app_counters: String,
    pub firewall_available: bool,
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HostSettings {
    pub record_history: bool,
    pub snooze_until: Option<String>,
    pub retention_days: u32,
    pub monthly_budget_bytes: Option<u64>,
}
#[derive(Clone, Debug)]
pub struct Sample {
    pub scope: &'static str,
    pub subject: String,
    pub interval_ms: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub coverage: &'static str,
}
struct Inner {
    snapshot: HostSnapshot,
    previous: Option<(Instant, HostSnapshot)>,
}
#[derive(Clone)]
pub struct HostMonitor {
    pool: SqlitePool,
    inner: Arc<Mutex<Inner>>,
    pub(crate) firewall_lock: Arc<Mutex<()>>,
    /// Unix seconds until which a reader is considered to be watching the live view.
    demand_until: Arc<AtomicI64>,
    /// Per-connection byte counters (Windows EStats) are off unless explicitly requested.
    app_counters: Arc<AtomicBool>,
}

/// How long one live-view request keeps the 2-second collector running.
const DEMAND_WINDOW_SECONDS: i64 = 30;
/// Collector period while only history recording (no viewer) needs samples. Stays below the
/// 15-second gap limit in `sample_delta` so the host totals keep accumulating.
const IDLE_RECORDING_PERIOD: std::time::Duration = std::time::Duration::from_secs(10);
impl HostMonitor {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            inner: Arc::new(Mutex::new(Inner {
                snapshot: HostSnapshot {
                    status: "starting".into(),
                    detail: "Waiting for the local computer collector.".into(),
                    ..Default::default()
                },
                previous: None,
            })),
            firewall_lock: Arc::new(Mutex::new(())),
            demand_until: Arc::new(AtomicI64::new(0)),
            app_counters: Arc::new(AtomicBool::new(
                std::env::var("LATTICE_HOST_APP_COUNTERS").is_ok_and(|v| v == "1"),
            )),
        }
    }
    /// Marks the live view as in use; the collector runs at full rate for a short window.
    pub fn touch(&self) {
        self.demand_until.store(
            Utc::now().timestamp() + DEMAND_WINDOW_SECONDS,
            Ordering::Relaxed,
        );
    }
    /// Enables per-connection TCP byte counters. On Windows this switches on kernel EStats
    /// collection for every connection of the machine, so it is opt-in.
    pub fn set_app_counters(&self, enabled: bool) {
        self.app_counters.store(enabled, Ordering::Relaxed);
    }
    fn demanded(&self) -> bool {
        self.demand_until.load(Ordering::Relaxed) >= Utc::now().timestamp()
    }
    pub fn start(&self, mut shutdown: watch::Receiver<bool>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_collect: Option<Instant> = None;
            let mut recording: (Instant, bool) = (Instant::now(), true);
            loop {
                tokio::select! {
                    _ = shutdown.changed() => { if *shutdown.borrow() || shutdown.has_changed().is_err() { break; } }
                    _ = interval.tick() => {
                        // Nobody watching and nothing recording: skip the socket-table and
                        // per-process work entirely. Recording alone runs at a slower period.
                        if !this.demanded() {
                            if last_collect.is_none() || recording.0.elapsed() >= std::time::Duration::from_secs(30) {
                                recording = (Instant::now(), this.settings().await.map(|s| s.record_history).unwrap_or(true));
                            }
                            let due = last_collect.is_none_or(|at| at.elapsed() >= IDLE_RECORDING_PERIOD);
                            if !recording.1 || !due {
                                continue;
                            }
                        }
                        last_collect = Some(Instant::now());
                        this.collect().await;
                    }
                }
            }
        });
    }
    async fn collect(&self) {
        let app_counters = self.app_counters.load(Ordering::Relaxed);
        let result = tokio::task::spawn_blocking(move || platform::snapshot(app_counters)).await;
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        let mut snapshot = match result {
            Ok(Ok(value)) => value,
            _ => {
                inner.snapshot = HostSnapshot {
                    observed_at: Utc::now().to_rfc3339(),
                    status: "unavailable".into(),
                    detail: "The operating system did not provide a complete connection snapshot. Saved observations remain in history.".into(),
                    ..Default::default()
                };
                inner.previous = None;
                return;
            }
        };
        snapshot.observed_at = Utc::now().to_rfc3339();
        let samples = inner
            .previous
            .as_ref()
            .map(|(at, old)| {
                sample_delta(old, &snapshot, now.duration_since(*at).as_millis() as u64)
            })
            .unwrap_or_default();
        if let Some(host) = samples.iter().find(|s| s.scope == "host") {
            snapshot.last_interval_ms = Some(host.interval_ms);
            snapshot.last_sent_bytes = Some(host.sent_bytes);
            snapshot.last_received_bytes = Some(host.received_bytes);
            snapshot.upload_bytes_per_second =
                Some(host.sent_bytes as f64 * 1000.0 / host.interval_ms as f64);
            snapshot.download_bytes_per_second =
                Some(host.received_bytes as f64 * 1000.0 / host.interval_ms as f64);
        }
        let previous = inner.previous.as_ref().map(|(_, s)| s.clone());
        inner.previous = Some((now, snapshot.clone()));
        inner.snapshot = snapshot.clone();
        drop(inner);
        if let Err(error) = self.persist(&snapshot, previous.as_ref(), &samples).await {
            tracing::warn!(error=%error,"host telemetry persistence failed");
            let mut inner = self.inner.lock().await;
            inner.snapshot.status = "history_unavailable".into();
            inner.snapshot.detail =
                "Live readings are available; history could not be saved.".into();
        }
    }
    pub async fn snapshot(&self) -> HostSnapshot {
        self.touch();
        self.inner.lock().await.snapshot.clone()
    }
}

pub fn sample_delta(old: &HostSnapshot, new: &HostSnapshot, interval_ms: u64) -> Vec<Sample> {
    // A suspension, collector restart, or counter reset is a gap, not a spike.
    if !(1..=15_000).contains(&interval_ms) {
        return vec![];
    }
    let mut samples = vec![];
    let previous: BTreeMap<_, _> = old
        .interfaces
        .iter()
        .filter(|i| i.physical)
        .map(|i| (&i.id, i))
        .collect();
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut measured = 0;
    for next in new.interfaces.iter().filter(|i| i.physical) {
        let Some(old) = previous.get(&next.id) else {
            continue;
        };
        if let (Some(up), Some(down)) = (
            next.sent_bytes.checked_sub(old.sent_bytes),
            next.received_bytes.checked_sub(old.received_bytes),
        ) {
            sent = sent.saturating_add(up);
            received = received.saturating_add(down);
            measured += 1;
        }
    }
    if measured > 0 {
        samples.push(Sample {
            scope: "host",
            subject: "physical_interfaces".into(),
            interval_ms,
            sent_bytes: sent,
            received_bytes: received,
            coverage: "physical_interfaces",
        });
    }
    let previous: BTreeMap<_, _> = old
        .connections
        .iter()
        .map(|c| (&c.connection_id, c))
        .collect();
    let mut apps: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for next in &new.connections {
        let Some(old) = previous.get(&next.connection_id) else {
            continue;
        };
        if old.app_id != next.app_id {
            continue;
        }
        if let (Some(up), Some(down)) = (
            next.sent_bytes
                .zip(old.sent_bytes)
                .and_then(|(n, o)| n.checked_sub(o)),
            next.received_bytes
                .zip(old.received_bytes)
                .and_then(|(n, o)| n.checked_sub(o)),
        ) {
            let values = apps.entry(next.app_id.clone()).or_default();
            values.0 = values.0.saturating_add(up);
            values.1 = values.1.saturating_add(down);
        }
    }
    samples.extend(
        apps.into_iter()
            .map(|(subject, (sent_bytes, received_bytes))| Sample {
                scope: "app",
                subject,
                interval_ms,
                sent_bytes,
                received_bytes,
                coverage: "sampled_tcp",
            }),
    );
    samples
}

pub(crate) fn digest(value: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
