//! Network-wide inventory and router-reported WAN measurements, independent of host counters.
pub mod api;
pub mod lan;
mod router;
#[cfg(test)]
mod tests;
use chrono::Utc;
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, watch};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub discovery_enabled: bool,
    pub interval_seconds: u32,
    pub router_ip: Option<String>,
    pub router_port: u16,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            discovery_enabled: false,
            interval_seconds: 120,
            router_ip: None,
            router_port: 8080,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct Discovery {
    pub state: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub total: usize,
    pub completed: usize,
    pub responding: usize,
    pub errors: usize,
    pub skipped_networks: usize,
}
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RouterReading {
    pub status: String,
    pub observed_at: Option<String>,
    pub source: Option<String>,
    pub download: Option<f64>,
    pub upload: Option<f64>,
    pub connected_devices: Option<u32>,
}
impl Default for RouterReading {
    fn default() -> Self {
        Self {
            status: "not_configured".into(),
            observed_at: None,
            source: None,
            download: None,
            upload: None,
            connected_devices: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct Presence {
    pub device_id: Option<String>,
    pub manufacturer: Option<String>,
    pub interface: u32,
    pub mac: String,
    pub ip: String,
    pub first_seen: String,
    pub last_seen: String,
    pub missed: u32,
}
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct PresenceEvent {
    pub id: i64,
    pub at: String,
    pub mac: String,
    pub ip: String,
    pub kind: String,
}
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct Point {
    pub at: i64,
    pub download: f64,
    pub upload: f64,
    pub samples: i64,
}
#[derive(Serialize, ToSchema)]
pub struct Snapshot {
    pub settings: Settings,
    pub router: RouterReading,
    pub discovery: Discovery,
    pub devices: Vec<Presence>,
    pub events: Vec<PresenceEvent>,
    pub points: Vec<Point>,
    pub bucket_seconds: u32,
}
#[derive(Clone)]
pub struct NetworkMonitor {
    pool: SqlitePool,
    router: Arc<Mutex<RouterReading>>,
    discovery: Arc<Mutex<Option<Discovery>>>,
    running: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    settings_lock: Arc<Mutex<()>>,
}
impl NetworkMonitor {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            router: Arc::new(Mutex::new(RouterReading::default())),
            discovery: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            cancel: Arc::new(AtomicBool::new(false)),
            settings_lock: Arc::new(Mutex::new(())),
        }
    }
    pub async fn settings(&self) -> Result<Settings, sqlx::Error> {
        let value: Option<String> =
            sqlx::query_scalar("SELECT payload FROM network_monitor_state WHERE kind='settings'")
                .fetch_optional(&self.pool)
                .await?;
        value
            .map(|v| {
                serde_json::from_str(&v)
                    .map_err(|_| sqlx::Error::Protocol("invalid network settings".into()))
            })
            .transpose()
            .map(|v| v.unwrap_or_default())
    }
    pub async fn update_settings(&self, value: Settings) -> Result<(), sqlx::Error> {
        let _lock = self.settings_lock.lock().await;
        let old = self.settings().await?;
        sqlx::query("INSERT INTO network_monitor_state(kind,payload) VALUES('settings',?) ON CONFLICT(kind) DO UPDATE SET payload=excluded.payload")
            .bind(serde_json::to_string(&value).map_err(|_| sqlx::Error::Protocol("settings encoding".into()))?).execute(&self.pool).await?;
        if old.router_ip != value.router_ip || old.router_port != value.router_port {
            *self.router.lock().await = RouterReading::default();
        }
        if !value.discovery_enabled && old.discovery_enabled {
            self.cancel.store(true, Ordering::Release);
        }
        Ok(())
    }
    pub fn start(&self, shutdown: watch::Receiver<bool>) {
        let this = self.clone();
        let mut stop = shutdown.clone();
        tokio::spawn(async move {
            loop {
                if *stop.borrow() {
                    break;
                }
                let settings = this.settings().await;
                let delay = if let Ok(settings) = settings {
                    if settings.discovery_enabled {
                        let _ = this.discover().await;
                    }
                    settings.interval_seconds.clamp(60, 3600)
                } else {
                    30
                };
                tokio::select! { _ = stop.changed() => { if *stop.borrow() || stop.has_changed().is_err() { break; } }, _ = tokio::time::sleep(Duration::from_secs(delay.into())) => {} }
            }
            this.cancel.store(true, Ordering::Release);
        });
        let this = self.clone();
        let mut stop = shutdown;
        tokio::spawn(async move {
            loop {
                if *stop.borrow() {
                    break;
                }
                tokio::select! { _ = stop.changed() => { if *stop.borrow() || stop.has_changed().is_err() { break; } }, _ = this.collect_router() => {} }
                tokio::select! { _ = stop.changed() => { if *stop.borrow() || stop.has_changed().is_err() { break; } }, _ = tokio::time::sleep(Duration::from_secs(3)) => {} }
            }
        });
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
    pub async fn discover(&self) -> Result<(), &'static str> {
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("already_running");
        }
        self.cancel.store(false, Ordering::Release);
        let this = self.clone();
        *this.discovery.lock().await = Some(Discovery {
            state: "running".into(),
            started_at: Some(Utc::now().to_rfc3339()),
            ..Default::default()
        });
        tokio::spawn(async move {
            // Drop guard releases the job slot even if a task panics.
            struct Running(Arc<AtomicBool>);
            impl Drop for Running {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            let _running = Running(this.running.clone());
            let result = this.run_discovery().await;
            let mut status = this.discovery.lock().await;
            if let Some(status) = status.as_mut() {
                status.state = match result {
                    Ok(()) => {
                        if this.cancel.load(Ordering::Acquire) {
                            "cancelled"
                        } else if status.errors > 0 {
                            "partial"
                        } else {
                            "complete"
                        }
                    }
                    Err(()) => "unavailable",
                }
                .into();
                status.finished_at = Some(Utc::now().to_rfc3339());
                if let Ok(payload) = serde_json::to_string(status) {
                    let _ = sqlx::query("INSERT INTO network_monitor_state(kind,payload) VALUES('discovery',?) ON CONFLICT(kind) DO UPDATE SET payload=excluded.payload").bind(payload).execute(&this.pool).await;
                }
            }
        });
        Ok(())
    }
    async fn run_discovery(&self) -> Result<(), ()> {
        let inventory =
            tokio::task::spawn_blocking(|| lattice_sensor::SystemInterfaceManager.snapshot())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
        let plan = lan::plan(&inventory);
        if let Some(status) = self.discovery.lock().await.as_mut() {
            status.total = plan.targets.len();
            status.skipped_networks = plan.skipped;
        }
        if plan.targets.is_empty() {
            return Err(());
        }
        let targets = plan.targets.clone();
        let mut sightings = Vec::new();
        let mut errors = 0;
        let mut probes = stream::iter(plan.targets)
            .map(|target| async move {
                if self.cancel.load(Ordering::Acquire) {
                    return None;
                }
                Some(lan::probe(target).await)
            })
            .buffer_unordered(16);
        while let Some(result) = probes.next().await {
            let Some(result) = result else { continue };
            let mut status = self.discovery.lock().await;
            if let Some(status) = status.as_mut() {
                status.completed += 1;
                match result {
                    Ok(Some(sighting)) => {
                        status.responding += 1;
                        sightings.push(sighting);
                    }
                    Ok(None) => {}
                    Err(()) => {
                        status.errors += 1;
                        errors += 1;
                    }
                }
            }
        }
        // A cancelled or degraded scan may add positive sightings, but never departures.
        self.persist_sightings(
            &sightings,
            &targets,
            errors == 0 && !self.cancel.load(Ordering::Acquire),
            Utc::now(),
        )
        .await
        .map_err(|error| {
            tracing::warn!(
                database_code = error
                    .as_database_error()
                    .and_then(|e| e.code())
                    .as_deref()
                    .unwrap_or("unknown"),
                "LAN discovery observations could not be stored"
            );
        })
    }
    pub(crate) async fn persist_sightings(
        &self,
        sightings: &[lan::Sighting],
        targets: &[lan::Target],
        complete: bool,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        let at = now.to_rfc3339();
        // Reserve the writer before reading prior sightings: a deferred WAL
        // transaction can otherwise lose its snapshot to the presence worker.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let seen: BTreeSet<_> = sightings
            .iter()
            .map(|s| (s.interface, s.mac.clone()))
            .collect();
        for s in sightings {
            let old: Option<(i64,)> =
                sqlx::query_as("SELECT missed FROM network_presence WHERE interface=? AND mac=?")
                    .bind(s.interface)
                    .bind(&s.mac)
                    .fetch_optional(&mut *tx)
                    .await?;
            if old.is_none() || old.is_some_and(|o| o.0 >= 2) {
                sqlx::query("INSERT INTO network_presence_events(at,interface,mac,ip,kind) VALUES(?,?,?,?,?)").bind(&at).bind(s.interface).bind(&s.mac).bind(&s.ip).bind(if old.is_none() { "discovered" } else { "responding_again" }).execute(&mut *tx).await?;
            }
            sqlx::query("INSERT INTO network_presence(interface,mac,ip,first_seen,last_seen,missed) VALUES(?,?,?,?,?,0) ON CONFLICT(interface,mac) DO UPDATE SET ip=excluded.ip,last_seen=excluded.last_seen,missed=0")
                .bind(s.interface).bind(&s.mac).bind(&s.ip).bind(&at).bind(&at).execute(&mut *tx).await?;
        }
        if complete {
            let tested: BTreeSet<_> = targets
                .iter()
                .map(|t| (t.interface, t.ip.to_string()))
                .collect();
            let rows = sqlx::query(
                "SELECT interface,mac,ip,missed FROM network_presence WHERE missed<2 LIMIT 4096",
            )
            .fetch_all(&mut *tx)
            .await?;
            for row in rows {
                let interface: u32 = row.get("interface");
                let mac: String = row.get("mac");
                let ip: String = row.get("ip");
                let missed: i64 = row.get("missed");
                if seen.contains(&(interface, mac.clone()))
                    || !tested.contains(&(interface, ip.clone()))
                {
                    continue;
                }
                sqlx::query(
                    "UPDATE network_presence SET missed=missed+1 WHERE interface=? AND mac=?",
                )
                .bind(interface)
                .bind(&mac)
                .execute(&mut *tx)
                .await?;
                if missed == 1 {
                    sqlx::query("INSERT INTO network_presence_events(at,interface,mac,ip,kind) VALUES(?,?,?,?, 'not_responding')").bind(&at).bind(interface).bind(mac).bind(ip).execute(&mut *tx).await?;
                }
            }
        }
        sqlx::query("DELETE FROM network_presence_events WHERE id NOT IN (SELECT id FROM network_presence_events ORDER BY id DESC LIMIT 2000)").execute(&mut *tx).await?;
        sqlx::query("DELETE FROM network_presence WHERE rowid NOT IN (SELECT rowid FROM network_presence ORDER BY last_seen DESC LIMIT 4096)").execute(&mut *tx).await?;
        tx.commit().await
    }
    pub async fn snapshot(&self, minutes: u32) -> Result<Snapshot, sqlx::Error> {
        let settings = self.settings().await?;
        let mut router = self.router.lock().await.clone();
        if settings.router_ip.is_some()
            && router.observed_at.as_ref().is_none_or(|at| {
                chrono::DateTime::parse_from_rfc3339(at).map_or(true, |at| {
                    (Utc::now() - at.with_timezone(&Utc)).num_seconds() > 10
                })
            })
        {
            router.status = "unavailable".into();
            router.download = None;
            router.upload = None;
            router.connected_devices = None;
        }
        let discovery = if let Some(value) = self.discovery.lock().await.clone() {
            value
        } else {
            let saved: Option<String> = sqlx::query_scalar(
                "SELECT payload FROM network_monitor_state WHERE kind='discovery'",
            )
            .fetch_optional(&self.pool)
            .await?;
            let mut value: Discovery = saved
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| Discovery {
                    state: "idle".into(),
                    ..Default::default()
                });
            if value.state == "running" {
                value.state = "interrupted".into();
            }
            value
        };
        let devices =
            sqlx::query("SELECT p.*, (SELECT CASE WHEN COUNT(DISTINCT device_id)=1 THEN MIN(device_id) ELSE NULL END FROM evidence WHERE family='link_layer' AND fact_key='mac' AND source='neighbor-interface-' || p.interface AND lower(fact_value)=lower(p.mac)) AS device_id FROM network_presence p ORDER BY last_seen DESC LIMIT 4096")
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|r| Presence {
                    device_id: r.get("device_id"),
                    manufacturer: crate::mac_vendor::lookup(r.get("mac")).organization,
                    interface: r.get("interface"),
                    mac: r.get("mac"),
                    ip: r.get("ip"),
                    first_seen: r.get("first_seen"),
                    last_seen: r.get("last_seen"),
                    missed: r.get("missed"),
                })
                .collect();
        let events =
            sqlx::query("SELECT * FROM network_presence_events ORDER BY id DESC LIMIT 200")
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|r| PresenceEvent {
                    id: r.get("id"),
                    at: r.get("at"),
                    mac: r.get("mac"),
                    ip: r.get("ip"),
                    kind: r.get("kind"),
                })
                .collect();
        let bucket_seconds = if minutes <= 5 {
            2
        } else if minutes <= 60 {
            15
        } else {
            60
        };
        let source = settings
            .router_ip
            .as_ref()
            .map(|ip| format!("{ip}:{}", settings.router_port))
            .unwrap_or_default();
        let points = sqlx::query("SELECT (at / ?) * ? AS bucket, AVG(download) AS download, AVG(upload) AS upload, COUNT(*) AS samples FROM network_router_samples WHERE at>=? AND source=? GROUP BY bucket ORDER BY bucket LIMIT 1441")
            .bind(bucket_seconds).bind(bucket_seconds).bind(Utc::now().timestamp()-i64::from(minutes)*60).bind(source).fetch_all(&self.pool).await?.into_iter().map(|r| Point { at:r.get("bucket"),download:r.get("download"),upload:r.get("upload"),samples:r.get("samples") }).collect();
        Ok(Snapshot {
            settings,
            router,
            discovery,
            devices,
            events,
            points,
            bucket_seconds,
        })
    }
}
