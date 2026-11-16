use super::*;
use serde_json::Value;
use std::net::Ipv4Addr;
use std::time::Instant;

const MAX_LINE: usize = 65536;
const SETTINGS_RECHECK: Duration = Duration::from_secs(5);
const PRUNE_EVERY: Duration = Duration::from_secs(60);
/// Longest the SSE stream may stay silent before the read fails and the feed reconnects.
/// An idle bound, not a total one: a healthy stream is never cut by it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// The same reason is logged at most this often (the feed retries every few seconds).
const FAILURE_LOG_EVERY: Duration = Duration::from_secs(300);

/// Why the router feed last failed, and when that reason was last logged. The reason is a short
/// machine-readable code; response bodies are never recorded.
#[derive(Default)]
pub(super) struct FailureNote {
    pub(super) reason: Option<&'static str>,
    logged: Option<(&'static str, Instant)>,
}
impl FailureNote {
    /// Records `reason`; true when it should be logged now (new reason, or not logged for a while).
    pub(super) fn record(&mut self, reason: &'static str, now: Instant) -> bool {
        self.reason = Some(reason);
        let repeat = matches!(self.logged, Some((last, at))
            if last == reason && now.saturating_duration_since(at) < FAILURE_LOG_EVERY);
        if !repeat {
            self.logged = Some((reason, now));
        }
        !repeat
    }
    pub(super) fn clear(&mut self) {
        self.reason = None;
    }
}

/// The reading that follows one event. `rate` is a fresh vnstat sample, if one arrived; otherwise
/// a dashboard event arrived with `connected` devices. Rates are never invented: without a fresh
/// rate (this call's, or the current reading's within `RATE_FRESH_SECS`) the reading is `connected`
/// with null rates. Unchanged connected readings only move `observed_at`.
pub(super) fn next_reading(
    current: &RouterReading,
    now: chrono::DateTime<Utc>,
    source: &str,
    rate: Option<(f64, f64)>,
    connected: Option<u32>,
) -> RouterReading {
    if let Some((download, upload)) = rate {
        return RouterReading {
            status: "ready".into(),
            observed_at: Some(now.to_rfc3339()),
            source: Some(source.to_owned()),
            download: Some(download),
            upload: Some(upload),
            connected_devices: connected,
            reason: None,
            rate_at: Some(now),
        };
    }
    let rate_fresh = current
        .rate_at
        .is_some_and(|at| (now - at).num_seconds() <= RATE_FRESH_SECS);
    if rate_fresh && matches!(current.status.as_str(), "ready" | "history_unavailable") {
        return RouterReading {
            observed_at: Some(now.to_rfc3339()),
            connected_devices: connected,
            ..current.clone()
        };
    }
    RouterReading {
        status: "connected".into(),
        observed_at: Some(now.to_rfc3339()),
        source: Some(source.to_owned()),
        download: None,
        upload: None,
        connected_devices: connected,
        reason: None,
        rate_at: None,
    }
}

/// Applies the freshness rules to a stored reading when a snapshot is taken. Rates live
/// `RATE_FRESH_SECS`; when they lapse but dashboard events continue (`CONNECTED_FRESH_SECS`) the
/// reading falls back to `connected`; otherwise it is `unavailable` with the last failure code.
pub(super) fn aged_reading(
    mut reading: RouterReading,
    now: chrono::DateTime<Utc>,
    failure: Option<&str>,
) -> RouterReading {
    let rate_fresh = reading
        .rate_at
        .is_some_and(|at| (now - at).num_seconds() <= RATE_FRESH_SECS);
    if rate_fresh {
        return reading;
    }
    let event_age = reading
        .observed_at
        .as_deref()
        .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
        .map(|at| (now - at.with_timezone(&Utc)).num_seconds());
    if event_age.is_some_and(|age| age <= CONNECTED_FRESH_SECS)
        && reading.connected_devices.is_some()
        && matches!(
            reading.status.as_str(),
            "ready" | "connected" | "history_unavailable"
        )
    {
        reading.status = "connected".into();
        reading.download = None;
        reading.upload = None;
        return reading;
    }
    reading.status = "unavailable".into();
    reading.download = None;
    reading.upload = None;
    reading.connected_devices = None;
    reading.reason = failure
        .map(str::to_owned)
        .or_else(|| event_age.map(|_| "feed_quiet".to_owned()));
    reading
}

/// Whether the raw-sample retention prune should run now: never ran, or a full interval ago.
pub(super) fn prune_due(last_prune: Option<Instant>, now: Instant) -> bool {
    last_prune.is_none_or(|at| now.saturating_duration_since(at) >= PRUNE_EVERY)
}
/// One day of raw rates, a hard ceiling even across clock changes (at most 50 000 newest rows
/// survive the OFFSET bound). Rows are keyed by `at`, so the cutoff compares seconds.
pub(super) async fn prune_samples(
    pool: &SqlitePool,
    now_timestamp: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM network_router_samples WHERE at < ? OR at <= COALESCE((SELECT at FROM network_router_samples ORDER BY at DESC LIMIT 1 OFFSET 50000), -1)")
        .bind(now_timestamp - 86400)
        .execute(pool)
        .await
        .map(|_| ())
}
/// Settings are re-read from the database at most every `SETTINGS_RECHECK`, not once per sample.
pub(super) struct SettingsWatch {
    checked: Instant,
}
impl SettingsWatch {
    pub(super) fn new(now: Instant) -> Self {
        Self { checked: now }
    }
    /// True while the settings the session started with are still current. Within the recheck
    /// period nothing is read; afterwards `reload` runs once and the period restarts.
    pub(super) async fn still_current<F, Fut>(
        &mut self,
        now: Instant,
        reload: F,
        current: &Settings,
    ) -> bool
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<Settings>>,
    {
        if now.saturating_duration_since(self.checked) < SETTINGS_RECHECK {
            return true;
        }
        if reload().await.as_ref() != Some(current) {
            return false;
        }
        self.checked = now;
        true
    }
}
const MAX_SESSION_BYTES: usize = 2 * 1024 * 1024;
fn counter(value: &Value) -> Option<f64> {
    let number = value.as_f64().or_else(|| value.as_str()?.parse().ok())?;
    (number.is_finite() && (0.0..=1_000_000_000_000.0).contains(&number)).then_some(number)
}
#[derive(Default)]
pub(super) struct Feed {
    pending: Vec<u8>,
    pub rate: Option<(f64, f64)>,
    pub connected: Option<u32>,
    /// A dashboard event with a valid device count arrived since this was last taken.
    pub dashboard: bool,
}
impl Feed {
    pub(super) fn push(&mut self, bytes: &[u8]) -> Result<(), ()> {
        // The transport may split or combine arbitrary lines. Unknown event bodies,
        // including SSIDs and WAN addresses, never enter the persisted projection.
        for &byte in bytes {
            if byte == b'\n' {
                let line = std::mem::take(&mut self.pending);
                let Some(json) = line.strip_prefix(b"data:") else {
                    continue;
                };
                let Ok(event) = serde_json::from_slice::<Value>(json) else {
                    continue;
                };
                let field = &event["Field"];
                match event["Message"].as_str() {
                    Some("NOTIFICATION_WIFI_vnstat") => {
                        if let (Some(download), Some(upload)) = (
                            counter(&field["rxbytespersecond"]),
                            counter(&field["txbytespersecond"]),
                        ) {
                            self.rate = Some((download, upload));
                        }
                    }
                    Some("CMD_WIFI_GET_dashBoardPage") => {
                        let keys = [
                            "Host1ConnectedDevice",
                            "Host2ConnectedDevice",
                            "Host3ConnectedDevice",
                            "Guest1ConnectedDevice",
                            "Guest2ConnectedDevice",
                            "Guest3ConnectedDevice",
                            "Smart1ConnectedDevice",
                            "Smart2ConnectedDevice",
                            "Smart3ConnectedDevice",
                            "LanConnectedDevice",
                        ];
                        self.connected = keys.iter().try_fold(0u32, |sum, k| {
                            let n = counter(&field[*k])?;
                            if n.fract() != 0.0 || n > 4096.0 {
                                return None;
                            }
                            sum.checked_add(n as u32).filter(|n| *n <= 4096)
                        });
                        self.dashboard |= self.connected.is_some();
                    }
                    _ => {}
                }
            } else {
                if self.pending.len() >= MAX_LINE {
                    return Err(());
                }
                self.pending.push(byte);
            }
        }
        Ok(())
    }
}
/// The router feed's HTTP client: no proxy, no redirects, bound to the LAN source address.
/// `idle_timeout` bounds how long the stream may stay silent; it is not a total timeout.
pub(super) fn feed_client_builder(
    source: Ipv4Addr,
    idle_timeout: Duration,
) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .local_address(std::net::IpAddr::V4(source))
        .connect_timeout(Duration::from_secs(3))
        // The feed is a long-lived stream: bound idle time, not total time. A total
        // timeout cut the stream every 20 s and forced a reconnect gap each time.
        .read_timeout(idle_timeout)
}
/// Opens the event stream. `None` unless the router answers 200 with `text/event-stream`.
pub(super) async fn open_feed(client: &reqwest::Client, url: &str) -> Option<reqwest::Response> {
    let response = client
        .get(url)
        .header("Accept", "text/event-stream")
        .send()
        .await
        .ok()?;
    if response.status() != reqwest::StatusCode::OK
        || response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v.split(';').next() != Some("text/event-stream"))
    {
        return None;
    }
    Some(response)
}
impl NetworkMonitor {
    /// Notes why the feed step failed: kept for the snapshot, and logged (debounced) without any
    /// response content.
    fn router_failed(&self, reason: &'static str) {
        let due = self
            .failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record(reason, Instant::now());
        if due {
            if matches!(reason, "feed_closed" | "session_byte_cap") {
                tracing::info!(reason, "router feed ended");
            } else {
                tracing::warn!(reason, "router feed step failed");
            }
        }
    }
    pub(super) async fn collect_router(&self) {
        let Ok(settings) = self.settings().await else {
            self.router_failed("settings_unreadable");
            return;
        };
        // No router configured is not a failure: nothing is logged or recorded.
        let Some(ip) = settings
            .router_ip
            .as_ref()
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        else {
            return;
        };
        let Some(target) = lan::local_target(ip) else {
            self.router_failed("no_local_interface");
            return;
        };
        let builder = feed_client_builder(target.source, IDLE_TIMEOUT);
        #[cfg(target_os = "linux")]
        let builder = {
            let Ok(inventory) = lattice_sensor::SystemInterfaceManager.snapshot() else {
                self.router_failed("interface_inventory");
                return;
            };
            let Some(interface) = inventory
                .interfaces()
                .find(|i| i.id.get() == target.interface)
            else {
                self.router_failed("no_local_interface");
                return;
            };
            builder.interface(&interface.name)
        };
        let Ok(client) = builder.build() else {
            self.router_failed("client_build");
            return;
        };
        // Exact vendor read endpoint; no login, cookies, token forwarding, redirects,
        // appliance commands, arbitrary paths, or proxy-environment inheritance.
        let Some(response) = open_feed(
            &client,
            &format!("http://{ip}:{}/cgi-bin/sse_cgi", settings.router_port),
        )
        .await
        else {
            self.router_failed("feed_not_event_stream");
            return;
        };
        let mut stream = response.bytes_stream();
        let mut feed = Feed::default();
        let mut received = 0;
        let mut settings_watch = SettingsWatch::new(Instant::now());
        let mut last_prune: Option<Instant> = None;
        while let Some(Ok(chunk)) = stream.next().await {
            received += chunk.len();
            if received > MAX_SESSION_BYTES {
                self.router_failed("session_byte_cap");
                return;
            }
            if feed.push(&chunk).is_err() {
                self.router_failed("parse_error");
                return;
            }
            let rate = feed.rate.take();
            let dashboard = std::mem::take(&mut feed.dashboard);
            if rate.is_none() && !dashboard {
                continue;
            }
            // Settings are re-read at most every few seconds, not once per sample.
            let monitor = self;
            if !settings_watch
                .still_current(
                    Instant::now(),
                    move || async move {
                        let _lock = monitor.settings_lock.lock().await;
                        monitor.settings().await.ok()
                    },
                    &settings,
                )
                .await
            {
                return;
            }
            let now = Utc::now();
            let source = format!("{ip}:{}", settings.router_port);
            {
                let mut current = self.router.lock().await;
                let reading = next_reading(&current, now, &source, rate, feed.connected);
                *current = reading;
            }
            self.failure
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            // Only a real rate is persisted: the samples table and its readers take rates, and a
            // connected-only reading stays in memory.
            let Some((download, upload)) = rate else {
                continue;
            };
            if sqlx::query("INSERT INTO network_router_samples(at,source,download,upload) VALUES(?,?,?,?) ON CONFLICT(at) DO NOTHING")
                .bind(now.timestamp()).bind(source).bind(download).bind(upload).execute(&self.pool).await.is_err() {
                self.router.lock().await.status = "history_unavailable".into();
                continue;
            }
            // One day of raw rates, a hard ceiling even across clock changes. Pruned once a
            // minute: the old per-sample `NOT IN (SELECT ... LIMIT 50000)` re-sorted the table
            // every second.
            let tick = Instant::now();
            if prune_due(last_prune, tick) {
                last_prune = Some(tick);
                let _ = prune_samples(&self.pool, now.timestamp()).await;
            }
        }
        // The stream closed or a read failed (including the idle timeout).
        self.router_failed("feed_closed");
    }
}
