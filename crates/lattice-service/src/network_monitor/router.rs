use super::*;
use serde_json::Value;
use std::net::Ipv4Addr;

const MAX_LINE: usize = 65536;
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
impl NetworkMonitor {
    pub(super) async fn collect_router(&self) {
        let Ok(settings) = self.settings().await else {
            return;
        };
        let Some(ip) = settings
            .router_ip
            .as_ref()
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        else {
            return;
        };
        let Some(target) = lan::local_target(ip) else {
            return;
        };
        let builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .local_address(std::net::IpAddr::V4(target.source))
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(20));
        #[cfg(target_os = "linux")]
        let builder = {
            let Ok(inventory) = lattice_sensor::SystemInterfaceManager.snapshot() else {
                return;
            };
            let Some(interface) = inventory
                .interfaces()
                .find(|i| i.id.get() == target.interface)
            else {
                return;
            };
            builder.interface(&interface.name)
        };
        let Ok(client) = builder.build() else { return };
        // Exact vendor read endpoint; no login, cookies, token forwarding, redirects,
        // appliance commands, arbitrary paths, or proxy-environment inheritance.
        let Ok(response) = client
            .get(format!(
                "http://{ip}:{}/cgi-bin/sse_cgi",
                settings.router_port
            ))
            .header("Accept", "text/event-stream")
            .send()
            .await
        else {
            return;
        };
        if response.status() != reqwest::StatusCode::OK
            || response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_none_or(|v| v.split(';').next() != Some("text/event-stream"))
        {
            return;
        }
        let mut stream = response.bytes_stream();
        let mut feed = Feed::default();
        let mut received = 0;
        while let Some(Ok(chunk)) = stream.next().await {
            received += chunk.len();
            if received > MAX_SESSION_BYTES || feed.push(&chunk).is_err() {
                return;
            }
            let Some((download, upload)) = feed.rate.take() else {
                continue;
            };
            let _lock = self.settings_lock.lock().await;
            if self.settings().await.ok().as_ref() != Some(&settings) {
                return;
            }
            let now = Utc::now();
            let source = format!("{ip}:{}", settings.router_port);
            let reading = RouterReading {
                status: "ready".into(),
                observed_at: Some(now.to_rfc3339()),
                source: Some(source.clone()),
                download: Some(download),
                upload: Some(upload),
                connected_devices: feed.connected,
            };
            *self.router.lock().await = reading;
            if sqlx::query("INSERT INTO network_router_samples(at,source,download,upload) VALUES(?,?,?,?) ON CONFLICT(at) DO NOTHING")
                .bind(now.timestamp()).bind(source).bind(download).bind(upload).execute(&self.pool).await.is_err() {
                self.router.lock().await.status = "history_unavailable".into();
                continue;
            }
            // One day of raw rates, a hard ceiling even across clock changes.
            let _ = sqlx::query("DELETE FROM network_router_samples WHERE at < ? OR at NOT IN (SELECT at FROM network_router_samples ORDER BY at DESC LIMIT 50000)")
                .bind(now.timestamp()-86400).execute(&self.pool).await;
        }
    }
}
