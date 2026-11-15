//! Publish-only bridge to the managed loopback broker. MQTT is not a control API.
use crate::AppState;
use rumqttc::{AsyncClient, Event, LastWill, MqttOptions, Packet, QoS};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{path::PathBuf, time::Duration};
use tokio::sync::watch;

#[derive(Clone, Serialize, utoipa::ToSchema)]
pub struct MqttStatus {
    pub status: String,
    pub detail: String,
}
impl Default for MqttStatus {
    fn default() -> Self {
        Self {
            status: "disabled".into(),
            detail: "Start the local MQTT hub to enable authenticated inventory publishing.".into(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    port: u16,
    username: String,
    password: String,
}

/// How long to wait before re-reading a missing or invalid credential file.
const CREDENTIAL_RETRY: Duration = Duration::from_secs(2);
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

async fn load_credentials(path: &PathBuf) -> Option<Credentials> {
    let metadata = tokio::fs::metadata(path).await.ok()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return None;
    }
    let config: Credentials = serde_json::from_slice(&tokio::fs::read(path).await.ok()?).ok()?;
    (config.port >= 1024
        && config.username == "neonhearth"
        && (32..=256).contains(&config.password.len()))
    .then_some(config)
}

pub fn start(
    state: AppState,
    path: PathBuf,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    start_with_retry_interval(state, path, shutdown, CREDENTIAL_RETRY)
}

/// Like [`start`] with an explicit credential retry interval (tests).
#[doc(hidden)]
pub fn start_with_retry_interval(
    state: AppState,
    path: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    retry: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // The launcher provisions the credential file around the time the
        // service starts; a file that is not there yet must not disable the
        // bridge until the next restart.
        let config = loop {
            if let Some(config) = load_credentials(&path).await {
                break config;
            }
            state
                .automation()
                .mqtt_status(
                    "configuration_failed",
                    "The private MQTT credential file is missing or invalid. Retrying.",
                )
                .await;
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(retry) => {}
            }
        };
        let mut options = MqttOptions::new(
            format!("neonhearth-{}", std::process::id()),
            "127.0.0.1",
            config.port,
        );
        options.set_credentials(config.username, config.password);
        options.set_keep_alive(Duration::from_secs(20));
        options.set_max_packet_size(MAX_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES);
        options.set_last_will(LastWill::new(
            "neonhearth/status",
            "offline",
            QoS::AtLeastOnce,
            true,
        ));
        let (client, mut eventloop) = AsyncClient::new(options, 8);
        let mut tick = tokio::time::interval(Duration::from_secs(3));
        let mut connected = false;
        let mut dropped: u64 = 0;
        let mut reported_dropped: u64 = 0;
        state
            .automation()
            .mqtt_status(
                "connecting",
                "Connecting to the authenticated local broker.",
            )
            .await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                event = eventloop.poll() => match event {
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        connected = true;
                        state.automation().mqtt_status("connected", "Authenticated broker connected. Publishing inventory; MQTT commands are disabled.").await;
                        reported_dropped = 0;
                        let _ = client.try_publish("neonhearth/status", QoS::AtLeastOnce, true, "online");
                    },
                    Ok(_) => {},
                    Err(_) => {
                        connected = false;
                        state.automation().mqtt_status("reconnecting", "Broker unavailable or authentication rejected. Retrying locally.").await;
                        tokio::select! { _ = shutdown.changed() => return, _ = tokio::time::sleep(Duration::from_secs(3)) => {} }
                    },
                },
                _ = tick.tick(), if connected => {
                    if let Ok(snapshot) = state.automation().snapshot().await {
                        let payload = json!({"api_version":"v1","observed_at":chrono::Utc::now(),"source":"home_assistant","connection_status":snapshot.status,"devices":snapshot.devices});
                        match serde_json::to_vec(&payload) {
                            Ok(bytes) if bytes.len() < MAX_PAYLOAD_BYTES => {
                                if client.try_publish("neonhearth/automation/inventory", QoS::AtMostOnce, false, bytes).is_err() {
                                    dropped += 1;
                                }
                            }
                            // Too large for the broker's packet limit, or not
                            // serialisable: dropped, and reported below.
                            _ => dropped += 1,
                        }
                    }
                    // Host discovery status is exported separately from HA availability.
                    let payload = json!({"api_version":"v1","observed_at":chrono::Utc::now(),"collector_status":state.service_status().await});
                    if client.try_publish("neonhearth/network/status", QoS::AtMostOnce, false, payload.to_string()).is_err() {
                        dropped += 1;
                    }
                    if let Ok(devices) = state.state_repository().list_device_snapshots(256, None).await {
                        let page_full = devices.len() == 256;
                        let inventory: Vec<_> = devices.into_iter().map(|device| json!({
                            "device_id":device.device_id, "name":device.owner_name,
                            "type":device.owner_type, "owner_confirmed":device.owner_confirmed,
                            "first_seen_at":device.first_seen_at, "last_seen_at":device.last_seen_at,
                            "presence":device.presence.map(|presence| presence.to_state)
                        })).collect();
                        let payload = json!({"api_version":"v1","observed_at":chrono::Utc::now(),"page_limit":256,"more_may_be_available":page_full,"devices":inventory});
                        if client.try_publish("neonhearth/network/inventory", QoS::AtMostOnce, false, payload.to_string()).is_err() {
                            dropped += 1;
                        }
                    }
                    if dropped != reported_dropped {
                        reported_dropped = dropped;
                        tracing::warn!(dropped, "mqtt bridge dropped publishes (queue full or payload over the packet limit)");
                        state.automation().mqtt_status(
                            "connected",
                            &format!("Authenticated broker connected. {dropped} publish(es) were dropped (queue full or payload over the 4 MiB limit); MQTT commands are disabled."),
                        ).await;
                    }
                },
            }
        }
    })
}
