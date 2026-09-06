//! Owner-only address details. MAC correlation is a label hint, never control authority.
use super::{AutomationHub, Device, LocalOwner};
use crate::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use lattice_sensor::{
    SystemInterfaceManager,
    neighbor::{NeighborSnapshotSource, SystemNeighborSnapshotSource},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
use utoipa::ToSchema;

#[derive(Clone, Serialize, ToSchema)]
pub struct NetworkIdentityHint {
    pub device_id: String,
    pub name: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub area: Option<String>,
}
#[derive(Clone, Serialize, ToSchema)]
pub struct NetworkDeviceDetails {
    pub device_id: String,
    pub mac_addresses: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub home_assistant: Option<NetworkIdentityHint>,
}
#[derive(Clone, Serialize, ToSchema)]
pub struct NetworkDetails {
    pub status: String,
    pub observed_at: String,
    pub devices: Vec<NetworkDeviceDetails>,
}
pub(crate) struct CachedNetwork {
    at: Instant,
    details: NetworkDetails,
}

fn canonical_mac(value: &str) -> Option<String> {
    if value.len() != 17 {
        return None;
    }
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|v| v.len() != 2 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(value.to_ascii_uppercase())
}

fn enrich(devices: &mut [NetworkDeviceDetails], imported: &[Device]) {
    let mut by_mac: BTreeMap<String, Vec<&Device>> = BTreeMap::new();
    for device in imported {
        for mac in &device.mac_addresses {
            if let Some(mac) = canonical_mac(mac) {
                by_mac.entry(mac).or_default().push(device);
            }
        }
    }
    for device in devices {
        let mut candidates = BTreeMap::new();
        for mac in &device.mac_addresses {
            for candidate in by_mac.get(mac).into_iter().flatten() {
                candidates.insert(&candidate.device_id, *candidate);
            }
        }
        if candidates.len() == 1
            && let Some(matched) = candidates.values().next()
        {
            device.home_assistant = Some(NetworkIdentityHint {
                device_id: matched.device_id.clone(),
                name: matched.name.clone(),
                manufacturer: matched.manufacturer.clone(),
                model: matched.model.clone(),
                area: matched.area.clone(),
            });
        }
    }
}

impl AutomationHub {
    pub async fn network_details(&self) -> Result<NetworkDetails, StatusCode> {
        let mut cache = self.network_cache.lock().await;
        if let Some(cached) = &*cache
            && cached.at.elapsed() < Duration::from_secs(5)
        {
            return Ok(cached.details.clone());
        }
        let evidence: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT DISTINCT device_id,source,fact_value FROM evidence WHERE family='link_layer' AND fact_key='mac' AND length(fact_value)=17 AND length(source)<128 AND length(device_id)=36 LIMIT 4097"
        ).fetch_all(&self.pool).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if evidence.len() > 4096 {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let mut devices: BTreeMap<String, NetworkDeviceDetails> = BTreeMap::new();
        let mut identities: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for (id, source, address) in evidence {
            let Some(mac) = canonical_mac(&address) else {
                continue;
            };
            if lattice_domain::DeviceId::parse(&id).is_err() {
                continue;
            }
            identities
                .entry((source, mac.clone()))
                .or_default()
                .insert(id.clone());
            let device = devices
                .entry(id.clone())
                .or_insert_with(|| NetworkDeviceDetails {
                    device_id: id,
                    mac_addresses: vec![],
                    ip_addresses: vec![],
                    home_assistant: None,
                });
            if !device.mac_addresses.contains(&mac) && device.mac_addresses.len() < 32 {
                device.mac_addresses.push(mac);
            }
        }
        let config = tokio::task::spawn_blocking(|| {
            let inventory = SystemInterfaceManager.snapshot().ok()?;
            Some(
                crate::runtime::plan_inventory(&inventory)
                    .ok()?
                    .snapshot_config()
                    .clone(),
            )
        })
        .await
        .ok()
        .flatten();
        let neighbors = match config {
            Some(config) => SystemNeighborSnapshotSource::new(config)
                .snapshot()
                .await
                .ok(),
            None => None,
        };
        let status = if neighbors.is_some() {
            "ready"
        } else {
            "unavailable"
        };
        for row in neighbors.into_iter().flatten() {
            let source = format!("neighbor-interface-{}", row.interface().get());
            let Some(mac) = canonical_mac(&row.link_address().to_string()) else {
                continue;
            };
            let Some(ids) = identities.get(&(source, mac)) else {
                continue;
            };
            if ids.len() != 1 {
                continue;
            }
            let Some(device) = ids.first().and_then(|id| devices.get_mut(id)) else {
                continue;
            };
            let ip = row.ip().to_string();
            if !device.ip_addresses.contains(&ip) && device.ip_addresses.len() < 32 {
                device.ip_addresses.push(ip);
            }
        }
        let mut devices: Vec<_> = devices.into_values().collect();
        let snapshot = self.snapshot().await?;
        if snapshot.status == "connected" {
            enrich(&mut devices, &snapshot.devices);
        }
        let details = NetworkDetails {
            status: status.into(),
            observed_at: chrono::Utc::now().to_rfc3339(),
            devices,
        };
        *cache = Some(CachedNetwork {
            at: Instant::now(),
            details: details.clone(),
        });
        Ok(details)
    }
}

#[utoipa::path(get, path="/api/v1/automation/network", responses((status=200,body=NetworkDetails),(status=401),(status=503)), security(("bearer_auth"=[])))]
pub(crate) async fn network_route(_: LocalOwner, State(state): State<AppState>) -> Response {
    match state.automation().network_details().await {
        Ok(details) => Json(details).into_response(),
        Err(status) => status.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mac_matching_requires_one_device_and_never_manufactures_identity() {
        let imported: Device = serde_json::from_value(serde_json::json!({
            "device_id":"fixture-a", "upstream_id":"a", "name":"Desk light", "manufacturer":"Fixture", "model":null,
            "area":"Office", "mac_addresses":["aa:bb:cc:dd:ee:ff"], "first_seen_at":"", "last_seen_at":"", "entities":[]
        })).unwrap();
        let original = NetworkDeviceDetails {
            device_id: "network".into(),
            mac_addresses: vec!["AA:BB:CC:DD:EE:FF".into()],
            ip_addresses: vec![],
            home_assistant: None,
        };
        let mut devices = vec![original.clone()];
        enrich(&mut devices, std::slice::from_ref(&imported));
        assert_eq!(
            devices[0].home_assistant.as_ref().unwrap().name,
            "Desk light"
        );
        let mut ambiguous = imported.clone();
        ambiguous.device_id = "fixture-b".into();
        let mut devices = vec![original];
        enrich(&mut devices, &[imported, ambiguous]);
        assert!(devices[0].home_assistant.is_none());
        assert!(canonical_mac("<script>alert(1)").is_none());
        assert!(canonical_mac("aa:bb:cc:dd:ee:gg").is_none());
    }
}
