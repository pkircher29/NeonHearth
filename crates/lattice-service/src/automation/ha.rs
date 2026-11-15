//! Home Assistant WebSocket adapter. No raw state attributes leave this module.
use super::{AutomationHub, Device, Entity, QueuedCommand, Receipt};
use axum::http::StatusCode;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};
use tokio::{net::TcpStream, sync::mpsc, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
const IO_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_RECORDS: usize = 4096;
#[derive(Debug)]
pub enum AdapterError {
    Invalid,
    Connection,
    Authentication,
    Protocol,
}

pub fn validate_url(value: &str) -> Result<Url, AdapterError> {
    if value.len() > 512 {
        return Err(AdapterError::Invalid);
    }
    let mut url = Url::parse(value).map_err(|_| AdapterError::Invalid)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "/" | "/api/websocket")
    {
        return Err(AdapterError::Invalid);
    }
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    let scheme = match url.scheme() {
        "https" | "wss" => "wss",
        "http" | "ws" if loopback => "ws",
        _ => return Err(AdapterError::Invalid),
    };
    url.set_scheme(scheme).map_err(|_| AdapterError::Invalid)?;
    url.set_path("/api/websocket");
    Ok(url)
}
pub fn allowed_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        }
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00 == 0xfc00),
    }
}
async fn dial(url: &Url) -> Result<Socket, AdapterError> {
    let host = url
        .host_str()
        .ok_or(AdapterError::Invalid)?
        .trim_matches(['[', ']']);
    let addresses: Vec<_> = timeout(
        IO_TIMEOUT,
        tokio::net::lookup_host((
            host,
            url.port_or_known_default().ok_or(AdapterError::Invalid)?,
        )),
    )
    .await
    .map_err(|_| AdapterError::Connection)?
    .map_err(|_| AdapterError::Connection)?
    .take(17)
    .collect();
    if addresses.is_empty()
        || addresses.len() > 16
        || addresses
            .iter()
            .any(|address| !allowed_address(address.ip()))
    {
        return Err(AdapterError::Invalid);
    }
    let mut connection = None;
    for address in addresses {
        if let Ok(Ok(socket)) = timeout(Duration::from_secs(3), TcpStream::connect(address)).await {
            connection = Some(socket);
            break;
        }
    }
    let tcp = connection.ok_or(AdapterError::Connection)?;
    // Pin the resolved private address. TLS still validates the original hostname;
    // the handshake never follows redirects or resolves the hostname a second time.
    let config = WebSocketConfig::default()
        .max_message_size(Some(4 * 1024 * 1024))
        .max_frame_size(Some(4 * 1024 * 1024));
    timeout(
        IO_TIMEOUT,
        client_async_tls_with_config(url.as_str(), tcp, Some(config), None),
    )
    .await
    .map_err(|_| AdapterError::Connection)?
    .map(|(socket, _)| socket)
    .map_err(|_| AdapterError::Connection)
}
async fn send(socket: &mut Socket, value: Value) -> Result<(), AdapterError> {
    timeout(
        IO_TIMEOUT,
        socket.send(Message::Text(value.to_string().into())),
    )
    .await
    .map_err(|_| AdapterError::Connection)?
    .map_err(|_| AdapterError::Connection)
}
async fn receive(socket: &mut Socket) -> Result<Value, AdapterError> {
    loop {
        let message = socket
            .next()
            .await
            .ok_or(AdapterError::Connection)?
            .map_err(|_| AdapterError::Connection)?;
        match message {
            Message::Text(text) => {
                return serde_json::from_str(&text).map_err(|_| AdapterError::Protocol);
            }
            Message::Ping(bytes) => {
                socket
                    .send(Message::Pong(bytes))
                    .await
                    .map_err(|_| AdapterError::Connection)?;
            }
            Message::Pong(_) => {}
            _ => return Err(AdapterError::Connection),
        }
    }
}
async fn request(
    socket: &mut Socket,
    next_id: &mut u64,
    mut value: Value,
    hub: &AutomationHub,
    cancel: &CancellationToken,
    buffered: &mut Vec<Value>,
    importing: bool,
) -> Result<Value, AdapterError> {
    *next_id = next_id.checked_add(1).ok_or(AdapterError::Protocol)?;
    let id = *next_id;
    value["id"] = json!(id);
    send(socket, value).await?;
    timeout(IO_TIMEOUT, async {
        loop {
            let mut value = receive(socket).await?;
            if value["type"] == "event" {
                if importing {
                    if buffered.len() >= MAX_RECORDS {
                        return Err(AdapterError::Protocol);
                    }
                    buffered.push(value);
                } else {
                    hub.state_event(cancel, &value).await;
                }
            } else if value["id"] == id {
                if value["type"] == "pong" {
                    return Ok(Value::Null);
                }
                if value["type"] != "result" || value["success"] != true {
                    return Err(AdapterError::Protocol);
                }
                return Ok(value["result"].take());
            }
        }
    })
    .await
    .map_err(|_| AdapterError::Connection)?
}

pub(crate) fn text(value: &Value, max: usize) -> Option<String> {
    let value = value.as_str()?;
    (!value.is_empty() && value.len() <= max && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}
pub fn valid_entity_id(value: &str) -> bool {
    value.len() <= 255
        && value.split_once('.').is_some_and(|(domain, name)| {
            !domain.is_empty()
                && !name.is_empty()
                && domain
                    .bytes()
                    .chain(name.bytes())
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}
fn records(value: &Value) -> Result<&Vec<Value>, AdapterError> {
    value
        .as_array()
        .filter(|items| items.len() <= MAX_RECORDS)
        .ok_or(AdapterError::Protocol)
}
fn mac(value: &Value) -> Option<String> {
    let value = value.as_str()?.replace([':', '-'], "");
    if value.len() != 12 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        value
            .as_bytes()
            .chunks(2)
            .map(|part| std::str::from_utf8(part).unwrap_or("").to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(":"),
    )
}
pub fn project(
    areas: &Value,
    devices: &Value,
    registry: &Value,
    states: &Value,
    services: &Value,
) -> Result<(Vec<Device>, Vec<String>), AdapterError> {
    let areas: BTreeMap<_, _> = records(areas)?
        .iter()
        .filter_map(|a| Some((text(&a["area_id"], 128)?, text(&a["name"], 128)?)))
        .collect();
    let registry: BTreeMap<_, _> = records(registry)?
        .iter()
        .filter_map(|e| Some((e["entity_id"].as_str()?, e)))
        .collect();
    let now = Utc::now().to_rfc3339();
    let mut output: BTreeMap<String, Device> = BTreeMap::new();
    for d in records(devices)? {
        let Some(id) = text(&d["id"], 128) else {
            continue;
        };
        let area = d["area_id"].as_str().and_then(|id| areas.get(id)).cloned();
        let mac_addresses = d["connections"]
            .as_array()
            .into_iter()
            .flatten()
            .take(32)
            .filter(|c| c[0] == "mac")
            .filter_map(|c| mac(&c[1]))
            .collect();
        output.insert(
            id.clone(),
            Device {
                device_id: Uuid::now_v7().to_string(),
                upstream_id: id,
                name: text(&d["name_by_user"], 256)
                    .or_else(|| text(&d["name"], 256))
                    .unwrap_or_else(|| "Unnamed device".into()),
                manufacturer: text(&d["manufacturer"], 128),
                model: text(&d["model"], 128),
                area,
                mac_addresses,
                first_seen_at: now.clone(),
                last_seen_at: now.clone(),
                entities: vec![],
            },
        );
    }
    for s in records(states)? {
        let Some(id) = text(&s["entity_id"], 255).filter(|id| valid_entity_id(id)) else {
            continue;
        };
        let r = registry.get(id.as_str()).copied().unwrap_or(&Value::Null);
        if !r["disabled_by"].is_null() {
            continue;
        }
        let domain = id.split_once('.').map(|(domain, _)| domain).unwrap_or("");
        let platform = text(&r["platform"], 128);
        let power_capable = matches!(domain, "light" | "switch")
            && platform.as_deref() != Some("group")
            && s["attributes"]["entity_id"].is_null()
            && services[domain].get("turn_on").is_some()
            && services[domain].get("turn_off").is_some();
        let key = text(&r["device_id"], 128).unwrap_or_else(|| format!("entity:{id}"));
        let device = output.entry(key.clone()).or_insert_with(|| Device {
            device_id: Uuid::now_v7().to_string(),
            upstream_id: key,
            name: text(&s["attributes"]["friendly_name"], 256).unwrap_or_else(|| id.clone()),
            manufacturer: None,
            model: None,
            area: None,
            mac_addresses: vec![],
            first_seen_at: now.clone(),
            last_seen_at: now.clone(),
            entities: vec![],
        });
        let area = r["area_id"]
            .as_str()
            .and_then(|id| areas.get(id))
            .cloned()
            .or_else(|| device.area.clone());
        device.entities.push(Entity {
            entity_id: id.clone(),
            name: text(&s["attributes"]["friendly_name"], 256).unwrap_or(id),
            state: text(&s["state"], 128).unwrap_or_else(|| "unknown".into()),
            last_changed: text(&s["last_changed"], 64),
            last_updated: text(&s["last_updated"], 64),
            area,
            platform,
            power_capable,
            control_enabled: false,
        });
    }
    if output.len() > MAX_RECORDS {
        return Err(AdapterError::Protocol);
    }
    Ok((
        output.into_values().collect(),
        areas
            .into_values()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    ))
}

async fn import(
    socket: &mut Socket,
    next_id: &mut u64,
    hub: &AutomationHub,
    url: &Url,
    cancel: &CancellationToken,
) -> Result<(), AdapterError> {
    let mut buffered = vec![];
    let mut results = Vec::new();
    for kind in [
        "config/area_registry/list",
        "config/device_registry/list",
        "config/entity_registry/list",
        "get_states",
        "get_services",
    ] {
        results.push(
            request(
                socket,
                next_id,
                json!({"type":kind}),
                hub,
                cancel,
                &mut buffered,
                true,
            )
            .await?,
        );
    }
    let (devices, areas) = project(
        &results[0],
        &results[1],
        &results[2],
        &results[3],
        &results[4],
    )?;
    hub.import(cancel, url.as_str(), devices, areas)
        .await
        .map_err(|_| AdapterError::Protocol)?;
    for event in buffered {
        hub.state_event(cancel, &event).await;
    }
    Ok(())
}

async fn execute(
    socket: &mut Socket,
    next_id: &mut u64,
    hub: &AutomationHub,
    cancel: &CancellationToken,
    command: QueuedCommand,
) {
    let result = execute_inner(socket, next_id, hub, cancel, &command.request).await;
    let _ = command.result.send(result);
}
async fn execute_inner(
    socket: &mut Socket,
    next_id: &mut u64,
    hub: &AutomationHub,
    cancel: &CancellationToken,
    command: &super::CommandRequest,
) -> Result<Receipt, StatusCode> {
    let _configuration = hub.configuration.lock().await;
    if cancel.is_cancelled()
        || Utc::now()
            .signed_duration_since(command.issued_at)
            .num_seconds()
            > 60
    {
        return Err(StatusCode::CONFLICT);
    }
    let source = hub.authorize_command(command, false).await?;
    let key = command.command_id.to_string();
    let previous: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT source,entity_id,action,status FROM automation_commands WHERE command_id=?",
    )
    .bind(&key)
    .fetch_optional(&hub.pool)
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if let Some((old_source, entity, action, status)) = previous {
        if source != old_source || entity != command.entity_id || action != command.action.as_str()
        {
            return Err(StatusCode::CONFLICT);
        }
        return Ok(Receipt {
            command_id: command.command_id,
            status,
            detail: "Existing command receipt. The command was not sent again.".into(),
        });
    }
    hub.authorize_command(command, true).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM automation_commands")
        .fetch_one(&hub.pool)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if count >= 100_000 {
        return Err(StatusCode::INSUFFICIENT_STORAGE);
    }
    hub.audit(
        "automation.power_intent",
        Some(command.entity_id.clone()),
        json!({"command_id":key,"action":command.action}),
    )
    .await?;
    sqlx::query("INSERT INTO automation_commands(command_id,source,entity_id,action,status,created_at) VALUES(?,?,?,?,?,?)").bind(&key).bind(source).bind(&command.entity_id).bind(command.action.as_str()).bind("uncertain").bind(Utc::now().to_rfc3339()).execute(&hub.pool).await.map_err(|_| StatusCode::CONFLICT)?;
    let domain = command
        .entity_id
        .split_once('.')
        .ok_or(StatusCode::BAD_REQUEST)?
        .0;
    let result = request(socket, next_id, json!({"type":"call_service","domain":domain,"service":command.action.as_str(),"target":{"entity_id":command.entity_id}}), hub, cancel, &mut vec![], false).await;
    let (status, detail) = if result.is_ok() {
        (
            "accepted",
            "Home Assistant accepted the command. The displayed state updates only from Home Assistant observations.",
        )
    } else {
        (
            "uncertain",
            "No successful acknowledgement. Check the device state before issuing another command; this command will not be retried.",
        )
    };
    sqlx::query("UPDATE automation_commands SET status=? WHERE command_id=?")
        .bind(status)
        .bind(&key)
        .execute(&hub.pool)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    hub.audit(
        "automation.power_result",
        Some(command.entity_id.clone()),
        json!({"command_id":key,"status":status}),
    )
    .await?;
    Ok(Receipt {
        command_id: command.command_id,
        status: status.into(),
        detail: detail.into(),
    })
}

async fn connected(
    hub: &AutomationHub,
    url: &Url,
    secret: &SecretString,
    cancel: &CancellationToken,
    commands: &mut mpsc::Receiver<QueuedCommand>,
) -> Result<(), AdapterError> {
    let mut socket = dial(url).await?;
    let hello = timeout(IO_TIMEOUT, receive(&mut socket))
        .await
        .map_err(|_| AdapterError::Connection)??;
    if hello["type"] != "auth_required" {
        return Err(AdapterError::Protocol);
    }
    send(
        &mut socket,
        json!({"type":"auth","access_token":secret.expose_secret()}),
    )
    .await?;
    let auth = timeout(IO_TIMEOUT, receive(&mut socket))
        .await
        .map_err(|_| AdapterError::Connection)??;
    if auth["type"] != "auth_ok" {
        return Err(AdapterError::Authentication);
    }
    let mut next_id = 0;
    request(
        &mut socket,
        &mut next_id,
        json!({"type":"subscribe_events","event_type":"state_changed"}),
        hub,
        cancel,
        &mut vec![],
        false,
    )
    .await?;
    import(&mut socket, &mut next_id, hub, url, cancel).await?;
    hub.set_status(
        cancel,
        "connected",
        "Live Home Assistant states. Control requires your permission for each entity.",
    )
    .await;
    let mut refresh = tokio::time::interval(Duration::from_secs(60));
    refresh.tick().await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    heartbeat.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            message = receive(&mut socket) => {
                let message = message?;
                if message["type"] == "event" { hub.state_event(cancel, &message).await; }
            },
            command = commands.recv() => {
                if let Some(command) = command { execute(&mut socket, &mut next_id, hub, cancel, command).await; } else { return Ok(()); }
            },
            _ = heartbeat.tick() => { request(&mut socket, &mut next_id, json!({"type":"ping"}), hub, cancel, &mut vec![], false).await?; },
            _ = refresh.tick() => { import(&mut socket, &mut next_id, hub, url, cancel).await?; },
        }
    }
}
pub(crate) async fn run(
    hub: AutomationHub,
    url: Url,
    secret: SecretString,
    cancel: CancellationToken,
    mut commands: mpsc::Receiver<QueuedCommand>,
) {
    let mut delay = 2;
    loop {
        let outcome = tokio::select! { _ = cancel.cancelled() => return, result = connected(&hub, &url, &secret, &cancel, &mut commands) => result };
        match outcome {
            Ok(()) => return,
            Err(AdapterError::Authentication) => { hub.set_status(&cancel, "authentication_failed", "Home Assistant rejected the credential. Reconnect with a valid token.").await; return; },
            Err(AdapterError::Invalid) => { hub.set_status(&cancel, "connection_failed", "Only a private network or Tailscale destination is allowed. Use HTTPS; HTTP is limited to loopback.").await; return; },
            Err(_) => hub.set_status(&cancel, "reconnecting", "Connection interrupted or inventory rejected. Retrying; all power permissions have been cleared.").await,
        }
        while let Ok(command) = commands.try_recv() {
            let _ = command.result.send(Err(StatusCode::SERVICE_UNAVAILABLE));
        }
        tokio::select! { _ = cancel.cancelled() => return, _ = tokio::time::sleep(Duration::from_secs(delay)) => {} }
        delay = (delay * 2).min(30);
    }
}
