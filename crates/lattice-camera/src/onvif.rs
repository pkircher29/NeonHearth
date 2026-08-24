//! Bounded ONVIF inventory contracts.  This crate deliberately has no socket
//! implementation: callers must authorize an exact numeric target first.
use async_trait::async_trait;
use quick_xml::{Reader, events::Event};
use secrecy::SecretString;
use serde::Serialize;
use std::{net::IpAddr, time::Duration};
use thiserror::Error;
use uuid::Uuid;

const DEVICE: &str = "http://www.onvif.org/ver10/device/wsdl";
const MEDIA: &str = "http://www.onvif.org/ver10/media/wsdl";
const SCHEMA: &str = "http://www.onvif.org/ver10/schema";

/// An exact caller-approved socket address and ONVIF path.  It intentionally
/// does not implement serialization or display.
#[derive(Clone, Eq, PartialEq)]
pub struct TargetAddress {
    address: IpAddr,
    port: u16,
    tls: bool,
    path: String,
}
impl TargetAddress {
    pub fn new(
        address: IpAddr,
        port: u16,
        tls: bool,
        path: impl Into<String>,
    ) -> Result<Self, OnvifError> {
        let path = path.into();
        if port == 0 || !path.starts_with('/') || path.starts_with("//") || path.contains(['?', '#', '@', '\\']) || path.len() > 128 || path.bytes().any(|b| b.is_ascii_control()) || path.split('/').any(|p| p=="." || p=="..")
        {
            return Err(OnvifError::InvalidTarget);
        }
        Ok(Self {
            address,
            port,
            tls,
            path,
        })
    }
    pub const fn address(&self) -> IpAddr {
        self.address
    }
    pub const fn port(&self) -> u16 {
        self.port
    }
    pub const fn tls(&self) -> bool {
        self.tls
    }
    pub fn path(&self) -> &str {
        &self.path
    }
}

pub struct OnvifCredential {
    username: String,
    password: SecretString,
}
impl OnvifCredential {
    pub fn new(username: impl Into<String>, password: SecretString) -> Result<Self, OnvifError> {
        let username = username.into();
        if username.is_empty() || username.len() > 128 || !username.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.'|b'_'|b'-')) {
            return Err(OnvifError::InvalidCredential);
        }
        Ok(Self { username, password })
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn password(&self) -> &SecretString {
        &self.password
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnvifAction {
    GetDeviceInformation,
    GetCapabilities,
    GetProfiles,
    GetStreamUri,
}
#[async_trait]
pub trait OnvifTransport: Send + Sync {
    async fn request(
        &self,
        target: &TargetAddress,
        action: OnvifAction,
        credential: Option<&OnvifCredential>,
        timeout: Duration,
    ) -> Result<String, OnvifError>;
}
pub trait StreamSecretSink: Send + Sync {
    fn store(&self, stream: StreamId, source: SecretString) -> Result<(), OnvifError>;
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct StreamId(Uuid);
impl StreamId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}
impl Default for StreamId {
    fn default() -> Self {
        Self::new()
    }
}
impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StreamSourceRef(String);
impl StreamSourceRef {
    pub fn new(value: impl Into<String>) -> Result<Self, OnvifError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(OnvifError::InvalidReference);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundedSerial(String);
impl BoundedSerial {
    pub fn new(value: impl AsRef<str>) -> Option<Self> {
        let v = value.as_ref().trim();
        (!v.is_empty()
            && v.len() <= 128
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'))
        .then(|| Self(v.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct CameraInventory {
    pub manufacturer: Option<BoundedSerial>,
    pub model: Option<BoundedSerial>,
    pub firmware: Option<BoundedSerial>,
    pub serial: Option<BoundedSerial>,
    pub profiles: Vec<StreamId>,
    pub capabilities: Vec<BoundedSerial>,
    pub health: CameraHealth,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all="snake_case")]
pub enum CameraHealth { Healthy, Degraded }
#[derive(Clone, Debug)]
pub struct InventoryLimits {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_xml_depth: usize,
    pub max_facts: usize,
    pub max_events: usize,
    pub max_profiles: usize,
    pub max_field_bytes: usize,
    pub max_uri_bytes: usize,
    pub timeout: Duration,
}
impl Default for InventoryLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 16 * 1024, max_response_bytes: 64 * 1024,
            max_xml_depth: 32,
            max_facts: 16, max_events: 1024, max_profiles: 16, max_field_bytes: 128, max_uri_bytes: 2048,
            timeout: Duration::from_secs(5),
        }
    }
}
#[derive(Debug, Error, Eq, PartialEq)]
pub enum OnvifError {
    #[error("invalid ONVIF target")]
    InvalidTarget,
    #[error("invalid credential")]
    InvalidCredential,
    #[error("invalid reference")]
    InvalidReference,
    #[error("authentication failed")]
    Authentication,
    #[error("transport unavailable")]
    Transport,
    #[error("TLS validation failed")]
    Tls,
    #[error("request timed out")]
    Timeout,
    #[error("ONVIF response exceeds limit")]
    ResponseTooLarge,
    #[error("invalid ONVIF response")]
    InvalidResponse,
    #[error("invalid inventory limits")]
    InvalidLimits,
    #[error("stream sink failed")]
    Sink,
}

pub async fn inventory<T: OnvifTransport, S: StreamSecretSink>(
    transport: &T,
    sink: &S,
    target: TargetAddress,
    credential: Option<&OnvifCredential>,
    limits: InventoryLimits,
) -> Result<CameraInventory, OnvifError> {
    if limits.max_request_bytes==0 || limits.max_response_bytes==0 || limits.max_xml_depth==0 || limits.max_facts==0 || limits.max_events==0 || limits.max_profiles==0 || limits.max_field_bytes==0 || limits.max_uri_bytes==0 || limits.timeout.is_zero() { return Err(OnvifError::InvalidLimits); }
    let device = transport
        .request(
            &target,
            OnvifAction::GetDeviceInformation,
            credential,
            limits.timeout,
        )
        .await?;
    let facts = parse(&device, DEVICE, "GetDeviceInformationResponse", &limits)?;
    let caps = transport
        .request(
            &target,
            OnvifAction::GetCapabilities,
            credential,
            limits.timeout,
        )
        .await?;
    let capfacts = parse(&caps, DEVICE, "GetCapabilitiesResponse", &limits)?;
    let profiles = transport
        .request(
            &target,
            OnvifAction::GetProfiles,
            credential,
            limits.timeout,
        )
        .await?;
    let tokens = parse_profiles(&profiles, &limits)?;
    let mut streams = Vec::new();
    for _ in tokens {
        let uri = transport
            .request(
                &target,
                OnvifAction::GetStreamUri,
                credential,
                limits.timeout,
            )
            .await?;
        let source = parse_uri(&uri, &limits)?;
        let id = StreamId::new();
        sink.store(id, SecretString::from(source))
            .map_err(|_| OnvifError::Sink)?;
        streams.push(id);
    }
    Ok(CameraInventory {
        manufacturer: facts.get("Manufacturer").and_then(BoundedSerial::new),
        model: facts.get("Model").and_then(BoundedSerial::new),
        firmware: facts.get("FirmwareVersion").and_then(BoundedSerial::new),
        serial: facts.get("SerialNumber").and_then(BoundedSerial::new),
        profiles: streams,
        capabilities: capfacts.get("Media").and_then(BoundedSerial::new)
            .map(|_| vec![BoundedSerial::new("media").unwrap()])
            .unwrap_or_default(),
        health: CameraHealth::Healthy,
    })
}
fn parse(
    input: &str,
    namespace: &str,
    response: &str,
    limits: &InventoryLimits,
) -> Result<std::collections::BTreeMap<String, String>, OnvifError> {
    let events = xml(input, limits)?;
    if !events
        .iter()
        .any(|(n, ns, _)| n == response && ns == namespace)
    {
        return Err(OnvifError::InvalidResponse);
    };
    Ok(events
        .into_iter()
        .filter_map(|(n, _, v)| {
            matches!(
                n.as_str(),
                "Manufacturer" | "Model" | "FirmwareVersion" | "SerialNumber" | "Media"
            )
            .then_some((n, v))
        })
        .collect())
}
fn parse_profiles(input: &str, limits: &InventoryLimits) -> Result<Vec<String>, OnvifError> {
    let events = xml(input, limits)?;
    if !events
        .iter()
        .any(|(n, ns, _)| n == "GetProfilesResponse" && ns == MEDIA)
    {
        return Err(OnvifError::InvalidResponse);
    };
    let p: Vec<_> = events
        .into_iter()
        .filter(|(n, _, _)| n == "Profiles")
        .map(|(_, _, v)| v)
        .collect();
    if p.len() > limits.max_facts {
        return Err(OnvifError::InvalidResponse);
    }
    Ok(p)
}
fn parse_uri(input: &str, limits: &InventoryLimits) -> Result<String, OnvifError> {
    let events = xml(input, limits)?;
    if !events
        .iter()
        .any(|(n, ns, _)| n == "GetStreamUriResponse" && ns == MEDIA)
    {
        return Err(OnvifError::InvalidResponse);
    };
    events
        .into_iter()
        .find(|(n, ns, v)| n == "Uri" && ns == SCHEMA && !v.is_empty())
        .map(|(_, _, v)| v)
        .filter(|v| v.len() <= limits.max_uri_bytes && v.starts_with("rtsp://"))
        .ok_or(OnvifError::InvalidResponse)
}
fn xml(input: &str, limits: &InventoryLimits) -> Result<Vec<(String, String, String)>, OnvifError> {
    if input.len() > limits.max_response_bytes
        || input.contains("<!DOCTYPE")
        || input.contains("<!ENTITY")
    {
        return Err(if input.len() > limits.max_response_bytes {
            OnvifError::ResponseTooLarge
        } else {
            OnvifError::InvalidResponse
        });
    }
    let mut r = Reader::from_str(input);
    r.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut stack: Vec<(String, String)> = Vec::new();
    let mut out = Vec::new();
    let mut events=0usize; loop {
        events+=1; if events>limits.max_events { return Err(OnvifError::InvalidResponse); }
        match r
            .read_event_into(&mut buf)
            .map_err(|_| OnvifError::InvalidResponse)?
        {
            Event::Start(e) => {
                if stack.len() >= limits.max_xml_depth {
                    return Err(OnvifError::InvalidResponse);
                }
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let ns = e
                    .attributes()
                    .flatten()
                    .find_map(|a| {
                        let k = String::from_utf8_lossy(a.key.as_ref());
                        (k == "xmlns" || k.starts_with("xmlns:"))
                            .then(|| String::from_utf8_lossy(&a.value).to_string())
                    })
                    .unwrap_or_default();
                out.push((name.clone(), ns.clone(), String::new()));
                stack.push((name, ns));
            }
            Event::Empty(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let ns = e
                    .attributes()
                    .flatten()
                    .find_map(|a| {
                        let k = String::from_utf8_lossy(a.key.as_ref());
                        (k == "xmlns" || k.starts_with("xmlns:"))
                            .then(|| String::from_utf8_lossy(&a.value).to_string())
                    })
                    .unwrap_or_default();
                out.push((name, ns, String::new()));
            }
            Event::Text(t) => {
                if let Some((n, ns)) = stack.last() {
                    out.push((
                        n.clone(),
                        ns.clone(),
                        t.decode()
                            .map_err(|_| OnvifError::InvalidResponse)?
                            .into_owned(),
                    ));
                }
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear()
    }
    if !stack.is_empty() {
        return Err(OnvifError::InvalidResponse);
    }
    Ok(out)
}
