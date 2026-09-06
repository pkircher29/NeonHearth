//! Bounded, fixture-driven ONVIF inventory contracts.
//!
//! This module intentionally contains no production socket transport. The caller
//! authorizes an exact target and supplies a transport implementation.

use async_trait::async_trait;
use quick_xml::{
    escape::unescape,
    events::{BytesStart, Event},
    name::ResolveResult,
    reader::NsReader,
};
use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeSet, fmt, net::IpAddr, time::Duration};
use thiserror::Error;
use uuid::Uuid;

const SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
const WSA: &str = "http://www.w3.org/2005/08/addressing";
const DEVICE: &str = "http://www.onvif.org/ver10/device/wsdl";
const MEDIA: &str = "http://www.onvif.org/ver10/media/wsdl";
const SCHEMA: &str = "http://www.onvif.org/ver10/schema";
const MAX_PUBLIC_TEXT_BYTES: usize = 128;
const MAX_OPAQUE_REF_BYTES: usize = 128;
const MAX_XML_NAME_BYTES: usize = 128;

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
        let valid_path = path.starts_with('/')
            && !path.starts_with("//")
            && path.len() <= 128
            && path.bytes().all(|byte| {
                byte.is_ascii_graphic()
                    && !matches!(
                        byte,
                        b'?' | b'#' | b'@' | b'\\' | b'\'' | b'"' | b'<' | b'>' | b'&'
                    )
            })
            && !path.split('/').any(|part| matches!(part, "." | ".."));
        if port == 0 || !valid_path {
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

    fn endpoint(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        match self.address {
            IpAddr::V4(address) => {
                format!("{scheme}://{address}:{}{path}", self.port, path = self.path)
            }
            IpAddr::V6(address) => format!(
                "{scheme}://[{address}]:{}{path}",
                self.port,
                path = self.path
            ),
        }
    }
}

pub struct OnvifCredential {
    username: String,
    password: SecretString,
}

impl OnvifCredential {
    pub fn new(username: impl Into<String>, password: SecretString) -> Result<Self, OnvifError> {
        let username = username.into();
        if username.is_empty()
            || username.len() > MAX_PUBLIC_TEXT_BYTES
            || !username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
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

#[derive(Clone, Eq, PartialEq)]
pub struct ProfileToken(String);

impl ProfileToken {
    fn new(value: &str, limit: usize) -> Result<Self, OnvifError> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > limit.min(MAX_PUBLIC_TEXT_BYTES)
            || value.bytes().any(|byte| {
                byte.is_ascii_control() || matches!(byte, b'<' | b'>' | b'&' | b'\'' | b'"')
            })
        {
            return Err(OnvifError::InvalidResponse);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProfileToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProfileToken([redacted])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnvifAction {
    GetDeviceInformation,
    GetCapabilities,
    GetProfiles,
    GetStreamUri { profile_token: ProfileToken },
    GetSystemDateAndTime,
}

impl OnvifAction {
    fn request_action(&self) -> &'static str {
        match self {
            Self::GetDeviceInformation => {
                "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"
            }
            Self::GetCapabilities => "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
            Self::GetProfiles => "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
            Self::GetStreamUri { .. } => "http://www.onvif.org/ver10/media/wsdl/GetStreamUri",
            Self::GetSystemDateAndTime => {
                "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"
            }
        }
    }

    fn response_action(&self) -> &'static str {
        match self {
            Self::GetDeviceInformation => {
                "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse"
            }
            Self::GetCapabilities => {
                "http://www.onvif.org/ver10/device/wsdl/GetCapabilitiesResponse"
            }
            Self::GetProfiles => "http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse",
            Self::GetStreamUri { .. } => {
                "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse"
            }
            Self::GetSystemDateAndTime => {
                "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse"
            }
        }
    }

    fn response_name(&self) -> (&'static str, &'static str) {
        match self {
            Self::GetDeviceInformation => (DEVICE, "GetDeviceInformationResponse"),
            Self::GetCapabilities => (DEVICE, "GetCapabilitiesResponse"),
            Self::GetProfiles => (MEDIA, "GetProfilesResponse"),
            Self::GetStreamUri { .. } => (MEDIA, "GetStreamUriResponse"),
            Self::GetSystemDateAndTime => (DEVICE, "GetSystemDateAndTimeResponse"),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OnvifMessageId(String);

impl OnvifMessageId {
    fn new() -> Self {
        Self(format!("urn:uuid:{}", Uuid::now_v7()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OnvifMessageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OnvifMessageId([opaque])")
    }
}

pub struct OnvifRequest {
    action: OnvifAction,
    message_id: OnvifMessageId,
    bytes: Box<[u8]>,
    max_response_bytes: usize,
    timeout: Duration,
}

impl OnvifRequest {
    fn new(
        action: OnvifAction,
        target: &TargetAddress,
        limits: &InventoryLimits,
    ) -> Result<Self, OnvifError> {
        let message_id = OnvifMessageId::new();
        let body = request_body(&action);
        let xml = format!(
            "<s:Envelope xmlns:s=\"{SOAP}\" xmlns:wsa=\"{WSA}\" xmlns:tds=\"{DEVICE}\" xmlns:trt=\"{MEDIA}\" xmlns:tt=\"{SCHEMA}\"><s:Header><wsa:Action>{}</wsa:Action><wsa:MessageID>{}</wsa:MessageID><wsa:To>{}</wsa:To></s:Header><s:Body>{body}</s:Body></s:Envelope>",
            action.request_action(),
            message_id.as_str(),
            target.endpoint()
        );
        if xml.len() > limits.max_request_bytes {
            return Err(OnvifError::RequestTooLarge);
        }
        Ok(Self {
            action,
            message_id,
            bytes: xml.into_bytes().into_boxed_slice(),
            max_response_bytes: limits.max_response_bytes,
            timeout: limits.timeout,
        })
    }

    pub fn action(&self) -> &OnvifAction {
        &self.action
    }
    pub fn message_id(&self) -> &OnvifMessageId {
        &self.message_id
    }
    pub fn request_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl fmt::Debug for OnvifRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnvifRequest")
            .field("action", &self.action)
            .field("message_id", &self.message_id)
            .field("request_bytes", &self.bytes.len())
            .field("max_response_bytes", &self.max_response_bytes)
            .field("timeout", &self.timeout)
            .finish()
    }
}

struct BoundedOnvifResponse {
    bytes: Box<[u8]>,
}

impl BoundedOnvifResponse {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for BoundedOnvifResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedOnvifResponse")
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// Inventory-owned bounded collector supplied to an ONVIF transport.
///
/// A rejected chunk poisons the collector, so a transport cannot ignore a
/// bounds error and return a truncated response as though it were complete.
pub struct OnvifResponseWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
    rejected: bool,
}

impl OnvifResponseWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_bytes,
            rejected: false,
        }
    }

    /// Appends one transport chunk after proving the resulting response stays
    /// within the request's response limit.
    pub fn append_chunk(&mut self, chunk: &[u8]) -> Result<(), OnvifError> {
        if self.rejected {
            return Err(OnvifError::ResponseTooLarge);
        }
        let Some(next_len) = self.bytes.len().checked_add(chunk.len()) else {
            self.rejected = true;
            return Err(OnvifError::ResponseTooLarge);
        };
        if next_len > self.max_bytes {
            self.rejected = true;
            return Err(OnvifError::ResponseTooLarge);
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    fn finish(self) -> Result<BoundedOnvifResponse, OnvifError> {
        if self.rejected {
            return Err(OnvifError::ResponseTooLarge);
        }
        Ok(BoundedOnvifResponse {
            bytes: self.bytes.into_boxed_slice(),
        })
    }
}

impl fmt::Debug for OnvifResponseWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnvifResponseWriter")
            .field("bytes", &self.bytes.len())
            .field("max_bytes", &self.max_bytes)
            .field("rejected", &self.rejected)
            .finish()
    }
}

#[async_trait]
pub trait OnvifTransport: Send + Sync {
    async fn request(
        &self,
        target: &TargetAddress,
        request: &OnvifRequest,
        credential: Option<&OnvifCredential>,
        response: &mut OnvifResponseWriter,
    ) -> Result<(), OnvifError>;
}

pub trait StreamSecretSink: Send + Sync {
    /// Atomically stores the bounded batch or stores none of it. Returned
    /// references correspond positionally to the supplied stream IDs.
    fn store_all(
        &self,
        sources: Vec<(StreamId, SecretString)>,
    ) -> Result<Vec<StreamSourceRef>, OnvifError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StreamId(Uuid);

impl StreamId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }

    fn for_profile(target: &TargetAddress, profile_token: &ProfileToken) -> Self {
        fn append(identity: &mut Vec<u8>, component: &[u8]) {
            identity.extend_from_slice(&(component.len() as u64).to_be_bytes());
            identity.extend_from_slice(component);
        }
        let mut identity = Vec::with_capacity(256);
        append(&mut identity, target.address.to_string().as_bytes());
        append(&mut identity, &target.port.to_be_bytes());
        append(&mut identity, &[u8::from(target.tls)]);
        append(&mut identity, target.path.as_bytes());
        append(&mut identity, profile_token.as_str().as_bytes());
        Self(Uuid::new_v5(&Uuid::NAMESPACE_URL, &identity))
    }
}

impl Default for StreamId {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Display for StreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
pub struct StreamSourceRef(String);

impl StreamSourceRef {
    pub fn new(value: impl Into<String>) -> Result<Self, OnvifError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_OPAQUE_REF_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(OnvifError::InvalidReference);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for StreamSourceRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("StreamSourceRef")
            .field(&"[opaque]")
            .finish()
    }
}

impl<'de> Deserialize<'de> for StreamSourceRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundedMetadata(String);

impl BoundedMetadata {
    pub fn new(value: impl AsRef<str>) -> Result<Self, OnvifError> {
        let value = value.as_ref().trim();
        let normalized = value.to_ascii_lowercase();
        if value.is_empty()
            || value.len() > MAX_PUBLIC_TEXT_BYTES
            || value.chars().any(char::is_control)
            || value.contains('@')
            || ["://", "authorization", "password", "bearer"]
                .iter()
                .any(|marker| normalized.contains(marker))
        {
            return Err(OnvifError::InvalidMetadata);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for BoundedMetadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct BoundedSerial(String);

impl BoundedSerial {
    pub fn new(value: impl AsRef<str>) -> Result<Self, OnvifError> {
        let value = value.as_ref().trim();
        if value.is_empty()
            || value.len() > MAX_PUBLIC_TEXT_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(OnvifError::InvalidMetadata);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedSerial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedSerial([redacted])")
    }
}

impl<'de> Deserialize<'de> for BoundedSerial {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CameraProfile {
    stream_id: StreamId,
    source_ref: StreamSourceRef,
}

impl CameraProfile {
    pub const fn new(stream_id: StreamId, source_ref: StreamSourceRef) -> Self {
        Self {
            stream_id,
            source_ref,
        }
    }
    pub const fn stream_id(&self) -> StreamId {
        self.stream_id
    }
    pub fn source_ref(&self) -> &StreamSourceRef {
        &self.source_ref
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CameraInventory {
    pub manufacturer: Option<BoundedMetadata>,
    pub model: Option<BoundedMetadata>,
    pub firmware: Option<BoundedMetadata>,
    #[serde(skip_serializing)]
    pub serial: Option<BoundedSerial>,
    pub profiles: Vec<CameraProfile>,
    pub capabilities: Vec<BoundedMetadata>,
    pub health: CameraHealth,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraHealth {
    Healthy,
    Degraded,
}

#[derive(Clone, Debug)]
pub struct InventoryLimits {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_xml_depth: usize,
    pub max_facts: usize,
    pub max_events: usize,
    pub max_profiles: usize,
    pub max_capabilities: usize,
    pub max_field_bytes: usize,
    pub max_token_bytes: usize,
    pub max_uri_bytes: usize,
    pub timeout: Duration,
}

impl Default for InventoryLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 16 * 1024,
            max_response_bytes: 64 * 1024,
            max_xml_depth: 32,
            max_facts: 16,
            max_events: 2_048,
            max_profiles: 16,
            max_capabilities: 16,
            max_field_bytes: MAX_PUBLIC_TEXT_BYTES,
            max_token_bytes: MAX_PUBLIC_TEXT_BYTES,
            max_uri_bytes: 2_048,
            timeout: Duration::from_secs(5),
        }
    }
}

impl InventoryLimits {
    fn validate(&self) -> Result<(), OnvifError> {
        let counts_valid = self.max_request_bytes > 0
            && self.max_request_bytes <= 64 * 1024
            && self.max_response_bytes > 0
            && self.max_response_bytes <= 1024 * 1024
            && (1..=64).contains(&self.max_xml_depth)
            && (1..=64).contains(&self.max_facts)
            && (1..=16_384).contains(&self.max_events)
            && (1..=64).contains(&self.max_profiles)
            && (1..=32).contains(&self.max_capabilities)
            && (1..=MAX_PUBLIC_TEXT_BYTES).contains(&self.max_field_bytes)
            && (1..=MAX_PUBLIC_TEXT_BYTES).contains(&self.max_token_bytes)
            && (1..=4_096).contains(&self.max_uri_bytes);
        if !counts_valid || self.timeout.is_zero() || self.timeout > Duration::from_secs(30) {
            Err(OnvifError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OnvifError {
    #[error("invalid ONVIF target")]
    InvalidTarget,
    #[error("invalid credential")]
    InvalidCredential,
    #[error("invalid opaque reference")]
    InvalidReference,
    #[error("invalid bounded metadata")]
    InvalidMetadata,
    #[error("authentication failed")]
    Authentication,
    #[error("transport unavailable")]
    Transport,
    #[error("TLS validation failed")]
    Tls,
    #[error("request timed out")]
    Timeout,
    #[error("ONVIF request exceeds limit")]
    RequestTooLarge,
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
    limits.validate()?;
    let deadline = tokio::time::Instant::now() + limits.timeout;

    let device = exchange(
        transport,
        &target,
        credential,
        &limits,
        deadline,
        OnvifAction::GetDeviceInformation,
    )
    .await?;
    let device_facts = parse_device_information(&device, &limits)?;

    let capabilities = exchange(
        transport,
        &target,
        credential,
        &limits,
        deadline,
        OnvifAction::GetCapabilities,
    )
    .await?;
    let capabilities = parse_capabilities(&capabilities, &limits)?;

    let profiles = exchange(
        transport,
        &target,
        credential,
        &limits,
        deadline,
        OnvifAction::GetProfiles,
    )
    .await?;
    let tokens = parse_profiles(&profiles, &limits)?;
    let mut pending_sources = Vec::with_capacity(tokens.len());
    for profile_token in tokens {
        let stream_id = StreamId::for_profile(&target, &profile_token);
        let response = exchange(
            transport,
            &target,
            credential,
            &limits,
            deadline,
            OnvifAction::GetStreamUri { profile_token },
        )
        .await?;
        let source = parse_stream_uri(&response, &limits)?;
        pending_sources.push((stream_id, source));
    }

    let health_response = exchange(
        transport,
        &target,
        credential,
        &limits,
        deadline,
        OnvifAction::GetSystemDateAndTime,
    )
    .await?;
    let health = parse_health(&health_response, &limits)?;

    let stream_ids: Vec<_> = pending_sources
        .iter()
        .map(|(stream_id, _)| *stream_id)
        .collect();
    let source_refs = if pending_sources.is_empty() {
        Vec::new()
    } else {
        sink.store_all(pending_sources)
            .map_err(|_| OnvifError::Sink)?
    };
    if stream_ids.len() != source_refs.len() {
        return Err(OnvifError::Sink);
    }
    let profiles = stream_ids
        .into_iter()
        .zip(source_refs)
        .map(|(stream_id, source_ref)| CameraProfile::new(stream_id, source_ref))
        .collect();

    Ok(CameraInventory {
        manufacturer: device_facts.manufacturer,
        model: device_facts.model,
        firmware: device_facts.firmware,
        serial: device_facts.serial,
        profiles,
        capabilities,
        health,
    })
}

async fn exchange<T: OnvifTransport>(
    transport: &T,
    target: &TargetAddress,
    credential: Option<&OnvifCredential>,
    limits: &InventoryLimits,
    deadline: tokio::time::Instant,
    action: OnvifAction,
) -> Result<ParsedEnvelope, OnvifError> {
    let request = OnvifRequest::new(action, target, limits)?;
    let mut writer = OnvifResponseWriter::new(request.max_response_bytes());
    tokio::time::timeout_at(
        deadline,
        transport.request(target, &request, credential, &mut writer),
    )
    .await
    .map_err(|_| OnvifError::Timeout)??;
    let response = writer.finish()?;
    parse_envelope(response.as_bytes(), &request, limits)
}

fn request_body(action: &OnvifAction) -> String {
    match action {
        OnvifAction::GetDeviceInformation => "<tds:GetDeviceInformation/>".into(),
        OnvifAction::GetCapabilities => {
            "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>".into()
        }
        OnvifAction::GetProfiles => "<trt:GetProfiles/>".into(),
        OnvifAction::GetStreamUri { profile_token } => format!(
            "<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>{}</trt:ProfileToken></trt:GetStreamUri>",
            profile_token.as_str()
        ),
        OnvifAction::GetSystemDateAndTime => "<tds:GetSystemDateAndTime/>".into(),
    }
}

#[derive(Clone, Eq, PartialEq)]
struct XmlName {
    namespace: Option<String>,
    local: String,
}

#[derive(Clone)]
struct XmlAttribute {
    namespace: Option<String>,
    local: String,
    value: String,
}

#[derive(Clone)]
struct XmlNode {
    name: XmlName,
    attributes: Vec<XmlAttribute>,
    text: String,
    children: Vec<XmlNode>,
}

struct ParsedEnvelope {
    response: XmlNode,
}

fn parse_envelope(
    bytes: &[u8],
    request: &OnvifRequest,
    limits: &InventoryLimits,
) -> Result<ParsedEnvelope, OnvifError> {
    let root = parse_xml(bytes, limits)?;
    require_name(&root, SOAP, "Envelope")?;
    if !root.attributes.is_empty() || !root.text.trim().is_empty() || root.children.len() != 2 {
        return Err(OnvifError::InvalidResponse);
    }
    let header = &root.children[0];
    let body = &root.children[1];
    require_name(header, SOAP, "Header")?;
    require_name(body, SOAP, "Body")?;
    if !header.attributes.is_empty() || !header.text.trim().is_empty() || header.children.len() != 2
    {
        return Err(OnvifError::InvalidResponse);
    }
    let action = unique_child(header, WSA, "Action")?;
    let relates_to = unique_child(header, WSA, "RelatesTo")?;
    if leaf_text(action, 256)? != request.action.response_action()
        || leaf_text(relates_to, 128)? != request.message_id.as_str()
    {
        return Err(OnvifError::InvalidResponse);
    }
    if !body.attributes.is_empty() || !body.text.trim().is_empty() || body.children.len() != 1 {
        return Err(OnvifError::InvalidResponse);
    }
    let response = body
        .children
        .first()
        .cloned()
        .ok_or(OnvifError::InvalidResponse)?;
    let (namespace, local) = request.action.response_name();
    require_name(&response, namespace, local)?;
    Ok(ParsedEnvelope { response })
}

fn parse_xml(bytes: &[u8], limits: &InventoryLimits) -> Result<XmlNode, OnvifError> {
    if bytes.len() > limits.max_response_bytes {
        return Err(OnvifError::ResponseTooLarge);
    }
    std::str::from_utf8(bytes).map_err(|_| OnvifError::InvalidResponse)?;
    let mut reader = NsReader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root = None;
    let mut declaration_seen = false;
    let mut events = 0usize;
    let max_retained = limits.max_uri_bytes.max(limits.max_field_bytes).max(256);

    loop {
        events = events.checked_add(1).ok_or(OnvifError::InvalidResponse)?;
        if events > limits.max_events {
            return Err(OnvifError::InvalidResponse);
        }
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|_| OnvifError::InvalidResponse)?;
        let event_namespace = owned_namespace(resolved)?;
        match event {
            Event::Start(start) => {
                if stack.len() >= limits.max_xml_depth {
                    return Err(OnvifError::InvalidResponse);
                }
                let node = node_from_start(&reader, start, event_namespace, max_retained)?;
                stack.push(node);
            }
            Event::Empty(start) => {
                if stack.len() >= limits.max_xml_depth {
                    return Err(OnvifError::InvalidResponse);
                }
                let node = node_from_start(&reader, start, event_namespace, max_retained)?;
                attach_node(&mut stack, &mut root, node)?;
            }
            Event::Text(text) => {
                if text.as_ref().len() > max_retained {
                    return Err(OnvifError::InvalidResponse);
                }
                let decoded = text.decode().map_err(|_| OnvifError::InvalidResponse)?;
                let decoded = unescape(&decoded).map_err(|_| OnvifError::InvalidResponse)?;
                if decoded.len() > max_retained {
                    return Err(OnvifError::InvalidResponse);
                }
                if let Some(node) = stack.last_mut() {
                    if node.text.len().saturating_add(decoded.len()) > max_retained {
                        return Err(OnvifError::InvalidResponse);
                    }
                    node.text.push_str(&decoded);
                } else if !decoded.trim().is_empty() {
                    return Err(OnvifError::InvalidResponse);
                }
            }
            Event::End(end) => {
                let closing = XmlName {
                    namespace: event_namespace,
                    local: bounded_utf8(end.local_name().as_ref(), MAX_XML_NAME_BYTES)?,
                };
                let node = stack.pop().ok_or(OnvifError::InvalidResponse)?;
                if node.name != closing {
                    return Err(OnvifError::InvalidResponse);
                }
                attach_node(&mut stack, &mut root, node)?;
            }
            Event::Decl(declaration) if root.is_none() && stack.is_empty() && !declaration_seen => {
                declaration_seen = true;
                if declaration
                    .version()
                    .map_err(|_| OnvifError::InvalidResponse)?
                    .as_ref()
                    != b"1.0"
                    || declaration
                        .encoding()
                        .transpose()
                        .map_err(|_| OnvifError::InvalidResponse)?
                        .is_some_and(|encoding| !encoding.eq_ignore_ascii_case(b"UTF-8"))
                    || declaration
                        .standalone()
                        .transpose()
                        .map_err(|_| OnvifError::InvalidResponse)?
                        .is_some_and(|standalone| {
                            standalone.as_ref() != b"yes" && standalone.as_ref() != b"no"
                        })
                {
                    return Err(OnvifError::InvalidResponse);
                }
            }
            Event::Eof => break,
            Event::Comment(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::CData(_)
            | Event::GeneralRef(_)
            | Event::Decl(_) => {
                return Err(OnvifError::InvalidResponse);
            }
        }
    }
    if !stack.is_empty() {
        return Err(OnvifError::InvalidResponse);
    }
    root.ok_or(OnvifError::InvalidResponse)
}

fn node_from_start(
    reader: &NsReader<&[u8]>,
    start: BytesStart<'_>,
    namespace: Option<String>,
    max_retained: usize,
) -> Result<XmlNode, OnvifError> {
    let local = bounded_utf8(start.local_name().as_ref(), MAX_XML_NAME_BYTES)?;
    let mut attributes = Vec::new();
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|_| OnvifError::InvalidResponse)?;
        if attribute.value.as_ref().len() > max_retained {
            return Err(OnvifError::InvalidResponse);
        }
        let raw_name = attribute.key.as_ref();
        if raw_name == b"xmlns" || raw_name.starts_with(b"xmlns:") {
            let value = attribute
                .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder())
                .map_err(|_| OnvifError::InvalidResponse)?;
            if value.len() > max_retained || std::str::from_utf8(value.as_bytes()).is_err() {
                return Err(OnvifError::InvalidResponse);
            }
            continue;
        }
        let (resolved, local) = reader.resolver().resolve_attribute(attribute.key);
        let namespace = owned_namespace(resolved)?;
        let local = bounded_utf8(local.as_ref(), MAX_XML_NAME_BYTES)?;
        let value = attribute
            .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder())
            .map_err(|_| OnvifError::InvalidResponse)?;
        if value.len() > max_retained {
            return Err(OnvifError::InvalidResponse);
        }
        attributes.push(XmlAttribute {
            namespace,
            local,
            value: value.into_owned(),
        });
    }
    Ok(XmlNode {
        name: XmlName { namespace, local },
        attributes,
        text: String::new(),
        children: Vec::new(),
    })
}

fn owned_namespace(resolved: ResolveResult<'_>) -> Result<Option<String>, OnvifError> {
    match resolved {
        ResolveResult::Bound(namespace) => {
            Ok(Some(bounded_utf8(namespace.as_ref(), MAX_XML_NAME_BYTES)?))
        }
        ResolveResult::Unbound => Ok(None),
        ResolveResult::Unknown(_) => Err(OnvifError::InvalidResponse),
    }
}

fn bounded_utf8(bytes: &[u8], max: usize) -> Result<String, OnvifError> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(OnvifError::InvalidResponse);
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| OnvifError::InvalidResponse)
}

fn attach_node(
    stack: &mut [XmlNode],
    root: &mut Option<XmlNode>,
    node: XmlNode,
) -> Result<(), OnvifError> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else if root.replace(node).is_some() {
        return Err(OnvifError::InvalidResponse);
    }
    Ok(())
}

fn require_name(node: &XmlNode, namespace: &str, local: &str) -> Result<(), OnvifError> {
    if node.name.namespace.as_deref() == Some(namespace) && node.name.local == local {
        Ok(())
    } else {
        Err(OnvifError::InvalidResponse)
    }
}

fn unique_child<'a>(
    node: &'a XmlNode,
    namespace: &str,
    local: &str,
) -> Result<&'a XmlNode, OnvifError> {
    let mut values = node.children.iter().filter(|child| {
        child.name.namespace.as_deref() == Some(namespace) && child.name.local == local
    });
    let value = values.next().ok_or(OnvifError::InvalidResponse)?;
    if values.next().is_some() {
        Err(OnvifError::InvalidResponse)
    } else {
        Ok(value)
    }
}

fn leaf_text(node: &XmlNode, limit: usize) -> Result<&str, OnvifError> {
    if !node.attributes.is_empty() || !node.children.is_empty() {
        return Err(OnvifError::InvalidResponse);
    }
    let value = node.text.trim();
    if value.is_empty() || value.len() > limit {
        Err(OnvifError::InvalidResponse)
    } else {
        Ok(value)
    }
}

struct DeviceFacts {
    manufacturer: Option<BoundedMetadata>,
    model: Option<BoundedMetadata>,
    firmware: Option<BoundedMetadata>,
    serial: Option<BoundedSerial>,
}

fn parse_device_information(
    envelope: &ParsedEnvelope,
    limits: &InventoryLimits,
) -> Result<DeviceFacts, OnvifError> {
    let response = &envelope.response;
    if !response.attributes.is_empty()
        || !response.text.trim().is_empty()
        || response.children.len() > limits.max_facts
    {
        return Err(OnvifError::InvalidResponse);
    }
    let allowed = [
        "Manufacturer",
        "Model",
        "FirmwareVersion",
        "SerialNumber",
        "HardwareId",
    ];
    let mut seen = BTreeSet::new();
    for child in &response.children {
        if child.name.namespace.as_deref() != Some(DEVICE)
            || !allowed.contains(&child.name.local.as_str())
            || !seen.insert(child.name.local.as_str())
        {
            return Err(OnvifError::InvalidResponse);
        }
        let _ = leaf_text(child, limits.max_field_bytes)?;
    }
    let metadata = |name| -> Result<Option<BoundedMetadata>, OnvifError> {
        response
            .children
            .iter()
            .find(|child| child.name.local == name)
            .map(|child| BoundedMetadata::new(leaf_text(child, limits.max_field_bytes)?))
            .transpose()
            .map_err(|_| OnvifError::InvalidResponse)
    };
    let serial = response
        .children
        .iter()
        .find(|child| child.name.local == "SerialNumber")
        .map(|child| BoundedSerial::new(leaf_text(child, limits.max_field_bytes)?))
        .transpose()
        .map_err(|_| OnvifError::InvalidResponse)?;
    Ok(DeviceFacts {
        manufacturer: metadata("Manufacturer")?,
        model: metadata("Model")?,
        firmware: metadata("FirmwareVersion")?,
        serial,
    })
}

fn parse_capabilities(
    envelope: &ParsedEnvelope,
    limits: &InventoryLimits,
) -> Result<Vec<BoundedMetadata>, OnvifError> {
    let response = &envelope.response;
    if !response.attributes.is_empty()
        || !response.text.trim().is_empty()
        || response.children.len() != 1
    {
        return Err(OnvifError::InvalidResponse);
    }
    let capabilities = &response.children[0];
    require_name(capabilities, DEVICE, "Capabilities")?;
    if !capabilities.attributes.is_empty()
        || !capabilities.text.trim().is_empty()
        || capabilities.children.len() > limits.max_capabilities
    {
        return Err(OnvifError::InvalidResponse);
    }
    let mut seen = BTreeSet::new();
    let mut output = Vec::with_capacity(capabilities.children.len());
    for capability in &capabilities.children {
        if capability.name.namespace.as_deref() != Some(SCHEMA)
            || !matches!(
                capability.name.local.as_str(),
                "Analytics" | "Device" | "Events" | "Imaging" | "Media" | "PTZ"
            )
            || !seen.insert(capability.name.local.as_str())
        {
            return Err(OnvifError::InvalidResponse);
        }
        output.push(
            BoundedMetadata::new(capability.name.local.to_ascii_lowercase())
                .map_err(|_| OnvifError::InvalidResponse)?,
        );
    }
    Ok(output)
}

fn parse_profiles(
    envelope: &ParsedEnvelope,
    limits: &InventoryLimits,
) -> Result<Vec<ProfileToken>, OnvifError> {
    let response = &envelope.response;
    if !response.attributes.is_empty()
        || !response.text.trim().is_empty()
        || response.children.len() > limits.max_profiles
    {
        return Err(OnvifError::InvalidResponse);
    }
    let mut seen = BTreeSet::new();
    let mut tokens = Vec::with_capacity(response.children.len());
    for profile in &response.children {
        require_name(profile, MEDIA, "Profiles")?;
        if !profile.text.trim().is_empty() {
            return Err(OnvifError::InvalidResponse);
        }
        let token_attributes: Vec<_> = profile
            .attributes
            .iter()
            .filter(|attribute| attribute.namespace.is_none() && attribute.local == "token")
            .collect();
        if token_attributes.len() != 1 {
            return Err(OnvifError::InvalidResponse);
        }
        let token = ProfileToken::new(&token_attributes[0].value, limits.max_token_bytes)?;
        if !seen.insert(token.as_str().to_owned()) {
            return Err(OnvifError::InvalidResponse);
        }
        tokens.push(token);
    }
    Ok(tokens)
}

fn parse_stream_uri(
    envelope: &ParsedEnvelope,
    limits: &InventoryLimits,
) -> Result<SecretString, OnvifError> {
    let response = &envelope.response;
    if !response.attributes.is_empty()
        || !response.text.trim().is_empty()
        || response.children.len() != 1
    {
        return Err(OnvifError::InvalidResponse);
    }
    let media_uri = &response.children[0];
    require_name(media_uri, MEDIA, "MediaUri")?;
    let uri = unique_child(media_uri, SCHEMA, "Uri")?;
    let value = leaf_text(uri, limits.max_uri_bytes)?;
    if !value.starts_with("rtsp://") || value.chars().any(char::is_control) {
        return Err(OnvifError::InvalidResponse);
    }
    Ok(SecretString::from(value.to_owned()))
}

fn parse_health(
    envelope: &ParsedEnvelope,
    limits: &InventoryLimits,
) -> Result<CameraHealth, OnvifError> {
    let response = &envelope.response;
    if !response.attributes.is_empty()
        || !response.text.trim().is_empty()
        || response.children.len() != 1
    {
        return Err(OnvifError::InvalidResponse);
    }
    let system_time = &response.children[0];
    require_name(system_time, DEVICE, "SystemDateAndTime")?;
    if !system_time.attributes.is_empty()
        || !system_time.text.trim().is_empty()
        || system_time.children.len() > limits.max_facts
    {
        return Err(OnvifError::InvalidResponse);
    }
    let mut seen = BTreeSet::new();
    for child in &system_time.children {
        if child.name.namespace.as_deref() != Some(SCHEMA)
            || !matches!(
                child.name.local.as_str(),
                "DateTimeType" | "DaylightSavings" | "TimeZone" | "UTCDateTime" | "LocalDateTime"
            )
            || !seen.insert(child.name.local.as_str())
        {
            return Err(OnvifError::InvalidResponse);
        }
    }
    let date_time_type = unique_child(system_time, SCHEMA, "DateTimeType")?;
    if !matches!(
        leaf_text(date_time_type, limits.max_field_bytes)?,
        "Manual" | "NTP"
    ) {
        return Err(OnvifError::InvalidResponse);
    }
    let daylight = unique_child(system_time, SCHEMA, "DaylightSavings")?;
    if !matches!(
        leaf_text(daylight, limits.max_field_bytes)?,
        "true" | "false" | "0" | "1"
    ) {
        return Err(OnvifError::InvalidResponse);
    }
    if let Ok(time_zone) = unique_child(system_time, SCHEMA, "TimeZone") {
        if !time_zone.attributes.is_empty()
            || !time_zone.text.trim().is_empty()
            || time_zone.children.len() != 1
        {
            return Err(OnvifError::InvalidResponse);
        }
        let _ = leaf_text(
            unique_child(time_zone, SCHEMA, "TZ")?,
            limits.max_field_bytes,
        )?;
    }
    validate_date_time(
        unique_child(system_time, SCHEMA, "UTCDateTime")?,
        limits.max_field_bytes,
    )?;
    if let Ok(local) = unique_child(system_time, SCHEMA, "LocalDateTime") {
        validate_date_time(local, limits.max_field_bytes)?;
    }
    Ok(CameraHealth::Healthy)
}

fn validate_date_time(node: &XmlNode, field_limit: usize) -> Result<(), OnvifError> {
    if !node.attributes.is_empty() || !node.text.trim().is_empty() || node.children.len() != 2 {
        return Err(OnvifError::InvalidResponse);
    }
    let time = unique_child(node, SCHEMA, "Time")?;
    let date = unique_child(node, SCHEMA, "Date")?;
    validate_integer_fields(
        time,
        field_limit,
        &[("Hour", 0, 23), ("Minute", 0, 59), ("Second", 0, 60)],
    )?;
    validate_integer_fields(
        date,
        field_limit,
        &[("Year", 1970, 9999), ("Month", 1, 12), ("Day", 1, 31)],
    )
}

fn validate_integer_fields(
    node: &XmlNode,
    field_limit: usize,
    fields: &[(&str, i32, i32)],
) -> Result<(), OnvifError> {
    if !node.attributes.is_empty()
        || !node.text.trim().is_empty()
        || node.children.len() != fields.len()
    {
        return Err(OnvifError::InvalidResponse);
    }
    for (name, minimum, maximum) in fields {
        let raw = leaf_text(unique_child(node, SCHEMA, name)?, field_limit)?;
        let value = raw
            .parse::<i32>()
            .map_err(|_| OnvifError::InvalidResponse)?;
        if !(minimum..=maximum).contains(&&value) {
            return Err(OnvifError::InvalidResponse);
        }
    }
    Ok(())
}
