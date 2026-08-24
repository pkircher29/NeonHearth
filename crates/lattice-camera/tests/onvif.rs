use async_trait::async_trait;
use lattice_camera::{
    BoundedMetadata, BoundedOnvifResponse, BoundedSerial, CameraProfile, InventoryLimits,
    OnvifAction, OnvifCredential, OnvifError, OnvifRequest, OnvifTransport, StreamId,
    StreamSecretSink, StreamSourceRef, TargetAddress, inventory,
};
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

const SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
const WSA: &str = "http://www.w3.org/2005/08/addressing";
const DEVICE: &str = "http://www.onvif.org/ver10/device/wsdl";
const MEDIA: &str = "http://www.onvif.org/ver10/media/wsdl";
const SCHEMA: &str = "http://www.onvif.org/ver10/schema";
const URI_SENTINEL: &str = "rtsp://uri-secret.invalid/live";

#[derive(Clone, Copy, Debug)]
enum Mutation {
    None,
    WrongResponseNamespace,
    WrongAction,
    WrongCorrelation,
    DuplicateResponse,
    MissingHeader,
    NestedManufacturer,
    DetachedManufacturer,
    MixedManufacturer,
    Comment,
    ProcessingInstruction,
    Doctype,
    Entity,
    MalformedEnd,
    UnknownPrefix,
    TooDeep,
    TooManyEvents,
    TooManyFacts,
    TooManyCapabilities,
    TooManyProfiles,
    FieldTooLong,
    TokenTooLong,
    UriTooLong,
    EscapedFieldTooLong,
    InvalidUtf8,
    EmptyHealth,
    WrongHealthNamespace,
    MixedHealth,
    WrongHealthAction,
    InvalidUtf8Declaration,
    NonUtf8Declaration,
}

struct FixtureTransport {
    mutation: Mutation,
    calls: Mutex<Vec<OnvifAction>>,
    credential_seen: AtomicBool,
    credential_digest: AtomicU64,
    failure: Option<OnvifError>,
    profile_token: &'static str,
}

struct SlowTransport(FixtureTransport);

#[async_trait]
impl OnvifTransport for SlowTransport {
    async fn request(
        &self,
        target: &TargetAddress,
        request: &OnvifRequest,
        credential: Option<&OnvifCredential>,
    ) -> Result<BoundedOnvifResponse, OnvifError> {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        self.0.request(target, request, credential).await
    }
}

impl FixtureTransport {
    fn valid() -> Self {
        Self {
            mutation: Mutation::None,
            calls: Mutex::new(Vec::new()),
            credential_seen: AtomicBool::new(false),
            credential_digest: AtomicU64::new(0),
            failure: None,
            profile_token: "main-profile",
        }
    }

    fn mutated(mutation: Mutation) -> Self {
        Self {
            mutation,
            ..Self::valid()
        }
    }

    fn failing(error: OnvifError) -> Self {
        Self {
            failure: Some(error),
            ..Self::valid()
        }
    }

    fn with_profile_token(profile_token: &'static str) -> Self {
        Self {
            profile_token,
            ..Self::valid()
        }
    }
}

#[async_trait]
impl OnvifTransport for FixtureTransport {
    async fn request(
        &self,
        _: &TargetAddress,
        request: &OnvifRequest,
        credential: Option<&OnvifCredential>,
    ) -> Result<BoundedOnvifResponse, OnvifError> {
        self.calls.lock().unwrap().push(request.action().clone());
        if let Some(credential) = credential {
            self.credential_seen.store(true, Ordering::SeqCst);
            let mut hasher = DefaultHasher::new();
            credential.password().expose_secret().hash(&mut hasher);
            self.credential_digest
                .store(hasher.finish(), Ordering::SeqCst);
        }
        if let Some(error) = self.failure {
            return Err(error);
        }

        let (action, mut body) = fixture_parts(request.action());
        if matches!(request.action(), OnvifAction::GetProfiles) {
            body = body.replace("main-profile", self.profile_token);
        }
        let mut relates_to = request.message_id().as_str().to_owned();
        let mut response_action = action.to_owned();
        let mut header = true;
        match self.mutation {
            Mutation::WrongResponseNamespace if matches!(request.action(), OnvifAction::GetDeviceInformation) => {}
            Mutation::WrongAction if matches!(request.action(), OnvifAction::GetDeviceInformation) => response_action = "urn:wrong-action".into(),
            Mutation::WrongCorrelation if matches!(request.action(), OnvifAction::GetDeviceInformation) => relates_to = "urn:uuid:00000000-0000-0000-0000-000000000000".into(),
            Mutation::DuplicateResponse if matches!(request.action(), OnvifAction::GetDeviceInformation) => body = format!("{body}{body}"),
            Mutation::MissingHeader if matches!(request.action(), OnvifAction::GetDeviceInformation) => header = false,
            Mutation::NestedManufacturer if matches!(request.action(), OnvifAction::GetDeviceInformation) => body = body.replace("<tds:Manufacturer>Acme</tds:Manufacturer>", "<tds:Manufacturer><tt:Name>Acme</tt:Name></tds:Manufacturer>"),
            Mutation::DetachedManufacturer if matches!(request.action(), OnvifAction::GetDeviceInformation) => body = body.replace("</tds:GetDeviceInformationResponse>", "</tds:GetDeviceInformationResponse><tds:Manufacturer>Detached</tds:Manufacturer>"),
            Mutation::MixedManufacturer if matches!(request.action(), OnvifAction::GetDeviceInformation) => body = body.replace("<tds:Manufacturer>Acme</tds:Manufacturer>", "<tds:Manufacturer>Acme<tt:Name>x</tt:Name></tds:Manufacturer>"),
            Mutation::TooDeep if matches!(request.action(), OnvifAction::GetDeviceInformation) => body = body.replace("<tds:Manufacturer>Acme</tds:Manufacturer>", "<tds:Manufacturer><tt:A><tt:B><tt:C>Acme</tt:C></tt:B></tt:A></tds:Manufacturer>"),
            Mutation::TooManyEvents if matches!(request.action(), OnvifAction::GetDeviceInformation) => body = body.replace("</tds:GetDeviceInformationResponse>", "<tds:Manufacturer>A</tds:Manufacturer><tds:Model>B</tds:Model></tds:GetDeviceInformationResponse>"),
            Mutation::TooManyFacts if matches!(request.action(), OnvifAction::GetDeviceInformation) => body = body.replace("</tds:GetDeviceInformationResponse>", "<tds:HardwareId>H</tds:HardwareId></tds:GetDeviceInformationResponse>"),
            Mutation::TooManyCapabilities if matches!(request.action(), OnvifAction::GetCapabilities) => body = body.replace("<tt:Media/>", "<tt:Media/><tt:Events/>"),
            Mutation::TooManyProfiles if matches!(request.action(), OnvifAction::GetProfiles) => body = body.replace("</trt:GetProfilesResponse>", "<trt:Profiles token=\"extra\"/></trt:GetProfilesResponse>"),
            Mutation::FieldTooLong if matches!(request.action(), OnvifAction::GetDeviceInformation) => body = body.replace("Acme", "ABCDEFGHI"),
            Mutation::TokenTooLong if matches!(request.action(), OnvifAction::GetProfiles) => body = body.replace("token=\"main-profile\"", "token=\"profile-token-too-long\""),
            Mutation::UriTooLong if matches!(request.action(), OnvifAction::GetStreamUri { .. }) => body = body.replace(URI_SENTINEL, "rtsp://uri-secret.invalid/this-is-too-long"),
            Mutation::EscapedFieldTooLong if matches!(request.action(), OnvifAction::GetDeviceInformation) => body = body.replace("Acme", "A&amp;B&amp;C"),
            Mutation::EmptyHealth if matches!(request.action(), OnvifAction::GetSystemDateAndTime) => {
                body = "<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime/></tds:GetSystemDateAndTimeResponse>".into();
            }
            Mutation::WrongHealthNamespace if matches!(request.action(), OnvifAction::GetSystemDateAndTime) => {
                body = body.replace("<tt:DateTimeType>", "<tds:DateTimeType>").replace("</tt:DateTimeType>", "</tds:DateTimeType>");
            }
            Mutation::MixedHealth if matches!(request.action(), OnvifAction::GetSystemDateAndTime) => {
                body = body.replace("<tds:SystemDateAndTime>", "<tds:SystemDateAndTime>mixed");
            }
            Mutation::WrongHealthAction if matches!(request.action(), OnvifAction::GetSystemDateAndTime) => {
                response_action = "urn:wrong-health-action".into();
            }
            _ => {}
        }

        let header_xml = if header {
            format!(
                "<s:Header><wsa:Action>{response_action}</wsa:Action><wsa:RelatesTo>{relates_to}</wsa:RelatesTo></s:Header>"
            )
        } else {
            String::new()
        };
        let mut xml = format!(
            "<s:Envelope xmlns:s=\"{SOAP}\" xmlns:wsa=\"{WSA}\" xmlns:tds=\"{DEVICE}\" xmlns:trt=\"{MEDIA}\" xmlns:tt=\"{SCHEMA}\">{header_xml}<s:Body>{body}</s:Body></s:Envelope>"
        );
        if matches!(self.mutation, Mutation::WrongResponseNamespace)
            && matches!(request.action(), OnvifAction::GetDeviceInformation)
        {
            xml = xml.replace(
                &format!("xmlns:tds=\"{DEVICE}\""),
                "xmlns:tds=\"urn:not-onvif\"",
            );
        }
        if matches!(self.mutation, Mutation::Comment) {
            xml = xml.replace("<s:Body>", "<!-- forbidden --><s:Body>");
        }
        if matches!(self.mutation, Mutation::ProcessingInstruction) {
            xml = format!("<?probe forbidden?>{xml}");
        }
        if matches!(self.mutation, Mutation::Doctype) {
            xml = format!("<!DOCTYPE s:Envelope>{xml}");
        }
        if matches!(self.mutation, Mutation::Entity) {
            xml =
                format!("<!DOCTYPE s:Envelope [<!ENTITY x \"Acme\">]>{xml}").replace("Acme", "&x;");
        }
        if matches!(self.mutation, Mutation::MalformedEnd) {
            xml = xml.replace("</s:Body>", "</s:Header>");
        }
        if matches!(self.mutation, Mutation::UnknownPrefix) {
            xml = xml
                .replace("<tds:Manufacturer>", "<bad:Manufacturer>")
                .replace("</tds:Manufacturer>", "</bad:Manufacturer>");
        }
        if matches!(self.mutation, Mutation::NonUtf8Declaration) {
            xml = format!("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>{xml}");
        }
        let mut bytes = xml.into_bytes();
        if matches!(self.mutation, Mutation::InvalidUtf8) {
            let at = bytes.iter().position(|byte| *byte == b'A').unwrap();
            bytes[at] = 0xff;
        }
        if matches!(self.mutation, Mutation::InvalidUtf8Declaration) {
            let mut declaration = b"<?xml version=\"1.0\" standalone=\"yes\"?>".to_vec();
            declaration[6] = 0xff;
            declaration.extend(bytes);
            bytes = declaration;
        }
        request.bind_response(bytes)
    }
}

fn fixture_parts(action: &OnvifAction) -> (&'static str, String) {
    match action {
        OnvifAction::GetDeviceInformation => ("http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse", "<tds:GetDeviceInformationResponse><tds:Manufacturer>Acme</tds:Manufacturer><tds:Model>Cam-1</tds:Model><tds:FirmwareVersion>1.2.3</tds:FirmwareVersion><tds:SerialNumber>SN-42</tds:SerialNumber></tds:GetDeviceInformationResponse>".into()),
        OnvifAction::GetCapabilities => ("http://www.onvif.org/ver10/device/wsdl/GetCapabilitiesResponse", "<tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media/></tds:Capabilities></tds:GetCapabilitiesResponse>".into()),
        OnvifAction::GetProfiles => ("http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse", "<trt:GetProfilesResponse><trt:Profiles token=\"main-profile\"/></trt:GetProfilesResponse>".into()),
        OnvifAction::GetStreamUri { .. } => ("http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse", format!("<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>{URI_SENTINEL}</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>")),
        OnvifAction::GetSystemDateAndTime => ("http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse", "<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:DateTimeType>NTP</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings><tt:UTCDateTime><tt:Time><tt:Hour>12</tt:Hour><tt:Minute>34</tt:Minute><tt:Second>56</tt:Second></tt:Time><tt:Date><tt:Year>2026</tt:Year><tt:Month>8</tt:Month><tt:Day>24</tt:Day></tt:Date></tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>".into()),
    }
}

#[derive(Default)]
struct Sink {
    called: AtomicBool,
    digest: AtomicU64,
    fail: AtomicBool,
}
impl StreamSecretSink for Sink {
    fn store_all(
        &self,
        sources: Vec<(StreamId, SecretString)>,
    ) -> Result<Vec<StreamSourceRef>, OnvifError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(OnvifError::Sink);
        }
        let mut hasher = DefaultHasher::new();
        for (_, source) in &sources {
            source.expose_secret().hash(&mut hasher);
        }
        self.digest.store(hasher.finish(), Ordering::SeqCst);
        self.called.store(true, Ordering::SeqCst);
        sources
            .into_iter()
            .enumerate()
            .map(|(index, _)| {
                let value = if index == 0 {
                    "opaque-source-ref".into()
                } else {
                    format!("opaque-source-ref-{index}")
                };
                StreamSourceRef::new(value)
            })
            .collect()
    }
}

fn target() -> TargetAddress {
    target_path("/onvif/device_service")
}

fn target_path(path: &str) -> TargetAddress {
    TargetAddress::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)), 8899, true, path).unwrap()
}
fn credential() -> OnvifCredential {
    OnvifCredential::new("admin", SecretString::from("digest-secret")).unwrap()
}

#[tokio::test]
async fn inherited_namespaces_correlation_token_health_and_opaque_stream_are_enforced() {
    let transport = FixtureTransport::valid();
    let sink = Sink::default();
    let value = inventory(
        &transport,
        &sink,
        target(),
        Some(&credential()),
        InventoryLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        value.manufacturer.as_ref().map(BoundedMetadata::as_str),
        Some("Acme")
    );
    assert_eq!(
        value.serial.as_ref().map(BoundedSerial::as_str),
        Some("SN-42")
    );
    assert_eq!(value.profiles.len(), 1);
    assert_eq!(value.profiles[0].source_ref().as_str(), "opaque-source-ref");
    assert_eq!(value.capabilities[0].as_str(), "media");
    assert_eq!(value.health, lattice_camera::OnvifHealth::Healthy);
    assert!(sink.called.load(Ordering::SeqCst));
    assert_ne!(sink.digest.load(Ordering::SeqCst), 0);
    assert!(transport.credential_seen.load(Ordering::SeqCst));
    assert_ne!(transport.credential_digest.load(Ordering::SeqCst), 0);
    let calls = transport.calls.lock().unwrap();
    assert!(matches!(calls[0], OnvifAction::GetDeviceInformation));
    assert!(matches!(calls[1], OnvifAction::GetCapabilities));
    assert!(matches!(calls[2], OnvifAction::GetProfiles));
    assert!(
        matches!(calls[3], OnvifAction::GetStreamUri { ref profile_token } if profile_token.as_str() == "main-profile")
    );
    assert!(matches!(calls[4], OnvifAction::GetSystemDateAndTime));
    let json = serde_json::to_string(&value).unwrap();
    let debug = format!("{value:?}");
    assert!(!json.contains("rtsp://"));
    assert!(!json.contains("SN-42"));
    assert!(!json.contains("\"serial\""));
    assert!(!debug.contains("uri-secret"));
    assert!(!format!("{:?}", value.serial.as_ref().unwrap()).contains("SN-42"));
}

#[tokio::test]
async fn reinventory_of_same_target_and_profile_keeps_stable_stream_id() {
    let transport = FixtureTransport::valid();
    let first = inventory(
        &transport,
        &Sink::default(),
        target(),
        None,
        InventoryLimits::default(),
    )
    .await
    .unwrap();
    let second = inventory(
        &transport,
        &Sink::default(),
        target(),
        None,
        InventoryLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        first.profiles[0].stream_id(),
        second.profiles[0].stream_id()
    );
}

#[tokio::test]
async fn digest_absent_tls_timeout_and_sink_failures_are_typed_and_redacted() {
    let sink = Sink::default();
    for expected in [
        OnvifError::Authentication,
        OnvifError::Tls,
        OnvifError::Timeout,
    ] {
        let transport = FixtureTransport::failing(expected);
        let result = inventory(
            &transport,
            &sink,
            target(),
            None,
            InventoryLimits::default(),
        )
        .await;
        assert_eq!(result.unwrap_err(), expected);
        assert!(!transport.credential_seen.load(Ordering::SeqCst));
    }
    sink.fail.store(true, Ordering::SeqCst);
    let error = inventory(
        &FixtureTransport::valid(),
        &sink,
        target(),
        Some(&credential()),
        InventoryLimits::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error, OnvifError::Sink);
    assert!(!sink.called.load(Ordering::SeqCst));
    assert!(!format!("{error:?}").contains("uri-secret"));
}

#[tokio::test]
async fn inventory_enforces_timeout_even_when_transport_does_not() {
    let limits = InventoryLimits {
        timeout: std::time::Duration::from_millis(1),
        ..InventoryLimits::default()
    };
    let error = inventory(
        &SlowTransport(FixtureTransport::valid()),
        &Sink::default(),
        target(),
        None,
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(error, OnvifError::Timeout);
}

#[tokio::test]
async fn inventory_timeout_is_one_total_operation_budget() {
    let limits = InventoryLimits {
        timeout: std::time::Duration::from_millis(60),
        ..InventoryLimits::default()
    };
    let error = inventory(
        &SlowTransport(FixtureTransport::valid()),
        &Sink::default(),
        target(),
        None,
        limits,
    )
    .await
    .unwrap_err();
    assert_eq!(error, OnvifError::Timeout);
}

#[tokio::test]
async fn stable_stream_identity_frames_target_and_profile_without_delimiter_collisions() {
    let first = inventory(
        &FixtureTransport::with_profile_token("c"),
        &Sink::default(),
        target_path("/a:b"),
        None,
        InventoryLimits::default(),
    )
    .await
    .unwrap();
    let second = inventory(
        &FixtureTransport::with_profile_token("b:c"),
        &Sink::default(),
        target_path("/a"),
        None,
        InventoryLimits::default(),
    )
    .await
    .unwrap();
    assert_ne!(
        first.profiles[0].stream_id(),
        second.profiles[0].stream_id()
    );
}

#[tokio::test]
async fn malformed_or_uncorrelated_health_never_writes_stream_secrets() {
    for mutation in [
        Mutation::EmptyHealth,
        Mutation::WrongHealthNamespace,
        Mutation::MixedHealth,
        Mutation::WrongHealthAction,
    ] {
        let sink = Sink::default();
        let result = inventory(
            &FixtureTransport::mutated(mutation),
            &sink,
            target(),
            None,
            InventoryLimits::default(),
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            OnvifError::InvalidResponse,
            "{mutation:?}"
        );
        assert!(!sink.called.load(Ordering::SeqCst), "{mutation:?}");
    }
}

#[tokio::test]
async fn soap_structure_actions_correlation_namespaces_and_leaf_ownership_are_strict() {
    let cases = [
        Mutation::WrongResponseNamespace,
        Mutation::WrongAction,
        Mutation::WrongCorrelation,
        Mutation::DuplicateResponse,
        Mutation::MissingHeader,
        Mutation::NestedManufacturer,
        Mutation::DetachedManufacturer,
        Mutation::MixedManufacturer,
        Mutation::MalformedEnd,
        Mutation::UnknownPrefix,
    ];
    for mutation in cases {
        let result = inventory(
            &FixtureTransport::mutated(mutation),
            &Sink::default(),
            target(),
            None,
            InventoryLimits::default(),
        )
        .await;
        assert!(result.is_err(), "{mutation:?} was accepted");
        assert_eq!(result.unwrap_err(), OnvifError::InvalidResponse);
    }
}

#[tokio::test]
async fn active_xml_content_invalid_utf8_and_expansion_constructs_are_rejected() {
    for mutation in [
        Mutation::Comment,
        Mutation::ProcessingInstruction,
        Mutation::Doctype,
        Mutation::Entity,
        Mutation::InvalidUtf8,
        Mutation::InvalidUtf8Declaration,
        Mutation::NonUtf8Declaration,
    ] {
        let result = inventory(
            &FixtureTransport::mutated(mutation),
            &Sink::default(),
            target(),
            None,
            InventoryLimits::default(),
        )
        .await;
        assert!(result.is_err(), "{mutation:?} was accepted");
        assert_eq!(result.unwrap_err(), OnvifError::InvalidResponse);
    }
}

#[tokio::test]
async fn depth_event_fact_profile_capability_field_token_uri_and_escaped_caps_apply() {
    let cases = [
        (
            Mutation::TooDeep,
            InventoryLimits {
                max_xml_depth: 5,
                ..InventoryLimits::default()
            },
        ),
        (
            Mutation::TooManyEvents,
            InventoryLimits {
                max_events: 16,
                ..InventoryLimits::default()
            },
        ),
        (
            Mutation::TooManyFacts,
            InventoryLimits {
                max_facts: 4,
                ..InventoryLimits::default()
            },
        ),
        (
            Mutation::TooManyCapabilities,
            InventoryLimits {
                max_capabilities: 1,
                ..InventoryLimits::default()
            },
        ),
        (
            Mutation::TooManyProfiles,
            InventoryLimits {
                max_profiles: 1,
                ..InventoryLimits::default()
            },
        ),
        (
            Mutation::FieldTooLong,
            InventoryLimits {
                max_field_bytes: 8,
                ..InventoryLimits::default()
            },
        ),
        (
            Mutation::TokenTooLong,
            InventoryLimits {
                max_token_bytes: 12,
                ..InventoryLimits::default()
            },
        ),
        (
            Mutation::UriTooLong,
            InventoryLimits {
                max_uri_bytes: 32,
                ..InventoryLimits::default()
            },
        ),
        (
            Mutation::EscapedFieldTooLong,
            InventoryLimits {
                max_field_bytes: 4,
                ..InventoryLimits::default()
            },
        ),
    ];
    for (mutation, limits) in cases {
        let result = inventory(
            &FixtureTransport::mutated(mutation),
            &Sink::default(),
            target(),
            None,
            limits,
        )
        .await;
        assert_eq!(result.unwrap_err(), OnvifError::InvalidResponse);
    }
}

#[tokio::test]
async fn response_request_target_and_limit_bounds_are_enforced_before_retention() {
    let transport = FixtureTransport::valid();
    let sink = Sink::default();
    let too_small_response = InventoryLimits {
        max_response_bytes: 8,
        ..InventoryLimits::default()
    };
    assert_eq!(
        inventory(&transport, &sink, target(), None, too_small_response)
            .await
            .unwrap_err(),
        OnvifError::ResponseTooLarge
    );
    let too_small_request = InventoryLimits {
        max_request_bytes: 8,
        ..InventoryLimits::default()
    };
    assert_eq!(
        inventory(&transport, &sink, target(), None, too_small_request)
            .await
            .unwrap_err(),
        OnvifError::RequestTooLarge
    );
    let invalid = InventoryLimits {
        max_profiles: 0,
        ..InventoryLimits::default()
    };
    assert_eq!(
        inventory(&transport, &sink, target(), None, invalid)
            .await
            .unwrap_err(),
        OnvifError::InvalidLimits
    );
    for path in ["", "relative", "//host/x", "/x?y", "/x#y", "/../x", "/x\\y"] {
        assert!(TargetAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80, false, path).is_err());
    }
    assert!(TargetAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, false, "/x").is_err());
    assert!(OnvifCredential::new("bad user", SecretString::from("x")).is_err());
    assert!(StreamSourceRef::new("not opaque/ref").is_err());
}

#[test]
fn public_output_constructors_preserve_bounds() {
    assert!(BoundedMetadata::new(" ").is_err());
    assert!(BoundedMetadata::new("x".repeat(129)).is_err());
    assert!(BoundedMetadata::new("rtsp://metadata-secret.invalid/live").is_err());
    assert!(BoundedMetadata::new("authorization: bearer value").is_err());
    assert!(BoundedSerial::new("serial with spaces").is_err());
    assert!(StreamSourceRef::new("x".repeat(129)).is_err());
    let profile = CameraProfile::new(
        StreamId::from_uuid(uuid::Uuid::nil()),
        StreamSourceRef::new("opaque-ref").unwrap(),
    );
    assert_eq!(profile.source_ref().as_str(), "opaque-ref");
}
