use async_trait::async_trait;
use lattice_camera::{
    BoundedSerial, InventoryLimits, OnvifAction, OnvifCredential, OnvifError, OnvifTransport, StreamId,
    StreamSecretSink, TargetAddress, inventory,
};
use secrecy::{ExposeSecret, SecretString};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Mutex,
    time::Duration,
};

const DEVICE: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Manufacturer>Acme</tds:Manufacturer><tds:Model>Cam</tds:Model><tds:FirmwareVersion>1.2</tds:FirmwareVersion><tds:SerialNumber>SN-42</tds:SerialNumber></tds:GetDeviceInformationResponse></s:Body></s:Envelope>"#;
const CAPS: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Capabilities><tt:Media xmlns:tt="http://www.onvif.org/ver10/schema"/></tds:Capabilities></tds:GetCapabilitiesResponse></s:Body></s:Envelope>"#;
const PROFILES: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:Profiles token="main"/></trt:GetProfilesResponse></s:Body></s:Envelope>"#;
const URI: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:MediaUri><tt:Uri xmlns:tt="http://www.onvif.org/ver10/schema">rtsp://user:secret@10.0.0.4/live</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse></s:Body></s:Envelope>"#;

struct Fake {
    replies: Vec<&'static str>,
    requires_auth: bool,
}
#[async_trait]
impl OnvifTransport for Fake {
    async fn request(
        &self,
        _: &TargetAddress,
        _: OnvifAction,
        credential: Option<&OnvifCredential>,
        _: Duration,
    ) -> Result<String, OnvifError> {
        if self.requires_auth && credential.is_none() {
            return Err(OnvifError::Authentication);
        }
        Ok(self
            .replies
            .iter()
            .copied()
            .next()
            .unwrap_or(DEVICE)
            .to_owned())
    }
}
// A response-sequenced fake keeps fixtures deterministic without network access.
struct Sequence(Mutex<Vec<&'static str>>);
#[async_trait]
impl OnvifTransport for Sequence {
    async fn request(
        &self,
        _: &TargetAddress,
        _: OnvifAction,
        _: Option<&OnvifCredential>,
        _: Duration,
    ) -> Result<String, OnvifError> {
        Ok(self.0.lock().unwrap().remove(0).to_owned())
    }
}
#[derive(Default)]
struct Sink(Mutex<Vec<String>>);
impl StreamSecretSink for Sink {
    fn store(&self, _: StreamId, source: SecretString) -> Result<(), OnvifError> {
        self.0
            .lock()
            .unwrap()
            .push(source.expose_secret().to_owned());
        Ok(())
    }
}
fn target() -> TargetAddress {
    TargetAddress::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
        8899,
        true,
        "/onvif/device_service",
    )
    .unwrap()
}

#[tokio::test]
async fn inventory_is_schema_valid_and_hands_stream_only_to_sink() {
    let t = Sequence(Mutex::new(vec![DEVICE, CAPS, PROFILES, URI]));
    let sink = Sink::default();
    let value = inventory(
        &t,
        &sink,
        target(),
        Some(&OnvifCredential::new("admin", SecretString::from("secret")).unwrap()),
        InventoryLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(value.manufacturer.as_ref().map(BoundedSerial::as_str), Some("Acme"));
    assert_eq!(value.serial.as_ref().unwrap().as_str(), "SN-42");
    assert_eq!(value.profiles.len(), 1);
    assert_eq!(
        sink.0.lock().unwrap().as_slice(),
        ["rtsp://user:secret@10.0.0.4/live"]
    );
    assert!(!serde_json::to_string(&value).unwrap().contains("secret"));
}
#[tokio::test]
async fn rejects_wrong_namespace_and_oversized_xml() {
    let sink = Sink::default();
    let wrong = Sequence(Mutex::new(vec![
        "<x:GetDeviceInformationResponse xmlns:x=\"bad\"/>",
    ]));
    assert_eq!(
        inventory(&wrong, &sink, target(), None, InventoryLimits::default())
            .await
            .unwrap_err(),
        OnvifError::InvalidResponse
    );
    let huge = Sequence(Mutex::new(vec![DEVICE]));
    let limits = InventoryLimits {
        max_response_bytes: 4,
        ..Default::default()
    };
    assert_eq!(
        inventory(&huge, &sink, target(), None, limits)
            .await
            .unwrap_err(),
        OnvifError::ResponseTooLarge
    );
}
#[tokio::test]
async fn auth_needs_supplied_credential() {
    let sink = Sink::default();
    let fake = Fake {
        replies: vec![DEVICE],
        requires_auth: true,
    };
    assert_eq!(
        inventory(&fake, &sink, target(), None, InventoryLimits::default())
            .await
            .unwrap_err(),
        OnvifError::Authentication
    );
}
#[test]
fn target_rejects_unsafe_paths() {
    assert!(TargetAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80, false, "/x?y").is_err());
}
