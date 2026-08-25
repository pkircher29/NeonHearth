use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Utc;
use http_body_util::BodyExt;
use lattice_camera::{
    CameraEvidence, CameraEvidenceFamily, CameraId, CameraProfile, FakeMediaProcessFactory,
    InventoryLimits, OnvifAction, OnvifCredential, OnvifError, OnvifRequest, OnvifResponseWriter,
    OnvifTransport, StreamId, StreamSecretSink, StreamSourceRef, TargetAddress, classify_candidate,
    inventory,
};
use lattice_sensor::{
    Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory, TargetApproval,
    TargetGuard,
};
use lattice_service::{
    AppState, FakeVault, Vault, app,
    cameras::{
        CameraSessionConfig, CameraSessionManager, FakeAuthorizedRtspConnector,
        GuardedCameraTargetRegistry,
    },
};
use lattice_store::{
    CameraInventoryRecord, CameraRecord, CameraRepository, M2StateRepository, connect_memory,
};
use secrecy::{ExposeSecret, SecretString};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
const PASSWORD: &str = "m4-camera-password-sentinel";
const RTSP: &str = "rtsp://camera-user:m4-camera-password-sentinel@192.168.44.22:8554/main";
const RAW_HEADER: &str = "m4-raw-header-sentinel";
const MAC: &str = "02:aa:bb:cc:dd:ee";

#[derive(Default)]
struct CapturingSink(Mutex<Vec<(StreamId, SecretString)>>);
impl StreamSecretSink for CapturingSink {
    fn store_all(
        &self,
        sources: Vec<(StreamId, SecretString)>,
    ) -> Result<Vec<StreamSourceRef>, OnvifError> {
        let refs = sources
            .iter()
            .enumerate()
            .map(|(n, _)| StreamSourceRef::new(format!("fixture-onvif-ref-{n}")))
            .collect::<Result<Vec<_>, _>>()?;
        *self.0.lock().unwrap() = sources;
        Ok(refs)
    }
}

struct FixtureTransport;
#[async_trait]
impl OnvifTransport for FixtureTransport {
    async fn request(
        &self,
        _: &TargetAddress,
        request: &OnvifRequest,
        credential: Option<&OnvifCredential>,
        response: &mut OnvifResponseWriter,
    ) -> Result<(), OnvifError> {
        let credential = credential.ok_or(OnvifError::Authentication)?;
        if credential.username() != "camera-user"
            || credential.password().expose_secret() != PASSWORD
        {
            return Err(OnvifError::Authentication);
        }
        let (action, body) = match request.action() {
            OnvifAction::GetDeviceInformation => ("http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse", "<tds:GetDeviceInformationResponse><tds:Manufacturer>FixtureCam</tds:Manufacturer><tds:Model>M4</tds:Model><tds:SerialNumber>OWNER-42</tds:SerialNumber></tds:GetDeviceInformationResponse>".to_owned()),
            OnvifAction::GetCapabilities => ("http://www.onvif.org/ver10/device/wsdl/GetCapabilitiesResponse", "<tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media/></tds:Capabilities></tds:GetCapabilitiesResponse>".to_owned()),
            OnvifAction::GetProfiles => ("http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse", "<trt:GetProfilesResponse><trt:Profiles token=\"main\"/></trt:GetProfilesResponse>".to_owned()),
            OnvifAction::GetStreamUri { .. } => ("http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse", format!("<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>{RTSP}</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>")),
            OnvifAction::GetSystemDateAndTime => ("http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse", "<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:DateTimeType>NTP</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings><tt:UTCDateTime><tt:Time><tt:Hour>12</tt:Hour><tt:Minute>34</tt:Minute><tt:Second>56</tt:Second></tt:Time><tt:Date><tt:Year>2026</tt:Year><tt:Month>8</tt:Month><tt:Day>24</tt:Day></tt:Date></tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>".to_owned()),
        };
        response.append_chunk(format!("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Header><wsa:Action>{action}</wsa:Action><wsa:RelatesTo>{}</wsa:RelatesTo></s:Header><s:Body>{body}</s:Body></s:Envelope>", request.message_id().as_str()).as_bytes())
    }
}

fn camera_id() -> CameraId {
    CameraId::from_uuid(Uuid::from_u128(0x44))
}
fn config() -> CameraSessionConfig {
    CameraSessionConfig {
        max_sessions: 2,
        idle_timeout: Duration::from_millis(25),
        total_timeout: Duration::from_secs(1),
        process_start_timeout: Duration::from_secs(1),
        snapshot_timeout: Duration::from_secs(1),
        max_playlist_bytes: 1024,
        max_segment_bytes: 1024,
        max_snapshot_bytes: 1024,
    }
}
fn auth(builder: axum::http::request::Builder) -> axum::http::request::Builder {
    builder.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
}

fn fixture_guard() -> TargetGuard {
    let interface = InterfaceId::new(4);
    TargetGuard::new(
        InterfaceInventory::new(vec![Interface {
            id: interface,
            name: "fixture-ethernet".into(),
            description: None,
            up: true,
            class: InterfaceClass::PhysicalWired,
            addresses: vec![Address {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 44, 5)),
                prefix: 24,
            }],
            owner_role: None,
        }]),
        [],
        [TargetApproval {
            interface,
            prefix: Address {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 44, 0)),
                prefix: 24,
            },
        }],
    )
    .unwrap()
}

fn assert_clean(bytes: impl AsRef<[u8]>, source_ref: &str) {
    let value = String::from_utf8_lossy(bytes.as_ref());
    for forbidden in [
        PASSWORD,
        RTSP,
        "camera-user",
        "soap-envelope",
        RAW_HEADER,
        "192.168.44.22",
        MAC,
        "fixture-onvif-ref",
        source_ref,
    ] {
        assert!(!value.contains(forbidden), "leaked {forbidden}");
    }
}

fn assert_clean_tree(path: &std::path::Path, source_ref: &str) {
    assert_clean(path.to_string_lossy().as_bytes(), source_ref);
    for entry in std::fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        assert_clean(path.to_string_lossy().as_bytes(), source_ref);
        if path.is_dir() {
            assert_clean_tree(&path, source_ref);
        } else {
            assert_clean(std::fs::read(&path).unwrap(), source_ref);
        }
    }
}

#[tokio::test]
async fn fixture_pipeline_projects_only_sanitized_camera_data_and_reaps_idle_media() {
    let camera = camera_id();
    let now = Utc::now();
    let candidate = classify_candidate(
        camera,
        [
            CameraEvidence::new(
                CameraEvidenceFamily::WsDiscovery,
                "passive_fixture",
                "ws_discovery_scope",
                0.7,
                now,
                None,
            )
            .unwrap(),
            CameraEvidence::new(
                CameraEvidenceFamily::Rtsp,
                "active_fixture",
                "rtsp_camera",
                0.8,
                now,
                None,
            )
            .unwrap(),
        ],
        now,
    )
    .unwrap();
    assert_eq!(
        candidate.classification,
        lattice_camera::CameraClassification::Camera
    );
    assert!((0.0..=1.0).contains(&candidate.confidence.get()));

    let target = TargetAddress::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 44, 22)),
        8899,
        false,
        "/onvif/device_service",
    )
    .unwrap();
    let sink = CapturingSink::default();
    let onvif = inventory(
        &FixtureTransport,
        &sink,
        target,
        Some(&OnvifCredential::new("camera-user", SecretString::from(PASSWORD)).unwrap()),
        InventoryLimits::default(),
    )
    .await
    .unwrap();
    let captured = std::mem::take(&mut *sink.0.lock().unwrap());
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].1.expose_secret(), RTSP);

    let pool = connect_memory().await.unwrap();
    let repo = CameraRepository::new(pool.clone());
    repo.upsert_camera(&CameraRecord {
        id: camera,
        classification: candidate.classification,
        confidence: candidate.confidence,
        health: candidate.health,
        observed_at: now,
    })
    .await
    .unwrap();
    repo.replace_inventory(
        camera,
        &CameraInventoryRecord {
            manufacturer: onvif.manufacturer.clone(),
            model: onvif.model.clone(),
            firmware: onvif.firmware.clone(),
            serial: onvif.serial.clone(),
            capabilities: onvif.capabilities.clone(),
            health: onvif.health,
        },
    )
    .await
    .unwrap();
    let vault = Arc::new(FakeVault::new());
    let stream = captured[0].0;
    let source_ref = vault
        .put_stream_source(camera, stream, captured.into_iter().next().unwrap().1)
        .await
        .unwrap();
    let source_ref_label = source_ref.as_str().to_owned();
    repo.put_stream_ref(camera, &CameraProfile::new(stream, source_ref))
        .await
        .unwrap();

    let registry = Arc::new(GuardedCameraTargetRegistry::new(fixture_guard()));
    registry
        .register(
            camera,
            stream,
            InterfaceId::new(4),
            IpAddr::V4(Ipv4Addr::new(192, 168, 44, 22)),
            8554,
        )
        .await
        .unwrap();
    assert!(
        registry
            .register(
                camera,
                StreamId::from_uuid(Uuid::from_u128(45)),
                InterfaceId::new(4),
                IpAddr::V4(Ipv4Addr::new(192, 168, 45, 22)),
                8554
            )
            .await
            .is_err()
    );
    assert!(
        registry
            .register(
                camera,
                StreamId::from_uuid(Uuid::from_u128(46)),
                InterfaceId::new(99),
                IpAddr::V4(Ipv4Addr::new(192, 168, 44, 22)),
                8554
            )
            .await
            .is_err()
    );
    let media = Arc::new(FakeMediaProcessFactory::new());
    media
        .set_hls_output(
            b"#EXTM3U\n#EXTINF:2,\nsegment-000001.ts\n".to_vec(),
            vec![("segment-000001.ts".into(), b"segment".to_vec())],
        )
        .await;
    media
        .set_snapshot_output(b"\xff\xd8fixture\xff\xd9".to_vec())
        .await;
    let dir = tempfile::tempdir().unwrap();
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(Vec::new()));
    let manager = Arc::new(
        CameraSessionManager::new(
            repo,
            vault,
            registry,
            media.clone(),
            connector.clone(),
            PathBuf::from(dir.path()),
            config(),
        )
        .unwrap(),
    );
    let app = app(AppState::new(TOKEN, M2StateRepository::new(pool))
        .unwrap()
        .with_camera_sessions(manager.clone()));

    let detail = app
        .clone()
        .oneshot(
            auth(Request::get(format!("/api/v1/cameras/{camera}")))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    let detail_body = detail.into_body().collect().await.unwrap().to_bytes();
    assert_clean(&detail_body, &source_ref_label);
    let text = String::from_utf8_lossy(&detail_body);
    assert!(text.contains("OWNER-42") && text.contains(&camera.to_string()));
    let inventory_response = app
        .clone()
        .oneshot(
            auth(Request::get(format!("/api/v1/cameras/{camera}/inventory")))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inventory_response.status(), StatusCode::OK);
    let inventory_body = inventory_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_clean(&inventory_body, &source_ref_label);
    assert!(String::from_utf8_lossy(&inventory_body).contains("OWNER-42"));

    let started = app
        .clone()
        .oneshot(
            auth(Request::post(format!("/api/v1/cameras/{camera}/sessions")))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"stream_id": stream}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::CREATED);
    let start_body = started.into_body().collect().await.unwrap().to_bytes();
    let session = serde_json::from_slice::<serde_json::Value>(&start_body).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(Uuid::parse_str(&session).is_ok());
    assert_clean(&start_body, &source_ref_label);
    let first_output = manager.session_output_path(&session).await.unwrap();
    assert_clean_tree(&first_output, &source_ref_label);
    for (uri, expected) in [
        (
            format!("/api/v1/camera-sessions/{session}/playlist.m3u8"),
            b"#EXTM3U".as_slice(),
        ),
        (
            format!("/api/v1/camera-sessions/{session}/segments/segment-000001.ts"),
            b"segment".as_slice(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(auth(Request::get(uri)).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.starts_with(expected));
        assert_clean(&body, &source_ref_label);
    }
    let snapshot = app
        .clone()
        .oneshot(
            auth(Request::get(format!(
                "/api/v1/cameras/{camera}/snapshot?stream_id={stream}"
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(snapshot.status(), StatusCode::OK);
    let snapshot_headers = format!("{:?}", snapshot.headers());
    assert_clean(snapshot_headers, &source_ref_label);
    let snapshot_body = snapshot.into_body().collect().await.unwrap().to_bytes();
    assert_clean(&snapshot_body, &source_ref_label);
    tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if manager.active_count().await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(manager.output_entries().await.unwrap().is_empty());
    assert!(
        media
            .observations()
            .await
            .iter()
            .all(|entry| entry.kill_requested && entry.awaited)
    );
    assert_eq!(connector.connection_count().await, 0);
    assert!(connector.requests().await.is_empty());

    let reopened = app
        .clone()
        .oneshot(
            auth(Request::post(format!("/api/v1/cameras/{camera}/sessions")))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"stream_id": stream}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reopened.status(), StatusCode::CREATED);
    let reopened_body = reopened.into_body().collect().await.unwrap().to_bytes();
    let reopened_session =
        serde_json::from_slice::<serde_json::Value>(&reopened_body).unwrap()["session_id"]
            .as_str()
            .unwrap()
            .to_owned();
    let reopened_output = manager
        .session_output_path(&reopened_session)
        .await
        .unwrap();
    assert_clean_tree(&reopened_output, &source_ref_label);
    let closed = app
        .clone()
        .oneshot(
            auth(Request::delete(format!(
                "/api/v1/camera-sessions/{reopened_session}"
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(closed.status(), StatusCode::NO_CONTENT);
    assert_eq!(manager.active_count().await, 0);
    assert_eq!(manager.pending_cleanup_count().await, 0);
    assert!(!reopened_output.exists());
    assert!(manager.output_entries().await.unwrap().is_empty());
    let observations = media.observations().await;
    assert!(observations.last().unwrap().kill_requested && observations.last().unwrap().awaited);
    for spec in media.specs().await {
        assert_clean(format!("{spec:?}"), &source_ref_label);
        assert_clean(
            spec.executable().to_string_lossy().as_bytes(),
            &source_ref_label,
        );
        for arg in spec.args() {
            assert_clean(arg.to_string_lossy().as_bytes(), &source_ref_label);
        }
        let input = spec
            .args()
            .windows(2)
            .find(|pair| pair[0] == "-i")
            .map(|pair| pair[1].to_string_lossy())
            .unwrap();
        assert!(input.starts_with("rtsp://127.0.0.1:"));
        assert!(input.contains("/source/"));
        let output = std::path::Path::new(spec.args().last().unwrap());
        // The session manager canonicalizes its output root (a \?\ path on
        // Windows), so the fixture dir must be canonicalized the same way.
        assert!(output.starts_with(dir.path().canonicalize().unwrap()));
    }
    assert_clean(format!("{:?}", onvif), &source_ref_label);
    let export = lattice_service::api::serialize_camera_inventory_for_support_export(
        &lattice_service::api::CameraInventoryProjection {
            manufacturer: Some("FixtureCam".into()),
            model: Some("M4".into()),
            firmware: None,
            serial: Some("OWNER-42".into()),
            capabilities: vec!["media".into()],
            health: "healthy".into(),
        },
    )
    .unwrap();
    assert_clean(export, &source_ref_label);
    assert!(
        !lattice_service::api::serialize_camera_inventory_for_support_export(
            &lattice_service::api::CameraInventoryProjection {
                manufacturer: None,
                model: None,
                firmware: None,
                serial: Some("OWNER-42".into()),
                capabilities: vec![],
                health: "healthy".into()
            }
        )
        .unwrap()
        .contains("OWNER-42")
    );
    let capacity_probe = app
        .clone()
        .oneshot(
            auth(Request::post(format!("/api/v1/cameras/{camera}/sessions")))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"stream_id": stream}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(capacity_probe.status(), StatusCode::CREATED);
    let capacity_session = serde_json::from_slice::<serde_json::Value>(
        &capacity_probe
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        app.oneshot(
            auth(Request::delete(format!(
                "/api/v1/camera-sessions/{capacity_session}"
            )))
            .body(Body::empty())
            .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::NO_CONTENT
    );
}
