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
use lattice_sensor::AuthorizedBinding;
use lattice_service::{
    AppState, FakeVault, Vault, app,
    cameras::{
        ApprovedRtspTarget, CameraSessionConfig, CameraSessionManager, FakeAuthorizedRtspConnector,
        FakeCameraTargetRegistry,
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
    repo.put_stream_ref(camera, &CameraProfile::new(stream, source_ref))
        .await
        .unwrap();

    let registry = Arc::new(FakeCameraTargetRegistry::new());
    registry
        .approve(
            camera,
            stream,
            ApprovedRtspTarget::new(
                AuthorizedBinding {
                    source: IpAddr::V4(Ipv4Addr::new(192, 168, 44, 5)),
                    interface_index: 4,
                    target: IpAddr::V4(Ipv4Addr::new(192, 168, 44, 22)),
                },
                8554,
            )
            .unwrap(),
        )
        .await;
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
    let manager = Arc::new(
        CameraSessionManager::new(
            repo,
            vault,
            registry,
            media.clone(),
            Arc::new(FakeAuthorizedRtspConnector::new(Vec::new())),
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
    let text = String::from_utf8_lossy(&detail_body);
    for forbidden in [
        PASSWORD,
        RTSP,
        "soap-envelope",
        "192.168.44.22",
        "camera-user",
        "fixture-onvif-ref",
    ] {
        assert!(!text.contains(forbidden), "leaked {forbidden}");
    }
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
    for uri in [
        format!("/api/v1/camera-sessions/{session}/playlist.m3u8"),
        format!("/api/v1/camera-sessions/{session}/segments/segment-000001.ts"),
    ] {
        let response = app
            .clone()
            .oneshot(auth(Request::get(uri)).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
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
    let closed = app
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
}
