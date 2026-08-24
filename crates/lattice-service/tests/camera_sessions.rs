use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Utc;
use http_body_util::BodyExt;
use lattice_camera::{
    CameraClassification, CameraHealth, CameraId, CameraProfile, Confidence,
    FakeMediaProcessFactory, StreamId,
};
use lattice_sensor::AuthorizedBinding;
use lattice_service::cameras::{
    ApprovedRtspTarget, CameraSessionConfig, CameraSessionManager, FakeAuthorizedRtspConnector,
    FakeCameraTargetRegistry,
};
use lattice_service::{AppState, FakeVault, Vault, app};
use lattice_store::{CameraRecord, CameraRepository, M2StateRepository, connect_memory};
use secrecy::SecretString;
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
const PASSWORD: &str = "session-password-leak-sentinel";

struct Fixture {
    app: axum::Router,
    camera: CameraId,
    stream: StreamId,
    factory: Arc<FakeMediaProcessFactory>,
    registry: Arc<FakeCameraTargetRegistry>,
    manager: Arc<CameraSessionManager>,
    _directory: TempDir,
}

fn camera_id(n: u128) -> CameraId {
    CameraId::from_uuid(Uuid::from_u128(n))
}
fn stream_id(n: u128) -> StreamId {
    StreamId::from_uuid(Uuid::from_u128(n))
}

async fn fixture(config: CameraSessionConfig) -> Fixture {
    let pool = connect_memory().await.unwrap();
    let repository = CameraRepository::new(pool.clone());
    let camera = camera_id(1);
    let stream = stream_id(2);
    repository
        .upsert_camera(&CameraRecord {
            id: camera,
            classification: CameraClassification::Camera,
            confidence: Confidence::new(0.95).unwrap(),
            health: CameraHealth::Healthy,
            observed_at: Utc::now(),
        })
        .await
        .unwrap();
    let vault = Arc::new(FakeVault::new());
    let source_ref = vault
        .put_stream_source(
            camera,
            stream,
            SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        )
        .await
        .unwrap();
    repository
        .put_stream_ref(camera, &CameraProfile::new(stream, source_ref))
        .await
        .unwrap();
    let registry = Arc::new(FakeCameraTargetRegistry::new());
    registry
        .approve(
            camera,
            stream,
            ApprovedRtspTarget::new(
                AuthorizedBinding {
                    source: IpAddr::V4(Ipv4Addr::new(192, 168, 4, 5)),
                    interface_index: 7,
                    target: IpAddr::V4(Ipv4Addr::new(192, 168, 4, 22)),
                },
                8554,
            )
            .unwrap(),
        )
        .await;
    let factory = Arc::new(FakeMediaProcessFactory::new());
    factory
        .set_hls_output(
            b"#EXTM3U\n#EXTINF:2,\nsegment-000001.ts\n".to_vec(),
            vec![("segment-000001.ts".into(), b"transport-stream".to_vec())],
        )
        .await;
    factory
        .set_snapshot_output(b"\xff\xd8jpeg\xff\xd9".to_vec())
        .await;
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(Vec::new()));
    let directory = tempfile::tempdir().unwrap();
    let manager = Arc::new(
        CameraSessionManager::new(
            repository,
            vault.clone(),
            registry.clone(),
            factory.clone(),
            connector,
            PathBuf::from(directory.path()),
            config,
        )
        .unwrap(),
    );
    let state = AppState::new(TOKEN, M2StateRepository::new(pool))
        .unwrap()
        .with_camera_sessions(manager.clone());
    Fixture {
        app: app(state),
        camera,
        stream,
        factory,
        registry,
        manager,
        _directory: directory,
    }
}

fn config() -> CameraSessionConfig {
    CameraSessionConfig {
        max_sessions: 2,
        idle_timeout: Duration::from_secs(30),
        total_timeout: Duration::from_secs(120),
        process_start_timeout: Duration::from_secs(2),
        snapshot_timeout: Duration::from_secs(2),
        max_playlist_bytes: 64 * 1024,
        max_segment_bytes: 1024 * 1024,
        max_snapshot_bytes: 1024 * 1024,
    }
}

fn authorized(builder: axum::http::request::Builder) -> axum::http::request::Builder {
    builder.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
}

async fn start(fixture: &Fixture) -> (StatusCode, Value) {
    let response = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::post(format!(
                "/api/v1/cameras/{}/sessions",
                fixture.camera
            )))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"stream_id": fixture.stream}).to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn session_routes_authenticate_before_any_path_query_or_json_validation() {
    let fixture = fixture(config()).await;
    for request in [
        Request::post("/api/v1/cameras/not-a-camera/sessions")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("not-json"))
            .unwrap(),
        Request::get("/api/v1/camera-sessions/not-a-session/segments/bad")
            .body(Body::empty())
            .unwrap(),
        Request::get("/api/v1/cameras/not-a-camera/snapshot?stream_id=bad")
            .body(Body::empty())
            .unwrap(),
    ] {
        assert_eq!(
            fixture.app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let malformed = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::post("/api/v1/cameras/not-a-camera/sessions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("not-json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn session_response_is_opaque_and_hls_files_have_strict_types_and_cache_policy() {
    let fixture = fixture(config()).await;
    let (status, value) = start(&fixture).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        value.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["session_id"]
    );
    let session = value["session_id"].as_str().unwrap();
    let serialized = value.to_string();
    for secret in [PASSWORD, "rtsp://", "192.168.4.22", "viewer"] {
        assert!(!serialized.contains(secret));
    }

    let playlist = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::get(format!(
                "/api/v1/camera-sessions/{session}/playlist.m3u8"
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(playlist.status(), StatusCode::OK);
    assert_eq!(
        playlist.headers()[header::CONTENT_TYPE],
        "application/vnd.apple.mpegurl"
    );
    assert_eq!(playlist.headers()[header::CACHE_CONTROL], "no-store");
    let playlist_body = playlist.into_body().collect().await.unwrap().to_bytes();
    assert!(playlist_body.starts_with(b"#EXTM3U"));

    let segment = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::get(format!(
                "/api/v1/camera-sessions/{session}/segments/segment-000001.ts"
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(segment.status(), StatusCode::OK);
    assert_eq!(segment.headers()[header::CONTENT_TYPE], "video/mp2t");
    assert_eq!(
        segment.into_body().collect().await.unwrap().to_bytes(),
        &b"transport-stream"[..]
    );

    let first_close = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::delete(format!(
                "/api/v1/camera-sessions/{session}"
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let second_close = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::delete(format!(
                "/api/v1/camera-sessions/{session}"
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_close.status(), StatusCode::NO_CONTENT);
    assert_eq!(second_close.status(), StatusCode::NO_CONTENT);
    let observations = fixture.factory.observations().await;
    assert!(observations[0].kill_requested && observations[0].awaited);
    assert_eq!(fixture.manager.active_count().await, 0);
}

#[tokio::test]
async fn exact_repository_vault_and_target_failures_are_sanitized() {
    let fixture = fixture(config()).await;
    let missing_camera = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::post(format!(
                "/api/v1/cameras/{}/sessions",
                camera_id(999)
            )))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"stream_id": fixture.stream}).to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_camera.status(), StatusCode::NOT_FOUND);
    let wrong_stream = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::post(format!(
                "/api/v1/cameras/{}/sessions",
                fixture.camera
            )))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"stream_id": stream_id(999)}).to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_stream.status(), StatusCode::NOT_FOUND);

    fixture.registry.deny(fixture.camera, fixture.stream).await;
    let (status, body) = start(&fixture).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!body.to_string().contains(PASSWORD));
    assert_eq!(fixture.factory.specs().await.len(), 0);
}

#[tokio::test]
async fn max_idle_total_and_process_crash_all_release_process_proxy_and_directory() {
    let mut bounded = config();
    bounded.max_sessions = 1;
    bounded.idle_timeout = Duration::from_millis(30);
    bounded.total_timeout = Duration::from_millis(80);
    let fixture = fixture(bounded).await;
    let (_, first) = start(&fixture).await;
    let first_id = first["session_id"].as_str().unwrap().to_owned();
    let (limited, _) = start(&fixture).await;
    assert_eq!(limited, StatusCode::TOO_MANY_REQUESTS);
    tokio::time::timeout(Duration::from_millis(250), async {
        loop {
            if fixture.manager.output_entries().await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("idle reaper did not remove session output");
    let expired = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::get(format!(
                "/api/v1/camera-sessions/{first_id}/playlist.m3u8"
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::NOT_FOUND);
    let (started, second) = start(&fixture).await;
    assert_eq!(started, StatusCode::CREATED);
    let second_id = second["session_id"].as_str().unwrap();
    fixture.factory.crash_last().await;
    let crashed = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::get(format!(
                "/api/v1/camera-sessions/{second_id}/playlist.m3u8"
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(crashed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(fixture.manager.active_count().await, 0);
    assert!(fixture.manager.output_entries().await.unwrap().is_empty());
}

#[tokio::test]
async fn playlist_and_segment_reject_traversal_wrong_names_symlinks_and_oversize() {
    let mut bounded = config();
    bounded.max_playlist_bytes = 16;
    bounded.max_segment_bytes = 8;
    let fixture = fixture(bounded).await;
    let (_, value) = start(&fixture).await;
    let session = value["session_id"].as_str().unwrap();
    let playlist = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::get(format!(
                "/api/v1/camera-sessions/{session}/playlist.m3u8"
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(playlist.status(), StatusCode::PAYLOAD_TOO_LARGE);
    for name in [
        "segment-1.ts",
        "segment-000001.ts.bak",
        "%2e%2e%2fsecret",
        "segment-000001.m3u8",
    ] {
        let response = fixture
            .app
            .clone()
            .oneshot(
                authorized(Request::get(format!(
                    "/api/v1/camera-sessions/{session}/segments/{name}"
                )))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::PAYLOAD_TOO_LARGE
        ));
    }
    #[cfg(unix)]
    {
        let path = fixture.manager.session_output_path(session).await.unwrap();
        let outside = fixture._directory.path().join("outside.ts");
        std::fs::write(&outside, b"x").unwrap();
        let link = path.join("segment-000002.ts");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let response = fixture
            .app
            .clone()
            .oneshot(
                authorized(Request::get(format!(
                    "/api/v1/camera-sessions/{session}/segments/segment-000002.ts"
                )))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn snapshot_uses_fixed_pipeline_and_enforces_timeout_and_byte_cap_with_cleanup() {
    let fixture = fixture(config()).await;
    let response = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::get(format!(
                "/api/v1/cameras/{}/snapshot?stream_id={}",
                fixture.camera, fixture.stream
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "image/jpeg");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, &b"\xff\xd8jpeg\xff\xd9"[..]);
    assert_eq!(fixture.manager.active_count().await, 0);
    assert!(fixture.manager.output_entries().await.unwrap().is_empty());

    fixture
        .factory
        .set_snapshot_output(vec![b'x'; config().max_snapshot_bytes + 1])
        .await;
    let oversized = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::get(format!(
                "/api/v1/cameras/{}/snapshot?stream_id={}",
                fixture.camera, fixture.stream
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(fixture.manager.output_entries().await.unwrap().is_empty());

    fixture.factory.set_snapshot_hang(true).await;
    let timed_out = fixture
        .app
        .clone()
        .oneshot(
            authorized(Request::get(format!(
                "/api/v1/cameras/{}/snapshot?stream_id={}",
                fixture.camera, fixture.stream
            )))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(timed_out.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(fixture.manager.output_entries().await.unwrap().is_empty());
}
