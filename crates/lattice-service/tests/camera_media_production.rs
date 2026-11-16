//! The production camera media constructor, exercised through the real router.
//! No camera, no real ffmpeg, no network: the "ffmpeg" is a plain file, the
//! vault is the in-memory test vault, and nothing is ever spawned.

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use chrono::Utc;
use lattice_camera::{
    CameraClassification, CameraHealth, CameraId, CameraProfile, Confidence, FFMPEG_ENV, StreamId,
};
use lattice_service::cameras::production::{
    CameraMediaEnvironment, REASON_FFMPEG_NOT_FOUND, REASON_READY, assemble,
};
use lattice_service::{AppState, FakeVault, Vault, app};
use lattice_store::{CameraRecord, CameraRepository, M2StateRepository, connect_memory};
use secrecy::SecretString;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
const SESSION: &str = "018f0000-0000-7000-8000-000000000001";

fn camera_id(value: u128) -> CameraId {
    CameraId::from_uuid(Uuid::from_u128(value))
}

fn stream_id(value: u128) -> StreamId {
    StreamId::from_uuid(Uuid::from_u128(value))
}

fn fake_ffmpeg(directory: &Path) -> PathBuf {
    let path = directory.join(if cfg!(windows) {
        "ffmpeg.exe"
    } else {
        "ffmpeg"
    });
    std::fs::write(&path, b"not really ffmpeg").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

async fn call(
    router: &Router,
    method: Method,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let response = router
        .clone()
        .oneshot(
            builder
                .body(body.map_or_else(Body::empty, |text| Body::from(text.to_owned())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn router_for(
    environment: CameraMediaEnvironment,
    state_dir: &Path,
) -> (Router, sqlx::SqlitePool) {
    let pool = connect_memory().await.unwrap();
    let build = assemble(
        &environment,
        pool.clone(),
        Arc::new(FakeVault::new()),
        "a test vault",
        state_dir,
    )
    .await;
    let state = AppState::new(TOKEN, M2StateRepository::new(pool.clone()))
        .unwrap()
        .with_camera_media(build);
    (app(state), pool)
}

#[tokio::test]
async fn a_missing_ffmpeg_gives_specific_reasons_and_leaves_the_service_ready() {
    let directory = tempfile::tempdir().unwrap();
    let expected = directory.path().join("absent-ffmpeg");
    let (router, _) = router_for(
        CameraMediaEnvironment {
            platform_supported: true,
            ffmpeg: expected.clone(),
        },
        directory.path(),
    )
    .await;

    let (status, media) = call(&router, Method::GET, "/api/v1/camera-media", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(media["enabled"], false);
    assert_eq!(media["reason"], REASON_FFMPEG_NOT_FOUND);
    let detail = media["detail"].as_str().unwrap();
    assert!(detail.contains(&expected.display().to_string()), "{detail}");
    assert!(detail.contains(FFMPEG_ENV), "{detail}");
    assert_eq!(media["setup_available"], false);

    let camera = "018f47a0-9b5c-4a22-8a33-112233445599";
    let stream = "018f47a0-9b5c-4a22-8a33-112233445500";
    let session_body = format!("{{\"stream_id\":\"{stream}\"}}");
    for (method, uri, body) in [
        (
            Method::POST,
            format!("/api/v1/cameras/{camera}/sessions"),
            Some(session_body.as_str()),
        ),
        (
            Method::GET,
            format!("/api/v1/cameras/{camera}/snapshot"),
            None,
        ),
        (
            Method::GET,
            format!("/api/v1/camera-sessions/{SESSION}/playlist.m3u8"),
            None,
        ),
        (
            Method::GET,
            format!("/api/v1/camera-sessions/{SESSION}/segments/segment-000001.ts"),
            None,
        ),
        (
            Method::DELETE,
            format!("/api/v1/camera-sessions/{SESSION}"),
            None,
        ),
    ] {
        let (status, body) = call(&router, method.clone(), &uri, body).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{method} {uri}");
        assert_eq!(body["reason"], REASON_FFMPEG_NOT_FOUND, "{method} {uri}");
        assert_eq!(body["detail"], media["detail"], "{method} {uri}");
        assert_ne!(
            body["error"], "camera media is not enabled in this build",
            "the generic message must not stand in for a specific reason"
        );
    }

    // Nothing else about the service is affected.
    let (status, state) = call(&router, Method::GET, "/api/v1/state", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["service_status"], "ready");
    let (status, cameras) = call(&router, Method::GET, "/api/v1/cameras", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cameras["items"].as_array().unwrap().len(), 0);
    // No ffmpeg means no output root and no vault were touched.
    assert!(!directory.path().join("camera-media").exists());
}

#[tokio::test]
async fn an_unsupported_platform_is_reported_as_such() {
    let directory = tempfile::tempdir().unwrap();
    let (router, _) = router_for(
        CameraMediaEnvironment {
            platform_supported: false,
            ffmpeg: fake_ffmpeg(directory.path()),
        },
        directory.path(),
    )
    .await;
    let (status, media) = call(&router, Method::GET, "/api/v1/camera-media", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(media["enabled"], false);
    assert_eq!(media["reason"], "unsupported_platform");
}

#[tokio::test]
async fn the_status_route_requires_the_owner_token() {
    let directory = tempfile::tempdir().unwrap();
    let (router, _) = router_for(
        CameraMediaEnvironment {
            platform_supported: true,
            ffmpeg: directory.path().join("absent-ffmpeg"),
        },
        directory.path(),
    )
    .await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/camera-media")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_ready_machine_serves_the_routes_and_still_refuses_unapproved_targets() {
    let directory = tempfile::tempdir().unwrap();
    let ffmpeg = fake_ffmpeg(directory.path());
    let state_dir = directory.path().join("state");
    let pool = connect_memory().await.unwrap();
    let vault = Arc::new(FakeVault::new());

    // A registered camera with a stored stream source but no approved target.
    let camera = camera_id(1);
    let stream = stream_id(2);
    let repository = CameraRepository::new(pool.clone());
    repository
        .upsert_camera(&CameraRecord {
            id: camera,
            classification: CameraClassification::Camera,
            confidence: Confidence::new(0.9).unwrap(),
            health: CameraHealth::Healthy,
            observed_at: Utc::now(),
        })
        .await
        .unwrap();
    let source_ref = vault
        .put_stream_source(
            camera,
            stream,
            SecretString::from("rtsp://viewer:secret@192.168.4.22:8554/live"),
        )
        .await
        .unwrap();
    repository
        .put_stream_ref(camera, &CameraProfile::new(stream, source_ref))
        .await
        .unwrap();

    let build = assemble(
        &CameraMediaEnvironment {
            platform_supported: true,
            ffmpeg,
        },
        pool.clone(),
        vault,
        "a test vault",
        &state_dir,
    )
    .await;
    assert!(build.manager.is_some(), "{:?}", build.status);
    let state = AppState::new(TOKEN, M2StateRepository::new(pool))
        .unwrap()
        .with_camera_media(build);
    let router = app(state);

    let (status, media) = call(&router, Method::GET, "/api/v1/camera-media", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(media["enabled"], true);
    assert_eq!(media["reason"], REASON_READY);
    // Media is running, so a camera can be added.
    assert_eq!(media["setup_available"], true);
    assert_eq!(media["setup_detail"], "");

    // The routes are live: an unknown camera is a 404, not "media disabled".
    let unknown = "018f47a0-9b5c-4a22-8a33-112233445599";
    let (status, _) = call(
        &router,
        Method::GET,
        &format!("/api/v1/cameras/{unknown}/snapshot"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A real camera whose stream has no owner-approved target fails closed.
    let body = format!("{{\"stream_id\":\"{stream}\"}}");
    let (status, _) = call(
        &router,
        Method::POST,
        &format!("/api/v1/cameras/{camera}/sessions"),
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}
