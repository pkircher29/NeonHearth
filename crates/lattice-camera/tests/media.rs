use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, TimeZone, Utc};
#[cfg(target_os = "linux")]
use lattice_camera::resolve_ffmpeg_executable;
use lattice_camera::{
    CameraId, FakeMediaProcessFactory, HlsSession, HlsSessionId, LoopbackSourceToken, MediaError,
    MediaJob, MediaProcess, MediaProcessExit, MediaProcessFactory, MediaProcessSpec,
    ProductionMediaProcessFactory, SnapshotRequest, StreamId, ffmpeg_executable, hls_args,
    platform_default_ffmpeg, snapshot_args,
};
#[cfg(target_os = "linux")]
use std::ffi::OsStr;
use std::{ffi::OsString, future::pending, path::Path, time::Duration};
use uuid::Uuid;

const CAMERA: &str = "192.168.4.22";
const USERNAME: &str = "camera-user";
const PASSWORD: &str = "camera-password-leak-sentinel";

#[test]
fn opaque_media_ids_have_canonical_serde_and_redacted_debug() {
    let token: LoopbackSourceToken =
        serde_json::from_str("\"0190c6d1-1234-7abc-8def-0123456789ab\"").unwrap();
    let session: HlsSessionId =
        serde_json::from_str("\"0190c6d1-1234-7abc-8def-0123456789ac\"").unwrap();
    assert_eq!(
        serde_json::to_string(&token).unwrap(),
        "\"0190c6d1-1234-7abc-8def-0123456789ab\""
    );
    assert_eq!(
        serde_json::to_string(&session).unwrap(),
        "\"0190c6d1-1234-7abc-8def-0123456789ac\""
    );
    assert_eq!(format!("{token:?}"), "LoopbackSourceToken([opaque])");
    assert_eq!(format!("{session:?}"), "HlsSessionId([opaque])");
    for invalid in [
        "\"secret-token\"",
        "\"0190c6d1-1234-4abc-8def-0123456789ab\"",
        "\"0190C6D1-1234-7ABC-8DEF-0123456789AB\"",
        "\"0190c6d1-1234-7abc-8def-0123456789ab/..\"",
    ] {
        assert!(serde_json::from_str::<LoopbackSourceToken>(invalid).is_err());
        assert!(serde_json::from_str::<HlsSessionId>(invalid).is_err());
    }
}

#[test]
fn hls_session_contract_is_bounded_opaque_and_round_trips() {
    let id = HlsSessionId::from_canonical("0190c6d1-1234-7abc-8def-0123456789ac").unwrap();
    let camera = CameraId::from_uuid(Uuid::from_u128(1));
    let stream = StreamId::from_uuid(Uuid::from_u128(2));
    let created = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
    let expires = created + ChronoDuration::minutes(10);
    let session = HlsSession::new(id.clone(), camera, stream, created, expires).unwrap();
    assert_eq!(session.id(), &id);
    assert_eq!(session.camera(), camera);
    assert_eq!(session.stream(), stream);
    assert_eq!(session.created_at(), created);
    assert_eq!(session.expires_at(), expires);
    assert_eq!(format!("{session:?}"), "HlsSession([opaque])");

    let encoded = serde_json::to_string(&session).unwrap();
    let decoded: HlsSession = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, session);
    let object = serde_json::from_str::<serde_json::Value>(&encoded).unwrap();
    assert_eq!(
        object
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        [
            "camera_id",
            "created_at",
            "expires_at",
            "session_id",
            "stream_id"
        ]
    );
    for forbidden in [
        "source_token",
        "output_path",
        "rtsp",
        "credential_ref",
        "endpoint",
        "camera-password-leak-sentinel",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    assert!(
        HlsSession::new(
            id.clone(),
            camera,
            stream,
            created,
            created + ChronoDuration::minutes(10) + ChronoDuration::milliseconds(1),
        )
        .is_err()
    );
    assert!(HlsSession::new(id, camera, stream, created, created).is_err());

    let mut unknown = object;
    unknown["endpoint"] = serde_json::Value::String("rtsp://camera/private".into());
    assert!(serde_json::from_value::<HlsSession>(unknown).is_err());
}

/// The production validator requires an absolute path; `/srv/...` is not
/// absolute on Windows, so the fixture directory is anchored per platform
/// and expected argument paths are built with the same `join` the code uses.
fn media_dir(name: &str) -> std::path::PathBuf {
    if cfg!(windows) {
        std::path::PathBuf::from(format!("C:/srv/neonhearth/media/{name}"))
    } else {
        std::path::PathBuf::from(format!("/srv/neonhearth/media/{name}"))
    }
}

#[test]
fn hls_arguments_are_an_exact_shell_free_vector_with_localhost_only_input() {
    let token =
        LoopbackSourceToken::from_canonical("0190c6d1-1234-7abc-8def-0123456789ab").unwrap();
    let dir = media_dir("session");
    let args = hls_args(43123, &token, &dir).unwrap();
    assert_eq!(
        args,
        [
            "-hide_banner",
            "-nostdin",
            "-loglevel",
            "error",
            "-rtsp_transport",
            "tcp",
            "-i",
            "rtsp://127.0.0.1:43123/source/0190c6d1-1234-7abc-8def-0123456789ab",
            "-map",
            "0:v:0",
            "-an",
            "-c:v",
            "copy",
            "-f",
            "hls",
            "-hls_time",
            "2",
            "-hls_list_size",
            "4",
            "-hls_flags",
            "delete_segments+append_list+omit_endlist+independent_segments",
            "-hls_segment_filename",
        ]
        .map(OsString::from)
        .into_iter()
        .chain([
            dir.join("segment-%06d.ts").into_os_string(),
            dir.join("playlist.m3u8").into_os_string(),
        ])
        .collect::<Vec<_>>()
    );
    let joined = args
        .iter()
        .map(|value| value.to_string_lossy())
        .collect::<String>();
    for secret in [CAMERA, USERNAME, PASSWORD, "rtsp://camera"] {
        assert!(!joined.contains(secret));
    }
}

#[test]
fn snapshot_arguments_are_fixed_to_one_jpeg_in_the_owned_directory() {
    let token =
        LoopbackSourceToken::from_canonical("0190c6d1-1234-7abc-8def-0123456789ab").unwrap();
    let dir = media_dir("snapshot");
    let args = snapshot_args(43123, &token, &dir).unwrap();
    assert_eq!(
        args,
        [
            "-hide_banner",
            "-nostdin",
            "-loglevel",
            "error",
            "-rtsp_transport",
            "tcp",
            "-i",
            "rtsp://127.0.0.1:43123/source/0190c6d1-1234-7abc-8def-0123456789ab",
            "-map",
            "0:v:0",
            "-an",
            "-frames:v",
            "1",
            "-f",
            "image2",
            "-c:v",
            "mjpeg",
        ]
        .map(OsString::from)
        .into_iter()
        .chain([dir.join("snapshot.jpg").into_os_string()])
        .collect::<Vec<_>>()
    );
    assert_eq!(SnapshotRequest::FILE_NAME, "snapshot.jpg");
}

#[test]
fn argument_builders_reject_non_absolute_or_traversing_output_and_invalid_port() {
    let token = LoopbackSourceToken::new();
    for path in [Path::new("relative"), Path::new("/owned/../escape")] {
        assert_eq!(hls_args(10, &token, path), Err(MediaError::InvalidOutput));
        assert_eq!(
            snapshot_args(10, &token, path),
            Err(MediaError::InvalidOutput)
        );
    }
    assert_eq!(
        hls_args(0, &token, Path::new("/owned")),
        Err(MediaError::InvalidSource)
    );
}

#[test]
fn platform_default_matches_the_installer_layout() {
    #[cfg(target_os = "linux")]
    assert_eq!(platform_default_ffmpeg(), Path::new("/usr/bin/ffmpeg"));
    #[cfg(target_os = "windows")]
    {
        // The MSI installs every binary flat in INSTALLFOLDER; there is no bin\.
        assert_eq!(
            platform_default_ffmpeg(),
            Path::new(r"C:\Program Files\NeonHearth\ffmpeg.exe")
        );
    }
    // The resolved executable is always absolute and never traverses.
    assert!(ffmpeg_executable().is_absolute());
}

#[cfg(target_os = "linux")]
#[test]
fn ffmpeg_resolution_prefers_override_then_default_then_path() {
    let default = platform_default_ffmpeg();
    let override_path = Path::new("/opt/custom/ffmpeg");
    let on_path = Path::new("/opt/tools/ffmpeg");
    let path_var = OsString::from("relative/bin:/nowhere:/opt/tools");

    // 1. An absolute override wins even when nothing exists on disk.
    let never = |_: &Path| false;
    assert_eq!(
        resolve_ffmpeg_executable(Some(override_path.as_os_str()), Some(&path_var), &never),
        override_path
    );
    // 2. A relative, empty, or traversing override is ignored.
    for bad in ["ffmpeg", "", "/opt/../usr/bin/ffmpeg", "./ffmpeg"] {
        let only_path = |candidate: &Path| candidate == on_path;
        assert_eq!(
            resolve_ffmpeg_executable(Some(OsStr::new(bad)), Some(&path_var), &only_path),
            on_path,
            "override {bad:?} must be ignored"
        );
    }
    // 3. The platform default is preferred over PATH when it exists.
    let both = |candidate: &Path| candidate == default || candidate == on_path;
    assert_eq!(
        resolve_ffmpeg_executable(None, Some(&path_var), &both),
        default
    );
    // 4. PATH is searched in order, skipping relative entries.
    let only_path = |candidate: &Path| candidate == on_path;
    assert_eq!(
        resolve_ffmpeg_executable(None, Some(&path_var), &only_path),
        on_path
    );
    // 5. Nothing found: fall back to the platform default so spawn fails typed.
    assert_eq!(
        resolve_ffmpeg_executable(None, Some(&path_var), &never),
        default
    );
    assert_eq!(resolve_ffmpeg_executable(None, None, &never), default);
}

#[tokio::test]
async fn fake_process_records_only_the_spec_and_close_kills_then_awaits() {
    let factory = FakeMediaProcessFactory::new();
    let spec = MediaProcessSpec::new(
        MediaJob::Hls,
        ffmpeg_executable().to_path_buf(),
        vec![OsString::from("-nostdin")],
    )
    .unwrap();
    let mut process = factory.spawn(spec.clone()).await.unwrap();
    assert_eq!(factory.specs().await, vec![spec]);
    process.close().await.unwrap();
    let observations = factory.observations().await;
    assert_eq!(observations.len(), 1);
    assert!(observations[0].kill_requested);
    assert!(observations[0].awaited);
}

struct UncooperativeMediaProcess;

#[async_trait]
impl MediaProcess for UncooperativeMediaProcess {
    async fn kill(&mut self) -> Result<(), MediaError> {
        Ok(())
    }

    async fn wait(&mut self) -> Result<MediaProcessExit, MediaError> {
        pending().await
    }

    fn try_wait(&mut self) -> Result<Option<MediaProcessExit>, MediaError> {
        Ok(None)
    }
}

#[tokio::test(start_paused = true)]
async fn media_close_bounds_an_uncooperative_process_wait() {
    let mut process = UncooperativeMediaProcess;
    let result = tokio::time::timeout(Duration::from_secs(6), process.close()).await;
    assert_eq!(result.unwrap(), Err(MediaError::ProcessFailed));
}

#[tokio::test]
async fn fake_process_bounds_diagnostics_and_errors_are_sanitized() {
    let factory = FakeMediaProcessFactory::new();
    factory.fail_next(PASSWORD.repeat(32).into_bytes()).await;
    let spec = MediaProcessSpec::new(
        MediaJob::Snapshot,
        ffmpeg_executable().to_path_buf(),
        Vec::new(),
    )
    .unwrap();
    let error = match factory.spawn(spec).await {
        Ok(_) => panic!("spawn unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(error, MediaError::ProcessFailed);
    assert!(!format!("{error:?}").contains(PASSWORD));
    assert!(factory.last_diagnostic().await.unwrap().len() <= 16 * 1024);
    assert!(!String::from_utf8_lossy(&factory.last_diagnostic().await.unwrap()).contains(PASSWORD));
}

#[tokio::test]
async fn production_factory_rejects_even_a_same_length_flag_mutation_before_spawn() {
    let token = LoopbackSourceToken::new();
    let mut args = hls_args(43123, &token, &media_dir("session")).unwrap();
    args[1] = OsString::from("-y");
    let spec =
        MediaProcessSpec::new(MediaJob::Hls, ffmpeg_executable().to_path_buf(), args).unwrap();
    let error = match ProductionMediaProcessFactory.spawn(spec).await {
        Ok(_) => panic!("mutated production arguments were accepted"),
        Err(error) => error,
    };
    assert_eq!(error, MediaError::InvalidArguments);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn production_factory_accepts_the_exact_fixed_vector() {
    if !ffmpeg_executable().is_file() {
        return;
    }
    let token = LoopbackSourceToken::new();
    let spec =
        MediaProcessSpec::hls(43123, &token, Path::new("/tmp/neonhearth-media-contract")).unwrap();
    let mut process = ProductionMediaProcessFactory.spawn(spec).await.unwrap();
    process.close().await.unwrap();
}
