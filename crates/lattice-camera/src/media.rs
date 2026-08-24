//! Camera media-process primitives.
//!
//! Callers can select only HLS or one-frame snapshot jobs. Both use an exact
//! argument vector, a loopback-only source, and a caller-owned absolute output
//! directory. Production spawning never invokes a shell and never returns
//! process diagnostics.

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::Arc,
};
use thiserror::Error;
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    sync::Mutex,
    task::JoinHandle,
};
use uuid::Uuid;

const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;

macro_rules! opaque_uuid_v7 {
    ($name:ident) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn from_canonical(value: &str) -> Result<Self, MediaError> {
                let parsed = Uuid::parse_str(value).map_err(|_| MediaError::InvalidOpaqueId)?;
                if parsed.get_version_num() != 7 || parsed.hyphenated().to_string() != value {
                    return Err(MediaError::InvalidOpaqueId);
                }
                Ok(Self(parsed))
            }

            #[must_use]
            pub fn as_str(&self) -> String {
                self.0.hyphenated().to_string()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([opaque])"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.hyphenated().fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0.hyphenated().to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct OpaqueVisitor;
                impl Visitor<'_> for OpaqueVisitor {
                    type Value = $name;
                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a canonical UUIDv7 opaque identifier")
                    }
                    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                        if value.len() != 36 {
                            return Err(E::custom("invalid opaque identifier"));
                        }
                        $name::from_canonical(value).map_err(E::custom)
                    }
                }
                deserializer.deserialize_str(OpaqueVisitor)
            }
        }
    };
}

opaque_uuid_v7!(LoopbackSourceToken);
opaque_uuid_v7!(HlsSessionId);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaJob {
    Hls,
    Snapshot,
}

pub struct SnapshotRequest;
impl SnapshotRequest {
    pub const FILE_NAME: &'static str = "snapshot.jpg";
}

#[derive(Clone, Eq, PartialEq)]
pub struct MediaProcessSpec {
    job: MediaJob,
    executable: PathBuf,
    args: Vec<OsString>,
}

impl fmt::Debug for MediaProcessSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MediaProcessSpec")
            .field("job", &self.job)
            .field("executable", &"[platform-fixed]")
            .field("args", &"[fixed-redacted]")
            .finish()
    }
}

impl MediaProcessSpec {
    /// Primarily a fake-process test seam. The production factory independently
    /// validates that this is one of the two exact supported vectors.
    pub fn new(
        job: MediaJob,
        executable: PathBuf,
        args: Vec<OsString>,
    ) -> Result<Self, MediaError> {
        if executable != ffmpeg_executable() {
            return Err(MediaError::InvalidExecutable);
        }
        Ok(Self {
            job,
            executable,
            args,
        })
    }

    pub fn hls(
        port: u16,
        token: &LoopbackSourceToken,
        output_dir: &Path,
    ) -> Result<Self, MediaError> {
        Self::new(
            MediaJob::Hls,
            ffmpeg_executable().to_path_buf(),
            hls_args(port, token, output_dir)?,
        )
    }

    pub fn snapshot(
        port: u16,
        token: &LoopbackSourceToken,
        output_dir: &Path,
    ) -> Result<Self, MediaError> {
        Self::new(
            MediaJob::Snapshot,
            ffmpeg_executable().to_path_buf(),
            snapshot_args(port, token, output_dir)?,
        )
    }

    pub const fn job(&self) -> MediaJob {
        self.job
    }
    pub fn executable(&self) -> &Path {
        &self.executable
    }
    pub fn args(&self) -> &[OsString] {
        &self.args
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MediaError {
    #[error("invalid opaque media identifier")]
    InvalidOpaqueId,
    #[error("invalid loopback media source")]
    InvalidSource,
    #[error("invalid media output location")]
    InvalidOutput,
    #[error("invalid media executable")]
    InvalidExecutable,
    #[error("invalid media arguments")]
    InvalidArguments,
    #[error("media process unavailable")]
    ProcessUnavailable,
    #[error("media process failed")]
    ProcessFailed,
}

#[must_use]
pub fn ffmpeg_executable() -> &'static Path {
    #[cfg(target_os = "windows")]
    {
        Path::new(r"C:\Program Files\NeonHearth\bin\ffmpeg.exe")
    }
    #[cfg(not(target_os = "windows"))]
    {
        Path::new("/usr/bin/ffmpeg")
    }
}

pub fn hls_args(
    port: u16,
    token: &LoopbackSourceToken,
    output_dir: &Path,
) -> Result<Vec<OsString>, MediaError> {
    let source = loopback_source(port, token)?;
    validate_output_dir(output_dir)?;
    Ok(strings([
        "-hide_banner",
        "-nostdin",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-i",
        &source,
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
    ])
    .into_iter()
    .chain([
        output_dir.join("segment-%06d.ts").into_os_string(),
        output_dir.join("playlist.m3u8").into_os_string(),
    ])
    .collect())
}

pub fn snapshot_args(
    port: u16,
    token: &LoopbackSourceToken,
    output_dir: &Path,
) -> Result<Vec<OsString>, MediaError> {
    let source = loopback_source(port, token)?;
    validate_output_dir(output_dir)?;
    Ok(strings([
        "-hide_banner",
        "-nostdin",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-i",
        &source,
        "-map",
        "0:v:0",
        "-an",
        "-frames:v",
        "1",
        "-f",
        "image2",
        "-c:v",
        "mjpeg",
    ])
    .into_iter()
    .chain([output_dir.join(SnapshotRequest::FILE_NAME).into_os_string()])
    .collect())
}

fn strings<const N: usize>(items: [&str; N]) -> Vec<OsString> {
    items.into_iter().map(OsString::from).collect()
}

fn loopback_source(port: u16, token: &LoopbackSourceToken) -> Result<String, MediaError> {
    if port == 0 {
        return Err(MediaError::InvalidSource);
    }
    Ok(format!("rtsp://127.0.0.1:{port}/source/{token}"))
}

fn validate_output_dir(path: &Path) -> Result<(), MediaError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        Err(MediaError::InvalidOutput)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaProcessExit {
    pub success: bool,
}

#[async_trait]
pub trait MediaProcess: Send {
    async fn kill(&mut self) -> Result<(), MediaError>;
    async fn wait(&mut self) -> Result<MediaProcessExit, MediaError>;
    fn try_wait(&mut self) -> Result<Option<MediaProcessExit>, MediaError>;

    async fn close(&mut self) -> Result<(), MediaError> {
        let kill = self.kill().await;
        let wait = self.wait().await;
        match (kill, wait) {
            (Ok(()), Ok(_)) => Ok(()),
            _ => Err(MediaError::ProcessFailed),
        }
    }
}

#[async_trait]
pub trait MediaProcessFactory: Send + Sync {
    async fn spawn(&self, spec: MediaProcessSpec) -> Result<Box<dyn MediaProcess>, MediaError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionMediaProcessFactory;

#[async_trait]
impl MediaProcessFactory for ProductionMediaProcessFactory {
    async fn spawn(&self, spec: MediaProcessSpec) -> Result<Box<dyn MediaProcess>, MediaError> {
        validate_production_spec(&spec)?;
        let mut command = Command::new(spec.executable());
        command
            .args(spec.args())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| MediaError::ProcessUnavailable)?;
        let stderr = child.stderr.take().ok_or(MediaError::ProcessUnavailable)?;
        let diagnostic = tokio::spawn(async move {
            let mut stderr = stderr;
            let mut buffer = [0_u8; 4096];
            let mut count = 0_usize;
            loop {
                match stderr.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(read) => count = count.saturating_add(read),
                    Err(_) => break,
                }
            }
            sanitized_diagnostic(count)
        });
        Ok(Box::new(ProductionMediaProcess {
            child,
            diagnostic: Some(diagnostic),
            waited: false,
        }))
    }
}

fn validate_production_spec(spec: &MediaProcessSpec) -> Result<(), MediaError> {
    if spec.executable() != ffmpeg_executable() {
        return Err(MediaError::InvalidExecutable);
    }
    let args = spec.args();
    let input = args
        .windows(2)
        .find(|pair| pair[0] == OsStr::new("-i"))
        .map(|pair| pair[1].to_string_lossy())
        .ok_or(MediaError::InvalidArguments)?;
    let source = input
        .strip_prefix("rtsp://127.0.0.1:")
        .ok_or(MediaError::InvalidArguments)?;
    let (port, token) = source
        .split_once("/source/")
        .ok_or(MediaError::InvalidArguments)?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(MediaError::InvalidArguments)?;
    let token =
        LoopbackSourceToken::from_canonical(token).map_err(|_| MediaError::InvalidArguments)?;
    let output = args
        .last()
        .map(PathBuf::from)
        .ok_or(MediaError::InvalidArguments)?;
    let output_dir = output.parent().ok_or(MediaError::InvalidArguments)?;
    let expected = match spec.job() {
        MediaJob::Hls => hls_args(port, &token, output_dir),
        MediaJob::Snapshot => snapshot_args(port, &token, output_dir),
    }
    .map_err(|_| MediaError::InvalidArguments)?;
    if args == expected {
        Ok(())
    } else {
        Err(MediaError::InvalidArguments)
    }
}

struct ProductionMediaProcess {
    child: Child,
    diagnostic: Option<JoinHandle<Vec<u8>>>,
    waited: bool,
}

#[async_trait]
impl MediaProcess for ProductionMediaProcess {
    async fn kill(&mut self) -> Result<(), MediaError> {
        match self.child.start_kill() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
            Err(_) => Err(MediaError::ProcessFailed),
        }
    }

    async fn wait(&mut self) -> Result<MediaProcessExit, MediaError> {
        let status = self
            .child
            .wait()
            .await
            .map_err(|_| MediaError::ProcessFailed)?;
        self.waited = true;
        if let Some(diagnostic) = self.diagnostic.take() {
            let _ = diagnostic.await;
        }
        Ok(MediaProcessExit {
            success: status.success(),
        })
    }

    fn try_wait(&mut self) -> Result<Option<MediaProcessExit>, MediaError> {
        self.child
            .try_wait()
            .map(|status| {
                status.map(|status| MediaProcessExit {
                    success: status.success(),
                })
            })
            .map_err(|_| MediaError::ProcessFailed)
    }
}

impl Drop for ProductionMediaProcess {
    fn drop(&mut self) {
        if !self.waited {
            let _ = self.child.start_kill();
        }
        if let Some(diagnostic) = self.diagnostic.take() {
            diagnostic.abort();
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MediaProcessObservation {
    pub kill_requested: bool,
    pub awaited: bool,
}

#[derive(Clone, Default)]
pub struct FakeMediaProcessFactory {
    inner: Arc<Mutex<FakeState>>,
    exits: Arc<std::sync::Mutex<Vec<Option<MediaProcessExit>>>>,
}

#[derive(Default)]
struct FakeState {
    specs: Vec<MediaProcessSpec>,
    observations: Vec<MediaProcessObservation>,
    fail_next: Option<Vec<u8>>,
    last_diagnostic: Option<Vec<u8>>,
    hls_output: Option<FakeHlsOutput>,
    snapshot_output: Option<Vec<u8>>,
    snapshot_hangs: bool,
}

type FakeHlsOutput = (Vec<u8>, Vec<FakeSegment>);
type FakeSegment = (String, Vec<u8>);

impl FakeMediaProcessFactory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub async fn specs(&self) -> Vec<MediaProcessSpec> {
        self.inner.lock().await.specs.clone()
    }
    pub async fn observations(&self) -> Vec<MediaProcessObservation> {
        self.inner.lock().await.observations.clone()
    }
    pub async fn fail_next(&self, diagnostic: Vec<u8>) {
        self.inner.lock().await.fail_next = Some(diagnostic);
    }
    pub async fn last_diagnostic(&self) -> Option<Vec<u8>> {
        self.inner.lock().await.last_diagnostic.clone()
    }
    pub async fn set_hls_output(&self, playlist: Vec<u8>, segments: Vec<(String, Vec<u8>)>) {
        self.inner.lock().await.hls_output = Some((playlist, segments));
    }
    pub async fn set_snapshot_output(&self, jpeg: Vec<u8>) {
        self.inner.lock().await.snapshot_output = Some(jpeg);
    }
    pub async fn set_snapshot_hang(&self, hangs: bool) {
        self.inner.lock().await.snapshot_hangs = hangs;
    }
    pub async fn crash_last(&self) {
        if let Some(exit) = self
            .exits
            .lock()
            .expect("fake media exits poisoned")
            .last_mut()
        {
            *exit = Some(MediaProcessExit { success: false });
        }
    }
}

#[async_trait]
impl MediaProcessFactory for FakeMediaProcessFactory {
    async fn spawn(&self, spec: MediaProcessSpec) -> Result<Box<dyn MediaProcess>, MediaError> {
        let mut state = self.inner.lock().await;
        let job = spec.job();
        let output = spec.args().last().map(PathBuf::from);
        state.specs.push(spec);
        if let Some(diagnostic) = state.fail_next.take() {
            state.last_diagnostic = Some(sanitized_diagnostic(diagnostic.len()));
            return Err(MediaError::ProcessFailed);
        }
        let index = state.observations.len();
        state.observations.push(MediaProcessObservation::default());
        let hls_output = state.hls_output.clone();
        let snapshot_output = state.snapshot_output.clone();
        let snapshot_hangs = state.snapshot_hangs;
        drop(state);
        self.exits.lock().expect("fake media exits poisoned").push(
            (job == MediaJob::Snapshot && !snapshot_hangs)
                .then_some(MediaProcessExit { success: true }),
        );
        if let Some(output) = output {
            match job {
                MediaJob::Hls => {
                    if let Some((playlist, segments)) = hls_output {
                        tokio::fs::write(&output, playlist)
                            .await
                            .map_err(|_| MediaError::ProcessFailed)?;
                        let directory = output.parent().ok_or(MediaError::ProcessFailed)?;
                        for (name, bytes) in segments {
                            if name.contains('/') || name.contains('\\') {
                                return Err(MediaError::ProcessFailed);
                            }
                            tokio::fs::write(directory.join(name), bytes)
                                .await
                                .map_err(|_| MediaError::ProcessFailed)?;
                        }
                    }
                }
                MediaJob::Snapshot => {
                    if let Some(jpeg) = snapshot_output {
                        tokio::fs::write(output, jpeg)
                            .await
                            .map_err(|_| MediaError::ProcessFailed)?;
                    }
                }
            }
        }
        Ok(Box::new(FakeMediaProcess {
            state: self.inner.clone(),
            exits: self.exits.clone(),
            index,
        }))
    }
}

struct FakeMediaProcess {
    state: Arc<Mutex<FakeState>>,
    exits: Arc<std::sync::Mutex<Vec<Option<MediaProcessExit>>>>,
    index: usize,
}

#[async_trait]
impl MediaProcess for FakeMediaProcess {
    async fn kill(&mut self) -> Result<(), MediaError> {
        self.state.lock().await.observations[self.index].kill_requested = true;
        self.exits.lock().expect("fake media exits poisoned")[self.index] =
            Some(MediaProcessExit { success: false });
        Ok(())
    }
    async fn wait(&mut self) -> Result<MediaProcessExit, MediaError> {
        self.state.lock().await.observations[self.index].awaited = true;
        loop {
            if let Some(exit) = self.exits.lock().expect("fake media exits poisoned")[self.index] {
                return Ok(exit);
            }
            tokio::task::yield_now().await;
        }
    }
    fn try_wait(&mut self) -> Result<Option<MediaProcessExit>, MediaError> {
        Ok(self.exits.lock().expect("fake media exits poisoned")[self.index])
    }
}

fn sanitized_diagnostic(bytes: usize) -> Vec<u8> {
    let bounded = bytes.min(MAX_DIAGNOSTIC_BYTES);
    format!("media process diagnostic redacted ({bounded} bytes)").into_bytes()
}
