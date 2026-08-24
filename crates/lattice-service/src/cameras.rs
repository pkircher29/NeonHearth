//! Authenticated camera media sessions and the credential-injecting RTSP loopback.

use async_trait::async_trait;
use axum::{
    Json,
    body::Body,
    extract::{Path as AxumPath, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{Duration as ChronoDuration, Utc};
use lattice_camera::{
    CameraId, HlsSession, HlsSessionId, LoopbackSourceToken, MediaProcess, MediaProcessFactory,
    MediaProcessSpec, StreamId,
};
use lattice_sensor::{
    AuthorizedBinding, InterfaceId, TargetGuard, active::pin_socket_to_interface,
};
use lattice_store::CameraRepository;
use md5_digest::{Digest, Md5};
use percent_encoding::percent_decode_str;
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::{HashMap, VecDeque},
    fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex, split},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore, watch},
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::{AppState, auth::Authorized, vault::Vault};

const CLEANUP_COMPONENT_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_RETRY_BASE: Duration = Duration::from_millis(25);
const CLEANUP_RETRY_MAX: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug)]
pub struct CameraSessionConfig {
    pub max_sessions: usize,
    pub idle_timeout: Duration,
    pub total_timeout: Duration,
    pub process_start_timeout: Duration,
    pub snapshot_timeout: Duration,
    pub max_playlist_bytes: usize,
    pub max_segment_bytes: usize,
    pub max_snapshot_bytes: usize,
}

impl Default for CameraSessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: 4,
            idle_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(5 * 60),
            process_start_timeout: Duration::from_secs(5),
            snapshot_timeout: Duration::from_secs(10),
            max_playlist_bytes: 256 * 1024,
            max_segment_bytes: 16 * 1024 * 1024,
            max_snapshot_bytes: 8 * 1024 * 1024,
        }
    }
}

impl CameraSessionConfig {
    fn validate(self) -> Result<Self, CameraSessionError> {
        if !(1..=16).contains(&self.max_sessions)
            || self.idle_timeout.is_zero()
            || self.total_timeout < self.idle_timeout
            || self.total_timeout > Duration::from_secs(10 * 60)
            || self.process_start_timeout.is_zero()
            || self.process_start_timeout > Duration::from_secs(30)
            || self.snapshot_timeout.is_zero()
            || self.snapshot_timeout > Duration::from_secs(30)
            || !(1..=1024 * 1024).contains(&self.max_playlist_bytes)
            || !(1..=64 * 1024 * 1024).contains(&self.max_segment_bytes)
            || !(4..=32 * 1024 * 1024).contains(&self.max_snapshot_bytes)
        {
            Err(CameraSessionError::Invalid)
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CameraSessionError {
    #[error("invalid camera media request")]
    Invalid,
    #[error("camera media resource not found")]
    NotFound,
    #[error("camera media capacity reached")]
    Capacity,
    #[error("camera media payload too large")]
    PayloadTooLarge,
    #[error("camera media unavailable")]
    Unavailable,
}

#[async_trait]
pub trait CameraTargetRegistry: Send + Sync {
    async fn authorized_binding(
        &self,
        camera: CameraId,
        stream: StreamId,
    ) -> Result<ApprovedRtspTarget, CameraSessionError>;
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovedRtspTarget {
    binding: AuthorizedBinding,
    port: u16,
}

impl fmt::Debug for ApprovedRtspTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovedRtspTarget([approved])")
    }
}

impl ApprovedRtspTarget {
    pub fn new(binding: AuthorizedBinding, port: u16) -> Result<Self, CameraSessionError> {
        if port == 0 {
            Err(CameraSessionError::Invalid)
        } else {
            Ok(Self { binding, port })
        }
    }

    #[must_use]
    pub const fn binding(self) -> AuthorizedBinding {
        self.binding
    }

    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }
}

#[derive(Clone, Default)]
pub struct FakeCameraTargetRegistry {
    bindings: Arc<Mutex<HashMap<(CameraId, StreamId), ApprovedRtspTarget>>>,
}

impl FakeCameraTargetRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub async fn approve(&self, camera: CameraId, stream: StreamId, target: ApprovedRtspTarget) {
        self.bindings.lock().await.insert((camera, stream), target);
    }
    pub async fn deny(&self, camera: CameraId, stream: StreamId) {
        self.bindings.lock().await.remove(&(camera, stream));
    }
}

#[async_trait]
impl CameraTargetRegistry for FakeCameraTargetRegistry {
    async fn authorized_binding(
        &self,
        camera: CameraId,
        stream: StreamId,
    ) -> Result<ApprovedRtspTarget, CameraSessionError> {
        self.bindings
            .lock()
            .await
            .get(&(camera, stream))
            .copied()
            .ok_or(CameraSessionError::Unavailable)
    }
}

/// Production in-memory registry. Every insert and every lookup is checked by
/// the same owner-configured [`TargetGuard`]; URI parsing is never an authority
/// source.
#[derive(Clone)]
pub struct GuardedCameraTargetRegistry {
    guard: TargetGuard,
    targets: Arc<Mutex<GuardedTargets>>,
}

type GuardedTargets = HashMap<(CameraId, StreamId), (InterfaceId, IpAddr, u16)>;

impl GuardedCameraTargetRegistry {
    #[must_use]
    pub fn new(guard: TargetGuard) -> Self {
        Self {
            guard,
            targets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn register(
        &self,
        camera: CameraId,
        stream: StreamId,
        interface: InterfaceId,
        target: IpAddr,
        port: u16,
    ) -> Result<(), CameraSessionError> {
        if port == 0 {
            return Err(CameraSessionError::Invalid);
        }
        self.guard
            .authorized_binding(interface, target)
            .map_err(|_| CameraSessionError::Unavailable)?;
        self.targets
            .lock()
            .await
            .insert((camera, stream), (interface, target, port));
        Ok(())
    }

    pub async fn unregister(&self, camera: CameraId, stream: StreamId) {
        self.targets.lock().await.remove(&(camera, stream));
    }
}

#[async_trait]
impl CameraTargetRegistry for GuardedCameraTargetRegistry {
    async fn authorized_binding(
        &self,
        camera: CameraId,
        stream: StreamId,
    ) -> Result<ApprovedRtspTarget, CameraSessionError> {
        let (interface, target, port) = self
            .targets
            .lock()
            .await
            .get(&(camera, stream))
            .copied()
            .ok_or(CameraSessionError::Unavailable)?;
        let binding = self
            .guard
            .authorized_binding(interface, target)
            .map_err(|_| CameraSessionError::Unavailable)?;
        ApprovedRtspTarget::new(binding, port)
    }
}

struct ManagedSession {
    camera: CameraId,
    stream: StreamId,
    created: Instant,
    last_access: Instant,
    output_dir: PathBuf,
    process: Box<dyn MediaProcess>,
    proxy: LoopbackRtspProxy,
    _permit: OwnedSemaphorePermit,
}

struct CleanupResources {
    process: Option<Box<dyn MediaProcess>>,
    proxy: Option<LoopbackRtspProxy>,
    output_dir: Option<PathBuf>,
    _permit: OwnedSemaphorePermit,
}

impl CleanupResources {
    fn from_session(value: ManagedSession) -> Self {
        let _ = (value.camera, value.stream);
        Self {
            process: Some(value.process),
            proxy: Some(value.proxy),
            output_dir: Some(value.output_dir),
            _permit: value._permit,
        }
    }

    fn transient(
        process: Option<Box<dyn MediaProcess>>,
        proxy: Option<LoopbackRtspProxy>,
        output_dir: PathBuf,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            process,
            proxy,
            output_dir: Some(output_dir),
            _permit: permit,
        }
    }
}

struct PendingCleanup {
    resources: CleanupResources,
    attempts: u32,
    next_retry: Instant,
}

pub struct CameraSessionManager {
    repository: CameraRepository,
    vault: Arc<dyn Vault>,
    registry: Arc<dyn CameraTargetRegistry>,
    process_factory: Arc<dyn MediaProcessFactory>,
    connector: Arc<dyn AuthorizedRtspConnector>,
    output_root: PathBuf,
    config: CameraSessionConfig,
    capacity: Arc<Semaphore>,
    sessions: Mutex<HashMap<HlsSessionId, ManagedSession>>,
    pending_cleanup: Mutex<HashMap<HlsSessionId, PendingCleanup>>,
    lifecycle: RwLock<()>,
    accepting: AtomicBool,
    reaper_started: AtomicBool,
}

impl fmt::Debug for CameraSessionManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CameraSessionManager")
    }
}

impl CameraSessionManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: CameraRepository,
        vault: Arc<dyn Vault>,
        registry: Arc<dyn CameraTargetRegistry>,
        process_factory: Arc<dyn MediaProcessFactory>,
        connector: Arc<dyn AuthorizedRtspConnector>,
        output_root: PathBuf,
        config: CameraSessionConfig,
    ) -> Result<Self, CameraSessionError> {
        let config = config.validate()?;
        if !output_root.is_absolute() {
            return Err(CameraSessionError::Invalid);
        }
        let metadata =
            std::fs::symlink_metadata(&output_root).map_err(|_| CameraSessionError::Invalid)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CameraSessionError::Invalid);
        }
        let output_root =
            std::fs::canonicalize(output_root).map_err(|_| CameraSessionError::Invalid)?;
        Ok(Self {
            repository,
            vault,
            registry,
            process_factory,
            connector,
            output_root,
            config,
            capacity: Arc::new(Semaphore::new(config.max_sessions)),
            sessions: Mutex::new(HashMap::new()),
            pending_cleanup: Mutex::new(HashMap::new()),
            lifecycle: RwLock::new(()),
            accepting: AtomicBool::new(true),
            reaper_started: AtomicBool::new(false),
        })
    }

    pub(crate) fn start_background_reaper(self: &Arc<Self>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.reaper_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let interval = self
            .config
            .idle_timeout
            .min(self.config.total_timeout)
            .div_f64(2.0)
            .clamp(Duration::from_millis(10), Duration::from_secs(1));
        let manager: Weak<Self> = Arc::downgrade(self);
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let Some(manager) = manager.upgrade() else {
                    break;
                };
                manager.reap(true).await;
            }
        });
    }

    pub async fn start_session(
        &self,
        camera: CameraId,
        stream: StreamId,
    ) -> Result<HlsSession, CameraSessionError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(CameraSessionError::Unavailable);
        }
        self.reap(true).await;
        self.exact_profile(camera, stream).await?;
        let (source, binding) = self.resolve_source(camera, stream).await?;
        let _operation = self.lifecycle.read().await;
        if !self.accepting.load(Ordering::Acquire) {
            return Err(CameraSessionError::Unavailable);
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| CameraSessionError::Capacity)?;
        let session = HlsSessionId::new();
        let created_at = Utc::now();
        let expires_at = created_at
            + ChronoDuration::from_std(self.config.total_timeout)
                .map_err(|_| CameraSessionError::Invalid)?;
        let contract = HlsSession::new(session.clone(), camera, stream, created_at, expires_at)
            .map_err(|_| CameraSessionError::Invalid)?;
        let token = LoopbackSourceToken::new();
        let output_dir = match self
            .create_output_dir("session", &session.to_string())
            .await
        {
            Ok(output_dir) => output_dir,
            Err(Some(output_dir)) => {
                let _ = self
                    .cleanup_or_retain(
                        session,
                        CleanupResources::transient(None, None, output_dir, permit),
                        0,
                    )
                    .await;
                return Err(CameraSessionError::Unavailable);
            }
            Err(None) => return Err(CameraSessionError::Unavailable),
        };
        let proxy_limits = RtspProxyLimits {
            lease_ttl: self.config.total_timeout,
            ..RtspProxyLimits::default()
        };
        let proxy = match LoopbackRtspProxy::start(
            session.clone(),
            token.clone(),
            source,
            binding,
            self.connector.clone(),
            proxy_limits,
        )
        .await
        {
            Ok(proxy) => proxy,
            Err(_) => {
                let _ = self
                    .cleanup_or_retain(
                        session.clone(),
                        CleanupResources::transient(None, None, output_dir, permit),
                        0,
                    )
                    .await;
                return Err(CameraSessionError::Unavailable);
            }
        };
        let spec = match MediaProcessSpec::hls(proxy.local_addr().port(), &token, &output_dir) {
            Ok(spec) => spec,
            Err(_) => {
                let _ = self
                    .cleanup_or_retain(
                        session.clone(),
                        CleanupResources::transient(None, Some(proxy), output_dir, permit),
                        0,
                    )
                    .await;
                return Err(CameraSessionError::Unavailable);
            }
        };
        let process = match timeout(
            self.config.process_start_timeout,
            self.process_factory.spawn(spec),
        )
        .await
        {
            Ok(Ok(process)) => process,
            Ok(Err(_)) | Err(_) => {
                let _ = self
                    .cleanup_or_retain(
                        session.clone(),
                        CleanupResources::transient(None, Some(proxy), output_dir, permit),
                        0,
                    )
                    .await;
                return Err(CameraSessionError::Unavailable);
            }
        };
        let now = Instant::now();
        let value = ManagedSession {
            camera,
            stream,
            created: now,
            last_access: now,
            output_dir,
            process,
            proxy,
            _permit: permit,
        };
        let value = {
            let mut sessions = self.sessions.lock().await;
            if self.accepting.load(Ordering::Acquire) {
                sessions.insert(session.clone(), value);
                None
            } else {
                Some(value)
            }
        };
        if let Some(value) = value {
            let _ = self
                .cleanup_or_retain(session.clone(), CleanupResources::from_session(value), 0)
                .await;
            return Err(CameraSessionError::Unavailable);
        }
        Ok(contract)
    }

    pub async fn playlist(&self, session: &HlsSessionId) -> Result<Vec<u8>, CameraSessionError> {
        self.read_session_file(session, "playlist.m3u8", self.config.max_playlist_bytes)
            .await
    }

    pub async fn segment(
        &self,
        session: &HlsSessionId,
        name: &str,
    ) -> Result<Vec<u8>, CameraSessionError> {
        if !valid_segment_name(name) {
            return Err(CameraSessionError::Invalid);
        }
        self.read_session_file(session, name, self.config.max_segment_bytes)
            .await
    }

    pub async fn close_session(&self, session: &HlsSessionId) -> Result<(), CameraSessionError> {
        let active = { self.sessions.lock().await.remove(session) };
        if let Some(value) = active {
            return self
                .cleanup_or_retain(session.clone(), CleanupResources::from_session(value), 0)
                .await;
        }
        let pending = { self.pending_cleanup.lock().await.remove(session) };
        if let Some(value) = pending {
            return self
                .cleanup_or_retain(session.clone(), value.resources, value.attempts)
                .await;
        }
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<(), CameraSessionError> {
        self.accepting.store(false, Ordering::Release);
        let _exclusive = self.lifecycle.write().await;
        let sessions = {
            let mut current = self.sessions.lock().await;
            current.drain().collect::<Vec<_>>()
        };
        for (session, value) in sessions {
            let _ = self
                .cleanup_or_retain(session, CleanupResources::from_session(value), 0)
                .await;
        }
        let _ = self.retry_pending(true).await;
        if !self.pending_cleanup.lock().await.is_empty()
            || self.capacity.available_permits() != self.config.max_sessions
        {
            Err(CameraSessionError::Unavailable)
        } else {
            Ok(())
        }
    }

    pub async fn snapshot(
        &self,
        camera: CameraId,
        stream: Option<StreamId>,
    ) -> Result<Vec<u8>, CameraSessionError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(CameraSessionError::Unavailable);
        }
        self.reap(true).await;
        let stream = match stream {
            Some(stream) => {
                self.exact_profile(camera, stream).await?;
                stream
            }
            None => self
                .repository
                .load_stream_refs(camera)
                .await
                .map_err(|_| CameraSessionError::Unavailable)?
                .first()
                .map(|profile| profile.stream_id())
                .ok_or(CameraSessionError::NotFound)?,
        };
        let (source, binding) = self.resolve_source(camera, stream).await?;
        let _operation = self.lifecycle.read().await;
        if !self.accepting.load(Ordering::Acquire) {
            return Err(CameraSessionError::Unavailable);
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| CameraSessionError::Capacity)?;
        let owner = HlsSessionId::new();
        let token = LoopbackSourceToken::new();
        let output_dir = match self.create_output_dir("snapshot", &owner.to_string()).await {
            Ok(output_dir) => output_dir,
            Err(Some(output_dir)) => {
                let _ = self
                    .cleanup_or_retain(
                        owner,
                        CleanupResources::transient(None, None, output_dir, permit),
                        0,
                    )
                    .await;
                return Err(CameraSessionError::Unavailable);
            }
            Err(None) => return Err(CameraSessionError::Unavailable),
        };
        let proxy_limits = RtspProxyLimits {
            lease_ttl: self.config.snapshot_timeout,
            ..RtspProxyLimits::default()
        };
        let proxy = match LoopbackRtspProxy::start(
            owner.clone(),
            token.clone(),
            source,
            binding,
            self.connector.clone(),
            proxy_limits,
        )
        .await
        {
            Ok(proxy) => proxy,
            Err(_) => {
                let _ = self
                    .cleanup_or_retain(
                        owner.clone(),
                        CleanupResources::transient(None, None, output_dir, permit),
                        0,
                    )
                    .await;
                return Err(CameraSessionError::Unavailable);
            }
        };
        let spec = match MediaProcessSpec::snapshot(proxy.local_addr().port(), &token, &output_dir)
        {
            Ok(spec) => spec,
            Err(_) => {
                let _ = self
                    .cleanup_or_retain(
                        owner.clone(),
                        CleanupResources::transient(None, Some(proxy), output_dir, permit),
                        0,
                    )
                    .await;
                return Err(CameraSessionError::Unavailable);
            }
        };
        let mut process = match timeout(
            self.config.process_start_timeout,
            self.process_factory.spawn(spec),
        )
        .await
        {
            Ok(Ok(process)) => process,
            Ok(Err(_)) | Err(_) => {
                let _ = self
                    .cleanup_or_retain(
                        owner.clone(),
                        CleanupResources::transient(None, Some(proxy), output_dir, permit),
                        0,
                    )
                    .await;
                return Err(CameraSessionError::Unavailable);
            }
        };
        let result = match timeout(self.config.snapshot_timeout, process.wait()).await {
            Ok(Ok(exit)) if exit.success => {
                let bytes =
                    read_bounded_file(&output_dir, "snapshot.jpg", self.config.max_snapshot_bytes)
                        .await;
                match bytes {
                    Ok(bytes)
                        if bytes.starts_with(&[0xff, 0xd8]) && bytes.ends_with(&[0xff, 0xd9]) =>
                    {
                        Ok(bytes)
                    }
                    Ok(_) => Err(CameraSessionError::Unavailable),
                    Err(error) => Err(error),
                }
            }
            Ok(Ok(_)) | Ok(Err(_)) | Err(_) => Err(CameraSessionError::Unavailable),
        };
        if self
            .cleanup_or_retain(
                owner,
                CleanupResources::transient(Some(process), Some(proxy), output_dir, permit),
                0,
            )
            .await
            .is_err()
        {
            Err(CameraSessionError::Unavailable)
        } else {
            result
        }
    }

    pub async fn active_count(&self) -> usize {
        self.reap(true).await;
        self.sessions.lock().await.len()
    }

    #[doc(hidden)]
    pub async fn pending_cleanup_count(&self) -> usize {
        self.pending_cleanup.lock().await.len()
    }

    #[doc(hidden)]
    pub async fn session_output_path(&self, session: &str) -> Option<PathBuf> {
        let session = HlsSessionId::from_canonical(session).ok()?;
        self.sessions
            .lock()
            .await
            .get(&session)
            .map(|value| value.output_dir.clone())
    }

    #[doc(hidden)]
    pub async fn output_entries(&self) -> Result<Vec<PathBuf>, CameraSessionError> {
        let mut reader = tokio::fs::read_dir(&self.output_root)
            .await
            .map_err(|_| CameraSessionError::Unavailable)?;
        let mut entries = Vec::new();
        while let Some(entry) = reader
            .next_entry()
            .await
            .map_err(|_| CameraSessionError::Unavailable)?
        {
            entries.push(entry.path());
        }
        Ok(entries)
    }

    async fn exact_profile(
        &self,
        camera: CameraId,
        stream: StreamId,
    ) -> Result<(), CameraSessionError> {
        if self
            .repository
            .load_camera(camera)
            .await
            .map_err(|_| CameraSessionError::Unavailable)?
            .is_none()
        {
            return Err(CameraSessionError::NotFound);
        }
        if self
            .repository
            .load_stream_ref(camera, stream)
            .await
            .map_err(|_| CameraSessionError::Unavailable)?
            .is_none()
        {
            return Err(CameraSessionError::NotFound);
        }
        Ok(())
    }

    async fn resolve_source(
        &self,
        camera: CameraId,
        stream: StreamId,
    ) -> Result<(SecretString, ApprovedRtspTarget), CameraSessionError> {
        let profile = self
            .repository
            .load_stream_ref(camera, stream)
            .await
            .map_err(|_| CameraSessionError::Unavailable)?
            .ok_or(CameraSessionError::NotFound)?;
        let source = self
            .vault
            .get_stream_source(camera, stream, profile.source_ref())
            .await
            .map_err(|_| CameraSessionError::Unavailable)?;
        let target = self.registry.authorized_binding(camera, stream).await?;
        Ok((source, target))
    }

    async fn create_output_dir(
        &self,
        prefix: &str,
        opaque: &str,
    ) -> Result<PathBuf, Option<PathBuf>> {
        let output = self.output_root.join(format!("{prefix}-{opaque}"));
        tokio::fs::create_dir(&output).await.map_err(|_| None)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|_| Some(output.clone()))?;
        }
        let canonical = tokio::fs::canonicalize(&output)
            .await
            .map_err(|_| Some(output.clone()))?;
        if canonical.parent() != Some(self.output_root.as_path()) {
            return Err(Some(output));
        }
        Ok(canonical)
    }

    async fn read_session_file(
        &self,
        session: &HlsSessionId,
        name: &str,
        limit: usize,
    ) -> Result<Vec<u8>, CameraSessionError> {
        self.reap(false).await;
        let (output, crashed) = {
            let mut sessions = self.sessions.lock().await;
            let value = sessions
                .get_mut(session)
                .ok_or(CameraSessionError::NotFound)?;
            let crashed = match value.process.try_wait() {
                Ok(Some(_)) | Err(_) => true,
                Ok(None) => false,
            };
            if !crashed {
                value.last_access = Instant::now();
            }
            (value.output_dir.clone(), crashed)
        };
        if crashed {
            let crashed = { self.sessions.lock().await.remove(session) };
            if let Some(value) = crashed {
                let _ = self
                    .cleanup_or_retain(session.clone(), CleanupResources::from_session(value), 0)
                    .await;
            }
            return Err(CameraSessionError::Unavailable);
        }
        read_bounded_file(&output, name, limit).await
    }

    async fn reap(&self, include_crashed: bool) {
        let _ = self.retry_pending(false).await;
        let now = Instant::now();
        let expired = {
            let mut sessions = self.sessions.lock().await;
            let ids: Vec<_> = sessions
                .iter_mut()
                .filter_map(|(id, value)| {
                    let timed_out = now.duration_since(value.last_access)
                        >= self.config.idle_timeout
                        || now.duration_since(value.created) >= self.config.total_timeout;
                    let crashed = include_crashed
                        && !timed_out
                        && matches!(value.process.try_wait(), Ok(Some(_)) | Err(_));
                    (timed_out || crashed).then_some(id.clone())
                })
                .collect();
            ids.into_iter()
                .filter_map(|id| sessions.remove(&id).map(|value| (id, value)))
                .collect::<Vec<_>>()
        };
        for (session, value) in expired {
            let _ = self
                .cleanup_or_retain(session, CleanupResources::from_session(value), 0)
                .await;
        }
    }

    async fn cleanup_or_retain(
        &self,
        owner: HlsSessionId,
        mut resources: CleanupResources,
        previous_attempts: u32,
    ) -> Result<(), CameraSessionError> {
        if self.cleanup_attempt(&mut resources).await.is_ok() {
            return Ok(());
        }
        let attempts = previous_attempts.saturating_add(1);
        let next_retry = Instant::now() + cleanup_retry_delay(attempts);
        let mut pending = self.pending_cleanup.lock().await;
        debug_assert!(pending.len() < self.config.max_sessions || pending.contains_key(&owner));
        pending.insert(
            owner,
            PendingCleanup {
                resources,
                attempts,
                next_retry,
            },
        );
        Err(CameraSessionError::Unavailable)
    }

    async fn retry_pending(&self, force: bool) -> Result<(), CameraSessionError> {
        let due = {
            let now = Instant::now();
            let mut pending = self.pending_cleanup.lock().await;
            let owners = pending
                .iter()
                .filter_map(|(owner, value)| {
                    (force || value.next_retry <= now).then_some(owner.clone())
                })
                .collect::<Vec<_>>();
            owners
                .into_iter()
                .filter_map(|owner| pending.remove(&owner).map(|value| (owner, value)))
                .collect::<Vec<_>>()
        };
        let mut failed = false;
        for (owner, value) in due {
            failed |= self
                .cleanup_or_retain(owner, value.resources, value.attempts)
                .await
                .is_err();
        }
        if failed {
            Err(CameraSessionError::Unavailable)
        } else {
            Ok(())
        }
    }

    async fn cleanup_attempt(
        &self,
        resources: &mut CleanupResources,
    ) -> Result<(), CameraSessionError> {
        let mut failed = false;
        if let Some(process) = resources.process.as_mut() {
            match timeout(CLEANUP_COMPONENT_TIMEOUT, process.close()).await {
                Ok(Ok(())) => resources.process = None,
                Ok(Err(_)) | Err(_) => failed = true,
            }
        }
        if let Some(proxy) = resources.proxy.as_ref() {
            match timeout(CLEANUP_COMPONENT_TIMEOUT, proxy.shutdown(&proxy.owner)).await {
                Ok(Ok(())) => resources.proxy = None,
                Ok(Err(_)) | Err(_) => failed = true,
            }
        }
        if let Some(output_dir) = resources.output_dir.as_ref() {
            match timeout(CLEANUP_COMPONENT_TIMEOUT, remove_output_dir(output_dir)).await {
                Ok(Ok(())) => resources.output_dir = None,
                Ok(Err(_)) | Err(_) => failed = true,
            }
        }
        if failed {
            Err(CameraSessionError::Unavailable)
        } else {
            Ok(())
        }
    }
}

fn cleanup_retry_delay(attempts: u32) -> Duration {
    let multiplier = 1_u32 << attempts.saturating_sub(1).min(5);
    CLEANUP_RETRY_BASE
        .saturating_mul(multiplier)
        .min(CLEANUP_RETRY_MAX)
}

async fn remove_output_dir(path: &Path) -> Result<(), CameraSessionError> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CameraSessionError::Unavailable),
    }
}

fn valid_segment_name(value: &str) -> bool {
    let value = value.as_bytes();
    value.len() == b"segment-000000.ts".len()
        && value.get(..8) == Some(b"segment-")
        && value.get(14..) == Some(b".ts")
        && value[8..14].iter().all(u8::is_ascii_digit)
}

async fn read_bounded_file(
    directory: &Path,
    name: &str,
    limit: usize,
) -> Result<Vec<u8>, CameraSessionError> {
    if name.contains('/') || name.contains('\\') || matches!(name, "." | "..") {
        return Err(CameraSessionError::Invalid);
    }
    let file = open_session_file(directory.to_path_buf(), name.to_owned()).await?;
    let file = tokio::fs::File::from_std(file);
    let metadata = file
        .metadata()
        .await
        .map_err(|_| CameraSessionError::Unavailable)?;
    if metadata.len() > limit as u64 {
        return Err(CameraSessionError::PayloadTooLarge);
    }
    let mut output = Vec::with_capacity(metadata.len() as usize);
    file.take((limit as u64) + 1)
        .read_to_end(&mut output)
        .await
        .map_err(|_| CameraSessionError::Unavailable)?;
    if output.len() > limit {
        Err(CameraSessionError::PayloadTooLarge)
    } else {
        Ok(output)
    }
}

async fn open_session_file(
    directory: PathBuf,
    name: String,
) -> Result<std::fs::File, CameraSessionError> {
    tokio::task::spawn_blocking(move || open_session_file_sync(&directory, &name))
        .await
        .map_err(|_| CameraSessionError::Unavailable)?
        .map_err(|_| CameraSessionError::NotFound)
}

#[cfg(target_os = "linux")]
fn open_session_file_sync(directory: &Path, name: &str) -> io::Result<std::fs::File> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::OpenOptionsExt,
        },
    };

    let directory_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(directory)?;
    #[cfg(test)]
    run_file_open_hook(directory);
    let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let descriptor = unsafe {
        libc::openat(
            directory_file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    if !file.metadata()?.is_file() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(file)
}

#[cfg(windows)]
fn open_session_file_sync(directory: &Path, name: &str) -> io::Result<std::fs::File> {
    use std::os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };

    let shared = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let directory_file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(shared)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory)?;
    let directory_metadata = directory_file.metadata()?;
    if !directory_metadata.is_dir()
        || directory_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    #[cfg(test)]
    run_file_open_hook(directory);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(shared)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory.join(name))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let directory_path = windows_final_path(
        directory_file.as_raw_handle(),
        GetFinalPathNameByHandleW,
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
    )?;
    let file_path = windows_final_path(
        file.as_raw_handle(),
        GetFinalPathNameByHandleW,
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
    )?;
    if !windows_paths_equal(file_path.parent(), Some(directory_path.as_path())) {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(file)
}

#[cfg(windows)]
fn windows_final_path(
    handle: std::os::windows::io::RawHandle,
    get_path: unsafe extern "system" fn(*mut std::ffi::c_void, *mut u16, u32, u32) -> u32,
    flags: u32,
) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let handle = handle.cast();
    let required = unsafe { get_path(handle, std::ptr::null_mut(), 0, flags) };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut value = vec![0_u16; required as usize + 1];
    let written = unsafe { get_path(handle, value.as_mut_ptr(), value.len() as u32, flags) };
    if written == 0 || written as usize >= value.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &value[..written as usize],
    )))
}

#[cfg(windows)]
fn windows_paths_equal(left: Option<&Path>, right: Option<&Path>) -> bool {
    let Some((left, right)) = left.zip(right) else {
        return false;
    };
    let normalize = |path: &Path| {
        path.components()
            .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
            .collect::<Vec<_>>()
    };
    normalize(left) == normalize(right)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn open_session_file_sync(_: &Path, _: &str) -> io::Result<std::fs::File> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(test)]
struct FileOpenHook {
    directory: PathBuf,
    action: Option<Box<dyn FnOnce() + Send>>,
}

#[cfg(test)]
static FILE_OPEN_HOOK: std::sync::Mutex<Option<FileOpenHook>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn run_file_open_hook(directory: &Path) {
    let action = {
        let mut hook = FILE_OPEN_HOOK.lock().expect("file hook lock");
        hook.as_mut()
            .filter(|hook| hook.directory == directory)
            .and_then(|hook| hook.action.take())
    };
    if let Some(action) = action {
        action();
    }
}

#[cfg(all(test, unix))]
mod safe_file_tests {
    use super::*;

    #[tokio::test]
    async fn directory_swap_never_serves_a_file_outside_the_pinned_session_directory() {
        let root = tempfile::tempdir().unwrap();
        let session = root.path().join("session");
        let held = root.path().join("held-session");
        let outside = root.path().join("outside");
        std::fs::create_dir(&session).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(session.join("segment-000001.ts"), b"inside").unwrap();
        std::fs::write(outside.join("segment-000001.ts"), b"outside-secret").unwrap();
        *FILE_OPEN_HOOK.lock().unwrap() = Some(FileOpenHook {
            directory: session.clone(),
            action: Some(Box::new({
                let session = session.clone();
                let held = held.clone();
                let outside = outside.clone();
                move || {
                    std::fs::rename(&session, &held).unwrap();
                    std::os::unix::fs::symlink(&outside, &session).unwrap();
                }
            })),
        });

        let result = read_bounded_file(&session, "segment-000001.ts", 1024).await;
        assert!(
            matches!(result.as_deref(), Ok(b"inside")) || result.is_err(),
            "outside bytes were served after an ancestor directory swap"
        );
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotQuery {
    stream_id: Option<String>,
}

#[utoipa::path(post, path = "/api/v1/cameras/{id}/sessions", request_body = crate::api::CameraSessionRequest, responses((status = 201, body = crate::api::CameraSessionResponse), (status = 400), (status = 401), (status = 404), (status = 429), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn start_session_route(
    _: Authorized,
    State(state): State<AppState>,
    path: Result<AxumPath<String>, axum::extract::rejection::PathRejection>,
    body: Result<Json<crate::api::CameraSessionRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Some(manager) = state.camera_sessions() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (Ok(AxumPath(camera)), Ok(Json(body))) = (path, body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Ok(camera), Ok(stream)) = (parse_camera_id(&camera), parse_stream_id(&body.stream_id))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match manager.start_session(camera, stream).await {
        Ok(session) => (
            StatusCode::CREATED,
            Json(crate::api::CameraSessionResponse {
                session_id: session.id().to_string(),
            }),
        )
            .into_response(),
        Err(error) => status(error).into_response(),
    }
}

#[utoipa::path(get, path = "/api/v1/camera-sessions/{id}/playlist.m3u8", responses((status = 200, content_type = "application/vnd.apple.mpegurl", body = String), (status = 400), (status = 401), (status = 404), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn playlist_route(
    _: Authorized,
    State(state): State<AppState>,
    path: Result<AxumPath<String>, axum::extract::rejection::PathRejection>,
) -> Response {
    file_route(state, path, None).await
}

#[utoipa::path(get, path = "/api/v1/camera-sessions/{id}/segments/{segment}", responses((status = 200, content_type = "video/mp2t", body = crate::api::BinaryMedia), (status = 400), (status = 401), (status = 404), (status = 413), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn segment_route(
    _: Authorized,
    State(state): State<AppState>,
    path: Result<AxumPath<(String, String)>, axum::extract::rejection::PathRejection>,
) -> Response {
    let Some(manager) = state.camera_sessions() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(AxumPath((session, segment))) = path else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(session) = HlsSessionId::from_canonical(&session) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match manager.segment(&session, &segment).await {
        Ok(bytes) => media_response(bytes, "video/mp2t"),
        Err(error) => status(error).into_response(),
    }
}

async fn file_route(
    state: AppState,
    path: Result<AxumPath<String>, axum::extract::rejection::PathRejection>,
    _unused: Option<()>,
) -> Response {
    let Some(manager) = state.camera_sessions() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(AxumPath(session)) = path else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(session) = HlsSessionId::from_canonical(&session) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match manager.playlist(&session).await {
        Ok(bytes) => media_response(bytes, "application/vnd.apple.mpegurl"),
        Err(error) => status(error).into_response(),
    }
}

#[utoipa::path(delete, path = "/api/v1/camera-sessions/{id}", responses((status = 204), (status = 400), (status = 401), (status = 404), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn close_session_route(
    _: Authorized,
    State(state): State<AppState>,
    path: Result<AxumPath<String>, axum::extract::rejection::PathRejection>,
) -> Response {
    let Some(manager) = state.camera_sessions() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(AxumPath(session)) = path else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(session) = HlsSessionId::from_canonical(&session) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match manager.close_session(&session).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => status(error).into_response(),
    }
}

#[utoipa::path(get, path = "/api/v1/cameras/{id}/snapshot", params(("stream_id" = Option<String>, Query, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")), responses((status = 200, content_type = "image/jpeg", body = crate::api::BinaryMedia), (status = 400), (status = 401), (status = 404), (status = 413), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn snapshot_route(
    _: Authorized,
    State(state): State<AppState>,
    path: Result<AxumPath<String>, axum::extract::rejection::PathRejection>,
    query: Result<Query<SnapshotQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Some(manager) = state.camera_sessions() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (Ok(AxumPath(camera)), Ok(Query(query))) = (path, query) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(camera) = parse_camera_id(&camera) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let stream = match query.stream_id.as_deref().map(parse_stream_id).transpose() {
        Ok(stream) => stream,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    match manager.snapshot(camera, stream).await {
        Ok(bytes) => media_response(bytes, "image/jpeg"),
        Err(error) => status(error).into_response(),
    }
}

fn media_response(bytes: Vec<u8>, content_type: &'static str) -> Response {
    let mut response = Body::from(bytes).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn status(error: CameraSessionError) -> StatusCode {
    match error {
        CameraSessionError::Invalid => StatusCode::BAD_REQUEST,
        CameraSessionError::NotFound => StatusCode::NOT_FOUND,
        CameraSessionError::Capacity => StatusCode::TOO_MANY_REQUESTS,
        CameraSessionError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        CameraSessionError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn parse_camera_id(value: &str) -> Result<CameraId, CameraSessionError> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| CameraSessionError::Invalid)?;
    if uuid.hyphenated().to_string() == value {
        Ok(CameraId::from_uuid(uuid))
    } else {
        Err(CameraSessionError::Invalid)
    }
}

fn parse_stream_id(value: &str) -> Result<StreamId, CameraSessionError> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| CameraSessionError::Invalid)?;
    if uuid.hyphenated().to_string() == value {
        Ok(StreamId::from_uuid(uuid))
    } else {
        Err(CameraSessionError::Invalid)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RtspProxyLimits {
    pub max_connections: usize,
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_interleaved_frame_bytes: usize,
    pub io_timeout: Duration,
    pub lease_ttl: Duration,
}

impl Default for RtspProxyLimits {
    fn default() -> Self {
        Self {
            max_connections: 2,
            max_header_bytes: 16 * 1024,
            max_body_bytes: 64 * 1024,
            max_interleaved_frame_bytes: 1024 * 1024,
            io_timeout: Duration::from_secs(5),
            lease_ttl: Duration::from_secs(60),
        }
    }
}

impl RtspProxyLimits {
    fn validate(self) -> Result<Self, RtspProxyError> {
        if !(1..=8).contains(&self.max_connections)
            || !(256..=64 * 1024).contains(&self.max_header_bytes)
            || !(1..=1024 * 1024).contains(&self.max_body_bytes)
            || !(1..=4 * 1024 * 1024).contains(&self.max_interleaved_frame_bytes)
            || self.io_timeout.is_zero()
            || self.io_timeout > Duration::from_secs(30)
            || self.lease_ttl.is_zero()
            || self.lease_ttl > Duration::from_secs(10 * 60)
        {
            Err(RtspProxyError::InvalidLimits)
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RtspProxyError {
    #[error("invalid RTSP proxy limits")]
    InvalidLimits,
    #[error("invalid RTSP source")]
    InvalidSource,
    #[error("RTSP source does not match the approved target")]
    TargetMismatch,
    #[error("RTSP proxy owner mismatch")]
    WrongOwner,
    #[error("RTSP proxy unavailable")]
    Unavailable,
    #[error("RTSP proxy protocol rejected")]
    Protocol,
    #[error("RTSP proxy limit exceeded")]
    Limit,
    #[error("RTSP proxy timed out")]
    Timeout,
}

pub trait RtspConnection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RtspConnection for T {}

#[async_trait]
pub trait AuthorizedRtspConnector: Send + Sync {
    async fn connect(
        &self,
        binding: AuthorizedBinding,
        port: u16,
    ) -> Result<Box<dyn RtspConnection>, RtspProxyError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAuthorizedRtspConnector;

#[async_trait]
impl AuthorizedRtspConnector for SystemAuthorizedRtspConnector {
    async fn connect(
        &self,
        binding: AuthorizedBinding,
        port: u16,
    ) -> Result<Box<dyn RtspConnection>, RtspProxyError> {
        let socket = match binding.target {
            IpAddr::V4(_) => TcpSocket::new_v4(),
            IpAddr::V6(_) => TcpSocket::new_v6(),
        }
        .map_err(|_| RtspProxyError::Unavailable)?;
        socket
            .bind(binding.source_socket())
            .map_err(|_| RtspProxyError::Unavailable)?;
        if socket
            .local_addr()
            .map_err(|_| RtspProxyError::Unavailable)?
            .ip()
            != binding.source
        {
            return Err(RtspProxyError::Unavailable);
        }
        pin_socket_to_interface(&socket, binding).map_err(|_| RtspProxyError::Unavailable)?;
        let stream = socket
            .connect(binding.target_socket(port))
            .await
            .map_err(|_| RtspProxyError::Unavailable)?;
        if stream
            .local_addr()
            .map_err(|_| RtspProxyError::Unavailable)?
            .ip()
            != binding.source
        {
            return Err(RtspProxyError::Unavailable);
        }
        Ok(Box::new(stream))
    }
}

pub struct LoopbackRtspProxy {
    owner: HlsSessionId,
    token: LoopbackSourceToken,
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    shutdown_timeout: Duration,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for LoopbackRtspProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoopbackRtspProxy([opaque])")
    }
}

impl LoopbackRtspProxy {
    pub async fn start(
        owner: HlsSessionId,
        token: LoopbackSourceToken,
        source: SecretString,
        approved: ApprovedRtspTarget,
        connector: Arc<dyn AuthorizedRtspConnector>,
        limits: RtspProxyLimits,
    ) -> Result<Self, RtspProxyError> {
        let limits = limits.validate()?;
        let upstream = Arc::new(Upstream::parse(source)?);
        if upstream.host != approved.binding.target || upstream.port != approved.port {
            return Err(RtspProxyError::TargetMismatch);
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| RtspProxyError::Unavailable)?;
        let local_addr = listener
            .local_addr()
            .map_err(|_| RtspProxyError::Unavailable)?;
        if local_addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(RtspProxyError::Unavailable);
        }
        let (shutdown, shutdown_rx) = watch::channel(false);
        let task_token = token.clone();
        let task = tokio::spawn(run_listener(
            listener,
            task_token,
            upstream,
            approved.binding,
            connector,
            limits,
            shutdown_rx,
        ));
        Ok(Self {
            owner,
            token,
            local_addr,
            shutdown,
            shutdown_timeout: limits.io_timeout,
            task: Mutex::new(Some(task)),
        })
    }

    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    #[must_use]
    pub fn endpoint(&self) -> String {
        format!(
            "rtsp://127.0.0.1:{}/source/{}",
            self.local_addr.port(),
            self.token
        )
    }

    pub async fn shutdown(&self, owner: &HlsSessionId) -> Result<(), RtspProxyError> {
        if owner != &self.owner {
            return Err(RtspProxyError::WrongOwner);
        }
        let _ = self.shutdown.send(true);
        let task = { self.task.lock().await.take() };
        if let Some(mut task) = task {
            match timeout(self.shutdown_timeout, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(RtspProxyError::Unavailable),
                Err(_) => {
                    task.abort();
                    return Err(RtspProxyError::Timeout);
                }
            }
        }
        Ok(())
    }
}

impl Drop for LoopbackRtspProxy {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Ok(mut task) = self.task.try_lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}

struct Upstream {
    host: IpAddr,
    port: u16,
    uri: SecretString,
    username: Option<String>,
    password: Option<SecretString>,
}

impl Upstream {
    fn parse(source: SecretString) -> Result<Self, RtspProxyError> {
        let exposed = source.expose_secret();
        if exposed.len() > 2048 || exposed.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(RtspProxyError::InvalidSource);
        }
        let mut url = Url::parse(exposed).map_err(|_| RtspProxyError::InvalidSource)?;
        if url.scheme() != "rtsp" || url.fragment().is_some() {
            return Err(RtspProxyError::InvalidSource);
        }
        let host = match url.host().ok_or(RtspProxyError::InvalidSource)? {
            Host::Ipv4(host) => IpAddr::V4(host),
            Host::Ipv6(host) => IpAddr::V6(host),
            // `rtsp` is a non-special URL scheme, so the URL crate represents
            // numeric IPv4 hosts as `Domain`; parse only numeric addresses and
            // continue rejecting DNS names.
            Host::Domain(host) => host
                .parse::<IpAddr>()
                .map_err(|_| RtspProxyError::InvalidSource)?,
        };
        let port = url.port().unwrap_or(554);
        if port == 0 || unsafe_path(url.path()) {
            return Err(RtspProxyError::InvalidSource);
        }
        let username = if url.username().is_empty() {
            None
        } else {
            Some(
                percent_decode_str(url.username())
                    .decode_utf8()
                    .map_err(|_| RtspProxyError::InvalidSource)?
                    .into_owned(),
            )
        };
        let password = url
            .password()
            .map(|value| {
                percent_decode_str(value)
                    .decode_utf8()
                    .map(|value| SecretString::from(value.into_owned()))
                    .map_err(|_| RtspProxyError::InvalidSource)
            })
            .transpose()?;
        if username.as_ref().is_some_and(|value| value.len() > 128)
            || password
                .as_ref()
                .is_some_and(|value| value.expose_secret().len() > 512)
        {
            return Err(RtspProxyError::InvalidSource);
        }
        url.set_username("")
            .map_err(|_| RtspProxyError::InvalidSource)?;
        url.set_password(None)
            .map_err(|_| RtspProxyError::InvalidSource)?;
        Ok(Self {
            host,
            port,
            uri: SecretString::from(url.to_string()),
            username,
            password,
        })
    }

    fn basic_header(&self) -> Option<Zeroizing<String>> {
        let username = self.username.as_ref()?;
        let password = self.password.as_ref()?;
        let credential = Zeroizing::new(format!("{username}:{}", password.expose_secret()));
        let encoded = Zeroizing::new(BASE64.encode(credential.as_bytes()));
        Some(Zeroizing::new(format!("Basic {}", encoded.as_str())))
    }
}

async fn run_listener(
    listener: TcpListener,
    token: LoopbackSourceToken,
    upstream: Arc<Upstream>,
    binding: AuthorizedBinding,
    connector: Arc<dyn AuthorizedRtspConnector>,
    limits: RtspProxyLimits,
    mut shutdown: watch::Receiver<bool>,
) {
    let expires = Instant::now() + limits.lease_ttl;
    let semaphore = Arc::new(Semaphore::new(limits.max_connections));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                match changed { Ok(()) | Err(_) => break }
            }
            _ = tokio::time::sleep_until(expires) => break,
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { break };
                if peer.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
                    continue;
                }
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    tokio::spawn(reject_connection(stream, 453, "Not Enough Bandwidth", limits.io_timeout));
                    continue;
                };
                let token = token.clone();
                let upstream = upstream.clone();
                let connector = connector.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let _ = serve_connection(stream, token, upstream, binding, connector, limits, expires).await;
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn reject_connection(mut stream: TcpStream, status: u16, reason: &str, limit: Duration) {
    let value = format!("RTSP/1.0 {status} {reason}\r\nContent-Length: 0\r\n\r\n");
    let _ = timeout(limit, stream.write_all(value.as_bytes())).await;
    let _ = stream.shutdown().await;
}

async fn serve_connection(
    client: TcpStream,
    token: LoopbackSourceToken,
    upstream: Arc<Upstream>,
    binding: AuthorizedBinding,
    connector: Arc<dyn AuthorizedRtspConnector>,
    limits: RtspProxyLimits,
    expires: Instant,
) -> Result<(), RtspProxyError> {
    let local_port = client
        .local_addr()
        .map_err(|_| RtspProxyError::Unavailable)?
        .port();
    let (mut client_read, mut client_write) = split(client);
    let mut upstream_io: Option<tokio::io::ReadHalf<Box<dyn RtspConnection>>> = None;
    let mut upstream_write: Option<tokio::io::WriteHalf<Box<dyn RtspConnection>>> = None;
    let mut digest_state = DigestState::default();
    loop {
        enum Incoming {
            Client(Option<u8>),
            Upstream(Option<u8>),
        }
        let incoming = if let Some(reader) = upstream_io.as_mut() {
            tokio::select! {
                value = read_byte(&mut client_read, limits.io_timeout, expires) => Incoming::Client(value?),
                value = read_byte(reader, limits.io_timeout, expires) => Incoming::Upstream(value?),
            }
        } else {
            Incoming::Client(read_byte(&mut client_read, limits.io_timeout, expires).await?)
        };
        let first = match incoming {
            Incoming::Client(first) => first,
            Incoming::Upstream(Some(b'$')) => {
                let reader = upstream_io.as_mut().ok_or(RtspProxyError::Unavailable)?;
                let frame = read_interleaved(reader, b'$', limits, expires).await?;
                write_all(&mut client_write, &frame, limits.io_timeout, expires).await?;
                continue;
            }
            Incoming::Upstream(Some(_)) => return Err(RtspProxyError::Protocol),
            Incoming::Upstream(None) => return Err(RtspProxyError::Unavailable),
        };
        let Some(first) = first else { return Ok(()) };
        if first == b'$' {
            let frame = read_interleaved(&mut client_read, first, limits, expires).await?;
            let writer = upstream_write.as_mut().ok_or(RtspProxyError::Protocol)?;
            write_all(writer, &frame, limits.io_timeout, expires).await?;
            continue;
        }
        let request = read_message(&mut client_read, first, limits, expires).await?;
        let validated = match ValidatedRequest::parse(request, &token, local_port) {
            Ok(request) => request,
            Err(RequestRejection::Forbidden) => {
                write_status(&mut client_write, 403, "Forbidden", limits, expires).await?;
                return Ok(());
            }
            Err(RequestRejection::Method) => {
                write_status(
                    &mut client_write,
                    405,
                    "Method Not Allowed",
                    limits,
                    expires,
                )
                .await?;
                return Ok(());
            }
            Err(RequestRejection::Invalid) => {
                write_status(&mut client_write, 400, "Bad Request", limits, expires).await?;
                return Ok(());
            }
        };
        if upstream_io.is_none() {
            let io = timeout_at(
                expires.min(Instant::now() + limits.io_timeout),
                connector.connect(binding, upstream.port),
            )
            .await
            .map_err(|_| RtspProxyError::Timeout)??;
            let (read, write) = split(io);
            upstream_io = Some(read);
            upstream_write = Some(write);
        }
        let upstream_uri = upstream_target(upstream.uri.expose_secret(), &validated.suffix)?;
        let basic = upstream.basic_header();
        let mut outbound = Zeroizing::new(
            validated.to_upstream(&upstream_uri, basic.as_ref().map(|value| value.as_str()))?,
        );
        let writer = upstream_write.as_mut().ok_or(RtspProxyError::Unavailable)?;
        write_all(writer, &outbound, limits.io_timeout, expires).await?;
        let reader = upstream_io.as_mut().ok_or(RtspProxyError::Unavailable)?;
        let mut response =
            read_upstream_response(reader, &mut client_write, limits, expires).await?;
        if response.status_code() == Some(401)
            && let Some(challenge) = response.header("www-authenticate")
            && challenge
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("digest ")
        {
            let digest = digest_state.header(
                challenge,
                &validated.method,
                &upstream_uri,
                upstream.username.as_deref(),
                upstream.password.as_ref(),
            )?;
            outbound = Zeroizing::new(validated.to_upstream(&upstream_uri, Some(&digest))?);
            write_all(writer, &outbound, limits.io_timeout, expires).await?;
            response = read_upstream_response(reader, &mut client_write, limits, expires).await?;
        }
        let local_endpoint = format!("rtsp://127.0.0.1:{local_port}/source/{token}");
        let sanitized = response.sanitize(
            upstream.uri.expose_secret(),
            &local_endpoint,
            limits.max_body_bytes,
        )?;
        write_all(&mut client_write, &sanitized, limits.io_timeout, expires).await?;

        // Drain a coalesced first frame promptly. Subsequent frames are handled by
        // the bidirectional select at the top of the loop.
        let reader = upstream_io.as_mut().ok_or(RtspProxyError::Unavailable)?;
        if let Ok(Ok(Some(first))) = timeout(Duration::from_millis(5), read_one(reader)).await {
            if first != b'$' {
                return Err(RtspProxyError::Protocol);
            }
            let frame = read_interleaved(reader, first, limits, expires).await?;
            write_all(&mut client_write, &frame, limits.io_timeout, expires).await?;
        }
    }
}

async fn read_upstream_response<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    client: &mut W,
    limits: RtspProxyLimits,
    expires: Instant,
) -> Result<RtspMessage, RtspProxyError> {
    loop {
        let first = read_byte(reader, limits.io_timeout, expires)
            .await?
            .ok_or(RtspProxyError::Protocol)?;
        if first == b'$' {
            let frame = read_interleaved(reader, first, limits, expires).await?;
            write_all(client, &frame, limits.io_timeout, expires).await?;
        } else {
            return read_message(reader, first, limits, expires).await;
        }
    }
}

#[derive(Clone)]
struct RtspMessage {
    start: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RtspMessage {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
    fn status_code(&self) -> Option<u16> {
        let mut values = self.start.split_ascii_whitespace();
        (values.next()? == "RTSP/1.0")
            .then(|| values.next()?.parse().ok())
            .flatten()
    }

    fn sanitize(
        &self,
        upstream: &str,
        local: &str,
        max_body: usize,
    ) -> Result<Vec<u8>, RtspProxyError> {
        if self.status_code().is_none() {
            return Err(RtspProxyError::Protocol);
        }
        let mut body = self.body.clone();
        if self
            .header("content-type")
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/sdp"))
        {
            body = rewrite_sdp(&body, upstream, local, max_body)?;
        }
        let mut output = Vec::new();
        push_line(&mut output, &self.start)?;
        for (name, value) in &self.headers {
            if [
                "content-length",
                "www-authenticate",
                "proxy-authenticate",
                "set-cookie",
            ]
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked))
            {
                continue;
            }
            if name.eq_ignore_ascii_case("content-base") || name.eq_ignore_ascii_case("location") {
                let suffix = if name.eq_ignore_ascii_case("content-base") {
                    "/"
                } else {
                    ""
                };
                push_header(&mut output, name, &format!("{local}{suffix}"))?;
            } else if name.eq_ignore_ascii_case("rtp-info") {
                let rewritten =
                    value.replace(upstream.trim_end_matches('/'), local.trim_end_matches('/'));
                if !all_rtsp_urls_are_local(&rewritten, local) {
                    return Err(RtspProxyError::Protocol);
                }
                push_header(&mut output, name, &rewritten)?;
            } else if name.eq_ignore_ascii_case("transport") {
                push_header(&mut output, name, &sanitize_transport(value)?)?;
            } else if [
                "cseq",
                "session",
                "content-type",
                "public",
                "allow",
                "range",
                "date",
            ]
            .iter()
            .any(|allowed| name.eq_ignore_ascii_case(allowed))
            {
                push_header(&mut output, name, value)?;
            }
        }
        push_header(&mut output, "Content-Length", &body.len().to_string())?;
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(&body);
        Ok(output)
    }
}

fn all_rtsp_urls_are_local(value: &str, local: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let local = local.trim_end_matches('/').to_ascii_lowercase();
    let mut remaining = value.as_str();
    while let Some(offset) = remaining.find("rtsp://") {
        let url = &remaining[offset..];
        let Some(tail) = url.strip_prefix(&local) else {
            return false;
        };
        if tail
            .as_bytes()
            .first()
            .is_some_and(|byte| !matches!(byte, b'/' | b';' | b',' | b' ' | b'\t'))
        {
            return false;
        }
        remaining = tail;
    }
    true
}

fn sanitize_transport(value: &str) -> Result<String, RtspProxyError> {
    let mut parts = value.split(';');
    let profile = parts.next().ok_or(RtspProxyError::Protocol)?.trim();
    if !profile.eq_ignore_ascii_case("RTP/AVP/TCP") {
        return Err(RtspProxyError::Protocol);
    }
    let mut output = profile.to_owned();
    for part in parts {
        let part = part.trim();
        let name = part.split_once('=').map_or(part, |(name, _)| name);
        if name.eq_ignore_ascii_case("source") || name.eq_ignore_ascii_case("destination") {
            continue;
        }
        if part.is_empty()
            || part
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b'\r' | b'\n'))
        {
            return Err(RtspProxyError::Protocol);
        }
        output.push(';');
        output.push_str(part);
    }
    Ok(output)
}

enum RequestRejection {
    Forbidden,
    Method,
    Invalid,
}

struct ValidatedRequest {
    method: String,
    suffix: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ValidatedRequest {
    fn parse(
        message: RtspMessage,
        token: &LoopbackSourceToken,
        local_port: u16,
    ) -> Result<Self, RequestRejection> {
        let mut start = message.start.split_ascii_whitespace();
        let method = start.next().ok_or(RequestRejection::Invalid)?;
        let target = start.next().ok_or(RequestRejection::Invalid)?;
        if start.next() != Some("RTSP/1.0") || start.next().is_some() {
            return Err(RequestRejection::Invalid);
        }
        if ![
            "OPTIONS",
            "DESCRIBE",
            "SETUP",
            "PLAY",
            "PAUSE",
            "TEARDOWN",
            "GET_PARAMETER",
            "SET_PARAMETER",
        ]
        .contains(&method)
        {
            return Err(RequestRejection::Method);
        }
        let url = Url::parse(target).map_err(|_| RequestRejection::Invalid)?;
        if url.scheme() != "rtsp"
            || url.host_str() != Some("127.0.0.1")
            || url.port_or_known_default() != Some(local_port)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(RequestRejection::Forbidden);
        }
        let base = format!("/source/{token}");
        let path = url.path();
        if !path.starts_with(&base) {
            return Err(RequestRejection::Forbidden);
        }
        let suffix = &path[base.len()..];
        if (!suffix.is_empty() && !suffix.starts_with('/')) || unsafe_path(path) {
            return Err(RequestRejection::Invalid);
        }
        let headers = validate_client_headers(method, message.headers)?;
        Ok(Self {
            method: method.to_owned(),
            suffix: suffix.to_owned(),
            headers,
            body: message.body,
        })
    }

    fn to_upstream(
        &self,
        target: &str,
        authorization: Option<&str>,
    ) -> Result<Vec<u8>, RtspProxyError> {
        let mut output = Vec::new();
        push_line(&mut output, &format!("{} {target} RTSP/1.0", self.method))?;
        for (name, value) in &self.headers {
            if [
                "authorization",
                "proxy-authorization",
                "host",
                "content-length",
                "cookie",
            ]
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked))
            {
                continue;
            }
            if [
                "cseq",
                "accept",
                "transport",
                "session",
                "range",
                "user-agent",
                "content-type",
            ]
            .iter()
            .any(|allowed| name.eq_ignore_ascii_case(allowed))
            {
                push_header(&mut output, name, value)?;
            }
        }
        if let Some(authorization) = authorization {
            push_header(&mut output, "Authorization", authorization)?;
        }
        push_header(&mut output, "Content-Length", &self.body.len().to_string())?;
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(&self.body);
        Ok(output)
    }
}

fn validate_client_headers(
    method: &str,
    mut headers: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, RequestRejection> {
    const FORWARDED: [&str; 7] = [
        "cseq",
        "accept",
        "transport",
        "session",
        "range",
        "user-agent",
        "content-type",
    ];
    for header in FORWARDED {
        if headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(header))
            .count()
            > 1
        {
            return Err(RequestRejection::Invalid);
        }
    }
    let cseq = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("cseq"))
        .map(|(_, value)| value.as_str())
        .ok_or(RequestRejection::Invalid)?;
    if cseq.is_empty()
        || !cseq.bytes().all(|byte| byte.is_ascii_digit())
        || cseq.parse::<u32>().is_err()
    {
        return Err(RequestRejection::Invalid);
    }

    let transport = headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case("transport"));
    match (method, transport) {
        ("SETUP", Some((_, value))) => {
            *value = sanitize_client_transport(value)?;
        }
        ("SETUP", None) | (_, Some(_)) => return Err(RequestRejection::Invalid),
        (_, None) => {}
    }
    Ok(headers)
}

fn sanitize_client_transport(value: &str) -> Result<String, RequestRejection> {
    let mut parts = value.split(';');
    let profile = parts.next().ok_or(RequestRejection::Invalid)?;
    if !profile.eq_ignore_ascii_case("RTP/AVP/TCP") {
        return Err(RequestRejection::Invalid);
    }
    let mut unicast = false;
    let mut channels = None;
    for part in parts {
        if part != part.trim() || part.is_empty() {
            return Err(RequestRejection::Invalid);
        }
        if part.eq_ignore_ascii_case("unicast") {
            if unicast {
                return Err(RequestRejection::Invalid);
            }
            unicast = true;
            continue;
        }
        let Some(value) = part.strip_prefix("interleaved=") else {
            return Err(RequestRejection::Invalid);
        };
        if channels.is_some() {
            return Err(RequestRejection::Invalid);
        }
        let (first, second) = value.split_once('-').ok_or(RequestRejection::Invalid)?;
        if first.is_empty()
            || second.is_empty()
            || (first.len() > 1 && first.starts_with('0'))
            || (second.len() > 1 && second.starts_with('0'))
            || !first.bytes().all(|byte| byte.is_ascii_digit())
            || !second.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(RequestRejection::Invalid);
        }
        let first = first.parse::<u8>().map_err(|_| RequestRejection::Invalid)?;
        let second = second
            .parse::<u8>()
            .map_err(|_| RequestRejection::Invalid)?;
        if first.checked_add(1) != Some(second) {
            return Err(RequestRejection::Invalid);
        }
        channels = Some((first, second));
    }
    let (first, second) = channels.ok_or(RequestRejection::Invalid)?;
    if !unicast {
        return Err(RequestRejection::Invalid);
    }
    Ok(format!("RTP/AVP/TCP;unicast;interleaved={first}-{second}"))
}

async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    first: u8,
    limits: RtspProxyLimits,
    expires: Instant,
) -> Result<RtspMessage, RtspProxyError> {
    let mut header = vec![first];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= limits.max_header_bytes {
            return Err(RtspProxyError::Limit);
        }
        let byte = read_byte(reader, limits.io_timeout, expires)
            .await?
            .ok_or(RtspProxyError::Protocol)?;
        header.push(byte);
    }
    let text = std::str::from_utf8(&header).map_err(|_| RtspProxyError::Protocol)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let start = lines.next().ok_or(RtspProxyError::Protocol)?.to_owned();
    if start.is_empty() || start.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(RtspProxyError::Protocol);
    }
    let mut headers = Vec::new();
    let mut content_length = None;
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err(RtspProxyError::Protocol);
        }
        let (name, value) = line.split_once(':').ok_or(RtspProxyError::Protocol)?;
        let value = value.trim();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(RtspProxyError::Protocol);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(RtspProxyError::Protocol);
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| RtspProxyError::Protocol)?,
            );
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    let body_len = content_length.unwrap_or(0);
    if body_len > limits.max_body_bytes {
        return Err(RtspProxyError::Limit);
    }
    let mut body = vec![0; body_len];
    read_exact(reader, &mut body, limits.io_timeout, expires).await?;
    Ok(RtspMessage {
        start,
        headers,
        body,
    })
}

async fn read_interleaved<R: AsyncRead + Unpin>(
    reader: &mut R,
    first: u8,
    limits: RtspProxyLimits,
    expires: Instant,
) -> Result<Vec<u8>, RtspProxyError> {
    if first != b'$' {
        return Err(RtspProxyError::Protocol);
    }
    let mut header = [0_u8; 3];
    read_exact(reader, &mut header, limits.io_timeout, expires).await?;
    let body_len = usize::from(u16::from_be_bytes([header[1], header[2]]));
    if body_len > limits.max_interleaved_frame_bytes {
        return Err(RtspProxyError::Limit);
    }
    let mut output = Vec::with_capacity(4 + body_len);
    output.push(first);
    output.extend_from_slice(&header);
    output.resize(4 + body_len, 0);
    read_exact(reader, &mut output[4..], limits.io_timeout, expires).await?;
    Ok(output)
}

async fn read_byte<R: AsyncRead + Unpin>(
    reader: &mut R,
    io_timeout: Duration,
    expires: Instant,
) -> Result<Option<u8>, RtspProxyError> {
    timeout_at(expires.min(Instant::now() + io_timeout), read_one(reader))
        .await
        .map_err(|_| RtspProxyError::Timeout)?
        .map_err(|_| RtspProxyError::Unavailable)
}

async fn read_one<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<u8>> {
    let mut byte = [0_u8; 1];
    match reader.read(&mut byte).await? {
        0 => Ok(None),
        _ => Ok(Some(byte[0])),
    }
}

async fn read_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    output: &mut [u8],
    io_timeout: Duration,
    expires: Instant,
) -> Result<(), RtspProxyError> {
    timeout_at(
        expires.min(Instant::now() + io_timeout),
        reader.read_exact(output),
    )
    .await
    .map_err(|_| RtspProxyError::Timeout)?
    .map(|_| ())
    .map_err(|_| RtspProxyError::Unavailable)
}

async fn write_all<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &[u8],
    io_timeout: Duration,
    expires: Instant,
) -> Result<(), RtspProxyError> {
    timeout_at(
        expires.min(Instant::now() + io_timeout),
        writer.write_all(value),
    )
    .await
    .map_err(|_| RtspProxyError::Timeout)?
    .map_err(|_| RtspProxyError::Unavailable)
}

async fn write_status<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    reason: &str,
    limits: RtspProxyLimits,
    expires: Instant,
) -> Result<(), RtspProxyError> {
    write_all(
        writer,
        format!("RTSP/1.0 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
        limits.io_timeout,
        expires,
    )
    .await
}

fn upstream_target(base: &str, suffix: &str) -> Result<String, RtspProxyError> {
    if unsafe_path(suffix) {
        return Err(RtspProxyError::Protocol);
    }
    if suffix.is_empty() {
        return Ok(base.to_owned());
    }
    let mut url = Url::parse(base).map_err(|_| RtspProxyError::Protocol)?;
    let path = format!("{}{suffix}", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url.to_string())
}

fn unsafe_path(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase();
    normalized.contains("%2e")
        || normalized.contains("%2f")
        || normalized.contains("%5c")
        || path.contains('\\')
        || path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn rewrite_sdp(
    body: &[u8],
    upstream: &str,
    local: &str,
    limit: usize,
) -> Result<Vec<u8>, RtspProxyError> {
    let text = std::str::from_utf8(body).map_err(|_| RtspProxyError::Protocol)?;
    let upstream_host = Url::parse(upstream)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .ok_or(RtspProxyError::Protocol)?;
    let mut output = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let newline = if line.ends_with("\r\n") {
            "\r\n"
        } else if line.ends_with('\n') {
            "\n"
        } else {
            ""
        };
        let sanitized_bare = line
            .trim_end_matches(['\r', '\n'])
            .replace(&upstream_host, "127.0.0.1");
        let bare = sanitized_bare.as_str();
        if let Some(control) = bare.strip_prefix("a=control:") {
            let rewritten = if control == "*" {
                "*".to_owned()
            } else if let Some(suffix) = control.strip_prefix(upstream.trim_end_matches('/')) {
                format!("{}{suffix}", local.trim_end_matches('/'))
            } else {
                let relative = control.rsplit('/').next().unwrap_or(control);
                format!("{}/{relative}", local.trim_end_matches('/'))
            };
            output.push_str("a=control:");
            output.push_str(&rewritten);
        } else if bare.starts_with("c=IN IP") {
            output.push_str("c=IN IP4 127.0.0.1");
        } else {
            output.push_str(bare);
        }
        output.push_str(newline);
        if output.len() > limit {
            return Err(RtspProxyError::Limit);
        }
    }
    Ok(output.into_bytes())
}

#[derive(Default)]
struct DigestState {
    realm: Option<String>,
    nonce: Option<String>,
    opaque: Option<String>,
    cnonce: Option<Zeroizing<String>>,
    nonce_count: u32,
}

impl DigestState {
    fn header(
        &mut self,
        challenge: &str,
        method: &str,
        uri: &str,
        username: Option<&str>,
        password: Option<&SecretString>,
    ) -> Result<Zeroizing<String>, RtspProxyError> {
        let username = username.ok_or(RtspProxyError::Protocol)?;
        let password = password.ok_or(RtspProxyError::Protocol)?.expose_secret();
        let parameters = parse_digest(challenge)?;
        let realm = parameter(&parameters, "realm")?;
        let nonce = parameter(&parameters, "nonce")?;
        let opaque = parameters
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("opaque"))
            .map(|(_, value)| quote_value(value))
            .transpose()?;
        let algorithm = parameters
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("algorithm"))
            .map(|(_, value)| value.as_str())
            .unwrap_or("MD5");
        if !algorithm.eq_ignore_ascii_case("MD5") {
            return Err(RtspProxyError::Protocol);
        }
        let qop = parameters
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("qop"))
            .map(|(_, value)| value.as_str());
        let uses_qop = match qop {
            Some(value) => {
                if !value
                    .split(',')
                    .any(|item| item.trim().eq_ignore_ascii_case("auth"))
                {
                    return Err(RtspProxyError::Protocol);
                }
                true
            }
            None => false,
        };
        let stale = parameters
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("stale"))
            .map(|(_, value)| {
                if value.eq_ignore_ascii_case("true") {
                    Ok(true)
                } else if value.eq_ignore_ascii_case("false") {
                    Ok(false)
                } else {
                    Err(RtspProxyError::Protocol)
                }
            })
            .transpose()?
            .unwrap_or(false);
        if stale || self.nonce.as_deref() != Some(nonce) || self.realm.as_deref() != Some(realm) {
            self.realm = Some(realm.to_owned());
            self.nonce = Some(nonce.to_owned());
            self.cnonce = Some(random_cnonce()?);
            self.nonce_count = 0;
        }
        self.opaque = opaque.map(str::to_owned);
        self.nonce_count = self
            .nonce_count
            .checked_add(1)
            .ok_or(RtspProxyError::Limit)?;
        let nc = format!("{:08x}", self.nonce_count);
        let cnonce = self.cnonce.as_ref().ok_or(RtspProxyError::Protocol)?;
        let a1 = Zeroizing::new(format!("{username}:{realm}:{password}"));
        let ha1 = Zeroizing::new(md5_hex(a1.as_bytes()));
        let a2 = Zeroizing::new(format!("{method}:{uri}"));
        let ha2 = Zeroizing::new(md5_hex(a2.as_bytes()));
        let response_input = if uses_qop {
            Zeroizing::new(format!(
                "{}:{nonce}:{nc}:{}:auth:{}",
                ha1.as_str(),
                cnonce.as_str(),
                ha2.as_str()
            ))
        } else {
            Zeroizing::new(format!("{}:{nonce}:{}", ha1.as_str(), ha2.as_str()))
        };
        let response = Zeroizing::new(md5_hex(response_input.as_bytes()));
        let mut value = Zeroizing::new(format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5",
            quote_value(username)?,
            quote_value(realm)?,
            quote_value(nonce)?,
            quote_value(uri)?,
            response.as_str()
        ));
        if uses_qop {
            value.push_str(&format!(
                ", qop=auth, nc={nc}, cnonce=\"{}\"",
                cnonce.as_str()
            ));
        }
        if let Some(opaque) = &self.opaque {
            value.push_str(&format!(", opaque=\"{}\"", quote_value(opaque)?));
        }
        Ok(value)
    }
}

fn random_cnonce() -> Result<Zeroizing<String>, RtspProxyError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = Zeroizing::new([0_u8; 16]);
    getrandom::fill(bytes.as_mut()).map_err(|_| RtspProxyError::Unavailable)?;
    let mut value = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes.iter().copied() {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(value)
}

fn parse_digest(value: &str) -> Result<Vec<(String, String)>, RtspProxyError> {
    let value = value.trim();
    let value = value
        .get(7..)
        .filter(|_| value[..7].eq_ignore_ascii_case("digest "))
        .ok_or(RtspProxyError::Protocol)?;
    let mut result = Vec::new();
    let mut rest = value;
    while !rest.trim().is_empty() {
        rest = rest.trim_start_matches([',', ' ']);
        let (name, tail) = rest.split_once('=').ok_or(RtspProxyError::Protocol)?;
        let name = name.trim();
        if name.is_empty()
            || result
                .iter()
                .any(|(existing, _): &(String, String)| existing.eq_ignore_ascii_case(name))
        {
            return Err(RtspProxyError::Protocol);
        }
        let tail = tail.trim_start();
        let (parsed, remaining) = if let Some(quoted) = tail.strip_prefix('"') {
            let end = quoted.find('"').ok_or(RtspProxyError::Protocol)?;
            if quoted[..end].contains('\\') {
                return Err(RtspProxyError::Protocol);
            }
            (quoted[..end].to_owned(), &quoted[end + 1..])
        } else {
            let end = tail.find(',').unwrap_or(tail.len());
            (tail[..end].trim().to_owned(), &tail[end..])
        };
        if parsed.is_empty()
            || parsed.len() > 512
            || parsed.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(RtspProxyError::Protocol);
        }
        result.push((name.to_owned(), parsed));
        rest = remaining;
    }
    Ok(result)
}

fn parameter<'a>(values: &'a [(String, String)], name: &str) -> Result<&'a str, RtspProxyError> {
    values
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .ok_or(RtspProxyError::Protocol)
}

fn quote_value(value: &str) -> Result<&str, RtspProxyError> {
    if value.len() > 2048
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\\'))
    {
        Err(RtspProxyError::Protocol)
    } else {
        Ok(value)
    }
}

fn md5_hex(value: &[u8]) -> String {
    format!("{:x}", Md5::digest(value))
}

fn push_line(output: &mut Vec<u8>, line: &str) -> Result<(), RtspProxyError> {
    if line.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(RtspProxyError::Protocol);
    }
    output.extend_from_slice(line.as_bytes());
    output.extend_from_slice(b"\r\n");
    Ok(())
}

fn push_header(output: &mut Vec<u8>, name: &str, value: &str) -> Result<(), RtspProxyError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(RtspProxyError::Protocol);
    }
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(b": ");
    output.extend_from_slice(value.as_bytes());
    output.extend_from_slice(b"\r\n");
    Ok(())
}

#[derive(Clone)]
pub struct FakeAuthorizedRtspConnector {
    inner: Arc<FakeConnectorState>,
}

struct FakeConnectorState {
    responses: Mutex<VecDeque<Vec<u8>>>,
    requests: Mutex<Vec<Vec<u8>>>,
    connections: AtomicUsize,
}

impl FakeAuthorizedRtspConnector {
    #[must_use]
    pub fn new(responses: Vec<Vec<u8>>) -> Self {
        Self {
            inner: Arc::new(FakeConnectorState {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
                connections: AtomicUsize::new(0),
            }),
        }
    }
    pub async fn connection_count(&self) -> usize {
        self.inner.connections.load(Ordering::SeqCst)
    }
    pub async fn requests(&self) -> Vec<Vec<u8>> {
        self.inner.requests.lock().await.clone()
    }
}

#[async_trait]
impl AuthorizedRtspConnector for FakeAuthorizedRtspConnector {
    async fn connect(
        &self,
        _binding: AuthorizedBinding,
        _port: u16,
    ) -> Result<Box<dyn RtspConnection>, RtspProxyError> {
        self.inner.connections.fetch_add(1, Ordering::SeqCst);
        let (proxy, fixture) = duplex(128 * 1024);
        let state = self.inner.clone();
        tokio::spawn(async move { run_fake_fixture(fixture, state).await });
        Ok(Box::new(proxy))
    }
}

async fn run_fake_fixture(mut fixture: DuplexStream, state: Arc<FakeConnectorState>) {
    loop {
        let Some(first) = read_one(&mut fixture).await.ok().flatten() else {
            break;
        };
        let limits = RtspProxyLimits {
            max_connections: 1,
            max_header_bytes: 64 * 1024,
            max_body_bytes: 1024 * 1024,
            max_interleaved_frame_bytes: 1024 * 1024,
            io_timeout: Duration::from_secs(5),
            lease_ttl: Duration::from_secs(60),
        };
        let Ok(request) = read_message(
            &mut fixture,
            first,
            limits,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        else {
            break;
        };
        let mut encoded = Vec::new();
        if push_line(&mut encoded, &request.start).is_err() {
            break;
        }
        for (name, value) in &request.headers {
            if push_header(&mut encoded, name, value).is_err() {
                return;
            }
        }
        encoded.extend_from_slice(b"\r\n");
        encoded.extend_from_slice(&request.body);
        state.requests.lock().await.push(encoded);
        let Some(response) = state.responses.lock().await.pop_front() else {
            break;
        };
        if fixture.write_all(&response).await.is_err() {
            break;
        }
    }
}
