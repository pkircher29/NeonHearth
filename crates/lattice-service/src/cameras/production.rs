//! Production construction of the camera media pipeline.
//!
//! [`build`] assembles the real implementations (the OS vault, the production
//! ffmpeg launcher with its cleared environment and argument whitelist, the
//! interface-pinned RTSP connector, the stored-approval target registry, and the
//! startup-swept output root) into one [`CameraSessionManager`], together with
//! the [`CameraOnboarding`] that adds and removes cameras. Every prerequisite
//! that can be absent on a given machine is checked first and reported as a
//! specific reason instead of a generic failure; none of them can fail the rest
//! of the service.

use super::{
    CameraSessionConfig, CameraSessionManager, SystemAuthorizedRtspConnector,
    onboarding::{
        CameraOnboarding, CameraTargetBook, InterfaceSource, SystemInterfaces,
        SystemOnvifConnector,
    },
};
use crate::vault::{Vault, VaultBackend, platform_vault};
use lattice_camera::{FFMPEG_ENV, ProductionMediaProcessFactory, ffmpeg_executable};
use lattice_store::CameraRepository;
use serde::Serialize;
use sqlx::SqlitePool;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// The state was never given a startup result (only tests build such a state).
pub const REASON_NOT_CONFIGURED: &str = "not_configured";
/// Camera media is running.
pub const REASON_READY: &str = "ready";
/// The platform cannot verify the RTSP peer or serve session files safely.
pub const REASON_UNSUPPORTED_PLATFORM: &str = "unsupported_platform";
/// No ffmpeg binary at the configured or default absolute location.
pub const REASON_FFMPEG_NOT_FOUND: &str = "ffmpeg_not_found";
/// A file exists at the ffmpeg location but is not executable.
pub const REASON_FFMPEG_NOT_EXECUTABLE: &str = "ffmpeg_not_executable";
/// The credential store could not be opened.
pub const REASON_VAULT_UNAVAILABLE: &str = "vault_unavailable";
/// The temporary media directory could not be prepared.
pub const REASON_OUTPUT_DIR_UNAVAILABLE: &str = "output_dir_unavailable";
/// The target registry could not be constructed.
pub const REASON_REGISTRY_UNAVAILABLE: &str = "target_registry_unavailable";

/// Directory (inside the service state directory) that holds temporary HLS
/// segments and snapshots. Everything in it that looks like a session is
/// deleted when the manager starts.
pub const OUTPUT_DIR_NAME: &str = "camera-media";

/// The OS keyring can hang on a missing session bus; startup must not.
const VAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(15);

const SETUP_NEEDS_MEDIA: &str = "A camera cannot be added while video support is off on this machine. Fix the problem above first; adding a camera needs the same pieces as watching one.";
const SETUP_NOT_WIRED: &str = "This service process was started without the part that adds cameras.";

/// What the owner needs to know about camera media on this machine. Served by
/// `GET /api/v1/camera-media` and embedded (as `reason` and `detail`) in the
/// 503 body of every camera media route when media is not running.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CameraMediaStatus {
    /// Whether the session, snapshot and playlist routes are serving.
    pub enabled: bool,
    /// Stable machine-readable reason; `ready` while enabled.
    pub reason: &'static str,
    /// Plain-language explanation with what the owner can do about it.
    pub detail: String,
    /// Whether a camera can be added right now (true exactly when camera
    /// media is running and the add-camera part was built with it).
    pub setup_available: bool,
    /// Plain-language reason a camera cannot be added; empty when it can.
    pub setup_detail: &'static str,
}

impl CameraMediaStatus {
    #[must_use]
    pub fn not_configured() -> Self {
        Self::disabled(
            REASON_NOT_CONFIGURED,
            "This service process was started without the camera media pipeline.",
        )
    }

    /// A state whose session manager was supplied by the host (tests).
    #[must_use]
    pub fn injected() -> Self {
        Self {
            setup_available: false,
            setup_detail: SETUP_NOT_WIRED,
            ..Self::ready("A camera session manager was supplied by the host process.")
        }
    }

    #[must_use]
    pub fn ready(detail: impl Into<String>) -> Self {
        Self {
            enabled: true,
            reason: REASON_READY,
            detail: detail.into(),
            setup_available: true,
            setup_detail: "",
        }
    }

    #[must_use]
    pub fn disabled(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            enabled: false,
            reason,
            detail: detail.into(),
            setup_available: false,
            setup_detail: SETUP_NEEDS_MEDIA,
        }
    }
}

/// The outcome of [`build`]: the manager and the add/remove part when every
/// prerequisite held, and in every case the status the routes report.
#[derive(Debug)]
pub struct CameraMediaBuild {
    pub manager: Option<Arc<CameraSessionManager>>,
    pub onboarding: Option<Arc<CameraOnboarding>>,
    pub status: CameraMediaStatus,
}

impl CameraMediaBuild {
    fn disabled(status: CameraMediaStatus) -> Self {
        Self {
            manager: None,
            onboarding: None,
            status,
        }
    }
}

/// The facts about this machine that decide whether camera media can run.
/// Separate from [`build`] so the decisions are testable without a host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraMediaEnvironment {
    /// Loopback peer verification and safe session-file access exist only on
    /// Linux and Windows; elsewhere the proxy fails closed.
    pub platform_supported: bool,
    /// The ffmpeg executable the media launcher will spawn (absolute; `PATH`
    /// is never searched).
    pub ffmpeg: PathBuf,
}

impl CameraMediaEnvironment {
    #[must_use]
    pub fn detect() -> Self {
        Self {
            platform_supported: cfg!(any(target_os = "linux", windows)),
            ffmpeg: ffmpeg_executable().to_path_buf(),
        }
    }
}

/// Checks every prerequisite that depends only on this machine (not on the
/// vault or the state directory), returning the first one that does not hold.
pub fn check_prerequisites(environment: &CameraMediaEnvironment) -> Result<(), CameraMediaStatus> {
    if !environment.platform_supported {
        return Err(CameraMediaStatus::disabled(
            REASON_UNSUPPORTED_PLATFORM,
            "Camera media runs only on Windows and Linux. On this operating system the service cannot verify which process is reading the local camera stream, so it stays off.",
        ));
    }
    let path = &environment.ffmpeg;
    let not_found = || {
        CameraMediaStatus::disabled(
            REASON_FFMPEG_NOT_FOUND,
            format!(
                "ffmpeg was expected at {} but is not there. Install ffmpeg at that exact location, or set {FFMPEG_ENV} to the absolute path of ffmpeg for the NeonHearth service and restart it. NeonHearth never searches PATH for ffmpeg.",
                path.display()
            ),
        )
    };
    let Ok(metadata) = std::fs::metadata(path) else {
        return Err(not_found());
    };
    if !metadata.is_file() {
        return Err(not_found());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(CameraMediaStatus::disabled(
                REASON_FFMPEG_NOT_EXECUTABLE,
                format!(
                    "A file exists at {} but it is not executable. Make it executable (chmod +x) or point {FFMPEG_ENV} at a working ffmpeg, then restart the service.",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

async fn prepare_output_root(state_dir: &Path) -> Result<PathBuf, CameraMediaStatus> {
    let unusable = || {
        CameraMediaStatus::disabled(
            REASON_OUTPUT_DIR_UNAVAILABLE,
            format!(
                "The temporary camera media folder {} could not be prepared. It must be a real folder (not a link) that the service can write to.",
                state_dir.join(OUTPUT_DIR_NAME).display()
            ),
        )
    };
    let absolute = std::path::absolute(state_dir).map_err(|_| unusable())?;
    let root = absolute.join(OUTPUT_DIR_NAME);
    tokio::fs::create_dir_all(&root)
        .await
        .map_err(|_| unusable())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|_| unusable())?;
    }
    Ok(root)
}

#[must_use]
pub fn vault_label(backend: VaultBackend) -> &'static str {
    match backend {
        VaultBackend::Keyring => "the operating-system credential store",
        VaultBackend::EncryptedFile => {
            "an encrypted file in the service state directory (the service has no OS keyring session)"
        }
    }
}

/// Builds camera media for this machine from the real implementations. Never
/// fails: the outcome carries the manager or the specific reason it is off.
pub async fn build(pool: SqlitePool, state_dir: &Path) -> CameraMediaBuild {
    let environment = CameraMediaEnvironment::detect();
    // Cheap machine checks first, so a machine without ffmpeg never touches
    // the vault or creates any state.
    let outcome = match check_prerequisites(&environment) {
        Err(status) => CameraMediaBuild::disabled(status),
        Ok(()) => match tokio::time::timeout(VAULT_OPEN_TIMEOUT, platform_vault(state_dir)).await {
            Ok(Ok((vault, backend))) => {
                assemble(&environment, pool, vault, vault_label(backend), state_dir).await
            }
            Ok(Err(_)) | Err(_) => CameraMediaBuild::disabled(CameraMediaStatus::disabled(
                REASON_VAULT_UNAVAILABLE,
                "The credential store for camera passwords could not be opened. On Windows the Credential Manager must be available to the service account; on Linux the service falls back to an encrypted file in its state directory, which also failed. Check that the state directory is writable, then restart the service.",
            )),
        },
    };
    if outcome.status.enabled {
        tracing::info!(reason = outcome.status.reason, "camera media enabled");
    } else {
        tracing::warn!(
            reason = outcome.status.reason,
            detail = %outcome.status.detail,
            "camera media is off; the rest of the service is unaffected"
        );
    }
    outcome
}

/// Everything after the vault is open: re-checks the machine prerequisites,
/// prepares the output root and constructs the manager (whose constructor
/// sweeps leftover `session-*` and `snapshot-*` directories). Public so a test
/// can supply an in-memory vault; production goes through [`build`].
pub async fn assemble(
    environment: &CameraMediaEnvironment,
    pool: SqlitePool,
    vault: Arc<dyn Vault>,
    vault_label: &str,
    state_dir: &Path,
) -> CameraMediaBuild {
    assemble_with_interfaces(
        environment,
        pool,
        vault,
        vault_label,
        state_dir,
        Arc::new(SystemInterfaces),
    )
    .await
}

/// [`assemble`] over an explicit interface source (the seam tests use to give
/// the target registry a fixed network).
pub async fn assemble_with_interfaces(
    environment: &CameraMediaEnvironment,
    pool: SqlitePool,
    vault: Arc<dyn Vault>,
    vault_label: &str,
    state_dir: &Path,
    interfaces: Arc<dyn InterfaceSource>,
) -> CameraMediaBuild {
    if let Err(status) = check_prerequisites(environment) {
        return CameraMediaBuild::disabled(status);
    }
    let root = match prepare_output_root(state_dir).await {
        Ok(root) => root,
        Err(status) => return CameraMediaBuild::disabled(status),
    };
    assemble_with(environment, pool, vault, vault_label, root, interfaces).await
}

async fn assemble_with(
    environment: &CameraMediaEnvironment,
    pool: SqlitePool,
    vault: Arc<dyn Vault>,
    vault_label: &str,
    root: PathBuf,
    interfaces: Arc<dyn InterfaceSource>,
) -> CameraMediaBuild {
    // The registry is rebuilt from the owner's stored approvals. If they cannot
    // be read, no camera is approved (fail closed) and the cause is logged.
    let repository = CameraRepository::new(pool.clone());
    let book = Arc::new(CameraTargetBook::new(interfaces.clone()));
    match book.load(&repository).await {
        Ok(count) => tracing::info!(count, "camera host approvals loaded"),
        Err(error) => tracing::error!(
            %error,
            "camera host approvals could not be read; no camera will stream until they can"
        ),
    }
    let manager = CameraSessionManager::new(
        repository,
        vault.clone(),
        book.clone(),
        Arc::new(ProductionMediaProcessFactory),
        Arc::new(SystemAuthorizedRtspConnector),
        root.clone(),
        CameraSessionConfig::default(),
    );
    match manager {
        Ok(manager) => {
            let manager = Arc::new(manager);
            let onboarding = Arc::new(CameraOnboarding::new(
                pool,
                vault,
                book,
                manager.clone(),
                interfaces,
                Arc::new(SystemOnvifConnector),
            ));
            CameraMediaBuild {
                manager: Some(manager),
                onboarding: Some(onboarding),
                status: CameraMediaStatus::ready(format!(
                    "ffmpeg found at {}; camera credentials are kept in {vault_label}.",
                    environment.ffmpeg.display()
                )),
            }
        }
        Err(_) => CameraMediaBuild::disabled(CameraMediaStatus::disabled(
            REASON_OUTPUT_DIR_UNAVAILABLE,
            format!(
                "The temporary camera media folder {} is not usable: it must be an existing real folder (not a link).",
                root.display()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cameras::CameraTargetRegistry, vault::FakeVault};
    use lattice_camera::{CameraId, StreamId};
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;

    fn executable_file(directory: &Path) -> PathBuf {
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

    fn environment(ffmpeg: PathBuf) -> CameraMediaEnvironment {
        CameraMediaEnvironment {
            platform_supported: true,
            ffmpeg,
        }
    }

    #[test]
    fn an_unsupported_platform_is_reported_before_anything_else() {
        let status = check_prerequisites(&CameraMediaEnvironment {
            platform_supported: false,
            ffmpeg: PathBuf::from("/nonexistent/ffmpeg"),
        })
        .unwrap_err();
        assert!(!status.enabled);
        assert_eq!(status.reason, REASON_UNSUPPORTED_PLATFORM);
    }

    #[test]
    fn a_missing_ffmpeg_names_its_expected_path_and_the_override() {
        let directory = tempfile::tempdir().unwrap();
        let expected = directory.path().join("absent-ffmpeg");
        let status = check_prerequisites(&environment(expected.clone())).unwrap_err();
        assert_eq!(status.reason, REASON_FFMPEG_NOT_FOUND);
        assert!(status.detail.contains(&expected.display().to_string()));
        assert!(status.detail.contains(FFMPEG_ENV));
        assert!(status.detail.contains("PATH"));
        assert!(!status.enabled);
        assert!(!status.setup_available);
    }

    #[test]
    fn a_directory_at_the_ffmpeg_location_is_not_ffmpeg() {
        let directory = tempfile::tempdir().unwrap();
        let status = check_prerequisites(&environment(directory.path().to_path_buf())).unwrap_err();
        assert_eq!(status.reason, REASON_FFMPEG_NOT_FOUND);
    }

    #[test]
    fn an_existing_executable_satisfies_the_machine_prerequisites() {
        let directory = tempfile::tempdir().unwrap();
        let path = executable_file(directory.path());
        assert!(check_prerequisites(&environment(path)).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_non_executable_file_is_reported_distinctly() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = executable_file(directory.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let status = check_prerequisites(&environment(path)).unwrap_err();
        assert_eq!(status.reason, REASON_FFMPEG_NOT_EXECUTABLE);
    }

    #[test]
    fn status_serializes_with_stable_keys() {
        let value =
            serde_json::to_value(CameraMediaStatus::disabled(REASON_FFMPEG_NOT_FOUND, "gone"))
                .unwrap();
        let object = value.as_object().unwrap();
        let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "detail",
                "enabled",
                "reason",
                "setup_available",
                "setup_detail"
            ]
        );
        assert_eq!(value["enabled"], false);
        assert_eq!(value["reason"], "ffmpeg_not_found");
        assert_eq!(value["setup_available"], false);
    }

    #[tokio::test]
    async fn the_production_registry_starts_empty_and_refuses_loopback_even_if_a_row_says_otherwise()
    {
        use lattice_sensor::{
            Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory,
        };
        let inventory = InterfaceInventory::new(vec![
            Interface {
                id: InterfaceId::new(1),
                name: "lo".into(),
                description: None,
                up: true,
                class: InterfaceClass::Loopback,
                addresses: vec![Address {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    prefix: 8,
                }],
                owner_role: None,
            },
            Interface {
                id: InterfaceId::new(2),
                name: "eth0".into(),
                description: None,
                up: true,
                class: InterfaceClass::PhysicalWired,
                addresses: vec![Address {
                    ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                    prefix: 24,
                }],
                owner_role: None,
            },
        ]);
        let book = CameraTargetBook::new(Arc::new(
            crate::cameras::onboarding::FixedInterfaces::new(inventory),
        ));
        let camera = CameraId::from_uuid(Uuid::from_u128(1));
        let stream = StreamId::from_uuid(Uuid::from_u128(2));
        assert!(book.authorized_binding(camera, stream).await.is_err());
        // A tampered row naming a host that must never be approved.
        for (interface, address) in [
            ("lo", Ipv4Addr::LOCALHOST),
            ("lo", Ipv4Addr::new(127, 0, 0, 2)),
            ("eth0", Ipv4Addr::UNSPECIFIED),
            ("eth0", Ipv4Addr::new(224, 0, 0, 251)),
            ("eth0", Ipv4Addr::BROADCAST),
            ("eth0", Ipv4Addr::new(192, 168, 1, 255)),
            ("eth0", Ipv4Addr::new(192, 168, 1, 10)),
            ("eth0", Ipv4Addr::new(8, 8, 8, 8)),
        ] {
            book.register(&lattice_store::CameraTarget {
                camera_id: camera,
                interface: interface.to_owned(),
                address,
                onvif_port: 80,
                rtsp_port: 554,
                allow_basic: false,
                approved_at: chrono::Utc::now(),
                name: None,
            })
            .await;
            assert!(
                book.authorized_binding(camera, stream).await.is_err(),
                "{address} on {interface} must never be approved"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_ffmpeg_builds_nothing_and_creates_no_state() {
        let pool = lattice_store::connect_memory().await.unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let outcome = assemble(
            &environment(state_dir.path().join("absent-ffmpeg")),
            pool,
            Arc::new(FakeVault::new()),
            "a test vault",
            state_dir.path(),
        )
        .await;
        assert!(outcome.manager.is_none());
        assert_eq!(outcome.status.reason, REASON_FFMPEG_NOT_FOUND);
        assert!(!state_dir.path().join(OUTPUT_DIR_NAME).exists());
    }

    #[tokio::test]
    async fn an_unusable_output_root_is_reported_not_raised() {
        let pool = lattice_store::connect_memory().await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let ffmpeg = executable_file(directory.path());
        // A regular file where the state directory should be.
        let state_dir = directory.path().join("state-is-a-file");
        std::fs::write(&state_dir, b"x").unwrap();
        let outcome = assemble(
            &environment(ffmpeg),
            pool,
            Arc::new(FakeVault::new()),
            "a test vault",
            &state_dir,
        )
        .await;
        assert!(outcome.manager.is_none());
        assert_eq!(outcome.status.reason, REASON_OUTPUT_DIR_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_ready_machine_builds_the_manager_and_sweeps_stale_sessions() {
        let pool = lattice_store::connect_memory().await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let ffmpeg = executable_file(directory.path());
        let state_dir = directory.path().join("state");
        let root = state_dir.join(OUTPUT_DIR_NAME);
        let stale = root.join("session-left-over-by-a-crash");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("segment-000001.ts"), b"camera video").unwrap();
        let unrelated = root.join("keep-me");
        std::fs::create_dir_all(&unrelated).unwrap();
        let outcome = assemble(
            &environment(ffmpeg),
            pool,
            Arc::new(FakeVault::new()),
            "a test vault",
            &state_dir,
        )
        .await;
        assert!(outcome.manager.is_some(), "{:?}", outcome.status);
        assert!(outcome.status.enabled);
        assert_eq!(outcome.status.reason, REASON_READY);
        assert!(outcome.onboarding.is_some());
        assert!(outcome.status.setup_available);
        assert_eq!(outcome.status.setup_detail, "");
        assert!(!stale.exists(), "stale session output must be swept");
        assert!(unrelated.exists(), "only session output is swept");
    }
}
