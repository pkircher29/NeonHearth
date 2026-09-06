use anyhow::{Context, Result};
use chrono::Utc;
use lattice_service::runtime::StartupResult;
use lattice_service::{AppState, app};
use lattice_service::{Platform, PlatformPaths, platform_paths};
use lattice_store::{InstallRepository, M2StateRepository, PolicyRepository};
use std::ffi::OsString;
use std::path::PathBuf;
use tokio::net::TcpListener;
use tokio::sync::watch;

#[cfg(windows)]
mod win_service;

/// How the process was asked to run. `--service` is the only recognized flag:
/// it selects the Windows Service Control Manager entry point (the SCM starts
/// the process and expects it to register a ServiceMain; a plain console run
/// under the SCM times out with event 7009). Anything else is rejected so a
/// typo cannot silently start the wrong mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunMode {
    Console,
    Service,
}

fn parse_mode<I>(args: I) -> Result<RunMode, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut mode = RunMode::Console;
    for arg in args {
        if arg == "--service" {
            mode = RunMode::Service;
        } else {
            return Err(format!(
                "unrecognized argument {arg:?}; the only supported flag is --service"
            ));
        }
    }
    Ok(mode)
}

fn main() -> Result<()> {
    match parse_mode(std::env::args_os().skip(1)).map_err(|message| anyhow::anyhow!(message))? {
        RunMode::Console => run_console(),
        RunMode::Service => run_service_mode(),
    }
}

#[cfg(windows)]
fn run_service_mode() -> Result<()> {
    win_service::run()
}

#[cfg(not(windows))]
fn run_service_mode() -> Result<()> {
    anyhow::bail!("--service is Windows-only (the SCM entry point); on Linux use the systemd unit")
}

/// The console (developer) flow: identical service startup, with tracing on
/// stdout and Ctrl-C / SIGTERM triggering the graceful shutdown.
#[tokio::main]
async fn run_console() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    #[cfg(unix)]
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("register SIGTERM handler")?;
    #[cfg(not(unix))]
    let terminate = ();
    tokio::spawn(console_shutdown_signals(terminate, shutdown_tx.clone()));
    serve(shutdown_tx, shutdown_rx, || {}).await
}

/// Resolve the service-owned state paths (docs/architecture/privilege-boundary.md):
/// `%ProgramData%\NeonHearth` on Windows, `/var/lib/neonhearth` on Linux, with
/// `LATTICE_STATE_BASE` overriding the base for tests and smoke runs.
pub(crate) fn resolve_state_paths() -> Result<PlatformPaths> {
    let platform = if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Linux
    };
    let base = match std::env::var_os("LATTICE_STATE_BASE") {
        Some(base) => PathBuf::from(base),
        None if platform == Platform::Windows => PathBuf::from(
            std::env::var_os("ProgramData").context("ProgramData is required on Windows")?,
        ),
        None => PathBuf::from("/var/lib"),
    };
    Ok(platform_paths(platform, base))
}

/// Default listener address; overridable with `LATTICE_BIND` (loopback only).
const DEFAULT_BIND: &str = "127.0.0.1:58120";

/// Parse and validate the listener address. `LATTICE_BIND` exists so test
/// instances can run beside a live installed service (different port, same
/// machine); it must never widen the privilege boundary, so any non-loopback
/// IP is refused outright (docs/architecture/privilege-boundary.md: the API
/// listens on loopback only).
pub(crate) fn parse_bind(value: Option<&str>) -> Result<std::net::SocketAddr, String> {
    let text = value.unwrap_or(DEFAULT_BIND);
    let addr: std::net::SocketAddr = text
        .parse()
        .map_err(|error| format!("LATTICE_BIND {text:?} is not a valid socket address: {error}"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "LATTICE_BIND {text:?} is not a loopback address; the NeonHearth API is loopback-only"
        ));
    }
    Ok(addr)
}

/// The single shared startup path: token, state directories, database,
/// runtime worker, loopback listener, and supervised serve-until-shutdown.
/// Both the console flow and the Windows service flow run exactly this, so
/// they cannot drift; they differ only in who triggers `shutdown_tx` and in
/// what `on_listening` does (the service reports Running to the SCM there,
/// immediately after the bind succeeds).
pub(crate) async fn serve(
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    on_listening: impl FnOnce(),
) -> Result<()> {
    let token = std::env::var("LATTICE_SERVICE_TOKEN")
        .context("LATTICE_SERVICE_TOKEN must be supplied by platform secret provider")?;
    let paths = resolve_state_paths()?;
    std::fs::create_dir_all(&paths.state_dir).context("create service state directory")?;
    std::fs::create_dir_all(&paths.backups).context("create service backups directory")?;
    let pool = lattice_store::connect_path(&paths.database)
        .await
        .context("open service database")?;
    InstallRepository::new(pool.clone())
        .initialize(Utc::now())
        .await
        .context("initialize install state")?;
    let state = AppState::new(token, M2StateRepository::new(pool.clone()))?;
    if let Some(path) = std::env::var_os("LATTICE_MQTT_CREDENTIAL_FILE") {
        lattice_service::mqtt::start(state.clone(), PathBuf::from(path), shutdown_rx.clone());
    }
    let startup =
        lattice_service::runtime::build(state.clone(), M2StateRepository::new(pool.clone())).await;
    let bind_var = std::env::var("LATTICE_BIND").ok();
    let bind = parse_bind(bind_var.as_deref()).map_err(|message| anyhow::anyhow!(message))?;
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind loopback listener {bind}"))?;
    on_listening();
    PolicyRepository::new(pool.clone())
        .mark_successful_service_start(Utc::now())
        .await
        .context("initialize first successful service baseline")?;
    // Optional static UI hosting: when the installer (or an operator) points
    // LATTICE_UI_DIR at the staged Vite bundle, the service serves the
    // dashboard at "/" (no bearer needed for assets; API auth unchanged).
    // Absent, the historical API-only behavior is preserved exactly.
    let router = app(state);
    let router = match std::env::var_os("LATTICE_UI_DIR") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            tracing::info!(ui_dir = %dir.display(), "serving UI bundle at /");
            lattice_service::with_ui_assets(router, &dir)
        }
        None => router,
    };
    let server = axum::serve(listener, router)
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()))
        .into_future();
    match startup {
        StartupResult::Worker(worker) => {
            lattice_service::runtime::supervise(
                server,
                Some(tokio::spawn(worker.run(shutdown_rx))),
                shutdown_tx,
            )
            .await?;
        }
        StartupResult::Degraded => {
            lattice_service::runtime::supervise(server, None, shutdown_tx).await?
        }
    }
    drop(pool);
    Ok(())
}

/// Resolves when the shared shutdown flag flips to true (or every sender is
/// gone). Used as the axum graceful-shutdown future in both run modes.
async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

#[cfg(unix)]
async fn console_shutdown_signals(
    mut terminate: tokio::signal::unix::Signal,
    shutdown: watch::Sender<bool>,
) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
    let _ = shutdown.send(true);
}

#[cfg(not(unix))]
async fn console_shutdown_signals(_terminate: (), shutdown: watch::Sender<bool>) {
    let _ = tokio::signal::ctrl_c().await;
    let _ = shutdown.send(true);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn no_arguments_is_console_mode() {
        assert_eq!(parse_mode(args(&[])), Ok(RunMode::Console));
    }

    #[test]
    fn service_flag_selects_service_mode() {
        assert_eq!(parse_mode(args(&["--service"])), Ok(RunMode::Service));
        // Repeating the flag is harmless (idempotent), matching sc.exe's
        // tolerance for argument echo in binPath edits.
        assert_eq!(
            parse_mode(args(&["--service", "--service"])),
            Ok(RunMode::Service)
        );
    }

    #[test]
    fn unknown_arguments_are_rejected() {
        let error = parse_mode(args(&["--serivce"])).unwrap_err();
        assert!(error.contains("--serivce"), "{error}");
        assert!(parse_mode(args(&["--service", "extra"])).is_err());
    }

    #[test]
    fn bind_defaults_to_loopback_58120() {
        assert_eq!(parse_bind(None), Ok("127.0.0.1:58120".parse().unwrap()));
    }

    #[test]
    fn bind_accepts_alternate_loopback_ports_and_ipv6_loopback() {
        assert_eq!(
            parse_bind(Some("127.0.0.1:58121")),
            Ok("127.0.0.1:58121".parse().unwrap())
        );
        assert_eq!(
            parse_bind(Some("[::1]:58121")),
            Ok("[::1]:58121".parse().unwrap())
        );
    }

    #[test]
    fn bind_refuses_non_loopback_addresses() {
        for bad in ["0.0.0.0:58120", "192.168.1.10:58120", "[::]:58120"] {
            let error = parse_bind(Some(bad)).unwrap_err();
            assert!(error.contains("loopback"), "{bad}: {error}");
        }
    }

    #[test]
    fn bind_refuses_garbage() {
        for bad in ["", "not-an-address", "127.0.0.1", "127.0.0.1:notaport"] {
            assert!(parse_bind(Some(bad)).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn state_base_override_feeds_platform_paths() {
        // resolve_state_paths must honor LATTICE_STATE_BASE exactly like the
        // pre-refactor inline code did (stage.ps1's smoke run relies on it).
        // Env mutation is process-global, so keep this to a single test.
        // SAFETY: tests in this binary run in-process; no other test reads
        // this variable concurrently.
        unsafe { std::env::set_var("LATTICE_STATE_BASE", "base-for-test") };
        let paths = resolve_state_paths().expect("paths resolve with explicit base");
        unsafe { std::env::remove_var("LATTICE_STATE_BASE") };
        let expected_platform = if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Linux
        };
        assert_eq!(paths, platform_paths(expected_platform, "base-for-test"));
    }
}
