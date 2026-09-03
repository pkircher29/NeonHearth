//! Windows Service Control Manager entry point.
//!
//! The SCM starts `lattice-service.exe --service` (the MSI's `ServiceInstall`
//! passes the flag) and this module immediately connects the service
//! dispatcher, registers a control handler, and walks the SCM status protocol:
//! `StartPending` (right after handler registration, with a wait hint) →
//! `Running` (only once the loopback listener has actually bound) →
//! `StopPending` → `Stopped`. Any startup failure reports `Stopped` with a
//! service-specific exit code so the SCM never waits out its 30 s connect
//! timeout (System event 7009 — the failure mode of the pre-service builds).
//!
//! The actual startup and shutdown logic is `crate::serve` — the exact code
//! path the console flow runs — so the two modes cannot drift.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

/// Must match `ServiceInstall/@Name` in packaging/windows/NeonHearth.wxs.
pub const SERVICE_NAME: &str = "NeonHearth";

/// Exit code reported to the SCM when startup or serving fails. Surfaces as
/// Win32 error 1066 (ERROR_SERVICE_SPECIFIC_ERROR) with this code attached.
const EXIT_CODE_RUNTIME_FAILURE: u32 = 1;

define_windows_service!(ffi_service_main, service_main);

/// Hand the process to the SCM dispatcher. Blocks until ServiceMain returns.
/// Fails fast (instead of hanging) when the process was not started by the
/// SCM — e.g. `--service` typed into a console.
pub fn run() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("connect to the Windows service control manager (--service only works when the SCM starts the process)")
}

fn service_main(_launch_args: Vec<OsString>) {
    if let Err(error) = run_service() {
        // The SCM was already told Stopped-with-error by run_service; this is
        // the only other place the failure can be recorded.
        tracing::error!(error = format!("{error:#}"), "NeonHearth service failed");
    }
}

fn run_service() -> Result<()> {
    init_service_logging();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // The control handler needs the status handle to report StopPending, but
    // the handle is only returned by registering the handler — hence the slot.
    let handle_slot: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
    let handler_slot = Arc::clone(&handle_slot);
    let handler_shutdown = shutdown_tx.clone();
    let event_handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(handle) = handler_slot.get() {
                let _ = handle.set_service_status(status(
                    ServiceState::StopPending,
                    ServiceExitCode::Win32(0),
                    Duration::from_secs(10),
                    1,
                ));
            }
            let _ = handler_shutdown.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("register service control handler")?;
    let _ = handle_slot.set(status_handle);
    status_handle
        .set_service_status(status(
            ServiceState::StartPending,
            ServiceExitCode::Win32(0),
            Duration::from_secs(30),
            1,
        ))
        .context("report StartPending to the SCM")?;

    let result = run_shared_startup(shutdown_tx, shutdown_rx, status_handle);

    if let Err(error) = &result {
        tracing::error!(
            error = format!("{error:#}"),
            "service startup or serve failed"
        );
    }
    let exit_code = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::ServiceSpecific(EXIT_CODE_RUNTIME_FAILURE),
    };
    // Always reach Stopped — success, startup error, or serve error — so the
    // SCM is never left waiting on a wait hint that will not be honored.
    let _ = status_handle.set_service_status(status(
        ServiceState::Stopped,
        exit_code,
        Duration::ZERO,
        0,
    ));
    result
}

/// Build the tokio runtime and run the same `serve` the console path uses.
/// `Running` is reported by the `on_listening` callback, i.e. only after the
/// loopback listener has bound successfully — never before.
fn run_shared_startup(
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    status_handle: ServiceStatusHandle,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(crate::serve(shutdown_tx, shutdown_rx, move || {
        let _ = status_handle.set_service_status(status(
            ServiceState::Running,
            ServiceExitCode::Win32(0),
            Duration::ZERO,
            0,
        ));
    }))
}

fn status(
    state: ServiceState,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
    checkpoint: u32,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint,
        wait_hint,
        process_id: None,
    }
}

/// Service processes have no console, so stdout tracing goes nowhere. Route
/// tracing to `service.log` in the existing service state directory (the same
/// directory platform.rs owns and configure-service.ps1 ACLs for the service
/// account). Best effort: a failure here must not stop the service, so the
/// process simply runs unlogged if the file cannot be opened.
fn init_service_logging() {
    let Ok(paths) = crate::resolve_state_paths() else {
        return;
    };
    if std::fs::create_dir_all(&paths.state_dir).is_err() {
        return;
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.state_dir.join("service.log"))
    else {
        return;
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(Mutex::new(file))
        .try_init();
}
