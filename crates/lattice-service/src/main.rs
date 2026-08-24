use anyhow::{Context, Result};
use chrono::Utc;
use lattice_service::runtime::StartupResult;
use lattice_service::{AppState, app};
use lattice_service::{Platform, platform_paths};
use lattice_store::{InstallRepository, M2StateRepository};
use std::path::PathBuf;
use tokio::net::TcpListener;
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let token = std::env::var("LATTICE_SERVICE_TOKEN")
        .context("LATTICE_SERVICE_TOKEN must be supplied by platform secret provider")?;
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
    let paths = platform_paths(platform, base);
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
    let startup =
        lattice_service::runtime::build(state.clone(), M2StateRepository::new(pool.clone())).await;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    #[cfg(unix)]
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("register SIGTERM handler")?;
    #[cfg(not(unix))]
    let terminate = ();
    let listener = TcpListener::bind("127.0.0.1:58120").await?;
    let server = axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal(terminate, shutdown_tx.clone()))
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
        StartupResult::Degraded => server.await?,
    }
    drop(pool);
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal(
    mut terminate: tokio::signal::unix::Signal,
    shutdown: tokio::sync::watch::Sender<bool>,
) {
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    let _ = shutdown.send(true);
}
#[cfg(not(unix))]
async fn shutdown_signal(_: (), shutdown: tokio::sync::watch::Sender<bool>) {
    let _ = tokio::signal::ctrl_c().await;
    let _ = shutdown.send(true);
}
