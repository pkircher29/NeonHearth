use anyhow::{Context, Result};
use lattice_service::{AppState, app};
use tokio::net::TcpListener;
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let token = std::env::var("LATTICE_SERVICE_TOKEN")
        .context("LATTICE_SERVICE_TOKEN must be supplied by platform secret provider")?;
    #[cfg(unix)]
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("register SIGTERM handler")?;
    #[cfg(not(unix))]
    let terminate = ();
    let listener = TcpListener::bind("127.0.0.1:58120").await?;
    axum::serve(listener, app(AppState::new(token)?))
        .with_graceful_shutdown(shutdown_signal(terminate))
        .await?;
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal(mut terminate: tokio::signal::unix::Signal) {
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
}
#[cfg(not(unix))]
async fn shutdown_signal(_: ()) {
    let _ = tokio::signal::ctrl_c().await;
}
