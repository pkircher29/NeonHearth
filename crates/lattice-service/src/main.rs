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
    let listener = TcpListener::bind("127.0.0.1:58120").await?;
    axum::serve(listener, app(AppState::new(token)?))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("register SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
