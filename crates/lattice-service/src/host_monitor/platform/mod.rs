use super::{Application, Connection, HostSnapshot, digest};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;
pub fn snapshot() -> Result<HostSnapshot, &'static str> {
    #[cfg(windows)]
    {
        windows::snapshot()
    }
    #[cfg(target_os = "linux")]
    {
        linux::snapshot()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("unsupported platform")
    }
}
fn identify(app: &mut Application) {
    app.app_id = digest(
        &app.executable
            .as_ref()
            .map(|s| {
                if cfg!(windows) {
                    s.to_lowercase()
                } else {
                    s.clone()
                }
            })
            .unwrap_or_else(|| format!("unresolved:{}:{}", app.pid, app.started)),
    );
}
fn connection_id(connection: &mut Connection, app: &Application) {
    connection.connection_id = digest(&format!(
        "{}|{}|{}|{}|{}|{}|{:?}|{:?}",
        app.app_id,
        app.pid,
        app.started,
        connection.protocol,
        connection.local_address,
        connection.local_port,
        connection.remote_address,
        connection.remote_port
    ));
    connection.app_id = app.app_id.clone();
}
