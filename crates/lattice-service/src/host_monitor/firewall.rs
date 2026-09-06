use super::*;
use axum::http::StatusCode;
use lattice_store::{AuditActor, AuditCategory, AuditLog, NewAuditEntry};
use serde_json::{Value, json};
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallInput {
    pub app_id: String,
    pub direction: String,
    pub blocked: bool,
    pub expected_blocked: bool,
    pub confirmed: bool,
}
pub fn protected_program(path: &str) -> bool {
    let path = path.replace('\\', "/").to_lowercase();
    let name = path.rsplit('/').next().unwrap_or("");
    path.contains("/windows/")
        || [
            "lattice-service.exe",
            "neonhearth.exe",
            "mosquitto.exe",
            "tailscale.exe",
            "tailscaled.exe",
            "powershell.exe",
            "pwsh.exe",
            "sshd.exe",
            "svchost.exe",
            "lsass.exe",
            "wininit.exe",
            "services.exe",
            "winlogon.exe",
            "smss.exe",
            "csrss.exe",
            "lattice-service",
            "tailscaled",
            "mosquitto",
            "sshd",
        ]
        .contains(&name)
}
impl HostMonitor {
    pub async fn firewall_rules(&self) -> Result<Value, StatusCode> {
        run(json!({"operation":"list"})).await
    }
    pub async fn firewall_action(&self, input: FirewallInput) -> Result<Value, StatusCode> {
        let this = self.clone();
        tokio::spawn(async move { this.apply_firewall_owned(input).await })
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    }
    async fn apply_firewall_owned(&self, input: FirewallInput) -> Result<Value, StatusCode> {
        if input.app_id.len() != 64
            || !input.app_id.bytes().all(|b| b.is_ascii_hexdigit())
            || !["inbound", "outbound"].contains(&input.direction.as_str())
            || !input.confirmed
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let _lock = self
            .firewall_lock
            .try_lock()
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        let snapshot = self.snapshot().await;
        if !snapshot.firewall_available {
            return Err(StatusCode::FORBIDDEN);
        }
        let saved: Option<String> =
            sqlx::query_scalar("SELECT executable FROM host_apps WHERE app_id=?")
                .bind(&input.app_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                .flatten();
        let path = saved
            .or_else(|| {
                snapshot
                    .applications
                    .iter()
                    .find(|a| a.app_id == input.app_id)
                    .and_then(|a| a.executable.clone())
            })
            .ok_or(StatusCode::NOT_FOUND)?;
        if protected_program(&path) {
            return Err(StatusCode::LOCKED);
        }
        let observed = snapshot
            .applications
            .iter()
            .find(|a| a.app_id == input.app_id);
        // Pin the observed executable before calling Windows so concurrent
        // history retention cannot discard the rule's owner. This row is only
        // a retention marker; every control decision reads actual OS rules.
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        sqlx::query("INSERT INTO host_apps(app_id,name,executable,first_seen_at,last_seen_at) VALUES(?,?,?,?,?) ON CONFLICT(app_id) DO NOTHING")
            .bind(&input.app_id).bind(observed.map(|a|a.name.as_str()).unwrap_or("Saved application")).bind(&path).bind(Utc::now().to_rfc3339()).bind(Utc::now().to_rfc3339()).execute(&mut *tx).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
        sqlx::query("INSERT INTO host_firewall_rules(app_id,direction,blocked,updated_at) VALUES(?,?,?,?) ON CONFLICT(app_id,direction) DO NOTHING")
            .bind(&input.app_id).bind(&input.direction).bind(input.expected_blocked).bind(Utc::now().to_rfc3339()).execute(&mut *tx).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
        tx.commit()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let audit = AuditLog::new(self.pool.clone());
        let request_id = uuid::Uuid::new_v4().to_string();
        audit.append(NewAuditEntry {occurred_at:Utc::now(),actor:AuditActor::Owner,category:AuditCategory::Enforcement,action:"host.firewall_requested".into(),subject:Some(input.app_id.clone()),detail:json!({"request_id":request_id,"direction":input.direction,"blocked":input.blocked})}).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
        let result=run(json!({"operation":if input.blocked {"block"} else {"release"},"app_id":input.app_id,"direction":input.direction,"expected_blocked":input.expected_blocked,"executable":path})).await;
        audit.append(NewAuditEntry {occurred_at:Utc::now(),actor:AuditActor::Service,category:AuditCategory::Enforcement,action:"host.firewall_result".into(),subject:Some(input.app_id.clone()),detail:json!({"request_id":request_id,"result":result.as_ref().ok(),"failure_status":result.as_ref().err().map(|s|s.as_u16())})}).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
        if result.is_ok() {
            sqlx::query("INSERT INTO host_firewall_rules(app_id,direction,blocked,updated_at) VALUES(?,?,?,?) ON CONFLICT(app_id,direction) DO UPDATE SET blocked=excluded.blocked,updated_at=excluded.updated_at")
                .bind(&input.app_id).bind(&input.direction).bind(input.blocked).bind(Utc::now().to_rfc3339()).execute(&self.pool).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
        }
        result
    }
}
#[cfg(windows)]
async fn run(value: Value) -> Result<Value, StatusCode> {
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut directory = vec![0u16; 4096];
    let len = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            directory.as_mut_ptr(),
            directory.len() as u32,
        )
    } as usize;
    if len == 0 || len >= directory.len() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let program = std::path::PathBuf::from(String::from_utf16_lossy(&directory[..len]))
        .join("WindowsPowerShell/v1.0/powershell.exe");
    let mut command = tokio::process::Command::new(program);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("firewall.ps1"),
        ])
        .creation_flags(0x08000000)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut input = child.stdin.take().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let output = child.stdout.take().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    tokio::time::timeout(std::time::Duration::from_secs(20), async move {
        input
            .write_all(&serde_json::to_vec(&value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        drop(input);
        let mut data = vec![];
        output
            .take(256 * 1024 + 1)
            .read_to_end(&mut data)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if data.len() > 256 * 1024
            || !child
                .wait()
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                .success()
        {
            return Err(StatusCode::CONFLICT);
        }
        serde_json::from_slice(&data).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    })
    .await
    .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
}
#[cfg(not(windows))]
async fn run(_: Value) -> Result<Value, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}
