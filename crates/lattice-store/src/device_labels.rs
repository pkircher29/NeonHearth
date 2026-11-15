//! Owner labels have no effect on Guard policy or appliance permissions.
use crate::{AuditActor, AuditCategory, M2StateRepository, NewAuditEntry};
use chrono::Utc;
use lattice_domain::DeviceId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct DeviceLabel {
    pub device_id: String,
    pub owner_name: Option<String>,
    pub owner_confirmed: bool,
}

#[derive(Debug, Error)]
pub enum DeviceLabelError {
    #[error("Use a name of 1 to 128 bytes without control or invisible formatting characters.")]
    Invalid,
    #[error("Device not found.")]
    NotFound,
    #[error("The saved name changed. Refresh and review it before saving again.")]
    Conflict,
    #[error("The name could not be saved.")]
    Storage,
}

pub fn valid_device_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.trim() == name
        && !name.chars().any(|c| {
            c.is_control()
                || matches!(c,
            '\u{00ad}' | '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' |
            '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
        })
}

impl M2StateRepository {
    pub async fn device_labels(&self) -> Result<Vec<DeviceLabel>, DeviceLabelError> {
        let rows: Vec<(String, Option<String>, bool)> = sqlx::query_as(
            "SELECT device_id, owner_name, owner_confirmed FROM devices ORDER BY device_id LIMIT 4097"
        ).fetch_all(self.pool()).await.map_err(|_| DeviceLabelError::Storage)?;
        if rows.len() > 4096 {
            return Err(DeviceLabelError::Storage);
        }
        Ok(rows
            .into_iter()
            .map(|(device_id, owner_name, owner_confirmed)| DeviceLabel {
                device_id,
                owner_name,
                owner_confirmed,
            })
            .collect())
    }

    pub async fn confirm_device_name(
        &self,
        device_id: DeviceId,
        name: String,
        expected_name: Option<String>,
        expected_confirmed: bool,
    ) -> Result<DeviceLabel, DeviceLabelError> {
        if !valid_device_name(&name) || expected_name.as_ref().is_some_and(|s| s.len() > 4096) {
            return Err(DeviceLabelError::Invalid);
        }
        let pool = self.pool().clone();
        // Detach the short transaction from HTTP cancellation. Both the label
        // and audit entry commit, or neither does, including during shutdown.
        tokio::spawn(async move {
            let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(|_| DeviceLabelError::Storage)?;
            let id = device_id.to_string();
            let current: Option<(Option<String>, bool)> = sqlx::query_as(
                "SELECT owner_name, owner_confirmed FROM devices WHERE device_id = ?"
            ).bind(&id).fetch_optional(&mut *tx).await.map_err(|_| DeviceLabelError::Storage)?;
            let (previous, confirmed) = current.ok_or(DeviceLabelError::NotFound)?;
            if previous != expected_name || confirmed != expected_confirmed {
                return Err(DeviceLabelError::Conflict);
            }
            if previous.as_deref() != Some(&name) || !confirmed {
                sqlx::query("UPDATE devices SET owner_name = ?, owner_confirmed = 1 WHERE device_id = ?")
                    .bind(&name).bind(&id).execute(&mut *tx).await.map_err(|_| DeviceLabelError::Storage)?;
                crate::audit_log::append_in_transaction(&mut tx, &NewAuditEntry {
                    occurred_at: Utc::now(), actor: AuditActor::Owner, category: AuditCategory::Approval,
                    action: "device.name_confirmed".into(), subject: Some(id.clone()),
                    detail: serde_json::json!({"previous_name":previous,"name":name,"label_only":true}),
                }).await.map_err(|_| DeviceLabelError::Storage)?;
            }
            tx.commit().await.map_err(|_| DeviceLabelError::Storage)?;
            Ok(DeviceLabel { device_id: id, owner_name: Some(name), owner_confirmed: true })
        }).await.map_err(|_| DeviceLabelError::Storage)?
    }
}
