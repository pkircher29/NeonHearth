use anyhow::Result;
use lattice_domain::{DeviceId, RequestedAction};
use lattice_w6::DeviceState;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct W6PriorStateRepository {
    pool: SqlitePool,
}
type W6AttemptRow = (String, Option<String>, Option<String>, Option<String>);
#[derive(Clone, Debug)]
pub struct W6Attempt {
    pub restore: DeviceState,
    pub action: RequestedAction,
    pub prepared_before: DeviceState,
    pub verified_after: Option<DeviceState>,
}

impl W6PriorStateRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
    pub async fn save(&self, device: DeviceId, state: &DeviceState) -> Result<()> {
        let json = serde_json::to_string(state)?;
        sqlx::query("INSERT INTO w6_policy_prior_state(device_id,state_json) VALUES(?,?) ON CONFLICT(device_id) DO NOTHING")
            .bind(device.to_string()).bind(json).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn begin_attempt(
        &self,
        device: DeviceId,
        action: RequestedAction,
        before: &DeviceState,
    ) -> Result<()> {
        let state = serde_json::to_string(before)?;
        let action = serde_json::to_string(&action)?;
        sqlx::query("INSERT INTO w6_policy_prior_state(device_id,state_json,action_json,prepared_before_json,verified_after_json) VALUES(?,?,?,?,NULL) ON CONFLICT(device_id) DO UPDATE SET action_json=excluded.action_json, prepared_before_json=excluded.prepared_before_json, verified_after_json=NULL")
            .bind(device.to_string()).bind(&state).bind(action).bind(&state).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn mark_verified(
        &self,
        device: DeviceId,
        action: RequestedAction,
        after: &DeviceState,
    ) -> Result<()> {
        let result=sqlx::query("UPDATE w6_policy_prior_state SET verified_after_json=? WHERE device_id=? AND action_json=? AND prepared_before_json IS NOT NULL").bind(serde_json::to_string(after)?).bind(device.to_string()).bind(serde_json::to_string(&action)?).execute(&self.pool).await?;
        anyhow::ensure!(result.rows_affected() == 1, "missing W6 actuation attempt");
        Ok(())
    }
    pub async fn load_attempt(&self, device: DeviceId) -> Result<Option<W6Attempt>> {
        let row: Option<W6AttemptRow>=sqlx::query_as("SELECT state_json,action_json,prepared_before_json,verified_after_json FROM w6_policy_prior_state WHERE device_id=?").bind(device.to_string()).fetch_optional(&self.pool).await?;
        row.map(|(restore, action, before, after)| match (action, before) {
            (Some(action), Some(before)) => Ok(W6Attempt {
                restore: serde_json::from_str(&restore)?,
                action: serde_json::from_str(&action)?,
                prepared_before: serde_json::from_str(&before)?,
                verified_after: after.map(|x| serde_json::from_str(&x)).transpose()?,
            }),
            _ => anyhow::bail!("incomplete W6 actuation attempt"),
        })
        .transpose()
    }
    pub async fn load(&self, device: DeviceId) -> Result<Option<DeviceState>> {
        let value: Option<String> =
            sqlx::query_scalar("SELECT state_json FROM w6_policy_prior_state WHERE device_id=?")
                .bind(device.to_string())
                .fetch_optional(&self.pool)
                .await?;
        value
            .map(|json| Ok(serde_json::from_str(&json)?))
            .transpose()
    }
    pub async fn remove(&self, device: DeviceId) -> Result<()> {
        sqlx::query("DELETE FROM w6_policy_prior_state WHERE device_id=?")
            .bind(device.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
