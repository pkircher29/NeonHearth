use anyhow::Result;
use lattice_domain::DeviceId;
use lattice_w6::DeviceState;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct W6PriorStateRepository {
    pool: SqlitePool,
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
