use anyhow::{Context, ensure};
use chrono::{DateTime, Duration, Utc};
use lattice_domain::{
    DeviceId, DevicePolicy, Identification, OwnerDecision, Protection, RiskSignal,
};
use serde::{Serialize, de::DeserializeOwned};
use sqlx::SqlitePool;

const BASELINE_WINDOW: Duration = Duration::hours(48);
const POLICY_VERSION: i64 = 1;

#[derive(Clone)]
pub struct PolicyRepository {
    pool: SqlitePool,
}

impl PolicyRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Enrolls a known device exactly once against the immutable install
    /// timestamp. Repeated calls return the original cohort membership.
    pub async fn enroll(&self, device_id: DeviceId) -> anyhow::Result<DevicePolicy> {
        let mut tx = self.pool.begin().await?;
        let first_seen: Option<String> =
            sqlx::query_scalar("SELECT first_seen_at FROM devices WHERE device_id=?")
                .bind(device_id.to_string())
                .fetch_optional(&mut *tx)
                .await?;
        let first_seen = parse_time(
            first_seen
                .as_deref()
                .context("cannot enroll policy for an unknown device")?,
            "device first-seen timestamp",
        )?;
        let baseline_started: Option<String> =
            sqlx::query_scalar("SELECT first_run_at FROM install_state WHERE singleton=1")
                .fetch_optional(&mut *tx)
                .await?;
        let baseline_started = parse_time(
            baseline_started
                .as_deref()
                .context("cannot enroll policy before install initialization")?,
            "install first-run timestamp",
        )?;
        let baseline_exempt =
            first_seen >= baseline_started && first_seen < baseline_started + BASELINE_WINDOW;
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT OR IGNORE INTO device_policy(
                device_id, baseline_exempt, identification_json, owner_decision_json,
                risk_json, protection_json, extension_until, extension_used,
                policy_version, enrolled_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?, ?, ?)",
        )
        .bind(device_id.to_string())
        .bind(i64::from(baseline_exempt))
        .bind(encode(&Identification::Unknown)?)
        .bind(encode(&OwnerDecision::Pending)?)
        .bind(encode(&RiskSignal::None)?)
        .bind(encode(&Protection::None)?)
        .bind(POLICY_VERSION)
        .bind(&now)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.load(device_id)
            .await?
            .context("policy missing after enrollment")
    }

    pub async fn load(&self, device_id: DeviceId) -> anyhow::Result<Option<DevicePolicy>> {
        let row: Option<(String, i64, String, String, String, String, Option<String>)> =
            sqlx::query_as(
                "SELECT d.first_seen_at, p.baseline_exempt, p.identification_json,
                        p.owner_decision_json, p.risk_json, p.protection_json,
                        p.extension_until
                 FROM device_policy p
                 JOIN devices d ON d.device_id=p.device_id
                 WHERE p.device_id=?",
            )
            .bind(device_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.map(
            |(
                first_seen,
                baseline_exempt,
                identification,
                owner_decision,
                risk,
                protection,
                extension_until,
            )| {
                Ok(DevicePolicy {
                    device_id,
                    first_seen_at: parse_time(&first_seen, "device first-seen timestamp")?,
                    baseline_exempt: baseline_exempt != 0,
                    identification: decode(&identification, "identification")?,
                    owner_decision: decode(&owner_decision, "owner decision")?,
                    risk: decode(&risk, "risk signal")?,
                    protection: decode(&protection, "protection")?,
                    extension_until: extension_until
                        .as_deref()
                        .map(|value| parse_time(value, "extension timestamp"))
                        .transpose()?,
                })
            },
        )
        .transpose()
    }

    pub async fn set_identification(
        &self,
        device_id: DeviceId,
        value: Identification,
    ) -> anyhow::Result<()> {
        self.update_json(device_id, "identification_json", &value)
            .await
    }

    pub async fn set_owner_decision(
        &self,
        device_id: DeviceId,
        value: OwnerDecision,
    ) -> anyhow::Result<()> {
        self.update_json(device_id, "owner_decision_json", &value)
            .await
    }

    pub async fn set_risk(&self, device_id: DeviceId, value: RiskSignal) -> anyhow::Result<()> {
        self.update_json(device_id, "risk_json", &value).await
    }

    pub async fn set_protection(
        &self,
        device_id: DeviceId,
        value: Protection,
    ) -> anyhow::Result<()> {
        self.update_json(device_id, "protection_json", &value).await
    }

    /// Persists at most one owner extension. Concurrent attempts are resolved
    /// by the `extension_used=0` predicate, so exactly one can succeed.
    pub async fn extend_once(
        &self,
        device_id: DeviceId,
        until: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let current = self
            .load(device_id)
            .await?
            .context("cannot extend an unenrolled device")?;
        ensure!(
            until > current.first_seen_at,
            "extension must be later than first seen"
        );
        let result = sqlx::query(
            "UPDATE device_policy
             SET extension_until=?, extension_used=1, updated_at=?
             WHERE device_id=? AND extension_used=0",
        )
        .bind(until.to_rfc3339())
        .bind(Utc::now().to_rfc3339())
        .bind(device_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn update_json<T: Serialize>(
        &self,
        device_id: DeviceId,
        column: &'static str,
        value: &T,
    ) -> anyhow::Result<()> {
        // `column` is selected only by private typed methods above.
        let statement =
            format!("UPDATE device_policy SET {column}=?, updated_at=? WHERE device_id=?");
        let result = sqlx::query(&statement)
            .bind(encode(value)?)
            .bind(Utc::now().to_rfc3339())
            .bind(device_id.to_string())
            .execute(&self.pool)
            .await?;
        ensure!(result.rows_affected() == 1, "policy device is not enrolled");
        Ok(())
    }
}

fn encode<T: Serialize>(value: &T) -> anyhow::Result<String> {
    serde_json::to_string(value).context("serialize policy value")
}

fn decode<T: DeserializeOwned>(value: &str, label: &str) -> anyhow::Result<T> {
    serde_json::from_str(value).with_context(|| format!("deserialize persisted {label}"))
}

fn parse_time(value: &str, label: &str) -> anyhow::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid persisted {label}"))
        .map(|value| value.with_timezone(&Utc))
}
