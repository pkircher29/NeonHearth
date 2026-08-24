use anyhow::{Context, ensure};
use chrono::{DateTime, Duration, Utc};
use lattice_domain::{
    AUTOMATIC_IDENTITY_THRESHOLD_BPS, AUTOMATIC_POLICY_DEADLINE_HOURS, DeviceId, DevicePolicy,
    Identification, OwnerDecision, Protection, RiskSignal, UNKNOWN_POLICY_DEADLINE_HOURS,
};
use serde::{Serialize, de::DeserializeOwned};
use sqlx::SqlitePool;

#[derive(sqlx::FromRow)]
struct PolicyRow {
    first_seen_at: String,
    baseline_exempt: i64,
    identification_json: String,
    owner_decision_json: String,
    risk_json: String,
    protection_json: String,
    extension_until: Option<String>,
}

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

    /// Persists the first point at which the service has successfully bound
    /// its listener. Later starts and wall-clock changes cannot replace it.
    pub async fn mark_successful_service_start(
        &self,
        now: DateTime<Utc>,
    ) -> anyhow::Result<DateTime<Utc>> {
        let mut tx = self.pool.begin().await?;
        let install_exists: Option<i64> =
            sqlx::query_scalar("SELECT singleton FROM install_state WHERE singleton=1")
                .fetch_optional(&mut *tx)
                .await?;
        ensure!(
            install_exists.is_some(),
            "cannot start policy baseline before install initialization"
        );
        sqlx::query(
            "INSERT OR IGNORE INTO policy_install_state(singleton, baseline_started_at)
             VALUES(1, ?)",
        )
        .bind(now.to_rfc3339())
        .execute(&mut *tx)
        .await?;
        let persisted: String = sqlx::query_scalar(
            "SELECT baseline_started_at FROM policy_install_state WHERE singleton=1",
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        parse_time(&persisted, "policy baseline timestamp")
    }

    pub async fn baseline_started_at(&self) -> anyhow::Result<Option<DateTime<Utc>>> {
        let persisted: Option<String> = sqlx::query_scalar(
            "SELECT baseline_started_at FROM policy_install_state WHERE singleton=1",
        )
        .fetch_optional(&self.pool)
        .await?;
        persisted
            .as_deref()
            .map(|value| parse_time(value, "policy baseline timestamp"))
            .transpose()
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
        let baseline_started: Option<String> = sqlx::query_scalar(
            "SELECT baseline_started_at FROM policy_install_state WHERE singleton=1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let baseline_started = parse_time(
            baseline_started
                .as_deref()
                .context("cannot enroll policy before a successful service start")?,
            "policy baseline timestamp",
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
        let row: Option<PolicyRow> = sqlx::query_as(
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
        row.map(|row| {
            Ok(DevicePolicy {
                device_id,
                first_seen_at: parse_time(&row.first_seen_at, "device first-seen timestamp")?,
                baseline_exempt: row.baseline_exempt != 0,
                identification: decode(&row.identification_json, "identification")?,
                owner_decision: decode(&row.owner_decision_json, "owner decision")?,
                risk: decode(&row.risk_json, "risk signal")?,
                protection: decode(&row.protection_json, "protection")?,
                extension_until: row
                    .extension_until
                    .as_deref()
                    .map(|value| parse_time(value, "extension timestamp"))
                    .transpose()?,
            })
        })
        .transpose()
    }

    /// Atomically records the last externally published decision fingerprint.
    /// Returns true only when a new typed event must be emitted.
    pub async fn record_decision_fingerprint(
        &self,
        device_id: DeviceId,
        fingerprint: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE device_policy SET decision_fingerprint=?, updated_at=?
             WHERE device_id=? AND (decision_fingerprint IS NULL OR decision_fingerprint<>?)",
        )
        .bind(fingerprint)
        .bind(Utc::now().to_rfc3339())
        .bind(device_id.to_string())
        .bind(fingerprint)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
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
        let automatically_identified = match &current.identification {
            Identification::Automatic {
                confidence_basis_points: AUTOMATIC_IDENTITY_THRESHOLD_BPS..,
                evidence_families,
            } => {
                evidence_families
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    >= 2
            }
            Identification::Unknown | Identification::Automatic { .. } => false,
        };
        let deadline_hours = if automatically_identified {
            AUTOMATIC_POLICY_DEADLINE_HOURS
        } else {
            UNKNOWN_POLICY_DEADLINE_HOURS
        };
        let original_due_at = current.first_seen_at + Duration::hours(deadline_hours);
        ensure!(
            until > original_due_at,
            "extension must move the applicable deadline later"
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
