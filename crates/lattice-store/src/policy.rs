use anyhow::{Context, ensure};
use chrono::{DateTime, Duration, Utc};
use lattice_domain::{
    AUTOMATIC_IDENTITY_THRESHOLD_BPS, AUTOMATIC_POLICY_DEADLINE_HOURS, DeviceId, DevicePolicy,
    Identification, OwnerDecision, PolicyChanged, Protection, RequestedAction, RiskSignal,
    UNKNOWN_POLICY_DEADLINE_HOURS,
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

/// The crash journal entry which fences a real-world policy mutation.  This is
/// deliberately separate from the event outbox: publication may be retried,
/// but a mutation must first be reconciled with the appliance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActuationAttempt {
    pub policy_version: u32,
    pub action: RequestedAction,
    pub decision: Option<PolicyChanged>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActuationReservation {
    Reserved,
    Existing,
}

/// A pending publication either has its exact event or predates durable event
/// storage. Legacy rows are intentionally distinguishable so callers can
/// project them fail-closed rather than manufacturing a successful result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingDecision {
    Exact(PolicyChanged),
    Legacy,
}

impl PolicyRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn actuation_attempt(
        &self,
        device_id: DeviceId,
    ) -> anyhow::Result<Option<ActuationAttempt>> {
        let row: Option<(i64, String, Option<String>)> = sqlx::query_as(
            "SELECT policy_version, action_json, decision_json FROM policy_actuation_journal WHERE device_id=?",
        )
        .bind(device_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(policy_version, action_json, decision_json)| {
            Ok(ActuationAttempt {
                policy_version: u32::try_from(policy_version)
                    .context("invalid journal policy version")?,
                action: decode(&action_json, "journal action")?,
                decision: decision_json
                    .as_deref()
                    .map(|v| decode(v, "journal decision"))
                    .transpose()?,
            })
        })
        .transpose()
    }

    /// Reserve an exact policy mutation before an actuator can be called.
    /// A different pending mutation is an error, never an implicit overwrite.
    pub async fn reserve_actuation(
        &self,
        device_id: DeviceId,
        policy_version: u32,
        action: RequestedAction,
        now: DateTime<Utc>,
    ) -> anyhow::Result<ActuationReservation> {
        self.reserve_actuation_with_decision(device_id, policy_version, action, now, None)
            .await
    }

    pub async fn reserve_actuation_with_decision(
        &self,
        device_id: DeviceId,
        policy_version: u32,
        action: RequestedAction,
        now: DateTime<Utc>,
        decision: Option<&PolicyChanged>,
    ) -> anyhow::Result<ActuationReservation> {
        let encoded = encode(&action)?;
        let mut tx = self.pool.begin().await?;
        if let Some(existing) = self.actuation_attempt_in(&mut tx, device_id).await? {
            ensure!(
                existing.policy_version == policy_version && existing.action == action,
                "superseded actuation attempt requires explicit reconciliation"
            );
            tx.commit().await?;
            return Ok(ActuationReservation::Existing);
        }
        sqlx::query("INSERT INTO policy_actuation_journal(device_id, policy_version, action_json, reserved_at, decision_json) VALUES(?,?,?,?,?)")
            .bind(device_id.to_string())
            .bind(i64::from(policy_version))
            .bind(encoded)
            .bind(now.to_rfc3339())
            .bind(decision.map(encode).transpose()?)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(ActuationReservation::Reserved)
    }

    pub async fn clear_actuation_attempt(
        &self,
        device_id: DeviceId,
        policy_version: u32,
        action: RequestedAction,
    ) -> anyhow::Result<()> {
        let result = sqlx::query("DELETE FROM policy_actuation_journal WHERE device_id=? AND policy_version=? AND action_json=?")
            .bind(device_id.to_string()).bind(i64::from(policy_version)).bind(encode(&action)?)
            .execute(&self.pool).await?;
        ensure!(
            result.rows_affected() == 1,
            "actuation journal entry changed before acknowledgement"
        );
        Ok(())
    }

    async fn actuation_attempt_in(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        device_id: DeviceId,
    ) -> anyhow::Result<Option<ActuationAttempt>> {
        let row: Option<(i64, String, Option<String>)> = sqlx::query_as(
            "SELECT policy_version, action_json, decision_json FROM policy_actuation_journal WHERE device_id=?",
        )
        .bind(device_id.to_string())
        .fetch_optional(&mut **tx)
        .await?;
        row.map(|(policy_version, action_json, decision_json)| {
            Ok(ActuationAttempt {
                policy_version: u32::try_from(policy_version)
                    .context("invalid journal policy version")?,
                action: decode(&action_json, "journal action")?,
                decision: decision_json
                    .as_deref()
                    .map(|v| decode(v, "journal decision"))
                    .transpose()?,
            })
        })
        .transpose()
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

    /// Returns the durable policy projection for every enrolled device. Runtime
    /// maintenance uses this rather than waiting for another discovery event.
    pub async fn list(&self) -> anyhow::Result<Vec<DevicePolicy>> {
        let ids: Vec<String> =
            sqlx::query_scalar("SELECT device_id FROM device_policy ORDER BY device_id")
                .fetch_all(&self.pool)
                .await?;
        let mut policies = Vec::with_capacity(ids.len());
        for id in ids {
            let id = DeviceId::parse(&id).context("invalid persisted policy device id")?;
            if let Some(policy) = self.load(id).await? {
                policies.push(policy);
            }
        }
        Ok(policies)
    }

    /// Durably prepare event publication.  A matching pending row deliberately
    /// returns true: a crash after publish but before acknowledgement is
    /// retried at-least-once.  Superseded pending rows are discarded only when
    /// a newer current decision is prepared for the same device.
    pub async fn prepare_decision_publication(
        &self,
        device_id: DeviceId,
        fingerprint: &str,
    ) -> anyhow::Result<bool> {
        self.prepare_decision_publication_inner(device_id, fingerprint, None)
            .await
    }

    /// Durably prepares an exact policy event for publication. The fingerprint
    /// is verified against the stored JSON so a pending snapshot can never
    /// combine one event's identity with another event's decision.
    pub async fn prepare_exact_decision_publication(
        &self,
        device_id: DeviceId,
        fingerprint: &str,
        decision: &PolicyChanged,
    ) -> anyhow::Result<bool> {
        let encoded = encode(decision)?;
        ensure!(
            fingerprint == encoded,
            "policy decision fingerprint does not match exact decision"
        );
        self.prepare_decision_publication_inner(device_id, fingerprint, Some(encoded))
            .await
    }

    async fn prepare_decision_publication_inner(
        &self,
        device_id: DeviceId,
        fingerprint: &str,
        decision_json: Option<String>,
    ) -> anyhow::Result<bool> {
        let mut tx = self.pool.begin().await?;
        let published: Option<String> =
            sqlx::query_scalar("SELECT decision_fingerprint FROM device_policy WHERE device_id=?")
                .bind(device_id.to_string())
                .fetch_optional(&mut *tx)
                .await?;
        if published.as_deref() == Some(fingerprint) {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM policy_outbox WHERE device_id=? AND fingerprint<>?")
            .bind(device_id.to_string())
            .bind(fingerprint)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT OR IGNORE INTO policy_outbox(device_id, fingerprint, created_at, decision_json)
             SELECT ?, ?, ?, ?
             WHERE EXISTS (
                 SELECT 1 FROM device_policy
                 WHERE device_id=? AND (decision_fingerprint IS NULL OR decision_fingerprint<>?)
             )",
        )
        .bind(device_id.to_string())
        .bind(fingerprint)
        .bind(Utc::now().to_rfc3339())
        .bind(decision_json.as_deref())
        .bind(device_id.to_string())
        .bind(fingerprint)
        .execute(&mut *tx)
        .await?;
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM policy_outbox WHERE device_id=? AND fingerprint=?",
        )
        .bind(device_id.to_string())
        .bind(fingerprint)
        .fetch_one(&mut *tx)
        .await?;
        if let Some(decision_json) = decision_json {
            let stored: Option<String> = sqlx::query_scalar(
                "SELECT decision_json FROM policy_outbox WHERE device_id=? AND fingerprint=?",
            )
            .bind(device_id.to_string())
            .bind(fingerprint)
            .fetch_one(&mut *tx)
            .await?;
            if let Some(stored) = stored {
                ensure!(
                    stored == decision_json,
                    "pending policy decision differs for matching fingerprint"
                );
            } else {
                sqlx::query(
                    "UPDATE policy_outbox SET decision_json=? WHERE device_id=? AND fingerprint=? AND decision_json IS NULL",
                )
                .bind(&decision_json)
                .bind(device_id.to_string())
                .bind(fingerprint)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1 || pending == 1)
    }

    /// Acknowledge only after the event bus accepted publication. Keeping the
    /// final fingerprint preserves restart deduplication while the outbox
    /// preserves retryability across a crash before this acknowledgement.
    pub async fn mark_decision_published(
        &self,
        device_id: DeviceId,
        fingerprint: &str,
        decision: &PolicyChanged,
    ) -> anyhow::Result<()> {
        self.mark_decision_published_and_clear_attempt(device_id, fingerprint, decision, None)
            .await
    }

    /// Atomically acknowledge the decision/outbox and retire precisely the
    /// matching verified actuation reservation.  Splitting these writes would
    /// leave a post-ack crash window that blocks later owner actions.
    pub async fn mark_decision_published_and_clear_attempt(
        &self,
        device_id: DeviceId,
        fingerprint: &str,
        decision: &PolicyChanged,
        attempt: Option<&ActuationAttempt>,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE device_policy SET decision_fingerprint=?, published_decision_json=?, updated_at=? WHERE device_id=?",
        )
        .bind(fingerprint)
        .bind(encode(decision)?)
        .bind(Utc::now().to_rfc3339())
        .bind(device_id.to_string())
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM policy_outbox WHERE device_id=? AND fingerprint=?")
            .bind(device_id.to_string())
            .bind(fingerprint)
            .execute(&mut *tx)
            .await?;
        if let Some(attempt) = attempt {
            let result = sqlx::query("DELETE FROM policy_actuation_journal WHERE device_id=? AND policy_version=? AND action_json=?")
                .bind(device_id.to_string())
                .bind(i64::from(attempt.policy_version))
                .bind(encode(&attempt.action)?)
                .execute(&mut *tx).await?;
            ensure!(
                result.rows_affected() == 1,
                "actuation journal entry changed before acknowledgement"
            );
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn published_decision(
        &self,
        device_id: DeviceId,
    ) -> anyhow::Result<Option<PolicyChanged>> {
        let value: Option<Option<String>> = sqlx::query_scalar(
            "SELECT published_decision_json FROM device_policy WHERE device_id=?",
        )
        .bind(device_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        value
            .flatten()
            .as_deref()
            .map(|v| decode(v, "published policy decision"))
            .transpose()
    }

    pub async fn pending_decision(&self, device_id: DeviceId) -> anyhow::Result<bool> {
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM policy_outbox WHERE device_id=?")
                .bind(device_id.to_string())
                .fetch_one(&self.pool)
                .await?;
        Ok(pending != 0)
    }

    /// Loads the exact pending event if available. A NULL value only occurs
    /// for rows created before migration 16 or via the legacy wrapper.
    pub async fn pending_decision_value(
        &self,
        device_id: DeviceId,
    ) -> anyhow::Result<Option<PendingDecision>> {
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT fingerprint, decision_json FROM policy_outbox WHERE device_id=?",
        )
        .bind(device_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some((fingerprint, decision_json)) = row else {
            return Ok(None);
        };
        let Some(decision_json) = decision_json else {
            return Ok(Some(PendingDecision::Legacy));
        };
        let decision: PolicyChanged = decode(&decision_json, "pending policy decision")?;
        ensure!(
            encode(&decision)? == fingerprint,
            "pending policy decision fingerprint does not match exact decision"
        );
        ensure!(
            decision.device_id == device_id,
            "pending policy decision device does not match outbox device"
        );
        Ok(Some(PendingDecision::Exact(decision)))
    }

    pub async fn enforcement_retry_due(
        &self,
        device_id: DeviceId,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let retry: Option<Option<String>> =
            sqlx::query_scalar("SELECT enforcement_retry_at FROM device_policy WHERE device_id=?")
                .bind(device_id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        retry
            .flatten()
            .as_deref()
            .map(|at| parse_time(at, "enforcement retry timestamp").map(|at| at <= now))
            .transpose()
            .map(|x| x.unwrap_or(true))
    }

    pub async fn schedule_enforcement_retry(
        &self,
        device_id: DeviceId,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE device_policy SET enforcement_retry_at=? WHERE device_id=?")
            .bind((now + Duration::minutes(1)).to_rfc3339())
            .bind(device_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn clear_enforcement_retry(&self, device_id: DeviceId) -> anyhow::Result<()> {
        sqlx::query("UPDATE device_policy SET enforcement_retry_at=NULL WHERE device_id=?")
            .bind(device_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn release_retry_action(
        &self,
        device_id: DeviceId,
    ) -> anyhow::Result<Option<RequestedAction>> {
        let value: Option<Option<String>> = sqlx::query_scalar(
            "SELECT release_retry_action_json FROM device_policy WHERE device_id=?",
        )
        .bind(device_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        value
            .flatten()
            .map(|v| decode(&v, "release retry action"))
            .transpose()
    }
    pub async fn release_retry_due(
        &self,
        device_id: DeviceId,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let value: Option<Option<String>> =
            sqlx::query_scalar("SELECT release_retry_at FROM device_policy WHERE device_id=?")
                .bind(device_id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        Ok(value
            .flatten()
            .as_deref()
            .map(|v| parse_time(v, "release retry timestamp"))
            .transpose()?
            .map(|v| v <= now)
            .unwrap_or(false))
    }
    pub async fn schedule_release_retry(
        &self,
        device_id: DeviceId,
        action: RequestedAction,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE device_policy SET release_retry_action_json=?, release_retry_at=? WHERE device_id=?").bind(encode(&action)?).bind((now + Duration::minutes(1)).to_rfc3339()).bind(device_id.to_string()).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn clear_release_retry(&self, device_id: DeviceId) -> anyhow::Result<()> {
        sqlx::query("UPDATE device_policy SET release_retry_action_json=NULL, release_retry_at=NULL WHERE device_id=?").bind(device_id.to_string()).execute(&self.pool).await?;
        Ok(())
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

    /// Atomically records an owner-approved release intent and the recovery
    /// reservation that must survive any external undo attempt.
    pub async fn set_owner_decision_and_schedule_release_retry(
        &self,
        device_id: DeviceId,
        value: OwnerDecision,
        action: RequestedAction,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE device_policy SET owner_decision_json=?, release_retry_action_json=?, release_retry_at=?, updated_at=? WHERE device_id=?",
        )
        .bind(encode(&value)?)
        .bind(encode(&action)?)
        .bind((now + Duration::minutes(1)).to_rfc3339())
        .bind(Utc::now().to_rfc3339())
        .bind(device_id.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
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
