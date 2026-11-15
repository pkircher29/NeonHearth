use anyhow::{Context, ensure};
use chrono::{DateTime, Duration, Utc};
use lattice_domain::{
    AUTOMATIC_IDENTITY_THRESHOLD_BPS, AUTOMATIC_POLICY_DEADLINE_HOURS, DeviceId, DevicePolicy,
    Identification, OwnerDecision, PolicyChanged, Protection, RequestedAction, RiskSignal,
    UNKNOWN_POLICY_DEADLINE_HOURS,
};
use serde::{Serialize, de::DeserializeOwned};
use sqlx::SqlitePool;
use std::collections::HashMap;

/// Largest `IN (...)` list one batched query binds; well under SQLite's
/// default 32766 variable limit and keeps statements short.
const SQL_BATCH_SIZE: usize = 256;

#[derive(sqlx::FromRow)]
struct KeyedPolicyRow {
    device_id: String,
    #[sqlx(flatten)]
    policy: PolicyRow,
}

/// Current version of the `*_json` column encodings. Rows written before
/// migration 029 carry 1 (same encoding); anything newer than this is skipped
/// and reported instead of being mis-decoded.
const JSON_SCHEMA_VERSION: i64 = 2;
/// Longest owner extension beyond the original deadline.
pub const MAX_EXTENSION: Duration = Duration::days(30);
/// Basis points are 0..=10_000.
const MAX_BASIS_POINTS: u16 = 10_000;
/// Clock readings before this cannot be real for this software.
pub const MIN_PLAUSIBLE_CLOCK_UNIX: i64 = 1_735_689_600; // 2025-01-01T00:00:00Z
/// A forward jump larger than this since the last heartbeat is suspicious.
pub const MAX_PLAUSIBLE_CLOCK_GAP: Duration = Duration::days(30);
/// Backwards movement tolerated before the clock is considered unreliable.
pub const CLOCK_BACKWARD_TOLERANCE: Duration = Duration::hours(1);

const POLICY_SELECT_ONE: &str = "SELECT p.json_schema_version, COALESCE(p.first_seen_at, d.first_seen_at) AS first_seen_at, p.baseline_exempt, p.identification_json,
                        p.owner_decision_json, p.risk_json, p.protection_json,
                        p.extension_until
                 FROM device_policy p
                 JOIN devices d ON d.device_id=p.device_id
                 WHERE p.device_id=?";
const POLICY_SELECT_MANY: &str = "SELECT p.device_id, p.json_schema_version, COALESCE(p.first_seen_at, d.first_seen_at) AS first_seen_at, p.baseline_exempt, p.identification_json,
                        p.owner_decision_json, p.risk_json, p.protection_json,
                        p.extension_until
                 FROM device_policy p
                 JOIN devices d ON d.device_id=p.device_id
                 WHERE p.device_id IN (";
const POLICY_SELECT_ALL: &str = "SELECT p.device_id, p.json_schema_version, COALESCE(p.first_seen_at, d.first_seen_at) AS first_seen_at, p.baseline_exempt, p.identification_json,
                        p.owner_decision_json, p.risk_json, p.protection_json,
                        p.extension_until
                 FROM device_policy p
                 JOIN devices d ON d.device_id=p.device_id";

/// A policy row that could not be decoded and was left out of a batch result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkippedPolicyRow {
    pub device_id: String,
    pub reason: String,
}

/// Stable short fingerprint of a policy decision. Legacy rows used the whole
/// serialized decision as the fingerprint; both spellings are still accepted
/// everywhere and compare equal when they describe the same decision.
pub fn decision_fingerprint(decision: &PolicyChanged) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(encode(decision)?.as_bytes());
    let mut out = String::from("v2:");
    for byte in &digest[..16] {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

fn normalize_fingerprint(fingerprint: &str) -> String {
    if fingerprint.starts_with("v2:") {
        return fingerprint.to_owned();
    }
    match serde_json::from_str::<PolicyChanged>(fingerprint)
        .ok()
        .and_then(|decision| decision_fingerprint(&decision).ok())
    {
        Some(normalized) => normalized,
        None => fingerprint.to_owned(),
    }
}

fn fingerprints_match(left: &str, right: &str) -> bool {
    left == right || normalize_fingerprint(left) == normalize_fingerprint(right)
}

/// True when `fingerprint` identifies exactly `decision` (new or legacy form).
fn fingerprint_binds(fingerprint: &str, decision: &PolicyChanged) -> bool {
    if decision_fingerprint(decision).is_ok_and(|new| new == fingerprint) {
        return true;
    }
    if encode(decision).is_ok_and(|text| text == fingerprint) {
        return true;
    }
    serde_json::from_str::<PolicyChanged>(fingerprint).is_ok_and(|decoded| &decoded == decision)
}

fn check_basis_points(value: u16) -> anyhow::Result<()> {
    ensure!(value <= MAX_BASIS_POINTS, "basis points must be 0..=10000");
    Ok(())
}

fn pending_from_row(
    device_id: DeviceId,
    fingerprint: &str,
    decision_json: Option<&str>,
) -> anyhow::Result<PendingDecision> {
    let Some(decision_json) = decision_json else {
        return Ok(PendingDecision::Legacy);
    };
    let decision: PolicyChanged = decode(decision_json, "pending policy decision")?;
    ensure!(
        fingerprint_binds(fingerprint, &decision),
        "pending policy decision fingerprint does not match exact decision"
    );
    ensure!(
        decision.device_id == device_id,
        "pending policy decision device does not match outbox device"
    );
    Ok(PendingDecision::Exact(decision))
}

fn policy_from_row(device_id: DeviceId, row: PolicyRow) -> anyhow::Result<DevicePolicy> {
    ensure!(
        row.json_schema_version <= JSON_SCHEMA_VERSION,
        "policy row uses unsupported json schema version {}",
        row.json_schema_version
    );
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
}

fn collect_policies(
    rows: Vec<KeyedPolicyRow>,
    policies: &mut HashMap<DeviceId, DevicePolicy>,
    skipped: &mut Vec<SkippedPolicyRow>,
) {
    for keyed in rows {
        let device_id = match DeviceId::parse(&keyed.device_id) {
            Ok(id) => id,
            Err(error) => {
                skipped.push(SkippedPolicyRow {
                    device_id: keyed.device_id,
                    reason: format!("invalid persisted policy device id: {error}"),
                });
                continue;
            }
        };
        match policy_from_row(device_id, keyed.policy) {
            Ok(policy) => {
                policies.insert(device_id, policy);
            }
            Err(error) => skipped.push(SkippedPolicyRow {
                device_id: keyed.device_id,
                reason: format!("{error:#}"),
            }),
        }
    }
}

/// Result of the clock plausibility gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClockStatus {
    Trusted,
    /// Deadline-driven enforcement must be suppressed while this holds.
    Suspect(String),
}

impl ClockStatus {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    json_schema_version: i64,
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
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
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
        // An already-persisted baseline is returned unchanged even on a bad
        // clock; only *creating* the immutable baseline needs a sane clock.
        if let Some(existing) = self.baseline_started_at().await? {
            return Ok(existing);
        }
        ensure!(
            now.timestamp() >= MIN_PLAUSIBLE_CLOCK_UNIX,
            "system clock is not plausible; refusing to start the policy baseline until it is corrected"
        );
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
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
        // These transactions read before writing. Acquire the writer reservation
        // first so concurrent discovery, home edits, and HA updates can wait
        // without a deferred read-to-write upgrade failing immediately.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
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
        let baseline_exempt = baseline_started
            .checked_add_signed(BASELINE_WINDOW)
            .is_some_and(|end| first_seen >= baseline_started && first_seen < end);
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT OR IGNORE INTO device_policy(
                device_id, baseline_exempt, identification_json, owner_decision_json,
                risk_json, protection_json, extension_until, extension_used,
                policy_version, enrolled_at, updated_at, first_seen_at, json_schema_version
             ) VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?, ?, ?, ?, ?)",
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
        .bind(first_seen.to_rfc3339())
        .bind(JSON_SCHEMA_VERSION)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.load(device_id)
            .await?
            .context("policy missing after enrollment")
    }

    pub async fn load(&self, device_id: DeviceId) -> anyhow::Result<Option<DevicePolicy>> {
        let row: Option<PolicyRow> = sqlx::query_as(POLICY_SELECT_ONE)
            .bind(device_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| policy_from_row(device_id, row)).transpose()
    }

    /// Loads the policy rows for many devices, keyed by device. Devices
    /// without a policy row are absent. A row that cannot be decoded is
    /// skipped (and logged) rather than failing the whole batch; use
    /// [`Self::load_many_report`] to see what was skipped.
    pub async fn load_many(
        &self,
        device_ids: &[DeviceId],
    ) -> anyhow::Result<HashMap<DeviceId, DevicePolicy>> {
        Ok(self.load_many_report(device_ids).await?.0)
    }

    pub async fn load_many_report(
        &self,
        device_ids: &[DeviceId],
    ) -> anyhow::Result<(HashMap<DeviceId, DevicePolicy>, Vec<SkippedPolicyRow>)> {
        let mut policies = HashMap::with_capacity(device_ids.len());
        let mut skipped = Vec::new();
        for chunk in device_ids.chunks(SQL_BATCH_SIZE) {
            let mut query = sqlx::QueryBuilder::new(POLICY_SELECT_MANY);
            let mut separated = query.separated(", ");
            for id in chunk {
                separated.push_bind(id.to_string());
            }
            separated.push_unseparated(")");
            let rows: Vec<KeyedPolicyRow> = query.build_query_as().fetch_all(&self.pool).await?;
            collect_policies(rows, &mut policies, &mut skipped);
        }
        for row in &skipped {
            tracing::warn!(device_id = %row.device_id, reason = %row.reason, "skipping undecodable policy row");
        }
        Ok((policies, skipped))
    }

    /// Loads the published decisions for many devices in one query. Devices
    /// with no published decision are absent from the map.
    pub async fn published_decisions_many(
        &self,
        device_ids: &[DeviceId],
    ) -> anyhow::Result<HashMap<DeviceId, PolicyChanged>> {
        let mut decisions = HashMap::new();
        for chunk in device_ids.chunks(SQL_BATCH_SIZE) {
            let mut query = sqlx::QueryBuilder::new(
                "SELECT device_id, published_decision_json FROM device_policy WHERE device_id IN (",
            );
            let mut separated = query.separated(", ");
            for id in chunk {
                separated.push_bind(id.to_string());
            }
            separated.push_unseparated(")");
            let rows: Vec<(String, Option<String>)> =
                query.build_query_as().fetch_all(&self.pool).await?;
            for (id, value) in rows {
                let Some(value) = value else { continue };
                let Ok(device_id) = DeviceId::parse(&id) else {
                    tracing::warn!(%id, "skipping policy row with invalid device id");
                    continue;
                };
                match decode(&value, "published policy decision") {
                    Ok(decision) => {
                        decisions.insert(device_id, decision);
                    }
                    Err(error) => {
                        tracing::warn!(%id, %error, "skipping undecodable published policy decision");
                    }
                }
            }
        }
        Ok(decisions)
    }

    /// Loads the pending outbox decisions for many devices in one query, with
    /// the same exact/legacy distinction as [`Self::pending_decision_value`].
    pub async fn pending_decision_values_many(
        &self,
        device_ids: &[DeviceId],
    ) -> anyhow::Result<HashMap<DeviceId, PendingDecision>> {
        let mut pending = HashMap::new();
        for chunk in device_ids.chunks(SQL_BATCH_SIZE) {
            let mut query = sqlx::QueryBuilder::new(
                "SELECT device_id, fingerprint, decision_json FROM policy_outbox WHERE json_schema_version <= 2 AND device_id IN (",
            );
            let mut separated = query.separated(", ");
            for id in chunk {
                separated.push_bind(id.to_string());
            }
            separated.push_unseparated(")");
            let rows: Vec<(String, String, Option<String>)> =
                query.build_query_as().fetch_all(&self.pool).await?;
            for (id, fingerprint, decision_json) in rows {
                let Ok(device_id) = DeviceId::parse(&id) else {
                    tracing::warn!(%id, "skipping outbox row with invalid device id");
                    continue;
                };
                match pending_from_row(device_id, &fingerprint, decision_json.as_deref()) {
                    Ok(value) => {
                        pending.insert(device_id, value);
                    }
                    Err(error) => {
                        tracing::warn!(%id, %error, "skipping unreadable pending policy decision");
                    }
                }
            }
        }
        Ok(pending)
    }

    pub async fn list(&self) -> anyhow::Result<Vec<DevicePolicy>> {
        Ok(self.list_report().await?.0)
    }

    /// Every enrolled device's policy in one query. Undecodable rows are
    /// skipped and returned in the second element.
    pub async fn list_report(&self) -> anyhow::Result<(Vec<DevicePolicy>, Vec<SkippedPolicyRow>)> {
        let rows: Vec<KeyedPolicyRow> =
            sqlx::query_as(&format!("{POLICY_SELECT_ALL} ORDER BY p.device_id"))
                .fetch_all(&self.pool)
                .await?;
        let mut map = HashMap::new();
        let mut skipped = Vec::new();
        collect_policies(rows, &mut map, &mut skipped);
        let mut policies: Vec<DevicePolicy> = map.into_values().collect();
        policies.sort_by_key(|policy| policy.device_id.to_string());
        for row in &skipped {
            tracing::warn!(device_id = %row.device_id, reason = %row.reason, "skipping undecodable policy row");
        }
        Ok((policies, skipped))
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
            fingerprint_binds(fingerprint, decision),
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
        let mut tx = crate::begin_write(&self.pool).await?;
        let published: Option<Option<String>> =
            sqlx::query_scalar("SELECT decision_fingerprint FROM device_policy WHERE device_id=?")
                .bind(device_id.to_string())
                .fetch_optional(&mut *tx)
                .await?;
        let Some(published) = published else {
            tx.commit().await?;
            return Ok(false);
        };
        if published
            .as_deref()
            .is_some_and(|stored| fingerprints_match(stored, fingerprint))
        {
            tx.commit().await?;
            return Ok(false);
        }
        let existing: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT fingerprint, decision_json FROM policy_outbox WHERE device_id=?",
        )
        .bind(device_id.to_string())
        .fetch_all(&mut *tx)
        .await?;
        let mut matching: Option<(String, Option<String>)> = None;
        for (stored, stored_decision) in existing {
            if fingerprints_match(&stored, fingerprint) {
                matching = Some((stored, stored_decision));
            } else {
                // A newer decision supersedes any other pending one.
                sqlx::query("DELETE FROM policy_outbox WHERE device_id=? AND fingerprint=?")
                    .bind(device_id.to_string())
                    .bind(&stored)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        match matching {
            None => {
                sqlx::query(
                    "INSERT INTO policy_outbox(device_id, fingerprint, created_at, decision_json, json_schema_version) VALUES(?,?,?,?,?)",
                )
                .bind(device_id.to_string())
                .bind(fingerprint)
                .bind(Utc::now().to_rfc3339())
                .bind(decision_json.as_deref())
                .bind(JSON_SCHEMA_VERSION)
                .execute(&mut *tx)
                .await?;
            }
            Some((stored_fingerprint, stored_decision)) => {
                if let Some(decision_json) = decision_json.as_deref() {
                    match stored_decision {
                        Some(stored) => {
                            let same = stored == decision_json
                                || matches!(
                                    (
                                        serde_json::from_str::<PolicyChanged>(&stored),
                                        serde_json::from_str::<PolicyChanged>(decision_json),
                                    ),
                                    (Ok(a), Ok(b)) if a == b
                                );
                            ensure!(
                                same,
                                "pending policy decision differs for matching fingerprint"
                            );
                        }
                        None => {
                            sqlx::query(
                                "UPDATE policy_outbox SET decision_json=? WHERE device_id=? AND fingerprint=? AND decision_json IS NULL",
                            )
                            .bind(decision_json)
                            .bind(device_id.to_string())
                            .bind(&stored_fingerprint)
                            .execute(&mut *tx)
                            .await?;
                        }
                    }
                }
            }
        }
        tx.commit().await?;
        Ok(true)
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
        let mut tx = crate::begin_write(&self.pool).await?;
        sqlx::query(
            "UPDATE device_policy SET decision_fingerprint=?, published_decision_json=?, updated_at=? WHERE device_id=?",
        )
        .bind(fingerprint)
        .bind(encode(decision)?)
        .bind(Utc::now().to_rfc3339())
        .bind(device_id.to_string())
        .execute(&mut *tx)
        .await?;
        let outbox: Vec<String> =
            sqlx::query_scalar("SELECT fingerprint FROM policy_outbox WHERE device_id=?")
                .bind(device_id.to_string())
                .fetch_all(&mut *tx)
                .await?;
        for stored in outbox
            .into_iter()
            .filter(|stored| fingerprints_match(stored, fingerprint))
        {
            sqlx::query("DELETE FROM policy_outbox WHERE device_id=? AND fingerprint=?")
                .bind(device_id.to_string())
                .bind(stored)
                .execute(&mut *tx)
                .await?;
        }
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
        pending_from_row(device_id, &fingerprint, decision_json.as_deref()).map(Some)
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
        if let Identification::Automatic {
            confidence_basis_points,
            ..
        } = &value
        {
            check_basis_points(*confidence_basis_points)?;
        }
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
        let mut tx = crate::begin_write(&self.pool).await?;
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
        if let RiskSignal::HighConfidenceDanger {
            confidence_basis_points,
            ..
        } = &value
        {
            check_basis_points(*confidence_basis_points)?;
        }
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
    ///
    /// `until` must be later than the applicable original deadline and at most
    /// [`MAX_EXTENSION`] after it, so "extend once" cannot become "exempt
    /// forever". Use [`Self::extend_once_at`] to also reject extensions that
    /// are already in the past (which would burn the single extension).
    pub async fn extend_once(
        &self,
        device_id: DeviceId,
        until: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        self.extend_once_inner(device_id, until, None).await
    }

    pub async fn extend_once_at(
        &self,
        device_id: DeviceId,
        until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        self.extend_once_inner(device_id, until, Some(now)).await
    }

    async fn extend_once_inner(
        &self,
        device_id: DeviceId,
        until: DateTime<Utc>,
        now: Option<DateTime<Utc>>,
    ) -> anyhow::Result<bool> {
        // Read and write in one writer-reserved transaction so the deadline
        // the bound is checked against cannot change underneath the UPDATE.
        let mut tx = crate::begin_write(&self.pool).await?;
        let row: Option<PolicyRow> = sqlx::query_as(POLICY_SELECT_ONE)
            .bind(device_id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
        let current = policy_from_row(
            device_id,
            row.context("cannot extend an unenrolled device")?,
        )?;
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
        let original_due_at = current
            .first_seen_at
            .checked_add_signed(Duration::hours(deadline_hours))
            .context("deadline overflows the calendar")?;
        ensure!(
            until > original_due_at,
            "extension must move the applicable deadline later"
        );
        ensure!(
            original_due_at
                .checked_add_signed(MAX_EXTENSION)
                .is_some_and(|limit| until <= limit),
            "extension is longer than the permitted maximum"
        );
        if let Some(now) = now {
            ensure!(until > now, "extension must end in the future");
        }
        let result = sqlx::query(
            "UPDATE device_policy
             SET extension_until=?, extension_used=1, updated_at=?
             WHERE device_id=? AND extension_used=0",
        )
        .bind(until.to_rfc3339())
        .bind(Utc::now().to_rfc3339())
        .bind(device_id.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    async fn update_json<T: Serialize>(
        &self,
        device_id: DeviceId,
        column: &'static str,
        value: &T,
    ) -> anyhow::Result<()> {
        // `column` is selected only by private typed methods above.
        let statement = format!(
            "UPDATE device_policy SET {column}=?, updated_at=?, json_schema_version=MAX(json_schema_version, {JSON_SCHEMA_VERSION}) WHERE device_id=?"
        );
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

impl PolicyRepository {
    /// Records that the service is alive at `now` and updates the clock
    /// plausibility state. A backwards step, a forward jump of more than
    /// [`MAX_PLAUSIBLE_CLOCK_GAP`], or a clock before
    /// [`MIN_PLAUSIBLE_CLOCK_UNIX`] makes [`Self::clock_status`] report
    /// `Suspect`; the heartbeat only advances while the clock is trusted, and a
    /// suspect state is sticky until [`Self::acknowledge_clock`].
    pub async fn record_clock_heartbeat(&self, now: DateTime<Utc>) -> anyhow::Result<ClockStatus> {
        let mut tx = crate::begin_write(&self.pool).await?;
        let state: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT last_heartbeat_at, suspect_reason FROM policy_clock_state WHERE singleton=1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        if now.timestamp() < MIN_PLAUSIBLE_CLOCK_UNIX {
            tx.commit().await?;
            return Ok(ClockStatus::Suspect(
                "system clock is earlier than the earliest plausible date".into(),
            ));
        }
        let status = match state {
            None => {
                sqlx::query(
                    "INSERT INTO policy_clock_state(singleton,last_heartbeat_at) VALUES(1,?)",
                )
                .bind(now.to_rfc3339())
                .execute(&mut *tx)
                .await?;
                ClockStatus::Trusted
            }
            Some((_, Some(reason))) => ClockStatus::Suspect(reason),
            Some((last, None)) => {
                let last = parse_time(&last, "clock heartbeat")?;
                let reason = if now < last - CLOCK_BACKWARD_TOLERANCE {
                    Some("system clock moved backwards")
                } else if now - last > MAX_PLAUSIBLE_CLOCK_GAP {
                    Some("system clock jumped far forward")
                } else {
                    None
                };
                match reason {
                    Some(reason) => {
                        sqlx::query(
                            "UPDATE policy_clock_state SET suspect_reason=? WHERE singleton=1",
                        )
                        .bind(reason)
                        .execute(&mut *tx)
                        .await?;
                        ClockStatus::Suspect(reason.into())
                    }
                    None => {
                        if now > last {
                            sqlx::query("UPDATE policy_clock_state SET last_heartbeat_at=? WHERE singleton=1")
                                .bind(now.to_rfc3339())
                                .execute(&mut *tx)
                                .await?;
                        }
                        ClockStatus::Trusted
                    }
                }
            }
        };
        tx.commit().await?;
        Ok(status)
    }

    /// Read-only view of the clock gate. Deadline enforcement must be
    /// suppressed (treated as owner attention) unless this is `Trusted`.
    pub async fn clock_status(&self, now: DateTime<Utc>) -> anyhow::Result<ClockStatus> {
        if now.timestamp() < MIN_PLAUSIBLE_CLOCK_UNIX {
            return Ok(ClockStatus::Suspect(
                "system clock is earlier than the earliest plausible date".into(),
            ));
        }
        let state: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT last_heartbeat_at, suspect_reason FROM policy_clock_state WHERE singleton=1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(match state {
            None => ClockStatus::Trusted,
            Some((_, Some(reason))) => ClockStatus::Suspect(reason),
            Some((last, None)) => {
                let last = parse_time(&last, "clock heartbeat")?;
                if now < last - CLOCK_BACKWARD_TOLERANCE {
                    ClockStatus::Suspect("system clock moved backwards".into())
                } else if now - last > MAX_PLAUSIBLE_CLOCK_GAP {
                    ClockStatus::Suspect("system clock jumped far forward".into())
                } else {
                    ClockStatus::Trusted
                }
            }
        })
    }

    /// Owner-confirmed resolution of a suspect clock: accepts `now` as the new
    /// reference. Audited. Fails when `now` itself is implausible.
    pub async fn acknowledge_clock(&self, now: DateTime<Utc>, reason: &str) -> anyhow::Result<()> {
        ensure!(
            now.timestamp() >= MIN_PLAUSIBLE_CLOCK_UNIX,
            "cannot acknowledge an implausible clock"
        );
        let mut tx = crate::begin_write(&self.pool).await?;
        sqlx::query(
            "INSERT INTO policy_clock_state(singleton,last_heartbeat_at,suspect_reason) VALUES(1,?,NULL)
             ON CONFLICT(singleton) DO UPDATE SET last_heartbeat_at=excluded.last_heartbeat_at, suspect_reason=NULL",
        )
        .bind(now.to_rfc3339())
        .execute(&mut *tx)
        .await?;
        crate::audit_log::append_in_transaction(
            &mut tx,
            &crate::NewAuditEntry {
                occurred_at: now,
                actor: crate::AuditActor::Owner,
                category: crate::AuditCategory::Approval,
                action: "policy_clock_acknowledged".into(),
                subject: None,
                detail: serde_json::json!({ "reason": reason }),
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!("audit append failed: {error}"))?;
        tx.commit().await?;
        Ok(())
    }

    /// Replaces the baseline start with `now` (owner action). The previous
    /// value is kept in `policy_baseline_history` and an audit entry is
    /// appended in the same transaction. Devices first seen inside the new
    /// 48 h window become baseline-exempt; nothing is ever un-exempted.
    pub async fn reset_baseline(
        &self,
        now: DateTime<Utc>,
        reason: &str,
    ) -> anyhow::Result<DateTime<Utc>> {
        ensure!(
            now.timestamp() >= MIN_PLAUSIBLE_CLOCK_UNIX,
            "cannot start a baseline from an implausible clock"
        );
        ensure!(
            !reason.trim().is_empty() && reason.len() <= 512,
            "a baseline reset needs a reason of 1..=512 bytes"
        );
        let mut tx = crate::begin_write(&self.pool).await?;
        let previous: Option<String> = sqlx::query_scalar(
            "SELECT baseline_started_at FROM policy_install_state WHERE singleton=1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO policy_install_state(singleton, baseline_started_at) VALUES(1, ?)
             ON CONFLICT(singleton) DO UPDATE SET baseline_started_at=excluded.baseline_started_at",
        )
        .bind(now.to_rfc3339())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO policy_baseline_history(changed_at, previous_baseline, new_baseline, reason) VALUES(?,?,?,?)",
        )
        .bind(now.to_rfc3339())
        .bind(previous.as_deref())
        .bind(now.to_rfc3339())
        .bind(reason)
        .execute(&mut *tx)
        .await?;
        let window_end = now
            .checked_add_signed(BASELINE_WINDOW)
            .context("baseline window overflows the calendar")?;
        sqlx::query(
            "UPDATE device_policy SET baseline_exempt=1
             WHERE baseline_exempt=0
               AND unixepoch(COALESCE(first_seen_at,(SELECT first_seen_at FROM devices d WHERE d.device_id=device_policy.device_id))) >= ?
               AND unixepoch(COALESCE(first_seen_at,(SELECT first_seen_at FROM devices d WHERE d.device_id=device_policy.device_id))) < ?",
        )
        .bind(now.timestamp())
        .bind(window_end.timestamp())
        .execute(&mut *tx)
        .await?;
        crate::audit_log::append_in_transaction(
            &mut tx,
            &crate::NewAuditEntry {
                occurred_at: now,
                actor: crate::AuditActor::Owner,
                category: crate::AuditCategory::Approval,
                action: "policy_baseline_reset".into(),
                subject: None,
                detail: serde_json::json!({ "reason": reason, "previous": previous }),
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!("audit append failed: {error}"))?;
        tx.commit().await?;
        Ok(now)
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
