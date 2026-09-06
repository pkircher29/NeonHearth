use crate::FlowRepository;
use chrono::{DateTime, Utc};
use lattice_domain::{
    Coverage, DeviceId, EvidenceFact, EvidenceFamily, PresenceChanged, PresenceState,
};
use lattice_sensor::{flow::RollupChange, neighbor::LinkAddress};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::{Sqlite, SqlitePool, Transaction};
use std::collections::HashSet;
use thiserror::Error;

pub const MAX_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BATCH: usize = 4096;
/// Bounds the per-device snapshot follow-up reads to a small home-network page.
pub const MAX_SNAPSHOT_DEVICES: usize = 256;
const CURRENT_FORMAT_VERSION: i64 = 1;
type StoredCheckpointRow = (i64, Vec<u8>, String, i64, String, Vec<u8>);
type StoredDiscoveryRow = (
    String,
    Vec<u8>,
    String,
    Vec<u8>,
    i64,
    String,
    Vec<u8>,
    Vec<u8>,
);
type StoredTransitionRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    Option<i64>,
);

#[derive(Clone, Debug)]
pub struct M2StateConfig {
    pub max_checkpoint_bytes: usize,
    pub max_discovery_summary_bytes: usize,
    pub max_batch: usize,
    pub max_string_bytes: usize,
    pub max_snapshot_devices: usize,
}
impl Default for M2StateConfig {
    fn default() -> Self {
        Self {
            max_checkpoint_bytes: MAX_CHECKPOINT_BYTES,
            max_discovery_summary_bytes: 1024 * 1024,
            max_batch: MAX_BATCH,
            max_string_bytes: 4096,
            max_snapshot_devices: MAX_SNAPSHOT_DEVICES,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceProjection {
    pub device_id: DeviceId,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub owner_name: Option<String>,
    pub owner_type: Option<String>,
    pub owner_confirmed: bool,
}
#[derive(Clone, Debug, PartialEq)]
pub struct StoredPresenceSummary {
    pub to_state: PresenceState,
    pub occurred_at: DateTime<Utc>,
    pub trigger_source: String,
    pub trigger_kind: String,
}
#[derive(Clone, Debug, PartialEq)]
pub struct StoredEvidenceSummary {
    pub family: EvidenceFamily,
    pub source: String,
    pub confidence: f32,
    pub observed_at: DateTime<Utc>,
    /// The evidence expiry as recorded by the sensor, if one was supplied.
    pub expires_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBandwidthSummary {
    pub upload: u64,
    pub download: u64,
    pub coverage: Coverage,
    pub observed_at: DateTime<Utc>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct StoredDeviceSnapshot {
    pub device_id: DeviceId,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub owner_name: Option<String>,
    pub owner_type: Option<String>,
    pub owner_confirmed: bool,
    pub presence: Option<StoredPresenceSummary>,
    pub evidence: Option<StoredEvidenceSummary>,
    pub bandwidth: Option<StoredBandwidthSummary>,
}
#[derive(Clone, Debug)]
pub struct EvidenceProjection {
    pub device_id: DeviceId,
    pub fact: EvidenceFact,
}
#[derive(Clone, Debug)]
pub struct DiscoveryCommit {
    pub input_hash: [u8; 32],
    pub source: String,
    pub result_summary: Vec<u8>,
    pub committed_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct CheckpointInput {
    pub format_version: i64,
    pub bytes: Vec<u8>,
    pub source_fingerprint: String,
    pub commit_sequence: i64,
    pub written_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct CommitInput {
    pub checkpoint: CheckpointInput,
    pub devices: Vec<DeviceProjection>,
    pub evidence: Vec<EvidenceProjection>,
    pub transitions: Vec<PresenceChanged>,
    pub discovery: Option<DiscoveryCommit>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LoadedCheckpoint {
    pub format_version: i64,
    pub bytes: Vec<u8>,
    pub source_fingerprint: String,
    pub commit_sequence: i64,
    pub written_at: DateTime<Utc>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredDiscoveryCommit {
    pub source: String,
    pub result_summary: Vec<u8>,
    pub committed_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("checkpoint input is invalid: {0}")]
    Invalid(String),
    #[error("checkpoint data is corrupt: {0}")]
    Corrupt(String),
    #[error("checkpoint commit conflicts: {0}")]
    Conflict(String),
    #[error("checkpoint capacity exceeded: {0}")]
    Capacity(String),
    #[error("checkpoint storage failed: {0}")]
    Storage(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct M2StateRepository {
    pool: SqlitePool,
    config: M2StateConfig,
}
impl M2StateRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            config: M2StateConfig::default(),
        }
    }
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
    /// Returns whether the most recent verified control-plane transition keeps
    /// the device blocked. Discovery evidence cannot override this state.
    pub async fn verified_control_blocked(
        &self,
        device_id: DeviceId,
    ) -> Result<bool, CheckpointError> {
        let state: Option<String> = sqlx::query_scalar(
            "SELECT to_state FROM presence_transitions
             WHERE device_id=? AND trigger_kind IN ('enforcement_blocked','enforcement_unblocked')
             ORDER BY occurred_at DESC, transition_id ASC LIMIT 1",
        )
        .bind(device_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        Ok(state.as_deref() == Some("blocked"))
    }
    /// Persist an enforcement control fact only after the caller has verified
    /// that the requested network action succeeded.  The next identifier is
    /// allocated inside the transaction so it cannot collide with discovery
    /// transitions.
    pub async fn record_verified_block(
        &self,
        device_id: DeviceId,
        at: DateTime<Utc>,
    ) -> Result<(), CheckpointError> {
        let mut tx = self.pool.begin().await?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT to_state FROM presence_transitions WHERE device_id=?
             ORDER BY CASE WHEN trigger_kind IN ('enforcement_blocked','enforcement_unblocked') THEN 1 ELSE 0 END DESC,
                      occurred_at DESC,
                      CASE WHEN trigger_kind IN ('enforcement_blocked','enforcement_unblocked') THEN transition_id END ASC,
                      transition_id DESC LIMIT 1",
        ).bind(device_id.to_string()).fetch_optional(&mut *tx).await?;
        if current.as_deref() == Some("blocked") {
            tx.commit().await?;
            return Ok(());
        }
        let from = current.as_deref().unwrap_or("unknown");
        // Discovery owns non-negative ids in its checkpoint.  Policy controls
        // use a disjoint negative range so a later discovery commit cannot
        // collide with a transition it did not allocate.
        let transition_id: i64 = sqlx::query_scalar("SELECT COALESCE(MIN(transition_id), 0) - 1 FROM presence_transitions WHERE transition_id < 0")
            .fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO presence_transitions(transition_id,device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,evidence_valid_until,trigger_arrival_at,correction_of) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)")
            .bind(transition_id).bind(device_id.to_string()).bind(from).bind("blocked")
            .bind(at.to_rfc3339()).bind("verified_policy_enforcement").bind("policy")
            .bind("enforcement_blocked").bind(at.to_rfc3339()).bind(Option::<String>::None)
            .bind(at.to_rfc3339())
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    /// A release changes durable control state only after the actuator verified
    /// restoration. It deliberately reports Unknown rather than inventing a
    /// network association from the control-plane response.
    pub async fn record_verified_unblock(
        &self,
        device_id: DeviceId,
        at: DateTime<Utc>,
    ) -> Result<(), CheckpointError> {
        let mut tx = self.pool.begin().await?;
        let transition_id: i64 = sqlx::query_scalar("SELECT COALESCE(MIN(transition_id), 0) - 1 FROM presence_transitions WHERE transition_id < 0")
            .fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO presence_transitions(transition_id,device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,evidence_valid_until,trigger_arrival_at,correction_of) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)")
            .bind(transition_id).bind(device_id.to_string()).bind("blocked").bind("unknown")
            .bind(at.to_rfc3339()).bind("verified_policy_release").bind("policy")
            .bind("enforcement_unblocked").bind(at.to_rfc3339()).bind(Option::<String>::None)
            .bind(at.to_rfc3339()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub fn with_config(pool: SqlitePool, config: M2StateConfig) -> Result<Self, CheckpointError> {
        if config.max_checkpoint_bytes == 0
            || config.max_discovery_summary_bytes == 0
            || config.max_batch == 0
            || config.max_string_bytes == 0
            || config.max_snapshot_devices == 0
            || config.max_snapshot_devices > MAX_SNAPSHOT_DEVICES
        {
            return Err(CheckpointError::Invalid(
                "all M2 state limits must be nonzero".into(),
            ));
        }
        Ok(Self { pool, config })
    }
    pub async fn load(
        &self,
        expected_fingerprint: &str,
    ) -> Result<Option<LoadedCheckpoint>, CheckpointError> {
        let row: Option<StoredCheckpointRow> = sqlx::query_as("SELECT format_version, checkpoint_bytes, source_fingerprint, commit_sequence, written_at, sha256 FROM state_checkpoints WHERE singleton=1").fetch_optional(&self.pool).await?;
        let Some((version, bytes, fingerprint, sequence, timestamp, checksum)) = row else {
            return Ok(None);
        };
        let written_at = parse_timestamp(
            &timestamp,
            "checkpoint written_at",
            CheckpointError::Corrupt,
        )?;
        validate_checkpoint(
            &self.config,
            &bytes,
            version,
            sequence,
            &fingerprint,
            expected_fingerprint,
            written_at,
            &checksum,
            CheckpointError::Corrupt,
        )?;
        Ok(Some(LoadedCheckpoint {
            format_version: version,
            bytes,
            source_fingerprint: fingerprint,
            commit_sequence: sequence,
            written_at,
        }))
    }
    pub async fn discovery_commit(
        &self,
        input_hash: [u8; 32],
    ) -> Result<Option<StoredDiscoveryCommit>, CheckpointError> {
        let row: Option<StoredDiscoveryRow> = sqlx::query_as(
            "SELECT source,result_summary,committed_at,result_sha256,checkpoint_sequence,source_fingerprint,commit_digest,row_sha256 FROM discovery_commits WHERE input_hash=?",
        )
        .bind(input_hash.to_vec())
        .fetch_optional(&self.pool)
        .await?;
        let Some((
            source,
            result_summary,
            committed_at,
            result_sha256,
            checkpoint_sequence,
            source_fingerprint,
            commit_digest,
            row_sha256,
        )) = row
        else {
            return Ok(None);
        };
        check_string_with(
            &source,
            &self.config,
            "discovery source",
            CheckpointError::Corrupt,
        )?;
        check_string_with(
            &source_fingerprint,
            &self.config,
            "discovery source fingerprint",
            CheckpointError::Corrupt,
        )?;
        if result_summary.len() > self.config.max_discovery_summary_bytes
            || result_sha256.len() != 32
            || Sha256::digest(&result_summary).as_slice() != result_sha256.as_slice()
            || commit_digest.len() != 32
            || row_sha256.len() != 32
        {
            return Err(CheckpointError::Corrupt(
                "discovery commit checksum or bound invalid".into(),
            ));
        }
        let committed_at = parse_timestamp(
            &committed_at,
            "discovery commit committed_at",
            CheckpointError::Corrupt,
        )?;
        if row_sha256
            != discovery_row_checksum(
                input_hash,
                &source,
                committed_at,
                &result_summary,
                &result_sha256,
                &commit_digest,
                checkpoint_sequence,
                &source_fingerprint,
            )
        {
            return Err(CheckpointError::Corrupt(
                "discovery commit row checksum mismatch".into(),
            ));
        }
        validate_discovery_summary(
            &result_summary,
            checkpoint_sequence,
            CheckpointError::Corrupt,
        )?;
        let checkpoint = self.load(&source_fingerprint).await?.ok_or_else(|| {
            CheckpointError::Corrupt("discovery record exists without checkpoint".into())
        })?;
        if checkpoint.commit_sequence < checkpoint_sequence {
            return Err(CheckpointError::Corrupt(
                "discovery commit names a future checkpoint sequence".into(),
            ));
        }
        Ok(Some(StoredDiscoveryCommit {
            source,
            result_summary,
            committed_at,
        }))
    }

    pub async fn lookup_link_layer_device(
        &self,
        address: LinkAddress,
        source: &str,
    ) -> Result<Option<DeviceId>, CheckpointError> {
        check_string(source, &self.config, "identity source")?;
        let rows: Vec<(Option<String>,)> = sqlx::query_as(
            "SELECT DISTINCT device_id FROM evidence WHERE family='link_layer' AND fact_key='mac' AND source=? AND fact_value=? LIMIT 2",
        )
        .bind(source)
        .bind(address.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut devices = rows.into_iter().map(|(id,)| {
            let id = id.ok_or_else(|| {
                CheckpointError::Corrupt(
                    "identity evidence contains an invalid device identifier".into(),
                )
            })?;
            DeviceId::parse(&id).map_err(|_| {
                CheckpointError::Corrupt(
                    "identity evidence contains an invalid device identifier".into(),
                )
            })
        });
        let first = devices.next().transpose()?;
        match (first, devices.next()) {
            (None, None) => Ok(None),
            (Some(id), None) => Ok(Some(id)),
            (Some(_), Some(Ok(_))) => Err(CheckpointError::Corrupt(
                "identity evidence is ambiguous".into(),
            )),
            (Some(_), Some(Err(error))) => Err(error),
            (None, Some(_)) => unreachable!(),
        }
    }
    pub fn flow_repository(&self, max_batch: usize) -> Result<FlowRepository, CheckpointError> {
        FlowRepository::new(self.pool.clone(), max_batch)
            .map_err(|e| CheckpointError::Invalid(e.to_string()))
    }

    pub async fn list_device_snapshots(
        &self,
        limit: usize,
        after: Option<DeviceId>,
    ) -> Result<Vec<StoredDeviceSnapshot>, CheckpointError> {
        macro_rules! corrupt_get {
            ($row:expr, $ty:ty, $column:expr) => {
                $row.try_get::<$ty, _>($column).map_err(|_| {
                    CheckpointError::Corrupt(format!(
                        "device snapshot {} has an invalid stored type",
                        $column
                    ))
                })?
            };
        }
        if limit == 0 {
            return Err(CheckpointError::Invalid(
                "snapshot limit must be nonzero".into(),
            ));
        }
        if limit > self.config.max_snapshot_devices || limit > MAX_SNAPSHOT_DEVICES {
            return Err(CheckpointError::Capacity(
                "snapshot limit exceeds configured bound".into(),
            ));
        }
        let rows = if let Some(after) = after {
            sqlx::query("SELECT device_id,first_seen_at,last_seen_at,owner_name,owner_type,owner_confirmed FROM devices WHERE device_id>? ORDER BY device_id ASC LIMIT ?").bind(after.to_string()).bind(limit as i64).fetch_all(&self.pool).await?
        } else {
            sqlx::query("SELECT device_id,first_seen_at,last_seen_at,owner_name,owner_type,owner_confirmed FROM devices ORDER BY device_id ASC LIMIT ?").bind(limit as i64).fetch_all(&self.pool).await?
        };
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let raw_device_id = corrupt_get!(row, String, "device_id");
            let id = DeviceId::parse(raw_device_id.as_str()).map_err(|_| {
                CheckpointError::Corrupt(
                    "device snapshot contains invalid device identifier".into(),
                )
            })?;
            if raw_device_id != id.to_string() {
                return Err(CheckpointError::Corrupt(
                    "device snapshot contains noncanonical device identifier".into(),
                ));
            }
            let first = parse_timestamp(
                &corrupt_get!(row, String, "first_seen_at"),
                "device first_seen_at",
                CheckpointError::Corrupt,
            )?;
            let last = parse_timestamp(
                &corrupt_get!(row, String, "last_seen_at"),
                "device last_seen_at",
                CheckpointError::Corrupt,
            )?;
            if first > last {
                return Err(CheckpointError::Corrupt(
                    "device first_seen_at is after last_seen_at".into(),
                ));
            }
            let owner_confirmed: i64 = corrupt_get!(row, i64, "owner_confirmed");
            let owner_confirmed = match owner_confirmed {
                0 => false,
                1 => true,
                _ => {
                    return Err(CheckpointError::Corrupt(
                        "device owner flag is invalid".into(),
                    ));
                }
            };
            let owner_name: Option<String> = corrupt_get!(row, Option<String>, "owner_name");
            let owner_type: Option<String> = corrupt_get!(row, Option<String>, "owner_type");
            if owner_name
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > self.config.max_string_bytes)
                || owner_type
                    .as_ref()
                    .is_some_and(|v| v.is_empty() || v.len() > self.config.max_string_bytes)
            {
                return Err(CheckpointError::Corrupt(
                    "owner string exceeds configured bound".into(),
                ));
            }
            let presence_row = sqlx::query("SELECT to_state,occurred_at,trigger_source,trigger_kind FROM presence_transitions WHERE device_id=? ORDER BY CASE WHEN trigger_kind IN ('enforcement_blocked','enforcement_unblocked') THEN 1 ELSE 0 END DESC, occurred_at DESC, CASE WHEN trigger_kind IN ('enforcement_blocked','enforcement_unblocked') THEN transition_id END ASC, transition_id DESC LIMIT 1").bind(id.to_string()).fetch_optional(&self.pool).await?;
            let presence = if let Some(r) = presence_row {
                Some(StoredPresenceSummary {
                    to_state: parse_presence_state(&corrupt_get!(r, String, "to_state"))?,
                    occurred_at: parse_timestamp(
                        &corrupt_get!(r, String, "occurred_at"),
                        "presence occurred_at",
                        CheckpointError::Corrupt,
                    )?,
                    trigger_source: corrupt_get!(r, String, "trigger_source"),
                    trigger_kind: corrupt_get!(r, String, "trigger_kind"),
                })
                .map(|p| {
                    if p.trigger_source.is_empty()
                        || p.trigger_kind.is_empty()
                        || p.trigger_source.len() > self.config.max_string_bytes
                        || p.trigger_kind.len() > self.config.max_string_bytes
                    {
                        return Err(CheckpointError::Corrupt(
                            "presence trigger string is invalid".into(),
                        ));
                    }
                    Ok(p)
                })
                .transpose()?
            } else {
                None
            };
            let evidence_row = sqlx::query("SELECT family,source,confidence,observed_at,expires_at FROM evidence WHERE device_id=? ORDER BY confidence DESC,observed_at DESC,evidence_id DESC LIMIT 1").bind(id.to_string()).fetch_optional(&self.pool).await?;
            let evidence = if let Some(r) = evidence_row {
                Some(StoredEvidenceSummary {
                    family: parse_evidence_family(&corrupt_get!(r, String, "family"))?,
                    source: corrupt_get!(r, String, "source"),
                    confidence: checked_confidence(corrupt_get!(r, f64, "confidence"))?,
                    observed_at: parse_timestamp(
                        &corrupt_get!(r, String, "observed_at"),
                        "evidence observed_at",
                        CheckpointError::Corrupt,
                    )?,
                    expires_at: corrupt_get!(r, Option<String>, "expires_at")
                        .as_deref()
                        .map(|value| {
                            parse_timestamp(value, "evidence expires_at", CheckpointError::Corrupt)
                        })
                        .transpose()?,
                })
                .map(|e| {
                    if e.source.is_empty() || e.source.len() > self.config.max_string_bytes {
                        return Err(CheckpointError::Corrupt(
                            "evidence source is invalid".into(),
                        ));
                    }
                    Ok(e)
                })
                .transpose()?
            } else {
                None
            };
            let flows = sqlx::query("SELECT bucket,upload,download,coverage FROM flow_rollups WHERE device_id=? AND resolution='second' AND bucket=(SELECT MAX(bucket) FROM flow_rollups WHERE device_id=? AND resolution='second')").bind(id.to_string()).bind(id.to_string()).fetch_all(&self.pool).await?;
            let bandwidth = if flows.is_empty() {
                None
            } else {
                let bucket = parse_timestamp(
                    &corrupt_get!(flows[0], String, "bucket"),
                    "flow bucket",
                    CheckpointError::Corrupt,
                )?;
                let mut up = 0u64;
                let mut down = 0u64;
                let mut cov = None;
                for r in flows {
                    let row_bucket = parse_timestamp(
                        &corrupt_get!(r, String, "bucket"),
                        "flow bucket",
                        CheckpointError::Corrupt,
                    )?;
                    if row_bucket != bucket {
                        return Err(CheckpointError::Corrupt(
                            "flow row is outside selected bucket".into(),
                        ));
                    }
                    up = up
                        .checked_add(i64_to_u64(corrupt_get!(r, i64, "upload"))?)
                        .ok_or_else(|| CheckpointError::Corrupt("flow upload overflow".into()))?;
                    down = down
                        .checked_add(i64_to_u64(corrupt_get!(r, i64, "download"))?)
                        .ok_or_else(|| CheckpointError::Corrupt("flow download overflow".into()))?;
                    let c = parse_coverage(&corrupt_get!(r, String, "coverage"))?;
                    if cov.is_some_and(|x| x != c) {
                        cov = Some(Coverage::Estimated)
                    } else if cov.is_none() {
                        cov = Some(c)
                    }
                }
                Some(StoredBandwidthSummary {
                    upload: up,
                    download: down,
                    coverage: cov.unwrap_or(Coverage::Estimated),
                    observed_at: bucket,
                })
            };
            out.push(StoredDeviceSnapshot {
                device_id: id,
                first_seen_at: first,
                last_seen_at: last,
                owner_name,
                owner_type,
                owner_confirmed,
                presence,
                evidence,
                bandwidth,
            });
        }
        Ok(out)
    }
    pub async fn commit(&self, input: CommitInput) -> Result<(), CheckpointError> {
        validate_input(&self.config, &input)?;
        let digest = logical_commit_digest(&input)?;
        self.commit_inner(input, digest, None).await
    }

    pub async fn commit_with_flow(
        &self,
        input: CommitInput,
        changes: &[RollupChange],
        now: DateTime<Utc>,
        flow: &FlowRepository,
    ) -> Result<(), CheckpointError> {
        validate_input(&self.config, &input)?;
        let digest = logical_commit_digest_with_flow(&input, changes)?;
        self.commit_inner(input, digest, Some((flow, changes, now)))
            .await
    }

    async fn commit_inner(
        &self,
        input: CommitInput,
        digest: Vec<u8>,
        flow: Option<(&FlowRepository, &[RollupChange], DateTime<Utc>)>,
    ) -> Result<(), CheckpointError> {
        // Reserve the writer before reading the checkpoint. A deferred transaction
        // can fail a read-to-write upgrade immediately when another writer is active,
        // even with busy_timeout configured. IMMEDIATE waits before taking that snapshot.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some(discovery) = &input.discovery {
            let old: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT commit_digest FROM discovery_commits WHERE input_hash=?",
            )
            .bind(discovery.input_hash.to_vec())
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(old) = old {
                if old == digest {
                    verify_idempotent_checkpoint(&mut tx, &self.config, &input).await?;
                    tx.commit().await?;
                    return Ok(());
                }
                return Err(CheckpointError::Conflict(
                    "input hash already names a different logical commit".into(),
                ));
            }
        }
        let previous: Option<i64> =
            sqlx::query_scalar("SELECT commit_sequence FROM state_checkpoints WHERE singleton=1")
                .fetch_optional(&mut *tx)
                .await?;
        let expected = previous.map_or(Ok(1), |v| {
            v.checked_add(1)
                .ok_or_else(|| CheckpointError::Conflict("commit sequence is exhausted".into()))
        })?;
        if input.checkpoint.commit_sequence != expected {
            return Err(CheckpointError::Conflict(format!(
                "stale or out-of-order sequence: expected {expected}, got {}",
                input.checkpoint.commit_sequence
            )));
        }
        let checksum = checkpoint_checksum(&input.checkpoint);
        let checkpoint_write = if let Some(previous) = previous {
            sqlx::query("UPDATE state_checkpoints SET format_version=?,checkpoint_bytes=?,source_fingerprint=?,commit_sequence=?,written_at=?,sha256=? WHERE singleton=1 AND commit_sequence=?").bind(input.checkpoint.format_version).bind(&input.checkpoint.bytes).bind(&input.checkpoint.source_fingerprint).bind(input.checkpoint.commit_sequence).bind(input.checkpoint.written_at.to_rfc3339()).bind(checksum).bind(previous).execute(&mut *tx).await
        } else {
            sqlx::query("INSERT INTO state_checkpoints(singleton,format_version,checkpoint_bytes,source_fingerprint,commit_sequence,written_at,sha256) VALUES(1,?,?,?,?,?,?) ON CONFLICT(singleton) DO NOTHING").bind(input.checkpoint.format_version).bind(&input.checkpoint.bytes).bind(&input.checkpoint.source_fingerprint).bind(input.checkpoint.commit_sequence).bind(input.checkpoint.written_at.to_rfc3339()).bind(checksum).execute(&mut *tx).await
        };
        let changed = match checkpoint_write {
            Ok(result) => result.rows_affected(),
            Err(error) if is_write_conflict(&error) => {
                return Err(CheckpointError::Conflict(
                    "another writer committed this sequence first".into(),
                ));
            }
            Err(error) => return Err(CheckpointError::Storage(error)),
        };
        if changed != 1 {
            return Err(CheckpointError::Conflict(
                "another writer advanced the checkpoint first".into(),
            ));
        }
        for device in &input.devices {
            upsert_device(&mut tx, device).await?;
        }
        for evidence in &input.evidence {
            insert_evidence(&mut tx, evidence).await?;
        }
        let mut transitions: Vec<_> = input.transitions.iter().collect();
        transitions.sort_by_key(|transition| transition.transition_id);
        for transition in transitions {
            insert_transition(&mut tx, transition).await?;
        }
        if let Some(discovery) = &input.discovery {
            insert_discovery_commit(&mut tx, &input.checkpoint, discovery, &digest).await?;
        }
        if let Some((flow, changes, now)) = flow {
            flow.apply_in_transaction(&mut tx, changes, now)
                .await
                .map_err(|e| CheckpointError::Invalid(e.to_string()))?;
        }
        tx.commit().await?;
        Ok(())
    }
}

fn validate_input(config: &M2StateConfig, input: &CommitInput) -> Result<(), CheckpointError> {
    let total = input
        .devices
        .len()
        .checked_add(input.evidence.len())
        .and_then(|v| v.checked_add(input.transitions.len()))
        .ok_or_else(|| CheckpointError::Capacity("batch size overflow".into()))?;
    if total > config.max_batch {
        return Err(CheckpointError::Capacity(
            "projection batch too large".into(),
        ));
    }
    validate_checkpoint(
        config,
        &input.checkpoint.bytes,
        input.checkpoint.format_version,
        input.checkpoint.commit_sequence,
        &input.checkpoint.source_fingerprint,
        &input.checkpoint.source_fingerprint,
        input.checkpoint.written_at,
        &checkpoint_checksum(&input.checkpoint),
        CheckpointError::Invalid,
    )?;
    let mut devices = HashSet::new();
    for d in &input.devices {
        if !devices.insert(d.device_id.to_string()) {
            return Err(CheckpointError::Invalid(
                "duplicate device projection".into(),
            ));
        }
        if d.first_seen_at > d.last_seen_at {
            return Err(CheckpointError::Invalid(
                "device first_seen_at is after last_seen_at".into(),
            ));
        }
        if !whole_seconds(d.first_seen_at) || !whole_seconds(d.last_seen_at) {
            return Err(CheckpointError::Invalid(
                "device timestamps must be whole UTC seconds".into(),
            ));
        }
        check_optional_string(&d.owner_name, config, "owner name")?;
        check_optional_string(&d.owner_type, config, "owner type")?;
    }
    for e in &input.evidence {
        let f = &e.fact;
        if !f.confidence.is_finite() || !(0.0..=1.0).contains(&f.confidence) {
            return Err(CheckpointError::Invalid(
                "evidence confidence must be finite and in range".into(),
            ));
        }
        if f.expires_at.is_some_and(|end| end < f.observed_at) {
            return Err(CheckpointError::Invalid(
                "evidence expiry is before observation".into(),
            ));
        }
        check_string(&f.source, config, "evidence source")?;
        check_string(&f.key, config, "evidence key")?;
        check_string(&f.value, config, "evidence value")?;
    }
    let mut transition_ids = HashSet::new();
    let mut evidence_keys = HashSet::new();
    for e in &input.evidence {
        let f = &e.fact;
        let key = format!(
            "{}|{}|{}|{}|{}|{:08x}|{}|{}|{}",
            e.device_id,
            evidence_family(f.family),
            f.source,
            f.key,
            f.value,
            f.confidence.to_bits(),
            f.observed_at.to_rfc3339(),
            f.expires_at
                .map(|value| value.to_rfc3339())
                .unwrap_or_default(),
            f.owner_confirmed
        );
        if !evidence_keys.insert(key) {
            return Err(CheckpointError::Invalid(
                "duplicate semantic evidence projection".into(),
            ));
        }
    }
    for t in &input.transitions {
        if !transition_ids.insert(t.transition_id) {
            return Err(CheckpointError::Invalid(
                "duplicate transition identifier".into(),
            ));
        }
        if t.transition_id == 0
            || t.transition_id > i64::MAX as u64
            || t.correction_of
                .is_some_and(|id| id == 0 || id > i64::MAX as u64)
        {
            return Err(CheckpointError::Invalid(
                "transition identifier is out of SQLite range".into(),
            ));
        }
        if t.from == t.to {
            return Err(CheckpointError::Invalid(
                "presence transition cannot keep the same state".into(),
            ));
        }
        if t.correction_of.is_some_and(|id| id >= t.transition_id) {
            return Err(CheckpointError::Invalid(
                "transition correction must reference an earlier identifier".into(),
            ));
        }
        if t.evidence_observed_at > t.trigger_arrival_at || t.occurred_at > t.trigger_arrival_at {
            return Err(CheckpointError::Invalid(
                "transition timestamps are not causally ordered".into(),
            ));
        }
        if !whole_seconds(t.occurred_at)
            || !whole_seconds(t.evidence_observed_at)
            || !whole_seconds(t.trigger_arrival_at)
            || t.evidence_valid_until
                .is_some_and(|value| !whole_seconds(value))
        {
            return Err(CheckpointError::Invalid(
                "transition timestamps must be whole UTC seconds".into(),
            ));
        }
        if t.evidence_valid_until
            .is_some_and(|end| end < t.evidence_observed_at)
        {
            return Err(CheckpointError::Invalid(
                "transition evidence expiry is before observation".into(),
            ));
        }
        for (value, name) in [
            (&t.reason, "transition reason"),
            (&t.trigger_source, "transition source"),
            (&t.trigger_kind, "transition kind"),
        ] {
            check_string(value, config, name)?;
        }
    }
    if let Some(d) = &input.discovery {
        check_string(&d.source, config, "discovery source")?;
        if d.result_summary.len() > config.max_discovery_summary_bytes {
            return Err(CheckpointError::Capacity(
                "discovery result summary too large".into(),
            ));
        }
        validate_discovery_summary(
            &d.result_summary,
            input.checkpoint.commit_sequence,
            CheckpointError::Invalid,
        )?;
    }
    Ok(())
}

fn validate_discovery_summary(
    bytes: &[u8],
    expected_sequence: i64,
    error: fn(String) -> CheckpointError,
) -> Result<(), CheckpointError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|cause| error(format!("discovery result summary is not JSON: {cause}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| error("discovery result summary must be an object".into()))?;
    if object.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(error(
            "discovery result summary has an unsupported version".into(),
        ));
    }
    let device_id = object
        .get("device_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| error("discovery result summary is missing device_id".into()))?;
    DeviceId::parse(device_id)
        .map_err(|_| error("discovery result summary has an invalid device_id".into()))?;
    if object
        .get("commit_sequence")
        .and_then(serde_json::Value::as_i64)
        != Some(expected_sequence)
    {
        return Err(error(
            "discovery result summary commit_sequence mismatch".into(),
        ));
    }
    for field in ["event_count", "presence_transition_count"] {
        if object
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .is_none()
        {
            return Err(error(format!(
                "discovery result summary has an invalid {field}"
            )));
        }
    }
    Ok(())
}

async fn insert_discovery_commit(
    tx: &mut Transaction<'_, Sqlite>,
    checkpoint: &CheckpointInput,
    discovery: &DiscoveryCommit,
    commit_digest: &[u8],
) -> Result<(), CheckpointError> {
    let result_sha256 = Sha256::digest(&discovery.result_summary).to_vec();
    let row_sha256 = discovery_row_checksum(
        discovery.input_hash,
        &discovery.source,
        discovery.committed_at,
        &discovery.result_summary,
        &result_sha256,
        commit_digest,
        checkpoint.commit_sequence,
        &checkpoint.source_fingerprint,
    );
    let result = sqlx::query(
        "INSERT INTO discovery_commits(input_hash,source,committed_at,result_summary,commit_digest,result_sha256,checkpoint_sequence,source_fingerprint,row_sha256) VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(discovery.input_hash.to_vec())
    .bind(&discovery.source)
    .bind(discovery.committed_at.to_rfc3339())
    .bind(&discovery.result_summary)
    .bind(commit_digest)
    .bind(result_sha256)
    .bind(checkpoint.commit_sequence)
    .bind(&checkpoint.source_fingerprint)
    .bind(row_sha256)
    .execute(&mut **tx)
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if is_write_conflict(&error) => Err(CheckpointError::Conflict(
            "another writer committed this discovery input first".into(),
        )),
        Err(error) => Err(CheckpointError::Storage(error)),
    }
}

#[allow(clippy::too_many_arguments)] // fields are the complete durable replay envelope
fn discovery_row_checksum(
    input_hash: [u8; 32],
    source: &str,
    committed_at: DateTime<Utc>,
    result_summary: &[u8],
    result_sha256: &[u8],
    commit_digest: &[u8],
    checkpoint_sequence: i64,
    source_fingerprint: &str,
) -> Vec<u8> {
    let canonical = json!({
        "checkpoint_sequence": checkpoint_sequence,
        "commit_digest": commit_digest,
        "committed_at": committed_at.to_rfc3339(),
        "input_hash": input_hash,
        "result_sha256": result_sha256,
        "result_summary": result_summary,
        "source": source,
        "source_fingerprint": source_fingerprint,
    });
    Sha256::digest(serde_json::to_vec(&canonical).expect("JSON value serializes")).to_vec()
}

fn is_write_conflict(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database| {
        database.is_unique_violation()
            || database.code().as_deref() == Some("5")
            || database.message().contains("database is locked")
    })
}

#[allow(clippy::too_many_arguments)] // fields mirror one durable checkpoint envelope
fn validate_checkpoint(
    config: &M2StateConfig,
    bytes: &[u8],
    version: i64,
    sequence: i64,
    fingerprint: &str,
    expected_fingerprint: &str,
    written_at: DateTime<Utc>,
    checksum: &[u8],
    error: fn(String) -> CheckpointError,
) -> Result<(), CheckpointError> {
    if version != CURRENT_FORMAT_VERSION {
        return Err(error("unknown format version".into()));
    }
    if bytes.len() > config.max_checkpoint_bytes {
        return Err(CheckpointError::Capacity(
            "checkpoint exceeds configured size".into(),
        ));
    }
    if sequence <= 0 {
        return Err(error("commit sequence must be nonzero".into()));
    }
    check_string_with(fingerprint, config, "source fingerprint", error)?;
    if fingerprint != expected_fingerprint {
        return Err(error("source fingerprint mismatch".into()));
    }
    if checksum
        != checkpoint_checksum_fields(version, bytes, fingerprint, sequence, written_at).as_slice()
    {
        return Err(error("checksum mismatch".into()));
    }
    serde_json::from_slice::<serde_json::Value>(bytes)
        .map_err(|e| error(format!("checkpoint bytes are not JSON: {e}")))?;
    Ok(())
}
fn checkpoint_checksum(checkpoint: &CheckpointInput) -> Vec<u8> {
    checkpoint_checksum_fields(
        checkpoint.format_version,
        &checkpoint.bytes,
        &checkpoint.source_fingerprint,
        checkpoint.commit_sequence,
        checkpoint.written_at,
    )
}
async fn verify_idempotent_checkpoint(
    tx: &mut Transaction<'_, Sqlite>,
    config: &M2StateConfig,
    input: &CommitInput,
) -> Result<(), CheckpointError> {
    let row: Option<StoredCheckpointRow> = sqlx::query_as("SELECT format_version,checkpoint_bytes,source_fingerprint,commit_sequence,written_at,sha256 FROM state_checkpoints WHERE singleton=1")
        .fetch_optional(&mut **tx).await?;
    let Some((version, bytes, fingerprint, sequence, timestamp, checksum)) = row else {
        return Err(CheckpointError::Corrupt(
            "idempotency record exists without a checkpoint".into(),
        ));
    };
    let written_at = parse_timestamp(
        &timestamp,
        "checkpoint written_at",
        CheckpointError::Corrupt,
    )?;
    validate_checkpoint(
        config,
        &bytes,
        version,
        sequence,
        &fingerprint,
        &input.checkpoint.source_fingerprint,
        written_at,
        &checksum,
        CheckpointError::Corrupt,
    )?;
    if version != input.checkpoint.format_version
        || bytes != input.checkpoint.bytes
        || sequence != input.checkpoint.commit_sequence
        || written_at != input.checkpoint.written_at
    {
        return Err(CheckpointError::Conflict(
            "idempotency record does not match current checkpoint envelope".into(),
        ));
    }
    Ok(())
}
fn checkpoint_checksum_fields(
    version: i64,
    bytes: &[u8],
    fingerprint: &str,
    sequence: i64,
    written_at: DateTime<Utc>,
) -> Vec<u8> {
    Sha256::digest(serde_json::to_vec(&json!({"checkpoint_bytes":bytes,"commit_sequence":sequence,"format_version":version,"source_fingerprint":fingerprint,"written_at":written_at.to_rfc3339()})).expect("JSON value serializes")).to_vec()
}
fn logical_commit_digest(input: &CommitInput) -> Result<Vec<u8>, CheckpointError> {
    logical_commit_digest_extra(input, None)
}
fn logical_commit_digest_with_flow(
    input: &CommitInput,
    changes: &[RollupChange],
) -> Result<Vec<u8>, CheckpointError> {
    let mut flow: Vec<_> = changes
        .iter()
        .map(|change| {
            serde_json::to_value(change).map_err(|e| {
                CheckpointError::Invalid(format!("flow canonical serialization failed: {e}"))
            })
        })
        .collect::<Result<_, _>>()?;
    sort_json_values(&mut flow);
    logical_commit_digest_extra(input, Some(flow))
}
fn logical_commit_digest_extra(
    input: &CommitInput,
    flow: Option<Vec<serde_json::Value>>,
) -> Result<Vec<u8>, CheckpointError> {
    let mut devices: Vec<_> = input.devices.iter().map(|d| json!({"device_id":d.device_id.to_string(),"first_seen_at":d.first_seen_at.to_rfc3339(),"last_seen_at":d.last_seen_at.to_rfc3339(),"owner_name":d.owner_name,"owner_type":d.owner_type,"owner_confirmed":d.owner_confirmed})).collect();
    let mut evidence: Vec<_> = input.evidence.iter().map(|e| { let f=&e.fact; json!({"device_id":e.device_id.to_string(),"family":evidence_family(f.family),"source":f.source,"key":f.key,"value":f.value,"confidence":f.confidence,"observed_at":f.observed_at.to_rfc3339(),"expires_at":f.expires_at.map(|x|x.to_rfc3339()),"owner_confirmed":f.owner_confirmed}) }).collect();
    let mut transitions: Vec<_> = input.transitions.iter().map(|t| json!({"transition_id":t.transition_id,"device_id":t.device_id.to_string(),"from":presence_state(t.from),"to":presence_state(t.to),"occurred_at":t.occurred_at.to_rfc3339(),"reason":t.reason,"trigger_source":t.trigger_source,"trigger_kind":t.trigger_kind,"evidence_observed_at":t.evidence_observed_at.to_rfc3339(),"evidence_valid_until":t.evidence_valid_until.map(|x|x.to_rfc3339()),"trigger_arrival_at":t.trigger_arrival_at.to_rfc3339(),"correction_of":t.correction_of})).collect();
    sort_json_values(&mut devices);
    sort_json_values(&mut evidence);
    sort_json_values(&mut transitions);
    let c = &input.checkpoint;
    let canonical = json!({"checkpoint":{"format_version":c.format_version,"bytes":c.bytes,"source_fingerprint":c.source_fingerprint,"commit_sequence":c.commit_sequence,"written_at":c.written_at.to_rfc3339()},"devices":devices,"evidence":evidence,"transitions":transitions,"discovery":input.discovery.as_ref().map(|d|json!({"input_hash":d.input_hash,"source":d.source,"result_summary":d.result_summary,"committed_at":d.committed_at.to_rfc3339()})),"flow":flow});
    Ok(Sha256::digest(serde_json::to_vec(&canonical).map_err(|e| {
        CheckpointError::Invalid(format!("canonical commit serialization failed: {e}"))
    })?)
    .to_vec())
}
fn sort_json_values(values: &mut [serde_json::Value]) {
    values.sort_by_key(|value| serde_json::to_string(value).expect("JSON value serializes"));
}
async fn upsert_device(
    tx: &mut Transaction<'_, Sqlite>,
    d: &DeviceProjection,
) -> Result<(), CheckpointError> {
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_name,owner_type,owner_confirmed) VALUES(?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET first_seen_at=MIN(devices.first_seen_at,excluded.first_seen_at),last_seen_at=MAX(devices.last_seen_at,excluded.last_seen_at),owner_name=CASE WHEN excluded.owner_confirmed=1 THEN COALESCE(excluded.owner_name,devices.owner_name) ELSE devices.owner_name END,owner_type=CASE WHEN excluded.owner_confirmed=1 THEN COALESCE(excluded.owner_type,devices.owner_type) ELSE devices.owner_type END,owner_confirmed=MAX(devices.owner_confirmed,excluded.owner_confirmed)").bind(d.device_id.to_string()).bind(d.first_seen_at.to_rfc3339()).bind(d.last_seen_at.to_rfc3339()).bind(&d.owner_name).bind(&d.owner_type).bind(d.owner_confirmed).execute(&mut **tx).await?;
    Ok(())
}
async fn insert_evidence(
    tx: &mut Transaction<'_, Sqlite>,
    e: &EvidenceProjection,
) -> Result<(), CheckpointError> {
    let f = &e.fact;
    sqlx::query("INSERT INTO evidence(device_id,family,source,fact_key,fact_value,confidence,observed_at,expires_at,owner_confirmed) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING").bind(e.device_id.to_string()).bind(evidence_family(f.family)).bind(&f.source).bind(&f.key).bind(&f.value).bind(f.confidence).bind(f.observed_at.to_rfc3339()).bind(f.expires_at.map(|x|x.to_rfc3339())).bind(f.owner_confirmed).execute(&mut **tx).await?;
    Ok(())
}
async fn insert_transition(
    tx: &mut Transaction<'_, Sqlite>,
    t: &PresenceChanged,
) -> Result<(), CheckpointError> {
    if let Some(correction_of) = t.correction_of {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT transition_id FROM presence_transitions WHERE transition_id=?",
        )
        .bind(correction_of as i64)
        .fetch_optional(&mut **tx)
        .await?;
        if exists.is_none() {
            return Err(CheckpointError::Invalid(format!(
                "transition {} references a missing correction target",
                t.transition_id
            )));
        }
    }
    let existing: Option<StoredTransitionRow> = sqlx::query_as("SELECT device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,evidence_valid_until,trigger_arrival_at,correction_of FROM presence_transitions WHERE transition_id=?").bind(t.transition_id as i64).fetch_optional(&mut **tx).await?;
    let row = (
        t.device_id.to_string(),
        presence_state(t.from).to_string(),
        presence_state(t.to).to_string(),
        t.occurred_at.to_rfc3339(),
        t.reason.clone(),
        t.trigger_source.clone(),
        t.trigger_kind.clone(),
        t.evidence_observed_at.to_rfc3339(),
        t.evidence_valid_until.map(|x| x.to_rfc3339()),
        t.trigger_arrival_at.to_rfc3339(),
        t.correction_of.map(|v| v as i64),
    );
    if let Some(existing) = existing {
        if existing == row {
            return Ok(());
        }
        return Err(CheckpointError::Conflict(format!(
            "transition {} already exists with different data",
            t.transition_id
        )));
    }
    sqlx::query("INSERT INTO presence_transitions(transition_id,device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,evidence_valid_until,trigger_arrival_at,correction_of) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").bind(t.transition_id as i64).bind(row.0).bind(row.1).bind(row.2).bind(row.3).bind(row.4).bind(row.5).bind(row.6).bind(row.7).bind(row.8).bind(row.9).bind(row.10).execute(&mut **tx).await?;
    Ok(())
}
fn evidence_family(value: EvidenceFamily) -> &'static str {
    match value {
        EvidenceFamily::LinkLayer => "link_layer",
        EvidenceFamily::Addressing => "addressing",
        EvidenceFamily::Naming => "naming",
        EvidenceFamily::Service => "service",
        EvidenceFamily::Cryptographic => "cryptographic",
        EvidenceFamily::RouterHint => "router_hint",
        EvidenceFamily::Owner => "owner",
    }
}
fn parse_presence_state(v: &str) -> Result<PresenceState, CheckpointError> {
    match v {
        "online" => Ok(PresenceState::Online),
        "quiet" => Ok(PresenceState::Quiet),
        "offline" => Ok(PresenceState::Offline),
        "blocked" => Ok(PresenceState::Blocked),
        "unknown" => Ok(PresenceState::Unknown),
        _ => Err(CheckpointError::Corrupt("presence state is invalid".into())),
    }
}
fn parse_evidence_family(v: &str) -> Result<EvidenceFamily, CheckpointError> {
    match v {
        "link_layer" => Ok(EvidenceFamily::LinkLayer),
        "addressing" => Ok(EvidenceFamily::Addressing),
        "naming" => Ok(EvidenceFamily::Naming),
        "service" => Ok(EvidenceFamily::Service),
        "cryptographic" => Ok(EvidenceFamily::Cryptographic),
        "router_hint" => Ok(EvidenceFamily::RouterHint),
        "owner" => Ok(EvidenceFamily::Owner),
        _ => Err(CheckpointError::Corrupt(
            "evidence family is invalid".into(),
        )),
    }
}
fn parse_coverage(v: &str) -> Result<Coverage, CheckpointError> {
    match v {
        "complete" => Ok(Coverage::Complete),
        "router-reported" => Ok(Coverage::RouterReported),
        "local-only" => Ok(Coverage::LocalOnly),
        "estimated" => Ok(Coverage::Estimated),
        _ => Err(CheckpointError::Corrupt("flow coverage is invalid".into())),
    }
}
fn checked_confidence(v: f64) -> Result<f32, CheckpointError> {
    if v.is_finite() && (0.0..=1.0).contains(&v) {
        Ok(v as f32)
    } else {
        Err(CheckpointError::Corrupt(
            "evidence confidence is invalid".into(),
        ))
    }
}
fn i64_to_u64(v: i64) -> Result<u64, CheckpointError> {
    u64::try_from(v).map_err(|_| CheckpointError::Corrupt("flow byte count is invalid".into()))
}
fn presence_state(value: PresenceState) -> &'static str {
    match value {
        PresenceState::Online => "online",
        PresenceState::Quiet => "quiet",
        PresenceState::Offline => "offline",
        PresenceState::Blocked => "blocked",
        PresenceState::Unknown => "unknown",
    }
}
fn parse_timestamp(
    value: &str,
    field: &str,
    error: fn(String) -> CheckpointError,
) -> Result<DateTime<Utc>, CheckpointError> {
    DateTime::parse_from_rfc3339(value)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|e| error(format!("{field}: {e}")))
}
fn check_string(value: &str, config: &M2StateConfig, field: &str) -> Result<(), CheckpointError> {
    check_string_with(value, config, field, CheckpointError::Invalid)
}
fn check_string_with(
    value: &str,
    config: &M2StateConfig,
    field: &str,
    error: fn(String) -> CheckpointError,
) -> Result<(), CheckpointError> {
    if value.is_empty() {
        return Err(error(format!("{field} cannot be empty")));
    }
    if value.len() > config.max_string_bytes {
        return Err(CheckpointError::Capacity(format!(
            "{field} exceeds configured size"
        )));
    }
    Ok(())
}
fn check_optional_string(
    value: &Option<String>,
    config: &M2StateConfig,
    field: &str,
) -> Result<(), CheckpointError> {
    if let Some(value) = value {
        check_string(value, config, field)?;
    }
    Ok(())
}
fn whole_seconds(value: DateTime<Utc>) -> bool {
    value.timestamp_subsec_nanos() == 0
}
