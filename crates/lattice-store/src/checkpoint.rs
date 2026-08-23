use chrono::{DateTime, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily, PresenceChanged, PresenceState};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Sqlite, SqlitePool, Transaction};
use thiserror::Error;

pub const MAX_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BATCH: usize = 4096;
const CURRENT_FORMAT_VERSION: i64 = 1;
type StoredCheckpointRow = (i64, Vec<u8>, String, i64, String, Vec<u8>);
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
}
impl Default for M2StateConfig {
    fn default() -> Self {
        Self {
            max_checkpoint_bytes: MAX_CHECKPOINT_BYTES,
            max_discovery_summary_bytes: 1024 * 1024,
            max_batch: MAX_BATCH,
            max_string_bytes: 4096,
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
    pub fn with_config(pool: SqlitePool, config: M2StateConfig) -> Result<Self, CheckpointError> {
        if config.max_checkpoint_bytes == 0
            || config.max_discovery_summary_bytes == 0
            || config.max_batch == 0
            || config.max_string_bytes == 0
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
    pub async fn commit(&self, input: CommitInput) -> Result<(), CheckpointError> {
        validate_input(&self.config, &input)?;
        let digest = logical_commit_digest(&input)?;
        let mut tx = self.pool.begin().await?;
        if let Some(discovery) = &input.discovery {
            let old: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT commit_digest FROM discovery_commits WHERE input_hash=?",
            )
            .bind(discovery.input_hash.to_vec())
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(old) = old {
                if old == digest {
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
        let expected = previous.map_or(1, |value| value.checked_add(1).unwrap_or(i64::MIN));
        if input.checkpoint.commit_sequence != expected {
            return Err(CheckpointError::Conflict(format!(
                "stale or out-of-order sequence: expected {expected}, got {}",
                input.checkpoint.commit_sequence
            )));
        }
        let checkpoint_insert = sqlx::query("INSERT INTO state_checkpoints(singleton,format_version,checkpoint_bytes,source_fingerprint,commit_sequence,written_at,sha256) VALUES(1,?,?,?,?,?,?)")
            .bind(input.checkpoint.format_version).bind(&input.checkpoint.bytes).bind(&input.checkpoint.source_fingerprint).bind(input.checkpoint.commit_sequence).bind(input.checkpoint.written_at.to_rfc3339()).bind(checkpoint_checksum(&input.checkpoint)).execute(&mut *tx).await;
        if let Err(error) = checkpoint_insert {
            if error.as_database_error().is_some_and(|db| {
                db.is_unique_violation()
                    || db.code().as_deref() == Some("5")
                    || db.message().contains("database is locked")
            }) {
                return Err(CheckpointError::Conflict(
                    "another writer committed this sequence first".into(),
                ));
            }
            return Err(CheckpointError::Storage(error));
        }
        for device in &input.devices {
            upsert_device(&mut tx, device).await?;
        }
        for evidence in &input.evidence {
            insert_evidence(&mut tx, evidence).await?;
        }
        for transition in &input.transitions {
            insert_transition(&mut tx, transition).await?;
        }
        if let Some(discovery) = &input.discovery {
            sqlx::query("INSERT INTO discovery_commits(input_hash,source,committed_at,result_summary,commit_digest) VALUES(?,?,?,?,?)").bind(discovery.input_hash.to_vec()).bind(&discovery.source).bind(discovery.committed_at.to_rfc3339()).bind(&discovery.result_summary).bind(digest).execute(&mut *tx).await?;
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
    for d in &input.devices {
        if d.first_seen_at > d.last_seen_at {
            return Err(CheckpointError::Invalid(
                "device first_seen_at is after last_seen_at".into(),
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
    for t in &input.transitions {
        if t.transition_id == 0
            || t.transition_id > i64::MAX as u64
            || t.correction_of
                .is_some_and(|id| id == 0 || id > i64::MAX as u64)
        {
            return Err(CheckpointError::Invalid(
                "transition identifier is out of SQLite range".into(),
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
        serde_json::from_slice::<serde_json::Value>(&d.result_summary).map_err(|e| {
            CheckpointError::Invalid(format!("discovery result summary is not JSON: {e}"))
        })?;
    }
    Ok(())
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
    let devices: Vec<_> = input.devices.iter().map(|d| json!({"device_id":d.device_id.to_string(),"first_seen_at":d.first_seen_at.to_rfc3339(),"last_seen_at":d.last_seen_at.to_rfc3339(),"owner_name":d.owner_name,"owner_type":d.owner_type,"owner_confirmed":d.owner_confirmed})).collect();
    let evidence: Vec<_> = input.evidence.iter().map(|e| { let f=&e.fact; json!({"device_id":e.device_id.to_string(),"family":evidence_family(f.family),"source":f.source,"key":f.key,"value":f.value,"confidence":f.confidence,"observed_at":f.observed_at.to_rfc3339(),"expires_at":f.expires_at.map(|x|x.to_rfc3339()),"owner_confirmed":f.owner_confirmed}) }).collect();
    let transitions: Vec<_> = input.transitions.iter().map(|t| json!({"transition_id":t.transition_id,"device_id":t.device_id.to_string(),"from":presence_state(t.from),"to":presence_state(t.to),"occurred_at":t.occurred_at.to_rfc3339(),"reason":t.reason,"trigger_source":t.trigger_source,"trigger_kind":t.trigger_kind,"evidence_observed_at":t.evidence_observed_at.to_rfc3339(),"evidence_valid_until":t.evidence_valid_until.map(|x|x.to_rfc3339()),"trigger_arrival_at":t.trigger_arrival_at.to_rfc3339(),"correction_of":t.correction_of})).collect();
    let c = &input.checkpoint;
    let canonical = json!({"checkpoint":{"format_version":c.format_version,"bytes":c.bytes,"source_fingerprint":c.source_fingerprint,"commit_sequence":c.commit_sequence,"written_at":c.written_at.to_rfc3339()},"devices":devices,"evidence":evidence,"transitions":transitions,"discovery":input.discovery.as_ref().map(|d|json!({"input_hash":d.input_hash,"source":d.source,"result_summary":d.result_summary,"committed_at":d.committed_at.to_rfc3339()}))});
    Ok(Sha256::digest(serde_json::to_vec(&canonical).map_err(|e| {
        CheckpointError::Invalid(format!("canonical commit serialization failed: {e}"))
    })?)
    .to_vec())
}
async fn upsert_device(
    tx: &mut Transaction<'_, Sqlite>,
    d: &DeviceProjection,
) -> Result<(), CheckpointError> {
    sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_name,owner_type,owner_confirmed) VALUES(?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET first_seen_at=MIN(devices.first_seen_at,excluded.first_seen_at),last_seen_at=MAX(devices.last_seen_at,excluded.last_seen_at),owner_name=COALESCE(excluded.owner_name,devices.owner_name),owner_type=COALESCE(excluded.owner_type,devices.owner_type),owner_confirmed=MAX(devices.owner_confirmed,excluded.owner_confirmed)").bind(d.device_id.to_string()).bind(d.first_seen_at.to_rfc3339()).bind(d.last_seen_at.to_rfc3339()).bind(&d.owner_name).bind(&d.owner_type).bind(d.owner_confirmed).execute(&mut **tx).await?;
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
