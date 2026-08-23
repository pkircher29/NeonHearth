use chrono::{DateTime, Utc};
use lattice_domain::{DeviceId, EvidenceFact, PresenceChanged};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use thiserror::Error;

pub const MAX_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BATCH: usize = 4096;

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
    #[error("checkpoint is invalid: {0}")]
    Invalid(String),
    #[error("checkpoint storage failed: {0}")]
    Storage(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct M2StateRepository {
    pool: SqlitePool,
}
impl M2StateRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
    pub async fn load(
        &self,
        source_fingerprint: &str,
    ) -> Result<Option<LoadedCheckpoint>, CheckpointError> {
        let r: Option<(i64, Vec<u8>, String, i64, String, Vec<u8>)> = sqlx::query_as("SELECT format_version,checkpoint_bytes,source_fingerprint,commit_sequence,written_at,sha256 FROM state_checkpoints WHERE singleton=1").fetch_optional(&self.pool).await?;
        let Some((v, b, f, s, w, hash)) = r else {
            return Ok(None);
        };
        validate(&b, v, s, &f, source_fingerprint, &hash)?;
        let written_at = DateTime::parse_from_rfc3339(&w)
            .map_err(|e| CheckpointError::Invalid(format!("timestamp: {e}")))?
            .with_timezone(&Utc);
        Ok(Some(LoadedCheckpoint {
            format_version: v,
            bytes: b,
            source_fingerprint: f,
            commit_sequence: s,
            written_at,
        }))
    }
    pub async fn commit(&self, input: CommitInput) -> Result<(), CheckpointError> {
        validate_input(&input)?;
        let mut tx = self.pool.begin().await?;
        if let Some(d) = &input.discovery {
            let old: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT result_summary FROM discovery_commits WHERE input_hash=?",
            )
            .bind(d.input_hash.to_vec())
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(x) = old {
                if x == d.result_summary {
                    return Ok(tx.commit().await?);
                } else {
                    return Err(CheckpointError::Invalid(
                        "conflicting discovery hash".into(),
                    ));
                }
            }
        }
        let hash = Sha256::digest(&input.checkpoint.bytes).to_vec();
        sqlx::query("INSERT INTO state_checkpoints(singleton,format_version,checkpoint_bytes,source_fingerprint,commit_sequence,written_at,sha256) VALUES(1,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET format_version=excluded.format_version,checkpoint_bytes=excluded.checkpoint_bytes,source_fingerprint=excluded.source_fingerprint,commit_sequence=excluded.commit_sequence,written_at=excluded.written_at,sha256=excluded.sha256")
   .bind(input.checkpoint.format_version).bind(&input.checkpoint.bytes).bind(&input.checkpoint.source_fingerprint).bind(input.checkpoint.commit_sequence).bind(input.checkpoint.written_at.to_rfc3339()).bind(hash).execute(&mut *tx).await?;
        for d in &input.devices {
            sqlx::query("INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_name,owner_type,owner_confirmed) VALUES(?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET last_seen_at=excluded.last_seen_at,owner_name=excluded.owner_name,owner_type=excluded.owner_type,owner_confirmed=excluded.owner_confirmed").bind(d.device_id.to_string()).bind(d.first_seen_at.to_rfc3339()).bind(d.last_seen_at.to_rfc3339()).bind(&d.owner_name).bind(&d.owner_type).bind(d.owner_confirmed).execute(&mut *tx).await?;
        }
        for e in &input.evidence {
            let f = &e.fact;
            sqlx::query("INSERT INTO evidence(device_id,family,source,fact_key,fact_value,confidence,observed_at,expires_at,owner_confirmed) SELECT ?,?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM evidence WHERE device_id=? AND source=? AND fact_key=? AND fact_value=? AND observed_at=? )").bind(e.device_id.to_string()).bind(format!("{:?}",f.family)).bind(&f.source).bind(&f.key).bind(&f.value).bind(f.confidence).bind(f.observed_at.to_rfc3339()).bind(f.expires_at.map(|x|x.to_rfc3339())).bind(f.owner_confirmed).bind(e.device_id.to_string()).bind(&f.source).bind(&f.key).bind(&f.value).bind(f.observed_at.to_rfc3339()).execute(&mut *tx).await?;
        }
        for t in &input.transitions {
            sqlx::query("INSERT OR IGNORE INTO presence_transitions(transition_id,device_id,from_state,to_state,occurred_at,reason,trigger_source,trigger_kind,evidence_observed_at,evidence_valid_until,trigger_arrival_at,correction_of) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").bind(t.transition_id as i64).bind(t.device_id.to_string()).bind(format!("{:?}",t.from)).bind(format!("{:?}",t.to)).bind(t.occurred_at.to_rfc3339()).bind(&t.reason).bind(&t.trigger_source).bind(&t.trigger_kind).bind(t.evidence_observed_at.to_rfc3339()).bind(t.evidence_valid_until.map(|x|x.to_rfc3339())).bind(t.trigger_arrival_at.to_rfc3339()).bind(t.correction_of.map(|x|x as i64)).execute(&mut *tx).await?;
        }
        if let Some(d) = &input.discovery {
            sqlx::query("INSERT INTO discovery_commits(input_hash,source,committed_at,result_summary) VALUES(?,?,?,?)").bind(d.input_hash.to_vec()).bind(&d.source).bind(d.committed_at.to_rfc3339()).bind(&d.result_summary).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
fn validate_input(i: &CommitInput) -> Result<(), CheckpointError> {
    if i.devices.len() + i.evidence.len() + i.transitions.len() > MAX_BATCH {
        return Err(CheckpointError::Invalid("batch too large".into()));
    };
    validate(
        &i.checkpoint.bytes,
        i.checkpoint.format_version,
        i.checkpoint.commit_sequence,
        &i.checkpoint.source_fingerprint,
        &i.checkpoint.source_fingerprint,
        &Sha256::digest(&i.checkpoint.bytes).to_vec(),
    )
}
fn validate(
    b: &[u8],
    v: i64,
    s: i64,
    f: &str,
    expected: &str,
    h: &[u8],
) -> Result<(), CheckpointError> {
    if v != 1 {
        return Err(CheckpointError::Invalid("unknown format version".into()));
    }
    if b.len() > MAX_CHECKPOINT_BYTES {
        return Err(CheckpointError::Invalid("checkpoint too large".into()));
    }
    if s <= 0 {
        return Err(CheckpointError::Invalid("invalid sequence".into()));
    }
    if f != expected {
        return Err(CheckpointError::Invalid(
            "source fingerprint mismatch".into(),
        ));
    }
    if Sha256::digest(b).as_slice() != h {
        return Err(CheckpointError::Invalid("checksum mismatch".into()));
    }
    serde_json::from_slice::<serde_json::Value>(b)
        .map_err(|e| CheckpointError::Invalid(format!("invalid JSON: {e}")))?;
    Ok(())
}
