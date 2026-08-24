use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use lattice_camera::{
    BoundedMetadata, BoundedSerial, CameraClassification, CameraEvidence, CameraEvidenceFamily,
    CameraHealth, CameraId, CameraProfile, Confidence, OnvifHealth, StreamId, StreamSourceRef,
};
use sqlx::SqlitePool;
use std::collections::BTreeSet;
use thiserror::Error;
use uuid::Uuid;

const MAX_EVIDENCE_ROWS: usize = 64;
const MAX_CAPABILITIES: usize = 32;
const MAX_STREAM_REFS: usize = 64;
type EvidenceRow = (String, String, String, String, f64, String, Option<String>);
type InventoryRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);

#[derive(Clone)]
pub struct CameraRepository {
    pool: SqlitePool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CameraRecord {
    pub id: CameraId,
    pub classification: CameraClassification,
    pub confidence: Confidence,
    pub health: CameraHealth,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CameraInventoryRecord {
    pub manufacturer: Option<BoundedMetadata>,
    pub model: Option<BoundedMetadata>,
    pub firmware: Option<BoundedMetadata>,
    pub serial: Option<BoundedSerial>,
    pub capabilities: Vec<BoundedMetadata>,
    pub health: OnvifHealth,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CameraStoreError {
    #[error("invalid camera record")]
    Invalid,
    #[error("camera record conflicts with existing data")]
    Conflict,
    #[error("camera relationship is invalid")]
    Constraint,
    #[error("camera storage capacity exceeded")]
    Capacity,
    #[error("camera data is corrupt")]
    Corrupt,
    #[error("camera storage failed")]
    Storage,
}

impl CameraRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn upsert_camera(&self, value: &CameraRecord) -> Result<(), CameraStoreError> {
        let observed_at = encode_time(value.observed_at).ok_or(CameraStoreError::Invalid)?;
        sqlx::query(
            "INSERT INTO cameras(camera_id, classification, confidence, health, observed_at) \
             VALUES(?, ?, ?, ?, ?) \
             ON CONFLICT(camera_id) DO UPDATE SET \
             classification=excluded.classification, confidence=excluded.confidence, \
             health=excluded.health, observed_at=excluded.observed_at",
        )
        .bind(value.id.to_string())
        .bind(classification_string(value.classification))
        .bind(f64::from(value.confidence.get()))
        .bind(camera_health_string(value.health))
        .bind(observed_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    pub async fn load_camera(
        &self,
        id: CameraId,
    ) -> Result<Option<CameraRecord>, CameraStoreError> {
        let row: Option<(String, String, f64, String, String)> = sqlx::query_as(
            "SELECT camera_id, classification, confidence, health, observed_at \
             FROM cameras WHERE camera_id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(
            |(raw_id, classification, confidence, health, observed_at)| {
                let stored_id = decode_camera_id(&raw_id)?;
                if stored_id != id {
                    return Err(CameraStoreError::Corrupt);
                }
                Ok(CameraRecord {
                    id: stored_id,
                    classification: decode_classification(&classification)?,
                    confidence: decode_confidence(confidence)?,
                    health: decode_camera_health(&health)?,
                    observed_at: decode_time(&observed_at)?,
                })
            },
        )
        .transpose()
    }

    pub async fn insert_evidence(
        &self,
        camera_id: CameraId,
        evidence: &CameraEvidence,
    ) -> Result<(), CameraStoreError> {
        if evidence
            .expires_at()
            .is_some_and(|expires| expires <= evidence.observed_at())
        {
            return Err(CameraStoreError::Invalid);
        }
        let observed_at = encode_time(evidence.observed_at()).ok_or(CameraStoreError::Invalid)?;
        let expires_at = match evidence.expires_at() {
            Some(expires_at) => Some(encode_time(expires_at).ok_or(CameraStoreError::Invalid)?),
            None => None,
        };
        sqlx::query(
            "INSERT INTO camera_evidence(camera_id, family, source, fact, confidence, observed_at, expires_at) \
             VALUES(?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(camera_id.to_string())
        .bind(evidence_family_string(evidence.family()))
        .bind(evidence.source())
        .bind(evidence.fact())
        .bind(f64::from(evidence.confidence().get()))
        .bind(observed_at)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    pub async fn load_evidence(
        &self,
        camera_id: CameraId,
        limit: usize,
    ) -> Result<Vec<CameraEvidence>, CameraStoreError> {
        if !(1..=MAX_EVIDENCE_ROWS).contains(&limit) {
            return Err(CameraStoreError::Invalid);
        }
        let rows: Vec<EvidenceRow> = sqlx::query_as(
            "SELECT camera_id, family, source, fact, confidence, observed_at, expires_at \
             FROM camera_evidence WHERE camera_id = ? \
             ORDER BY observed_at DESC, family, source, fact LIMIT ?",
        )
        .bind(camera_id.to_string())
        .bind(i64::try_from(limit).map_err(|_| CameraStoreError::Invalid)?)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.into_iter()
            .map(
                |(raw_id, family, source, fact, confidence, observed_at, expires_at)| {
                    if decode_camera_id(&raw_id)? != camera_id {
                        return Err(CameraStoreError::Corrupt);
                    }
                    let observed_at = decode_time(&observed_at)?;
                    let expires_at = expires_at.as_deref().map(decode_time).transpose()?;
                    if expires_at.is_some_and(|expires| expires <= observed_at) {
                        return Err(CameraStoreError::Corrupt);
                    }
                    CameraEvidence::new(
                        decode_evidence_family(&family)?,
                        source,
                        fact,
                        decode_confidence(confidence)?.get(),
                        observed_at,
                        expires_at,
                    )
                    .map_err(|_| CameraStoreError::Corrupt)
                },
            )
            .collect()
    }

    pub async fn replace_inventory(
        &self,
        camera_id: CameraId,
        value: &CameraInventoryRecord,
    ) -> Result<(), CameraStoreError> {
        if value.capabilities.len() > MAX_CAPABILITIES
            || value
                .capabilities
                .iter()
                .map(BoundedMetadata::as_str)
                .collect::<BTreeSet<_>>()
                .len()
                != value.capabilities.len()
        {
            return Err(CameraStoreError::Invalid);
        }
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        sqlx::query(
            "INSERT INTO camera_inventory(camera_id, manufacturer, model, firmware, serial, health) \
             VALUES(?, ?, ?, ?, ?, ?) \
             ON CONFLICT(camera_id) DO UPDATE SET manufacturer=excluded.manufacturer, \
             model=excluded.model, firmware=excluded.firmware, serial=excluded.serial, health=excluded.health",
        )
        .bind(camera_id.to_string())
        .bind(value.manufacturer.as_ref().map(BoundedMetadata::as_str))
        .bind(value.model.as_ref().map(BoundedMetadata::as_str))
        .bind(value.firmware.as_ref().map(BoundedMetadata::as_str))
        .bind(value.serial.as_ref().map(BoundedSerial::as_str))
        .bind(onvif_health_string(value.health))
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        sqlx::query("DELETE FROM camera_capabilities WHERE camera_id = ?")
            .bind(camera_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        for capability in &value.capabilities {
            sqlx::query("INSERT INTO camera_capabilities(camera_id, capability) VALUES(?, ?)")
                .bind(camera_id.to_string())
                .bind(capability.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        }
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    pub async fn load_inventory(
        &self,
        camera_id: CameraId,
    ) -> Result<Option<CameraInventoryRecord>, CameraStoreError> {
        let row: Option<InventoryRow> = sqlx::query_as(
            "SELECT camera_id, manufacturer, model, firmware, serial, health \
                 FROM camera_inventory WHERE camera_id = ?",
        )
        .bind(camera_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let Some((raw_id, manufacturer, model, firmware, serial, health)) = row else {
            return Ok(None);
        };
        if decode_camera_id(&raw_id)? != camera_id {
            return Err(CameraStoreError::Corrupt);
        }
        let capability_rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT camera_id, capability FROM camera_capabilities WHERE camera_id = ? ORDER BY capability",
        )
        .bind(camera_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if capability_rows.len() > MAX_CAPABILITIES {
            return Err(CameraStoreError::Corrupt);
        }
        let capabilities = capability_rows
            .into_iter()
            .map(|(raw_id, capability)| {
                if decode_camera_id(&raw_id)? != camera_id {
                    return Err(CameraStoreError::Corrupt);
                }
                BoundedMetadata::new(capability).map_err(|_| CameraStoreError::Corrupt)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(CameraInventoryRecord {
            manufacturer: decode_metadata(manufacturer)?,
            model: decode_metadata(model)?,
            firmware: decode_metadata(firmware)?,
            serial: serial
                .map(BoundedSerial::new)
                .transpose()
                .map_err(|_| CameraStoreError::Corrupt)?,
            capabilities,
            health: decode_onvif_health(&health)?,
        }))
    }

    pub async fn put_stream_ref(
        &self,
        camera_id: CameraId,
        profile: &CameraProfile,
    ) -> Result<(), CameraStoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let existing_owner: Option<String> =
            sqlx::query_scalar("SELECT camera_id FROM camera_stream_refs WHERE stream_id = ?")
                .bind(profile.stream_id().to_string())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        if let Some(existing_owner) = existing_owner {
            if decode_camera_id(&existing_owner)? != camera_id {
                return Err(CameraStoreError::Conflict);
            }
            sqlx::query("UPDATE camera_stream_refs SET source_ref = ? WHERE stream_id = ?")
                .bind(profile.source_ref().as_str())
                .bind(profile.stream_id().to_string())
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        } else {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM camera_stream_refs WHERE camera_id = ?")
                    .bind(camera_id.to_string())
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(map_sqlx)?;
            if count >= i64::try_from(MAX_STREAM_REFS).map_err(|_| CameraStoreError::Storage)? {
                return Err(CameraStoreError::Capacity);
            }
            sqlx::query(
                "INSERT INTO camera_stream_refs(camera_id, stream_id, source_ref) VALUES(?, ?, ?)",
            )
            .bind(camera_id.to_string())
            .bind(profile.stream_id().to_string())
            .bind(profile.source_ref().as_str())
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        }
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    pub async fn load_stream_refs(
        &self,
        camera_id: CameraId,
    ) -> Result<Vec<CameraProfile>, CameraStoreError> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT camera_id, stream_id, source_ref FROM camera_stream_refs \
             WHERE camera_id = ? ORDER BY stream_id LIMIT ?",
        )
        .bind(camera_id.to_string())
        .bind(i64::try_from(MAX_STREAM_REFS + 1).map_err(|_| CameraStoreError::Storage)?)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if rows.len() > MAX_STREAM_REFS {
            return Err(CameraStoreError::Corrupt);
        }
        rows.into_iter()
            .map(|row| decode_profile_row(camera_id, row))
            .collect()
    }

    pub async fn load_stream_ref(
        &self,
        camera_id: CameraId,
        stream_id: StreamId,
    ) -> Result<Option<CameraProfile>, CameraStoreError> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT camera_id, stream_id, source_ref FROM camera_stream_refs \
             WHERE camera_id = ? AND stream_id = ?",
        )
        .bind(camera_id.to_string())
        .bind(stream_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(|row| decode_profile_row(camera_id, row))
            .transpose()
    }

    pub async fn delete_camera(&self, camera_id: CameraId) -> Result<bool, CameraStoreError> {
        let result = sqlx::query("DELETE FROM cameras WHERE camera_id = ?")
            .bind(camera_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(result.rows_affected() == 1)
    }
}

fn map_sqlx(error: sqlx::Error) -> CameraStoreError {
    match error {
        sqlx::Error::Database(database) if database.is_unique_violation() => {
            CameraStoreError::Conflict
        }
        sqlx::Error::Database(database) if database.is_foreign_key_violation() => {
            CameraStoreError::Constraint
        }
        _ => CameraStoreError::Storage,
    }
}

fn encode_time(value: DateTime<Utc>) -> Option<String> {
    (value.year() >= 1970 && value.year() <= 9999)
        .then(|| value.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

fn decode_time(value: &str) -> Result<DateTime<Utc>, CameraStoreError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| CameraStoreError::Corrupt)?
        .with_timezone(&Utc);
    if encode_time(parsed).as_deref() == Some(value) {
        Ok(parsed)
    } else {
        Err(CameraStoreError::Corrupt)
    }
}

fn decode_camera_id(value: &str) -> Result<CameraId, CameraStoreError> {
    let uuid = Uuid::parse_str(value).map_err(|_| CameraStoreError::Corrupt)?;
    if uuid.to_string() == value {
        Ok(CameraId::from_uuid(uuid))
    } else {
        Err(CameraStoreError::Corrupt)
    }
}

fn decode_confidence(value: f64) -> Result<Confidence, CameraStoreError> {
    if !value.is_finite() || value < f64::from(f32::MIN) || value > f64::from(f32::MAX) {
        return Err(CameraStoreError::Corrupt);
    }
    Confidence::new(value as f32).map_err(|_| CameraStoreError::Corrupt)
}

fn classification_string(value: CameraClassification) -> &'static str {
    match value {
        CameraClassification::Camera => "camera",
        CameraClassification::PossibleCamera => "possible_camera",
        CameraClassification::Unknown => "unknown",
    }
}
fn decode_classification(value: &str) -> Result<CameraClassification, CameraStoreError> {
    match value {
        "camera" => Ok(CameraClassification::Camera),
        "possible_camera" => Ok(CameraClassification::PossibleCamera),
        "unknown" => Ok(CameraClassification::Unknown),
        _ => Err(CameraStoreError::Corrupt),
    }
}
fn camera_health_string(value: CameraHealth) -> &'static str {
    match value {
        CameraHealth::Healthy => "healthy",
        CameraHealth::Degraded => "degraded",
        CameraHealth::Unknown => "unknown",
    }
}
fn decode_camera_health(value: &str) -> Result<CameraHealth, CameraStoreError> {
    match value {
        "healthy" => Ok(CameraHealth::Healthy),
        "degraded" => Ok(CameraHealth::Degraded),
        "unknown" => Ok(CameraHealth::Unknown),
        _ => Err(CameraStoreError::Corrupt),
    }
}
fn onvif_health_string(value: OnvifHealth) -> &'static str {
    match value {
        OnvifHealth::Healthy => "healthy",
        OnvifHealth::Degraded => "degraded",
    }
}
fn decode_onvif_health(value: &str) -> Result<OnvifHealth, CameraStoreError> {
    match value {
        "healthy" => Ok(OnvifHealth::Healthy),
        "degraded" => Ok(OnvifHealth::Degraded),
        _ => Err(CameraStoreError::Corrupt),
    }
}
fn evidence_family_string(value: CameraEvidenceFamily) -> &'static str {
    match value {
        CameraEvidenceFamily::Onvif => "onvif",
        CameraEvidenceFamily::WsDiscovery => "ws_discovery",
        CameraEvidenceFamily::Rtsp => "rtsp",
        CameraEvidenceFamily::Upnp => "upnp",
        CameraEvidenceFamily::Http => "http",
        CameraEvidenceFamily::Tls => "tls",
        CameraEvidenceFamily::Service => "service",
        CameraEvidenceFamily::Behavior => "behavior",
    }
}
fn decode_evidence_family(value: &str) -> Result<CameraEvidenceFamily, CameraStoreError> {
    match value {
        "onvif" => Ok(CameraEvidenceFamily::Onvif),
        "ws_discovery" => Ok(CameraEvidenceFamily::WsDiscovery),
        "rtsp" => Ok(CameraEvidenceFamily::Rtsp),
        "upnp" => Ok(CameraEvidenceFamily::Upnp),
        "http" => Ok(CameraEvidenceFamily::Http),
        "tls" => Ok(CameraEvidenceFamily::Tls),
        "service" => Ok(CameraEvidenceFamily::Service),
        "behavior" => Ok(CameraEvidenceFamily::Behavior),
        _ => Err(CameraStoreError::Corrupt),
    }
}

fn decode_metadata(value: Option<String>) -> Result<Option<BoundedMetadata>, CameraStoreError> {
    value
        .map(BoundedMetadata::new)
        .transpose()
        .map_err(|_| CameraStoreError::Corrupt)
}

fn decode_profile_row(
    camera_id: CameraId,
    (raw_id, stream_id, source_ref): (String, String, String),
) -> Result<CameraProfile, CameraStoreError> {
    if decode_camera_id(&raw_id)? != camera_id {
        return Err(CameraStoreError::Corrupt);
    }
    let stream_uuid = Uuid::parse_str(&stream_id).map_err(|_| CameraStoreError::Corrupt)?;
    if stream_uuid.to_string() != stream_id {
        return Err(CameraStoreError::Corrupt);
    }
    let source_ref = StreamSourceRef::new(source_ref).map_err(|_| CameraStoreError::Corrupt)?;
    Ok(CameraProfile::new(
        StreamId::from_uuid(stream_uuid),
        source_ref,
    ))
}
