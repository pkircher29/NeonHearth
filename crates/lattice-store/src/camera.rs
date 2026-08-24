use chrono::{DateTime, Utc};
use lattice_camera::{CameraId, Confidence, StreamId, StreamSourceRef};
use sqlx::SqlitePool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone)]
pub struct CameraRepository {
    pool: SqlitePool,
}
#[derive(Clone)]
pub struct NewCamera {
    pub id: CameraId,
    pub classification: String,
    pub confidence: Confidence,
    pub health: String,
    pub observed_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct CameraInventoryRecord {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub serial: Option<String>,
    pub capabilities: Vec<String>,
}
#[derive(Clone, Debug)]
pub struct StoredCamera {
    pub id: CameraId,
    pub classification: String,
    pub confidence: Confidence,
    pub health: String,
    pub observed_at: DateTime<Utc>,
}
#[derive(Debug, Error)]
pub enum CameraStoreError {
    #[error("invalid camera record")]
    Invalid,
    #[error("camera data is corrupt")]
    Corrupt,
    #[error("camera storage failed")]
    Storage(#[from] sqlx::Error),
}
impl CameraRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
    pub async fn insert(&self, value: NewCamera) -> Result<(), CameraStoreError> {
        if !matches!(
            value.classification.as_str(),
            "camera" | "possible_camera" | "unknown"
        ) || value.health.is_empty()
            || value.health.len() > 32
        {
            return Err(CameraStoreError::Invalid);
        }
        sqlx::query("INSERT INTO cameras(camera_id,classification,confidence,health,observed_at) VALUES(?,?,?,?,?)").bind(value.id.to_string()).bind(value.classification).bind(value.confidence.get()).bind(value.health).bind(value.observed_at.to_rfc3339()).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn get(&self, id: CameraId) -> Result<Option<StoredCamera>, CameraStoreError> {
        let row:Option<(String,String,f32,String,String)>=sqlx::query_as("SELECT camera_id,classification,confidence,health,observed_at FROM cameras WHERE camera_id=?").bind(id.to_string()).fetch_optional(&self.pool).await?;
        row.map(|(id, classification, confidence, health, at)| {
            Ok(StoredCamera {
                id: CameraId::from_uuid(
                    Uuid::parse_str(&id).map_err(|_| CameraStoreError::Corrupt)?,
                ),
                classification,
                confidence: Confidence::new(confidence).map_err(|_| CameraStoreError::Corrupt)?,
                health,
                observed_at: DateTime::parse_from_rfc3339(&at)
                    .map_err(|_| CameraStoreError::Corrupt)?
                    .with_timezone(&Utc),
            })
        })
        .transpose()
    }
    pub async fn save_inventory(
        &self,
        id: CameraId,
        value: CameraInventoryRecord,
    ) -> Result<(), CameraStoreError> {
        for v in [
            &value.manufacturer,
            &value.model,
            &value.firmware,
            &value.serial,
        ] {
            if v.as_ref().is_some_and(|s| s.len() > 128) {
                return Err(CameraStoreError::Invalid);
            }
        }
        if value
            .capabilities
            .iter()
            .any(|v| v.is_empty() || v.len() > 64)
        {
            return Err(CameraStoreError::Invalid);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO camera_inventory(camera_id,manufacturer,model,firmware,serial) VALUES(?,?,?,?,?) ON CONFLICT(camera_id) DO UPDATE SET manufacturer=excluded.manufacturer,model=excluded.model,firmware=excluded.firmware,serial=excluded.serial").bind(id.to_string()).bind(value.manufacturer).bind(value.model).bind(value.firmware).bind(value.serial).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM camera_capabilities WHERE camera_id=?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        for c in value.capabilities {
            sqlx::query("INSERT INTO camera_capabilities(camera_id,capability) VALUES(?,?)")
                .bind(id.to_string())
                .bind(c)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn add_stream_ref(
        &self,
        id: CameraId,
        stream: StreamId,
        source_ref: StreamSourceRef,
    ) -> Result<(), CameraStoreError> {
        sqlx::query("INSERT INTO camera_stream_refs(camera_id,stream_id,source_ref) VALUES(?,?,?)")
            .bind(id.to_string())
            .bind(stream.to_string())
            .bind(source_ref.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn stream_refs(&self, id: CameraId) -> Result<Vec<StreamId>, CameraStoreError> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT stream_id FROM camera_stream_refs WHERE camera_id=? ORDER BY stream_id",
        )
        .bind(id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|v| {
                Uuid::parse_str(&v)
                    .map(StreamId::from_uuid)
                    .map_err(|_| CameraStoreError::Corrupt)
            })
            .collect()
    }
}
