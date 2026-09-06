use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use lattice_domain::{
    DeviceId, FloorId, HomeId, HomePlan, LocationEstimate, Mounting, OwnerPlacement, PlacementId,
    PlanValidationError, RoomId,
};
use sqlx::SqlitePool;
use thiserror::Error;
use uuid::Uuid;

/// Server-side draft cap (512 KiB), mirrored by the migration CHECK.
pub const MAX_DRAFT_BYTES: usize = 524_288;
/// Committed plan JSON cap, mirrored by the migration CHECK.
pub const MAX_PLAN_BYTES: usize = 1_048_576;
/// Only the newest rows of `home_plan_history` are retained.
pub const PLAN_HISTORY_KEEP: u32 = 100;
const MAX_ESTIMATE_EVIDENCE: usize = 32;
const MAX_EVIDENCE_ENTRY_CHARS: usize = 128;
const MAX_PLACEMENT_HEIGHT_M: f64 = 6.0;
const MAX_COORDINATE_M: f64 = 1000.0;

type PlacementRow = (
    String,
    String,
    String,
    f64,
    f64,
    Option<f64>,
    Option<String>,
);
type EstimateRow = (String, Option<String>, Option<String>, f64, String, String);

#[derive(Clone)]
pub struct HomeRepository {
    pool: SqlitePool,
}

/// A loaded committed plan. `recovered_from_history` is true when the current
/// row's JSON failed to parse or validate and the plan body was recovered from
/// the newest valid history row (H3). The recovered plan keeps the current
/// row's version number so optimistic concurrency stays coherent.
#[derive(Clone, Debug, PartialEq)]
pub struct LoadedPlan {
    pub plan: HomePlan,
    pub recovered_from_history: bool,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum HomeStoreError {
    #[error("plan version conflict: expected {expected}, actual {actual}")]
    VersionConflict { expected: u32, actual: u32 },
    #[error("home plan failed validation: {0}")]
    InvalidPlan(PlanValidationError),
    #[error("home record is invalid")]
    Invalid,
    #[error("draft exceeds the {MAX_DRAFT_BYTES}-byte cap")]
    DraftTooLarge,
    #[error("stored draft was corrupt and has been discarded")]
    DraftCorrupt,
    #[error("home data is corrupt")]
    Corrupt,
    #[error("home storage failed")]
    Storage,
}

impl HomeRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Loads the current committed plan, or `None` when no plan was ever
    /// saved. When the current row's plan body is corrupt, falls back to the
    /// newest valid history row and flags the recovery (H3).
    pub async fn load_plan(&self) -> Result<Option<LoadedPlan>, HomeStoreError> {
        let row: Option<(String, i64, String)> =
            sqlx::query_as("SELECT home_id, version, plan FROM home_plans WHERE singleton = 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx)?;
        let Some((raw_home_id, raw_version, plan_json)) = row else {
            return Ok(None);
        };
        let home_id = decode_id(&raw_home_id, HomeId::parse)?;
        let version = u32::try_from(raw_version).map_err(|_| HomeStoreError::Corrupt)?;
        if let Some(plan) = decode_plan(&plan_json, home_id, version, true) {
            return Ok(Some(LoadedPlan {
                plan,
                recovered_from_history: false,
            }));
        }
        let history: Vec<(String,)> = sqlx::query_as(
            "SELECT plan FROM home_plan_history WHERE home_id = ? ORDER BY version DESC LIMIT ?",
        )
        .bind(&raw_home_id)
        .bind(i64::from(PLAN_HISTORY_KEEP))
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        for (candidate,) in history {
            if let Some(plan) = decode_plan(&candidate, home_id, version, false) {
                return Ok(Some(LoadedPlan {
                    plan,
                    recovered_from_history: true,
                }));
            }
        }
        Err(HomeStoreError::Corrupt)
    }

    /// Commits a whole-plan save with optimistic concurrency. The caller's
    /// `expected_version` must equal the stored version (0 when unset);
    /// otherwise the save is rejected with [`HomeStoreError::VersionConflict`]
    /// (H1). On success the plan is stored with `expected_version + 1`, a
    /// history row is appended, and history is pruned to the newest
    /// [`PLAN_HISTORY_KEEP`] rows — all in one transaction. Returns the new
    /// version.
    pub async fn save_plan(
        &self,
        expected_version: u32,
        plan: &HomePlan,
        now: DateTime<Utc>,
    ) -> Result<u32, HomeStoreError> {
        plan.validate().map_err(HomeStoreError::InvalidPlan)?;
        let saved_at = encode_time(now).ok_or(HomeStoreError::Invalid)?;
        let new_version = expected_version
            .checked_add(1)
            .ok_or(HomeStoreError::Invalid)?;
        let mut stored = plan.clone();
        stored.version = new_version;
        let json = serde_json::to_string(&stored).map_err(|_| HomeStoreError::Storage)?;
        if json.len() > MAX_PLAN_BYTES {
            return Err(HomeStoreError::Invalid);
        }
        // Reserve the writer before reading the version. A deferred read-to-write
        // upgrade can fail immediately while discovery or automation is writing.
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(map_sqlx)?;
        let actual: Option<i64> =
            sqlx::query_scalar("SELECT version FROM home_plans WHERE singleton = 1")
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        let actual = match actual {
            Some(version) => u32::try_from(version).map_err(|_| HomeStoreError::Corrupt)?,
            None => 0,
        };
        if actual != expected_version {
            return Err(HomeStoreError::VersionConflict {
                expected: expected_version,
                actual,
            });
        }
        sqlx::query(
            "INSERT INTO home_plans(singleton, home_id, version, plan, saved_at) \
             VALUES(1, ?, ?, ?, ?) \
             ON CONFLICT(singleton) DO UPDATE SET home_id=excluded.home_id, \
             version=excluded.version, plan=excluded.plan, saved_at=excluded.saved_at",
        )
        .bind(stored.home_id.to_string())
        .bind(i64::from(new_version))
        .bind(&json)
        .bind(&saved_at)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        sqlx::query(
            "INSERT INTO home_plan_history(home_id, version, plan, saved_at) VALUES(?, ?, ?, ?)",
        )
        .bind(stored.home_id.to_string())
        .bind(i64::from(new_version))
        .bind(&json)
        .bind(&saved_at)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let prune_below = i64::from(new_version) - i64::from(PLAN_HISTORY_KEEP);
        if prune_below > 0 {
            sqlx::query("DELETE FROM home_plan_history WHERE version <= ?")
                .bind(prune_below)
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        }
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(new_version)
    }

    /// Stores the editor's uncommitted draft as an opaque JSON blob.
    pub async fn put_draft(
        &self,
        home_id: HomeId,
        draft: &str,
        now: DateTime<Utc>,
    ) -> Result<(), HomeStoreError> {
        if draft.len() > MAX_DRAFT_BYTES {
            return Err(HomeStoreError::DraftTooLarge);
        }
        if serde_json::from_str::<serde::de::IgnoredAny>(draft).is_err() {
            return Err(HomeStoreError::Invalid);
        }
        let updated_at = encode_time(now).ok_or(HomeStoreError::Invalid)?;
        sqlx::query(
            "INSERT INTO home_drafts(home_id, draft, updated_at) VALUES(?, ?, ?) \
             ON CONFLICT(home_id) DO UPDATE SET draft=excluded.draft, updated_at=excluded.updated_at",
        )
        .bind(home_id.to_string())
        .bind(draft)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    /// Returns the stored draft blob. A draft whose stored JSON is invalid is
    /// deleted and reported as [`HomeStoreError::DraftCorrupt`] — it is never
    /// returned or silently merged.
    pub async fn get_draft(&self, home_id: HomeId) -> Result<Option<String>, HomeStoreError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT draft FROM home_drafts WHERE home_id = ?")
                .bind(home_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx)?;
        let Some((draft,)) = row else {
            return Ok(None);
        };
        if serde_json::from_str::<serde::de::IgnoredAny>(&draft).is_err() {
            sqlx::query("DELETE FROM home_drafts WHERE home_id = ?")
                .bind(home_id.to_string())
                .execute(&self.pool)
                .await
                .map_err(map_sqlx)?;
            return Err(HomeStoreError::DraftCorrupt);
        }
        Ok(Some(draft))
    }

    pub async fn delete_draft(&self, home_id: HomeId) -> Result<bool, HomeStoreError> {
        let result = sqlx::query("DELETE FROM home_drafts WHERE home_id = ?")
            .bind(home_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(result.rows_affected() == 1)
    }

    /// Upserts an owner-confirmed placement (authoritative, H4).
    pub async fn upsert_placement(&self, value: &OwnerPlacement) -> Result<(), HomeStoreError> {
        if !coordinate_ok(value.x) || !coordinate_ok(value.y) {
            return Err(HomeStoreError::Invalid);
        }
        if let Some(height) = value.height_m
            && !(height.is_finite() && (0.0..=MAX_PLACEMENT_HEIGHT_M).contains(&height))
        {
            return Err(HomeStoreError::Invalid);
        }
        sqlx::query(
            "INSERT INTO owner_placements(device_id, placement_id, floor_id, x, y, height_m, mounting) \
             VALUES(?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(device_id) DO UPDATE SET placement_id=excluded.placement_id, \
             floor_id=excluded.floor_id, x=excluded.x, y=excluded.y, \
             height_m=excluded.height_m, mounting=excluded.mounting",
        )
        .bind(value.device_id.to_string())
        .bind(value.placement_id.to_string())
        .bind(value.floor_id.to_string())
        .bind(value.x)
        .bind(value.y)
        .bind(value.height_m)
        .bind(value.mounting.map(mounting_string))
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    /// Removes an owner placement, returning the device to the unplaced tray.
    pub async fn delete_placement(&self, device_id: DeviceId) -> Result<bool, HomeStoreError> {
        let result = sqlx::query("DELETE FROM owner_placements WHERE device_id = ?")
            .bind(device_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_placements(&self) -> Result<Vec<OwnerPlacement>, HomeStoreError> {
        let rows: Vec<PlacementRow> = sqlx::query_as(
            "SELECT device_id, placement_id, floor_id, x, y, height_m, mounting \
             FROM owner_placements ORDER BY device_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.into_iter()
            .map(
                |(device_id, placement_id, floor_id, x, y, height_m, mounting)| {
                    if !coordinate_ok(x) || !coordinate_ok(y) {
                        return Err(HomeStoreError::Corrupt);
                    }
                    if let Some(height) = height_m
                        && !(height.is_finite() && (0.0..=MAX_PLACEMENT_HEIGHT_M).contains(&height))
                    {
                        return Err(HomeStoreError::Corrupt);
                    }
                    Ok(OwnerPlacement {
                        placement_id: decode_id(&placement_id, PlacementId::parse)?,
                        device_id: decode_id(&device_id, DeviceId::parse)?,
                        floor_id: decode_id(&floor_id, FloorId::parse)?,
                        x,
                        y,
                        height_m,
                        mounting: mounting.as_deref().map(decode_mounting).transpose()?,
                    })
                },
            )
            .collect()
    }

    /// Upserts an automatic location estimate. This writes only to
    /// `location_estimates`; owner placements are never touched (H4/H5).
    pub async fn upsert_estimate(&self, value: &LocationEstimate) -> Result<(), HomeStoreError> {
        if !(value.confidence.is_finite() && (0.0..=1.0).contains(&value.confidence)) {
            return Err(HomeStoreError::Invalid);
        }
        if value.evidence.len() > MAX_ESTIMATE_EVIDENCE
            || value
                .evidence
                .iter()
                .any(|entry| !(1..=MAX_EVIDENCE_ENTRY_CHARS).contains(&entry.chars().count()))
        {
            return Err(HomeStoreError::Invalid);
        }
        let estimated_at = encode_time(value.estimated_at).ok_or(HomeStoreError::Invalid)?;
        let evidence =
            serde_json::to_string(&value.evidence).map_err(|_| HomeStoreError::Storage)?;
        sqlx::query(
            "INSERT INTO location_estimates(device_id, floor_id, room_id, confidence, evidence, estimated_at) \
             VALUES(?, ?, ?, ?, ?, ?) \
             ON CONFLICT(device_id) DO UPDATE SET floor_id=excluded.floor_id, \
             room_id=excluded.room_id, confidence=excluded.confidence, \
             evidence=excluded.evidence, estimated_at=excluded.estimated_at",
        )
        .bind(value.device_id.to_string())
        .bind(value.floor_id.map(|id| id.to_string()))
        .bind(value.room_id.map(|id| id.to_string()))
        .bind(f64::from(value.confidence))
        .bind(evidence)
        .bind(estimated_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    pub async fn list_estimates(&self) -> Result<Vec<LocationEstimate>, HomeStoreError> {
        let rows: Vec<EstimateRow> = sqlx::query_as(
            "SELECT device_id, floor_id, room_id, confidence, evidence, estimated_at \
             FROM location_estimates ORDER BY device_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.into_iter()
            .map(
                |(device_id, floor_id, room_id, confidence, evidence, estimated_at)| {
                    let evidence: Vec<String> =
                        serde_json::from_str(&evidence).map_err(|_| HomeStoreError::Corrupt)?;
                    if evidence.len() > MAX_ESTIMATE_EVIDENCE
                        || evidence.iter().any(|entry| {
                            !(1..=MAX_EVIDENCE_ENTRY_CHARS).contains(&entry.chars().count())
                        })
                    {
                        return Err(HomeStoreError::Corrupt);
                    }
                    Ok(LocationEstimate {
                        device_id: decode_id(&device_id, DeviceId::parse)?,
                        floor_id: floor_id
                            .as_deref()
                            .map(|id| decode_id(id, FloorId::parse))
                            .transpose()?,
                        room_id: room_id
                            .as_deref()
                            .map(|id| decode_id(id, RoomId::parse))
                            .transpose()?,
                        confidence: decode_confidence(confidence)?,
                        evidence,
                        estimated_at: decode_time(&estimated_at)?,
                    })
                },
            )
            .collect()
    }
}

fn map_sqlx(_error: sqlx::Error) -> HomeStoreError {
    HomeStoreError::Storage
}

fn coordinate_ok(value: f64) -> bool {
    value.is_finite() && (-MAX_COORDINATE_M..=MAX_COORDINATE_M).contains(&value)
}

/// Parses a stored plan body. The stored version column is authoritative: the
/// returned plan is stamped with it. When `require_version_match` is set the
/// embedded version must agree with the column (current-row integrity check);
/// history bodies naturally carry older versions.
fn decode_plan(
    json: &str,
    home_id: HomeId,
    version: u32,
    require_version_match: bool,
) -> Option<HomePlan> {
    let mut plan: HomePlan = serde_json::from_str(json).ok()?;
    if plan.home_id != home_id {
        return None;
    }
    if require_version_match && plan.version != version {
        return None;
    }
    plan.validate().ok()?;
    plan.version = version;
    Some(plan)
}

fn encode_time(value: DateTime<Utc>) -> Option<String> {
    (value.year() >= 1970 && value.year() <= 9999)
        .then(|| value.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

fn decode_time(value: &str) -> Result<DateTime<Utc>, HomeStoreError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| HomeStoreError::Corrupt)?
        .with_timezone(&Utc);
    if encode_time(parsed).as_deref() == Some(value) {
        Ok(parsed)
    } else {
        Err(HomeStoreError::Corrupt)
    }
}

fn decode_id<T>(
    value: &str,
    parse: impl Fn(&str) -> Result<T, uuid::Error>,
) -> Result<T, HomeStoreError> {
    let uuid = Uuid::parse_str(value).map_err(|_| HomeStoreError::Corrupt)?;
    if uuid.to_string() != value {
        return Err(HomeStoreError::Corrupt);
    }
    parse(value).map_err(|_| HomeStoreError::Corrupt)
}

fn decode_confidence(value: f64) -> Result<f32, HomeStoreError> {
    if !(value.is_finite() && (0.0..=1.0).contains(&value)) {
        return Err(HomeStoreError::Corrupt);
    }
    Ok(value as f32)
}

fn mounting_string(value: Mounting) -> &'static str {
    match value {
        Mounting::Wall => "wall",
        Mounting::Ceiling => "ceiling",
        Mounting::Floor => "floor",
        Mounting::Shelf => "shelf",
    }
}

fn decode_mounting(value: &str) -> Result<Mounting, HomeStoreError> {
    match value {
        "wall" => Ok(Mounting::Wall),
        "ceiling" => Ok(Mounting::Ceiling),
        "floor" => Ok(Mounting::Floor),
        "shelf" => Ok(Mounting::Shelf),
        _ => Err(HomeStoreError::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounting_strings_round_trip() {
        for mounting in [
            Mounting::Wall,
            Mounting::Ceiling,
            Mounting::Floor,
            Mounting::Shelf,
        ] {
            assert_eq!(decode_mounting(mounting_string(mounting)), Ok(mounting));
        }
        assert_eq!(decode_mounting("roof"), Err(HomeStoreError::Corrupt));
    }

    #[test]
    fn decode_id_requires_canonical_lowercase_uuids() {
        assert!(decode_id("018F47A0-9B5C-7A22-8A33-112233445566", HomeId::parse).is_err());
        assert!(decode_id("not-a-uuid", HomeId::parse).is_err());
        assert!(decode_id("018f47a0-9b5c-7a22-8a33-112233445566", HomeId::parse).is_ok());
    }

    #[test]
    fn decode_time_requires_canonical_encoding() {
        let now = encode_time(Utc::now()).unwrap();
        assert!(decode_time(&now).is_ok());
        assert_eq!(
            decode_time("2026-08-24T00:00:00Z"),
            Err(HomeStoreError::Corrupt)
        );
        assert_eq!(decode_time("garbage"), Err(HomeStoreError::Corrupt));
    }

    #[test]
    fn decode_confidence_bounds() {
        assert_eq!(decode_confidence(0.5), Ok(0.5));
        assert!(decode_confidence(-0.1).is_err());
        assert!(decode_confidence(1.1).is_err());
        assert!(decode_confidence(f64::NAN).is_err());
    }
}
