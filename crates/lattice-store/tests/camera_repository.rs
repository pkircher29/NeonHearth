use chrono::{Duration, TimeZone, Utc};
use lattice_camera::{
    BoundedMetadata, BoundedSerial, CameraClassification, CameraEvidence, CameraEvidenceFamily,
    CameraHealth, CameraId, CameraProfile, Confidence, OnvifHealth, StreamId, StreamSourceRef,
};
use lattice_store::{
    CameraInventoryRecord, CameraRecord, CameraRepository, CameraStoreError, connect_memory,
    connect_path,
};
use tempfile::tempdir;
use uuid::Uuid;

fn at(second: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(second, 0).single().unwrap()
}

fn id() -> CameraId {
    CameraId::from_uuid(Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap())
}

fn camera() -> CameraRecord {
    CameraRecord {
        id: id(),
        classification: CameraClassification::Camera,
        confidence: Confidence::new(0.91).unwrap(),
        health: CameraHealth::Healthy,
        observed_at: at(1_700_000_000),
    }
}

fn evidence() -> CameraEvidence {
    CameraEvidence::new(
        CameraEvidenceFamily::Onvif,
        "authenticated-onvif",
        "onvif_camera_profile",
        0.93,
        at(1_700_000_001),
        Some(at(1_700_000_001) + Duration::minutes(10)),
    )
    .unwrap()
}

fn inventory_record() -> CameraInventoryRecord {
    CameraInventoryRecord {
        manufacturer: Some(BoundedMetadata::new("Acme Cameras").unwrap()),
        model: Some(BoundedMetadata::new("Cam-1").unwrap()),
        firmware: Some(BoundedMetadata::new("1.2.3").unwrap()),
        serial: Some(BoundedSerial::new("SN-42").unwrap()),
        capabilities: vec![BoundedMetadata::new("media").unwrap()],
        health: OnvifHealth::Healthy,
    }
}

#[tokio::test]
async fn all_typed_camera_records_round_trip_after_reopen() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("camera.db");
    let pool = connect_path(&path).await?;
    let repository = CameraRepository::new(pool.clone());
    let camera = camera();
    repository.upsert_camera(&camera).await?;
    repository.upsert_camera(&camera).await?;
    repository.insert_evidence(camera.id, &evidence()).await?;
    repository
        .replace_inventory(camera.id, &inventory_record())
        .await?;
    let profile = CameraProfile::new(
        StreamId::from_uuid(Uuid::parse_str("018f0000-0000-7000-8000-000000000002").unwrap()),
        StreamSourceRef::new("opaque-source-ref").unwrap(),
    );
    repository.put_stream_ref(camera.id, &profile).await?;
    drop(repository);
    pool.close().await;

    let pool = connect_path(&path).await?;
    let repository = CameraRepository::new(pool.clone());
    assert_eq!(
        repository.load_camera(camera.id).await?,
        Some(camera.clone())
    );
    let evidence = repository.load_evidence(camera.id, 64).await?;
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].source(), "authenticated-onvif");
    assert_eq!(evidence[0].fact(), "onvif_camera_profile");
    assert_eq!(evidence[0].confidence(), Confidence::new(0.93).unwrap());
    assert_eq!(evidence[0].observed_at(), at(1_700_000_001));
    assert_eq!(
        evidence[0].expires_at(),
        Some(at(1_700_000_001) + Duration::minutes(10))
    );
    assert_eq!(
        repository.load_inventory(camera.id).await?,
        Some(inventory_record())
    );
    assert_eq!(repository.load_stream_refs(camera.id).await?, vec![profile]);
    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn foreign_keys_uniqueness_and_delete_cascade_are_enforced() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = CameraRepository::new(pool.clone());
    let missing = CameraId::from_uuid(Uuid::now_v7());
    assert_eq!(
        repository
            .insert_evidence(missing, &evidence())
            .await
            .unwrap_err(),
        CameraStoreError::Constraint
    );
    repository.upsert_camera(&camera()).await?;
    repository.insert_evidence(id(), &evidence()).await?;
    assert_eq!(
        repository
            .insert_evidence(id(), &evidence())
            .await
            .unwrap_err(),
        CameraStoreError::Conflict
    );
    repository
        .replace_inventory(id(), &inventory_record())
        .await?;
    let profile = CameraProfile::new(StreamId::new(), StreamSourceRef::new("opaque-one").unwrap());
    repository.put_stream_ref(id(), &profile).await?;
    assert_eq!(
        repository
            .load_stream_ref(id(), profile.stream_id())
            .await?,
        Some(profile.clone())
    );
    let other_id = CameraId::from_uuid(Uuid::now_v7());
    let mut other_camera = camera();
    other_camera.id = other_id;
    repository.upsert_camera(&other_camera).await?;
    assert_eq!(
        repository
            .load_stream_ref(other_id, profile.stream_id())
            .await?,
        None
    );
    let ownership_collision = CameraProfile::new(
        profile.stream_id(),
        StreamSourceRef::new("opaque-other").unwrap(),
    );
    assert_eq!(
        repository
            .put_stream_ref(other_id, &ownership_collision)
            .await
            .unwrap_err(),
        CameraStoreError::Conflict
    );
    assert_eq!(
        repository.load_stream_refs(id()).await?,
        vec![profile.clone()]
    );
    let duplicate_ref =
        CameraProfile::new(StreamId::new(), StreamSourceRef::new("opaque-one").unwrap());
    assert_eq!(
        repository
            .put_stream_ref(id(), &duplicate_ref)
            .await
            .unwrap_err(),
        CameraStoreError::Conflict
    );
    assert!(repository.delete_camera(id()).await?);
    assert!(!repository.delete_camera(id()).await?);
    assert_eq!(repository.load_camera(id()).await?, None);
    assert!(repository.load_evidence(id(), 64).await?.is_empty());
    assert_eq!(repository.load_inventory(id()).await?, None);
    assert!(repository.load_stream_refs(id()).await?.is_empty());
    assert_eq!(
        repository
            .load_stream_ref(id(), profile.stream_id())
            .await?,
        None
    );
    for table in [
        "camera_evidence",
        "camera_inventory",
        "camera_capabilities",
        "camera_stream_refs",
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await?;
        assert_eq!(count, 0, "{table}");
    }
    Ok(())
}

#[tokio::test]
async fn writes_limits_schema_columns_checks_and_indexes_are_complete() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = CameraRepository::new(pool.clone());
    repository.upsert_camera(&camera()).await?;
    let mut oversized = inventory_record();
    oversized.capabilities = (0..33)
        .map(|index| BoundedMetadata::new(format!("cap-{index}")).unwrap())
        .collect();
    assert_eq!(
        repository
            .replace_inventory(id(), &oversized)
            .await
            .unwrap_err(),
        CameraStoreError::Invalid
    );
    assert_eq!(
        repository.load_evidence(id(), 0).await.unwrap_err(),
        CameraStoreError::Invalid
    );
    assert_eq!(
        repository.load_evidence(id(), 65).await.unwrap_err(),
        CameraStoreError::Invalid
    );
    for index in 0..64 {
        repository
            .put_stream_ref(
                id(),
                &CameraProfile::new(
                    StreamId::new(),
                    StreamSourceRef::new(format!("bounded-{index}")).unwrap(),
                ),
            )
            .await?;
    }
    assert_eq!(repository.load_stream_refs(id()).await?.len(), 64);
    assert_eq!(
        repository
            .put_stream_ref(
                id(),
                &CameraProfile::new(
                    StreamId::new(),
                    StreamSourceRef::new("bounded-overflow").unwrap(),
                ),
            )
            .await
            .unwrap_err(),
        CameraStoreError::Capacity
    );

    let evidence_columns: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('camera_evidence') ORDER BY cid")
            .fetch_all(&pool)
            .await?;
    assert_eq!(
        evidence_columns,
        [
            "camera_id",
            "family",
            "source",
            "fact",
            "confidence",
            "observed_at",
            "expires_at"
        ]
    );
    let inventory_columns: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('camera_inventory') ORDER BY cid")
            .fetch_all(&pool)
            .await?;
    assert_eq!(
        inventory_columns,
        [
            "camera_id",
            "manufacturer",
            "model",
            "firmware",
            "serial",
            "health"
        ]
    );
    let migration_sql: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='camera_evidence'",
    )
    .fetch_one(&pool)
    .await?;
    for required in ["confidence", "expires_at", "CHECK", "ON DELETE CASCADE"] {
        assert!(migration_sql.contains(required), "missing {required}");
    }
    let indexes: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_index_list('camera_evidence')")
            .fetch_all(&pool)
            .await?;
    assert!(
        indexes
            .iter()
            .any(|name| name == "camera_evidence_camera_observed_idx")
    );
    assert!(
        indexes
            .iter()
            .any(|name| name == "camera_evidence_expiry_idx")
    );
    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await?;
    assert_eq!(version, 21);
    Ok(())
}

#[tokio::test]
async fn corrupt_rows_in_every_camera_table_are_rejected_without_payloads() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO cameras(camera_id,classification,confidence,health,observed_at) VALUES(?, 'not-a-classification', 2.0, 'healthy', 'bad-time')")
        .bind(id().to_string()).execute(&pool).await?;
    let repository = CameraRepository::new(pool.clone());
    let error = repository.load_camera(id()).await.unwrap_err();
    assert_eq!(error, CameraStoreError::Corrupt);
    assert_eq!(format!("{error:?}"), "Corrupt");
    assert_eq!(error.to_string(), "camera data is corrupt");
    sqlx::query("UPDATE cameras SET classification='camera', confidence=0.9, observed_at=? WHERE camera_id=?")
        .bind(at(1_700_000_000).to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
        .bind(id().to_string()).execute(&pool).await?;
    sqlx::query("INSERT INTO camera_evidence(camera_id,family,source,fact,confidence,observed_at,expires_at) VALUES(?, 'bad-family', 'source', 'fact', 0.5, ?, NULL)")
        .bind(id().to_string()).bind(at(1_700_000_001).to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)).execute(&pool).await?;
    assert_eq!(
        repository.load_evidence(id(), 64).await.unwrap_err(),
        CameraStoreError::Corrupt
    );
    sqlx::query("DELETE FROM camera_evidence")
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO camera_inventory(camera_id,manufacturer,model,firmware,serial,health) VALUES(?, 'rtsp://corrupt.invalid', NULL, NULL, NULL, 'healthy')")
        .bind(id().to_string()).execute(&pool).await?;
    assert_eq!(
        repository.load_inventory(id()).await.unwrap_err(),
        CameraStoreError::Corrupt
    );
    sqlx::query("DELETE FROM camera_inventory")
        .execute(&pool)
        .await?;
    sqlx::query(
        "INSERT INTO camera_stream_refs(camera_id,stream_id,source_ref) VALUES(?, ?, 'bad/ref')",
    )
    .bind(id().to_string())
    .bind(Uuid::now_v7().to_string())
    .execute(&pool)
    .await?;
    assert_eq!(
        repository.load_stream_refs(id()).await.unwrap_err(),
        CameraStoreError::Corrupt
    );
    pool.close().await;
    let error = repository.load_camera(id()).await.unwrap_err();
    assert_eq!(error, CameraStoreError::Storage);
    assert_eq!(format!("{error:?}"), "Storage");
    Ok(())
}

#[tokio::test]
async fn whole_database_never_contains_rejected_secret_sentinel() -> anyhow::Result<()> {
    const SENTINEL: &str = "whole-db-camera-secret-sentinel";
    assert!(BoundedMetadata::new(format!("rtsp://{SENTINEL}.invalid/live")).is_err());
    let directory = tempdir()?;
    let path = directory.path().join("sentinel.db");
    let pool = connect_path(&path).await?;
    let repository = CameraRepository::new(pool.clone());
    repository.upsert_camera(&camera()).await?;
    repository.insert_evidence(id(), &evidence()).await?;
    repository
        .replace_inventory(id(), &inventory_record())
        .await?;
    repository
        .put_stream_ref(
            id(),
            &CameraProfile::new(
                StreamId::new(),
                StreamSourceRef::new("opaque-vault-ref").unwrap(),
            ),
        )
        .await?;
    drop(repository);
    pool.close().await;
    let bytes = std::fs::read(&path)?;
    assert!(
        !bytes
            .windows(SENTINEL.len())
            .any(|window| window == SENTINEL.as_bytes())
    );
    Ok(())
}
