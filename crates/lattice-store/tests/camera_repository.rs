use chrono::{Duration, TimeZone, Utc};
use lattice_camera::{
    BoundedMetadata, BoundedSerial, CameraClassification, CameraEvidence, CameraEvidenceFamily,
    CameraHealth, CameraId, CameraProfile, Confidence, OnvifHealth, StreamId, StreamSourceRef,
};
use lattice_store::{
    CameraInventoryRecord, CameraRecord, CameraRepository, CameraStoreError, CameraTarget,
    connect_memory, connect_path,
};
use std::net::Ipv4Addr;
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
    let version: i64 =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE version=23 AND success=1")
            .fetch_one(&pool)
            .await?;
    assert_eq!(version, 23);
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

fn target() -> CameraTarget {
    CameraTarget {
        camera_id: id(),
        interface: "eth0".into(),
        address: Ipv4Addr::new(192, 168, 1, 50),
        onvif_port: 80,
        rtsp_port: 554,
        allow_basic: false,
        approved_at: at(1_700_000_100),
        name: Some("Porch".into()),
    }
}

fn profile(reference: &str) -> CameraProfile {
    CameraProfile::new(StreamId::new(), StreamSourceRef::new(reference).unwrap())
}

fn other_id() -> CameraId {
    CameraId::from_uuid(Uuid::parse_str("018f0000-0000-7000-8000-000000000002").unwrap())
}

#[tokio::test]
async fn camera_target_round_trips_and_survives_reopen() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("targets.db");
    let pool = connect_path(&path).await?;
    let repository = CameraRepository::new(pool.clone());
    repository.upsert_camera(&camera()).await?;
    repository.put_camera_target(&target()).await?;
    pool.close().await;
    let repository = CameraRepository::new(connect_path(&path).await?);
    assert_eq!(repository.load_camera_target(id()).await?, Some(target()));
    assert_eq!(repository.list_camera_targets().await?, vec![target()]);
    let mut basic = target();
    basic.allow_basic = true;
    basic.name = None;
    assert!(repository.delete_camera_target(id()).await?);
    assert!(!repository.delete_camera_target(id()).await?);
    repository.put_camera_target(&basic).await?;
    assert_eq!(repository.load_camera_target(id()).await?, Some(basic));
    Ok(())
}

#[tokio::test]
async fn camera_target_needs_a_camera_and_one_row_per_camera_and_address() -> anyhow::Result<()> {
    let repository = CameraRepository::new(connect_memory().await?);
    assert_eq!(
        repository.put_camera_target(&target()).await,
        Err(CameraStoreError::Constraint)
    );
    repository.upsert_camera(&camera()).await?;
    repository.put_camera_target(&target()).await?;
    assert_eq!(
        repository.put_camera_target(&target()).await,
        Err(CameraStoreError::Conflict)
    );
    repository
        .upsert_camera(&CameraRecord {
            id: other_id(),
            ..camera()
        })
        .await?;
    // The same host cannot be approved for two cameras.
    let same_host = CameraTarget {
        camera_id: other_id(),
        ..target()
    };
    assert_eq!(
        repository.put_camera_target(&same_host).await,
        Err(CameraStoreError::Conflict)
    );
    Ok(())
}

#[tokio::test]
async fn camera_target_rejects_invalid_values_and_cascades_on_camera_delete() -> anyhow::Result<()>
{
    let repository = CameraRepository::new(connect_memory().await?);
    repository.upsert_camera(&camera()).await?;
    for broken in [
        CameraTarget {
            interface: String::new(),
            ..target()
        },
        CameraTarget {
            interface: "x".repeat(257),
            ..target()
        },
        CameraTarget {
            onvif_port: 0,
            ..target()
        },
        CameraTarget {
            rtsp_port: 0,
            ..target()
        },
        CameraTarget {
            name: Some(String::new()),
            ..target()
        },
        CameraTarget {
            name: Some("n".repeat(65)),
            ..target()
        },
        CameraTarget {
            name: Some("line\nbreak".into()),
            ..target()
        },
    ] {
        assert_eq!(
            repository.put_camera_target(&broken).await,
            Err(CameraStoreError::Invalid)
        );
    }
    repository.put_camera_target(&target()).await?;
    assert!(repository.delete_camera(id()).await?);
    assert_eq!(repository.load_camera_target(id()).await?, None);
    assert!(repository.list_camera_targets().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn corrupt_camera_target_rows_are_reported_not_trusted() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = CameraRepository::new(pool.clone());
    repository.upsert_camera(&camera()).await?;
    repository.put_camera_target(&target()).await?;
    // The schema itself refuses a hostname in the address column.
    assert!(
        sqlx::query("UPDATE camera_targets SET address = 'camera.local'")
            .execute(&pool)
            .await
            .is_err()
    );
    // A non-canonical address spelling (leading zero) was never written by us.
    sqlx::query("UPDATE camera_targets SET address = '192.168.001.050'")
        .execute(&pool)
        .await?;
    assert_eq!(
        repository.load_camera_target(id()).await,
        Err(CameraStoreError::Corrupt)
    );
    assert_eq!(
        repository.list_camera_targets().await,
        Err(CameraStoreError::Corrupt)
    );
    Ok(())
}

#[tokio::test]
async fn onboarded_camera_is_written_all_or_nothing() -> anyhow::Result<()> {
    let repository = CameraRepository::new(connect_memory().await?);
    let profiles = vec![profile("opaque-a"), profile("opaque-b")];
    repository
        .insert_onboarded_camera(&camera(), &inventory_record(), &profiles, &target())
        .await?;
    assert_eq!(repository.load_camera(id()).await?, Some(camera()));
    assert_eq!(
        repository.load_inventory(id()).await?,
        Some(inventory_record())
    );
    assert_eq!(repository.load_stream_refs(id()).await?.len(), 2);
    assert_eq!(repository.load_camera_target(id()).await?, Some(target()));

    // A second camera at the same address fails at the last statement and
    // leaves nothing behind: no camera, inventory, capability or stream row.
    let second = CameraRecord {
        id: other_id(),
        ..camera()
    };
    let second_target = CameraTarget {
        camera_id: other_id(),
        ..target()
    };
    assert_eq!(
        repository
            .insert_onboarded_camera(
                &second,
                &inventory_record(),
                &[profile("opaque-c")],
                &second_target
            )
            .await,
        Err(CameraStoreError::Conflict)
    );
    assert_eq!(repository.load_camera(other_id()).await?, None);
    assert_eq!(repository.load_inventory(other_id()).await?, None);
    assert!(repository.load_stream_refs(other_id()).await?.is_empty());

    // A target for a different camera than the record is refused up front.
    assert_eq!(
        repository
            .insert_onboarded_camera(&second, &inventory_record(), &[], &target())
            .await,
        Err(CameraStoreError::Invalid)
    );
    Ok(())
}

#[tokio::test]
async fn camera_targets_are_capped() -> anyhow::Result<()> {
    let repository = CameraRepository::new(connect_memory().await?);
    for n in 0..lattice_store::MAX_CAMERA_TARGETS {
        let camera_id = CameraId::from_uuid(Uuid::from_u128(0x1000 + n as u128));
        repository
            .upsert_camera(&CameraRecord {
                id: camera_id,
                ..camera()
            })
            .await?;
        repository
            .put_camera_target(&CameraTarget {
                camera_id,
                address: Ipv4Addr::new(10, 0, (n / 200) as u8, (n % 200) as u8 + 1),
                ..target()
            })
            .await?;
    }
    let extra = CameraId::from_uuid(Uuid::from_u128(0x9999));
    repository
        .upsert_camera(&CameraRecord {
            id: extra,
            ..camera()
        })
        .await?;
    assert_eq!(
        repository
            .put_camera_target(&CameraTarget {
                camera_id: extra,
                address: Ipv4Addr::new(10, 9, 9, 9),
                ..target()
            })
            .await,
        Err(CameraStoreError::Capacity)
    );
    Ok(())
}
