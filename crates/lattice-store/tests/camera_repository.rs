use chrono::Utc;
use lattice_camera::{CameraId, Confidence, StreamId, StreamSourceRef};
use lattice_store::{
    CameraInventoryRecord, CameraRepository, CameraStoreError, NewCamera, connect_memory,
};
use uuid::Uuid;
#[tokio::test]
async fn camera_repository_persists_only_bounded_non_secret_records() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repo = CameraRepository::new(pool.clone());
    let id = CameraId::from_uuid(Uuid::nil());
    repo.insert(NewCamera {
        id,
        classification: "camera".into(),
        confidence: Confidence::new(0.9).unwrap(),
        health: "healthy".into(),
        observed_at: Utc::now(),
    })
    .await?;
    repo.save_inventory(
        id,
        CameraInventoryRecord {
            manufacturer: Some("Acme".into()),
            model: None,
            firmware: None,
            serial: Some("SN-42".into()),
            capabilities: vec!["media".into()],
        },
    )
    .await?;
    let stream = StreamId::new();
    repo.add_stream_ref(id, stream, StreamSourceRef::new("opaque-ref").unwrap()).await?;
    assert_eq!(repo.stream_refs(id).await?.len(), 1);
    assert!(
        repo.add_stream_ref(
            CameraId::from_uuid(Uuid::now_v7()),
            StreamId::new(),
            StreamSourceRef::new("opaque-ref").unwrap()
        )
        .await
        .is_err()
    );
    let raw: String =
        sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE name='camera_inventory'")
            .fetch_one(&pool)
            .await?;
    assert!(!raw.contains("password"));
    Ok(())
}

#[tokio::test]
async fn corrupt_rows_are_reported_without_echoing_contents() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let id = CameraId::from_uuid(Uuid::now_v7());
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO cameras(camera_id,classification,confidence,health,observed_at) VALUES(?, 'camera', 2.0, 'healthy', ?)")
        .bind(id.to_string()).bind(Utc::now().to_rfc3339()).execute(&pool).await?;
    let error = CameraRepository::new(pool).get(id).await.unwrap_err();
    assert!(matches!(error, CameraStoreError::Corrupt));
    assert!(!error.to_string().contains(&id.to_string()));
    Ok(())
}
