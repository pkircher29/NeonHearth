use chrono::{DateTime, TimeZone, Utc};
use lattice_domain::{
    DeviceId, EffectiveLocation, Floor, FloorId, HomeId, HomePlan, LocationEstimate, Mounting,
    Opening, OpeningId, OpeningKind, OwnerPlacement, PlacementId, Point, Room, RoomId, Wall,
    WallId, effective_location,
};
use lattice_store::{
    HomeRepository, HomeStoreError, MAX_DRAFT_BYTES, PLAN_HISTORY_KEEP, connect_memory,
    connect_path,
};
use tempfile::tempdir;

fn at(second: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(second, 0).single().unwrap()
}

fn home_id() -> HomeId {
    HomeId::parse("018f0000-0000-7000-8000-0000000000aa").unwrap()
}

fn device_id() -> DeviceId {
    DeviceId::parse("018f0000-0000-7000-8000-0000000000ab").unwrap()
}

fn plan(name: &str) -> HomePlan {
    HomePlan {
        home_id: home_id(),
        version: 0,
        name: name.to_owned(),
        floors: vec![Floor {
            floor_id: FloorId::parse("018f0000-0000-7000-8000-0000000000ac").unwrap(),
            level: 0,
            name: "Ground".to_owned(),
            ceiling_height_m: 2.4,
            walls: vec![Wall {
                wall_id: WallId::parse("018f0000-0000-7000-8000-0000000000ad").unwrap(),
                start: Point { x: 0.0, y: 0.0 },
                end: Point { x: 4.2, y: 0.0 },
                thickness_m: 0.1,
                openings: vec![Opening {
                    opening_id: OpeningId::parse("018f0000-0000-7000-8000-0000000000ae").unwrap(),
                    kind: OpeningKind::Door,
                    offset_m: 0.8,
                    width_m: 0.9,
                }],
            }],
            rooms: vec![Room {
                room_id: RoomId::parse("018f0000-0000-7000-8000-0000000000af").unwrap(),
                name: "Kitchen".to_owned(),
                polygon: vec![
                    Point { x: 0.0, y: 0.0 },
                    Point { x: 4.0, y: 0.0 },
                    Point { x: 4.0, y: 3.0 },
                    Point { x: 0.0, y: 3.0 },
                ],
            }],
        }],
    }
}

fn placement() -> OwnerPlacement {
    OwnerPlacement {
        placement_id: PlacementId::parse("018f0000-0000-7000-8000-0000000000b0").unwrap(),
        device_id: device_id(),
        floor_id: FloorId::parse("018f0000-0000-7000-8000-0000000000ac").unwrap(),
        x: 1.5,
        y: 2.0,
        height_m: Some(1.1),
        mounting: Some(Mounting::Wall),
    }
}

fn estimate(confidence: f32) -> LocationEstimate {
    LocationEstimate {
        device_id: device_id(),
        floor_id: Some(FloorId::parse("018f0000-0000-7000-8000-0000000000ac").unwrap()),
        room_id: Some(RoomId::parse("018f0000-0000-7000-8000-0000000000af").unwrap()),
        confidence,
        evidence: vec!["w6-rssi".to_owned(), "collector-arp".to_owned()],
        estimated_at: at(1_700_000_010),
    }
}

#[tokio::test]
async fn plan_save_waits_for_a_competing_writer_without_losing_geometry() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let pool = connect_path(directory.path().join("home-contention.db")).await?;
    let repository = HomeRepository::new(pool.clone());
    let writer = pool.begin_with("BEGIN IMMEDIATE").await?;
    let pending = repository.clone();
    let mut saving = tokio::spawn(async move {
        pending
            .save_plan(0, &plan("Owner home"), at(1_700_000_000))
            .await
    });
    let early = tokio::time::timeout(std::time::Duration::from_millis(150), &mut saving).await;
    writer.commit().await?;
    assert!(
        early.is_err(),
        "Saving must wait for the writer instead of failing a lock upgrade: {early:?}"
    );
    assert_eq!(saving.await??, 1);
    let stored = repository.load_plan().await?.unwrap().plan;
    assert_eq!(stored.floors, plan("Owner home").floors);
    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn plan_save_and_load_round_trips_after_reopen() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let path = directory.path().join("home.db");
    let pool = connect_path(&path).await?;
    let repository = HomeRepository::new(pool.clone());

    assert_eq!(repository.load_plan().await?, None);
    let version = repository
        .save_plan(0, &plan("Home"), at(1_700_000_000))
        .await?;
    assert_eq!(version, 1);
    repository
        .put_draft(home_id(), "{\"draft\":true}", at(1_700_000_001))
        .await?;
    repository.upsert_placement(&placement()).await?;
    pool.close().await;

    let pool = connect_path(&path).await?;
    let repository = HomeRepository::new(pool.clone());
    let loaded = repository.load_plan().await?.unwrap();
    assert!(!loaded.recovered_from_history);
    assert_eq!(loaded.plan.version, 1);
    assert_eq!(loaded.plan.name, "Home");
    assert_eq!(loaded.plan.floors, plan("Home").floors);
    assert_eq!(
        repository.get_draft(home_id()).await?,
        Some("{\"draft\":true}".to_owned())
    );
    assert_eq!(repository.list_placements().await?, vec![placement()]);
    pool.close().await;
    Ok(())
}

#[tokio::test]
async fn stale_expected_version_is_rejected_with_typed_conflict() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = HomeRepository::new(pool);

    assert_eq!(
        repository
            .save_plan(0, &plan("v1"), at(1_700_000_000))
            .await?,
        1
    );
    let error = repository
        .save_plan(0, &plan("stale"), at(1_700_000_001))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        HomeStoreError::VersionConflict {
            expected: 0,
            actual: 1
        }
    );
    // The rejected write must not have changed anything.
    let loaded = repository.load_plan().await?.unwrap();
    assert_eq!(loaded.plan.name, "v1");
    assert_eq!(loaded.plan.version, 1);
    // Reloading and retrying with the current version succeeds.
    assert_eq!(
        repository
            .save_plan(1, &plan("v2"), at(1_700_000_002))
            .await?,
        2
    );
    Ok(())
}

#[tokio::test]
async fn corrupt_current_plan_recovers_from_newest_history_row() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = HomeRepository::new(pool.clone());

    repository
        .save_plan(0, &plan("v1"), at(1_700_000_000))
        .await?;
    repository
        .save_plan(1, &plan("v2"), at(1_700_000_001))
        .await?;
    repository
        .save_plan(2, &plan("v3"), at(1_700_000_002))
        .await?;

    // Corrupt the current row with JSON that is valid JSON (passes the SQL
    // CHECK) but is not a parsable plan.
    sqlx::query("UPDATE home_plans SET plan = '{\"not\":\"a plan\"}' WHERE singleton = 1")
        .execute(&pool)
        .await?;

    let loaded = repository.load_plan().await?.unwrap();
    assert!(loaded.recovered_from_history);
    assert_eq!(loaded.plan.name, "v3");
    // The version column stays authoritative so optimistic concurrency still
    // lines up after recovery.
    assert_eq!(loaded.plan.version, 3);
    assert_eq!(
        repository
            .save_plan(3, &plan("v4"), at(1_700_000_003))
            .await?,
        4
    );
    let loaded = repository.load_plan().await?.unwrap();
    assert!(!loaded.recovered_from_history);
    assert_eq!(loaded.plan.name, "v4");
    Ok(())
}

#[tokio::test]
async fn history_is_pruned_to_the_newest_hundred_rows() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = HomeRepository::new(pool.clone());

    let total = PLAN_HISTORY_KEEP + 5;
    for version in 0..total {
        repository
            .save_plan(
                version,
                &plan(&format!("v{}", version + 1)),
                at(1_700_000_000),
            )
            .await?;
    }
    let (count, oldest, newest): (i64, i64, i64) =
        sqlx::query_as("SELECT COUNT(*), MIN(version), MAX(version) FROM home_plan_history")
            .fetch_one(&pool)
            .await?;
    assert_eq!(count, i64::from(PLAN_HISTORY_KEEP));
    assert_eq!(oldest, 6);
    assert_eq!(newest, i64::from(total));
    Ok(())
}

#[tokio::test]
async fn oversized_draft_is_rejected_and_boundary_draft_accepted() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = HomeRepository::new(pool);

    let oversized = "x".repeat(MAX_DRAFT_BYTES + 1);
    assert_eq!(
        repository
            .put_draft(home_id(), &oversized, at(1_700_000_000))
            .await
            .unwrap_err(),
        HomeStoreError::DraftTooLarge
    );
    assert_eq!(repository.get_draft(home_id()).await?, None);

    let boundary = format!("\"{}\"", "x".repeat(MAX_DRAFT_BYTES - 2));
    assert_eq!(boundary.len(), MAX_DRAFT_BYTES);
    repository
        .put_draft(home_id(), &boundary, at(1_700_000_001))
        .await?;
    assert_eq!(repository.get_draft(home_id()).await?, Some(boundary));
    assert!(repository.delete_draft(home_id()).await?);
    assert!(!repository.delete_draft(home_id()).await?);
    assert_eq!(repository.get_draft(home_id()).await?, None);
    Ok(())
}

#[tokio::test]
async fn corrupt_draft_is_reported_and_discarded_never_returned() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = HomeRepository::new(pool.clone());

    sqlx::query("INSERT INTO home_drafts(home_id, draft, updated_at) VALUES(?, ?, ?)")
        .bind(home_id().to_string())
        .bind("not json {{{")
        .bind("2026-08-24T00:00:00.000000000Z")
        .execute(&pool)
        .await?;

    assert_eq!(
        repository.get_draft(home_id()).await.unwrap_err(),
        HomeStoreError::DraftCorrupt
    );
    // The corrupt draft was deleted; the committed plan path is unaffected.
    assert_eq!(repository.get_draft(home_id()).await?, None);
    Ok(())
}

#[tokio::test]
async fn estimate_upsert_never_touches_owner_placement() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = HomeRepository::new(pool);

    // Placements are validated against the saved plan.
    repository
        .save_plan(0, &plan("Home"), at(1_700_000_000))
        .await?;
    let owner = placement();
    repository.upsert_placement(&owner).await?;
    repository.upsert_estimate(&estimate(0.95)).await?;
    repository.upsert_estimate(&estimate(0.2)).await?;

    // Placement is byte-for-byte intact after estimate upserts (H4).
    assert_eq!(repository.list_placements().await?, vec![owner.clone()]);
    let estimates = repository.list_estimates().await?;
    assert_eq!(estimates, vec![estimate(0.2)]);

    // Owner placement wins regardless of the estimate.
    assert_eq!(
        effective_location(Some(&owner), estimates.first()),
        EffectiveLocation::Owner(owner.clone())
    );

    // Deleting the placement leaves the estimate in place; a low-confidence
    // estimate alone is uncertain.
    assert!(repository.delete_placement(owner.device_id).await?);
    assert!(!repository.delete_placement(owner.device_id).await?);
    assert_eq!(repository.list_placements().await?, Vec::new());
    let estimates = repository.list_estimates().await?;
    assert_eq!(estimates.len(), 1);
    assert_eq!(
        effective_location(None, estimates.first()),
        EffectiveLocation::Uncertain
    );
    Ok(())
}

#[tokio::test]
async fn placement_and_estimate_reject_invalid_values() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = HomeRepository::new(pool);

    let mut bad = placement();
    bad.x = 1000.5;
    assert_eq!(
        repository.upsert_placement(&bad).await.unwrap_err(),
        HomeStoreError::Invalid
    );
    let mut bad = placement();
    bad.height_m = Some(f64::NAN);
    assert_eq!(
        repository.upsert_placement(&bad).await.unwrap_err(),
        HomeStoreError::Invalid
    );

    let mut bad = estimate(1.5);
    assert_eq!(
        repository.upsert_estimate(&bad).await.unwrap_err(),
        HomeStoreError::Invalid
    );
    bad = estimate(0.5);
    bad.evidence = vec![String::new()];
    assert_eq!(
        repository.upsert_estimate(&bad).await.unwrap_err(),
        HomeStoreError::Invalid
    );

    assert_eq!(repository.list_placements().await?, Vec::new());
    assert_eq!(repository.list_estimates().await?, Vec::new());
    Ok(())
}

#[tokio::test]
async fn invalid_plan_is_rejected_before_any_write() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = HomeRepository::new(pool.clone());

    let mut bad = plan("bad");
    bad.floors[0].ceiling_height_m = 0.5;
    assert!(matches!(
        repository.save_plan(0, &bad, at(1_700_000_000)).await,
        Err(HomeStoreError::InvalidPlan(_))
    ));
    assert_eq!(repository.load_plan().await?, None);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM home_plan_history")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 0);
    Ok(())
}

fn other_floor_id() -> FloorId {
    FloorId::parse("018f0000-0000-7000-8000-0000000000c1").unwrap()
}

#[tokio::test]
async fn saving_a_plan_with_a_different_home_id_is_refused_and_leaves_history_intact()
-> anyhow::Result<()> {
    let repository = HomeRepository::new(connect_memory().await?);
    repository
        .save_plan(0, &plan("Home"), at(1_700_000_000))
        .await?;
    let mut stranger = plan("Home");
    stranger.home_id = HomeId::parse("018f0000-0000-7000-8000-0000000000bb").unwrap();
    assert_eq!(
        repository
            .save_plan(1, &stranger, at(1_700_000_001))
            .await
            .unwrap_err(),
        HomeStoreError::HomeIdChanged
    );
    let loaded = repository.load_plan().await?.unwrap();
    assert_eq!(loaded.plan.home_id, home_id());
    assert_eq!(loaded.plan.version, 1);
    Ok(())
}

#[tokio::test]
async fn the_first_save_discards_the_unreachable_placeholder_draft() -> anyhow::Result<()> {
    let repository = HomeRepository::new(connect_memory().await?);
    let unset = HomeId::parse("00000000-0000-0000-0000-000000000000").unwrap();
    repository
        .put_draft(unset, "{\"draft\":true}", at(1_700_000_000))
        .await?;
    repository
        .save_plan(0, &plan("Home"), at(1_700_000_001))
        .await?;
    assert_eq!(repository.get_draft(unset).await?, None);
    Ok(())
}

#[tokio::test]
async fn placements_need_a_saved_plan_with_that_floor_and_are_capped() -> anyhow::Result<()> {
    let repository = HomeRepository::new(connect_memory().await?);
    // No plan at all.
    assert_eq!(
        repository.upsert_placement(&placement()).await.unwrap_err(),
        HomeStoreError::Invalid
    );
    repository
        .save_plan(0, &plan("Home"), at(1_700_000_000))
        .await?;
    // A floor the plan does not have.
    let mut dangling = placement();
    dangling.floor_id = other_floor_id();
    assert_eq!(
        repository.upsert_placement(&dangling).await.unwrap_err(),
        HomeStoreError::Invalid
    );
    assert!(repository.list_placements().await?.is_empty());
    repository.upsert_placement(&placement()).await?;
    assert_eq!(repository.list_placements().await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn placement_count_is_capped() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = HomeRepository::new(pool.clone());
    repository
        .save_plan(0, &plan("Home"), at(1_700_000_000))
        .await?;
    // Fill to the cap directly, then prove the next new device is refused
    // while an existing device may still be moved.
    for index in 0..lattice_store::MAX_PLACEMENTS {
        sqlx::query(
            "INSERT INTO owner_placements(device_id, placement_id, floor_id, x, y) VALUES(?, ?, ?, 0, 0)",
        )
        .bind(format!("018f0000-0000-7000-8000-{index:012x}"))
        .bind(format!("018f0001-0000-7000-8000-{index:012x}"))
        .bind("018f0000-0000-7000-8000-0000000000ac")
        .execute(&pool)
        .await?;
    }
    let mut extra = placement();
    extra.device_id = DeviceId::parse("018f0002-0000-7000-8000-000000000001").unwrap();
    assert_eq!(
        repository.upsert_placement(&extra).await.unwrap_err(),
        HomeStoreError::Invalid
    );
    let mut existing = placement();
    existing.device_id = DeviceId::parse("018f0000-0000-7000-8000-000000000001").unwrap();
    repository.upsert_placement(&existing).await?;
    Ok(())
}

#[tokio::test]
async fn saving_a_plan_without_a_floor_returns_its_placed_devices_to_the_tray() -> anyhow::Result<()>
{
    let repository = HomeRepository::new(connect_memory().await?);
    repository
        .save_plan(0, &plan("Home"), at(1_700_000_000))
        .await?;
    repository.upsert_placement(&placement()).await?;
    let mut emptied = plan("Home");
    emptied.floors.clear();
    repository.save_plan(1, &emptied, at(1_700_000_001)).await?;
    assert!(repository.list_placements().await?.is_empty());
    Ok(())
}
