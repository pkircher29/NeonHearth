use chrono::{DateTime, Duration, TimeZone, Utc};
use lattice_domain::{
    DeviceId, EvidenceFamily, Identification, OwnerDecision, Protection, RiskSignal,
};
use lattice_store::{InstallRepository, PolicyRepository, connect_memory};

fn at(hours: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 23, 0, 0, 0).unwrap() + Duration::hours(hours)
}

async fn insert_device(
    pool: &sqlx::SqlitePool,
    id: DeviceId,
    first_seen: DateTime<Utc>,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at) VALUES (?, ?, ?)")
        .bind(id.to_string())
        .bind(first_seen.to_rfc3339())
        .bind(first_seen.to_rfc3339())
        .execute(pool)
        .await?;
    Ok(())
}

#[tokio::test]
async fn enrollment_uses_the_immutable_install_baseline_once() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let install = InstallRepository::new(pool.clone());
    install.initialize(at(0)).await?;
    let repo = PolicyRepository::new(pool.clone());
    assert_eq!(repo.mark_successful_service_start(at(0)).await?, at(0));
    assert_eq!(repo.mark_successful_service_start(at(500)).await?, at(0));

    let inside = DeviceId::new();
    insert_device(&pool, inside, at(47) + Duration::minutes(59)).await?;
    assert!(repo.enroll(inside).await?.baseline_exempt);

    let boundary = DeviceId::new();
    insert_device(&pool, boundary, at(48)).await?;
    assert!(!repo.enroll(boundary).await?.baseline_exempt);

    // Reinitialization and later enrollment cannot create a new cohort.
    assert_eq!(install.initialize(at(500)).await?.first_run_at, at(0));
    let late = DeviceId::new();
    insert_device(&pool, late, at(501)).await?;
    assert!(!repo.enroll(late).await?.baseline_exempt);
    assert_eq!(
        repo.enroll(inside).await?,
        repo.load(inside).await?.unwrap()
    );
    Ok(())
}

#[tokio::test]
async fn lifecycle_facts_round_trip_and_extension_is_single_use() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    let id = DeviceId::new();
    insert_device(&pool, id, at(60)).await?;
    repo.enroll(id).await?;

    repo.set_identification(
        id,
        Identification::Automatic {
            confidence_basis_points: 9_100,
            evidence_families: vec![
                EvidenceFamily::LinkLayer,
                EvidenceFamily::Naming,
                EvidenceFamily::Service,
            ],
        },
    )
    .await?;
    repo.set_owner_decision(id, OwnerDecision::Pending).await?;
    repo.set_risk(
        id,
        RiskSignal::HighConfidenceDanger {
            confidence_basis_points: 9_500,
            evidence: "confirmed-active-exploitation".into(),
        },
    )
    .await?;
    repo.set_protection(id, Protection::AdministratorPhone)
        .await?;

    assert!(repo.extend_once(id, at(100)).await.is_err());
    assert!(repo.extend_once(id, at(240)).await?);
    assert!(!repo.extend_once(id, at(300)).await?);

    let loaded = repo.load(id).await?.unwrap();
    assert_eq!(
        loaded.identification,
        Identification::Automatic {
            confidence_basis_points: 9_100,
            evidence_families: vec![
                EvidenceFamily::LinkLayer,
                EvidenceFamily::Naming,
                EvidenceFamily::Service,
            ]
        }
    );
    assert_eq!(loaded.owner_decision, OwnerDecision::Pending);
    assert_eq!(
        loaded.risk,
        RiskSignal::HighConfidenceDanger {
            confidence_basis_points: 9_500,
            evidence: "confirmed-active-exploitation".into()
        }
    );
    assert_eq!(loaded.protection, Protection::AdministratorPhone);
    assert_eq!(loaded.extension_until, Some(at(240)));
    Ok(())
}

#[tokio::test]
async fn missing_install_or_device_fails_without_creating_orphan_policy() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repo = PolicyRepository::new(pool.clone());
    let missing = DeviceId::new();
    assert!(repo.enroll(missing).await.is_err());

    let id = DeviceId::new();
    insert_device(&pool, id, at(1)).await?;
    assert!(repo.enroll(id).await.is_err());
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    assert!(repo.enroll(id).await.is_err());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_policy")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 0);
    Ok(())
}
