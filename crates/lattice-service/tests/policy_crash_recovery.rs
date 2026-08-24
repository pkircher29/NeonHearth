use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, RequestedAction};
use lattice_service::policy::{EnforcementResult, PolicyActuator, PolicyCoordinator};
use lattice_store::{InstallRepository, PolicyRepository, connect_memory};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn at(hour: i64) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 23, 0, 0, 0).unwrap() + Duration::hours(hour)
}
#[derive(Clone)]
struct Counter(Arc<AtomicUsize>);
#[async_trait]
impl PolicyActuator for Counter {
    async fn enforce(&self, _: DeviceId, _: RequestedAction) -> EnforcementResult {
        self.0.fetch_add(1, Ordering::SeqCst);
        EnforcementResult::Verified
    }
}

#[tokio::test]
async fn reservation_restart_with_default_reconciliation_fails_closed_without_enforce()
-> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    let d = DeviceId::new();
    sqlx::query(
        "INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_confirmed) VALUES(?,?,?,0)",
    )
    .bind(d.to_string())
    .bind(at(60).to_rfc3339())
    .bind(at(60).to_rfc3339())
    .execute(&pool)
    .await?;
    repo.enroll(d).await?;
    repo.set_owner_decision(d, lattice_domain::OwnerDecision::Rejected)
        .await?;
    repo.reserve_actuation(d, 1, RequestedAction::PermanentBan, at(60))
        .await?;
    let count = Arc::new(AtomicUsize::new(0));
    let c = PolicyCoordinator::with_actuator(repo.clone(), None, Counter(count.clone()));
    assert_eq!(
        c.evaluate(repo.load(d).await?.unwrap(), at(60))
            .await?
            .enforcement,
        EnforcementResult::ManualRequired
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert!(repo.actuation_attempt(d).await?.is_some());
    Ok(())
}
