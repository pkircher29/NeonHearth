use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, Evaluation, PolicyChanged, PolicyReason, RequestedAction};
use lattice_service::policy::{
    ActuationReconciliation, EnforcementResult, PolicyActuator, PolicyCoordinator,
};
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

#[derive(Clone)]
struct ProvenAbsentCounter(Arc<AtomicUsize>);
#[async_trait]
impl PolicyActuator for ProvenAbsentCounter {
    async fn enforce(&self, _: DeviceId, _: RequestedAction) -> EnforcementResult {
        self.0.fetch_add(1, Ordering::SeqCst);
        EnforcementResult::Verified
    }
    async fn reconcile(&self, _: DeviceId, _: RequestedAction) -> ActuationReconciliation {
        ActuationReconciliation::ProvenNotApplied
    }
}

#[derive(Clone)]
struct VerifiedCounter(Arc<AtomicUsize>);
#[async_trait]
impl PolicyActuator for VerifiedCounter {
    async fn enforce(&self, _: DeviceId, _: RequestedAction) -> EnforcementResult {
        self.0.fetch_add(1, Ordering::SeqCst);
        EnforcementResult::Verified
    }
    async fn reconcile(&self, _: DeviceId, _: RequestedAction) -> ActuationReconciliation {
        ActuationReconciliation::VerifiedApplied
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

#[tokio::test]
async fn stale_different_attempt_proven_absent_is_retired_before_current_action_is_reserved()
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
    repo.set_owner_decision(d, lattice_domain::OwnerDecision::Quarantined)
        .await?;
    repo.reserve_actuation(d, 1, RequestedAction::PermanentBan, at(60))
        .await?;
    let count = Arc::new(AtomicUsize::new(0));
    let coordinator =
        PolicyCoordinator::with_actuator(repo.clone(), None, ProvenAbsentCounter(count.clone()));
    let result = coordinator
        .evaluate(repo.load(d).await?.unwrap(), at(60))
        .await?;
    assert_eq!(result.requested_action, RequestedAction::Quarantine);
    assert_eq!(result.enforcement, EnforcementResult::Verified);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(repo.actuation_attempt(d).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn verified_stale_attempt_publishes_its_exact_decision_then_allows_later_action()
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
    let old_evaluation = Evaluation::quarantine(PolicyReason::OwnerQuarantined);
    let old = PolicyChanged {
        device_id: d,
        policy_version: 1,
        evaluation: old_evaluation,
        requested_action: RequestedAction::Quarantine,
        evidence_summary: "old evidence".into(),
        enforcement_result: EnforcementResult::Verified,
        undo_available: false,
    };
    repo.reserve_actuation_with_decision(d, 1, RequestedAction::Quarantine, at(60), Some(&old))
        .await?;
    repo.set_owner_decision(d, lattice_domain::OwnerDecision::Rejected)
        .await?;
    let count = Arc::new(AtomicUsize::new(0));
    let coordinator =
        PolicyCoordinator::with_actuator(repo.clone(), None, VerifiedCounter(count.clone()));
    let result = coordinator
        .evaluate(repo.load(d).await?.unwrap(), at(61))
        .await?;
    assert_eq!(result.requested_action, RequestedAction::PermanentBan);
    assert_eq!(result.enforcement, EnforcementResult::Verified);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(repo.actuation_attempt(d).await?.is_none());
    assert_eq!(
        repo.published_decision(d).await?.unwrap().requested_action,
        RequestedAction::PermanentBan
    );
    Ok(())
}

#[tokio::test]
async fn verified_permanent_ban_is_not_overclaimed_as_a_quarantine_downgrade() -> anyhow::Result<()>
{
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
    let old = PolicyChanged {
        device_id: d,
        policy_version: 1,
        evaluation: Evaluation::ban(PolicyReason::OwnerRejected),
        requested_action: RequestedAction::PermanentBan,
        evidence_summary: "old evidence".into(),
        enforcement_result: EnforcementResult::Verified,
        undo_available: true,
    };
    repo.reserve_actuation_with_decision(d, 1, RequestedAction::PermanentBan, at(60), Some(&old))
        .await?;
    repo.set_owner_decision(d, lattice_domain::OwnerDecision::Quarantined)
        .await?;
    let count = Arc::new(AtomicUsize::new(0));
    let coordinator =
        PolicyCoordinator::with_actuator(repo.clone(), None, VerifiedCounter(count.clone()));
    let result = coordinator
        .evaluate(repo.load(d).await?.unwrap(), at(61))
        .await?;
    assert_eq!(result.requested_action, RequestedAction::Quarantine);
    assert_eq!(result.enforcement, EnforcementResult::ManualRequired);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert_eq!(
        repo.release_retry_action(d).await?,
        Some(RequestedAction::PermanentBan)
    );
    Ok(())
}
