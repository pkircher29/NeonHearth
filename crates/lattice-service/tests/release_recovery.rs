use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{
    DeviceId, Evaluation, OwnerDecision, PolicyChanged, PolicyReason, RequestedAction,
};
use lattice_service::policy::{
    ActuationReconciliation, EnforcementResult, PolicyActuator, PolicyCoordinator,
};
use lattice_store::{InstallRepository, M2StateRepository, PolicyRepository, connect_memory};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn at(hour: i64) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 23, 0, 0, 0).unwrap() + Duration::hours(hour)
}

async fn enrolled(repo: &PolicyRepository, pool: &sqlx::SqlitePool) -> anyhow::Result<DeviceId> {
    let device = DeviceId::new();
    sqlx::query(
        "INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_confirmed) VALUES(?,?,?,0)",
    )
    .bind(device.to_string())
    .bind(at(60).to_rfc3339())
    .bind(at(60).to_rfc3339())
    .execute(pool)
    .await?;
    repo.enroll(device).await?;
    Ok(device)
}

#[derive(Clone)]
struct ReleaseActuator {
    undos: Arc<AtomicUsize>,
    enforces: Arc<AtomicUsize>,
    undo_result: EnforcementResult,
    reconciliation: ActuationReconciliation,
}

#[async_trait]
impl PolicyActuator for ReleaseActuator {
    async fn enforce(&self, _: DeviceId, _: RequestedAction) -> EnforcementResult {
        self.enforces.fetch_add(1, Ordering::SeqCst);
        EnforcementResult::Verified
    }
    async fn undo(&self, _: DeviceId, _: RequestedAction) -> EnforcementResult {
        self.undos.fetch_add(1, Ordering::SeqCst);
        self.undo_result
    }
    async fn undo_available(&self, _: DeviceId, _: RequestedAction) -> bool {
        true
    }
    async fn reconcile(&self, _: DeviceId, _: RequestedAction) -> ActuationReconciliation {
        self.reconciliation
    }
}

async fn setup() -> anyhow::Result<(sqlx::SqlitePool, PolicyRepository, DeviceId)> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    let device = enrolled(&repo, &pool).await?;
    Ok((pool, repo, device))
}

#[tokio::test]
async fn release_retry_preserves_manual_required_and_blocked_control_until_due_after_restart()
-> anyhow::Result<()> {
    let (pool, repo, device) = setup().await?;
    let state = M2StateRepository::new(pool.clone());
    let undos = Arc::new(AtomicUsize::new(0));
    let coordinator = PolicyCoordinator::with_actuator_and_state(
        repo.clone(),
        None,
        ReleaseActuator {
            undos: undos.clone(),
            enforces: Arc::new(AtomicUsize::new(0)),
            undo_result: EnforcementResult::ManualRequired,
            reconciliation: ActuationReconciliation::VerifiedApplied,
        },
        state.clone(),
    );
    coordinator.enroll_and_evaluate(device, at(108)).await?;
    let first = coordinator.approve(device, at(108)).await?;
    assert_eq!(first.enforcement, EnforcementResult::ManualRequired);
    assert!(first.undo_available);
    assert!(coordinator.control_blocks(device).await?);
    assert_eq!(undos.load(Ordering::SeqCst), 1);
    let restarted = PolicyCoordinator::with_actuator_and_state(
        repo.clone(),
        None,
        ReleaseActuator {
            undos: undos.clone(),
            enforces: Arc::new(AtomicUsize::new(0)),
            undo_result: EnforcementResult::ManualRequired,
            reconciliation: ActuationReconciliation::VerifiedApplied,
        },
        state.clone(),
    );
    let before_due = restarted.sweep(at(108)).await?.pop().unwrap();
    assert_eq!(before_due.enforcement, EnforcementResult::ManualRequired);
    assert!(before_due.undo_available);
    assert_eq!(undos.load(Ordering::SeqCst), 1);
    let retry = restarted.sweep(at(109)).await?.pop().unwrap();
    assert_eq!(retry.enforcement, EnforcementResult::ManualRequired);
    assert!(retry.undo_available);
    assert!(restarted.control_blocks(device).await?);
    assert_eq!(undos.load(Ordering::SeqCst), 2);
    assert_eq!(
        repo.release_retry_action(device).await?,
        Some(RequestedAction::Quarantine)
    );
    Ok(())
}

#[tokio::test]
async fn newer_same_action_quarantine_cancels_release_retry_without_duplicate_router_mutation()
-> anyhow::Result<()> {
    let (pool, repo, device) = setup().await?;
    let state = M2StateRepository::new(pool.clone());
    state.record_verified_block(device, at(60)).await?;
    repo.set_owner_decision(device, OwnerDecision::Approved)
        .await?;
    repo.schedule_release_retry(device, RequestedAction::Quarantine, at(60))
        .await?;
    let undos = Arc::new(AtomicUsize::new(0));
    let enforces = Arc::new(AtomicUsize::new(0));
    let coordinator = PolicyCoordinator::with_actuator_and_state(
        repo.clone(),
        None,
        ReleaseActuator {
            undos: undos.clone(),
            enforces: enforces.clone(),
            undo_result: EnforcementResult::Verified,
            reconciliation: ActuationReconciliation::VerifiedApplied,
        },
        state,
    );
    let decision = coordinator.quarantine(device, at(61)).await?;
    assert_eq!(decision.enforcement, EnforcementResult::Verified);
    assert_eq!(undos.load(Ordering::SeqCst), 0);
    assert_eq!(enforces.load(Ordering::SeqCst), 0);
    assert_eq!(repo.release_retry_action(device).await?, None);
    Ok(())
}

#[tokio::test]
async fn newer_rejection_cancels_stale_release_before_it_can_undo() -> anyhow::Result<()> {
    let (_pool, repo, device) = setup().await?;
    repo.set_owner_decision(device, OwnerDecision::Approved)
        .await?;
    repo.schedule_release_retry(device, RequestedAction::Quarantine, at(60))
        .await?;
    let undos = Arc::new(AtomicUsize::new(0));
    let enforces = Arc::new(AtomicUsize::new(0));
    let coordinator = PolicyCoordinator::with_actuator(
        repo.clone(),
        None,
        ReleaseActuator {
            undos: undos.clone(),
            enforces: enforces.clone(),
            undo_result: EnforcementResult::Verified,
            reconciliation: ActuationReconciliation::VerifiedApplied,
        },
    );
    coordinator.reject(device, at(61)).await?;
    coordinator.sweep(at(62)).await?;
    assert_eq!(undos.load(Ordering::SeqCst), 0);
    assert_eq!(enforces.load(Ordering::SeqCst), 1);
    assert_eq!(repo.release_retry_action(device).await?, None);
    Ok(())
}

#[tokio::test]
async fn already_durable_unblock_clears_retry_without_second_undo() -> anyhow::Result<()> {
    let (pool, repo, device) = setup().await?;
    let state = M2StateRepository::new(pool.clone());
    state.record_verified_block(device, at(60)).await?;
    state.record_verified_unblock(device, at(60)).await?;
    repo.schedule_release_retry(device, RequestedAction::Quarantine, at(59))
        .await?;
    let undos = Arc::new(AtomicUsize::new(0));
    let coordinator = PolicyCoordinator::with_actuator_and_state(
        repo.clone(),
        None,
        ReleaseActuator {
            undos: undos.clone(),
            enforces: Arc::new(AtomicUsize::new(0)),
            undo_result: EnforcementResult::Verified,
            reconciliation: ActuationReconciliation::VerifiedApplied,
        },
        state.clone(),
    );
    let decision = coordinator.sweep(at(60)).await?.pop().unwrap();
    assert_eq!(decision.enforcement, EnforcementResult::Verified);
    assert_eq!(undos.load(Ordering::SeqCst), 0);
    assert_eq!(repo.release_retry_action(device).await?, None);
    assert!(!coordinator.control_blocks(device).await?);
    Ok(())
}

#[tokio::test]
async fn failed_durable_unblock_write_keeps_release_retry_and_blocked_control() -> anyhow::Result<()>
{
    let (pool, repo, device) = setup().await?;
    let state = M2StateRepository::new(pool.clone());
    let undos = Arc::new(AtomicUsize::new(0));
    let coordinator = PolicyCoordinator::with_actuator_and_state(
        repo.clone(),
        None,
        ReleaseActuator {
            undos: undos.clone(),
            enforces: Arc::new(AtomicUsize::new(0)),
            undo_result: EnforcementResult::Verified,
            reconciliation: ActuationReconciliation::VerifiedApplied,
        },
        state.clone(),
    );
    coordinator.enroll_and_evaluate(device, at(108)).await?;
    sqlx::query("CREATE TRIGGER fail_unblock BEFORE INSERT ON presence_transitions WHEN NEW.trigger_kind='enforcement_unblocked' BEGIN SELECT RAISE(ABORT, 'injected unblock write failure'); END")
        .execute(&pool).await?;
    assert!(coordinator.approve(device, at(108)).await.is_err());
    assert_eq!(undos.load(Ordering::SeqCst), 1);
    assert_eq!(
        repo.release_retry_action(device).await?,
        Some(RequestedAction::Quarantine)
    );
    assert!(coordinator.control_blocks(device).await?);
    Ok(())
}

#[tokio::test]
async fn failed_release_persists_failed_outcome_and_undo_availability_until_due()
-> anyhow::Result<()> {
    let (pool, repo, device) = setup().await?;
    let state = M2StateRepository::new(pool);
    let undos = Arc::new(AtomicUsize::new(0));
    let coordinator = PolicyCoordinator::with_actuator_and_state(
        repo.clone(),
        None,
        ReleaseActuator {
            undos: undos.clone(),
            enforces: Arc::new(AtomicUsize::new(0)),
            undo_result: EnforcementResult::Failed,
            reconciliation: ActuationReconciliation::VerifiedApplied,
        },
        state,
    );
    coordinator.enroll_and_evaluate(device, at(108)).await?;
    let failed = coordinator.approve(device, at(108)).await?;
    assert_eq!(failed.enforcement, EnforcementResult::Failed);
    assert!(failed.undo_available);
    let restarted = PolicyCoordinator::with_actuator(
        repo.clone(),
        None,
        ReleaseActuator {
            undos: undos.clone(),
            enforces: Arc::new(AtomicUsize::new(0)),
            undo_result: EnforcementResult::Failed,
            reconciliation: ActuationReconciliation::VerifiedApplied,
        },
    );
    let before_due = restarted.sweep(at(108)).await?.pop().unwrap();
    assert_eq!(before_due.enforcement, EnforcementResult::Failed);
    assert!(before_due.undo_available);
    assert_eq!(undos.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn stale_published_cleanup_does_not_clear_a_different_journal_decision() -> anyhow::Result<()>
{
    let (_pool, repo, device) = setup().await?;
    repo.set_owner_decision(device, OwnerDecision::Rejected)
        .await?;
    let published = PolicyChanged {
        device_id: device,
        policy_version: 1,
        evaluation: Evaluation::ban(PolicyReason::OwnerRejected),
        requested_action: RequestedAction::PermanentBan,
        evidence_summary: "published".into(),
        enforcement_result: EnforcementResult::Verified,
        undo_available: true,
    };
    repo.mark_decision_published(device, "published", &published)
        .await?;
    let mut journal = published.clone();
    journal.evidence_summary = "different journal causality".into();
    repo.reserve_actuation_with_decision(
        device,
        1,
        RequestedAction::PermanentBan,
        at(60),
        Some(&journal),
    )
    .await?;
    let coordinator = PolicyCoordinator::with_actuator(
        repo.clone(),
        None,
        ReleaseActuator {
            undos: Arc::new(AtomicUsize::new(0)),
            enforces: Arc::new(AtomicUsize::new(0)),
            undo_result: EnforcementResult::Verified,
            reconciliation: ActuationReconciliation::VerifiedApplied,
        },
    );
    coordinator
        .evaluate(repo.load(device).await?.unwrap(), at(61))
        .await?;
    assert_eq!(
        repo.actuation_attempt(device).await?.unwrap().decision,
        Some(journal)
    );
    Ok(())
}

#[tokio::test]
async fn same_second_verified_unblock_is_newer_than_block() -> anyhow::Result<()> {
    let (pool, _repo, device) = setup().await?;
    let state = M2StateRepository::new(pool);
    state.record_verified_block(device, at(60)).await?;
    state.record_verified_unblock(device, at(60)).await?;
    assert!(!state.verified_control_blocked(device).await?);
    Ok(())
}
