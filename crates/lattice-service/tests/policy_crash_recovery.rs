use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{
    DeviceId, Evaluation, EventPayload, PolicyChanged, PolicyReason, PresenceState, RequestedAction,
};
use lattice_event_bus::EventBus;
use lattice_service::policy::{
    ActuationReconciliation, EnforcementResult, PolicyActuator, PolicyCoordinator, W6PolicyActuator,
};
use lattice_store::{InstallRepository, M2StateRepository, PolicyRepository, connect_memory};
use lattice_w6::{Capability, Connector, DeviceState, Profile, Transport};
use secrecy::SecretString;
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

#[derive(Clone)]
struct W6Fixture {
    state: Arc<std::sync::Mutex<DeviceState>>,
    applies: Arc<AtomicUsize>,
    restores: Arc<AtomicUsize>,
}
#[async_trait]
impl Transport for W6Fixture {
    async fn login(&mut self, _: &str, _: &SecretString) -> Result<(), lattice_w6::Error> {
        Ok(())
    }
    async fn renew(&mut self) -> Result<(), lattice_w6::Error> {
        Ok(())
    }
    async fn profile(&mut self) -> Result<Profile, lattice_w6::Error> {
        Ok(Profile {
            fingerprint: "fw-1".into(),
            capabilities: vec![
                Capability::DisconnectNow,
                Capability::DenyWifiAssociation,
                Capability::DenyInternet,
                Capability::DenyLan,
                Capability::PersistentFilter,
            ],
            filter_capacity: Some(32),
        })
    }
    async fn state(&mut self) -> Result<DeviceState, lattice_w6::Error> {
        Ok(self.state.lock().unwrap().clone())
    }
    async fn apply(&mut self, capability: Capability) -> Result<(), lattice_w6::Error> {
        self.applies.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap();
        match capability {
            Capability::DenyInternet => state.deny_internet = true,
            Capability::PersistentFilter => {
                state.persistent_filter = true;
                state.filter_entries += 1;
            }
            _ => unreachable!("only policy capabilities are exposed"),
        }
        Ok(())
    }
    async fn restore(&mut self, previous: DeviceState) -> Result<(), lattice_w6::Error> {
        self.restores.fetch_add(1, Ordering::SeqCst);
        *self.state.lock().unwrap() = previous;
        Ok(())
    }
}

async fn w6_connector(fixture: W6Fixture) -> Connector<W6Fixture> {
    let mut connector = Connector::new(fixture);
    connector
        .login("owner", SecretString::new("fixture-secret".into()))
        .await
        .unwrap();
    connector
}

async fn w6_crash_window(action: RequestedAction, publish_before_ack: bool) -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    let presence = M2StateRepository::new(pool.clone());
    let device = DeviceId::new();
    sqlx::query(
        "INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_confirmed) VALUES(?,?,?,0)",
    )
    .bind(device.to_string())
    .bind(at(60).to_rfc3339())
    .bind(at(60).to_rfc3339())
    .execute(&pool)
    .await?;
    repo.enroll(device).await?;
    let (evaluation, reason) = match action {
        RequestedAction::Quarantine => {
            repo.set_owner_decision(device, lattice_domain::OwnerDecision::Quarantined)
                .await?;
            (
                Evaluation::quarantine(PolicyReason::OwnerQuarantined),
                PolicyReason::OwnerQuarantined,
            )
        }
        RequestedAction::PermanentBan => {
            repo.set_owner_decision(device, lattice_domain::OwnerDecision::Rejected)
                .await?;
            (
                Evaluation::ban(PolicyReason::OwnerRejected),
                PolicyReason::OwnerRejected,
            )
        }
        _ => unreachable!(),
    };
    let fixture = W6Fixture {
        state: Arc::new(std::sync::Mutex::new(DeviceState {
            disconnect_now: false,
            deny_wifi_association: false,
            deny_internet: false,
            deny_lan: false,
            persistent_filter: false,
            filter_entries: 0,
        })),
        applies: Arc::new(AtomicUsize::new(0)),
        restores: Arc::new(AtomicUsize::new(0)),
    };
    let event = PolicyChanged {
        device_id: device,
        policy_version: evaluation.policy_version,
        evaluation,
        requested_action: action,
        evidence_summary: "policy facts evaluated".into(),
        enforcement_result: EnforcementResult::Verified,
        undo_available: true,
    };
    repo.reserve_actuation_with_decision(
        device,
        evaluation.policy_version,
        action,
        at(60),
        Some(&event),
    )
    .await?;
    let first = W6PolicyActuator::with_sqlite(w6_connector(fixture.clone()).await, pool.clone());
    assert_eq!(
        first.enforce(device, action).await,
        EnforcementResult::Verified
    );
    assert!(first.undo_available(device, action).await);
    assert_eq!(fixture.applies.load(Ordering::SeqCst), 1);
    let events = EventBus::new(16, 16);
    if publish_before_ack {
        let fingerprint = serde_json::to_string(&event)?;
        assert!(
            repo.prepare_decision_publication(device, &fingerprint)
                .await?
        );
        events
            .publish(at(60), EventPayload::PolicyChanged(event.clone()))
            .await;
    }
    let restarted = PolicyCoordinator::with_actuator_and_state(
        repo.clone(),
        Some(events.clone()),
        W6PolicyActuator::with_sqlite(w6_connector(fixture.clone()).await, pool.clone()),
        presence.clone(),
    );
    let recovered = restarted
        .evaluate(repo.load(device).await?.unwrap(), at(61))
        .await?;
    assert_eq!(recovered.enforcement, EnforcementResult::Verified);
    assert_eq!(fixture.applies.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.state.lock().unwrap().filter_entries,
        if action == RequestedAction::PermanentBan {
            1
        } else {
            0
        }
    );
    assert!(repo.actuation_attempt(device).await?.is_none());
    assert!(!repo.pending_decision(device).await?);
    assert_eq!(repo.published_decision(device).await?, Some(event.clone()));
    assert_eq!(
        presence.list_device_snapshots(1, None).await?[0]
            .presence
            .as_ref()
            .map(|p| p.to_state),
        Some(PresenceState::Blocked)
    );
    let lattice_event_bus::Resume::Events(published) = events.resume_after(0).await else {
        panic!("event bus must retain events")
    };
    assert_eq!(
        published
            .iter()
            .filter(|e| e.payload == EventPayload::PolicyChanged(event.clone()))
            .count(),
        if publish_before_ack { 2 } else { 1 }
    );
    assert_eq!(reason, evaluation.reason);
    Ok(())
}

async fn w6_verified_crash_then_immediate_approve(action: RequestedAction) -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    let presence = M2StateRepository::new(pool.clone());
    let device = DeviceId::new();
    sqlx::query(
        "INSERT INTO devices(device_id,first_seen_at,last_seen_at,owner_confirmed) VALUES(?,?,?,0)",
    )
    .bind(device.to_string())
    .bind(at(60).to_rfc3339())
    .bind(at(60).to_rfc3339())
    .execute(&pool)
    .await?;
    repo.enroll(device).await?;
    let evaluation = match action {
        RequestedAction::Quarantine => {
            repo.set_owner_decision(device, lattice_domain::OwnerDecision::Quarantined)
                .await?;
            Evaluation::quarantine(PolicyReason::OwnerQuarantined)
        }
        RequestedAction::PermanentBan => {
            repo.set_owner_decision(device, lattice_domain::OwnerDecision::Rejected)
                .await?;
            Evaluation::ban(PolicyReason::OwnerRejected)
        }
        _ => unreachable!(),
    };
    let fixture = W6Fixture {
        state: Arc::new(std::sync::Mutex::new(DeviceState {
            disconnect_now: false,
            deny_wifi_association: false,
            deny_internet: false,
            deny_lan: false,
            persistent_filter: false,
            filter_entries: 0,
        })),
        applies: Arc::new(AtomicUsize::new(0)),
        restores: Arc::new(AtomicUsize::new(0)),
    };
    let event = PolicyChanged {
        device_id: device,
        policy_version: evaluation.policy_version,
        evaluation,
        requested_action: action,
        evidence_summary: "policy facts evaluated".into(),
        enforcement_result: EnforcementResult::Verified,
        undo_available: false,
    };
    repo.reserve_actuation_with_decision(
        device,
        evaluation.policy_version,
        action,
        at(60),
        Some(&event),
    )
    .await?;
    let first = W6PolicyActuator::with_sqlite(w6_connector(fixture.clone()).await, pool.clone());
    assert_eq!(
        first.enforce(device, action).await,
        EnforcementResult::Verified
    );
    assert_eq!(repo.published_decision(device).await?, None);

    let events = EventBus::new(16, 16);
    let restarted = PolicyCoordinator::with_actuator_and_state(
        repo.clone(),
        Some(events.clone()),
        W6PolicyActuator::with_sqlite(w6_connector(fixture.clone()).await, pool),
        presence.clone(),
    );
    let approved = restarted.approve(device, at(61)).await?;

    assert_eq!(approved.enforcement, EnforcementResult::Verified);
    assert_eq!(approved.requested_action, RequestedAction::None);
    assert_eq!(fixture.applies.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.restores.load(Ordering::SeqCst), 1);
    assert!(repo.actuation_attempt(device).await?.is_none());
    assert_eq!(repo.release_retry_action(device).await?, None);
    assert!(!restarted.control_blocks(device).await?);
    assert_eq!(
        *fixture.state.lock().unwrap(),
        DeviceState {
            disconnect_now: false,
            deny_wifi_association: false,
            deny_internet: false,
            deny_lan: false,
            persistent_filter: false,
            filter_entries: 0,
        }
    );
    let lattice_event_bus::Resume::Events(published) = events.resume_after(0).await else {
        panic!("event bus must retain events")
    };
    assert!(
        published
            .iter()
            .any(|record| record.payload == EventPayload::PolicyChanged(event.clone()))
    );
    Ok(())
}

#[tokio::test]
async fn immediate_approval_recovers_verified_unacknowledged_w6_mutations() -> anyhow::Result<()> {
    w6_verified_crash_then_immediate_approve(RequestedAction::Quarantine).await?;
    w6_verified_crash_then_immediate_approve(RequestedAction::PermanentBan).await
}

#[tokio::test]
async fn w6_quarantine_crash_windows_reconcile_without_a_second_apply() -> anyhow::Result<()> {
    w6_crash_window(RequestedAction::Quarantine, false).await?;
    w6_crash_window(RequestedAction::Quarantine, true).await
}

#[tokio::test]
async fn w6_permanent_ban_crash_windows_reconcile_without_a_second_apply() -> anyhow::Result<()> {
    w6_crash_window(RequestedAction::PermanentBan, false).await?;
    w6_crash_window(RequestedAction::PermanentBan, true).await
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
