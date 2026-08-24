use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily, RequestedAction};
use lattice_event_bus::EventBus;
use lattice_intelligence::presence::PresenceEvidenceKind;
use lattice_sensor::{
    InterfaceId,
    neighbor::{
        LinkAddress, NeighborError, NeighborReachability, NeighborRow, NeighborSnapshotSource,
        NeighborTrackerConfig,
    },
};
use lattice_service::{
    AppState,
    discovery::{
        DiscoveryObservation, DiscoveryPipelineOutcome, DiscoverySources, NeighborCoordinator,
        NeighborCoordinatorConfig, NeighborInterfaceBinding, PersistentDiscoveryPipeline,
        neighbor_discovery_sources,
    },
    policy::{EnforcementResult, PolicyActuator, PolicyCoordinator},
};
use lattice_store::{InstallRepository, M2StateRepository, PolicyRepository, connect_memory, connect_path};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tempfile::tempdir;

fn at(hour: i64) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 23, 0, 0, 0).unwrap() + Duration::hours(hour)
}

#[derive(Clone, Default)]
struct FakeActuator(Arc<AtomicUsize>);
#[async_trait]
impl PolicyActuator for FakeActuator {
    async fn enforce(&self, _: DeviceId, _: RequestedAction) -> EnforcementResult {
        self.0.fetch_add(1, Ordering::SeqCst);
        EnforcementResult::Verified
    }
}

struct OutcomeActuator(EnforcementResult);
#[async_trait]
impl PolicyActuator for OutcomeActuator {
    async fn enforce(&self, _: DeviceId, _: RequestedAction) -> EnforcementResult { self.0 }
}

struct QueuedSource(Mutex<VecDeque<Result<Vec<NeighborRow>, NeighborError>>>);
#[async_trait]
impl NeighborSnapshotSource for QueuedSource {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError> {
        self.0.lock().unwrap().pop_front().unwrap_or(Ok(vec![]))
    }
}

fn neighbor_row(last_octet: u8) -> NeighborRow {
    NeighborRow::new(
        InterfaceId::new(7),
        IpAddr::V4(format!("192.168.7.{last_octet}").parse().unwrap()),
        LinkAddress::try_from([2, 0, 0, 0, 0, last_octet]).unwrap(),
        NeighborReachability::Reachable,
    )
    .unwrap()
}

fn observation(t: chrono::DateTime<Utc>) -> DiscoveryObservation {
    DiscoveryObservation {
        source_id: 7,
        candidate: None,
        facts: vec![EvidenceFact {
            family: EvidenceFamily::LinkLayer,
            source: "sensor".into(),
            key: "mac".into(),
            value: "00:11:22:33:44:55".into(),
            confidence: 0.9,
            observed_at: t,
            expires_at: None,
            owner_confirmed: false,
        }],
        presence_source: "sensor".into(),
        presence_kind: PresenceEvidenceKind::Traffic,
        observed_at: t,
        valid_until: Some(t + Duration::seconds(30)),
    }
}

#[tokio::test]
async fn committed_discovery_enrollment_is_post_commit_and_unknown_expires_after_48_hours()
-> anyhow::Result<()> {
    let dir = tempdir()?;
    let pool = connect_path(&dir.path().join("policy.db")).await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    let sources = DiscoverySources::sensor(7, "sensor", vec![EvidenceFamily::LinkLayer])?;
    let mut pipeline = PersistentDiscoveryPipeline::open(
        M2StateRepository::new(pool.clone()),
        sources,
        [DeviceId::new()].into_iter(),
        Default::default(),
        8,
        8,
    )
    .await?;
    let committed = match pipeline
        .observe_with_flow(observation(at(60)), &[], 0, at(60))
        .await?
    {
        DiscoveryPipelineOutcome::Committed(value) => value,
        _ => unreachable!(),
    };
    let actuator = FakeActuator::default();
    let coordinator = PolicyCoordinator::with_actuator(repo.clone(), None, actuator.clone());
    let pending = coordinator
        .enroll_and_evaluate(committed.result.device_id, at(84))
        .await?;
    assert_eq!(pending.requested_action, RequestedAction::None);
    assert_eq!(
        pending.evaluation.warning,
        Some(lattice_domain::DeadlineWarning::Hours24)
    );
    let expired = coordinator
        .enroll_and_evaluate(committed.result.device_id, at(108))
        .await?;
    assert_eq!(expired.requested_action, RequestedAction::Quarantine);
    assert_eq!(expired.enforcement, EnforcementResult::Verified);
    assert_eq!(actuator.0.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn identical_policy_changed_is_deduplicated_across_coordinator_restart() -> anyhow::Result<()>
{
    let dir = tempdir()?;
    let pool = connect_path(&dir.path().join("dedup.db")).await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    let device = DeviceId::new();
    sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at, owner_confirmed) VALUES(?, ?, ?, 0)")
        .bind(device.to_string()).bind(at(60).to_rfc3339()).bind(at(60).to_rfc3339()).execute(&pool).await?;
    let bus = EventBus::new(8, 8);
    let first =
        PolicyCoordinator::with_actuator(repo.clone(), Some(bus.clone()), FakeActuator::default());
    first.enroll_and_evaluate(device, at(84)).await?;
    assert_eq!(bus.current_sequence().await, 1);
    let restarted =
        PolicyCoordinator::with_actuator(repo, Some(bus.clone()), FakeActuator::default());
    restarted.enroll_and_evaluate(device, at(84)).await?;
    assert_eq!(bus.current_sequence().await, 1);
    restarted.enroll_and_evaluate(device, at(102)).await?;
    assert_eq!(bus.current_sequence().await, 2);
    Ok(())
}

#[tokio::test]
async fn injected_neighbor_policy_failure_recovers_from_duplicate_without_replaying_discovery_events()
-> anyhow::Result<()> {
    let dir = tempdir()?;
    let pool = connect_path(&dir.path().join("neighbor-policy-recovery.db")).await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let policy_repo = PolicyRepository::new(pool.clone());
    policy_repo.mark_successful_service_start(at(0)).await?;
    let state_repo = M2StateRepository::new(pool.clone());
    let state = AppState::new("owner-token-0123456789abcdefghijkl", state_repo.clone())?;
    let binding = NeighborInterfaceBinding::for_interface(InterfaceId::new(7))?;
    let first = DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445501")?;
    let second = DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445502")?;
    let pipeline = PersistentDiscoveryPipeline::open(
        state_repo,
        neighbor_discovery_sources(&[binding])?,
        [first, second].into_iter(),
        Default::default(),
        16,
        16,
    )
    .await?;
    let rows = vec![neighbor_row(1), neighbor_row(2)];
    let actuator = FakeActuator::default();
    let policy = PolicyCoordinator::with_actuator(
        policy_repo.clone(),
        Some(state.events().clone()),
        actuator.clone(),
    );
    let config = NeighborCoordinatorConfig {
        poll_interval: Duration::seconds(5),
        support_ttl: Duration::seconds(4),
        tracker: NeighborTrackerConfig::default(),
    };
    let mut coordinator = NeighborCoordinator::with_policy(
        QueuedSource(Mutex::new(VecDeque::from([Ok(rows.clone()), Ok(rows)]))),
        pipeline,
        state.clone(),
        [binding],
        config,
        policy,
    )?;

    sqlx::query(
        "CREATE TRIGGER injected_policy_failure BEFORE INSERT ON device_policy
         BEGIN SELECT RAISE(ABORT, 'injected policy failure'); END",
    )
    .execute(&pool)
    .await?;
    sqlx::query(&format!(
        "CREATE TRIGGER injected_second_discovery_failure BEFORE INSERT ON devices
         WHEN NEW.device_id='{}'
         BEGIN SELECT RAISE(ABORT, 'injected discovery failure'); END",
        second
    ))
    .execute(&pool)
    .await?;

    assert!(coordinator.cycle(at(60)).await.is_err());
    assert!(policy_repo.load(first).await?.is_none());
    let sequence_before_recovery = state.events().current_sequence().await;
    sqlx::query("DROP TRIGGER injected_policy_failure")
        .execute(&pool)
        .await?;
    sqlx::query("DROP TRIGGER injected_second_discovery_failure")
        .execute(&pool)
        .await?;

    let recovered = coordinator.cycle(at(60)).await?;
    assert!(matches!(
        recovered.outcomes(),
        [
            DiscoveryPipelineOutcome::Duplicate(_),
            DiscoveryPipelineOutcome::Committed(_)
        ]
    ));
    assert!(policy_repo.load(first).await?.is_some());
    assert_eq!(actuator.0.load(Ordering::SeqCst), 0);

    let lattice_event_bus::Resume::Events(events) =
        state.events().resume_after(sequence_before_recovery).await
    else {
        panic!("replay should remain available")
    };
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                &event.payload,
                lattice_domain::EventPayload::PresenceChanged(change)
                    if change.device_id == first
            ))
            .count(),
        0,
        "duplicate recovery must not replay a discovery event"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                &event.payload,
                lattice_domain::EventPayload::PolicyChanged(change)
                    if change.device_id == first
            ))
            .count(),
        1,
        "recovery should publish the missing policy decision exactly once"
    );
    Ok(())
}

#[tokio::test]
async fn changed_enforcement_result_emits_a_new_typed_policy_event() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let pool = connect_path(&dir.path().join("enforcement-change.db")).await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    let device = DeviceId::new();
    sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at, owner_confirmed) VALUES(?, ?, ?, 0)")
        .bind(device.to_string()).bind(at(60).to_rfc3339()).bind(at(60).to_rfc3339()).execute(&pool).await?;
    let bus = EventBus::new(8, 8);
    let manual = PolicyCoordinator::new(repo.clone(), Some(bus.clone()));
    manual.enroll_and_evaluate(device, at(60)).await?;
    manual.reject(device, at(60)).await?;
    assert_eq!(bus.current_sequence().await, 2);
    let verified =
        PolicyCoordinator::with_actuator(repo, Some(bus.clone()), FakeActuator::default());
    verified.reject(device, at(60)).await?;
    assert_eq!(bus.current_sequence().await, 3);
    let restarted_repo = PolicyRepository::new(pool.clone());
    assert_eq!(
        restarted_repo.published_decision(device).await?.unwrap().enforcement_result,
        EnforcementResult::Verified,
        "resync projections must retain the acknowledged enforcement result"
    );
    Ok(())
}

#[tokio::test]
async fn runtime_sweep_evaluates_persisted_policies_without_new_discovery() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone()).initialize(at(0)).await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    let device = DeviceId::new();
    sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at, owner_confirmed) VALUES(?, ?, ?, 0)")
        .bind(device.to_string()).bind(at(60).to_rfc3339()).bind(at(60).to_rfc3339()).execute(&pool).await?;
    let actuator = FakeActuator::default();
    let coordinator = PolicyCoordinator::with_actuator(repo.clone(), None, actuator.clone());
    coordinator.enroll_and_evaluate(device, at(60)).await?;

    let decisions = coordinator.sweep(at(108)).await?;

    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].requested_action, RequestedAction::Quarantine);
    assert_eq!(decisions[0].enforcement, EnforcementResult::Verified);
    assert_eq!(actuator.0.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn only_verified_enforcement_persists_a_blocked_presence_transition() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone()).initialize(at(0)).await?;
    let policy_repo = PolicyRepository::new(pool.clone());
    policy_repo.mark_successful_service_start(at(0)).await?;
    let device = DeviceId::new();
    sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at, owner_confirmed) VALUES(?, ?, ?, 0)")
        .bind(device.to_string()).bind(at(60).to_rfc3339()).bind(at(60).to_rfc3339()).execute(&pool).await?;

    let verified = PolicyCoordinator::with_actuator_and_state(
        policy_repo.clone(), None, FakeActuator::default(), M2StateRepository::new(pool.clone()),
    );
    verified.enroll_and_evaluate(device, at(108)).await?;
    assert_eq!(
        M2StateRepository::new(pool.clone()).list_device_snapshots(8, None).await?[0]
            .presence.as_ref().map(|p| p.to_state),
        Some(lattice_domain::PresenceState::Blocked),
    );

    let manual_device = DeviceId::new();
    sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at, owner_confirmed) VALUES(?, ?, ?, 0)")
        .bind(manual_device.to_string()).bind(at(60).to_rfc3339()).bind(at(60).to_rfc3339()).execute(&pool).await?;
    let manual = PolicyCoordinator::with_state(policy_repo, None, M2StateRepository::new(pool.clone()));
    manual.enroll_and_evaluate(manual_device, at(108)).await?;
    assert_ne!(M2StateRepository::new(pool).list_device_snapshots(8, None).await?[1]
        .presence.as_ref().map(|p| p.to_state), Some(lattice_domain::PresenceState::Blocked));
    Ok(())
}

#[tokio::test]
async fn failed_enforcement_never_claims_blocked_presence() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone()).initialize(at(0)).await?;
    let policy_repo = PolicyRepository::new(pool.clone());
    policy_repo.mark_successful_service_start(at(0)).await?;
    let device = DeviceId::new();
    sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at, owner_confirmed) VALUES(?, ?, ?, 0)")
        .bind(device.to_string()).bind(at(60).to_rfc3339()).bind(at(60).to_rfc3339()).execute(&pool).await?;
    let coordinator = PolicyCoordinator::with_actuator_and_state(
        policy_repo, None, OutcomeActuator(EnforcementResult::Failed), M2StateRepository::new(pool.clone()),
    );
    assert_eq!(coordinator.enroll_and_evaluate(device, at(108)).await?.enforcement, EnforcementResult::Failed);
    let blocked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM presence_transitions WHERE device_id=? AND to_state='blocked'")
        .bind(device.to_string()).fetch_one(&pool).await?;
    assert_eq!(blocked, 0);
    Ok(())
}

#[tokio::test]
async fn protected_devices_keep_owner_actions_available_without_automatic_blocking() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone()).initialize(at(0)).await?;
    let repo = PolicyRepository::new(pool.clone());
    repo.mark_successful_service_start(at(0)).await?;
    for protection in [
        lattice_domain::Protection::Router,
        lattice_domain::Protection::Collector,
        lattice_domain::Protection::AdministratorPhone,
        lattice_domain::Protection::SafetyDevice,
    ] {
        let device = DeviceId::new();
        sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at, owner_confirmed) VALUES(?, ?, ?, 0)")
            .bind(device.to_string()).bind(at(60).to_rfc3339()).bind(at(60).to_rfc3339()).execute(&pool).await?;
        repo.enroll(device).await?;
        repo.set_protection(device, protection).await?;
        repo.set_risk(device, lattice_domain::RiskSignal::HighConfidenceDanger { confidence_basis_points: 9_500, evidence: "confirmed".into() }).await?;
        let coordinator = PolicyCoordinator::with_actuator_and_state(
            repo.clone(), None, FakeActuator::default(), M2StateRepository::new(pool.clone()),
        );
        assert_eq!(coordinator.evaluate(repo.load(device).await?.unwrap(), at(61)).await?.requested_action, RequestedAction::OwnerAttention);
        assert_eq!(coordinator.approve(device, at(61)).await?.requested_action, RequestedAction::OwnerAttention);
        assert_eq!(repo.load(device).await?.unwrap().owner_decision, lattice_domain::OwnerDecision::Approved);
        assert_eq!(coordinator.quarantine(device, at(61)).await?.requested_action, RequestedAction::Quarantine);
        assert_eq!(repo.load(device).await?.unwrap().owner_decision, lattice_domain::OwnerDecision::Quarantined);
        assert!(coordinator.extend_once(device, at(300), at(61)).await.is_ok());
    }
    Ok(())
}

#[tokio::test]
async fn policy_failure_after_a_committed_discovery_keeps_the_cycle_degraded() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone()).initialize(at(0)).await?;
    let policy_repo = PolicyRepository::new(pool.clone());
    policy_repo.mark_successful_service_start(at(0)).await?;
    let state_repo = M2StateRepository::new(pool.clone());
    let state = AppState::new("owner-token-0123456789abcdefghijkl", state_repo.clone())?;
    let binding = NeighborInterfaceBinding::for_interface(InterfaceId::new(7))?;
    let pipeline = PersistentDiscoveryPipeline::open(
        state_repo, neighbor_discovery_sources(&[binding])?, [DeviceId::new()].into_iter(), Default::default(), 16, 16,
    ).await?;
    let policy = PolicyCoordinator::with_actuator(policy_repo, Some(state.events().clone()), FakeActuator::default());
    let mut coordinator = NeighborCoordinator::with_policy(
        QueuedSource(Mutex::new(VecDeque::from([Ok(vec![neighbor_row(1)])]))), pipeline, state.clone(), [binding],
        NeighborCoordinatorConfig { poll_interval: Duration::seconds(5), support_ttl: Duration::seconds(4), tracker: NeighborTrackerConfig::default() }, policy,
    )?;
    sqlx::query("CREATE TRIGGER injected_policy_failure BEFORE INSERT ON device_policy BEGIN SELECT RAISE(ABORT, 'injected policy failure'); END")
        .execute(&pool).await?;

    let cycle = coordinator.cycle(at(60)).await?;

    assert_eq!(cycle.outcomes().len(), 1, "durable discovery output is retained");
    assert_eq!(state.service_status().await, "degraded");
    Ok(())
}
