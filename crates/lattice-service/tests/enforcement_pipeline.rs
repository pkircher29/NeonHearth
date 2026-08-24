use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, EvidenceFact, EvidenceFamily, RequestedAction};
use lattice_event_bus::EventBus;
use lattice_intelligence::presence::PresenceEvidenceKind;
use lattice_service::{
    discovery::{
        DiscoveryObservation, DiscoveryPipelineOutcome, DiscoverySources,
        PersistentDiscoveryPipeline,
    },
    policy::{EnforcementResult, PolicyActuator, PolicyCoordinator},
};
use lattice_store::{InstallRepository, M2StateRepository, PolicyRepository, connect_path};
use std::sync::{
    Arc,
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
    Ok(())
}
