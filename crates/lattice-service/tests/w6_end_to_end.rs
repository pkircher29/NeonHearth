use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, EventPayload, PresenceState, RequestedAction};
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
        NeighborCoordinator, NeighborCoordinatorConfig, NeighborInterfaceBinding,
        PersistentDiscoveryPipeline, neighbor_discovery_sources,
    },
    policy::{EnforcementResult, PolicyActuator, PolicyCoordinator, W6PolicyActuator},
};
use lattice_store::{InstallRepository, M2StateRepository, PolicyRepository, connect_memory};
use lattice_w6::{Capability, Connector, DeviceState, Profile, Transport};
use secrecy::SecretString;
use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

fn at(hour: i64) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 23, 0, 0, 0).unwrap() + Duration::hours(hour)
}

fn binding() -> NeighborInterfaceBinding {
    NeighborInterfaceBinding::for_interface(InterfaceId::new(7)).unwrap()
}

fn row() -> NeighborRow {
    NeighborRow::new(
        InterfaceId::new(7),
        IpAddr::V4("192.168.7.42".parse().unwrap()),
        LinkAddress::try_from([2, 0, 0, 0, 0, 42]).unwrap(),
        NeighborReachability::Reachable,
    )
    .unwrap()
}

struct QueuedSource(Mutex<VecDeque<Result<Vec<NeighborRow>, NeighborError>>>);

#[async_trait]
impl NeighborSnapshotSource for QueuedSource {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError> {
        self.0.lock().unwrap().pop_front().unwrap_or(Ok(vec![]))
    }
}

#[derive(Clone)]
struct Fixture {
    state: Arc<Mutex<DeviceState>>,
    applies: Arc<AtomicUsize>,
}

struct DriftFixture {
    state_reads: Arc<AtomicUsize>,
    applies: Arc<AtomicUsize>,
}

#[async_trait]
impl Transport for DriftFixture {
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
        Ok(DeviceState {
            disconnect_now: false,
            deny_wifi_association: false,
            deny_internet: false,
            deny_lan: self.state_reads.fetch_add(1, Ordering::SeqCst) > 0,
            persistent_filter: false,
            filter_entries: 0,
        })
    }
    async fn apply(&mut self, _: Capability) -> Result<(), lattice_w6::Error> {
        self.applies.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait]
impl Transport for Fixture {
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
            _ => {}
        }
        Ok(())
    }
    async fn restore(&mut self, previous: DeviceState) -> Result<(), lattice_w6::Error> {
        *self.state.lock().unwrap() = previous;
        Ok(())
    }
}

async fn trusted_connector(fixture: Fixture) -> Connector<Fixture> {
    let mut connector = Connector::new(fixture);
    connector
        .login("owner", SecretString::new("fixture-secret".into()))
        .await
        .unwrap();
    connector
}

fn config() -> NeighborCoordinatorConfig {
    NeighborCoordinatorConfig {
        poll_interval: Duration::seconds(5),
        support_ttl: Duration::seconds(4),
        tracker: NeighborTrackerConfig::default(),
    }
}

#[tokio::test]
async fn w6_unknown_deadline_is_verified_once_and_owner_approval_restores_durable_prior_state()
-> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let policy_repo = PolicyRepository::new(pool.clone());
    policy_repo.mark_successful_service_start(at(0)).await?;
    let state_repo = M2StateRepository::new(pool.clone());
    let state = AppState::new(TOKEN, state_repo.clone())?;
    let device = DeviceId::parse("018f47a0-9b5c-7a22-8a33-112233445542")?;
    let fixture = Fixture {
        state: Arc::new(Mutex::new(DeviceState {
            disconnect_now: false,
            deny_wifi_association: false,
            deny_internet: false,
            deny_lan: false,
            persistent_filter: false,
            filter_entries: 0,
        })),
        applies: Arc::new(AtomicUsize::new(0)),
    };
    let initial_state = fixture.state.lock().unwrap().clone();
    let interface = binding();
    let pipeline = PersistentDiscoveryPipeline::open(
        state_repo.clone(),
        neighbor_discovery_sources(&[interface])?,
        [device].into_iter(),
        Default::default(),
        16,
        16,
    )
    .await?;
    let policy = PolicyCoordinator::with_actuator_and_state(
        policy_repo.clone(),
        Some(state.events().clone()),
        W6PolicyActuator::with_sqlite(trusted_connector(fixture.clone()).await, pool.clone()),
        state_repo.clone(),
    );
    let mut coordinator = NeighborCoordinator::with_policy(
        QueuedSource(Mutex::new(VecDeque::from([Ok(vec![row()]), Ok(vec![])]))),
        pipeline,
        state.clone(),
        [interface],
        config(),
        policy,
    )?;

    coordinator.cycle(at(60)).await?;
    coordinator.cycle(at(108)).await?;
    assert_eq!(fixture.applies.load(Ordering::SeqCst), 1);
    assert!(fixture.state.lock().unwrap().deny_internet);
    assert_eq!(
        state_repo.list_device_snapshots(8, None).await?[0]
            .presence
            .as_ref()
            .map(|transition| transition.to_state),
        Some(PresenceState::Blocked)
    );
    let lattice_event_bus::Resume::Events(events) = state.events().resume_after(0).await else {
        panic!("fixture event bus must retain policy events");
    };
    assert!(events.iter().any(|event| matches!(
        &event.payload,
        EventPayload::PolicyChanged(change)
            if change.device_id == device
                && change.requested_action == RequestedAction::Quarantine
                && change.enforcement_result == EnforcementResult::Verified
    )));
    assert!(
        sqlx::query_scalar::<_, String>(
            "SELECT state_json FROM w6_policy_prior_state WHERE device_id=?",
        )
        .bind(device.to_string())
        .fetch_optional(&pool)
        .await?
        .is_some()
    );

    let restored_pipeline = PersistentDiscoveryPipeline::open(
        state_repo.clone(),
        neighbor_discovery_sources(&[interface])?,
        [device].into_iter(),
        Default::default(),
        16,
        16,
    )
    .await?;
    let restarted_policy = PolicyCoordinator::with_actuator_and_state(
        policy_repo.clone(),
        Some(state.events().clone()),
        W6PolicyActuator::with_sqlite(trusted_connector(fixture.clone()).await, pool.clone()),
        state_repo.clone(),
    );
    let mut restarted = NeighborCoordinator::with_policy(
        QueuedSource(Mutex::new(VecDeque::from([Ok(vec![])]))),
        restored_pipeline,
        state,
        [interface],
        config(),
        restarted_policy,
    )?;
    restarted.cycle(at(109)).await?;
    assert_eq!(fixture.applies.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.lock().unwrap().filter_entries, 0);

    let approval = PolicyCoordinator::with_actuator_and_state(
        policy_repo,
        None,
        W6PolicyActuator::with_sqlite(trusted_connector(fixture.clone()).await, pool.clone()),
        state_repo.clone(),
    )
    .approve(device, at(109))
    .await?;
    assert_eq!(approval.enforcement, EnforcementResult::Verified);
    assert_eq!(*fixture.state.lock().unwrap(), initial_state);
    assert!(
        sqlx::query_scalar::<_, String>(
            "SELECT state_json FROM w6_policy_prior_state WHERE device_id=?",
        )
        .bind(device.to_string())
        .fetch_optional(&pool)
        .await?
        .is_none()
    );
    assert_ne!(
        state_repo.list_device_snapshots(8, None).await?[0]
            .presence
            .as_ref()
            .map(|transition| transition.to_state),
        Some(PresenceState::Blocked)
    );
    Ok(())
}

#[tokio::test]
async fn durable_checkpoint_save_failure_prevents_any_w6_apply() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    InstallRepository::new(pool.clone())
        .initialize(at(0))
        .await?;
    let device = DeviceId::new();
    sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at) VALUES(?, ?, ?)")
        .bind(device.to_string())
        .bind(at(0).to_rfc3339())
        .bind(at(0).to_rfc3339())
        .execute(&pool)
        .await?;
    sqlx::query("CREATE TRIGGER reject_w6_checkpoint BEFORE INSERT ON w6_policy_prior_state BEGIN SELECT RAISE(ABORT, 'fixture checkpoint failure'); END")
        .execute(&pool)
        .await?;
    let fixture = Fixture {
        state: Arc::new(Mutex::new(DeviceState {
            disconnect_now: false,
            deny_wifi_association: false,
            deny_internet: false,
            deny_lan: false,
            persistent_filter: false,
            filter_entries: 0,
        })),
        applies: Arc::new(AtomicUsize::new(0)),
    };
    let actuator = W6PolicyActuator::with_sqlite(trusted_connector(fixture.clone()).await, pool);
    assert_eq!(
        actuator.enforce(device, RequestedAction::Quarantine).await,
        EnforcementResult::Failed
    );
    assert_eq!(fixture.applies.load(Ordering::SeqCst), 0);
    assert!(!fixture.state.lock().unwrap().deny_internet);
    Ok(())
}

#[tokio::test]
async fn prepare_apply_state_drift_prevents_any_w6_apply() -> anyhow::Result<()> {
    let applies = Arc::new(AtomicUsize::new(0));
    let mut connector = Connector::new(DriftFixture {
        state_reads: Arc::new(AtomicUsize::new(0)),
        applies: applies.clone(),
    });
    connector
        .login("owner", SecretString::new("fixture-secret".into()))
        .await?;
    let actuator = W6PolicyActuator::new(connector);

    assert_eq!(
        actuator
            .enforce(DeviceId::new(), RequestedAction::Quarantine)
            .await,
        EnforcementResult::Failed
    );
    assert_eq!(applies.load(Ordering::SeqCst), 0);
    Ok(())
}
