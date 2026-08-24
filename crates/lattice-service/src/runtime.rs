//! Production wiring for the bounded M2 neighbor worker.
//!
//! Interface inventory is intentionally startup-static in M2; a later slice can add a
//! refresh mechanism without treating a failed refresh as an empty inventory.
use crate::discovery::{
    NeighborCoordinator, NeighborCoordinatorConfig, NeighborInterfaceBinding,
    PersistentDiscoveryPipeline, neighbor_discovery_sources,
};
use crate::{AppState, ServiceRuntimeStatus};
use chrono::Utc;
use lattice_domain::DeviceId;
use lattice_sensor::neighbor::{NeighborSnapshotConfig, SystemNeighborSnapshotSource};
use lattice_sensor::{InterfaceId, InterfaceInventory, InterfaceOverride, SystemInterfaceManager};
use lattice_store::M2StateRepository;
use std::{fmt, future::Future, io};
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub const MAX_NEIGHBOR_ROWS: usize = 4096;
pub const FLOW_BATCH_LIMIT: usize = 4096;
pub const LIVE_ROW_LIMIT: usize = 4096;

pub struct NeighborRuntime {
    coordinator: NeighborCoordinator<SystemNeighborSnapshotSource>,
}

/// A startup plan deliberately contains only stable interface identifiers and derived bindings.
/// It never carries names, descriptions, or addresses from the OS inventory.
#[derive(Clone, Debug)]
pub struct RuntimePlan {
    bindings: Vec<NeighborInterfaceBinding>,
    snapshot: NeighborSnapshotConfig,
}

impl RuntimePlan {
    pub fn bindings(&self) -> &[NeighborInterfaceBinding] {
        &self.bindings
    }
    pub fn snapshot_config(&self) -> &NeighborSnapshotConfig {
        &self.snapshot
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SanitizedStartupError {
    #[error("no eligible network interfaces")]
    NoEligibleInterfaces,
    #[error("invalid runtime interface plan")]
    InvalidPlan,
}

/// Select only owner-approved, up physical adapters. The inventory is intentionally static at
/// startup; runtime hot-plug refresh is outside M2 and must not turn a refresh failure into an
/// empty plan.
pub fn plan_inventory(
    inventory: &InterfaceInventory,
) -> Result<RuntimePlan, SanitizedStartupError> {
    let mut ids: Vec<InterfaceId> = inventory
        .interfaces()
        .filter(|interface| interface.discovery_eligible(InterfaceOverride::Default))
        .map(|interface| interface.id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Err(SanitizedStartupError::NoEligibleInterfaces);
    }
    let bindings = ids
        .into_iter()
        .map(NeighborInterfaceBinding::for_interface)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SanitizedStartupError::InvalidPlan)?;
    let snapshot =
        NeighborSnapshotConfig::new(MAX_NEIGHBOR_ROWS, bindings.iter().map(|b| b.interface()))
            .map_err(|_| SanitizedStartupError::InvalidPlan)?;
    Ok(RuntimePlan { bindings, snapshot })
}

pub enum StartupResult {
    Worker(Box<NeighborRuntime>),
    Degraded,
}

/// Build the worker from the startup inventory. Failures are deliberately summarized so raw
/// interface names, addresses, and checkpoint contents never reach callers or logs.
pub async fn build(state: AppState, repository: M2StateRepository) -> StartupResult {
    let inventory = match SystemInterfaceManager.snapshot() {
        Ok(inventory) => inventory,
        Err(_) => return degraded(state).await,
    };
    build_from_inventory(state, repository, inventory).await
}

pub async fn build_from_inventory(
    state: AppState,
    repository: M2StateRepository,
    inventory: InterfaceInventory,
) -> StartupResult {
    let plan = match plan_inventory(&inventory) {
        Ok(plan) => plan,
        Err(_) => return degraded(state).await,
    };
    let sources = match neighbor_discovery_sources(plan.bindings()) {
        Ok(s) => s,
        Err(_) => return degraded(state).await,
    };
    let pipeline = match PersistentDiscoveryPipeline::open(
        repository,
        sources,
        std::iter::repeat_with(DeviceId::new),
        Default::default(),
        FLOW_BATCH_LIMIT,
        LIVE_ROW_LIMIT,
    )
    .await
    {
        Ok(p) => p,
        Err(_) => return degraded(state).await,
    };
    let source = SystemNeighborSnapshotSource::new(plan.snapshot.clone());
    match NeighborCoordinator::new(
        source,
        pipeline,
        state.clone(),
        plan.bindings,
        NeighborCoordinatorConfig::default(),
    ) {
        Ok(coordinator) => StartupResult::Worker(Box::new(NeighborRuntime { coordinator })),
        Err(_) => degraded(state).await,
    }
}

async fn degraded(state: AppState) -> StartupResult {
    state
        .transition_service_status(ServiceRuntimeStatus::Degraded, Utc::now())
        .await;
    StartupResult::Degraded
}

impl NeighborRuntime {
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        run_loop(&mut self.coordinator, &mut shutdown).await;
    }
}

/// Generic loop kept separate from production construction for deterministic paused-time tests.
pub async fn run_loop<S: lattice_sensor::neighbor::NeighborSnapshotSource>(
    coordinator: &mut NeighborCoordinator<S>,
    shutdown: &mut watch::Receiver<bool>,
) {
    if *shutdown.borrow() {
        return;
    }
    let interval = coordinator
        .poll_interval()
        .to_std()
        .expect("NeighborCoordinator validates a positive poll interval");
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => match changed { Ok(()) if *shutdown.borrow() => return, Ok(()) => {}, Err(_) => return },
            _ = ticker.tick() => {
                if *shutdown.borrow() { return; }
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => match changed { Ok(()) if *shutdown.borrow() => return, Ok(()) => {}, Err(_) => return },
                    result = coordinator.cycle(Utc::now()) => if let Err(error) = result {
                        tracing::warn!(category = error_category(&error), "neighbor discovery cycle degraded");
                    },
                }
            }
        }
    }
}

/// Error from a supervised service. Both independently failing sides are retained so cleanup
/// cannot hide a worker panic behind a server I/O error (or vice versa).
#[derive(Debug)]
pub struct SupervisionError {
    server: Option<io::Error>,
    worker: Option<tokio::task::JoinError>,
}
impl SupervisionError {
    pub fn server_error(&self) -> Option<&io::Error> {
        self.server.as_ref()
    }
    pub fn worker_error(&self) -> Option<&tokio::task::JoinError> {
        self.worker.as_ref()
    }
}
impl fmt::Display for SupervisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.server, &self.worker) {
            (Some(_), Some(_)) => f.write_str("server and worker failed"),
            (Some(_), None) => f.write_str("server failed"),
            (None, Some(_)) => f.write_str("worker failed"),
            (None, None) => f.write_str("supervision failed"),
        }
    }
}
impl std::error::Error for SupervisionError {}

/// Own a server and optional worker exactly once. On either completion, broadcast shutdown and
/// await only its still-running peer before returning all observed errors.
pub async fn supervise<S>(
    server: S,
    worker: Option<JoinHandle<()>>,
    shutdown: watch::Sender<bool>,
) -> Result<(), SupervisionError>
where
    S: Future<Output = io::Result<()>>,
{
    let Some(mut worker) = worker else {
        return server.await.map_err(|error| SupervisionError {
            server: Some(error),
            worker: None,
        });
    };
    tokio::pin!(server);
    enum First {
        Server(io::Result<()>),
        Worker(Result<(), tokio::task::JoinError>),
    }
    let first = tokio::select! {
        result = &mut server => First::Server(result),
        result = &mut worker => First::Worker(result),
    };
    let _ = shutdown.send(true);
    let (server, worker) = match first {
        First::Server(result) => (result.err(), worker.await.err()),
        First::Worker(result) => (server.await.err(), result.err()),
    };
    if server.is_none() && worker.is_none() {
        Ok(())
    } else {
        Err(SupervisionError { server, worker })
    }
}

fn error_category(error: &crate::discovery::NeighborCoordinatorError) -> &'static str {
    match error {
        crate::discovery::NeighborCoordinatorError::Snapshot(_) => "snapshot",
        crate::discovery::NeighborCoordinatorError::Discovery(_) => "discovery",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_sensor::{Interface, InterfaceClass, InterfaceRole};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::oneshot;

    fn interface(id: u32, class: InterfaceClass, up: bool, corporate: bool) -> Interface {
        Interface {
            id: InterfaceId::new(id),
            name: format!("adapter-{id}"),
            description: Some("private".into()),
            up,
            class,
            addresses: vec![],
            owner_role: corporate.then_some(InterfaceRole::Corporate),
        }
    }

    #[test]
    fn inventory_plan_is_sorted_bounded_and_sanitized() {
        let inventory = InterfaceInventory::new(vec![
            interface(9, InterfaceClass::PhysicalWifi, true, false),
            interface(2, InterfaceClass::PhysicalWired, true, false),
            interface(3, InterfaceClass::PhysicalWired, false, false),
            interface(4, InterfaceClass::PhysicalWired, true, true),
            interface(5, InterfaceClass::Tailscale, true, false),
            interface(6, InterfaceClass::Unknown, true, false),
            interface(7, InterfaceClass::Loopback, true, false),
            interface(8, InterfaceClass::VpnTunnel, true, false),
            interface(10, InterfaceClass::Container, true, false),
            interface(11, InterfaceClass::VirtualMachine, true, false),
        ]);
        let plan = plan_inventory(&inventory).unwrap();
        assert_eq!(
            plan.bindings()
                .iter()
                .map(|b| b.interface().get())
                .collect::<Vec<_>>(),
            vec![2, 9]
        );
        assert_eq!(plan.snapshot_config().max_rows(), MAX_NEIGHBOR_ROWS);
        assert_eq!(plan.snapshot_config().allowed_interfaces().len(), 2);
        assert!(!format!("{plan:?}").contains("private"));
    }

    #[test]
    fn inventory_plan_rejects_no_eligible_and_accepts_over_capacity() {
        assert!(matches!(
            plan_inventory(&InterfaceInventory::new(vec![interface(
                1,
                InterfaceClass::Tailscale,
                true,
                false
            )])),
            Err(SanitizedStartupError::NoEligibleInterfaces)
        ));
        let plan = plan_inventory(&InterfaceInventory::new(
            (1..=65)
                .map(|id| interface(id, InterfaceClass::PhysicalWired, true, false))
                .collect(),
        ))
        .unwrap();
        assert_eq!(plan.bindings().len(), 65);
    }

    #[tokio::test]
    async fn supervisor_server_first_signals_and_joins_worker_once() {
        let (shutdown, mut rx) = watch::channel(false);
        let drops = Arc::new(AtomicUsize::new(0));
        let worker_drops = drops.clone();
        let worker = tokio::spawn(async move {
            rx.changed().await.unwrap();
            worker_drops.fetch_add(1, Ordering::SeqCst);
        });
        let result = supervise(
            async { Err(io::Error::other("server")) },
            Some(worker),
            shutdown,
        )
        .await;
        let error = result.unwrap_err();
        assert!(error.server_error().is_some());
        assert!(error.worker_error().is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn supervisor_worker_panic_stops_and_awaits_server_once() {
        let (shutdown, mut rx) = watch::channel(false);
        let (server_done_tx, server_done_rx) = oneshot::channel();
        let worker = tokio::spawn(async move { panic!("worker failure") });
        let server = async move {
            rx.changed().await.unwrap();
            let _ = server_done_tx.send(());
            Ok(())
        };
        let result = supervise(server, Some(worker), shutdown).await;
        assert!(result.unwrap_err().worker_error().unwrap().is_panic());
        server_done_rx.await.unwrap();
    }

    #[tokio::test]
    async fn supervisor_keeps_both_errors_after_worker_first() {
        let (shutdown, mut rx) = watch::channel(false);
        let worker = tokio::spawn(async {});
        let result = supervise(
            async move {
                rx.changed().await.unwrap();
                Err(io::Error::other("server"))
            },
            Some(worker),
            shutdown,
        )
        .await;
        let error = result.unwrap_err();
        assert!(error.server_error().is_some());
        assert!(error.worker_error().is_none());
    }
}
