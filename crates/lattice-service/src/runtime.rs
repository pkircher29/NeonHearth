//! Production wiring for the bounded M2 neighbor worker.
//!
//! The worker re-checks the eligible interface set periodically and rebuilds when it changes.
//! A failed inventory read or a momentarily empty set never tears down a running worker, and
//! startup without an eligible interface retries with backoff instead of staying degraded.
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
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::{fmt, future::Future, io};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

pub const MAX_NEIGHBOR_ROWS: usize = 4096;
pub const FLOW_BATCH_LIMIT: usize = 4096;
pub const LIVE_ROW_LIMIT: usize = 4096;

/// Why a worker restart did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RestartError {
    #[error("the discovery worker is not running")]
    NotRunning,
    #[error("the discovery worker did not finish restarting in time")]
    TimedOut,
    #[error("the discovery worker restarted but could not rebuild its capture")]
    RebuildFailed,
}

/// The newest restart request the worker has answered.
#[derive(Clone, Copy, Debug, Default)]
struct RestartAck {
    generation: u64,
    rebuilt: bool,
}

struct WorkerControlInner {
    /// True while a [`NeighborRuntime::run`] loop owns this control.
    attached: AtomicBool,
    /// Count of restart requests made so far.
    requested: AtomicU64,
    wake: Notify,
    ack: watch::Sender<RestartAck>,
}

/// Lets the Doctor ask the running discovery worker to rebuild itself in place
/// (without restarting the process) and learn whether the rebuild worked.
/// The worker polls the request counter, so a request made while it is busy is
/// never lost.
#[derive(Clone)]
pub struct WorkerControl {
    inner: Arc<WorkerControlInner>,
}

impl Default for WorkerControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Marks the worker attached for as long as it lives.
pub struct WorkerAttachment {
    inner: Arc<WorkerControlInner>,
}

impl Drop for WorkerAttachment {
    fn drop(&mut self) {
        self.inner.attached.store(false, Ordering::SeqCst);
    }
}

impl WorkerControl {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(WorkerControlInner {
                attached: AtomicBool::new(false),
                requested: AtomicU64::new(0),
                wake: Notify::new(),
                ack: watch::channel(RestartAck::default()).0,
            }),
        }
    }

    /// Whether a worker loop is currently running.
    pub fn is_attached(&self) -> bool {
        self.inner.attached.load(Ordering::SeqCst)
    }

    /// Called by the worker loop on entry; the returned guard detaches on drop.
    pub fn attach(&self) -> WorkerAttachment {
        self.inner.attached.store(true, Ordering::SeqCst);
        WorkerAttachment {
            inner: Arc::clone(&self.inner),
        }
    }

    /// How many restarts have been requested so far.
    pub fn requested(&self) -> u64 {
        self.inner.requested.load(Ordering::SeqCst)
    }

    /// Worker side: resolves once a request newer than `handled` exists.
    pub async fn wait_request(&self, handled: u64) {
        loop {
            if self.requested() > handled {
                return;
            }
            self.inner.wake.notified().await;
        }
    }

    /// Worker side: reports that the request numbered `generation` was
    /// handled and whether the capture was rebuilt.
    pub fn acknowledge(&self, generation: u64, rebuilt: bool) {
        self.inner
            .ack
            .send_replace(RestartAck { generation, rebuilt });
    }

    /// Doctor side: asks the worker to rebuild and waits (bounded) for its
    /// answer.
    pub async fn restart(&self, timeout: std::time::Duration) -> Result<(), RestartError> {
        if !self.is_attached() {
            return Err(RestartError::NotRunning);
        }
        let mut ack = self.inner.ack.subscribe();
        let target = self.inner.requested.fetch_add(1, Ordering::SeqCst) + 1;
        self.inner.wake.notify_one();
        let wait = async {
            loop {
                let current = *ack.borrow_and_update();
                if current.generation >= target {
                    return Some(current);
                }
                if ack.changed().await.is_err() {
                    return None;
                }
            }
        };
        match tokio::time::timeout(timeout, wait).await {
            Ok(Some(answer)) if answer.rebuilt => Ok(()),
            Ok(Some(_)) => Err(RestartError::RebuildFailed),
            Ok(None) => Err(RestartError::NotRunning),
            Err(_) => Err(RestartError::TimedOut),
        }
    }
}

/// Owns the neighbor worker for the life of the process. It builds the coordinator from the
/// current inventory, retries with backoff while no interface is eligible yet (service started
/// before the network was up), and rebuilds when the set of eligible interfaces changes.
pub struct NeighborRuntime {
    coordinator: Option<NeighborCoordinator<SystemNeighborSnapshotSource>>,
    planned: Vec<InterfaceId>,
    state: AppState,
    repository: M2StateRepository,
}

/// How often the running worker checks whether the eligible interface set changed.
const REPLAN_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);
const RETRY_INITIAL: std::time::Duration = std::time::Duration::from_secs(5);
const RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(60);

/// A startup plan deliberately contains only stable interface identifiers and derived bindings.
/// It never carries names, descriptions, or addresses from the OS inventory.
#[derive(Clone, Debug)]
pub struct RuntimePlan {
    bindings: Vec<NeighborInterfaceBinding>,
    sources: crate::discovery::DiscoverySources,
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
    let sources =
        neighbor_discovery_sources(&bindings).map_err(|_| SanitizedStartupError::InvalidPlan)?;
    let networks = inventory
        .interfaces()
        .flat_map(|interface| {
            interface
                .addresses
                .iter()
                .map(move |address| (interface.id, address.clone()))
        })
        .collect();
    let snapshot =
        NeighborSnapshotConfig::new(MAX_NEIGHBOR_ROWS, bindings.iter().map(|b| b.interface()))
            .map_err(|_| SanitizedStartupError::InvalidPlan)?
            .with_networks(networks);
    Ok(RuntimePlan {
        bindings,
        sources,
        snapshot,
    })
}

pub enum StartupResult {
    Worker(Box<NeighborRuntime>),
    Degraded,
}

/// Build the worker from the startup inventory. Failures are deliberately summarized so raw
/// interface names, addresses, and checkpoint contents never reach callers or logs.
///
/// Production never stays degraded: when the inventory is unavailable or has no eligible
/// interface yet, the returned worker retries in the background.
pub async fn build(state: AppState, repository: M2StateRepository) -> StartupResult {
    let inventory = match SystemInterfaceManager.snapshot() {
        Ok(inventory) => inventory,
        Err(_) => return deferred(state, repository).await,
    };
    match build_from_inventory(state.clone(), repository.clone(), inventory).await {
        StartupResult::Degraded => StartupResult::Worker(Box::new(NeighborRuntime {
            coordinator: None,
            planned: Vec::new(),
            state,
            repository,
        })),
        worker => worker,
    }
}

async fn deferred(state: AppState, repository: M2StateRepository) -> StartupResult {
    state
        .transition_service_status(ServiceRuntimeStatus::Degraded, Utc::now())
        .await;
    StartupResult::Worker(Box::new(NeighborRuntime {
        coordinator: None,
        planned: Vec::new(),
        state,
        repository,
    }))
}

pub async fn build_from_inventory(
    state: AppState,
    repository: M2StateRepository,
    inventory: InterfaceInventory,
) -> StartupResult {
    match construct(&state, &repository, &inventory).await {
        Some((coordinator, planned)) => StartupResult::Worker(Box::new(NeighborRuntime {
            coordinator: Some(coordinator),
            planned,
            state,
            repository,
        })),
        None => degraded(state).await,
    }
}

type Built = (
    NeighborCoordinator<SystemNeighborSnapshotSource>,
    Vec<InterfaceId>,
);

async fn construct(
    state: &AppState,
    repository: &M2StateRepository,
    inventory: &InterfaceInventory,
) -> Option<Built> {
    let plan = plan_inventory(inventory).ok()?;
    let planned: Vec<InterfaceId> = plan.bindings.iter().map(|b| b.interface()).collect();
    let mut pipeline = PersistentDiscoveryPipeline::open(
        repository.clone(),
        plan.sources,
        std::iter::repeat_with(DeviceId::new),
        Default::default(),
        FLOW_BATCH_LIMIT,
        LIVE_ROW_LIMIT,
    )
    .await
    .ok()?;
    // Devices last seen through an interface that is gone must not stay Online forever.
    pipeline.reconcile_orphans(Utc::now());
    let source = SystemNeighborSnapshotSource::new(plan.snapshot.clone());
    let coordinator = NeighborCoordinator::new(
        source,
        pipeline,
        state.clone(),
        plan.bindings,
        NeighborCoordinatorConfig::default(),
    )
    .ok()?;
    Some((coordinator, planned))
}

async fn degraded(state: AppState) -> StartupResult {
    state
        .transition_service_status(ServiceRuntimeStatus::Degraded, Utc::now())
        .await;
    StartupResult::Degraded
}

/// The eligible interface ids right now, or `None` when the inventory cannot be read or has
/// no eligible interface (a momentary gap must not tear the running worker down).
async fn eligible_now() -> Option<Vec<InterfaceId>> {
    let inventory = tokio::task::spawn_blocking(|| SystemInterfaceManager.snapshot())
        .await
        .ok()?
        .ok()?;
    let plan = plan_inventory(&inventory).ok()?;
    Some(plan.bindings.iter().map(|b| b.interface()).collect())
}

/// Resolves when the eligible interface set differs from `planned`.
async fn interface_set_changed(planned: &[InterfaceId]) {
    loop {
        tokio::time::sleep(REPLAN_PERIOD).await;
        if eligible_now().await.is_some_and(|now| now != planned) {
            return;
        }
    }
}

impl NeighborRuntime {
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let control = self.state.worker_control().clone();
        // Read before attaching: requests are refused until a worker is
        // attached, so everything counted after this point is for this loop.
        let mut handled = control.requested();
        let _attached = control.attach();
        let mut pending_ack: Option<u64> = None;
        let mut backoff = RETRY_INITIAL;
        loop {
            if *shutdown.borrow() {
                return;
            }
            let requested = control.requested();
            if requested > handled {
                // An owner-approved restart: drop the coordinator so the block
                // below rebuilds it from a fresh inventory.
                handled = requested;
                pending_ack = Some(requested);
                if self.coordinator.take().is_some() {
                    tracing::info!("worker restart requested; rebuilding the neighbor worker");
                }
            }
            if self.coordinator.is_none() {
                let inventory = tokio::task::spawn_blocking(|| SystemInterfaceManager.snapshot())
                    .await
                    .ok()
                    .and_then(Result::ok);
                let built = match inventory {
                    Some(inventory) => construct(&self.state, &self.repository, &inventory).await,
                    None => None,
                };
                match built {
                    Some((coordinator, planned)) => {
                        self.coordinator = Some(coordinator);
                        self.planned = planned;
                        backoff = RETRY_INITIAL;
                        if let Some(generation) = pending_ack.take() {
                            control.acknowledge(generation, true);
                        }
                    }
                    None => {
                        if let Some(generation) = pending_ack.take() {
                            control.acknowledge(generation, false);
                        }
                        self.state
                            .transition_service_status(ServiceRuntimeStatus::Degraded, Utc::now())
                            .await;
                        tokio::select! {
                            changed = shutdown.changed() => {
                                if changed.is_err() || *shutdown.borrow() {
                                    return;
                                }
                            }
                            () = tokio::time::sleep(backoff) => {}
                            () = control.wait_request(handled) => {}
                        }
                        backoff = (backoff * 2).min(RETRY_MAX);
                        continue;
                    }
                }
            }
            let Some(coordinator) = self.coordinator.as_mut() else {
                continue;
            };
            let changed = tokio::select! {
                () = run_loop(coordinator, &mut shutdown) => false,
                () = interface_set_changed(&self.planned) => true,
                () = control.wait_request(handled) => true,
            };
            if !changed {
                return;
            }
            tracing::info!("discovery worker is rebuilding (interface change or restart request)");
            self.coordinator = None;
        }
    }
}

/// Generic loop kept separate from production construction for deterministic paused-time tests.
pub async fn run_loop<S: lattice_sensor::neighbor::NeighborSnapshotSource>(
    coordinator: &mut NeighborCoordinator<S>,
    shutdown: &mut watch::Receiver<bool>,
) {
    run_loop_with_clock(coordinator, shutdown, Utc::now).await;
}

/// Runtime loop with an injectable clock for deterministic coordinator tests.
pub async fn run_loop_with_clock<S, C>(
    coordinator: &mut NeighborCoordinator<S>,
    shutdown: &mut watch::Receiver<bool>,
    mut now: C,
) where
    S: lattice_sensor::neighbor::NeighborSnapshotSource,
    C: FnMut() -> chrono::DateTime<Utc>,
{
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
                    result = coordinator.cycle(now()) => if let Err(error) = result {
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
        crate::discovery::NeighborCoordinatorError::Discovery(error) => match error {
            crate::discovery::DiscoveryError::Identity(_) => "discovery_identity",
            crate::discovery::DiscoveryError::Presence(_) => "discovery_presence",
            crate::discovery::DiscoveryError::Checkpoint(
                lattice_store::CheckpointError::Capacity(_),
            ) => "discovery_checkpoint_capacity",
            crate::discovery::DiscoveryError::Checkpoint(
                lattice_store::CheckpointError::Conflict(_),
            ) => "discovery_checkpoint_conflict",
            crate::discovery::DiscoveryError::Checkpoint(_) => "discovery_checkpoint",
            crate::discovery::DiscoveryError::InvalidCheckpoint => "discovery_invalid_checkpoint",
            crate::discovery::DiscoveryError::UnboundLink => "discovery_unbound_link",
            _ => "discovery",
        },
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
    fn inventory_plan_rejects_no_eligible_and_over_capacity() {
        assert!(matches!(
            plan_inventory(&InterfaceInventory::new(vec![interface(
                1,
                InterfaceClass::Tailscale,
                true,
                false
            )])),
            Err(SanitizedStartupError::NoEligibleInterfaces)
        ));
        assert!(matches!(
            plan_inventory(&InterfaceInventory::new(
                (1..=65)
                    .map(|id| interface(id, InterfaceClass::PhysicalWired, true, false))
                    .collect(),
            )),
            Err(SanitizedStartupError::InvalidPlan)
        ));
    }

    #[test]
    fn inventory_duplicate_ids_are_deduplicated_by_inventory_before_planning() {
        let plan = plan_inventory(&InterfaceInventory::new(vec![
            interface(4, InterfaceClass::PhysicalWired, true, false),
            interface(4, InterfaceClass::PhysicalWifi, true, false),
        ]))
        .unwrap();
        assert_eq!(
            plan.bindings()
                .iter()
                .map(|binding| binding.interface().get())
                .collect::<Vec<_>>(),
            vec![4]
        );
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

    #[tokio::test]
    async fn supervisor_without_worker_returns_server_success_or_error() {
        let (shutdown, _) = watch::channel(false);
        assert!(supervise(async { Ok(()) }, None, shutdown).await.is_ok());
        let (shutdown, _) = watch::channel(false);
        let error = supervise(async { Err(io::Error::other("server")) }, None, shutdown)
            .await
            .unwrap_err();
        assert!(error.server_error().is_some());
        assert!(error.worker_error().is_none());
    }

    #[tokio::test]
    async fn supervisor_aggregates_worker_panic_and_server_error() {
        let (shutdown, mut rx) = watch::channel(false);
        let worker = tokio::spawn(async move { panic!("worker failure") });
        let error = supervise(
            async move {
                rx.changed().await.unwrap();
                Err(io::Error::other("server failure"))
            },
            Some(worker),
            shutdown,
        )
        .await
        .unwrap_err();
        assert!(error.server_error().is_some());
        assert!(error.worker_error().unwrap().is_panic());
    }

    fn answering_worker(control: &WorkerControl, rebuilt: bool) -> JoinHandle<()> {
        let control = control.clone();
        let mut handled = control.requested();
        let attachment = control.attach();
        tokio::spawn(async move {
            let _attachment = attachment;
            loop {
                control.wait_request(handled).await;
                handled = control.requested();
                control.acknowledge(handled, rebuilt);
            }
        })
    }

    #[tokio::test]
    async fn a_restart_is_refused_without_a_worker_and_answered_by_one() {
        let control = WorkerControl::new();
        assert_eq!(
            control.restart(std::time::Duration::from_secs(5)).await,
            Err(RestartError::NotRunning)
        );
        assert_eq!(control.requested(), 0, "a refused restart is not counted");

        let worker = answering_worker(&control, true);
        assert!(control.is_attached());
        for _ in 0..2 {
            assert_eq!(
                control.restart(std::time::Duration::from_secs(30)).await,
                Ok(())
            );
        }
        worker.abort();
        let _ = worker.await;
        assert!(!control.is_attached());
    }

    #[tokio::test]
    async fn a_worker_that_could_not_rebuild_is_reported_as_failed() {
        let control = WorkerControl::new();
        let worker = answering_worker(&control, false);
        assert_eq!(
            control.restart(std::time::Duration::from_secs(30)).await,
            Err(RestartError::RebuildFailed)
        );
        worker.abort();
    }

    #[tokio::test]
    async fn a_worker_that_never_answers_times_the_restart_out() {
        let control = WorkerControl::new();
        let _attachment = control.attach();
        assert_eq!(
            control.restart(std::time::Duration::from_millis(100)).await,
            Err(RestartError::TimedOut)
        );
    }
}
