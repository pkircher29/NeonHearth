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
use std::time::Duration;
use tokio::sync::watch;

pub const MAX_NEIGHBOR_ROWS: usize = 4096;
pub const FLOW_BATCH_LIMIT: usize = 4096;
pub const LIVE_ROW_LIMIT: usize = 4096;

pub struct NeighborRuntime {
    coordinator: NeighborCoordinator<SystemNeighborSnapshotSource>,
}

pub enum StartupResult {
    Worker(NeighborRuntime),
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
    let mut ids: Vec<InterfaceId> = inventory
        .interfaces()
        .filter(|interface| interface.discovery_eligible(InterfaceOverride::Default))
        .map(|interface| interface.id)
        .collect();
    ids.sort();
    if ids.is_empty() {
        return degraded(state).await;
    }
    let bindings: Vec<_> = match ids
        .iter()
        .map(|id| NeighborInterfaceBinding::for_interface(*id))
        .collect()
    {
        Ok(bindings) => bindings,
        Err(_) => return degraded(state).await,
    };
    let sources = match neighbor_discovery_sources(&bindings) {
        Ok(s) => s,
        Err(_) => return degraded(state).await,
    };
    let config = match NeighborSnapshotConfig::new(MAX_NEIGHBOR_ROWS, ids.iter().copied()) {
        Ok(c) => c,
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
    let source = SystemNeighborSnapshotSource::new(config);
    match NeighborCoordinator::new(
        source,
        pipeline,
        state.clone(),
        bindings,
        NeighborCoordinatorConfig::default(),
    ) {
        Ok(coordinator) => StartupResult::Worker(NeighborRuntime { coordinator }),
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
        .unwrap_or(Duration::from_secs(5));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => match changed { Ok(()) if *shutdown.borrow() => return, Ok(()) => {}, Err(_) => return },
            _ = ticker.tick() => {
                if *shutdown.borrow() { return; }
                if let Err(error) = coordinator.cycle(Utc::now()).await {
                    tracing::warn!(category = %error_category(&error), "neighbor discovery cycle degraded");
                }
            }
        }
    }
}

fn error_category(error: &crate::discovery::NeighborCoordinatorError) -> &'static str {
    match error {
        crate::discovery::NeighborCoordinatorError::Snapshot(_) => "snapshot",
        crate::discovery::NeighborCoordinatorError::Discovery(_) => "discovery",
    }
}
