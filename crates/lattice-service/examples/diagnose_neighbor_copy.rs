//! Diagnose discovery against a disposable SQLite copy, never a live database.
use lattice_sensor::{SystemInterfaceManager, neighbor::SystemNeighborSnapshotSource};
use lattice_service::{
    AppState,
    discovery::{
        NeighborCoordinator, NeighborCoordinatorConfig, PersistentDiscoveryPipeline,
        neighbor_discovery_sources,
    },
};
use lattice_store::M2StateRepository;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();
    let path = std::env::args()
        .nth(1)
        .expect("pass a disposable database copy");
    let pool = lattice_store::connect_path(path).await?;
    let repository = M2StateRepository::new(pool);
    let state = AppState::new("diagnostic-copy-owner-0123456789abcdef", repository.clone())?;
    let inventory = SystemInterfaceManager.snapshot()?;
    let plan = lattice_service::runtime::plan_inventory(&inventory)?;
    let pipeline = PersistentDiscoveryPipeline::open(
        repository,
        neighbor_discovery_sources(plan.bindings())?,
        std::iter::repeat_with(lattice_domain::DeviceId::new),
        Default::default(),
        4096,
        4096,
    )
    .await?;
    let mut coordinator = NeighborCoordinator::new(
        SystemNeighborSnapshotSource::new(plan.snapshot_config().clone()),
        pipeline,
        state.clone(),
        plan.bindings().iter().copied(),
        NeighborCoordinatorConfig::default(),
    )?;
    for cycle in 0..3 {
        let start = std::time::Instant::now();
        match coordinator.cycle(chrono::Utc::now()).await {
            Ok(_) => {
                let status = state.service_status().await;
                anyhow::ensure!(status == "ready", "cycle {cycle} ended with {status}");
                println!(
                    "cycle {cycle}: committed and ready in {:?}",
                    start.elapsed()
                );
            }
            Err(error) => return Err(error.into()),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    Ok(())
}
