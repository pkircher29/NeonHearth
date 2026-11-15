//! Regression: a steady 90-device network must not write a checkpoint per device per cycle.
use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone, Utc};
use lattice_domain::PresenceState;
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
};
use lattice_store::{M2StateRepository, connect_memory};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
const DEVICES: u8 = 90;

#[derive(Clone)]
struct Steady(Arc<Mutex<Vec<NeighborRow>>>);
#[async_trait]
impl NeighborSnapshotSource for Steady {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError> {
        Ok(self.0.lock().unwrap().clone())
    }
}
fn rows(count: u8) -> Vec<NeighborRow> {
    (1..=count)
        .map(|n| {
            NeighborRow::new(
                InterfaceId::new(7),
                IpAddr::V4(format!("192.168.7.{n}").parse().unwrap()),
                LinkAddress::try_from([2, 0, 0, 0, 0, n]).unwrap(),
                NeighborReachability::Reachable,
            )
            .unwrap()
        })
        .collect()
}
fn t(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap()
}
async fn open(repo: &M2StateRepository, source: Steady) -> (NeighborCoordinator<Steady>, AppState) {
    let binding = NeighborInterfaceBinding::for_interface(InterfaceId::new(7)).unwrap();
    let pipeline = PersistentDiscoveryPipeline::open(
        repo.clone(),
        neighbor_discovery_sources(&[binding]).unwrap(),
        std::iter::repeat_with(lattice_domain::DeviceId::new),
        Default::default(),
        16,
        16,
    )
    .await
    .unwrap();
    let state = AppState::new(TOKEN, repo.clone()).unwrap();
    let cfg = NeighborCoordinatorConfig {
        poll_interval: Duration::seconds(5),
        support_ttl: Duration::seconds(4),
        tracker: NeighborTrackerConfig::default(),
    };
    (
        NeighborCoordinator::new(source, pipeline, state.clone(), vec![binding], cfg).unwrap(),
        state,
    )
}

#[tokio::test]
async fn steady_cycles_do_not_commit_or_serialize_per_device() {
    let repo = M2StateRepository::new(connect_memory().await.unwrap());
    let source = Steady(Arc::new(Mutex::new(rows(DEVICES))));
    let (mut coordinator, _state) = open(&repo, source).await;
    // Warm-up: Appeared, then the second confirmation takes every device Online.
    for cycle in 0..3 {
        coordinator.cycle(t(cycle * 5)).await.unwrap();
    }
    let sequence = coordinator.commit_sequence();
    let serializations = coordinator.pipeline().checkpoint_serializations();
    assert!(sequence >= i64::from(DEVICES), "warm-up committed devices");
    for cycle in 3..43 {
        coordinator.cycle(t(cycle * 5)).await.unwrap();
        assert_eq!(coordinator.commit_sequence(), sequence, "cycle {cycle}");
    }
    assert_eq!(
        coordinator.pipeline().checkpoint_serializations(),
        serializations,
        "no checkpoint serialization on a quiet network"
    );
    // The in-memory refreshes are persisted in one commit once the interval elapses.
    coordinator.cycle(t(43 * 5 + 300)).await.unwrap();
    assert_eq!(coordinator.commit_sequence(), sequence + 1);
    assert_eq!(
        coordinator.pipeline().checkpoint_serializations(),
        serializations + 1
    );
}

#[tokio::test]
async fn restart_rebuilds_presence_from_checkpoint_plus_fresh_observations() {
    let repo = M2StateRepository::new(connect_memory().await.unwrap());
    let source = Steady(Arc::new(Mutex::new(rows(DEVICES))));
    let (mut first, _state) = open(&repo, source.clone()).await;
    for cycle in 0..10 {
        first.cycle(t(cycle * 5)).await.unwrap();
    }
    // Refreshes after the last persisted commit are deliberately lost by the "crash".
    drop(first);
    let (mut second, _state) = open(&repo, source).await;
    for cycle in 0..3 {
        second.cycle(t(1000 + cycle * 5)).await.unwrap();
    }
    let online = repo_online(&repo, &second).await;
    assert_eq!(online, usize::from(DEVICES));
}

async fn repo_online(repo: &M2StateRepository, coordinator: &NeighborCoordinator<Steady>) -> usize {
    let mut online = 0;
    for n in 1..=DEVICES {
        let link = LinkAddress::try_from([2, 0, 0, 0, 0, n]).unwrap();
        let id = repo
            .lookup_link_layer_device(link, "neighbor-interface-7")
            .await
            .unwrap()
            .expect("identity survives restart");
        if coordinator.pipeline().presence_state(id) == Some(PresenceState::Online) {
            online += 1;
        }
    }
    online
}
