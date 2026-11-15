//! Regression: a change in the set of observed interfaces between runs must not disable
//! discovery, and must not lose device identities.
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

#[derive(Clone)]
struct Rows(Arc<Mutex<Vec<NeighborRow>>>);
#[async_trait]
impl NeighborSnapshotSource for Rows {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError> {
        Ok(self.0.lock().unwrap().clone())
    }
}
fn mac(high: u8, low: u8) -> LinkAddress {
    LinkAddress::try_from([2, 0, 0, 0, high, low]).unwrap()
}
fn row(interface: u32, high: u8, low: u8) -> NeighborRow {
    NeighborRow::new(
        InterfaceId::new(interface),
        IpAddr::V4(
            format!("192.168.{interface}.{}", low.max(1))
                .parse()
                .unwrap(),
        ),
        mac(high, low),
        NeighborReachability::Reachable,
    )
    .unwrap()
}
fn t(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap()
}
async fn open(
    repo: &M2StateRepository,
    interfaces: &[u32],
    rows: Rows,
) -> NeighborCoordinator<Rows> {
    let bindings: Vec<_> = interfaces
        .iter()
        .map(|i| NeighborInterfaceBinding::for_interface(InterfaceId::new(*i)).unwrap())
        .collect();
    let pipeline = PersistentDiscoveryPipeline::open(
        repo.clone(),
        neighbor_discovery_sources(&bindings).unwrap(),
        std::iter::repeat_with(lattice_domain::DeviceId::new),
        Default::default(),
        16,
        16,
    )
    .await
    .expect("opening must succeed whatever interface set wrote the checkpoint");
    let state = AppState::new(TOKEN, repo.clone()).unwrap();
    let cfg = NeighborCoordinatorConfig {
        poll_interval: Duration::seconds(5),
        support_ttl: Duration::seconds(4),
        tracker: NeighborTrackerConfig::default(),
    };
    NeighborCoordinator::new(rows, pipeline, state, bindings, cfg).unwrap()
}

#[tokio::test]
async fn removing_and_adding_interfaces_keeps_identities_and_discovery_running() {
    let repo = M2StateRepository::new(connect_memory().await.unwrap());
    let both = Rows(Arc::new(Mutex::new(vec![row(7, 0, 1), row(8, 0, 2)])));
    let mut first = open(&repo, &[7, 8], both.clone()).await;
    for cycle in 0..4 {
        first.cycle(t(cycle * 5)).await.unwrap();
    }
    let id7 = repo
        .lookup_link_layer_device(mac(0, 1), "neighbor-interface-7")
        .await
        .unwrap()
        .unwrap();
    let id8 = repo
        .lookup_link_layer_device(mac(0, 2), "neighbor-interface-8")
        .await
        .unwrap()
        .unwrap();
    drop(first);

    // Restart with interface 8 gone: previously the fingerprint mismatch failed open().
    let only7 = Rows(Arc::new(Mutex::new(vec![row(7, 0, 1)])));
    let mut second = open(&repo, &[7], only7.clone()).await;
    for cycle in 0..4 {
        second.cycle(t(1000 + cycle * 5)).await.unwrap();
    }
    assert_eq!(
        repo.lookup_link_layer_device(mac(0, 1), "neighbor-interface-7")
            .await
            .unwrap(),
        Some(id7),
        "the surviving interface keeps its device identity"
    );
    assert_eq!(
        second.pipeline().presence_state(id7),
        Some(PresenceState::Online)
    );
    assert_ne!(
        second.pipeline().presence_state(id8),
        Some(PresenceState::Online),
        "a device seen only through the removed interface must not stay Online"
    );
    let backups: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM state_checkpoint_backups")
        .fetch_one(repo.pool())
        .await
        .unwrap();
    assert_eq!(backups, 1, "the old checkpoint is kept, never discarded");
    drop(second);

    // And back to both interfaces: the identities are still there.
    let mut third = open(&repo, &[7, 8], both).await;
    for cycle in 0..4 {
        third.cycle(t(2000 + cycle * 5)).await.unwrap();
    }
    assert_eq!(
        repo.lookup_link_layer_device(mac(0, 2), "neighbor-interface-8")
            .await
            .unwrap(),
        Some(id8)
    );
    assert_eq!(
        third.pipeline().presence_state(id8),
        Some(PresenceState::Online)
    );
}

#[tokio::test]
async fn a_neighbor_flood_creates_a_bounded_number_of_identities() {
    let repo = M2StateRepository::new(connect_memory().await.unwrap());
    let flood: Vec<NeighborRow> = (0..400u16)
        .map(|n| {
            NeighborRow::new(
                InterfaceId::new(7),
                IpAddr::V4(
                    format!("10.7.{}.{}", n >> 8, (n & 0xff) as u8)
                        .parse()
                        .unwrap(),
                ),
                mac((n >> 8) as u8, (n & 0xff) as u8),
                NeighborReachability::Reachable,
            )
            .unwrap()
        })
        .collect();
    let rows = Rows(Arc::new(Mutex::new(flood)));
    let mut coordinator = open(&repo, &[7], rows).await;
    coordinator.cycle(t(0)).await.unwrap();
    let devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices")
        .fetch_one(repo.pool())
        .await
        .unwrap();
    assert!(
        devices <= 256,
        "identities per window are capped, got {devices}"
    );
    assert!(devices > 0);
}
