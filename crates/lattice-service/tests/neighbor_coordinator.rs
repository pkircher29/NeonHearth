use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use lattice_domain::EvidenceFamily;
use lattice_sensor::{
    InterfaceId,
    neighbor::{
        LinkAddress, NeighborError, NeighborReachability, NeighborRow, NeighborSnapshotSource,
        NeighborTrackerConfig,
    },
};
use lattice_service::discovery::{
    DiscoveryPipelineOutcome, DiscoverySource, DiscoverySources, NeighborCoordinator,
    NeighborCoordinatorConfig, PersistentDiscoveryPipeline,
};
use lattice_store::{M2StateRepository, connect_memory};
use std::net::IpAddr;
use std::sync::Mutex;

struct Source {
    result: Mutex<Option<Result<Vec<NeighborRow>, NeighborError>>>,
}
#[async_trait]
impl NeighborSnapshotSource for Source {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError> {
        self.result.lock().unwrap().take().unwrap_or(Ok(vec![]))
    }
}
fn mac(n: u8) -> LinkAddress {
    LinkAddress::try_from([2, 0, 0, 0, 0, n]).unwrap()
}
fn row(n: u8) -> NeighborRow {
    NeighborRow::new(
        InterfaceId::new(7),
        IpAddr::V4(format!("192.168.1.{n}").parse().unwrap()),
        mac(n),
        NeighborReachability::Reachable,
    )
    .unwrap()
}
fn id(n: u8) -> lattice_domain::DeviceId {
    lattice_domain::DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}

#[tokio::test]
async fn successful_polls_commit_and_publish_only_after_commit() {
    let pool = connect_memory().await.unwrap();
    let repo = M2StateRepository::new(pool.clone());
    let sources = DiscoverySources::new(vec![DiscoverySource {
        id: 11,
        name: "neighbor-7".into(),
        families: vec![EvidenceFamily::LinkLayer],
        presence: true,
    }])
    .unwrap();
    let pipeline = PersistentDiscoveryPipeline::open(
        repo,
        sources,
        [id(1), id(2)].into_iter(),
        Default::default(),
        16,
        16,
    )
    .await
    .unwrap();
    let source = Source {
        result: Mutex::new(Some(Ok(vec![row(1)]))),
    };
    let mut coordinator = NeighborCoordinator::new(
        source,
        [(InterfaceId::new(7), 11)].into_iter(),
        NeighborCoordinatorConfig::default(),
    )
    .unwrap();
    let mut published = Vec::new();
    let mut p = pipeline;
    let t = Utc.timestamp_opt(1_700_000_000, 987_000_000).unwrap();
    let outcomes = coordinator
        .poll_and_publish(&mut p, t, |event| {
            published.push(event);
        })
        .await
        .unwrap();
    assert!(matches!(
        outcomes.as_slice(),
        [DiscoveryPipelineOutcome::Committed(_)]
    ));
    assert_eq!(published.len(), 0, "first join has no presence event");
    assert_eq!(p.commit_sequence(), 1);
}

#[tokio::test]
async fn failed_snapshot_is_inert_and_config_is_bounded() {
    let source = Source {
        result: Mutex::new(Some(Err(NeighborError::Transport))),
    };
    let cfg = NeighborCoordinatorConfig {
        poll_interval: Duration::seconds(7),
        support_ttl: Duration::seconds(3),
        tracker: NeighborTrackerConfig::default(),
    };
    let mut c =
        NeighborCoordinator::new(source, [(InterfaceId::new(7), 11)].into_iter(), cfg.clone())
            .unwrap();
    assert_eq!(c.poll_interval(), Duration::seconds(7));
    assert_eq!(c.support_ttl(), Duration::seconds(3));
    let t = Utc.timestamp_opt(1_700_000_000, 999_000_000).unwrap();
    assert!(c.poll(t).await.is_none());
}
