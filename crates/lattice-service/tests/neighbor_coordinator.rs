use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{EventPayload, PresenceState};
use lattice_event_bus::Resume;
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
use std::{collections::VecDeque, net::IpAddr, sync::Mutex};

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

struct QueuedSource(Mutex<VecDeque<Result<Vec<NeighborRow>, NeighborError>>>);
#[async_trait]
impl NeighborSnapshotSource for QueuedSource {
    async fn snapshot(&self) -> Result<Vec<NeighborRow>, NeighborError> {
        self.0.lock().unwrap().pop_front().unwrap_or(Ok(vec![]))
    }
}
fn mac(n: u8) -> LinkAddress {
    LinkAddress::try_from([2, 0, 0, 0, 0, n]).unwrap()
}
fn row(interface: u32, n: u8) -> NeighborRow {
    NeighborRow::new(
        InterfaceId::new(interface),
        IpAddr::V4(format!("192.168.{interface}.{n}").parse().unwrap()),
        mac(n),
        NeighborReachability::Reachable,
    )
    .unwrap()
}
fn ids() -> impl Iterator<Item = lattice_domain::DeviceId> {
    [
        "018f47a0-9b5c-7a22-8a33-112233445501",
        "018f47a0-9b5c-7a22-8a33-112233445502",
    ]
    .into_iter()
    .map(|id| lattice_domain::DeviceId::parse(id).unwrap())
}
async fn coordinator(
    queue: Vec<Result<Vec<NeighborRow>, NeighborError>>,
    bindings: Vec<NeighborInterfaceBinding>,
) -> (
    NeighborCoordinator<QueuedSource>,
    M2StateRepository,
    AppState,
) {
    let repo = M2StateRepository::new(connect_memory().await.unwrap());
    let pipeline = PersistentDiscoveryPipeline::open(
        repo.clone(),
        neighbor_discovery_sources(&bindings).unwrap(),
        ids(),
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
        NeighborCoordinator::new(
            QueuedSource(Mutex::new(queue.into())),
            pipeline,
            state.clone(),
            bindings,
            cfg,
        )
        .unwrap(),
        repo,
        state,
    )
}
fn binding(interface: u32, source_id: u64) -> NeighborInterfaceBinding {
    NeighborInterfaceBinding::new(InterfaceId::new(interface), source_id)
}

#[tokio::test]
async fn cycles_commit_before_presence_events_and_preserve_presence_lifecycle() {
    let (mut c, repo, state) = coordinator(
        vec![
            Ok(vec![row(7, 1)]),
            Ok(vec![row(7, 1)]),
            Ok(vec![]),
            Ok(vec![]),
            Ok(vec![row(7, 1)]),
        ],
        vec![binding(7, 11)],
    )
    .await;
    let t = Utc.timestamp_opt(1_700_000_000, 987_000_000).unwrap();
    let first = c.cycle(t).await.unwrap();
    assert_eq!(first.commit_sequence(), 1);
    assert!(
        matches!(state.events().resume_after(0).await, Resume::Events(ref xs) if xs.is_empty())
    );
    let second = c.cycle(t + Duration::seconds(5)).await.unwrap();
    assert_eq!(second.commit_sequence(), 2);
    let events = match state.events().resume_after(0).await {
        Resume::Events(xs) => xs,
        _ => panic!(),
    };
    assert!(
        matches!(events.as_slice(), [x] if matches!(x.payload, EventPayload::PresenceChanged(_)))
    );
    assert_eq!(
        events[0].occurred_at,
        Utc.timestamp_opt(1_700_000_005, 0).unwrap()
    );
    assert_eq!(repo.list_device_snapshots(8, None).await.unwrap().len(), 1);
    c.cycle(t + Duration::seconds(10)).await.unwrap();
    assert_eq!(c.commit_sequence(), 3);
    assert_eq!(
        repo.list_device_snapshots(8, None).await.unwrap()[0]
            .presence
            .as_ref()
            .unwrap()
            .to_state,
        PresenceState::Quiet
    );
    c.cycle(t + Duration::seconds(15)).await.unwrap();
    assert_eq!(c.commit_sequence(), 4);
    assert_eq!(
        repo.list_device_snapshots(8, None).await.unwrap()[0]
            .presence
            .as_ref()
            .unwrap()
            .to_state,
        PresenceState::Offline
    );
    let after_offline = match state.events().resume_after(0).await {
        Resume::Events(xs) => xs,
        _ => panic!(),
    };
    assert_eq!(
        after_offline
            .iter()
            .filter(|x| matches!(x.payload, EventPayload::PresenceChanged(_)))
            .count(),
        2
    );
    c.cycle(t + Duration::seconds(20)).await.unwrap();
    assert_eq!(repo.list_device_snapshots(8, None).await.unwrap().len(), 1);
    assert!(
        match state.events().resume_after(0).await {
            Resume::Events(xs) => xs,
            _ => panic!(),
        }
        .iter()
        .all(|x| !matches!(x.payload, EventPayload::BandwidthFrame(_)))
    );
}

#[tokio::test]
async fn failure_is_inert_sanitized_and_recovers_once() {
    let raw = "192.168.7.9 02:00:00:00:00:09 command output";
    let (mut c, _repo, state) = coordinator(
        vec![
            Ok(vec![row(7, 1)]),
            Err(NeighborError::Transport),
            Err(NeighborError::Transport),
            Ok(vec![row(7, 1)]),
        ],
        vec![binding(7, 11)],
    )
    .await;
    let t = Utc.timestamp_opt(1_700_000_000, 1).unwrap();
    c.cycle(t).await.unwrap();
    let before = c.commit_sequence();
    assert!(c.cycle(t + Duration::seconds(5)).await.is_err());
    assert_eq!(c.commit_sequence(), before);
    assert_eq!(state.service_status().await.as_str(), "degraded");
    assert!(c.cycle(t + Duration::seconds(10)).await.is_err());
    assert_eq!(c.commit_sequence(), before);
    c.cycle(t + Duration::seconds(15)).await.unwrap();
    assert_eq!(state.service_status().await.as_str(), "ready");
    let events = match state.events().resume_after(0).await {
        Resume::Events(xs) => xs,
        _ => panic!(),
    };
    let statuses: Vec<_> = events
        .into_iter()
        .filter_map(|x| {
            if let EventPayload::ServiceStatus(s) = x.payload {
                Some(s)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(statuses.len(), 2);
    let serialized = format!("{statuses:?}");
    assert!(
        !serialized.contains("192.168.7.9") && !serialized.contains("02:00:00:00:00:09"),
        "raw input must not escape: {raw}"
    );
}

#[tokio::test]
async fn bindings_are_stable_distinct_and_reject_invalid_configuration() {
    let a = binding(7, 11);
    let b = binding(8, 12);
    assert_eq!(a.safe_name(), "neighbor-interface-7");
    assert_ne!(a.safe_name(), b.safe_name());
    let sources = neighbor_discovery_sources(&[b, a]).unwrap();
    assert_eq!(
        sources.fingerprint(),
        neighbor_discovery_sources(&[a, b]).unwrap().fingerprint()
    );
    assert!(neighbor_discovery_sources(&[]).is_err());
    assert!(neighbor_discovery_sources(&[binding(0, 11)]).is_err());
    assert!(neighbor_discovery_sources(&[binding(7, 0)]).is_err());
    assert!(neighbor_discovery_sources(&[a, binding(7, 12)]).is_err());
    assert!(neighbor_discovery_sources(&[a, binding(8, 11)]).is_err());
    let source = QueuedSource(Mutex::new(VecDeque::new()));
    let repo = M2StateRepository::new(connect_memory().await.unwrap());
    let state = AppState::new(TOKEN, repo.clone()).unwrap();
    let pipeline = PersistentDiscoveryPipeline::open(
        repo,
        neighbor_discovery_sources(&[a]).unwrap(),
        ids(),
        Default::default(),
        16,
        16,
    )
    .await
    .unwrap();
    let invalid = NeighborCoordinatorConfig {
        poll_interval: Duration::seconds(5),
        support_ttl: Duration::seconds(5),
        tracker: NeighborTrackerConfig::default(),
    };
    assert!(NeighborCoordinator::new(source, pipeline, state, vec![a, a], invalid).is_err());
    let repo = M2StateRepository::new(connect_memory().await.unwrap());
    let state = AppState::new(TOKEN, repo.clone()).unwrap();
    let pipeline = PersistentDiscoveryPipeline::open(
        repo,
        neighbor_discovery_sources(&[a]).unwrap(),
        ids(),
        Default::default(),
        16,
        16,
    )
    .await
    .unwrap();
    let invalid_tracker = NeighborCoordinatorConfig {
        poll_interval: Duration::seconds(5),
        support_ttl: Duration::seconds(4),
        tracker: NeighborTrackerConfig {
            max_rows: 0,
            ..Default::default()
        },
    };
    assert!(
        NeighborCoordinator::new(
            QueuedSource(Mutex::new(VecDeque::new())),
            pipeline,
            state,
            vec![a],
            invalid_tracker
        )
        .is_err()
    );
}

#[tokio::test]
async fn unbound_rows_are_ignored_and_same_mac_isolated_per_interface() {
    let (mut c, repo, _state) = coordinator(
        vec![
            Ok(vec![row(7, 1), row(99, 2)]),
            Ok(vec![row(7, 1), row(8, 1)]),
        ],
        vec![binding(7, 11), binding(8, 12)],
    )
    .await;
    let t = Utc.timestamp_opt(1_700_000_000, 500_000_000).unwrap();
    c.cycle(t).await.unwrap();
    c.cycle(t + Duration::seconds(5)).await.unwrap();
    assert_eq!(repo.list_device_snapshots(8, None).await.unwrap().len(), 2);
}
