use chrono::{Duration, TimeZone, Utc};
use lattice_domain::{EvidenceFamily, PresenceState};
use lattice_sensor::neighbor::LinkAddress;
use lattice_service::discovery::{
    DiscoveryError, DiscoveryPipelineOutcome, DiscoverySources, LinkPresenceKind,
    LinkPresenceObservation, PersistentDiscoveryPipeline,
};
use lattice_store::{M2StateRepository, connect_memory};

fn at(s: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(s, 0).single().unwrap()
}
fn link(n: u8) -> LinkAddress {
    LinkAddress::try_from([2, 0, 0, 0, 0, n]).unwrap()
}
fn id(n: u8) -> lattice_domain::DeviceId {
    lattice_domain::DeviceId::parse(&format!("018f47a0-9b5c-7a22-8a33-1122334455{n:02x}")).unwrap()
}
async fn pipeline() -> (
    sqlx::SqlitePool,
    M2StateRepository,
    PersistentDiscoveryPipeline,
) {
    let pool = connect_memory().await.unwrap();
    let repo = M2StateRepository::new(pool.clone());
    let sources =
        DiscoverySources::sensor(1, "synthetic", vec![EvidenceFamily::LinkLayer]).unwrap();
    let pipeline = PersistentDiscoveryPipeline::open(
        repo.clone(),
        sources,
        [id(1), id(2), id(3)].into_iter(),
        Default::default(),
        16,
        16,
    )
    .await
    .unwrap();
    (pool, repo, pipeline)
}
fn present(source_id: u64, mac: LinkAddress, t: chrono::DateTime<Utc>) -> LinkPresenceObservation {
    LinkPresenceObservation {
        source_id,
        link_address: mac,
        observed_at: t,
        kind: LinkPresenceKind::Present {
            valid_until: t + Duration::seconds(30),
        },
    }
}

#[tokio::test]
async fn present_allocates_then_reuses_exact_binding_without_new_evidence() {
    let (pool, _repo, mut p) = pipeline().await;
    let t = at(1_700_000_000);
    let first = p
        .observe_link_presence_with_flow(present(1, link(1), t), &[], 0, t)
        .await
        .unwrap();
    let device = match first {
        DiscoveryPipelineOutcome::Committed(x) => x.result.device_id,
        _ => panic!(),
    };
    assert_eq!(device, id(1));
    let second = p
        .observe_link_presence_with_flow(
            present(1, link(1), t + Duration::seconds(1)),
            &[],
            0,
            t + Duration::seconds(1),
        )
        .await
        .unwrap();
    assert!(matches!(second, DiscoveryPipelineOutcome::Committed(_)));
    assert_eq!(p.presence_state(device), Some(PresenceState::Quiet));
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM evidence WHERE family='link_layer' AND fact_key='mac'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn missed_before_binding_is_typed_and_inert_and_subseconds_are_rejected() {
    let (pool, _repo, mut p) = pipeline().await;
    let t = at(1_700_000_000);
    let err = p
        .observe_link_presence_with_flow(
            LinkPresenceObservation {
                source_id: 1,
                link_address: link(2),
                observed_at: t,
                kind: LinkPresenceKind::Missed,
            },
            &[],
            0,
            t,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DiscoveryError::UnboundLink));
    let err = p
        .observe_link_presence_with_flow(
            LinkPresenceObservation {
                source_id: 1,
                link_address: link(2),
                observed_at: t + Duration::milliseconds(1),
                kind: LinkPresenceKind::Missed,
            },
            &[],
            0,
            t,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DiscoveryError::InvalidSource));
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn debug_redacts_link_address() {
    let observation = present(1, link(7), at(1_700_000_000));
    let text = format!("{observation:?}");
    assert!(!text.contains("02:00:00:00:00:07"));
}
