use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use lattice_sensor::{
    Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory, InterfaceOverride,
    TargetApproval, TargetGuard,
    active::{
        ActiveEngine, ActiveError, AttemptTransport, BudgetConfig, CuratedPlan, FakeClock,
        ProbeCredential, ProbeMode, ProbeOutcome, ProbeRequest, Scheduler, SchedulerConfig,
        TransportResponse, catalog, owner_full_port_probe_ids, parse_http_metadata,
    },
};

fn guard() -> TargetGuard {
    let id = InterfaceId::new(7);
    TargetGuard::new(
        InterfaceInventory::new(vec![Interface {
            id,
            name: "test0".into(),
            description: None,
            up: true,
            class: InterfaceClass::PhysicalWired,
            addresses: vec![Address {
                ip: "192.168.50.2".parse().unwrap(),
                prefix: 24,
            }],
            owner_role: None,
        }]),
        [(id, InterfaceOverride::Default)],
        [TargetApproval {
            interface: id,
            prefix: Address {
                ip: "192.168.50.0".parse().unwrap(),
                prefix: 24,
            },
        }],
    )
    .unwrap()
}

#[derive(Default)]
struct FakeTransport {
    sends: Mutex<Vec<(InterfaceId, IpAddr, String)>>,
    responses: Mutex<VecDeque<Result<TransportResponse, ActiveError>>>,
}

struct BlockingTransport;
#[async_trait]
impl AttemptTransport for BlockingTransport {
    async fn attempt(
        &self,
        _guard: &TargetGuard,
        _request: &ProbeRequest,
        _descriptor: &lattice_sensor::active::ProbeDescriptor,
        _credential: Option<&ProbeCredential>,
    ) -> Result<TransportResponse, ActiveError> {
        std::future::pending().await
    }
}

#[async_trait]
impl AttemptTransport for FakeTransport {
    async fn attempt(
        &self,
        _guard: &TargetGuard,
        request: &ProbeRequest,
        descriptor: &lattice_sensor::active::ProbeDescriptor,
        _credential: Option<&ProbeCredential>,
    ) -> Result<TransportResponse, ActiveError> {
        self.sends
            .lock()
            .unwrap()
            .push((request.interface, request.target, descriptor.id.clone()));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(TransportResponse::Refused))
    }
}

fn request(target: &str, probe: &str) -> ProbeRequest {
    ProbeRequest {
        interface: InterfaceId::new(7),
        target: target.parse().unwrap(),
        probe_id: probe.into(),
        mode: ProbeMode::Default,
        owner_approved: true,
    }
}

#[test]
fn catalog_is_unique_deterministic_and_full_port_is_opt_in() {
    let catalog = catalog().unwrap();
    assert!(catalog.len() >= 35);
    let default = catalog.plan(CuratedPlan::Default);
    assert!(default.iter().any(|p| p.id == "tcp.http.80"));
    assert!(default.iter().any(|p| p.id == "udp.dns.53"));
    assert!(
        default
            .iter()
            .all(|p| !p.potential_side_effects.is_empty() && p.rate_cost > 0)
    );
    assert!(!default.iter().any(|p| p.id.starts_with("full.")));
    assert!(
        catalog
            .plan(CuratedPlan::OwnerFullPort)
            .iter()
            .all(|p| p.owner_start_required)
    );
    let ports: Vec<_> = owner_full_port_probe_ids().collect();
    assert_eq!(ports.len(), 65_535);
    assert_eq!(ports.first().unwrap(), "full.tcp.1");
    assert_eq!(ports.last().unwrap(), "full.tcp.65535");
}

#[tokio::test]
async fn authorization_happens_before_each_send_and_rejects_without_send() {
    let transport = Arc::new(FakeTransport::default());
    let engine = ActiveEngine::new(Arc::new(guard()), transport.clone(), catalog().unwrap());
    let outcome = engine
        .execute(request("192.168.50.9", "tcp.http.80"), None)
        .await
        .unwrap();
    assert!(matches!(outcome, ProbeOutcome::Refused { .. }));
    let error = engine
        .execute(request("8.8.8.8", "tcp.http.80"), None)
        .await
        .unwrap_err();
    assert!(matches!(error, ActiveError::Unauthorized));
    assert_eq!(transport.sends.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn credentials_are_required_borrowed_and_never_returned() {
    let transport = Arc::new(FakeTransport::default());
    let engine = ActiveEngine::new(Arc::new(guard()), transport, catalog().unwrap());
    let mut req = request("192.168.50.9", "udp.snmp.161");
    req.mode = ProbeMode::OwnerFullPort;
    assert!(matches!(
        engine.execute(req.clone(), None).await.unwrap_err(),
        ActiveError::CredentialRequired
    ));
    let secret = ProbeCredential::SnmpV2c {
        community: "private-community".into(),
    };
    let result = engine.execute(req, Some(&secret)).await.unwrap();
    assert!(!format!("{result:?}").contains("private-community"));
}

#[tokio::test]
async fn global_stop_cancels_in_flight_and_does_not_report_target_failure() {
    let engine = Arc::new(ActiveEngine::new(
        Arc::new(guard()),
        Arc::new(BlockingTransport),
        catalog().unwrap(),
    ));
    let running = tokio::spawn({
        let engine = engine.clone();
        async move {
            engine
                .execute(request("192.168.50.9", "tcp.http.80"), None)
                .await
        }
    });
    tokio::task::yield_now().await;
    engine.stop();
    assert_eq!(running.await.unwrap().unwrap_err(), ActiveError::Cancelled);
    assert_eq!(
        engine
            .execute(request("192.168.50.10", "tcp.http.80"), None)
            .await
            .unwrap_err(),
        ActiveError::Cancelled
    );
}

#[tokio::test]
async fn descriptor_timeout_is_a_typed_timeout_outcome() {
    let mut probes = catalog().unwrap();
    probes
        .override_timeout("tcp.http.80", Duration::from_millis(5))
        .unwrap();
    let engine = ActiveEngine::new(Arc::new(guard()), Arc::new(BlockingTransport), probes);
    assert!(matches!(
        engine
            .execute(request("192.168.50.9", "tcp.http.80"), None)
            .await
            .unwrap(),
        ProbeOutcome::Timeout { .. }
    ));
}

#[tokio::test]
async fn normalized_evidence_rejects_response_amplification() {
    let transport = Arc::new(FakeTransport::default());
    transport
        .responses
        .lock()
        .unwrap()
        .push_back(Ok(TransportResponse::Success(
            (0..33)
                .map(|index| (format!("k{index}"), "x".into()))
                .collect(),
        )));
    let engine = ActiveEngine::new(Arc::new(guard()), transport, catalog().unwrap());
    assert_eq!(
        engine
            .execute(request("192.168.50.9", "tcp.http.80"), None)
            .await
            .unwrap_err(),
        ActiveError::ResponseLimit
    );
}

#[test]
fn budgets_validate_backoff_jitter_and_reset() {
    assert!(BudgetConfig::new(0, 1, 1, Duration::from_secs(1)).is_err());
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let mut scheduler = Scheduler::new(SchedulerConfig::default(), clock).unwrap();
    let req = request("192.168.50.9", "tcp.http.80");
    assert_eq!(scheduler.retry_delay(&req, 0), Duration::from_secs(1));
    assert_eq!(scheduler.retry_delay(&req, 8), Duration::from_secs(60));
    scheduler.record_success(&req);
    assert_eq!(scheduler.retry_delay(&req, 0), Duration::from_secs(1));
    assert!(scheduler.jitter(Duration::from_secs(10)).as_millis() <= 1_000);
}

#[test]
fn queue_coalesces_duplicates_prioritizes_discovery_and_is_fair() {
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let mut scheduler = Scheduler::new(SchedulerConfig::default(), clock).unwrap();
    let mut full = request("192.168.50.9", "tcp.http.80");
    full.mode = ProbeMode::OwnerFullPort;
    scheduler.enqueue(full.clone()).unwrap();
    assert!(!scheduler.enqueue(full).unwrap());
    scheduler
        .enqueue(request("192.168.50.10", "tcp.ssh.22"))
        .unwrap();
    scheduler
        .enqueue(request("192.168.50.11", "tcp.ssh.22"))
        .unwrap();
    assert_eq!(
        scheduler.next_request().unwrap().target,
        "192.168.50.10".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        scheduler.next_request().unwrap().target,
        "192.168.50.11".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        scheduler.next_request().unwrap().mode,
        ProbeMode::OwnerFullPort
    );
}

#[test]
fn stop_clears_queue_and_prevents_new_work() {
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let mut scheduler = Scheduler::new(SchedulerConfig::default(), clock).unwrap();
    scheduler
        .enqueue(request("192.168.50.9", "tcp.http.80"))
        .unwrap();
    scheduler.stop();
    assert!(scheduler.next_request().is_none());
    assert!(matches!(
        scheduler.enqueue(request("192.168.50.10", "tcp.http.80")),
        Err(ActiveError::Cancelled)
    ));
}

#[test]
fn concurrency_and_rate_budgets_enforce_exact_ceiling_and_refill() {
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let config = SchedulerConfig {
        budgets: BudgetConfig::new(2, 1, 2, Duration::from_secs(10)).unwrap(),
        ..SchedulerConfig::default()
    };
    let mut scheduler = Scheduler::new(config, clock.clone()).unwrap();
    let a = request("192.168.50.9", "tcp.http.80");
    let b = request("192.168.50.10", "tcp.http.80");
    let c = request("192.168.50.11", "tcp.http.80");
    assert!(scheduler.try_start(&a));
    assert!(!scheduler.try_start(&a));
    assert!(scheduler.try_start(&b));
    assert!(!scheduler.try_start(&c));
    scheduler.finish(&a);
    scheduler.finish(&b);
    assert!(!scheduler.try_start(&c));
    clock.advance(Duration::from_secs(10));
    assert!(scheduler.try_start(&c));
}

#[test]
fn scheduler_state_is_bounded_and_ttl_evicted() {
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let config = SchedulerConfig {
        state_capacity: 2,
        state_ttl: Duration::from_secs(5),
        budgets: BudgetConfig::new(8, 2, 16, Duration::from_secs(1)).unwrap(),
        ..SchedulerConfig::default()
    };
    let mut scheduler = Scheduler::new(config, clock.clone()).unwrap();
    for host in ["192.168.50.9", "192.168.50.10"] {
        let req = request(host, "tcp.http.80");
        assert!(scheduler.try_start(&req));
        scheduler.finish(&req);
        scheduler.retry_delay(&req, 0);
    }
    assert_eq!(scheduler.state_sizes().0, 2);
    let third = request("192.168.50.11", "tcp.http.80");
    assert!(!scheduler.try_start(&third));
    clock.advance(Duration::from_secs(6));
    assert!(scheduler.try_start(&third));
    assert!(scheduler.state_sizes().0 <= 2);
}

#[test]
fn http_metadata_is_bounded_and_redirect_locations_are_not_exposed() {
    let response = b"HTTP/1.1 302 Found\r\nServer: camera/1.0\r\nContent-Type: text/html\r\nLocation: http://8.8.8.8/\r\n\r\nsecret-body";
    let facts = parse_http_metadata(response).unwrap();
    assert_eq!(
        facts,
        vec![
            ("status".into(), "302".into()),
            ("server".into(), "camera/1.0".into()),
            ("content_type".into(), "text/html".into())
        ]
    );
    assert!(!format!("{facts:?}").contains("8.8.8.8"));
    assert!(!format!("{facts:?}").contains("secret-body"));
}
