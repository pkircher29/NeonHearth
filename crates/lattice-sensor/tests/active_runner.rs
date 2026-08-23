use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use lattice_sensor::{
    Address, Interface, InterfaceClass, InterfaceId, InterfaceInventory, InterfaceOverride,
    TargetApproval, TargetGuard,
    active::{
        ActiveEngine, ActiveError, AttemptTransport, BudgetConfig, ExecutionCredentialSource,
        FakeClock, ProbeCredential, ProbeMode, ProbeRequest, SchedulerConfig, SchedulerRunner,
        TransportResponse, catalog,
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
            addresses: vec![
                Address {
                    ip: "192.168.50.2".parse().unwrap(),
                    prefix: 24,
                },
                Address {
                    ip: "192.168.51.2".parse().unwrap(),
                    prefix: 24,
                },
            ],
            owner_role: None,
        }]),
        [(id, InterfaceOverride::Default)],
        [
            TargetApproval {
                interface: id,
                prefix: Address {
                    ip: "192.168.50.0".parse().unwrap(),
                    prefix: 24,
                },
            },
            TargetApproval {
                interface: id,
                prefix: Address {
                    ip: "192.168.51.0".parse().unwrap(),
                    prefix: 24,
                },
            },
        ],
    )
    .unwrap()
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

#[derive(Default)]
struct ScriptedTransport {
    responses: Mutex<VecDeque<Result<TransportResponse, ActiveError>>>,
    sends: Mutex<Vec<(IpAddr, String)>>,
}
#[async_trait]
impl AttemptTransport for ScriptedTransport {
    async fn attempt(
        &self,
        guard: &TargetGuard,
        request: &ProbeRequest,
        descriptor: &lattice_sensor::active::ProbeDescriptor,
        _: Option<&ProbeCredential>,
    ) -> Result<TransportResponse, ActiveError> {
        guard
            .authorize(request.interface, request.target)
            .map_err(|_| ActiveError::Unauthorized)?;
        self.sends
            .lock()
            .unwrap()
            .push((request.target, descriptor.id.clone()));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(TransportResponse::Refused))
    }
}

fn runner(
    config: SchedulerConfig,
    transport: Arc<ScriptedTransport>,
) -> (
    Arc<SchedulerRunner<FakeClock, ScriptedTransport>>,
    tokio::sync::mpsc::Receiver<lattice_sensor::active::RunnerEvent>,
    Arc<FakeClock>,
) {
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let probes = catalog().unwrap();
    let engine = Arc::new(ActiveEngine::new(
        Arc::new(guard()),
        transport,
        probes.clone(),
    ));
    let (runner, results) =
        SchedulerRunner::new(config, clock.clone(), engine, probes, 16).unwrap();
    (runner, results, clock)
}

#[tokio::test]
async fn runner_dispatches_real_engine_work_and_publishes_bounded_results() {
    let transport = Arc::new(ScriptedTransport::default());
    let (runner, mut results, _) = runner(SchedulerConfig::default(), transport.clone());
    runner
        .enqueue(request("192.168.50.9", "tcp.http.80"))
        .unwrap();
    assert_eq!(runner.dispatch_ready().await, 1);
    let event = results.recv().await.unwrap();
    assert!(event.result.is_ok());
    assert_eq!(transport.sends.lock().unwrap().len(), 1);
    runner.stop_and_drain().await;
}

#[tokio::test]
async fn retry_uses_fake_monotonic_time_jitter_and_resets_after_terminal_result() {
    let transport = Arc::new(ScriptedTransport::default());
    transport.responses.lock().unwrap().extend([
        Ok(TransportResponse::Timeout),
        Ok(TransportResponse::Refused),
    ]);
    let config = SchedulerConfig {
        base_backoff: Duration::from_secs(5),
        max_backoff: Duration::from_secs(20),
        jitter_percent: 10,
        ..SchedulerConfig::default()
    };
    let (runner, mut results, clock) = runner(config, transport.clone());
    clock.set_jitter_unit(u32::MAX);
    runner
        .enqueue(request("192.168.50.9", "tcp.http.80"))
        .unwrap();
    runner.dispatch_ready().await;
    let first = results.recv().await.unwrap();
    assert!(first.will_retry);
    assert_eq!(runner.dispatch_ready().await, 0);
    clock.advance(Duration::from_secs(5));
    assert_eq!(runner.dispatch_ready().await, 0);
    clock.advance(Duration::from_millis(300));
    assert_eq!(runner.dispatch_ready().await, 1);
    let second = results.recv().await.unwrap();
    assert_eq!(second.attempt, 1);
    assert!(!second.will_retry);
    assert_eq!(transport.sends.lock().unwrap().len(), 2);
    runner.stop_and_drain().await;
}

#[tokio::test]
async fn retry_attempts_and_exponent_are_bounded_without_a_storm() {
    let transport = Arc::new(ScriptedTransport::default());
    transport
        .responses
        .lock()
        .unwrap()
        .extend((0..3).map(|_| Ok(TransportResponse::Timeout)));
    let config = SchedulerConfig {
        base_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(2),
        jitter_percent: 0,
        max_retry_attempts: 2,
        ..SchedulerConfig::default()
    };
    let (runner, mut results, clock) = runner(config, transport.clone());
    runner
        .enqueue(request("192.168.50.9", "tcp.http.80"))
        .unwrap();
    for (attempt, advance) in [(0, 1), (1, 2), (2, 0)] {
        assert_eq!(runner.dispatch_ready().await, 1);
        let event = results.recv().await.unwrap();
        assert_eq!(event.attempt, attempt);
        assert_eq!(event.will_retry, attempt < 2);
        clock.advance(Duration::from_secs(advance));
    }
    assert_eq!(runner.dispatch_ready().await, 0);
    assert_eq!(transport.sends.lock().unwrap().len(), 3);
    runner.stop_and_drain().await;
}

#[tokio::test]
async fn descriptor_cost_consumes_the_exact_subnet_budget() {
    let transport = Arc::new(ScriptedTransport::default());
    let config = SchedulerConfig {
        budgets: BudgetConfig::new(8, 2, 16, 4, Duration::from_secs(60)).unwrap(),
        ..SchedulerConfig::default()
    };
    struct Credentials;
    impl ExecutionCredentialSource for Credentials {
        fn credential_for(&self, request: &ProbeRequest) -> Option<ProbeCredential> {
            (request.probe_id == "udp.snmp.161").then(|| ProbeCredential::SnmpV2c {
                community: "execution-only".into(),
            })
        }
    }
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let probes = catalog().unwrap();
    let engine = Arc::new(ActiveEngine::new(
        Arc::new(guard()),
        transport.clone(),
        probes.clone(),
    ));
    let (runner, mut results) = SchedulerRunner::new_with_credentials(
        config,
        clock,
        engine,
        probes,
        16,
        Arc::new(Credentials),
    )
    .unwrap();
    let mut snmp = request("192.168.50.9", "udp.snmp.161");
    snmp.mode = ProbeMode::OwnerInventory;
    runner.enqueue(snmp).unwrap();
    runner
        .enqueue(request("192.168.50.10", "tcp.http.80"))
        .unwrap();
    assert_eq!(runner.dispatch_ready().await, 1);
    let _ = results.recv().await.unwrap();
    assert_eq!(transport.sends.lock().unwrap().len(), 1);
    assert_eq!(runner.dispatch_ready().await, 0);
    runner.stop_and_drain().await;
}

struct BlockingTransport;
#[async_trait]
impl AttemptTransport for BlockingTransport {
    async fn attempt(
        &self,
        _: &TargetGuard,
        _: &ProbeRequest,
        _: &lattice_sensor::active::ProbeDescriptor,
        _: Option<&ProbeCredential>,
    ) -> Result<TransportResponse, ActiveError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn stop_cancels_inflight_drains_queue_and_reports_cancellation_without_retry() {
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let probes = catalog().unwrap();
    let engine = Arc::new(ActiveEngine::new(
        Arc::new(guard()),
        Arc::new(BlockingTransport),
        probes.clone(),
    ));
    let (runner, mut results) =
        SchedulerRunner::new(SchedulerConfig::default(), clock, engine, probes, 4).unwrap();
    runner
        .enqueue(request("192.168.50.9", "tcp.http.80"))
        .unwrap();
    runner
        .enqueue(request("192.168.50.10", "tcp.http.80"))
        .unwrap();
    runner.dispatch_ready().await;
    runner.stop_and_drain().await;
    while let Ok(event) = results.try_recv() {
        assert_eq!(event.result.unwrap_err(), ActiveError::Cancelled);
        assert!(!event.will_retry);
    }
    assert!(matches!(
        runner.enqueue(request("192.168.50.11", "tcp.http.80")),
        Err(ActiveError::Cancelled)
    ));
}

struct PanicOnceTransport(AtomicBool);
#[async_trait]
impl AttemptTransport for PanicOnceTransport {
    async fn attempt(
        &self,
        _: &TargetGuard,
        _: &ProbeRequest,
        _: &lattice_sensor::active::ProbeDescriptor,
        _: Option<&ProbeCredential>,
    ) -> Result<TransportResponse, ActiveError> {
        if !self.0.swap(true, Ordering::AcqRel) {
            panic!("injected transport panic")
        }
        Ok(TransportResponse::Refused)
    }
}

#[tokio::test]
async fn panic_releases_raii_budget_and_is_observable_without_retry() {
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let probes = catalog().unwrap();
    let engine = Arc::new(ActiveEngine::new(
        Arc::new(guard()),
        Arc::new(PanicOnceTransport(AtomicBool::new(false))),
        probes.clone(),
    ));
    let config = SchedulerConfig {
        budgets: BudgetConfig::new(1, 1, 8, 8, Duration::from_secs(1)).unwrap(),
        ..SchedulerConfig::default()
    };
    let (runner, mut results) = SchedulerRunner::new(config, clock, engine, probes, 4).unwrap();
    runner
        .enqueue(request("192.168.50.9", "tcp.http.80"))
        .unwrap();
    runner.dispatch_ready().await;
    let event = results.recv().await.unwrap();
    assert_eq!(event.result.unwrap_err(), ActiveError::Internal);
    assert!(!event.will_retry);
    runner
        .enqueue(request("192.168.50.10", "tcp.http.80"))
        .unwrap();
    assert_eq!(runner.dispatch_ready().await, 1);
    assert!(results.recv().await.unwrap().result.is_ok());
    runner.stop_and_drain().await;
}

#[tokio::test]
async fn actual_dispatch_prioritizes_discovery_and_coalesces_inflight_duplicates() {
    struct InventoryCredentials;
    impl ExecutionCredentialSource for InventoryCredentials {
        fn credential_for(&self, request: &ProbeRequest) -> Option<ProbeCredential> {
            (request.mode == ProbeMode::OwnerInventory).then(|| ProbeCredential::SnmpV2c {
                community: "execution-only".into(),
            })
        }
    }
    let transport = Arc::new(ScriptedTransport::default());
    let config = SchedulerConfig {
        budgets: BudgetConfig::new(1, 1, 8, 8, Duration::from_secs(1)).unwrap(),
        ..SchedulerConfig::default()
    };
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let probes = catalog().unwrap();
    let engine = Arc::new(ActiveEngine::new(
        Arc::new(guard()),
        transport.clone(),
        probes.clone(),
    ));
    let (runner, mut results) = SchedulerRunner::new_with_credentials(
        config,
        clock,
        engine,
        probes,
        8,
        Arc::new(InventoryCredentials),
    )
    .unwrap();
    let mut low = request("192.168.50.11", "full.tcp.80");
    low.mode = ProbeMode::OwnerFullPort;
    runner.enqueue(low).unwrap();
    let mut inventory = request("192.168.50.9", "udp.snmp.161");
    inventory.mode = ProbeMode::OwnerInventory;
    runner.enqueue(inventory).unwrap();
    let high = request("192.168.50.10", "tcp.http.80");
    runner.enqueue(high.clone()).unwrap();
    assert!(!runner.enqueue(high).unwrap());
    assert_eq!(runner.dispatch_ready().await, 1);
    let first = results.recv().await.unwrap();
    assert_eq!(first.request.mode, ProbeMode::OwnerInventory);
    assert!(first.result.is_ok());
    assert_eq!(runner.dispatch_ready().await, 1);
    let second = results.recv().await.unwrap();
    assert_eq!(second.request.mode, ProbeMode::Default);
    assert!(second.result.is_ok());
    assert_eq!(runner.dispatch_ready().await, 1);
    let low_event = results.recv().await.unwrap();
    assert_eq!(low_event.request.mode, ProbeMode::OwnerFullPort);
    assert!(low_event.result.is_ok());
    runner.stop_and_drain().await;
}

#[tokio::test]
async fn actual_dispatch_round_robins_hosts_before_revisiting_a_noisy_host() {
    let transport = Arc::new(ScriptedTransport::default());
    let config = SchedulerConfig {
        budgets: BudgetConfig::new(2, 1, 16, 16, Duration::from_secs(1)).unwrap(),
        ..SchedulerConfig::default()
    };
    let (runner, mut results, _) = runner(config, transport);
    runner
        .enqueue(request("192.168.50.9", "tcp.http.80"))
        .unwrap();
    runner
        .enqueue(request("192.168.50.9", "tcp.ssh.22"))
        .unwrap();
    runner
        .enqueue(request("192.168.50.10", "tcp.http.80"))
        .unwrap();
    assert_eq!(runner.dispatch_ready().await, 2);
    let mut hosts = vec![
        results.recv().await.unwrap().request.target,
        results.recv().await.unwrap().request.target,
    ];
    hosts.sort();
    assert_eq!(
        hosts,
        vec![
            "192.168.50.9".parse::<IpAddr>().unwrap(),
            "192.168.50.10".parse::<IpAddr>().unwrap()
        ]
    );
    runner.stop_and_drain().await;
}

#[tokio::test]
async fn rate_denied_host_does_not_block_an_eligible_host_on_another_subnet() {
    let transport = Arc::new(ScriptedTransport::default());
    let config = SchedulerConfig {
        budgets: BudgetConfig::new(2, 1, 32, 32, Duration::from_secs(60)).unwrap(),
        ..SchedulerConfig::default()
    };
    let (runner, mut results, _) = runner(config, transport);
    for probe in ["tcp.http.80", "tcp.ssh.22"] {
        runner.enqueue(request("192.168.50.9", probe)).unwrap();
        assert_eq!(runner.dispatch_ready().await, 1);
        results.recv().await.unwrap();
    }
    runner
        .enqueue(request("192.168.50.9", "tcp.ftp.21"))
        .unwrap();
    runner
        .enqueue(request("192.168.51.9", "tcp.http.80"))
        .unwrap();

    assert_eq!(runner.dispatch_ready().await, 1);
    assert_eq!(
        results.recv().await.unwrap().request.target,
        "192.168.51.9".parse::<IpAddr>().unwrap()
    );
    runner.stop_and_drain().await;
}

#[tokio::test]
async fn result_backpressure_never_admits_work_without_a_guaranteed_event_slot() {
    let transport = Arc::new(ScriptedTransport::default());
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let probes = catalog().unwrap();
    let engine = Arc::new(ActiveEngine::new(
        Arc::new(guard()),
        transport,
        probes.clone(),
    ));
    let (runner, mut results) =
        SchedulerRunner::new(SchedulerConfig::default(), clock, engine, probes, 1).unwrap();
    runner
        .enqueue(request("192.168.50.9", "tcp.http.80"))
        .unwrap();
    runner
        .enqueue(request("192.168.50.10", "tcp.http.80"))
        .unwrap();

    assert_eq!(runner.dispatch_ready().await, 1);
    tokio::time::timeout(Duration::from_secs(1), runner.stop_and_drain())
        .await
        .expect("stop cannot depend on the consumer draining results");
    assert!(results.recv().await.is_some());
    assert!(results.try_recv().is_err());
}

#[tokio::test]
async fn closed_result_receiver_stops_without_spinning_or_consuming_budget() {
    let transport = Arc::new(ScriptedTransport::default());
    let (runner, results, _) = runner(SchedulerConfig::default(), transport.clone());
    drop(results);
    runner
        .enqueue(request("192.168.50.9", "tcp.http.80"))
        .unwrap();
    assert_eq!(runner.dispatch_ready().await, 0);
    assert!(transport.sends.lock().unwrap().is_empty());
    assert!(matches!(
        runner.enqueue(request("192.168.50.10", "tcp.http.80")),
        Err(ActiveError::Cancelled)
    ));
}

struct PanicCredentials;
impl ExecutionCredentialSource for PanicCredentials {
    fn credential_for(&self, _: &ProbeRequest) -> Option<ProbeCredential> {
        panic!("injected credential provider panic")
    }
}

#[tokio::test]
async fn credential_provider_panic_is_terminal_observable_and_releases_pending_state() {
    let transport = Arc::new(ScriptedTransport::default());
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let probes = catalog().unwrap();
    let engine = Arc::new(ActiveEngine::new(
        Arc::new(guard()),
        transport.clone(),
        probes.clone(),
    ));
    let config = SchedulerConfig {
        budgets: BudgetConfig::new(1, 1, 8, 8, Duration::from_secs(1)).unwrap(),
        ..SchedulerConfig::default()
    };
    let (runner, mut results) = SchedulerRunner::new_with_credentials(
        config,
        clock.clone(),
        engine,
        probes,
        1,
        Arc::new(PanicCredentials),
    )
    .unwrap();
    let mut snmp = request("192.168.50.9", "udp.snmp.161");
    snmp.mode = ProbeMode::OwnerInventory;
    runner.enqueue(snmp.clone()).unwrap();
    assert_eq!(runner.dispatch_ready().await, 1);
    let event = results.recv().await.unwrap();
    assert_eq!(event.result.unwrap_err(), ActiveError::Internal);
    assert!(!event.will_retry);
    assert!(transport.sends.lock().unwrap().is_empty());

    assert!(runner.enqueue(snmp).unwrap());
    clock.advance(Duration::from_secs(4));
    assert_eq!(runner.dispatch_ready().await, 1);
    assert_eq!(
        results.recv().await.unwrap().result.unwrap_err(),
        ActiveError::Internal
    );
    runner.stop_and_drain().await;
}

struct BarrierCredentials {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}
impl ExecutionCredentialSource for BarrierCredentials {
    fn credential_for(&self, _: &ProbeRequest) -> Option<ProbeCredential> {
        self.entered.wait();
        self.release.wait();
        Some(ProbeCredential::SnmpV2c {
            community: "execution-only".into(),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_serializes_with_admission_and_awaits_every_registered_attempt() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let transport = Arc::new(ScriptedTransport::default());
    let clock = Arc::new(FakeClock::new(Utc.timestamp_opt(1_700_000_000, 0).unwrap()));
    let probes = catalog().unwrap();
    let engine = Arc::new(ActiveEngine::new(
        Arc::new(guard()),
        transport.clone(),
        probes.clone(),
    ));
    let (runner, mut results) = SchedulerRunner::new_with_credentials(
        SchedulerConfig::default(),
        clock,
        engine,
        probes,
        2,
        Arc::new(BarrierCredentials {
            entered: entered.clone(),
            release: release.clone(),
        }),
    )
    .unwrap();
    let mut snmp = request("192.168.50.9", "udp.snmp.161");
    snmp.mode = ProbeMode::OwnerInventory;
    runner.enqueue(snmp).unwrap();
    assert_eq!(runner.dispatch_ready().await, 1);
    entered.wait();

    let mut first_stop = tokio::spawn({
        let runner = runner.clone();
        async move { runner.stop_and_drain().await }
    });
    tokio::task::yield_now().await;
    let mut second_stop = tokio::spawn({
        let runner = runner.clone();
        async move { runner.stop_and_drain().await }
    });
    let late_dispatch = tokio::spawn({
        let runner = runner.clone();
        async move { runner.dispatch_ready().await }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), async {
            tokio::join!(&mut first_stop, &mut second_stop)
        })
        .await
        .is_err()
    );
    release.wait();
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::try_join!(first_stop, second_stop)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(late_dispatch.await.unwrap(), 0);
    let event = results.recv().await.unwrap();
    assert_eq!(event.result.unwrap_err(), ActiveError::Cancelled);
    assert!(!event.will_retry);
    assert!(transport.sends.lock().unwrap().is_empty());
    tokio::time::timeout(Duration::from_millis(20), runner.stop_and_drain())
        .await
        .expect("later stop remains idempotent");
}
