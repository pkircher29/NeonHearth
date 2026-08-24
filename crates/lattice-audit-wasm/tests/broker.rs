use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use lattice_audit_wasm::*;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
fn target() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 44))
}
fn module() -> Vec<u8> {
    wat::parse_str(r#"(module (import "audit" "exchange" (func $x (param i32 i32 i32 i32) (result i32))) (memory (export "memory") 1) (data (i32.const 16) "ping") (func (export "run") (param i32 i32) (result i64) i32.const 16 i32.const 4 i32.const 32 i32.const 4 call $x drop i64.const 32 i64.const 32 i64.shl i64.const 4 i64.or))"#).unwrap()
}
fn limits() -> Limits {
    Limits {
        max_bytes: 32,
        max_requests: 2,
        max_time: Duration::from_secs(1),
        max_fuel: 100_000,
        max_memory_pages: 1,
    }
}
fn verified(port: u16, limits: Limits) -> VerifiedManifest {
    let w = module();
    let mut m = AuditManifest::new(
        "broker-test".into(),
        1,
        Sha256::digest(&w).into(),
        TargetKind::NumericPrivateDevice,
        BTreeSet::from([Capability::TcpExchange { port }]),
        "test".into(),
        SideEffectProfile::ReadOnly,
        RollbackPlan {
            required: false,
            description: "none".into(),
        },
        EvidenceSchema {
            fields: BTreeMap::from([("out".into(), EvidenceType::Bytes)]),
        },
        limits,
    )
    .unwrap();
    let k = SigningKey::from_bytes(&[9; 32]);
    m.sign(&k).unwrap();
    verify_manifest(&m, &w, &k.verifying_key()).unwrap()
}
struct Auth(AtomicUsize);
impl TargetAuthorizer for Auth {
    fn authorize(&self, t: IpAddr, i: u32, p: u16) -> Result<AuthorizedTarget, TargetError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        AuthorizedTarget::new(t, i, p)
    }
}
struct Exchange;
#[async_trait]
impl TargetBoundExchange for Exchange {
    async fn exchange(
        &self,
        authorized: &AuthorizedTarget,
        request: ExchangeRequest,
    ) -> Result<ExchangeResponse, BrokerError> {
        assert_eq!(authorized.target(), target());
        assert_eq!(request.payload, b"ping");
        assert_eq!(request.protocol, ExchangeProtocol::Tcp);
        assert_eq!(request.response_limit, 4);
        ExchangeResponse::try_new(b"pong".to_vec(), request.response_limit)
    }
}
fn request(port: u16) -> BrokerRequest {
    BrokerRequest {
        module: verified(port, limits()),
        input: vec![],
        target: target(),
        interface: 7,
        port,
        capability: Capability::TcpExchange { port },
        approval_id: Uuid::new_v4(),
        limits: limits(),
        cancellation: CancellationToken::new(),
    }
}
#[tokio::test]
async fn broker_composes_signed_module_and_fixed_target_exchange() {
    let auth = Arc::new(Auth(AtomicUsize::new(0)));
    let broker = Broker::new(auth.clone(), Arc::new(Exchange));
    let result = broker.execute(request(80)).await.unwrap();
    assert_eq!(result.target, target());
    assert_eq!(result.bytes, b"pong");
    assert_eq!(auth.0.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn broker_rejects_capability_port_mismatch_before_exchange() {
    let broker = Broker::new(Arc::new(Auth(AtomicUsize::new(0))), Arc::new(Exchange));
    let mut r = request(80);
    r.capability = Capability::TcpExchange { port: 81 };
    assert!(matches!(
        broker.execute(r).await,
        Err(BrokerError::CapabilityDenied)
    ));
}
#[tokio::test]
async fn broker_rejects_nil_approval() {
    let broker = Broker::new(Arc::new(Auth(AtomicUsize::new(0))), Arc::new(Exchange));
    let mut r = request(80);
    r.approval_id = Uuid::nil();
    assert!(matches!(
        broker.execute(r).await,
        Err(BrokerError::MissingApproval)
    ));
}

struct ScriptedAuth {
    calls: AtomicUsize,
    second: Mutex<Option<Result<AuthorizedTarget, TargetError>>>,
}
impl TargetAuthorizer for ScriptedAuth {
    fn authorize(&self, t: IpAddr, i: u32, p: u16) -> Result<AuthorizedTarget, TargetError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 1 {
            self.second.lock().unwrap().take().unwrap()
        } else {
            AuthorizedTarget::new(t, i, p)
        }
    }
}
struct CountExchange(AtomicUsize);
#[async_trait]
impl TargetBoundExchange for CountExchange {
    async fn exchange(
        &self,
        _: &AuthorizedTarget,
        request: ExchangeRequest,
    ) -> Result<ExchangeResponse, BrokerError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        ExchangeResponse::try_new(b"pong".to_vec(), request.response_limit)
    }
}

#[tokio::test]
async fn rejected_or_changed_immediate_reauthorization_never_reaches_exchange() {
    for second in [
        Err(TargetError::Rejected),
        AuthorizedTarget::new(target(), 8, 80),
    ] {
        let auth = Arc::new(ScriptedAuth {
            calls: AtomicUsize::new(0),
            second: Mutex::new(Some(second)),
        });
        let exchange = Arc::new(CountExchange(AtomicUsize::new(0)));
        let result = Broker::new(auth.clone(), exchange.clone())
            .execute(request(80))
            .await;
        assert!(matches!(
            result,
            Err(BrokerError::Target(TargetError::Rejected))
        ));
        assert_eq!(auth.calls.load(Ordering::SeqCst), 2);
        assert_eq!(exchange.0.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn all_protocols_are_propagated_and_invalid_capability_is_rejected_before_authorization() {
    struct ProtocolExchange(Mutex<Vec<ExchangeProtocol>>);
    #[async_trait]
    impl TargetBoundExchange for ProtocolExchange {
        async fn exchange(
            &self,
            _: &AuthorizedTarget,
            request: ExchangeRequest,
        ) -> Result<ExchangeResponse, BrokerError> {
            self.0.lock().unwrap().push(request.protocol);
            ExchangeResponse::try_new(b"pong".to_vec(), request.response_limit)
        }
    }
    for capability in [
        Capability::TcpExchange { port: 80 },
        Capability::HttpExchange { port: 80 },
        Capability::TlsMetadata { port: 80 },
    ] {
        let exchange = Arc::new(ProtocolExchange(Mutex::new(vec![])));
        let mut r = request(80);
        r.module = {
            let w = module();
            let mut m = AuditManifest::new(
                "protocol".into(),
                1,
                Sha256::digest(&w).into(),
                TargetKind::NumericPrivateDevice,
                BTreeSet::from([capability.clone()]),
                "test".into(),
                SideEffectProfile::ReadOnly,
                RollbackPlan {
                    required: false,
                    description: "none".into(),
                },
                EvidenceSchema {
                    fields: BTreeMap::from([("out".into(), EvidenceType::Bytes)]),
                },
                limits(),
            )
            .unwrap();
            let k = SigningKey::from_bytes(&[9; 32]);
            m.sign(&k).unwrap();
            verify_manifest(&m, &w, &k.verifying_key()).unwrap()
        };
        r.capability = capability.clone();
        Broker::new(Arc::new(Auth(AtomicUsize::new(0))), exchange.clone())
            .execute(r)
            .await
            .unwrap();
        assert_eq!(
            exchange.0.lock().unwrap().as_slice(),
            &[match capability {
                Capability::TcpExchange { .. } => ExchangeProtocol::Tcp,
                Capability::HttpExchange { .. } => ExchangeProtocol::Http,
                Capability::TlsMetadata { .. } => ExchangeProtocol::TlsMetadata,
            }]
        );
    }
    let auth = Arc::new(Auth(AtomicUsize::new(0)));
    let mut r = request(80);
    r.capability = Capability::HttpExchange { port: 80 };
    assert!(matches!(
        Broker::new(auth.clone(), Arc::new(CountExchange(AtomicUsize::new(0))))
            .execute(r)
            .await,
        Err(BrokerError::CapabilityDenied)
    ));
    assert_eq!(auth.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn aggregate_bytes_include_input_exchange_request_response_and_final_output() {
    let exchange = Arc::new(CountExchange(AtomicUsize::new(0)));
    let mut r = request(80);
    r.input = vec![0; 21]; // 21 input + 4 request + 4 response + 4 final output > 32.
    assert!(matches!(
        Broker::new(Arc::new(Auth(AtomicUsize::new(0))), exchange.clone())
            .execute(r)
            .await,
        Err(BrokerError::BudgetExhausted)
    ));
    assert_eq!(exchange.0.load(Ordering::SeqCst), 1);
}

struct FutureDropped(Arc<AtomicBool>);
impl Drop for FutureDropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
struct BlockingExchange {
    started: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
    calls: AtomicUsize,
}
#[async_trait]
impl TargetBoundExchange for BlockingExchange {
    async fn exchange(
        &self,
        _: &AuthorizedTarget,
        request: ExchangeRequest,
    ) -> Result<ExchangeResponse, BrokerError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            let _drop = FutureDropped(Arc::clone(&self.dropped));
            self.started.store(true, Ordering::Release);
            std::future::pending::<()>().await;
            unreachable!()
        }
        ExchangeResponse::try_new(b"pong".to_vec(), request.response_limit)
    }
}

#[tokio::test]
async fn cancellation_drops_waiting_exchange_publishes_no_result_and_next_execution_is_clean() {
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let exchange = Arc::new(BlockingExchange {
        started: Arc::clone(&started),
        dropped: Arc::clone(&dropped),
        calls: AtomicUsize::new(0),
    });
    let broker = Arc::new(Broker::new(Arc::new(Auth(AtomicUsize::new(0))), exchange));
    let cancellation = CancellationToken::new();
    let mut first = request(80);
    first.cancellation = cancellation.clone();
    let running = {
        let broker = Arc::clone(&broker);
        tokio::spawn(async move { broker.execute(first).await })
    };
    while !started.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    cancellation.cancel();
    assert!(matches!(
        running.await.unwrap(),
        Err(BrokerError::Cancelled)
    ));
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(broker.execute(request(80)).await.unwrap().bytes, b"pong");
}
