use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use lattice_audit_wasm::*;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
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
