//! Approval, manifest-policy and concurrency gates added after review.

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use lattice_audit_wasm::*;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn target_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 44))
}

fn limits() -> Limits {
    Limits {
        max_bytes: 64,
        max_requests: 2,
        max_time: Duration::from_secs(1),
        max_fuel: 100_000,
        max_memory_pages: 1,
    }
}

fn manifest(wasm: &[u8], version: u16) -> AuditManifest {
    AuditManifest::new(
        "gate-test".into(),
        version,
        Sha256::digest(wasm).into(),
        TargetKind::NumericPrivateDevice,
        BTreeSet::from([Capability::TcpExchange { port: 80 }]),
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
    .unwrap()
}

const NOW: u64 = 1_800_000_000;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[5; 32])
}

fn policy() -> VerificationPolicy {
    VerificationPolicy::new([TrustedKey {
        key_id: "release-1".into(),
        key: key().verifying_key(),
        revoked: false,
    }])
}

fn signed(version: u16, from: u64, until: u64) -> AuditManifest {
    let mut m = manifest(b"wasm", version)
        .with_key_id("release-1")
        .unwrap()
        .with_validity(from, until)
        .unwrap();
    m.sign(&key()).unwrap();
    m
}

#[test]
fn policy_rejects_unknown_revoked_keys_and_tampered_key_ids() {
    let m = signed(1, 0, NOW + 10);
    assert!(verify_manifest_with_policy(&m, b"wasm", &policy(), NOW).is_ok());
    assert_eq!(
        verify_manifest_with_policy(&m, b"wasm", &VerificationPolicy::default(), NOW).unwrap_err(),
        AuditError::UnknownKey
    );
    let revoked = VerificationPolicy::new([TrustedKey {
        key_id: "release-1".into(),
        key: key().verifying_key(),
        revoked: true,
    }]);
    assert_eq!(
        verify_manifest_with_policy(&m, b"wasm", &revoked, NOW).unwrap_err(),
        AuditError::KeyRevoked
    );
    // The key id is signed: renaming it to another trusted id fails.
    let mut renamed = m.clone();
    renamed.key_id = "release-2".into();
    let two = VerificationPolicy::new([
        TrustedKey {
            key_id: "release-1".into(),
            key: key().verifying_key(),
            revoked: false,
        },
        TrustedKey {
            key_id: "release-2".into(),
            key: key().verifying_key(),
            revoked: false,
        },
    ]);
    assert_eq!(
        verify_manifest_with_policy(&renamed, b"wasm", &two, NOW).unwrap_err(),
        AuditError::InvalidSignature
    );
}

#[test]
fn signed_validity_window_is_enforced_at_both_ends() {
    let m = signed(1, NOW - 10, NOW + 10);
    assert!(verify_manifest_with_policy(&m, b"wasm", &policy(), NOW).is_ok());
    assert_eq!(
        verify_manifest_with_policy(&m, b"wasm", &policy(), NOW - 11).unwrap_err(),
        AuditError::NotYetValid
    );
    assert_eq!(
        verify_manifest_with_policy(&m, b"wasm", &policy(), NOW + 11).unwrap_err(),
        AuditError::Expired
    );
    // Widening the window after signing breaks the signature.
    let mut widened = m.clone();
    widened.valid_until = u64::MAX;
    assert_eq!(
        verify_manifest_with_policy(&widened, b"wasm", &policy(), NOW).unwrap_err(),
        AuditError::InvalidSignature
    );
    let open_ended = signed(1, 0, u64::MAX);
    assert!(verify_manifest_with_policy(&open_ended, b"wasm", &policy(), NOW).is_ok());
    assert_eq!(
        verify_manifest_with_policy(
            &open_ended,
            b"wasm",
            &policy().require_validity_window(),
            NOW
        )
        .unwrap_err(),
        AuditError::ValidityRequired
    );
}

#[test]
fn version_floor_blocks_replay_of_an_older_signed_manifest() {
    // Regression: nothing stopped a recalled, looser, still-validly-signed
    // manifest from verifying again after a newer one was installed.
    let old = signed(1, 0, NOW + 10);
    let new = signed(2, 0, NOW + 10);
    let mut policy = policy();
    let accepted = verify_manifest_with_policy(&new, b"wasm", &policy, NOW).unwrap();
    policy.record_accepted(&accepted);
    assert_eq!(policy.version_floors().get("gate-test"), Some(&2));
    assert_eq!(
        verify_manifest_with_policy(&old, b"wasm", &policy, NOW).unwrap_err(),
        AuditError::ModuleRollback
    );
    // The floor is plain data a caller can persist and restore.
    let restored = VerificationPolicy::new([TrustedKey {
        key_id: "release-1".into(),
        key: key().verifying_key(),
        revoked: false,
    }])
    .with_version_floors(policy.version_floors().clone());
    assert_eq!(
        verify_manifest_with_policy(&old, b"wasm", &restored, NOW).unwrap_err(),
        AuditError::ModuleRollback
    );
    assert!(verify_manifest_with_policy(&new, b"wasm", &restored, NOW).is_ok());
}

#[test]
fn revoked_module_digests_are_refused() {
    let m = signed(1, 0, NOW + 10);
    let revoked = policy().revoke_digest(Sha256::digest(b"wasm").into());
    assert_eq!(
        verify_manifest_with_policy(&m, b"wasm", &revoked, NOW).unwrap_err(),
        AuditError::ModuleRevoked
    );
}

#[test]
fn approval_ledger_is_single_use_expiring_and_bound_to_target_and_module() {
    let ledger = ApprovalLedger::new();
    let target = AuthorizedTarget::new(AuthorizerWitness::for_tests(), target_ip(), 7, 80).unwrap();
    let other = AuthorizedTarget::new(AuthorizerWitness::for_tests(), target_ip(), 7, 81).unwrap();
    let digest = [1u8; 32];
    let now = Instant::now();
    let id = ledger
        .mint_at(&target, digest, Duration::from_secs(60), now)
        .unwrap();
    // Wrong target, wrong module, wrong id, and expiry all fail without
    // consuming the grant.
    assert!(ledger.redeem_at(id, &other, digest, now).is_err());
    assert!(ledger.redeem_at(id, &target, [2; 32], now).is_err());
    assert!(
        ledger
            .redeem_at(Uuid::new_v4(), &target, digest, now)
            .is_err()
    );
    assert!(
        ledger
            .redeem_at(id, &target, digest, now + Duration::from_secs(61))
            .is_err()
    );
    assert!(ledger.redeem_at(id, &target, digest, now).is_ok());
    // Single use.
    assert!(ledger.redeem_at(id, &target, digest, now).is_err());
    assert!(
        ledger
            .mint_at(&target, digest, Duration::ZERO, now)
            .is_err()
    );
}

struct LedgerAuth(ApprovalLedger);
impl TargetAuthorizer for LedgerAuth {
    fn authorize(
        &self,
        witness: AuthorizerWitness,
        t: IpAddr,
        i: u32,
        p: u16,
    ) -> Result<AuthorizedTarget, TargetError> {
        AuthorizedTarget::new(witness, t, i, p)
    }
    fn redeem_approval(
        &self,
        approval: Uuid,
        target: &AuthorizedTarget,
        module_sha256: [u8; 32],
    ) -> Result<(), TargetError> {
        self.0.redeem(approval, target, module_sha256)
    }
}

struct Echo;
#[async_trait]
impl TargetBoundExchange for Echo {
    async fn exchange(
        &self,
        _: &AuthorizedTarget,
        request: ExchangeRequest,
    ) -> Result<ExchangeResponse, BrokerError> {
        let mut response = ExchangeResponse::new(request.response_limit);
        response.extend_from_slice(b"pong")?;
        Ok(response)
    }
}

fn module() -> Vec<u8> {
    wat::parse_str(r#"(module (import "audit" "exchange" (func $x (param i32 i32 i32 i32) (result i32))) (memory (export "memory") 1) (data (i32.const 16) "ping") (func (export "run") (param i32 i32) (result i64) i32.const 16 i32.const 4 i32.const 32 i32.const 4 call $x drop i64.const 32 i64.const 32 i64.shl i64.const 4 i64.or))"#).unwrap()
}

fn broker_request(approval: Uuid) -> BrokerRequest {
    let wasm = module();
    let mut m = manifest(&wasm, 1);
    m.sign(&key()).unwrap();
    BrokerRequest {
        module: verify_manifest(&m, &wasm, &key().verifying_key()).unwrap(),
        input: vec![],
        target: target_ip(),
        interface: 7,
        port: 80,
        capability: Capability::TcpExchange { port: 80 },
        approval_id: approval,
        limits: limits(),
        cancellation: CancellationToken::new(),
    }
}

#[tokio::test]
async fn broker_runs_only_with_a_real_single_use_approval() {
    // Regression: any non-nil UUID used to satisfy the approval gate.
    let auth = Arc::new(LedgerAuth(ApprovalLedger::new()));
    let broker = Broker::new(auth.clone(), Arc::new(Echo));
    let fabricated = broker.execute(broker_request(Uuid::new_v4())).await;
    assert!(matches!(
        fabricated,
        Err(BrokerError::Target(TargetError::ApprovalRejected))
    ));

    let probe = broker_request(Uuid::nil());
    let target = AuthorizedTarget::new(AuthorizerWitness::for_tests(), target_ip(), 7, 80).unwrap();
    let id = auth
        .0
        .mint(&target, probe.module.sha256(), Duration::from_secs(30))
        .unwrap();
    let ok = broker.execute(broker_request(id)).await.unwrap();
    assert_eq!(ok.bytes, b"pong");
    let reused = broker.execute(broker_request(id)).await;
    assert!(matches!(
        reused,
        Err(BrokerError::Target(TargetError::ApprovalRejected))
    ));
}

struct ParkHost {
    release: tokio::sync::Notify,
    parked: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl AuditHost for ParkHost {
    async fn deterministic(&self) -> u32 {
        use std::sync::atomic::Ordering;
        // The first caller parks until released; later callers return at once.
        if self.parked.swap(true, Ordering::SeqCst) {
            1
        } else {
            self.release.notified().await;
            0
        }
    }
}

#[tokio::test]
async fn a_parked_execution_does_not_block_another_run_of_the_same_module() {
    // Regression: a per-module mutex serialised executions, so one slow run
    // (up to 300 s) blocked every other audit of that module.
    let wasm = wat::parse_str(
        r#"(module (import "audit" "deterministic" (func $d (result i32))) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) call $d drop i64.const 0))"#,
    )
    .unwrap();
    let mut m = manifest(&wasm, 1);
    m.limits.max_time = Duration::from_secs(20);
    m.sign(&key()).unwrap();
    let verified = verify_manifest(&m, &wasm, &key().verifying_key()).unwrap();
    let sandbox = Arc::new(Sandbox::new(verified).await.unwrap());
    let host = Arc::new(ParkHost {
        release: tokio::sync::Notify::new(),
        parked: std::sync::atomic::AtomicBool::new(false),
    });
    let first = {
        let (sandbox, host) = (sandbox.clone(), host.clone());
        tokio::spawn(async move { sandbox.execute(&[], &*host).await })
    };
    while !host.parked.load(std::sync::atomic::Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    let second = tokio::time::timeout(Duration::from_secs(5), sandbox.execute(&[], &*host))
        .await
        .expect("second execution must not wait for the parked one")
        .unwrap();
    assert!(second.output.is_empty());
    host.release.notify_one();
    first.await.unwrap().unwrap();
}

#[tokio::test]
async fn relaxed_simd_modules_are_refused_for_determinism() {
    let wasm = wat::parse_str(
        r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) (drop (f32x4.relaxed_madd (v128.const f32x4 1 2 3 4) (v128.const f32x4 1 2 3 4) (v128.const f32x4 1 2 3 4))) i64.const 0))"#,
    )
    .unwrap();
    let mut m = manifest(&wasm, 1);
    m.sign(&key()).unwrap();
    let verified = verify_manifest(&m, &wasm, &key().verifying_key()).unwrap();
    assert!(matches!(
        Sandbox::new(verified).await,
        Err(AuditError::InvalidModule)
    ));
}
