use ed25519_dalek::SigningKey;
use lattice_audit_wasm::*;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

fn verified(wasm: &[u8], limits: Limits) -> VerifiedManifest {
    let mut manifest = AuditManifest::new(
        "runtime-test".into(),
        1,
        Sha256::digest(wasm).into(),
        TargetKind::NumericPrivateDevice,
        BTreeSet::from([Capability::TcpExchange { port: 80 }]),
        "deterministic test".into(),
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
    let key = SigningKey::from_bytes(&[7; 32]);
    manifest.sign(&key).unwrap();
    verify_manifest(&manifest, wasm, &key.verifying_key()).unwrap()
}
fn limits() -> Limits {
    Limits {
        max_bytes: 64,
        max_requests: 2,
        max_time: Duration::from_secs(1),
        max_fuel: 100_000,
        max_memory_pages: 2,
    }
}
fn wasm(source: &str) -> Vec<u8> {
    wat::parse_str(source).unwrap()
}
struct Host(u32);
#[async_trait::async_trait]
impl AuditHost for Host {
    async fn deterministic(&self) -> u32 {
        self.0
    }
}
const ECHO: &str = r#"(module (memory (export "memory") 1 2) (func (export "run") (param i32 i32) (result i64) local.get 0 i64.extend_i32_u i64.const 32 i64.shl local.get 1 i64.extend_i32_u i64.or))"#;

#[tokio::test]
async fn guest_owned_output_copies_exactly_from_the_returned_range() {
    let sandbox = Sandbox::new(verified(&wasm(ECHO), limits())).await.unwrap();
    assert_eq!(
        sandbox
            .execute(b"guest bytes", &Host(7))
            .await
            .unwrap()
            .output,
        b"guest bytes"
    );
}
#[tokio::test]
async fn host_scalar_result_is_usable_by_the_guest() {
    let module = wasm(
        r#"(module (import "audit" "deterministic" (func $d (result i32))) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i32.const 8 call $d i32.store8 i64.const 8 i64.const 32 i64.shl i64.const 1 i64.or))"#,
    );
    let sandbox = Sandbox::new(verified(&module, limits())).await.unwrap();
    assert_eq!(
        sandbox.execute(&[], &Host(0x41)).await.unwrap().output,
        b"A"
    );
}
#[tokio::test]
async fn rejects_ambient_wasi_and_imported_memory_or_table() {
    for source in [
        r#"(module (import "env" "socket" (func)) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
        r#"(module (import "wasi_snapshot_preview1" "fd_write" (func)) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
        r#"(module (import "env" "memory" (memory 1)) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
        r#"(module (import "env" "table" (table 1 funcref)) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
    ] {
        assert!(matches!(
            Sandbox::new(verified(&wasm(source), limits())).await,
            Err(AuditError::ForbiddenImport(_))
        ));
    }
}
#[tokio::test]
async fn rejects_malformed_start_and_bad_abi() {
    assert!(matches!(
        Sandbox::new(verified(b"not wasm", limits())).await,
        Err(AuditError::InvalidModule)
    ));
    assert!(matches!(
        Sandbox::new(verified(b"\0asm\x01\0\0\0\x05\x80", limits())).await,
        Err(AuditError::InvalidModule)
    ));
    for source in [
        r#"(module (memory (export "memory") 1) (start 0) (func))"#,
        r#"(module (memory (export "memory") 1))"#,
        r#"(module (memory (export "memory") 1) (func (export "run") (param i32) (result i64) i64.const 0))"#,
        r#"(module (memory 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
        r#"(module (import "audit" "deterministic" (func)) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
    ] {
        assert_eq!(
            Sandbox::new(verified(&wasm(source), limits()))
                .await
                .unwrap_err(),
            AuditError::InvalidAbi
        );
    }
}
#[tokio::test]
async fn input_and_output_bounds_are_distinct_and_checked() {
    let mut small = limits();
    small.max_bytes = 3;
    let sandbox = Sandbox::new(verified(&wasm(ECHO), small)).await.unwrap();
    assert_eq!(
        sandbox.execute(b"four", &Host(0)).await.unwrap_err(),
        AuditError::InputLimitExceeded
    );
    let module = wasm(
        r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0 i64.const 32 i64.shl i64.const 65 i64.or))"#,
    );
    let sandbox = Sandbox::new(verified(&module, limits())).await.unwrap();
    assert_eq!(
        sandbox.execute(&[], &Host(0)).await.unwrap_err(),
        AuditError::OutputLimitExceeded
    );
    let module = wasm(
        r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 65535 i64.const 32 i64.shl i64.const 2 i64.or))"#,
    );
    let sandbox = Sandbox::new(verified(&module, limits())).await.unwrap();
    assert_eq!(
        sandbox.execute(&[], &Host(0)).await.unwrap_err(),
        AuditError::InvalidAbi
    );
}
#[tokio::test]
async fn memory_and_table_declarations_and_growth_fail_closed() {
    let mut one = limits();
    one.max_memory_pages = 1;
    for source in [
        r#"(module (memory (export "memory") 2) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
        r#"(module (memory (export "memory") 1 2) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
    ] {
        assert_eq!(
            Sandbox::new(verified(&wasm(source), one.clone()))
                .await
                .unwrap_err(),
            AuditError::MemoryLimitExceeded
        );
    }
    let grow_memory = wasm(
        r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i32.const 1 memory.grow drop i64.const 0))"#,
    );
    let sandbox = Sandbox::new(verified(&grow_memory, one)).await.unwrap();
    assert_eq!(
        sandbox.execute(&[], &Host(0)).await.unwrap_err(),
        AuditError::MemoryLimitExceeded
    );
    for source in [
        r#"(module (table 65 funcref) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
        r#"(module (table 1 65 funcref) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
    ] {
        assert_eq!(
            Sandbox::new(verified(&wasm(source), limits()))
                .await
                .unwrap_err(),
            AuditError::TableLimitExceeded
        );
    }
    let grow_table = wasm(
        r#"(module (table 1 funcref) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) ref.null func i32.const 64 table.grow drop i64.const 0))"#,
    );
    let sandbox = Sandbox::new(verified(&grow_table, limits())).await.unwrap();
    assert_eq!(
        sandbox.execute(&[], &Host(0)).await.unwrap_err(),
        AuditError::TableLimitExceeded
    );
    let extra_memory = wasm(
        r#"(module (memory (export "memory") 1) (memory 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
    );
    assert_eq!(
        Sandbox::new(verified(&extra_memory, limits()))
            .await
            .unwrap_err(),
        AuditError::InvalidAbi
    );
    let extra_tables = wasm(
        r#"(module (table 1 funcref) (table 1 funcref) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
    );
    assert_eq!(
        Sandbox::new(verified(&extra_tables, limits()))
            .await
            .unwrap_err(),
        AuditError::TableLimitExceeded
    );
}
#[tokio::test]
async fn request_limit_fails_inside_the_callback_and_ordinary_traps_stay_traps() {
    let mut one = limits();
    one.max_requests = 1;
    let calls = wasm(
        r#"(module (import "audit" "deterministic" (func $d (result i32))) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) call $d drop call $d drop i64.const 0))"#,
    );
    let sandbox = Sandbox::new(verified(&calls, one)).await.unwrap();
    assert_eq!(
        sandbox.execute(&[], &Host(1)).await.unwrap_err(),
        AuditError::RequestLimitExceeded
    );
    let trap = wasm(
        r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) unreachable))"#,
    );
    let sandbox = Sandbox::new(verified(&trap, limits())).await.unwrap();
    assert_eq!(
        sandbox.execute(&[], &Host(0)).await.unwrap_err(),
        AuditError::Trap
    );
}
#[tokio::test]
async fn fuel_exhaustion_is_distinct() {
    let mut bounded = limits();
    bounded.max_fuel = 100;
    let module = wasm(
        r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) (loop br 0) i64.const 0))"#,
    );
    let sandbox = Sandbox::new(verified(&module, bounded)).await.unwrap();
    assert_eq!(
        sandbox.execute(&[], &Host(0)).await.unwrap_err(),
        AuditError::FuelExhausted
    );
}

#[tokio::test]
async fn epoch_deadline_enforces_max_time_without_leaking_into_the_next_execution() {
    let mut timed = limits();
    timed.max_fuel = 10_000_000_000;
    let loop_forever = wasm(
        r#"(module (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) (loop br 0) i64.const 0))"#,
    );
    let sandbox = Sandbox::new(verified(&loop_forever, timed)).await.unwrap();
    assert_eq!(
        sandbox.execute(&[], &Host(0)).await.unwrap_err(),
        AuditError::TimedOut
    );
    let clean = Sandbox::new(verified(&wasm(ECHO), limits())).await.unwrap();
    assert_eq!(
        clean.execute(b"next", &Host(0)).await.unwrap().output,
        b"next"
    );
}

struct SleepingHost;
#[async_trait::async_trait]
impl AuditHost for SleepingHost {
    async fn deterministic(&self) -> u32 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        1
    }
}

struct HostFutureDrop(Arc<AtomicBool>);
impl Drop for HostFutureDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
struct NeverReadyHost(Arc<AtomicBool>);
#[async_trait::async_trait]
impl AuditHost for NeverReadyHost {
    async fn deterministic(&self) -> u32 {
        let _cancelled = HostFutureDrop(Arc::clone(&self.0));
        tokio::time::sleep(Duration::from_secs(10)).await;
        0
    }
}

#[tokio::test]
async fn host_await_is_cancelled_at_max_time_and_releases_the_sandbox() {
    let module = wasm(
        r#"(module (import "audit" "deterministic" (func $d (result i32))) (memory (export "memory") 1) (func (export "run") (param i32 i32) (result i64) call $d drop local.get 0 i64.extend_i32_u i64.const 32 i64.shl local.get 1 i64.extend_i32_u i64.or))"#,
    );
    let sandbox = Sandbox::new(verified(&module, limits())).await.unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let started = tokio::time::Instant::now();
    assert_eq!(
        sandbox
            .execute(b"x", &NeverReadyHost(Arc::clone(&cancelled)))
            .await
            .unwrap_err(),
        AuditError::TimedOut
    );
    assert!(started.elapsed() < Duration::from_millis(1_500));
    assert!(cancelled.load(Ordering::Acquire));
    assert_eq!(
        sandbox.execute(b"ok", &Host(1)).await.unwrap().output,
        b"ok"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_sandbox_admission_isolated_from_another_calls_epoch_ticker() {
    let mut timed = limits();
    timed.max_fuel = 10_000_000_000;
    let module = wasm(
        r#"(module
          (import "audit" "deterministic" (func $d (result i32)))
          (memory (export "memory") 1)
          (func (export "run") (param i32 i32) (result i64)
            local.get 1 i32.eqz
            if
              loop $forever
                br $forever
              end
            end
            call $d drop
            local.get 0 i64.extend_i32_u i64.const 32 i64.shl
            local.get 1 i64.extend_i32_u i64.or))"#,
    );
    let sandbox = Arc::new(Sandbox::new(verified(&module, timed)).await.unwrap());
    let slow_sandbox = Arc::clone(&sandbox);
    let slow = tokio::spawn(async move { slow_sandbox.execute(&[], &SleepingHost).await });
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        sandbox.execute(b"ok", &SleepingHost).await.unwrap().output,
        b"ok"
    );
    assert_eq!(slow.await.unwrap().unwrap_err(), AuditError::TimedOut);
}
