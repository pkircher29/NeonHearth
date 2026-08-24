use ed25519_dalek::SigningKey;
use lattice_audit_wasm::*;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

fn verified(wasm: &[u8], max_bytes: u64) -> VerifiedManifest {
    let mut m = AuditManifest::new(
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
        Limits {
            max_bytes,
            max_requests: 2,
            max_time: Duration::from_secs(1),
            max_fuel: 100_000,
            max_memory_pages: 2,
        },
    )
    .unwrap();
    m.sign(&SigningKey::from_bytes(&[7; 32])).unwrap();
    verify_manifest(&m, wasm, &SigningKey::from_bytes(&[7; 32]).verifying_key()).unwrap()
}

#[tokio::test]
async fn ambient_imports_are_rejected_before_start() {
    let wasm =
        wat::parse_str("(module (import \"env\" \"socket\" (func)) (func (export \"run\")))")
            .unwrap();
    let err = Sandbox::new(verified(&wasm, 64)).await.unwrap_err();
    assert!(matches!(err, AuditError::ForbiddenImport(_)));
}

#[tokio::test]
async fn infinite_loop_is_stopped_by_resource_budget() {
    let wasm = wat::parse_str("(module (func (export \"run\") (loop br 0)))").unwrap();
    let sandbox = Sandbox::new(verified(&wasm, 64)).await.unwrap();
    let err = sandbox.execute(&[], &DeterministicHost).await.unwrap_err();
    assert!(matches!(
        err,
        AuditError::FuelExhausted | AuditError::TimedOut
    ));
}

#[tokio::test]
async fn memory_growth_and_oversized_output_fail_closed() {
    let wasm = wat::parse_str(
        "(module (memory 1 3) (func (export \"run\") (memory.grow (i32.const 3)) drop))",
    )
    .unwrap();
    let sandbox = Sandbox::new(verified(&wasm, 4)).await.unwrap();
    let err = sandbox.execute(&[], &DeterministicHost).await.unwrap_err();
    assert!(matches!(err, AuditError::MemoryLimitExceeded));
}

#[tokio::test]
async fn permitted_host_call_is_deterministic_and_output_is_capped() {
    let wasm = wat::parse_str(
        "(module (import \"audit\" \"deterministic\" (func $h)) (func (export \"run\") call $h))",
    )
    .unwrap();
    let sandbox = Sandbox::new(verified(&wasm, 8)).await.unwrap();
    let result = sandbox.execute(&[], &DeterministicHost).await.unwrap();
    assert!(result.output.len() <= 8);
}

struct DeterministicHost;
impl AuditHost for DeterministicHost {
    fn deterministic(&self) -> Vec<u8> {
        b"ok".to_vec()
    }
}
