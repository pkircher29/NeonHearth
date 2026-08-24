use ed25519_dalek::SigningKey;
use lattice_audit_wasm::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;

fn unsigned(wasm: &[u8]) -> AuditManifest {
    AuditManifest::new(
        "net.audit".into(),
        1,
        Sha256::digest(wasm).into(),
        TargetKind::NumericPrivateDevice,
        [Capability::TcpExchange { port: 443 }]
            .into_iter()
            .collect(),
        "read device metadata".into(),
        SideEffectProfile::ReadOnly,
        RollbackPlan {
            required: false,
            description: "none".into(),
        },
        EvidenceSchema {
            fields: [("status".into(), EvidenceType::Text)]
                .into_iter()
                .collect(),
        },
        Limits {
            max_bytes: 1024,
            max_requests: 1,
            max_time: Duration::from_secs(2),
            max_fuel: 1000,
            max_memory_pages: 2,
        },
    )
    .unwrap()
}

fn signed(wasm: &[u8]) -> (AuditManifest, SigningKey) {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut m = unsigned(wasm);
    m.sign(&key).unwrap();
    (m, key)
}

#[test]
fn manifest_accepts_only_matching_digest_and_signature() {
    let (manifest, key) = signed(b"module");
    assert!(verify_manifest(&manifest, b"module", &key.verifying_key()).is_ok());
    assert!(verify_manifest(&manifest, b"tampered", &key.verifying_key()).is_err());
}

#[test]
fn tampered_manifest_and_wrong_key_are_rejected() {
    let (mut manifest, key) = signed(b"module");
    manifest.expected_behavior = "write firmware".into();
    assert!(verify_manifest(&manifest, b"module", &key.verifying_key()).is_err());
    let other = SigningKey::from_bytes(&[8u8; 32]);
    let (manifest, _) = signed(b"module");
    assert!(verify_manifest(&manifest, b"module", &other.verifying_key()).is_err());
}

#[test]
fn unsafe_effects_and_invalid_limits_are_rejected() {
    let (mut m, key) = signed(b"module");
    for effect in [
        SideEffectProfile::Destructive,
        SideEffectProfile::Persistent,
        SideEffectProfile::CredentialExfiltration,
        SideEffectProfile::DenialOfService,
        SideEffectProfile::FirmwareWrite,
    ] {
        m.side_effects = effect;
        m.sign(&key).unwrap();
        assert!(matches!(
            verify_manifest(&m, b"module", &key.verifying_key()),
            Err(AuditError::UnsafeSideEffects(_))
        ));
    }
    let invalid = AuditManifest::new(
        "net.audit".into(),
        1,
        Sha256::digest(b"module").into(),
        TargetKind::NumericPrivateDevice,
        [Capability::TcpExchange { port: 443 }]
            .into_iter()
            .collect(),
        "read".into(),
        SideEffectProfile::ReadOnly,
        RollbackPlan {
            required: false,
            description: "none".into(),
        },
        EvidenceSchema {
            fields: [("status".into(), EvidenceType::Text)]
                .into_iter()
                .collect(),
        },
        Limits {
            max_bytes: 0,
            max_requests: 1,
            max_time: Duration::from_secs(1),
            max_fuel: 1,
            max_memory_pages: 1,
        },
    );
    assert!(invalid.is_err());
}

#[test]
fn canonical_bytes_are_deterministic_and_verified_output_is_immutable() {
    let (m, key) = signed(b"module");
    assert_eq!(m.canonical_bytes(), m.canonical_bytes());
    let v = verify_manifest(&m, b"module", &key.verifying_key()).unwrap();
    assert_eq!(v.sha256(), m.sha256);
    assert_eq!(v.module_id(), "net.audit");
}

#[test]
fn serde_rejects_unknown_and_invalid_values() {
    let (m, _) = signed(b"module");
    let mut value = serde_json::to_value(&m).unwrap();
    value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<AuditManifest>(value).is_err());
    let mut value = serde_json::to_value(&m).unwrap();
    value["version"] = json!(0);
    assert!(serde_json::from_value::<AuditManifest>(value).is_err());
}
