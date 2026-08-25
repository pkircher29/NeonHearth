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

#[test]
fn rejects_subsecond_limits_and_duplicate_or_nested_unknown_fields() {
    let (m, _) = signed(b"module");
    let mut value = serde_json::to_value(&m).unwrap();
    value["limits"]["max_time"] = json!("not used");
    // serde_json serializes Duration through the seconds adapter as a number.
    value["limits"]["max_time"] = json!(2.5);
    assert!(serde_json::from_value::<AuditManifest>(value).is_err());

    let raw = serde_json::to_string(&m).unwrap();
    let start = raw.find(r#""capabilities":["#).unwrap() + r#""capabilities":["#.len();
    let end = raw[start..].find(']').unwrap() + start;
    let item = &raw[start..end];
    let duplicate_capabilities = format!("{}{},{}{}", &raw[..start], item, item, &raw[end..]);
    assert!(serde_json::from_str::<AuditManifest>(&duplicate_capabilities).is_err());

    let mut value = serde_json::to_value(&m).unwrap();
    value["rollback"]["extra"] = json!(true);
    assert!(serde_json::from_value::<AuditManifest>(value).is_err());
    let mut value = serde_json::to_value(&m).unwrap();
    value["evidence_schema"]["extra"] = json!(true);
    assert!(serde_json::from_value::<AuditManifest>(value).is_err());
    let mut value = serde_json::to_value(&m).unwrap();
    value["limits"]["extra"] = json!(true);
    assert!(serde_json::from_value::<AuditManifest>(value).is_err());
}

#[test]
fn rejects_duplicate_evidence_keys_and_noncanonical_text() {
    let (m, _) = signed(b"module");
    let raw = serde_json::to_string(&m).unwrap();
    let duplicate = raw.replace(
        r#""fields":{"status":"Text"}"#,
        r#""fields":{"status":"Text","status":"Text"}"#,
    );
    assert!(serde_json::from_str::<AuditManifest>(&duplicate).is_err());

    for field in ["expected_behavior", "rollback"] {
        let mut value = serde_json::to_value(&m).unwrap();
        if field == "expected_behavior" {
            value[field] = json!(" read ");
        } else {
            value[field]["description"] = json!(" none ");
        }
        assert!(serde_json::from_value::<AuditManifest>(value).is_err());
    }
}

#[test]
fn programmatic_subsecond_and_noncanonical_evidence_are_rejected() {
    let (mut manifest, key) = signed(b"module");
    manifest.limits.max_time = Duration::new(2, 1);
    manifest.sign(&key).unwrap();
    assert!(matches!(
        verify_manifest(&manifest, b"module", &key.verifying_key()),
        Err(AuditError::InvalidManifest(_))
    ));

    for name in [" status", "status ", "status\n"] {
        let mut manifest = unsigned(b"module");
        manifest.evidence_schema.fields.clear();
        manifest
            .evidence_schema
            .fields
            .insert(name.into(), EvidenceType::Text);
        manifest.sign(&key).unwrap();
        assert!(matches!(
            verify_manifest(&manifest, b"module", &key.verifying_key()),
            Err(AuditError::InvalidManifest(_))
        ));
    }
}

#[test]
fn canonical_order_is_independent_of_collection_insertion_order() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut left = unsigned(b"module");
    left.capabilities = [
        Capability::TlsMetadata { port: 443 },
        Capability::TcpExchange { port: 80 },
    ]
    .into_iter()
    .collect();
    left.evidence_schema.fields = [
        ("zeta".into(), EvidenceType::Boolean),
        ("alpha".into(), EvidenceType::Text),
    ]
    .into_iter()
    .collect();

    let mut right = unsigned(b"module");
    right.capabilities = [
        Capability::TcpExchange { port: 80 },
        Capability::TlsMetadata { port: 443 },
    ]
    .into_iter()
    .collect();
    right.evidence_schema.fields = [
        ("alpha".into(), EvidenceType::Text),
        ("zeta".into(), EvidenceType::Boolean),
    ]
    .into_iter()
    .collect();

    left.sign(&key).unwrap();
    right.sign(&key).unwrap();
    assert_eq!(left.canonical_bytes(), right.canonical_bytes());
    assert_eq!(left.signature, right.signature);
}

fn assert_signed_mutation_rejected(mutate: impl FnOnce(&mut AuditManifest)) {
    let (mut manifest, key) = signed(b"module");
    mutate(&mut manifest);
    assert!(verify_manifest(&manifest, b"module", &key.verifying_key()).is_err());
}

#[test]
fn every_mutable_signed_field_is_authenticated_or_revalidated() {
    assert_signed_mutation_rejected(|m| m.module_id = "net.other".into());
    assert_signed_mutation_rejected(|m| m.version = 2);
    assert_signed_mutation_rejected(|m| m.sha256[0] ^= 1);
    assert_signed_mutation_rejected(|m| {
        m.capabilities = [Capability::HttpExchange { port: 443 }]
            .into_iter()
            .collect();
    });
    assert_signed_mutation_rejected(|m| m.expected_behavior = "read other metadata".into());
    assert_signed_mutation_rejected(|m| m.side_effects = SideEffectProfile::Persistent);
    assert_signed_mutation_rejected(|m| m.rollback.description = "different".into());
    assert_signed_mutation_rejected(|m| {
        m.evidence_schema
            .fields
            .insert("extra".into(), EvidenceType::Integer);
    });
    assert_signed_mutation_rejected(|m| m.limits.max_bytes += 1);
    assert_signed_mutation_rejected(|m| m.limits.max_requests += 1);
    assert_signed_mutation_rejected(|m| m.limits.max_time += Duration::from_secs(1));
    assert_signed_mutation_rejected(|m| m.limits.max_fuel += 1);
    assert_signed_mutation_rejected(|m| m.limits.max_memory_pages += 1);
    assert_signed_mutation_rejected(|m| m.signature[0] ^= 1);
}

#[test]
fn malformed_signature_lengths_and_cross_domain_signatures_are_rejected() {
    let (manifest, key) = signed(b"module");
    for len in [63, 65] {
        let mut value = serde_json::to_value(&manifest).unwrap();
        value["signature"] = json!(vec![0u8; len]);
        assert!(serde_json::from_value::<AuditManifest>(value).is_err());
    }

    let mut wrong_domain = manifest.clone();
    let canonical = wrong_domain.canonical_bytes();
    let prefix = b"NeonHearth/lattice-audit-wasm/manifest/v1\0";
    wrong_domain.signature =
        ed25519_dalek::Signer::sign(&key, &canonical[prefix.len()..]).to_bytes();
    assert!(matches!(
        verify_manifest(&wrong_domain, b"module", &key.verifying_key()),
        Err(AuditError::InvalidSignature)
    ));
}

fn assert_resigned_limit_rejected(mutate: impl FnOnce(&mut Limits)) {
    let (mut manifest, key) = signed(b"module");
    mutate(&mut manifest.limits);
    manifest.sign(&key).unwrap();
    assert!(matches!(
        verify_manifest(&manifest, b"module", &key.verifying_key()),
        Err(AuditError::InvalidManifest(_))
    ));
}

#[test]
fn every_limit_accepts_its_exact_ceiling_and_rejects_zero_or_ceiling_plus_one() {
    let (mut manifest, key) = signed(b"module");
    manifest.limits = Limits {
        max_bytes: 16 * 1024 * 1024,
        max_requests: 1024,
        max_time: Duration::from_secs(300),
        max_fuel: 10_000_000_000,
        max_memory_pages: 1024,
    };
    manifest.sign(&key).unwrap();
    assert!(verify_manifest(&manifest, b"module", &key.verifying_key()).is_ok());

    assert_resigned_limit_rejected(|v| v.max_bytes = 0);
    assert_resigned_limit_rejected(|v| v.max_bytes = 16 * 1024 * 1024 + 1);
    assert_resigned_limit_rejected(|v| v.max_requests = 0);
    assert_resigned_limit_rejected(|v| v.max_requests = 1025);
    assert_resigned_limit_rejected(|v| v.max_time = Duration::ZERO);
    assert_resigned_limit_rejected(|v| v.max_time = Duration::from_secs(301));
    assert_resigned_limit_rejected(|v| v.max_fuel = 0);
    assert_resigned_limit_rejected(|v| v.max_fuel = 10_000_000_001);
    assert_resigned_limit_rejected(|v| v.max_memory_pages = 0);
    assert_resigned_limit_rejected(|v| v.max_memory_pages = 1025);
}
