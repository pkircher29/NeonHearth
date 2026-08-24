use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use thiserror::Error;

const DOMAIN: &[u8] = b"NeonHearth/lattice-audit-wasm/manifest/v1\0";
/// Maximum module size and aggregate exchange/evidence bytes permitted by a manifest.
const MAX_WASM_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TEXT: usize = 4096;
const MAX_FIELDS: usize = 64;
const MAX_CAPABILITIES: usize = 16;
const MAX_REQUESTS: u32 = 1024;
const MAX_TIME_SECS: u64 = 300;
const MAX_FUEL: u64 = 10_000_000_000;
const MAX_MEMORY_PAGES: u32 = 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("module digest does not match manifest")]
    DigestMismatch,
    #[error("manifest signature is invalid")]
    InvalidSignature,
    #[error("manifest has unsafe side effects: {0:?}")]
    UnsafeSideEffects(SideEffectProfile),
    #[error("manifest exceeds maximum wasm size")]
    WasmTooLarge,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    TcpExchange { port: u16 },
    HttpExchange { port: u16 },
    TlsMetadata { port: u16 },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TargetKind {
    NumericPrivateDevice,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SideEffectProfile {
    ReadOnly,
    Destructive,
    Persistent,
    CredentialExfiltration,
    DenialOfService,
    FirmwareWrite,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackPlan {
    pub required: bool,
    pub description: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceType {
    Text,
    Integer,
    Boolean,
    Bytes,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EvidenceSchema {
    pub fields: BTreeMap<String, EvidenceType>,
}

impl<'de> Deserialize<'de> for EvidenceSchema {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = EvidenceSchema;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("evidence schema object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut fields = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key != "fields" || fields.is_some() {
                        return Err(serde::de::Error::custom(
                            "unknown or duplicate evidence schema field",
                        ));
                    }
                    struct Fields(BTreeMap<String, EvidenceType>);
                    impl<'de> Deserialize<'de> for Fields {
                        fn deserialize<D: serde::Deserializer<'de>>(
                            d: D,
                        ) -> Result<Self, D::Error> {
                            d.deserialize_map(FieldsVisitor).map(Fields)
                        }
                    }
                    struct FieldsVisitor;
                    impl<'de> serde::de::Visitor<'de> for FieldsVisitor {
                        type Value = BTreeMap<String, EvidenceType>;
                        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                            f.write_str("evidence fields map")
                        }
                        fn visit_map<M: serde::de::MapAccess<'de>>(
                            self,
                            mut m: M,
                        ) -> Result<Self::Value, M::Error> {
                            let mut out = BTreeMap::new();
                            while let Some(k) = m.next_key::<String>()? {
                                let v = m.next_value()?;
                                if out.insert(k, v).is_some() {
                                    return Err(serde::de::Error::custom(
                                        "duplicate evidence field",
                                    ));
                                }
                            }
                            Ok(out)
                        }
                    }
                    fields = Some(map.next_value::<Fields>()?.0);
                }
                let fields = fields.ok_or_else(|| serde::de::Error::custom("missing fields"))?;
                Ok(EvidenceSchema { fields })
            }
        }
        let schema = d.deserialize_map(Visitor)?;
        // serde_json's map access preserves duplicate keys only when we insert via a visitor.
        Ok(schema)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_requests: u32,
    #[serde(with = "duration_seconds")]
    pub max_time: Duration,
    pub max_fuel: u64,
    pub max_memory_pages: u32,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditManifest {
    pub module_id: String,
    pub version: u16,
    pub sha256: [u8; 32],
    pub target_kind: TargetKind,
    pub capabilities: BTreeSet<Capability>,
    pub expected_behavior: String,
    pub side_effects: SideEffectProfile,
    pub rollback: RollbackPlan,
    pub evidence_schema: EvidenceSchema,
    pub limits: Limits,
    #[serde(serialize_with = "sig_bytes::serialize")]
    pub signature: [u8; 64],
}

impl<'de> Deserialize<'de> for AuditManifest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            module_id: String,
            version: u16,
            sha256: [u8; 32],
            target_kind: TargetKind,
            capabilities: Vec<Capability>,
            expected_behavior: String,
            side_effects: SideEffectProfile,
            rollback: RollbackPlan,
            evidence_schema: EvidenceSchema,
            limits: Limits,
            signature: Vec<u8>,
        }
        let w = Wire::deserialize(d)?;
        let signature: [u8; 64] = w
            .signature
            .try_into()
            .map_err(|_| serde::de::Error::custom("signature must contain exactly 64 bytes"))?;
        let mut capabilities = BTreeSet::new();
        for capability in w.capabilities {
            if !capabilities.insert(capability) {
                return Err(serde::de::Error::custom("duplicate capability"));
            }
        }
        AuditManifest::from_parts(
            w.module_id,
            w.version,
            w.sha256,
            w.target_kind,
            capabilities,
            w.expected_behavior,
            w.side_effects,
            w.rollback,
            w.evidence_schema,
            w.limits,
            signature,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl AuditManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        module_id: String,
        version: u16,
        sha256: [u8; 32],
        target_kind: TargetKind,
        capabilities: BTreeSet<Capability>,
        expected_behavior: String,
        side_effects: SideEffectProfile,
        rollback: RollbackPlan,
        evidence_schema: EvidenceSchema,
        limits: Limits,
    ) -> Result<Self, AuditError> {
        Self::from_parts(
            module_id,
            version,
            sha256,
            target_kind,
            capabilities,
            expected_behavior,
            side_effects,
            rollback,
            evidence_schema,
            limits,
            [0; 64],
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        module_id: String,
        version: u16,
        sha256: [u8; 32],
        target_kind: TargetKind,
        capabilities: BTreeSet<Capability>,
        expected_behavior: String,
        side_effects: SideEffectProfile,
        rollback: RollbackPlan,
        evidence_schema: EvidenceSchema,
        limits: Limits,
        signature: [u8; 64],
    ) -> Result<Self, AuditError> {
        if version == 0
            || module_id.is_empty()
            || module_id.len() > 128
            || !module_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        {
            return Err(AuditError::InvalidManifest(
                "noncanonical module identity".into(),
            ));
        }
        if expected_behavior.trim().is_empty()
            || expected_behavior.len() > MAX_TEXT
            || rollback.description.trim().is_empty()
            || rollback.description.len() > MAX_TEXT
            || expected_behavior.trim() != expected_behavior
            || rollback.description.trim() != rollback.description
            || expected_behavior.chars().any(char::is_control)
            || rollback.description.chars().any(char::is_control)
        {
            return Err(AuditError::InvalidManifest("invalid text".into()));
        }
        if rollback.required {
            return Err(AuditError::InvalidManifest(
                "executable rollback is unsupported".into(),
            ));
        }
        if capabilities.is_empty()
            || capabilities.len() > MAX_CAPABILITIES
            || capabilities.iter().any(|c| {
                matches!(
                    c,
                    Capability::TcpExchange { port: 0 }
                        | Capability::HttpExchange { port: 0 }
                        | Capability::TlsMetadata { port: 0 }
                )
            })
        {
            return Err(AuditError::InvalidManifest("invalid capabilities".into()));
        }
        if evidence_schema.fields.is_empty()
            || evidence_schema.fields.len() > MAX_FIELDS
            || evidence_schema
                .fields
                .keys()
                .any(|k| k.is_empty() || k.len() > 128)
        {
            return Err(AuditError::InvalidManifest(
                "invalid evidence schema".into(),
            ));
        }
        if limits.max_bytes == 0
            || limits.max_bytes > MAX_WASM_BYTES
            || limits.max_requests == 0
            || limits.max_requests > MAX_REQUESTS
            || limits.max_time.is_zero()
            || limits.max_time.subsec_nanos() != 0
            || limits.max_time.as_secs() > MAX_TIME_SECS
            || limits.max_fuel == 0
            || limits.max_fuel > MAX_FUEL
            || limits.max_memory_pages == 0
            || limits.max_memory_pages > MAX_MEMORY_PAGES
        {
            return Err(AuditError::InvalidManifest("invalid limits".into()));
        }
        Ok(Self {
            module_id,
            version,
            sha256,
            target_kind,
            capabilities,
            expected_behavior,
            side_effects,
            rollback,
            evidence_schema,
            limits,
            signature,
        })
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_unsigned()
    }
    fn canonical_unsigned(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(DOMAIN);
        put_str(&mut b, &self.module_id);
        b.extend(self.version.to_be_bytes());
        b.extend(self.sha256);
        b.push(match self.target_kind {
            TargetKind::NumericPrivateDevice => 1,
        });
        b.extend((self.capabilities.len() as u32).to_be_bytes());
        for c in &self.capabilities {
            match c {
                Capability::TcpExchange { port } => {
                    b.push(1);
                    b.extend(port.to_be_bytes())
                }
                Capability::HttpExchange { port } => {
                    b.push(2);
                    b.extend(port.to_be_bytes())
                }
                Capability::TlsMetadata { port } => {
                    b.push(3);
                    b.extend(port.to_be_bytes())
                }
            }
        }
        put_str(&mut b, &self.expected_behavior);
        b.push(match self.side_effects {
            SideEffectProfile::ReadOnly => 0,
            SideEffectProfile::Destructive => 1,
            SideEffectProfile::Persistent => 2,
            SideEffectProfile::CredentialExfiltration => 3,
            SideEffectProfile::DenialOfService => 4,
            SideEffectProfile::FirmwareWrite => 5,
        });
        b.push(self.rollback.required as u8);
        put_str(&mut b, &self.rollback.description);
        b.extend((self.evidence_schema.fields.len() as u32).to_be_bytes());
        for (k, v) in &self.evidence_schema.fields {
            put_str(&mut b, k);
            b.push(match v {
                EvidenceType::Text => 1,
                EvidenceType::Integer => 2,
                EvidenceType::Boolean => 3,
                EvidenceType::Bytes => 4,
            });
        }
        b.extend(self.limits.max_bytes.to_be_bytes());
        b.extend(self.limits.max_requests.to_be_bytes());
        b.extend(self.limits.max_time.as_secs().to_be_bytes());
        b.extend(self.limits.max_fuel.to_be_bytes());
        b.extend(self.limits.max_memory_pages.to_be_bytes());
        b
    }
    pub fn sign(&mut self, key: &SigningKey) -> Result<(), AuditError> {
        self.signature = key.sign(&self.canonical_unsigned()).to_bytes();
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedManifest {
    inner: AuditManifest,
}
impl VerifiedManifest {
    pub fn module_id(&self) -> &str {
        &self.inner.module_id
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.inner.sha256
    }
    pub fn limits(&self) -> &Limits {
        &self.inner.limits
    }
    pub fn manifest(&self) -> &AuditManifest {
        &self.inner
    }
}
pub fn verify_manifest(
    manifest: &AuditManifest,
    wasm: &[u8],
    key: &VerifyingKey,
) -> Result<VerifiedManifest, AuditError> {
    // Re-run structural validation here because callers may have obtained a mutable
    // pre-verification manifest from a builder; no unchecked value may become verified.
    AuditManifest::from_parts(
        manifest.module_id.clone(),
        manifest.version,
        manifest.sha256,
        manifest.target_kind.clone(),
        manifest.capabilities.clone(),
        manifest.expected_behavior.clone(),
        manifest.side_effects.clone(),
        manifest.rollback.clone(),
        manifest.evidence_schema.clone(),
        manifest.limits.clone(),
        manifest.signature,
    )?;
    if wasm.len() as u64 > MAX_WASM_BYTES {
        return Err(AuditError::WasmTooLarge);
    }
    if Sha256::digest(wasm).as_slice() != manifest.sha256 {
        return Err(AuditError::DigestMismatch);
    }
    if !matches!(manifest.side_effects, SideEffectProfile::ReadOnly) {
        return Err(AuditError::UnsafeSideEffects(manifest.side_effects.clone()));
    }
    let sig = Signature::from_bytes(&manifest.signature);
    key.verify(&manifest.canonical_unsigned(), &sig)
        .map_err(|_| AuditError::InvalidSignature)?;
    Ok(VerifiedManifest {
        inner: manifest.clone(),
    })
}
fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend(s.as_bytes())
}
mod duration_seconds {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}
mod sig_bytes {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
}
