use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use thiserror::Error;

const DOMAIN: &[u8] = b"NeonHearth/lattice-audit-wasm/manifest/v2\0";
/// Maximum module size and aggregate exchange/evidence bytes permitted by a manifest.
const MAX_WASM_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TEXT: usize = 4096;
const MAX_FIELDS: usize = 64;
const MAX_CAPABILITIES: usize = 16;
const MAX_REQUESTS: u32 = 1024;
const MAX_TIME_SECS: u64 = 300;
const MAX_FUEL: u64 = 10_000_000_000;
const MAX_MEMORY_PAGES: u32 = 1024;
pub(crate) fn valid_limits(limits: &Limits) -> bool {
    limits.max_bytes > 0
        && limits.max_bytes <= MAX_WASM_BYTES
        && limits.max_requests > 0
        && limits.max_requests <= MAX_REQUESTS
        && !limits.max_time.is_zero()
        && limits.max_time.subsec_nanos() == 0
        && limits.max_time.as_secs() <= MAX_TIME_SECS
        && limits.max_fuel > 0
        && limits.max_fuel <= MAX_FUEL
        && limits.max_memory_pages > 0
        && limits.max_memory_pages <= MAX_MEMORY_PAGES
}

fn bounded_string<'de, D: serde::Deserializer<'de>>(d: D, max: usize) -> Result<String, D::Error> {
    struct V(usize);
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("bounded string")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<String, E> {
            if v.len() > self.0 {
                return Err(E::custom("string exceeds maximum length"));
            }
            Ok(v.to_owned())
        }
        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<String, E> {
            if v.len() > self.0 {
                return Err(E::custom("string exceeds maximum length"));
            }
            Ok(v)
        }
    }
    d.deserialize_string(V(max))
}

fn bounded_signature<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = [u8; 64];
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("exactly 64 signature bytes")
        }
        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<[u8; 64], E> {
            v.try_into()
                .map_err(|_| E::custom("signature must contain exactly 64 bytes"))
        }
        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<[u8; 64], E> {
            self.visit_bytes(&v)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<[u8; 64], A::Error> {
            let mut out = [0u8; 64];
            for slot in &mut out {
                *slot = a.next_element()?.ok_or_else(|| {
                    serde::de::Error::custom("signature must contain exactly 64 bytes")
                })?;
            }
            if a.next_element::<u8>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "signature must contain exactly 64 bytes",
                ));
            }
            Ok(out)
        }
    }
    d.deserialize_bytes(V)
}

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
    #[error("forbidden wasm import: {0}")]
    ForbiddenImport(String),
    #[error("wasm fuel exhausted")]
    FuelExhausted,
    #[error("wasm execution timed out")]
    TimedOut,
    #[error("wasm memory limit exceeded")]
    MemoryLimitExceeded,
    #[error("wasm table limit exceeded")]
    TableLimitExceeded,
    #[error("wasm output limit exceeded")]
    OutputLimitExceeded,
    #[error("wasm trap")]
    Trap,
    #[error("invalid wasm module")]
    InvalidModule,
    #[error("invalid wasm ABI")]
    InvalidAbi,
    #[error("input limit exceeded")]
    InputLimitExceeded,
    #[error("request limit exceeded")]
    RequestLimitExceeded,
    #[error("byte budget exhausted")]
    BudgetExhausted,
    #[error("audit host rejected exchange")]
    HostRejected,
    #[error("audit execution cancelled")]
    Cancelled,
    #[error("manifest names a signing key that is not trusted")]
    UnknownKey,
    #[error("manifest signing key is revoked")]
    KeyRevoked,
    #[error("module digest is revoked")]
    ModuleRevoked,
    #[error("module version is below the accepted floor")]
    ModuleRollback,
    #[error("manifest is not valid yet")]
    NotYetValid,
    #[error("manifest validity window has ended")]
    Expired,
    #[error("policy requires a bounded validity window")]
    ValidityRequired,
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
                                if out.len() == MAX_FIELDS {
                                    return Err(serde::de::Error::custom(
                                        "too many evidence fields",
                                    ));
                                }
                                if k.is_empty()
                                    || k.len() > 128
                                    || k.trim() != k
                                    || k.chars().any(char::is_control)
                                {
                                    return Err(serde::de::Error::custom(
                                        "invalid evidence field key",
                                    ));
                                }
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
    /// Which trusted key signed this manifest (see [`VerificationPolicy`]).
    pub key_id: String,
    /// Unix seconds; the signed validity window. `u64::MAX` as `valid_until`
    /// means no expiry, which a strict policy refuses.
    pub valid_from: u64,
    pub valid_until: u64,
    #[serde(serialize_with = "sig_bytes::serialize")]
    pub signature: [u8; 64],
}

const DEFAULT_KEY_ID: &str = "default";
fn default_key_id() -> String {
    DEFAULT_KEY_ID.to_owned()
}
fn default_valid_until() -> u64 {
    u64::MAX
}

impl<'de> Deserialize<'de> for AuditManifest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(deserialize_with = "deserialize_module_id")]
            module_id: String,
            version: u16,
            sha256: [u8; 32],
            target_kind: TargetKind,
            capabilities: BoundedCapabilities,
            expected_behavior: BoundedText,
            side_effects: SideEffectProfile,
            rollback: BoundedRollback,
            evidence_schema: EvidenceSchema,
            limits: Limits,
            #[serde(default = "default_key_id", deserialize_with = "deserialize_module_id")]
            key_id: String,
            #[serde(default)]
            valid_from: u64,
            #[serde(default = "default_valid_until")]
            valid_until: u64,
            #[serde(deserialize_with = "bounded_signature")]
            signature: [u8; 64],
        }
        #[derive(Deserialize)]
        struct BoundedText(#[serde(deserialize_with = "deserialize_max_text")] String);
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BoundedRollback {
            required: bool,
            #[serde(deserialize_with = "deserialize_max_text")]
            description: String,
        }
        struct BoundedCapabilities(Vec<Capability>);
        impl<'de> Deserialize<'de> for BoundedCapabilities {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = BoundedCapabilities;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        f.write_str("at most 16 capabilities")
                    }
                    fn visit_seq<A: serde::de::SeqAccess<'de>>(
                        self,
                        mut a: A,
                    ) -> Result<Self::Value, A::Error> {
                        let mut out = Vec::with_capacity(MAX_CAPABILITIES);
                        while let Some(c) = a.next_element()? {
                            if out.len() == MAX_CAPABILITIES {
                                return Err(serde::de::Error::custom("too many capabilities"));
                            }
                            out.push(c);
                        }
                        Ok(BoundedCapabilities(out))
                    }
                }
                d.deserialize_seq(V)
            }
        }
        fn deserialize_max_text<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> Result<String, D::Error> {
            bounded_string(d, MAX_TEXT)
        }
        fn deserialize_module_id<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> Result<String, D::Error> {
            bounded_string(d, 128)
        }
        let w = Wire::deserialize(d)?;
        let mut capabilities = BTreeSet::new();
        if w.capabilities.0.len() > MAX_CAPABILITIES {
            return Err(serde::de::Error::custom("too many capabilities"));
        }
        for capability in w.capabilities.0 {
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
            w.expected_behavior.0,
            w.side_effects,
            RollbackPlan {
                required: w.rollback.required,
                description: w.rollback.description,
            },
            w.evidence_schema,
            w.limits,
            w.key_id,
            w.valid_from,
            w.valid_until,
            w.signature,
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
            default_key_id(),
            0,
            u64::MAX,
            [0; 64],
        )
    }

    /// Names the signing key. Part of the signed bytes.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Result<Self, AuditError> {
        let key_id = key_id.into();
        if !valid_identifier(&key_id) {
            return Err(AuditError::InvalidManifest("noncanonical key id".into()));
        }
        self.key_id = key_id;
        Ok(self)
    }

    /// Sets the signed validity window in Unix seconds.
    pub fn with_validity(mut self, valid_from: u64, valid_until: u64) -> Result<Self, AuditError> {
        if valid_from >= valid_until {
            return Err(AuditError::InvalidManifest("empty validity window".into()));
        }
        self.valid_from = valid_from;
        self.valid_until = valid_until;
        Ok(self)
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
        key_id: String,
        valid_from: u64,
        valid_until: u64,
        signature: [u8; 64],
    ) -> Result<Self, AuditError> {
        if !valid_identifier(&key_id) || valid_from >= valid_until {
            return Err(AuditError::InvalidManifest(
                "invalid key id or validity window".into(),
            ));
        }
        if version == 0 || !valid_identifier(&module_id) {
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
            || evidence_schema.fields.keys().any(|k| {
                k.is_empty() || k.len() > 128 || k.trim() != k || k.chars().any(char::is_control)
            })
        {
            return Err(AuditError::InvalidManifest(
                "invalid evidence schema".into(),
            ));
        }
        if !valid_limits(&limits) {
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
            key_id,
            valid_from,
            valid_until,
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
        put_str(&mut b, &self.key_id);
        b.extend(self.valid_from.to_be_bytes());
        b.extend(self.valid_until.to_be_bytes());
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
    wasm: Vec<u8>,
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
    pub(crate) fn wasm(&self) -> &[u8] {
        &self.wasm
    }
}
fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// One trusted signing key.
#[derive(Clone, Debug)]
pub struct TrustedKey {
    pub key_id: String,
    pub key: VerifyingKey,
    pub revoked: bool,
}

/// What a deployment trusts: keys by id, revoked module digests, and the
/// lowest accepted version per module id. The floors are plain data so the
/// caller can persist them (`version_floors`) and restore them
/// (`with_version_floors`) across restarts.
#[derive(Clone, Debug, Default)]
pub struct VerificationPolicy {
    keys: BTreeMap<String, TrustedKey>,
    revoked_digests: BTreeSet<[u8; 32]>,
    floors: BTreeMap<String, u16>,
    require_validity_window: bool,
}

impl VerificationPolicy {
    pub fn new(keys: impl IntoIterator<Item = TrustedKey>) -> Self {
        Self {
            keys: keys.into_iter().map(|k| (k.key_id.clone(), k)).collect(),
            ..Self::default()
        }
    }
    /// Refuse manifests without an expiry.
    #[must_use]
    pub fn require_validity_window(mut self) -> Self {
        self.require_validity_window = true;
        self
    }
    #[must_use]
    pub fn revoke_digest(mut self, sha256: [u8; 32]) -> Self {
        self.revoked_digests.insert(sha256);
        self
    }
    #[must_use]
    pub fn with_version_floors(mut self, floors: BTreeMap<String, u16>) -> Self {
        self.floors = floors;
        self
    }
    pub fn version_floors(&self) -> &BTreeMap<String, u16> {
        &self.floors
    }
    /// Raises the floor to a manifest that was accepted and is being
    /// installed, so an older signed manifest can no longer be replayed.
    pub fn record_accepted(&mut self, accepted: &VerifiedManifest) {
        let manifest = accepted.manifest();
        let floor = self.floors.entry(manifest.module_id.clone()).or_insert(0);
        *floor = (*floor).max(manifest.version);
    }
}

/// Verifies against a policy at `now_unix` seconds: trusted and unrevoked key
/// id, signature, digest, validity window, revoked digests, and version floor.
pub fn verify_manifest_with_policy(
    manifest: &AuditManifest,
    wasm: &[u8],
    policy: &VerificationPolicy,
    now_unix: u64,
) -> Result<VerifiedManifest, AuditError> {
    let trusted = policy
        .keys
        .get(&manifest.key_id)
        .ok_or(AuditError::UnknownKey)?;
    if trusted.revoked {
        return Err(AuditError::KeyRevoked);
    }
    if policy.require_validity_window && manifest.valid_until == u64::MAX {
        return Err(AuditError::ValidityRequired);
    }
    if now_unix < manifest.valid_from {
        return Err(AuditError::NotYetValid);
    }
    if now_unix > manifest.valid_until {
        return Err(AuditError::Expired);
    }
    if policy.revoked_digests.contains(&manifest.sha256) {
        return Err(AuditError::ModuleRevoked);
    }
    if policy
        .floors
        .get(&manifest.module_id)
        .is_some_and(|floor| manifest.version < *floor)
    {
        return Err(AuditError::ModuleRollback);
    }
    verify_manifest(manifest, wasm, &trusted.key)
}

/// Verifies signature, digest and structure against one key. It does not
/// check the validity window, revocation or version floor; deployments use
/// [`verify_manifest_with_policy`].
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
        manifest.key_id.clone(),
        manifest.valid_from,
        manifest.valid_until,
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
    // Strict verification rejects non-canonical S values and small-order
    // components, matching the advisory crate's vendor-key check.
    key.verify_strict(&manifest.canonical_unsigned(), &sig)
        .map_err(|_| AuditError::InvalidSignature)?;
    Ok(VerifiedManifest {
        inner: manifest.clone(),
        wasm: wasm.to_vec(),
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
