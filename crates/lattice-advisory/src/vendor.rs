//! Registered vendor advisories use the fixed `neonhearth.vendor-advisory.v1` JSON schema.
//! A detached signature covers `b"NeonHearth vendor advisory v1\0" || raw UTF-8 body` exactly;
//! whitespace or key-order changes invalidate it. The parsed JSON is never reserialized to sign.
//! Vendor bodies are capped at 1 MiB and each source produces at most 2,000 advisories.
use crate::{
    AdvisoryError, AdvisoryInput, AdvisorySource, Confidence, Exploitability, Exposure, Freshness,
    MAX_PARSER_OUTPUTS, NormalizedAdvisory, Remediation, Severity, SourceTrust, VersionConstraint,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

pub const VENDOR_SCHEMA_ID: &str = "neonhearth.vendor-advisory.v1";
pub const MAX_VENDOR_BYTES: usize = 1024 * 1024;
const SIGNING_PREFIX: &[u8] = b"NeonHearth vendor advisory v1\0";

#[derive(Clone)]
pub struct VendorSource {
    url: String,
    schema_id: &'static str,
    key_id: Option<String>,
    public_key: Option<[u8; 32]>,
    enabled: bool,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
}
impl VendorSource {
    pub fn unsigned(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            schema_id: VENDOR_SCHEMA_ID,
            key_id: None,
            public_key: None,
            enabled: true,
            valid_from: None,
            valid_until: None,
        }
    }
    pub fn signed(url: impl Into<String>, key_id: impl Into<String>, public_key: [u8; 32]) -> Self {
        Self {
            url: url.into(),
            schema_id: VENDOR_SCHEMA_ID,
            key_id: Some(key_id.into()),
            public_key: Some(public_key),
            enabled: true,
            valid_from: None,
            valid_until: None,
        }
    }
    pub fn with_validity(
        mut self,
        valid_from: Option<DateTime<Utc>>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        self.valid_from = valid_from;
        self.valid_until = valid_until;
        self
    }
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}
#[derive(Clone, Default)]
pub struct VendorRegistry {
    sources: Vec<VendorSource>,
}
impl VendorRegistry {
    pub fn new(sources: impl IntoIterator<Item = VendorSource>) -> Self {
        Self {
            sources: sources.into_iter().collect(),
        }
    }
}
/// Detached, canonical base64url-without-padding Ed25519 signature. Do not log or debug this value.
pub struct VendorSignature {
    key_id: String,
    encoded: String,
}
impl VendorSignature {
    pub fn new(key_id: impl Into<String>, encoded: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            encoded: encoded.into(),
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum VendorParseError {
    #[error("vendor document is malformed or unregistered")]
    Malformed,
    #[error("vendor document exceeds limit")]
    Oversized,
    #[error("vendor advisory is invalid")]
    Advisory(#[from] AdvisoryError),
}

pub fn parse_vendor(
    body: &str,
    source_url: &str,
    signature: Option<&VendorSignature>,
    retrieved_at: DateTime<Utc>,
    cache_expires_at: DateTime<Utc>,
    registry: &VendorRegistry,
) -> Result<Vec<NormalizedAdvisory>, VendorParseError> {
    if body.len() > MAX_VENDOR_BYTES {
        return Err(VendorParseError::Oversized);
    }
    let source = registry
        .sources
        .iter()
        .find(|source| source.url == source_url)
        .ok_or(VendorParseError::Malformed)?;
    if source.schema_id != VENDOR_SCHEMA_ID
        || !is_https(source_url)
        || (!source.enabled && signature.is_none())
    {
        return Err(VendorParseError::Malformed);
    }
    let document: VendorDocument =
        serde_json::from_str(body).map_err(|_| VendorParseError::Malformed)?;
    if document.schema_id != VENDOR_SCHEMA_ID {
        return Err(VendorParseError::Malformed);
    }
    if document.advisories.len() > MAX_PARSER_OUTPUTS {
        return Err(VendorParseError::Oversized);
    }
    let (source_trust, confidence) = trust(source, signature, body.as_bytes(), retrieved_at);
    document
        .advisories
        .into_iter()
        .map(|entry| {
            NormalizedAdvisory::new(AdvisoryInput {
                source: AdvisorySource::Vendor,
                source_id: entry.id,
                source_url: source_url.into(),
                title: entry.title,
                vendor: entry.vendor,
                model: entry.model,
                firmware: VersionConstraint::Exact(entry.version),
                published_at: entry.published_at,
                modified_at: entry.modified_at,
                retrieved_at,
                cache_expires_at,
                freshness: Freshness::Fresh,
                source_trust,
                severity: entry.severity.into(),
                exploitability: Exploitability::Unknown,
                exposure: Exposure::Unknown,
                confidence,
                remediation: entry.remediation.into(),
            })
            .map_err(Into::into)
        })
        .collect()
}
fn trust(
    source: &VendorSource,
    signature: Option<&VendorSignature>,
    body: &[u8],
    retrieved_at: DateTime<Utc>,
) -> (SourceTrust, Confidence) {
    let Some(signature) = signature else {
        return (SourceTrust::RegisteredHttps, Confidence::Low);
    };
    let valid_time = source.valid_from.is_none_or(|time| retrieved_at >= time)
        && source.valid_until.is_none_or(|time| retrieved_at <= time);
    let verified = source.enabled
        && valid_time
        && source.key_id.as_deref() == Some(signature.key_id.as_str())
        && source
            .public_key
            .is_some_and(|key| verify(key, &signature.encoded, body));
    if verified {
        (SourceTrust::VerifiedSignature, Confidence::High)
    } else {
        (SourceTrust::Invalid, Confidence::Low)
    }
}
fn verify(key: [u8; 32], encoded: &str, body: &[u8]) -> bool {
    if encoded.contains('=') || encoded.len() != 86 {
        return false;
    }
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded) else {
        return false;
    };
    let Ok(signature) =
        <[u8; 64]>::try_from(bytes.as_slice()).map(|bytes| Signature::from_bytes(&bytes))
    else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    let mut message = Vec::with_capacity(SIGNING_PREFIX.len() + body.len());
    message.extend_from_slice(SIGNING_PREFIX);
    message.extend_from_slice(body);
    key.verify_strict(&message, &signature).is_ok()
}
fn is_https(url: &str) -> bool {
    url::Url::parse(url).ok().is_some_and(|url| {
        url.scheme() == "https"
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VendorDocument {
    schema_id: String,
    advisories: Vec<VendorAdvisory>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VendorAdvisory {
    id: String,
    title: String,
    vendor: String,
    model: Option<String>,
    version: String,
    published_at: DateTime<Utc>,
    modified_at: DateTime<Utc>,
    severity: VendorSeverity,
    remediation: VendorRemediation,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum VendorSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}
impl From<VendorSeverity> for Severity {
    fn from(value: VendorSeverity) -> Self {
        match value {
            VendorSeverity::None => Self::None,
            VendorSeverity::Low => Self::Low,
            VendorSeverity::Medium => Self::Medium,
            VendorSeverity::High => Self::High,
            VendorSeverity::Critical => Self::Critical,
            VendorSeverity::Unknown => Self::Unknown,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum VendorRemediation {
    Upgrade,
    Mitigate,
    Monitor,
    None,
    Unknown,
}
impl From<VendorRemediation> for Remediation {
    fn from(value: VendorRemediation) -> Self {
        match value {
            VendorRemediation::Upgrade => Self::Upgrade,
            VendorRemediation::Mitigate => Self::Mitigate,
            VendorRemediation::Monitor => Self::Monitor,
            VendorRemediation::None => Self::None,
            VendorRemediation::Unknown => Self::Unknown,
        }
    }
}
