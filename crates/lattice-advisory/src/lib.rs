#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn at(seconds: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).single().unwrap()
    }

    #[test]
    fn normalized_advisory_requires_source_identity_and_freshness() {
        let err = NormalizedAdvisory::new(AdvisoryInput {
            source: AdvisorySource::Nvd,
            source_id: String::new(),
            source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
            title: "CVE".into(),
            vendor: "Acme".into(),
            model: None,
            firmware: VersionConstraint::Any,
            published_at: at(0),
            modified_at: at(0),
            retrieved_at: at(1),
            cache_expires_at: at(2),
            freshness: Freshness::Fresh,
            source_trust: SourceTrust::OfficialApi,
            severity: Severity::High,
            exploitability: Exploitability::Unknown,
            exposure: Exposure::Unknown,
            confidence: Confidence::Low,
            remediation: Remediation::Unknown,
        });
        assert!(matches!(err, Err(AdvisoryError::MissingSourceId)));
    }

    fn input() -> AdvisoryInput {
        AdvisoryInput {
            source: AdvisorySource::Nvd,
            source_id: "CVE-1".into(),
            source_url: "https://example.test/a".into(),
            title: "title".into(),
            vendor: "Acme".into(),
            model: None,
            firmware: VersionConstraint::Any,
            published_at: at(0),
            modified_at: at(0),
            retrieved_at: at(1),
            cache_expires_at: at(2),
            freshness: Freshness::Fresh,
            source_trust: SourceTrust::OfficialApi,
            severity: Severity::High,
            exploitability: Exploitability::Unknown,
            exposure: Exposure::Unknown,
            confidence: Confidence::Low,
            remediation: Remediation::Unknown,
        }
    }

    #[test]
    fn future_source_timestamp_is_classified_without_trusting_it() {
        let mut value = input();
        value.modified_at = at(2);
        let normalized = NormalizedAdvisory::new(value).unwrap();
        assert_eq!(normalized.input().freshness, Freshness::FutureDated);
    }

    #[test]
    fn unsafe_and_unbounded_text_is_rejected() {
        let mut value = input();
        value.source_url = "http://example.test".into();
        assert!(matches!(
            NormalizedAdvisory::new(value),
            Err(AdvisoryError::NonHttpsUrl)
        ));
        let mut value = input();
        value.title = "x\n".into();
        assert!(matches!(
            NormalizedAdvisory::new(value),
            Err(AdvisoryError::ControlCharacters("title"))
        ));
        let mut value = input();
        value.vendor = "x".repeat(MAX_FIELD + 1);
        assert!(matches!(
            NormalizedAdvisory::new(value),
            Err(AdvisoryError::OversizeField("vendor"))
        ));
    }

    #[test]
    fn provenance_is_deterministic() {
        let first = NormalizedAdvisory::new(input()).unwrap();
        let second = NormalizedAdvisory::new(input()).unwrap();
        assert_eq!(first.provenance_sha256(), second.provenance_sha256());
        assert_eq!(first.provenance_sha256().len(), 64);
    }

    #[test]
    fn serde_round_trip_recomputes_and_verifies_provenance() {
        let value = NormalizedAdvisory::new(input()).unwrap();
        let json = serde_json::to_string(&value).unwrap();
        let restored: NormalizedAdvisory = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.provenance_sha256(), value.provenance_sha256());
        let tampered = json.replace(value.provenance_sha256(), &"0".repeat(64));
        assert!(serde_json::from_str::<NormalizedAdvisory>(&tampered).is_err());
    }

    #[test]
    fn future_dated_claim_without_future_timestamp_is_rejected() {
        let mut value = input();
        value.freshness = Freshness::FutureDated;
        assert!(matches!(
            NormalizedAdvisory::new(value),
            Err(AdvisoryError::InvalidFreshness)
        ));
    }

    #[test]
    fn opaque_equal_range_bounds_are_accepted() {
        let mut value = input();
        value.firmware = VersionConstraint::Range {
            min: "vendor-format".into(),
            max: "vendor-format".into(),
        };
        assert!(NormalizedAdvisory::new(value).is_ok());
    }
}
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_FIELD: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AdvisorySource {
    Nvd,
    CisaKev,
    Vendor,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Freshness {
    Fresh,
    Stale,
    FutureDated,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceTrust {
    OfficialApi,
    VerifiedSignature,
    RegisteredHttps,
    Invalid,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Exploitability {
    None,
    ProofOfConcept,
    ActiveKnownExploitation,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Exposure {
    NotExposed,
    PotentiallyExposed,
    Exposed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Remediation {
    Upgrade,
    Mitigate,
    Monitor,
    None,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum VersionConstraint {
    Any,
    Exact(String),
    LessThan(String),
    Range { min: String, max: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvisoryInput {
    pub source: AdvisorySource,
    pub source_id: String,
    pub source_url: String,
    pub title: String,
    pub vendor: String,
    pub model: Option<String>,
    pub firmware: VersionConstraint,
    pub published_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub retrieved_at: DateTime<Utc>,
    pub cache_expires_at: DateTime<Utc>,
    pub freshness: Freshness,
    pub source_trust: SourceTrust,
    pub severity: Severity,
    pub exploitability: Exploitability,
    pub exposure: Exposure,
    pub confidence: Confidence,
    pub remediation: Remediation,
}

#[derive(Clone, Debug, Serialize)]
pub struct NormalizedAdvisory {
    input: AdvisoryInput,
    provenance_sha256: String,
}

impl NormalizedAdvisory {
    pub fn input(&self) -> &AdvisoryInput {
        &self.input
    }
    pub fn provenance_sha256(&self) -> &str {
        &self.provenance_sha256
    }
}

#[derive(Deserialize)]
struct WireAdvisory {
    input: AdvisoryInput,
    provenance_sha256: String,
}

impl<'de> Deserialize<'de> for NormalizedAdvisory {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WireAdvisory::deserialize(deserializer)?;
        let normalized = Self::new(wire.input).map_err(serde::de::Error::custom)?;
        if normalized.provenance_sha256 != wire.provenance_sha256 {
            return Err(serde::de::Error::custom("provenance hash mismatch"));
        }
        Ok(normalized)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AdvisoryError {
    #[error("source id is missing")]
    MissingSourceId,
    #[error("field is missing: {0}")]
    MissingField(&'static str),
    #[error("field is too long: {0}")]
    OversizeField(&'static str),
    #[error("field contains control characters: {0}")]
    ControlCharacters(&'static str),
    #[error("source URL must be HTTPS")]
    NonHttpsUrl,
    #[error("source URL contains credentials or is malformed")]
    UnsafeUrl,
    #[error("modified timestamp predates published timestamp")]
    InvalidChronology,
    #[error("cache expiry predates retrieval timestamp")]
    InvalidCacheWindow,
    #[error("future-dated freshness requires a future source timestamp")]
    InvalidFreshness,
    #[error("invalid firmware version constraint")]
    InvalidVersion,
    #[error("could not canonicalize advisory: {0}")]
    Serialization(String),
}

impl NormalizedAdvisory {
    pub fn new(mut input: AdvisoryInput) -> Result<Self, AdvisoryError> {
        if input.source_id.trim().is_empty() {
            return Err(AdvisoryError::MissingSourceId);
        }
        validate_text("source_id", &input.source_id)?;
        validate_url(&input.source_url)?;
        validate_text("title", &input.title)?;
        validate_text("vendor", &input.vendor)?;
        if let Some(model) = &input.model {
            validate_text("model", model)?;
        }
        validate_version(&input.firmware)?;
        if input.modified_at < input.published_at {
            return Err(AdvisoryError::InvalidChronology);
        }
        if input.cache_expires_at < input.retrieved_at {
            return Err(AdvisoryError::InvalidCacheWindow);
        }
        let future =
            input.published_at > input.retrieved_at || input.modified_at > input.retrieved_at;
        if input.freshness == Freshness::FutureDated && !future {
            return Err(AdvisoryError::InvalidFreshness);
        }
        if future {
            input.freshness = Freshness::FutureDated;
        }
        let canonical =
            serde_json::to_vec(&input).map_err(|e| AdvisoryError::Serialization(e.to_string()))?;
        let digest = Sha256::digest(canonical);
        Ok(Self {
            input,
            provenance_sha256: format!("{digest:x}"),
        })
    }
}

fn validate_text(name: &'static str, value: &str) -> Result<(), AdvisoryError> {
    if value.trim().is_empty() {
        return Err(AdvisoryError::MissingField(name));
    }
    if value.len() > MAX_FIELD {
        return Err(AdvisoryError::OversizeField(name));
    }
    if value.chars().any(char::is_control) {
        return Err(AdvisoryError::ControlCharacters(name));
    }
    Ok(())
}
fn validate_url(url: &str) -> Result<(), AdvisoryError> {
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) || url.contains('\\') {
        return Err(AdvisoryError::UnsafeUrl);
    }
    let parsed = url::Url::parse(url).map_err(|_| AdvisoryError::UnsafeUrl)?;
    if parsed.scheme() != "https" {
        return Err(AdvisoryError::NonHttpsUrl);
    }
    if parsed.host().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(AdvisoryError::UnsafeUrl);
    }
    validate_text("source_url", url)
}
fn validate_version(v: &VersionConstraint) -> Result<(), AdvisoryError> {
    let valid = |s: &str| {
        !s.trim().is_empty()
            && s.len() <= 128
            && !s.chars().any(|c| c.is_control() || c.is_whitespace())
    };
    let ok = match v {
        VersionConstraint::Any => true,
        VersionConstraint::Exact(s) | VersionConstraint::LessThan(s) => valid(s),
        VersionConstraint::Range { min, max } => valid(min) && valid(max),
    };
    if ok {
        Ok(())
    } else {
        Err(AdvisoryError::InvalidVersion)
    }
}
pub mod feed;
pub mod kev;
pub mod nvd;
pub mod transport;
