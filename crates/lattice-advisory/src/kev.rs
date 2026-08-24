use crate::transport::{KEV_URL, MAX_RESPONSE_BYTES};
use crate::{
    AdvisoryError, AdvisoryInput, AdvisorySource, Confidence, Exploitability, Exposure, Freshness,
    MAX_FIELD, MAX_PARSER_OUTPUTS, NormalizedAdvisory, Remediation, Severity, SourceTrust,
    VersionConstraint, is_strict_cve,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::Value;
#[derive(Debug, thiserror::Error)]
pub enum KevParseError {
    #[error("KEV document is malformed")]
    Malformed,
    #[error("KEV document exceeds limit")]
    Oversized,
    #[error("KEV advisory is invalid")]
    Advisory(#[from] AdvisoryError),
}
pub fn parse_kev(
    body: &str,
    retrieved_at: DateTime<Utc>,
    cache_expires_at: DateTime<Utc>,
) -> Result<Vec<NormalizedAdvisory>, KevParseError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(KevParseError::Oversized);
    }
    let root: Value = serde_json::from_str(body).map_err(|_| KevParseError::Malformed)?;
    let entries = root
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or(KevParseError::Malformed)?;
    if entries.len() > MAX_PARSER_OUTPUTS {
        return Err(KevParseError::Oversized);
    }
    entries
        .iter()
        .map(|entry| {
            let value = |field| {
                entry
                    .get(field)
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .ok_or(KevParseError::Malformed)
            };
            let id = value("cveID")?;
            if !is_strict_cve(id) {
                return Err(KevParseError::Malformed);
            }
            let added = date(value("dateAdded")?)?;
            let due = date(value("dueDate")?)?;
            let ransomware = value("knownRansomwareCampaignUse")?;
            if !matches!(ransomware, "Known" | "Unknown") {
                return Err(KevParseError::Malformed);
            }
            discarded(value("shortDescription")?)?;
            discarded(value("requiredAction")?)?;
            discarded(ransomware)?;
            NormalizedAdvisory::new(AdvisoryInput {
                source: AdvisorySource::CisaKev,
                source_id: id.into(),
                source_url: KEV_URL.into(),
                title: value("vulnerabilityName")?.into(),
                vendor: value("vendorProject")?.into(),
                model: Some(value("product")?.into()),
                firmware: VersionConstraint::Any,
                published_at: added,
                modified_at: added,
                retrieved_at,
                cache_expires_at,
                freshness: Freshness::Fresh,
                source_trust: SourceTrust::OfficialApi,
                severity: Severity::Unknown,
                exploitability: Exploitability::ActiveKnownExploitation,
                exposure: Exposure::Unknown,
                confidence: Confidence::Medium,
                remediation: if due < retrieved_at {
                    Remediation::Mitigate
                } else {
                    Remediation::Upgrade
                },
            })
            .map_err(Into::into)
        })
        .collect()
}
fn discarded(value: &str) -> Result<(), KevParseError> {
    if value.len() > MAX_FIELD || value.chars().any(char::is_control) {
        Err(KevParseError::Malformed)
    } else {
        Ok(())
    }
}
fn date(value: &str) -> Result<DateTime<Utc>, KevParseError> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| KevParseError::Malformed)?
        .and_hms_opt(0, 0, 0)
        .ok_or(KevParseError::Malformed)
        .map(|value| value.and_utc())
}
