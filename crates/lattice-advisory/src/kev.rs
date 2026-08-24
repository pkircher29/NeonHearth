use crate::transport::{KEV_URL, MAX_RESPONSE_BYTES};
use crate::{
    AdvisoryError, AdvisoryInput, AdvisorySource, Confidence, Exploitability, Exposure, Freshness,
    NormalizedAdvisory, Remediation, Severity, SourceTrust, VersionConstraint,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::Value;
#[derive(Debug, thiserror::Error)]
pub enum KevParseError {
    #[error("KEV document is malformed")]
    Malformed,
    #[error("KEV document exceeds limit")]
    Oversized,
    #[error(transparent)]
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
    let xs = root
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or(KevParseError::Malformed)?;
    xs.iter()
        .map(|x| {
            let get = |n| {
                x.get(n)
                    .and_then(Value::as_str)
                    .ok_or(KevParseError::Malformed)
            };
            let id = get("cveID")?;
            let vendor = get("vendorProject")?;
            let product = get("product")?;
            let title = get("vulnerabilityName")?;
            let added = NaiveDate::parse_from_str(get("dateAdded")?, "%Y-%m-%d")
                .map_err(|_| KevParseError::Malformed)?
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc();
            let active = matches!(get("knownRansomwareCampaignUse")?, "Known" | "Yes");
            NormalizedAdvisory::new(AdvisoryInput {
                source: AdvisorySource::CisaKev,
                source_id: id.into(),
                source_url: KEV_URL.into(),
                title: title.into(),
                vendor: vendor.into(),
                model: Some(product.into()),
                firmware: VersionConstraint::Any,
                published_at: added,
                modified_at: added,
                retrieved_at,
                cache_expires_at,
                freshness: Freshness::Fresh,
                source_trust: SourceTrust::OfficialApi,
                severity: Severity::Unknown,
                exploitability: if active {
                    Exploitability::ActiveKnownExploitation
                } else {
                    Exploitability::Unknown
                },
                exposure: Exposure::Unknown,
                confidence: Confidence::Medium,
                remediation: Remediation::Upgrade,
            })
            .map_err(Into::into)
        })
        .collect()
}
