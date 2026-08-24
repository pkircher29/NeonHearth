use crate::transport::{MAX_RESPONSE_BYTES, NVD_URL};
use crate::{
    AdvisoryError, AdvisoryInput, AdvisorySource, Confidence, Exploitability, Exposure, Freshness,
    NormalizedAdvisory, Remediation, Severity, SourceTrust, VersionConstraint,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum NvdParseError {
    #[error("NVD document is malformed")]
    Malformed,
    #[error("NVD document exceeds limit")]
    Oversized,
    #[error(transparent)]
    Advisory(#[from] AdvisoryError),
}
pub fn parse_nvd(
    body: &str,
    retrieved_at: DateTime<Utc>,
    cache_expires_at: DateTime<Utc>,
) -> Result<Vec<NormalizedAdvisory>, NvdParseError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(NvdParseError::Oversized);
    }
    let root: Value = serde_json::from_str(body).map_err(|_| NvdParseError::Malformed)?;
    let list = root
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or(NvdParseError::Malformed)?;
    if list.len() > 2000 {
        return Err(NvdParseError::Oversized);
    };
    list.iter()
        .map(|entry| {
            let c = entry.get("cve").ok_or(NvdParseError::Malformed)?;
            let id = c
                .get("id")
                .and_then(Value::as_str)
                .filter(|s| s.starts_with("CVE-"))
                .ok_or(NvdParseError::Malformed)?;
            let title = c
                .get("descriptions")
                .and_then(Value::as_array)
                .and_then(|a| {
                    a.iter()
                        .find(|x| x.get("lang").and_then(Value::as_str) == Some("en"))
                })
                .and_then(|x| x.get("value"))
                .and_then(Value::as_str)
                .ok_or(NvdParseError::Malformed)?;
            let published = time(c, "published")?;
            let modified = time(c, "lastModified")?;
            let (vendor, product, firmware) = c
                .get("configurations")
                .and_then(Value::as_array)
                .and_then(|x| x.first())
                .and_then(|x| x.pointer("/nodes/0/cpeMatch/0"))
                .map(cpe)
                .transpose()?
                .unwrap_or(("unknown".into(), None, VersionConstraint::Any));
            let severity = severity(c);
            NormalizedAdvisory::new(AdvisoryInput {
                source: AdvisorySource::Nvd,
                source_id: id.into(),
                source_url: NVD_URL.into(),
                title: title.into(),
                vendor,
                model: product,
                firmware,
                published_at: published,
                modified_at: modified,
                retrieved_at,
                cache_expires_at,
                freshness: Freshness::Fresh,
                source_trust: SourceTrust::OfficialApi,
                severity,
                exploitability: Exploitability::Unknown,
                exposure: Exposure::Unknown,
                confidence: Confidence::Medium,
                remediation: Remediation::Upgrade,
            })
            .map_err(Into::into)
        })
        .collect()
}
fn time(c: &Value, name: &str) -> Result<DateTime<Utc>, NvdParseError> {
    c.get(name)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or(NvdParseError::Malformed)
}
fn severity(c: &Value) -> Severity {
    for key in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ] {
        if let Some(s) = c
            .pointer(&format!("/metrics/{key}/0/cvssData/baseSeverity"))
            .and_then(Value::as_str)
        {
            return match s {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MEDIUM" => Severity::Medium,
                "LOW" => Severity::Low,
                "NONE" => Severity::None,
                _ => Severity::Unknown,
            };
        }
    }
    Severity::Unknown
}
fn cpe(v: &Value) -> Result<(String, Option<String>, VersionConstraint), NvdParseError> {
    let raw = v
        .get("criteria")
        .and_then(Value::as_str)
        .ok_or(NvdParseError::Malformed)?;
    let parts: Vec<_> = raw.split(':').collect();
    if parts.len() < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
        return Err(NvdParseError::Malformed);
    }
    let vendor = parts[3].replace("\\:", ":");
    let product = parts[4].replace("\\:", ":");
    let min = v
        .get("versionStartIncluding")
        .or_else(|| v.get("versionStartExcluding"))
        .and_then(Value::as_str);
    let max = v
        .get("versionEndIncluding")
        .or_else(|| v.get("versionEndExcluding"))
        .and_then(Value::as_str);
    let fw = match (min, max, parts[5]) {
        (Some(a), Some(b), _) => VersionConstraint::Range {
            min: a.into(),
            max: b.into(),
        },
        (None, None, x) if x != "*" && x != "-" => VersionConstraint::Exact(x.into()),
        _ => VersionConstraint::Any,
    };
    Ok((vendor, Some(product), fw))
}
