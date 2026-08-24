use crate::transport::{MAX_RESPONSE_BYTES, NVD_URL};
use crate::{
    AdvisoryError, AdvisoryInput, AdvisorySource, Confidence, Exploitability, Exposure, Freshness,
    MAX_PARSER_OUTPUTS, NormalizedAdvisory, Remediation, Severity, SourceTrust, VersionConstraint,
    is_strict_cve,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::BTreeSet;
#[derive(Debug, thiserror::Error)]
pub enum NvdParseError {
    #[error("NVD document is malformed")]
    Malformed,
    #[error("NVD document exceeds limit")]
    Oversized,
    #[error("NVD advisory is invalid")]
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
    let vulnerabilities = root
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or(NvdParseError::Malformed)?;
    if vulnerabilities.len() > MAX_PARSER_OUTPUTS {
        return Err(NvdParseError::Oversized);
    }
    let mut output = Vec::new();
    for entry in vulnerabilities {
        let cve = entry.get("cve").ok_or(NvdParseError::Malformed)?;
        let id = required(cve, "id")?;
        if !is_strict_cve(id) {
            return Err(NvdParseError::Malformed);
        }
        let title = cve
            .get("descriptions")
            .and_then(Value::as_array)
            .and_then(|xs| {
                xs.iter()
                    .find(|x| x.get("lang").and_then(Value::as_str) == Some("en"))
            })
            .and_then(|x| x.get("value"))
            .and_then(Value::as_str)
            .ok_or(NvdParseError::Malformed)?;
        let published = time(cve, "published")?;
        let modified = time(cve, "lastModified")?;
        let severity = severity(cve);
        let mut seen = BTreeSet::new();
        if let Some(configurations) = cve.get("configurations").and_then(Value::as_array) {
            for configuration in configurations {
                visit_nodes(configuration.get("nodes"), &mut |cpe_match| {
                    let parsed = cpe(cpe_match)?;
                    // CPE criteria is the stable identity. Keep the first occurrence in JSON traversal order.
                    if !seen.insert(parsed.0) {
                        return Ok(());
                    }
                    if output.len() == MAX_PARSER_OUTPUTS {
                        return Err(NvdParseError::Oversized);
                    }
                    output.push(NormalizedAdvisory::new(AdvisoryInput {
                        source: AdvisorySource::Nvd,
                        source_id: id.to_owned(),
                        source_url: NVD_URL.into(),
                        title: title.into(),
                        vendor: parsed.1,
                        model: Some(parsed.2),
                        firmware: parsed.3,
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
                    })?);
                    Ok(())
                })?;
            }
        }
    }
    Ok(output)
}
fn required<'a>(value: &'a Value, field: &str) -> Result<&'a str, NvdParseError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .ok_or(NvdParseError::Malformed)
}
fn time(cve: &Value, field: &str) -> Result<DateTime<Utc>, NvdParseError> {
    required(cve, field)?
        .parse()
        .map_err(|_| NvdParseError::Malformed)
}
fn visit_nodes(
    nodes: Option<&Value>,
    visitor: &mut impl FnMut(&Value) -> Result<(), NvdParseError>,
) -> Result<(), NvdParseError> {
    let Some(nodes) = nodes else {
        return Ok(());
    };
    for node in nodes.as_array().ok_or(NvdParseError::Malformed)? {
        if let Some(matches) = node.get("cpeMatch") {
            for cpe_match in matches.as_array().ok_or(NvdParseError::Malformed)? {
                if cpe_match.get("vulnerable").and_then(Value::as_bool) != Some(false) {
                    visitor(cpe_match)?;
                }
            }
        }
        visit_nodes(node.get("children"), visitor)?;
    }
    Ok(())
}
fn severity(cve: &Value) -> Severity {
    let Some(metrics) = cve.get("metrics").and_then(Value::as_object) else {
        return Severity::Unknown;
    };
    for key in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ] {
        let Some(values) = metrics.get(key) else {
            continue;
        };
        let Some(values) = values.as_array() else {
            return Severity::Unknown;
        };
        let score = values
            .iter()
            .filter_map(|value| value.pointer("/cvssData/baseScore").and_then(Value::as_f64))
            .filter(|score| score.is_finite() && (0.0..=10.0).contains(score))
            .max_by(f64::total_cmp);
        return score.map(severity_for_score).unwrap_or(Severity::Unknown);
    }
    Severity::Unknown
}
fn severity_for_score(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::None
    }
}
fn cpe(value: &Value) -> Result<(String, String, String, VersionConstraint), NvdParseError> {
    let criteria = required(value, "criteria")?;
    let parts = parse_cpe23(criteria)?;
    if parts[0] != "cpe" || parts[1] != "2.3" {
        return Err(NvdParseError::Malformed);
    }
    let start = value
        .get("versionStartIncluding")
        .or_else(|| value.get("versionStartExcluding"))
        .and_then(Value::as_str);
    let end = value
        .get("versionEndIncluding")
        .or_else(|| value.get("versionEndExcluding"))
        .and_then(Value::as_str);
    let firmware = match (start, end, parts[5].as_str()) {
        (Some(min), Some(max), _) if valid_bound(min) && valid_bound(max) => {
            VersionConstraint::Range {
                min: min.into(),
                max: max.into(),
            }
        }
        (None, Some(max), _) if valid_bound(max) => VersionConstraint::LessThan(max.into()),
        (Some(_), None, _) => VersionConstraint::Any,
        (None, None, version) if version != "*" && version != "-" => {
            VersionConstraint::Exact(version.into())
        }
        _ => VersionConstraint::Any,
    };
    Ok((
        criteria.into(),
        parts[3].clone(),
        parts[4].clone(),
        firmware,
    ))
}
fn valid_bound(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 128
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}
fn parse_cpe23(raw: &str) -> Result<Vec<String>, NvdParseError> {
    let mut fields = vec![String::new()];
    let mut escaped = false;
    for character in raw.chars() {
        if escaped {
            fields.last_mut().expect("field exists").push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            fields.push(String::new());
        } else {
            fields.last_mut().expect("field exists").push(character);
        }
    }
    if escaped || fields.len() != 13 || fields.iter().any(String::is_empty) {
        return Err(NvdParseError::Malformed);
    }
    Ok(fields)
}
