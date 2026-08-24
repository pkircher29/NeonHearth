use crate::transport::{MAX_RESPONSE_BYTES, NVD_URL};
use crate::{
    AdvisoryError, AdvisoryInput, AdvisorySource, Confidence, Exploitability, Exposure, Freshness,
    MAX_PARSER_OUTPUTS, NormalizedAdvisory, Remediation, Severity, SourceTrust, VersionConstraint,
    is_strict_cve,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::BTreeSet;

pub const MAX_CPE_DEPTH: usize = 32;
pub const MAX_CPE_NODES: usize = 8_192;
const MAX_CPE_FIELD: usize = 128;
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
        let mut node_count = 0;
        let mut emitted = false;
        if let Some(configurations_value) = cve.get("configurations") {
            let configurations = configurations_value
                .as_array()
                .ok_or(NvdParseError::Malformed)?;
            for configuration in configurations {
                visit_nodes_iterative(
                    configuration.get("nodes"),
                    &mut node_count,
                    &mut |cpe_match| {
                        let Some(selector) = cpe(cpe_match)? else {
                            return Ok(());
                        };
                        if !seen.insert(selector.identity) {
                            return Ok(());
                        }
                        push_advisory(
                            &mut output,
                            id,
                            title,
                            selector.vendor,
                            selector.model,
                            selector.firmware,
                            published,
                            modified,
                            retrieved_at,
                            cache_expires_at,
                            severity,
                        )?;
                        emitted = true;
                        Ok(())
                    },
                )?;
            }
        }
        if !emitted {
            push_advisory(
                &mut output,
                id,
                title,
                "unknown".into(),
                None,
                VersionConstraint::Any,
                published,
                modified,
                retrieved_at,
                cache_expires_at,
                severity,
            )?;
        }
    }
    Ok(output)
}
#[allow(clippy::too_many_arguments)]
fn push_advisory(
    output: &mut Vec<NormalizedAdvisory>,
    id: &str,
    title: &str,
    vendor: String,
    model: Option<String>,
    firmware: VersionConstraint,
    published_at: DateTime<Utc>,
    modified_at: DateTime<Utc>,
    retrieved_at: DateTime<Utc>,
    cache_expires_at: DateTime<Utc>,
    severity: Severity,
) -> Result<(), NvdParseError> {
    if output.len() == MAX_PARSER_OUTPUTS {
        return Err(NvdParseError::Oversized);
    }
    output.push(NormalizedAdvisory::new(AdvisoryInput {
        source: AdvisorySource::Nvd,
        source_id: id.into(),
        source_url: NVD_URL.into(),
        title: title.into(),
        vendor,
        model,
        firmware,
        published_at,
        modified_at,
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

fn visit_nodes_iterative(
    nodes: Option<&Value>,
    node_count: &mut usize,
    visitor: &mut impl FnMut(&Value) -> Result<(), NvdParseError>,
) -> Result<(), NvdParseError> {
    let Some(nodes) = nodes else {
        return Ok(());
    };
    let roots = nodes.as_array().ok_or(NvdParseError::Malformed)?;
    let mut stack = Vec::new();
    push_nodes(&mut stack, roots, 1, node_count)?;
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_CPE_DEPTH {
            return Err(NvdParseError::Oversized);
        }
        if let Some(matches) = node.get("cpeMatch") {
            for cpe_match in matches.as_array().ok_or(NvdParseError::Malformed)? {
                if cpe_match.get("vulnerable").and_then(Value::as_bool) != Some(false) {
                    visitor(cpe_match)?;
                }
            }
        }
        if let Some(children) = node.get("children") {
            push_nodes(
                &mut stack,
                children.as_array().ok_or(NvdParseError::Malformed)?,
                depth + 1,
                node_count,
            )?;
        }
    }
    Ok(())
}
fn push_nodes<'a>(
    stack: &mut Vec<(&'a Value, usize)>,
    nodes: &'a [Value],
    depth: usize,
    node_count: &mut usize,
) -> Result<(), NvdParseError> {
    if depth > MAX_CPE_DEPTH || nodes.len() > MAX_CPE_NODES.saturating_sub(*node_count) {
        return Err(NvdParseError::Oversized);
    }
    *node_count += nodes.len();
    for node in nodes.iter().rev() {
        stack.push((node, depth));
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

struct Selector {
    identity: String,
    vendor: String,
    model: Option<String>,
    firmware: VersionConstraint,
}
fn cpe(value: &Value) -> Result<Option<Selector>, NvdParseError> {
    let criteria = required(value, "criteria")?;
    let parts = parse_cpe23(criteria)?;
    if parts[0].text != "cpe" || parts[0].escaped || parts[1].text != "2.3" || parts[1].escaped {
        return Err(NvdParseError::Malformed);
    }
    // Unescaped wildcard/NA in target fields is not a literal vendor or model selector.
    if parts[3].wildcard_or_na() || parts[4].wildcard_or_na() {
        return Ok(None);
    }
    let start_including = bound(value, "versionStartIncluding")?;
    let start_excluding = bound(value, "versionStartExcluding")?;
    let end_including = bound(value, "versionEndIncluding")?;
    let end_excluding = bound(value, "versionEndExcluding")?;
    if (start_including.is_some() && start_excluding.is_some())
        || (end_including.is_some() && end_excluding.is_some())
    {
        return Err(NvdParseError::Malformed);
    }
    let firmware = match (
        start_including.as_deref().or(start_excluding.as_deref()),
        end_including.as_deref().or(end_excluding.as_deref()),
        &parts[5],
    ) {
        (Some(min), Some(max), _) => VersionConstraint::Range {
            min: min.into(),
            max: max.into(),
        },
        (None, Some(max), _) => VersionConstraint::LessThan(max.into()),
        (Some(_), None, _) => VersionConstraint::Any,
        (None, None, version) if !version.wildcard_or_na() => {
            VersionConstraint::Exact(version.text.clone())
        }
        _ => VersionConstraint::Any,
    };
    Ok(Some(Selector {
        identity: format!(
            "{criteria}\u{0}si={:?}\u{0}sx={:?}\u{0}ei={:?}\u{0}ex={:?}",
            start_including, start_excluding, end_including, end_excluding
        ),
        vendor: parts[3].text.clone(),
        model: Some(parts[4].text.clone()),
        firmware,
    }))
}
fn bound(value: &Value, name: &str) -> Result<Option<String>, NvdParseError> {
    match value.get(name) {
        None => Ok(None),
        Some(value) => {
            let value = value
                .as_str()
                .filter(|value| valid_bound(value))
                .ok_or(NvdParseError::Malformed)?;
            Ok(Some(value.into()))
        }
    }
}
fn valid_bound(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_CPE_FIELD
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}
struct CpeField {
    text: String,
    escaped: bool,
}
impl CpeField {
    fn wildcard_or_na(&self) -> bool {
        !self.escaped && matches!(self.text.as_str(), "*" | "-")
    }
}
fn parse_cpe23(raw: &str) -> Result<Vec<CpeField>, NvdParseError> {
    let mut fields = vec![CpeField {
        text: String::new(),
        escaped: false,
    }];
    let mut escape = false;
    for character in raw.chars() {
        if escape {
            if !valid_cpe_escape(character) {
                return Err(NvdParseError::Malformed);
            }
            let field = fields.last_mut().expect("field exists");
            field.text.push(character);
            field.escaped = true;
            escape = false;
        } else if character == '\\' {
            escape = true;
        } else if character == ':' {
            fields.push(CpeField {
                text: String::new(),
                escaped: false,
            });
        } else if character.is_control() {
            return Err(NvdParseError::Malformed);
        } else {
            fields
                .last_mut()
                .expect("field exists")
                .text
                .push(character);
        }
        if fields
            .last()
            .is_some_and(|field| field.text.len() > MAX_CPE_FIELD)
        {
            return Err(NvdParseError::Oversized);
        }
    }
    if escape || fields.len() != 13 || fields.iter().any(|field| field.text.is_empty()) {
        return Err(NvdParseError::Malformed);
    }
    Ok(fields)
}
fn valid_cpe_escape(character: char) -> bool {
    character == '\\'
        || (!character.is_ascii_alphanumeric()
            && !character.is_whitespace()
            && !character.is_control())
}
