use crate::{
    AdvisorySource, Confidence, Exploitability, Exposure, Freshness, MAX_FIELD, NormalizedAdvisory,
    Remediation, Severity, SourceTrust, VersionConstraint,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_EXPLANATION: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceIdentity {
    vendor: String,
    model: Option<String>,
    firmware: Option<String>,
    contradictory_high_confidence: bool,
}

impl DeviceIdentity {
    pub fn new(
        vendor: impl Into<String>,
        model: Option<String>,
        firmware: Option<String>,
    ) -> Result<Self, MatchError> {
        let vendor = vendor.into();
        validate_device_field("vendor", &vendor)?;
        if let Some(value) = &model {
            validate_device_field("model", value)?;
        }
        if let Some(value) = &firmware {
            validate_device_field("firmware", value)?;
        }
        Ok(Self {
            vendor,
            model,
            firmware,
            contradictory_high_confidence: false,
        })
    }
    pub fn known(
        vendor: impl Into<String>,
        model: impl Into<String>,
        firmware: impl Into<String>,
    ) -> Result<Self, MatchError> {
        Self::new(vendor, Some(model.into()), Some(firmware.into()))
    }
    pub fn contradictory_high_confidence(mut self, value: bool) -> Self {
        self.contradictory_high_confidence = value;
        self
    }
    pub fn vendor(&self) -> &str {
        &self.vendor
    }
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }
    pub fn firmware(&self) -> Option<&str> {
        self.firmware.as_deref()
    }
    pub fn has_contradictory_high_confidence(&self) -> bool {
        self.contradictory_high_confidence
    }
}

fn validate_device_field(name: &'static str, value: &str) -> Result<(), MatchError> {
    if value.is_empty()
        || value.len() > MAX_FIELD
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(MatchError::InvalidDeviceField(name))
    } else {
        Ok(())
    }
}
#[derive(Deserialize)]
struct DeviceIdentityWire {
    vendor: String,
    model: Option<String>,
    firmware: Option<String>,
    contradictory_high_confidence: bool,
}
impl<'de> Deserialize<'de> for DeviceIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = DeviceIdentityWire::deserialize(deserializer)?;
        Self::new(wire.vendor, wire.model, wire.firmware)
            .map(|d| d.contradictory_high_confidence(wire.contradictory_high_confidence))
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MatchLabel {
    Exact,
    Possible,
    Contradicted,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MatchedField {
    Vendor,
    Model,
    Firmware,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdvisoryMatch {
    label: MatchLabel,
    matched_fields: Vec<MatchedField>,
    explanation: String,
    confidence: Confidence,
}
impl AdvisoryMatch {
    pub fn label(&self) -> MatchLabel {
        self.label
    }
    pub fn matched_fields(&self) -> &[MatchedField] {
        &self.matched_fields
    }
    pub fn explanation(&self) -> &str {
        &self.explanation
    }
    pub fn confidence(&self) -> Confidence {
        self.confidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceEvidence {
    pub exposure: Exposure,
    pub confidence: Confidence,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RiskDimensions {
    pub severity: Severity,
    pub exploitability: Exploitability,
    pub exposure: Exposure,
    pub confidence: Confidence,
    pub remediation: Remediation,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MatchError {
    #[error("invalid device field: {0}")]
    InvalidDeviceField(&'static str),
    #[error("cannot compose advisories with mixed source IDs")]
    MixedSourceIds,
    #[error("advisory group is empty or oversized")]
    InvalidGroup,
}

pub trait DeviceInput {
    fn as_device(&self) -> Option<&DeviceIdentity>;
}
impl DeviceInput for &DeviceIdentity {
    fn as_device(&self) -> Option<&DeviceIdentity> {
        Some(self)
    }
}
impl DeviceInput for Option<&DeviceIdentity> {
    fn as_device(&self) -> Option<&DeviceIdentity> {
        *self
    }
}

pub fn match_advisory<D: DeviceInput>(
    device: D,
    advisory: &NormalizedAdvisory,
) -> Result<AdvisoryMatch, MatchError> {
    let input = advisory.input();
    let selectors = !input.vendor.eq_ignore_ascii_case("unknown")
        || input.model.is_some()
        || !matches!(input.firmware, VersionConstraint::Any);
    if input.source_trust == SourceTrust::Invalid {
        return Ok(result(
            MatchLabel::Unknown,
            vec![],
            "source trust is invalid",
            Confidence::Low,
        ));
    }
    if !selectors {
        return Ok(result(
            MatchLabel::Unknown,
            vec![],
            "advisory has no usable identity selectors",
            Confidence::Low,
        ));
    }
    let Some(device) = device.as_device() else {
        return Ok(result(
            MatchLabel::Possible,
            vec![],
            "device evidence is unavailable",
            Confidence::Low,
        ));
    };
    let vendor_match = input.vendor.eq_ignore_ascii_case("unknown")
        || input.vendor.eq_ignore_ascii_case(device.vendor());
    let model_match = input
        .model
        .as_ref()
        .is_none_or(|m| device.model().is_some_and(|d| m.eq_ignore_ascii_case(d)));
    let firmware_match = match &input.firmware {
        VersionConstraint::Exact(v) => device
            .firmware()
            .is_some_and(|d| v.as_bytes() == d.as_bytes()),
        VersionConstraint::Any
        | VersionConstraint::LessThan(_)
        | VersionConstraint::Range { .. } => true,
    };
    let contradiction = !vendor_match
        || input
            .model
            .as_ref()
            .is_some_and(|_| device.model().is_some() && !model_match)
        || matches!(input.firmware, VersionConstraint::Exact(_))
            && device.firmware().is_some()
            && !firmware_match;
    if device.has_contradictory_high_confidence() {
        return Ok(result(
            MatchLabel::Contradicted,
            vec![],
            "high-confidence device evidence is contradictory",
            Confidence::High,
        ));
    }
    if contradiction {
        return Ok(result(
            MatchLabel::Contradicted,
            matched(input, vendor_match, model_match, firmware_match),
            "identity evidence contradicts the advisory",
            Confidence::High,
        ));
    }
    let mut fields = Vec::new();
    if !input.vendor.eq_ignore_ascii_case("unknown") && vendor_match {
        fields.push(MatchedField::Vendor);
    }
    if input.model.is_some() && device.model().is_some() && model_match {
        fields.push(MatchedField::Model);
    }
    if matches!(input.firmware, VersionConstraint::Exact(_))
        && device.firmware().is_some()
        && firmware_match
    {
        fields.push(MatchedField::Firmware);
    }
    let exact_allowed = !input.vendor.eq_ignore_ascii_case("unknown")
        && input.freshness == Freshness::Fresh
        && matches!(
            input.source_trust,
            SourceTrust::OfficialApi | SourceTrust::VerifiedSignature
        )
        && input.model.is_some()
        && device.model().is_some()
        && matches!(input.firmware, VersionConstraint::Exact(_))
        && device.firmware().is_some()
        && !device.has_contradictory_high_confidence();
    if exact_allowed {
        Ok(result(
            MatchLabel::Exact,
            fields,
            "all advisory identity fields match",
            Confidence::High,
        ))
    } else {
        Ok(result(
            MatchLabel::Possible,
            fields,
            "identity is incomplete or source evidence is not actionable",
            Confidence::Medium,
        ))
    }
}

fn matched(
    input: &crate::AdvisoryInput,
    vendor: bool,
    model: bool,
    firmware: bool,
) -> Vec<MatchedField> {
    let mut out = Vec::new();
    if vendor && !input.vendor.eq_ignore_ascii_case("unknown") {
        out.push(MatchedField::Vendor);
    }
    if model && input.model.is_some() {
        out.push(MatchedField::Model);
    }
    if firmware && matches!(input.firmware, VersionConstraint::Exact(_)) {
        out.push(MatchedField::Firmware);
    }
    out
}
fn result(
    label: MatchLabel,
    matched_fields: Vec<MatchedField>,
    explanation: &str,
    confidence: Confidence,
) -> AdvisoryMatch {
    AdvisoryMatch {
        label,
        matched_fields,
        explanation: explanation.chars().take(MAX_EXPLANATION).collect(),
        confidence,
    }
}

pub fn compose_risk(
    advisories: &[NormalizedAdvisory],
    device: Option<DeviceEvidence>,
) -> Result<RiskDimensions, MatchError> {
    if advisories.is_empty() || advisories.len() > 64 {
        return Err(MatchError::InvalidGroup);
    }
    let id = advisories[0].input().source_id.as_str();
    if advisories.iter().any(|a| a.input().source_id != id) {
        return Err(MatchError::MixedSourceIds);
    }
    let mut risk = RiskDimensions {
        severity: Severity::Unknown,
        exploitability: Exploitability::Unknown,
        exposure: Exposure::Unknown,
        confidence: Confidence::Low,
        remediation: Remediation::Unknown,
    };
    for advisory in advisories {
        let a = advisory.input();
        if a.source != AdvisorySource::CisaKev {
            risk.severity = max_severity(risk.severity, a.severity);
            risk.remediation = max_remediation(risk.remediation, a.remediation);
            risk.exploitability = max_exploitability(risk.exploitability, a.exploitability);
        } else if a.exploitability == Exploitability::ActiveKnownExploitation {
            risk.exploitability = Exploitability::ActiveKnownExploitation;
        }
    }
    if let Some(e) = device {
        risk.exposure = e.exposure;
        risk.confidence = max_confidence(risk.confidence, e.confidence);
    }
    Ok(risk)
}

fn max_severity(a: Severity, b: Severity) -> Severity {
    if rank_severity(b) > rank_severity(a) {
        b
    } else {
        a
    }
}
fn rank_severity(v: Severity) -> u8 {
    match v {
        Severity::None => 1,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
        Severity::Unknown => 0,
    }
}
fn max_exploitability(a: Exploitability, b: Exploitability) -> Exploitability {
    if rank_exploitability(b) > rank_exploitability(a) {
        b
    } else {
        a
    }
}
fn rank_exploitability(v: Exploitability) -> u8 {
    match v {
        Exploitability::None => 1,
        Exploitability::ProofOfConcept => 1,
        Exploitability::ActiveKnownExploitation => 2,
        Exploitability::Unknown => 0,
    }
}
fn max_remediation(a: Remediation, b: Remediation) -> Remediation {
    if rank_remediation(b) > rank_remediation(a) {
        b
    } else {
        a
    }
}
fn rank_remediation(v: Remediation) -> u8 {
    match v {
        Remediation::None => 1,
        Remediation::Monitor => 1,
        Remediation::Mitigate => 2,
        Remediation::Upgrade => 3,
        Remediation::Unknown => 0,
    }
}
fn max_confidence(a: Confidence, b: Confidence) -> Confidence {
    if rank_confidence(b) > rank_confidence(a) {
        b
    } else {
        a
    }
}
fn rank_confidence(v: Confidence) -> u8 {
    match v {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}
