use crate::{BoundedText, CameraId, Confidence};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const MAX_EVIDENCE: usize = 64;
const MIN_FAMILY_CONFIDENCE: f32 = 0.2;
const MIN_COMBINED_CONFIDENCE: f32 = 0.6;
const SINGLE_WEAK_FAMILY_CAP: f32 = 0.35;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraClassification {
    Camera,
    PossibleCamera,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraEvidenceFamily {
    Onvif,
    WsDiscovery,
    Rtsp,
    Upnp,
    Http,
    Tls,
    Service,
    Behavior,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraHealth {
    Healthy,
    Degraded,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CameraEvidence {
    family: CameraEvidenceFamily,
    source: String,
    fact: String,
    confidence: Confidence,
    observed_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

impl CameraEvidence {
    pub fn new(
        family: CameraEvidenceFamily,
        source: impl Into<String>,
        fact: impl Into<String>,
        confidence: f32,
        observed_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, DetectionError> {
        Ok(Self {
            family,
            source: safe_source(source.into())?,
            fact: normalized_fact(family, fact.into())?,
            confidence: Confidence::new(confidence).map_err(|_| DetectionError::InvalidEvidence)?,
            observed_at,
            expires_at,
        })
    }
    pub const fn family(&self) -> CameraEvidenceFamily {
        self.family
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn fact(&self) -> &str {
        &self.fact
    }
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CameraCandidate {
    pub id: CameraId,
    pub classification: CameraClassification,
    pub confidence: Confidence,
    pub evidence: Vec<CameraEvidence>,
    pub health: CameraHealth,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DetectionError {
    #[error("camera evidence is invalid or exceeds bounds")]
    InvalidEvidence,
}

fn bounded(value: String, max: usize) -> Result<String, DetectionError> {
    if value.trim().is_empty() || value.len() > max {
        Err(DetectionError::InvalidEvidence)
    } else {
        Ok(value)
    }
}
fn safe_source(value: String) -> Result<String, DetectionError> {
    let normalized = value.to_ascii_lowercase();
    if normalized.contains("://")
        || value.contains('@')
        || normalized.contains("password")
        || normalized.contains("bearer")
        || normalized.contains("authorization")
        || normalized.contains("header")
        || normalized.contains("body")
    {
        return Err(DetectionError::InvalidEvidence);
    }
    bounded(value, 128)
}

fn normalized_fact(family: CameraEvidenceFamily, value: String) -> Result<String, DetectionError> {
    let fact = value.to_ascii_lowercase();
    let contains_secret = ["://", "@", "password", "bearer", "authorization", "header", "body"]
        .iter()
        .any(|needle| fact.contains(needle));
    let metadata_family = matches!(
        family,
        CameraEvidenceFamily::Onvif
            | CameraEvidenceFamily::Upnp
            | CameraEvidenceFamily::Http
            | CameraEvidenceFamily::Tls
    );
    let marker = metadata_family && fact
        .strip_prefix("vendor:")
        .or_else(|| fact.strip_prefix("model:"))
        .is_some_and(|name| !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')));
    if contains_secret || (!allowed(family, &fact) && !marker) {
        return Err(DetectionError::InvalidEvidence);
    }
    bounded(fact, 256)
}

fn allowed(family: CameraEvidenceFamily, fact: &str) -> bool {
    matches!(
        (family, fact),
        (CameraEvidenceFamily::Onvif, "onvif_camera_profile")
            | (CameraEvidenceFamily::Onvif, "onvif_namespace")
            | (CameraEvidenceFamily::WsDiscovery, "ws_discovery_type")
            | (CameraEvidenceFamily::WsDiscovery, "ws_discovery_scope")
            | (CameraEvidenceFamily::Rtsp, "rtsp_camera")
            | (CameraEvidenceFamily::Upnp, "upnp_camera")
            | (CameraEvidenceFamily::Http, "camera_web")
            | (CameraEvidenceFamily::Tls, "tls_camera")
            | (CameraEvidenceFamily::Service, "camera_service")
            | (CameraEvidenceFamily::Behavior, "camera_behavior")
            | (CameraEvidenceFamily::Onvif, "camera_contradiction")
    )
}

impl<'de> Deserialize<'de> for CameraEvidence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            family: CameraEvidenceFamily,
            source: BoundedText<128>,
            fact: BoundedText<256>,
            confidence: Confidence,
            observed_at: DateTime<Utc>,
            expires_at: Option<DateTime<Utc>>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.family,
            wire.source.into_inner(),
            wire.fact.into_inner(),
            wire.confidence.get(),
            wire.observed_at,
            wire.expires_at,
        )
        .map_err(serde::de::Error::custom)
    }
}

pub fn classify_candidate(
    id: CameraId,
    inputs: impl IntoIterator<Item = CameraEvidence>,
    now: DateTime<Utc>,
) -> Result<CameraCandidate, DetectionError> {
    let mut evidence = Vec::new();
    for item in inputs {
        if item.expires_at.is_some_and(|expiry| expiry <= now) {
            continue;
        }
        if let Some(index) = evidence.iter().position(|selected: &CameraEvidence| {
            (selected.family, &selected.source, &selected.fact)
                == (item.family, &item.source, &item.fact)
        }) {
            if selected_before(&evidence[index], &item) {
                evidence[index] = item;
            }
        } else if evidence.len() < MAX_EVIDENCE {
            evidence.push(item);
        } else if let Some((worst, _)) = evidence
            .iter()
            .enumerate()
            .min_by(|(_, left), (_, right)| selection_order(left, right))
            && selected_before(&evidence[worst], &item)
        {
            evidence[worst] = item;
        }
    }
    evidence.sort_by(|a, b| (a.family, &a.source, &a.fact).cmp(&(b.family, &b.source, &b.fact)));
    let contradiction = evidence.iter().any(|e| e.fact == "camera_contradiction");
    let families: BTreeSet<_> = evidence
        .iter()
        .filter(|e| e.fact != "camera_contradiction")
        .map(|e| e.family)
        .collect();
    let family_scores: Vec<_> = families
        .iter()
        .map(|family| {
            evidence
                .iter()
                .filter(|e| e.family == *family && e.fact != "camera_contradiction")
                .map(|e| e.confidence.get())
                .fold(0.0, f32::max)
        })
        .collect();
    let strong_profile_confidence = evidence
        .iter()
        .filter(|e| e.family == CameraEvidenceFamily::Onvif && e.fact == "onvif_camera_profile")
        .map(|e| e.confidence.get())
        .fold(0.0, f32::max);
    let qualifying_scores: Vec<_> = family_scores
        .iter()
        .copied()
        .filter(|score| *score >= MIN_FAMILY_CONFIDENCE)
        .collect();
    let qualifying_total: f32 = qualifying_scores.iter().sum();
    let classification = if contradiction {
        CameraClassification::Unknown
    } else if strong_profile_confidence >= 0.8
        || (qualifying_scores.len() >= 2 && qualifying_total >= MIN_COMBINED_CONFIDENCE)
    {
        CameraClassification::Camera
    } else if !families.is_empty() {
        CameraClassification::PossibleCamera
    } else {
        CameraClassification::Unknown
    };
    let score = if contradiction {
        0.0
    } else {
        if strong_profile_confidence >= 0.8 {
            strong_profile_confidence
        } else if qualifying_scores.len() == 1 {
            qualifying_total.min(SINGLE_WEAK_FAMILY_CAP)
        } else {
            qualifying_total.min(1.0)
        }
    };
    Ok(CameraCandidate {
        id,
        classification,
        confidence: Confidence::new(score).unwrap(),
        evidence,
        health: CameraHealth::Unknown,
    })
}

fn selected_before(left: &CameraEvidence, right: &CameraEvidence) -> bool {
    selection_order(left, right).is_lt()
}

fn selection_order(left: &CameraEvidence, right: &CameraEvidence) -> std::cmp::Ordering {
    evidence_priority(left)
        .cmp(&evidence_priority(right))
        .then_with(|| left.confidence.get().total_cmp(&right.confidence.get()))
        .then_with(|| left.observed_at.cmp(&right.observed_at))
        .then_with(|| left.expires_at.cmp(&right.expires_at))
        .then_with(|| {
            (right.family, &right.source, &right.fact)
                .cmp(&(left.family, &left.source, &left.fact))
        })
}

fn evidence_priority(evidence: &CameraEvidence) -> u8 {
    if evidence.fact == "camera_contradiction" {
        2
    } else if evidence.family == CameraEvidenceFamily::Onvif
        && evidence.fact == "onvif_camera_profile"
        && evidence.confidence.get() >= 0.8
    {
        1
    } else {
        0
    }
}
