use crate::{CameraId, Confidence};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

const MAX_EVIDENCE: usize = 64;

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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CameraEvidence {
    pub family: CameraEvidenceFamily,
    pub source: String,
    pub fact: String,
    pub confidence: Confidence,
    pub observed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
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
            source: bounded(source.into(), 128)?,
            fact: bounded(fact.into(), 256)?,
            confidence: Confidence::new(confidence).map_err(|_| DetectionError::InvalidEvidence)?,
            observed_at,
            expires_at,
        })
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

fn allowed(family: CameraEvidenceFamily, fact: &str) -> bool {
    if fact.contains("://")
        || fact.contains("password")
        || fact.contains("bearer")
        || fact.contains("authorization")
        || fact.contains("body=")
        || fact.contains("header=")
    {
        return false;
    }
    matches!(
        (family, fact),
        (CameraEvidenceFamily::Onvif, "onvif_camera_profile")
            | (CameraEvidenceFamily::WsDiscovery, "ws_discovery_scope")
            | (CameraEvidenceFamily::Rtsp, "rtsp_camera")
            | (CameraEvidenceFamily::Upnp, "upnp_camera")
            | (CameraEvidenceFamily::Http, "camera_web")
            | (CameraEvidenceFamily::Tls, "tls_camera")
            | (CameraEvidenceFamily::Service, "camera_service")
            | (CameraEvidenceFamily::Behavior, "camera_behavior")
    )
}

pub fn classify_candidate(
    id: CameraId,
    inputs: impl IntoIterator<Item = CameraEvidence>,
    now: DateTime<Utc>,
) -> Result<CameraCandidate, DetectionError> {
    let mut evidence = Vec::new();
    let mut seen = BTreeSet::new();
    for item in inputs {
        if evidence.len() >= MAX_EVIDENCE
            || item.expires_at.is_some_and(|expiry| expiry <= now)
            || !allowed(item.family, &item.fact)
        {
            continue;
        }
        if seen.insert((item.family, item.source.clone(), item.fact.clone())) {
            evidence.push(item);
        }
    }
    evidence.sort_by(|a, b| (a.family, &a.source, &a.fact).cmp(&(b.family, &b.source, &b.fact)));
    let families: BTreeSet<_> = evidence.iter().map(|e| e.family).collect();
    let classification = if evidence
        .iter()
        .any(|e| e.family == CameraEvidenceFamily::Onvif && e.fact == "onvif_camera_profile")
    {
        CameraClassification::Camera
    } else if !families.is_empty() {
        CameraClassification::PossibleCamera
    } else {
        CameraClassification::Unknown
    };
    let score = if classification == CameraClassification::Camera {
        0.95
    } else if families.len() >= 2 {
        0.7
    } else if !families.is_empty() {
        0.35
    } else {
        0.0
    };
    Ok(CameraCandidate {
        id,
        classification,
        confidence: Confidence::new(score).unwrap(),
        evidence,
        health: CameraHealth::Unknown,
    })
}
