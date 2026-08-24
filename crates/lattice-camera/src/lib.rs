use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

mod detection;
mod media;
mod onvif;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CameraId(Uuid);

impl CameraId {
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl fmt::Display for CameraId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraKind {
    Onvif,
    Rtsp,
    Upnp,
    Http,
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Confidence(f32);

impl Confidence {
    pub fn new(value: f32) -> Result<Self, CameraError> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(CameraError::InvalidConfidence)
        }
    }

    pub const fn get(self) -> f32 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceInput {
    pub kind: CameraKind,
    pub source: String,
    pub fact: String,
    pub confidence: Confidence,
}

impl EvidenceInput {
    pub fn new(
        kind: CameraKind,
        source: impl Into<String>,
        fact: impl Into<String>,
        confidence: Confidence,
    ) -> Result<Self, CameraError> {
        let source = source.into();
        let fact = fact.into();
        if source.is_empty() || source.len() > 128 {
            return Err(CameraError::InvalidEvidence("source"));
        }
        if fact.is_empty() || fact.len() > 256 {
            return Err(CameraError::InvalidEvidence("fact"));
        }
        Ok(Self {
            kind,
            source,
            fact,
            confidence,
        })
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CameraError {
    #[error("confidence must be finite and between 0 and 1")]
    InvalidConfidence,
    #[error("evidence {0} is empty or exceeds its bound")]
    InvalidEvidence(&'static str),
}
