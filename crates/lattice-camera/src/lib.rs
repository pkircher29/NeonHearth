use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
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

impl TryFrom<f32> for Confidence {
    type Error = CameraError;
    fn try_from(value: f32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Confidence> for f32 {
    fn from(value: Confidence) -> Self {
        value.0
    }
}

impl Serialize for Confidence {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_f32(self.0)
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(f32::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceInput {
    kind: CameraKind,
    source: String,
    fact: String,
    confidence: Confidence,
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
        if source.trim().is_empty() || source.len() > 128 {
            return Err(CameraError::InvalidEvidence("source"));
        }
        if fact.trim().is_empty() || fact.len() > 256 {
            return Err(CameraError::InvalidEvidence("fact"));
        }
        Ok(Self {
            kind,
            source,
            fact,
            confidence,
        })
    }

    pub const fn kind(&self) -> CameraKind {
        self.kind
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

#[derive(Serialize, Deserialize)]
struct EvidenceInputWire {
    kind: CameraKind,
    source: String,
    fact: String,
    confidence: Confidence,
}

impl Serialize for EvidenceInput {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        EvidenceInputWire {
            kind: self.kind,
            source: self.source.clone(),
            fact: self.fact.clone(),
            confidence: self.confidence,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EvidenceInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = EvidenceInputWire::deserialize(deserializer)?;
        Self::new(wire.kind, wire.source, wire.fact, wire.confidence)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CameraError {
    #[error("confidence must be finite and between 0 and 1")]
    InvalidConfidence,
    #[error("evidence {0} is empty or exceeds its bound")]
    InvalidEvidence(&'static str),
}
