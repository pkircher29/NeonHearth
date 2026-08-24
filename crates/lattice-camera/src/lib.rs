use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

pub mod detection;
mod media;
mod onvif;

pub use detection::{
    CameraCandidate, CameraClassification, CameraEvidence, CameraEvidenceFamily, CameraHealth,
    DetectionError, classify_candidate,
};

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

struct EvidenceInputWire {
    kind: CameraKind,
    source: BoundedText<128>,
    fact: BoundedText<256>,
    confidence: Confidence,
}

impl Serialize for EvidenceInputWire {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EvidenceInput", 4)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("fact", &self.fact)?;
        state.serialize_field("confidence", &self.confidence)?;
        state.end()
    }
}

struct BoundedText<const MAX: usize>(String);

impl<const MAX: usize> BoundedText<MAX> {
    fn validate(value: &str) -> Result<(), CameraError> {
        if value.trim().is_empty() || value.len() > MAX {
            Err(CameraError::InvalidEvidence("text"))
        } else {
            Ok(())
        }
    }
}

impl<const MAX: usize> Serialize for BoundedText<MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedText<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedTextVisitor<const MAX: usize>;
        impl<'de, const MAX: usize> Visitor<'de> for BoundedTextVisitor<MAX> {
            type Value = BoundedText<MAX>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a bounded non-empty string")
            }
            fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
                Self::check(value)
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Self::check(value)
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                BoundedText::<MAX>::validate(&value).map_err(E::custom)?;
                Ok(BoundedText(value))
            }
        }
        impl<const MAX: usize> BoundedTextVisitor<MAX> {
            fn check<E: de::Error>(value: &str) -> Result<BoundedText<MAX>, E> {
                BoundedText::<MAX>::validate(value).map_err(E::custom)?;
                Ok(BoundedText(value.to_owned()))
            }
        }
        deserializer.deserialize_string(BoundedTextVisitor::<MAX>)
    }
}

impl<'de> Deserialize<'de> for EvidenceInputWire {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            kind: CameraKind,
            source: BoundedText<128>,
            fact: BoundedText<256>,
            confidence: Confidence,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            kind: wire.kind,
            source: wire.source,
            fact: wire.fact,
            confidence: wire.confidence,
        })
    }
}

impl Serialize for EvidenceInput {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        EvidenceInputWire {
            kind: self.kind,
            source: BoundedText(self.source.clone()),
            fact: BoundedText(self.fact.clone()),
            confidence: self.confidence,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EvidenceInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = EvidenceInputWire::deserialize(deserializer)?;
        Self::new(wire.kind, wire.source.0, wire.fact.0, wire.confidence)
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
