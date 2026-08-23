use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFamily {
    LinkLayer,
    Addressing,
    Naming,
    Service,
    Cryptographic,
    RouterHint,
    Owner,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct EvidenceFact {
    pub family: EvidenceFamily,
    pub source: String,
    pub key: String,
    pub value: String,
    pub confidence: f32,
    pub observed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub owner_confirmed: bool,
}
