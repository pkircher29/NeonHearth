use crate::DeviceId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PresenceState {
    Online,
    Quiet,
    Offline,
    Blocked,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct PresenceChanged {
    pub device_id: DeviceId,
    pub from: PresenceState,
    pub to: PresenceState,
    pub reason: String,
    pub trigger_source: String,
    pub trigger_kind: String,
    pub evidence_observed_at: DateTime<Utc>,
    pub evidence_valid_until: Option<DateTime<Utc>>,
    pub correction_of: Option<u64>,
}
