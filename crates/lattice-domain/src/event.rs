use crate::PresenceChanged;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum EventPayload {
    PresenceChanged(PresenceChanged),
    ServiceStatus(ServiceStatus),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ServiceStatus {
    pub state: String,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct EventEnvelope {
    pub sequence: u64,
    pub occurred_at: DateTime<Utc>,
    pub payload: EventPayload,
}
