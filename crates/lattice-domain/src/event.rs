use crate::{ByteCount, Coverage, DeviceId, PresenceChanged};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum EventPayload {
    PresenceChanged(PresenceChanged),
    ServiceStatus(ServiceStatus),
    BandwidthFrame(BandwidthFrame),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct BandwidthFrame {
    pub interval_ms: u64,
    pub observed_at: DateTime<Utc>,
    pub emitted_at: DateTime<Utc>,
    pub samples: Vec<BandwidthSample>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct BandwidthSample {
    pub device_id: DeviceId,
    pub delta: ByteCount,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
    pub coverage: Coverage,
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
