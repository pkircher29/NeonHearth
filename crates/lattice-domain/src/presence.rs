use crate::DeviceId;
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
}
