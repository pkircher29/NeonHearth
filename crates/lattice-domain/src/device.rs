use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct DeviceId(Uuid);

impl DeviceId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
    pub fn parse(value: &str) -> Result<Self, uuid::Error> {
        value.parse().map(Self)
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}
