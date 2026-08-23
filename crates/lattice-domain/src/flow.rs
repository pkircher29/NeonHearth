use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    Complete,
    RouterReported,
    LocalOnly,
    Estimated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ByteCount {
    pub upload: u64,
    pub download: u64,
}
