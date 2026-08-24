use crate::transport::{FeedRequest, FeedTransport, NVD_URL, TransportError};
use chrono::{DateTime, Utc};
use serde_json::Value;

pub struct ModifiedWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}
impl ModifiedWindow {
    pub fn since(start: DateTime<Utc>) -> Self {
        Self {
            start,
            end: Utc::now(),
        }
    }
}
pub struct FeedResult {
    pub source_url: String,
    pub records: Vec<Value>,
    pub response: crate::transport::FeedResponse,
}
pub struct NvdFeed<T> {
    transport: T,
}
impl<T> NvdFeed<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}
impl<T: FeedTransport> NvdFeed<T> {
    pub async fn sync(&self, window: ModifiedWindow) -> Result<FeedResult, TransportError> {
        let response = self
            .transport
            .get(FeedRequest::nvd(0, 2_000, window.start, window.end))
            .await?;
        let value: Value =
            serde_json::from_str(&response.body).map_err(|_| TransportError::Unavailable)?;
        let records = value
            .get("vulnerabilities")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(FeedResult {
            source_url: NVD_URL.into(),
            records,
            response,
        })
    }
}
