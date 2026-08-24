use chrono::{DateTime, Utc};
use url::Url;

pub const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    #[error("unsafe URL")]
    UnsafeUrl,
    #[error("response exceeds byte limit")]
    Oversized,
    #[error("transport unavailable")]
    Unavailable,
}

#[derive(Clone, Debug)]
pub struct FeedRequest {
    pub url: String,
    pub start_index: usize,
    pub results_per_page: usize,
    pub modified_start: DateTime<Utc>,
    pub modified_end: DateTime<Utc>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}
impl FeedRequest {
    pub fn nvd(
        start_index: usize,
        results_per_page: usize,
        modified_start: DateTime<Utc>,
        modified_end: DateTime<Utc>,
    ) -> Self {
        Self {
            url: NVD_URL.into(),
            start_index,
            results_per_page: results_per_page.min(2_000),
            modified_start,
            modified_end,
            etag: None,
            last_modified: None,
        }
    }
    pub fn url(url: &str) -> Result<Self, TransportError> {
        validate_url(url)?;
        Ok(Self {
            url: url.into(),
            start_index: 0,
            results_per_page: 1,
            modified_start: Utc::now(),
            modified_end: Utc::now(),
            etag: None,
            last_modified: None,
        })
    }
}
#[derive(Clone, Debug)]
pub struct FeedResponse {
    pub status: u16,
    pub body: String,
    pub retrieved_at: DateTime<Utc>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub source_url: String,
}
pub trait FeedTransport {
    fn get(
        &self,
        request: FeedRequest,
    ) -> impl std::future::Future<Output = Result<FeedResponse, TransportError>> + Send;
}
#[derive(Clone, Debug)]
pub struct FixtureTransport {
    body: String,
}
impl FixtureTransport {
    pub fn from_json(body: &str) -> Self {
        Self { body: body.into() }
    }
}
impl FeedTransport for FixtureTransport {
    async fn get(&self, request: FeedRequest) -> Result<FeedResponse, TransportError> {
        validate_url(&request.url)?;
        if self.body.len() > MAX_RESPONSE_BYTES {
            return Err(TransportError::Oversized);
        }
        Ok(FeedResponse {
            status: 200,
            body: self.body.clone(),
            retrieved_at: Utc::now(),
            etag: None,
            last_modified: None,
            source_url: request.url,
        })
    }
}
fn validate_url(raw: &str) -> Result<(), TransportError> {
    let url = Url::parse(raw).map_err(|_| TransportError::UnsafeUrl)?;
    let exact = (url.as_str() == NVD_URL || url.as_str() == KEV_URL)
        && url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none();
    if exact {
        Ok(())
    } else {
        Err(TransportError::UnsafeUrl)
    }
}
