use crate::SourceTrust;
use chrono::{DateTime, Duration, Utc};
use reqwest::header::{ETAG, HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration as StdDuration,
};
use url::Url;

pub const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RESULTS_PER_PAGE: usize = 2_000;
pub const DEFAULT_NVD_RESULTS_PER_PAGE: usize = 1_000;
pub const MAX_PAGE_SIZE_REDUCTIONS: usize = 10;
pub const MAX_PAGES: usize = 128;
pub const MAX_AGGREGATE_RECORDS: usize = 256_000;
const MAX_VALIDATOR_BYTES: usize = 1024;

pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> DateTime<Utc>;
}
#[derive(Clone, Debug, Default)]
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    #[error("unsafe feed URL")]
    UnsafeUrl,
    #[error("invalid modified window")]
    InvalidWindow,
    #[error("invalid validator header")]
    InvalidValidator,
    #[error("response exceeds byte limit")]
    Oversized,
    #[error("feed returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("feed response content type is not JSON")]
    InvalidContentType,
    #[error("feed response JSON is malformed")]
    MalformedDocument,
    #[error("transport unavailable")]
    Unavailable,
    #[error("official host resolved to an unsafe address")]
    UnsafeAddress,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedRequest {
    pub url: String,
    pub start_index: usize,
    pub results_per_page: usize,
    pub modified_start: Option<DateTime<Utc>>,
    pub modified_end: Option<DateTime<Utc>>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}
impl FeedRequest {
    pub fn nvd(
        start_index: usize,
        results_per_page: usize,
        modified_start: DateTime<Utc>,
        modified_end: DateTime<Utc>,
    ) -> Result<Self, TransportError> {
        if modified_start > modified_end || modified_end - modified_start > Duration::days(120) {
            return Err(TransportError::InvalidWindow);
        }
        let results_per_page = results_per_page.min(MAX_RESULTS_PER_PAGE);
        let start = nvd_date(modified_start);
        let end = nvd_date(modified_end);
        let mut url = Url::parse(NVD_URL).expect("constant NVD URL is valid");
        url.query_pairs_mut()
            .append_pair("lastModStartDate", &start)
            .append_pair("lastModEndDate", &end)
            .append_pair("startIndex", &start_index.to_string())
            .append_pair("resultsPerPage", &results_per_page.to_string());
        let request = Self {
            url: url.into(),
            start_index,
            results_per_page,
            modified_start: Some(modified_start),
            modified_end: Some(modified_end),
            etag: None,
            last_modified: None,
        };
        request.validate()?;
        Ok(request)
    }
    pub fn kev() -> Self {
        Self {
            url: KEV_URL.into(),
            start_index: 0,
            results_per_page: 0,
            modified_start: None,
            modified_end: None,
            etag: None,
            last_modified: None,
        }
    }
    pub fn url(url: &str) -> Result<Self, TransportError> {
        validate_exact_url(url)?;
        Ok(Self {
            url: url.into(),
            start_index: 0,
            results_per_page: 0,
            modified_start: None,
            modified_end: None,
            etag: None,
            last_modified: None,
        })
    }
    pub fn with_validators(
        mut self,
        etag: Option<String>,
        last_modified: Option<String>,
    ) -> Result<Self, TransportError> {
        validate_validator(etag.as_deref())?;
        validate_validator(last_modified.as_deref())?;
        self.etag = etag;
        self.last_modified = last_modified;
        Ok(self)
    }
    pub fn validate(&self) -> Result<(), TransportError> {
        validate_exact_url(&self.url)?;
        validate_validator(self.etag.as_deref())?;
        validate_validator(self.last_modified.as_deref())?;
        if self.url.starts_with(NVD_URL) {
            if self.results_per_page == 0 || self.results_per_page > MAX_RESULTS_PER_PAGE {
                return Err(TransportError::InvalidWindow);
            }
            let (Some(start), Some(end)) = (self.modified_start, self.modified_end) else {
                return Err(TransportError::InvalidWindow);
            };
            if start > end || end - start > Duration::days(120) {
                return Err(TransportError::InvalidWindow);
            }
            let mut canonical = Url::parse(NVD_URL).expect("constant NVD URL is valid");
            canonical
                .query_pairs_mut()
                .append_pair("lastModStartDate", &nvd_date(start))
                .append_pair("lastModEndDate", &nvd_date(end))
                .append_pair("startIndex", &self.start_index.to_string())
                .append_pair("resultsPerPage", &self.results_per_page.to_string());
            if canonical.as_str() != self.url {
                return Err(TransportError::UnsafeUrl);
            }
        }
        Ok(())
    }
}

/// NVD documents `lastModStartDate=2021-08-04T13:00:00.000` plus an optional
/// `+HH:MM` offset. UTC is always sent with an explicit offset.
fn nvd_date(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()
}

#[derive(Clone, Debug)]
pub struct FeedResponse {
    /// Assigned by the transport from how the body was obtained. Parsers take
    /// their `SourceTrust` from here and never promote a bare string.
    pub trust: SourceTrust,
    pub status: u16,
    pub body: String,
    pub retrieved_at: DateTime<Utc>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub source_url: String,
}

pub struct ProductionTransport {
    clock: Arc<dyn Clock>,
}
impl ProductionTransport {
    pub fn new() -> Result<Self, TransportError> {
        Self::with_clock(SystemClock)
    }
    pub fn with_clock(clock: impl Clock + 'static) -> Result<Self, TransportError> {
        Ok(Self {
            clock: Arc::new(clock),
        })
    }

    /// Resolves the official host asynchronously for this request, rejects any
    /// non-public answer, and pins the validated addresses for the connection.
    /// Re-resolving per request keeps CDN rotation working while the address
    /// check still prevents a poisoned answer from redirecting to a private
    /// host.
    async fn client_for(&self, host: &str) -> Result<reqwest::Client, TransportError> {
        let addresses = resolve_public_host(host).await?;
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(StdDuration::from_secs(10))
            .timeout(StdDuration::from_secs(30))
            .pool_max_idle_per_host(0)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| TransportError::Unavailable)
    }
}
impl FeedTransport for ProductionTransport {
    async fn get(&self, request: FeedRequest) -> Result<FeedResponse, TransportError> {
        request.validate()?;
        let host = url::Url::parse(&request.url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or(TransportError::UnsafeUrl)?;
        let client = self.client_for(&host).await?;
        let mut builder = client.get(&request.url);
        if let Some(etag) = &request.etag {
            builder = builder.header(IF_NONE_MATCH, etag);
        }
        if let Some(last) = &request.last_modified {
            builder = builder.header(IF_MODIFIED_SINCE, last);
        }
        let mut response = builder
            .send()
            .await
            .map_err(|_| TransportError::Unavailable)?;
        let status = response.status().as_u16();
        let headers = response.headers();
        let etag = header(headers, ETAG)?;
        let last_modified = header(headers, LAST_MODIFIED)?;
        if status == 304 {
            return Ok(FeedResponse {
                trust: SourceTrust::OfficialApi,
                status,
                body: String::new(),
                retrieved_at: self.clock.now(),
                etag,
                last_modified,
                source_url: request.url,
            });
        }
        if !(200..300).contains(&status) {
            return Err(TransportError::HttpStatus(status));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(TransportError::Oversized);
        }
        let content_type = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !content_type
            .split(';')
            .next()
            .is_some_and(|v| v.eq_ignore_ascii_case("application/json"))
        {
            return Err(TransportError::InvalidContentType);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| TransportError::Unavailable)?
        {
            if bytes
                .len()
                .checked_add(chunk.len())
                .filter(|n| *n <= MAX_RESPONSE_BYTES)
                .is_none()
            {
                return Err(TransportError::Oversized);
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Err(TransportError::InvalidContentType);
        }
        let body = String::from_utf8(bytes).map_err(|_| TransportError::InvalidContentType)?;
        Ok(FeedResponse {
            trust: SourceTrust::OfficialApi,
            status,
            body,
            retrieved_at: self.clock.now(),
            etag,
            last_modified,
            source_url: request.url,
        })
    }
}

pub trait FeedTransport: Send + Sync {
    fn get(
        &self,
        request: FeedRequest,
    ) -> impl std::future::Future<Output = Result<FeedResponse, TransportError>> + Send;
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub struct FixtureReply {
    pub status: u16,
    pub body: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}
#[cfg(any(test, feature = "test-support"))]
impl FixtureReply {
    pub fn json(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            etag: None,
            last_modified: None,
        }
    }
    pub fn status(status: u16) -> Self {
        Self {
            status,
            body: String::new(),
            etag: None,
            last_modified: None,
        }
    }
    pub fn with_headers(mut self, etag: Option<&str>, last_modified: Option<&str>) -> Self {
        self.etag = etag.map(str::to_owned);
        self.last_modified = last_modified.map(str::to_owned);
        self
    }
}
#[cfg(any(test, feature = "test-support"))]
pub struct FixtureTransport {
    replies: Arc<Mutex<VecDeque<Result<FixtureReply, TransportError>>>>,
    requests: Arc<Mutex<Vec<FeedRequest>>>,
    clock: Arc<dyn Clock>,
}
#[cfg(any(test, feature = "test-support"))]
impl Clone for FixtureTransport {
    fn clone(&self) -> Self {
        Self {
            replies: self.replies.clone(),
            requests: self.requests.clone(),
            clock: self.clock.clone(),
        }
    }
}
#[cfg(any(test, feature = "test-support"))]
impl std::fmt::Debug for FixtureTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixtureTransport").finish_non_exhaustive()
    }
}
#[cfg(any(test, feature = "test-support"))]
impl FixtureTransport {
    pub fn queued(replies: impl IntoIterator<Item = Result<FixtureReply, TransportError>>) -> Self {
        Self::with_clock(replies, SystemClock)
    }
    pub fn with_clock(
        replies: impl IntoIterator<Item = Result<FixtureReply, TransportError>>,
        clock: impl Clock + 'static,
    ) -> Self {
        Self {
            replies: Arc::new(Mutex::new(replies.into_iter().collect())),
            requests: Arc::new(Mutex::new(Vec::new())),
            clock: Arc::new(clock),
        }
    }
    pub fn from_json(body: &str) -> Self {
        Self::queued([Ok(FixtureReply::json(body))])
    }
    pub fn requests(&self) -> Vec<FeedRequest> {
        self.requests.lock().expect("fixture lock").clone()
    }
}
#[cfg(any(test, feature = "test-support"))]
impl FeedTransport for FixtureTransport {
    async fn get(&self, request: FeedRequest) -> Result<FeedResponse, TransportError> {
        request.validate()?;
        self.requests
            .lock()
            .expect("fixture lock")
            .push(request.clone());
        let reply = self
            .replies
            .lock()
            .expect("fixture lock")
            .pop_front()
            .ok_or(TransportError::Unavailable)??;
        if reply.body.len() > MAX_RESPONSE_BYTES {
            return Err(TransportError::Oversized);
        }
        Ok(FeedResponse {
            trust: SourceTrust::RegisteredHttps,
            status: reply.status,
            body: reply.body,
            retrieved_at: self.clock.now(),
            etag: reply.etag,
            last_modified: reply.last_modified,
            source_url: request.url,
        })
    }
}

fn header(
    headers: &HeaderMap,
    name: reqwest::header::HeaderName,
) -> Result<Option<String>, TransportError> {
    let value = headers
        .get(name)
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .map_err(|_| TransportError::InvalidValidator)
        })
        .transpose()?;
    validate_validator(value.as_deref())?;
    Ok(value)
}
fn validate_validator(value: Option<&str>) -> Result<(), TransportError> {
    if value.is_some_and(|v| {
        v.is_empty() || v.len() > MAX_VALIDATOR_BYTES || v.chars().any(char::is_control)
    }) {
        Err(TransportError::InvalidValidator)
    } else {
        Ok(())
    }
}
fn validate_exact_url(raw: &str) -> Result<(), TransportError> {
    let parsed = Url::parse(raw).map_err(|_| TransportError::UnsafeUrl)?;
    let allowed = if raw.starts_with(NVD_URL) {
        parsed.scheme() == "https"
            && parsed.host_str() == Some("services.nvd.nist.gov")
            && parsed.port_or_known_default() == Some(443)
            && parsed.port().is_none()
            && parsed.path() == "/rest/json/cves/2.0"
    } else {
        raw == KEV_URL
            && parsed.scheme() == "https"
            && parsed.host_str() == Some("www.cisa.gov")
            && parsed.port_or_known_default() == Some(443)
            && parsed.port().is_none()
            && parsed.path() == "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    };
    if allowed
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
    {
        Ok(())
    } else {
        Err(TransportError::UnsafeUrl)
    }
}

async fn resolve_public_host(host: &str) -> Result<Vec<SocketAddr>, TransportError> {
    let addresses: Vec<_> = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|_| TransportError::Unavailable)?
        .collect();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !is_public_feed_address(address.ip()))
    {
        return Err(TransportError::UnsafeAddress);
    }
    Ok(addresses)
}
pub fn is_public_feed_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && matches!(b, 0 | 2))
                || (a == 198 && ((18..=19).contains(&b) || b == 51))
                || (a == 203 && b == 0)
                || a >= 240)
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public_feed_address(IpAddr::V4(v4));
            }
            let segments = ip.segments();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || (segments[0] & 0xfe00 == 0xfc00)
                || (segments[0] & 0xffc0 == 0xfe80)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}
