use crate::transport::{
    Clock, FeedRequest, FeedResponse, FeedTransport, KEV_URL, MAX_AGGREGATE_RECORDS, MAX_PAGES,
    MAX_RESULTS_PER_PAGE, NVD_URL, SystemClock, TransportError,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const CACHE_TTL: Duration = Duration::hours(1);
pub const MAX_STALE_AGE: Duration = Duration::days(7);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModifiedWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}
impl ModifiedWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, FeedError> {
        FeedRequest::nvd(0, 1, start, end).map_err(FeedError::Transport)?;
        Ok(Self { start, end })
    }
    pub fn since(start: DateTime<Utc>) -> Result<Self, FeedError> {
        Self::new(start, SystemClock.now())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedWarning {
    Stale(TransportError),
}
#[derive(Clone, Debug)]
pub struct FeedResult {
    pub source_url: String,
    pub records: Vec<Value>,
    pub response: FeedResponse,
    pub cache_expires_at: DateTime<Utc>,
    pub warnings: Vec<FeedWarning>,
}
impl FeedResult {
    pub fn is_stale(&self) -> bool {
        !self.warnings.is_empty()
    }
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeedError {
    #[error("feed unavailable: {0}")]
    Unavailable(TransportError),
    #[error("malformed feed pagination metadata")]
    MalformedMetadata,
    #[error("page or aggregate record bound exceeded")]
    RecordLimit,
    #[error("cache protocol error")]
    CacheProtocol,
    #[error("cached feed records have expired")]
    CacheExpired,
    #[error(transparent)]
    Transport(TransportError),
}

#[derive(Clone, Debug)]
struct Cached {
    result: FeedResult,
}
pub struct NvdFeed<T> {
    transport: T,
    cache: Mutex<HashMap<String, Cached>>,
    clock: Arc<dyn Clock>,
}
impl<T> NvdFeed<T> {
    pub fn new(transport: T) -> Self {
        Self::with_clock(transport, SystemClock)
    }
    pub fn with_clock(transport: T, clock: impl Clock + 'static) -> Self {
        Self {
            transport,
            cache: Mutex::new(HashMap::new()),
            clock: Arc::new(clock),
        }
    }
}
impl<T: FeedTransport> NvdFeed<T> {
    pub async fn sync(&self, window: ModifiedWindow) -> Result<FeedResult, FeedError> {
        let mut start = 0usize;
        let mut all = Vec::new();
        let mut first_response = None;
        let mut first_expiry = None;
        for page in 0..MAX_PAGES {
            let uncached = FeedRequest::nvd(start, MAX_RESULTS_PER_PAGE, window.start, window.end)
                .map_err(FeedError::Transport)?;
            let key = uncached.url.clone();
            let cached = self.cache.lock().expect("cache lock").get(&key).cloned();
            let request = if let Some(cached) = &cached {
                uncached
                    .with_validators(
                        cached.result.response.etag.clone(),
                        cached.result.response.last_modified.clone(),
                    )
                    .map_err(FeedError::Transport)?
            } else {
                uncached
            };
            let response = match self.transport.get(request).await {
                Ok(response) if response.status == 304 => {
                    let Some(cached) = cached else {
                        return Err(FeedError::Unavailable(TransportError::Unavailable));
                    };
                    if cached.result.cache_expires_at < self.clock.now() {
                        return Err(FeedError::Unavailable(TransportError::Unavailable));
                    }
                    let mut merged = cached.result.response;
                    if response.etag.is_some() {
                        merged.etag = response.etag;
                    }
                    if response.last_modified.is_some() {
                        merged.last_modified = response.last_modified;
                    }
                    merged
                }
                Ok(response) if response.status == 200 => response,
                Ok(response) => {
                    return self
                        .stale_or_unavailable(&key, TransportError::HttpStatus(response.status));
                }
                Err(error) => return self.stale_or_unavailable(&key, error),
            };
            let (meta_start, page_size, total, records) = match parse_nvd(&response.body) {
                Ok(parsed) => parsed,
                Err(_) => {
                    return self.stale_or_unavailable(&key, TransportError::MalformedDocument);
                }
            };
            if meta_start != start
                || page_size == 0
                || page_size > MAX_RESULTS_PER_PAGE
                || records.len() > page_size
                || total
                    < start
                        .checked_add(records.len())
                        .ok_or(FeedError::RecordLimit)?
            {
                return Err(FeedError::MalformedMetadata);
            }
            let next = start
                .checked_add(records.len())
                .ok_or(FeedError::RecordLimit)?;
            if records.len() > MAX_AGGREGATE_RECORDS.saturating_sub(all.len()) {
                return Err(FeedError::RecordLimit);
            }
            all.extend(records);
            let expiry = self.clock.now() + CACHE_TTL;
            let result = FeedResult {
                source_url: NVD_URL.into(),
                records: all.clone(),
                response: response.clone(),
                cache_expires_at: expiry,
                warnings: Vec::new(),
            };
            self.cache.lock().expect("cache lock").insert(
                key,
                Cached {
                    result: FeedResult {
                        source_url: NVD_URL.into(),
                        records: result.records.clone(),
                        response: response.clone(),
                        cache_expires_at: expiry,
                        warnings: Vec::new(),
                    },
                },
            );
            first_response.get_or_insert(response);
            first_expiry.get_or_insert(expiry);
            if next == total {
                return Ok(FeedResult {
                    source_url: NVD_URL.into(),
                    records: all,
                    response: first_response.expect("set"),
                    cache_expires_at: first_expiry.expect("set"),
                    warnings: Vec::new(),
                });
            }
            if next <= start || next > total {
                return Err(FeedError::MalformedMetadata);
            }
            start = next;
            if page + 1 == MAX_PAGES {
                return Err(FeedError::RecordLimit);
            }
        }
        Err(FeedError::RecordLimit)
    }
    fn stale_or_unavailable(
        &self,
        key: &str,
        error: TransportError,
    ) -> Result<FeedResult, FeedError> {
        if let Some(cached) = self.cache.lock().expect("cache lock").get(key).cloned() {
            let Some(stale_until) = cached
                .result
                .cache_expires_at
                .checked_add_signed(MAX_STALE_AGE)
            else {
                return Err(FeedError::CacheExpired);
            };
            if self.clock.now() > stale_until {
                return Err(FeedError::CacheExpired);
            }
            let mut result = cached.result;
            result.warnings.push(FeedWarning::Stale(error));
            Ok(result)
        } else {
            Err(FeedError::Unavailable(error))
        }
    }
}
fn parse_nvd(body: &str) -> Result<(usize, usize, usize, Vec<Value>), FeedError> {
    let value: Value = serde_json::from_str(body).map_err(|_| FeedError::MalformedMetadata)?;
    let number = |name| {
        value
            .get(name)
            .and_then(Value::as_u64)
            .and_then(|v| usize::try_from(v).ok())
            .ok_or(FeedError::MalformedMetadata)
    };
    let records = value
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .cloned()
        .ok_or(FeedError::MalformedMetadata)?;
    Ok((
        number("startIndex")?,
        number("resultsPerPage")?,
        number("totalResults")?,
        records,
    ))
}

pub struct CisaKevFeed<T> {
    transport: T,
    cache: Mutex<Option<Cached>>,
    clock: Arc<dyn Clock>,
}
impl<T> CisaKevFeed<T> {
    pub fn new(transport: T) -> Self {
        Self::with_clock(transport, SystemClock)
    }
    pub fn with_clock(transport: T, clock: impl Clock + 'static) -> Self {
        Self {
            transport,
            cache: Mutex::new(None),
            clock: Arc::new(clock),
        }
    }
}
impl<T: FeedTransport> CisaKevFeed<T> {
    pub async fn sync(&self) -> Result<FeedResult, FeedError> {
        let cached = self.cache.lock().expect("cache lock").clone();
        let request = FeedRequest::kev()
            .with_validators(
                cached.as_ref().and_then(|c| c.result.response.etag.clone()),
                cached
                    .as_ref()
                    .and_then(|c| c.result.response.last_modified.clone()),
            )
            .map_err(FeedError::Transport)?;
        let response = match self.transport.get(request).await {
            Ok(response) if response.status == 304 => {
                let Some(cached) = cached else {
                    return Err(FeedError::Unavailable(TransportError::Unavailable));
                };
                if cached.result.cache_expires_at < self.clock.now() {
                    return Err(FeedError::Unavailable(TransportError::Unavailable));
                }
                let mut result = cached.result;
                if response.etag.is_some() {
                    result.response.etag = response.etag;
                }
                if response.last_modified.is_some() {
                    result.response.last_modified = response.last_modified;
                }
                result.cache_expires_at = self.clock.now() + CACHE_TTL;
                *self.cache.lock().expect("cache lock") = Some(Cached {
                    result: result.clone(),
                });
                return Ok(result);
            }
            Ok(response) if response.status == 200 => response,
            Ok(response) => {
                return self.stale_or_unavailable(TransportError::HttpStatus(response.status));
            }
            Err(error) => {
                return self.stale_or_unavailable(error);
            }
        };
        let value: Value = match serde_json::from_str(&response.body) {
            Ok(value) => value,
            Err(_) => return self.stale_or_unavailable(TransportError::MalformedDocument),
        };
        let records = match value
            .get("vulnerabilities")
            .and_then(Value::as_array)
            .cloned()
        {
            Some(records) => records,
            None => return self.stale_or_unavailable(TransportError::MalformedDocument),
        };
        if records.len() > MAX_AGGREGATE_RECORDS {
            return Err(FeedError::RecordLimit);
        }
        let result = FeedResult {
            source_url: KEV_URL.into(),
            records,
            response: response.clone(),
            cache_expires_at: self.clock.now() + CACHE_TTL,
            warnings: Vec::new(),
        };
        *self.cache.lock().expect("cache lock") = Some(Cached {
            result: result.clone(),
        });
        Ok(result)
    }
    fn stale_or_unavailable(&self, error: TransportError) -> Result<FeedResult, FeedError> {
        if let Some(mut cached) = self.cache.lock().expect("cache lock").clone() {
            let Some(stale_until) = cached
                .result
                .cache_expires_at
                .checked_add_signed(MAX_STALE_AGE)
            else {
                return Err(FeedError::CacheExpired);
            };
            if self.clock.now() > stale_until {
                return Err(FeedError::CacheExpired);
            }
            cached.result.warnings.push(FeedWarning::Stale(error));
            Ok(cached.result)
        } else {
            Err(FeedError::Unavailable(error))
        }
    }
}
