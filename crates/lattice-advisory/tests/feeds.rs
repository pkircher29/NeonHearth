use chrono::{Duration, TimeZone, Utc};
use lattice_advisory::{
    feed::{CisaKevFeed, FeedError, ModifiedWindow, NvdFeed},
    transport::{
        Clock, FeedRequest, FixtureReply, FixtureTransport, KEV_URL, MAX_AGGREGATE_RECORDS,
        MAX_PAGES, MAX_RESPONSE_BYTES, MAX_RESULTS_PER_PAGE, NVD_URL, TransportError,
        is_public_feed_address,
    },
};
use std::sync::{Arc, Mutex};

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}
fn nvd_page(start: usize, total: usize, items: usize) -> String {
    format!(
        r#"{{"startIndex":{start},"resultsPerPage":{items},"totalResults":{total},"vulnerabilities":[{}]}}"#,
        (0..items).map(|_| "{}").collect::<Vec<_>>().join(",")
    )
}

#[derive(Clone, Debug)]
struct MutableClock(Arc<Mutex<chrono::DateTime<Utc>>>);
impl MutableClock {
    fn set(&self, now: chrono::DateTime<Utc>) {
        *self.0.lock().unwrap() = now;
    }
}
impl Clock for MutableClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

#[test]
fn nvd_requests_have_canonical_url_encoded_incremental_query_and_bounded_window() {
    let request = FeedRequest::nvd(4, 9_999, at(0), at(1)).unwrap();
    assert_eq!(
        request.url,
        format!(
            "{NVD_URL}?lastModStartDate=1970-01-01T00%3A00%3A00.000Z&lastModEndDate=1970-01-01T00%3A00%3A01.000Z&startIndex=4&resultsPerPage=2000"
        )
    );
    assert_eq!(request.results_per_page, MAX_RESULTS_PER_PAGE);
    assert!(FeedRequest::nvd(0, 1, at(0), at(0) + Duration::days(121)).is_err());
    assert!(FeedRequest::nvd(0, 1, at(2), at(1)).is_err());
}

#[tokio::test]
async fn nvd_paginates_and_records_each_deterministic_request() {
    let transport = FixtureTransport::queued([
        Ok(FixtureReply::json(nvd_page(0, 3, 2))),
        Ok(FixtureReply::json(nvd_page(2, 3, 1))),
    ]);
    let feed = NvdFeed::new(transport.clone());
    let result = feed
        .sync(ModifiedWindow::new(at(0), at(1)).unwrap())
        .await
        .unwrap();
    assert_eq!(result.records.len(), 3);
    assert_eq!(transport.requests().len(), 2);
    assert!(transport.requests()[1].url.contains("startIndex=2"));
}

#[tokio::test]
async fn cisa_uses_the_exact_canonical_endpoint() {
    let transport = FixtureTransport::queued([Ok(FixtureReply::json(r#"{"vulnerabilities":[]}"#))]);
    let result = CisaKevFeed::new(transport.clone()).sync().await.unwrap();
    assert_eq!(result.source_url, KEV_URL);
    assert_eq!(transport.requests()[0].url, KEV_URL);
}

#[tokio::test]
async fn conditionals_are_sent_together_and_304_reuses_nonexpired_same_request_cache() {
    let transport = FixtureTransport::queued([
        Ok(FixtureReply::json(nvd_page(0, 1, 1)).with_headers(Some("e"), Some("yesterday"))),
        Ok(FixtureReply::status(304)),
    ]);
    let feed = NvdFeed::new(transport.clone());
    let window = ModifiedWindow::new(at(0), at(1)).unwrap();
    feed.sync(window.clone()).await.unwrap();
    let second = feed.sync(window).await.unwrap();
    assert_eq!(second.records.len(), 1);
    let request = &transport.requests()[1];
    assert_eq!(request.etag.as_deref(), Some("e"));
    assert_eq!(request.last_modified.as_deref(), Some("yesterday"));
}

#[tokio::test]
async fn a_304_without_a_same_request_cache_is_typed_unavailable() {
    let feed = NvdFeed::new(FixtureTransport::queued([Ok(FixtureReply::status(304))]));
    assert!(matches!(
        feed.sync(ModifiedWindow::new(at(0), at(1)).unwrap()).await,
        Err(FeedError::Unavailable(_))
    ));
}

#[tokio::test]
async fn failure_returns_stale_cache_warning_but_no_cache_is_typed_unavailable() {
    let transport = FixtureTransport::queued([
        Ok(FixtureReply::json(nvd_page(0, 1, 1))),
        Err(TransportError::Unavailable),
    ]);
    let feed = NvdFeed::new(transport);
    let window = ModifiedWindow::new(at(0), at(1)).unwrap();
    feed.sync(window.clone()).await.unwrap();
    let stale = feed.sync(window).await.unwrap();
    assert!(stale.is_stale());
    assert!(!stale.warnings.is_empty());
    let no_cache = NvdFeed::new(FixtureTransport::queued([Err(TransportError::Unavailable)]));
    assert!(matches!(
        no_cache
            .sync(ModifiedWindow::new(at(0), at(1)).unwrap())
            .await,
        Err(FeedError::Unavailable(_))
    ));
}

#[tokio::test]
async fn parser_failure_returns_stale_cache_warning() {
    let transport = FixtureTransport::queued([
        Ok(FixtureReply::json(nvd_page(0, 1, 1))),
        Ok(FixtureReply::json("not-json")),
    ]);
    let feed = NvdFeed::new(transport);
    let window = ModifiedWindow::new(at(0), at(1)).unwrap();
    feed.sync(window.clone()).await.unwrap();
    let stale = feed.sync(window).await.unwrap();
    assert_eq!(stale.records.len(), 1);
    assert!(stale.is_stale());
}

#[tokio::test]
async fn rejects_malformed_and_nonadvancing_pagination_metadata() {
    let feed = NvdFeed::new(FixtureTransport::queued([Ok(FixtureReply::json(
        nvd_page(1, 1, 1),
    ))]));
    assert!(matches!(
        feed.sync(ModifiedWindow::new(at(0), at(1)).unwrap()).await,
        Err(FeedError::MalformedMetadata)
    ));
}

#[test]
fn exact_urls_reject_redirect_targets_credentials_ports_fragments_and_substitutions() {
    for unsafe_url in [
        "http://services.nvd.nist.gov/rest/json/cves/2.0",
        "https://services.nvd.nist.gov:443/rest/json/cves/2.0",
        "https://user@services.nvd.nist.gov/rest/json/cves/2.0",
        "https://services.nvd.nist.gov/rest/json/cves/2.0#x",
        "https://evil.test/rest/json/cves/2.0",
        "https://www.cisa.gov/sites/default/files/feeds/other.json",
    ] {
        assert!(FeedRequest::url(unsafe_url).is_err(), "{unsafe_url}");
    }
}

#[test]
fn constants_match_the_hard_resource_bounds() {
    assert_eq!(MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
    assert_eq!(MAX_PAGES, 128);
    assert_eq!(MAX_AGGREGATE_RECORDS, 256_000);
}

#[test]
fn only_public_unicast_addresses_are_eligible_for_pinned_official_hosts() {
    use std::net::IpAddr;
    assert!(is_public_feed_address("8.8.8.8".parse().unwrap()));
    assert!(is_public_feed_address(
        "2606:4700:4700::1111".parse().unwrap()
    ));
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "fc00::1",
        "fe80::1",
        "ff00::1",
        "2001:db8::1",
    ] {
        assert!(
            !is_public_feed_address(address.parse::<IpAddr>().unwrap()),
            "{address}"
        );
    }
}

#[tokio::test]
async fn stale_cache_expires_after_exact_seven_day_grace() {
    let initial = at(100);
    let clock = MutableClock(Arc::new(Mutex::new(initial)));
    let transport = FixtureTransport::with_clock(
        [
            Ok(FixtureReply::json(nvd_page(0, 1, 1))),
            Err(TransportError::Unavailable),
        ],
        clock.clone(),
    );
    let feed = NvdFeed::with_clock(transport, clock.clone());
    let window = ModifiedWindow::new(at(0), at(1)).unwrap();
    feed.sync(window.clone()).await.unwrap();
    clock.set(initial + Duration::hours(1) + Duration::days(7) + Duration::seconds(1));
    assert!(matches!(
        feed.sync(window).await,
        Err(FeedError::CacheExpired)
    ));
}

#[tokio::test]
async fn stale_cache_is_available_at_the_exact_seven_day_boundary() {
    let initial = at(200);
    let clock = MutableClock(Arc::new(Mutex::new(initial)));
    let transport = FixtureTransport::with_clock(
        [
            Ok(FixtureReply::json(nvd_page(0, 1, 1))),
            Err(TransportError::Unavailable),
        ],
        clock.clone(),
    );
    let feed = NvdFeed::with_clock(transport, clock.clone());
    let window = ModifiedWindow::new(at(0), at(1)).unwrap();
    feed.sync(window.clone()).await.unwrap();
    clock.set(initial + Duration::hours(1) + Duration::days(7));
    assert!(feed.sync(window).await.unwrap().is_stale());
}

#[tokio::test]
async fn cisa_http_and_schema_failures_serve_stale_cached_records() {
    let transport = FixtureTransport::queued([
        Ok(FixtureReply::json(r#"{"vulnerabilities":[{}]}"#)),
        Ok(FixtureReply::status(503)),
    ]);
    let feed = CisaKevFeed::new(transport);
    feed.sync().await.unwrap();
    assert!(feed.sync().await.unwrap().is_stale());
    let schema = CisaKevFeed::new(FixtureTransport::queued([
        Ok(FixtureReply::json(r#"{"vulnerabilities":[{}]}"#)),
        Ok(FixtureReply::json(r#"{"wrong":[]}"#)),
    ]));
    schema.sync().await.unwrap();
    assert!(schema.sync().await.unwrap().is_stale());
}

#[tokio::test]
async fn cisa_304_refreshes_expiry_and_retains_cached_provenance() {
    let initial = at(300);
    let clock = MutableClock(Arc::new(Mutex::new(initial)));
    let transport = FixtureTransport::with_clock(
        [
            Ok(FixtureReply::json(r#"{"vulnerabilities":[{}]}"#)
                .with_headers(Some("old"), Some("old-date"))),
            Ok(FixtureReply::status(304).with_headers(Some("new"), None)),
            Err(TransportError::Unavailable),
        ],
        clock.clone(),
    );
    let feed = CisaKevFeed::with_clock(transport, clock.clone());
    let initial_result = feed.sync().await.unwrap();
    clock.set(initial + Duration::minutes(59));
    let revalidated = feed.sync().await.unwrap();
    assert_eq!(revalidated.records, initial_result.records);
    assert_eq!(revalidated.response.etag.as_deref(), Some("new"));
    assert_eq!(
        revalidated.response.last_modified.as_deref(),
        Some("old-date")
    );
    assert_eq!(
        revalidated.cache_expires_at,
        initial + Duration::minutes(59) + Duration::hours(1)
    );
    clock.set(initial + Duration::hours(1) + Duration::minutes(30));
    assert!(feed.sync().await.unwrap().is_stale());
}

#[tokio::test]
async fn cisa_304_after_expiry_is_unavailable_without_extending_cache() {
    let initial = at(400);
    let clock = MutableClock(Arc::new(Mutex::new(initial)));
    let transport = FixtureTransport::with_clock(
        [
            Ok(FixtureReply::json(r#"{"vulnerabilities":[{}]}"#)),
            Ok(FixtureReply::status(304)),
        ],
        clock.clone(),
    );
    let feed = CisaKevFeed::with_clock(transport, clock.clone());
    feed.sync().await.unwrap();
    clock.set(initial + Duration::hours(1) + Duration::seconds(1));
    assert!(matches!(feed.sync().await, Err(FeedError::Unavailable(_))));
}

#[tokio::test]
async fn nvd_304_rotates_cached_validators_for_the_next_conditional_request() {
    let transport = FixtureTransport::queued([
        Ok(FixtureReply::json(nvd_page(0, 1, 1)).with_headers(Some("old-tag"), Some("old-date"))),
        Ok(FixtureReply::status(304).with_headers(Some("new-tag"), Some("new-date"))),
        Err(TransportError::Unavailable),
    ]);
    let feed = NvdFeed::new(transport.clone());
    let window = ModifiedWindow::new(at(0), at(1)).unwrap();
    feed.sync(window.clone()).await.unwrap();
    let revalidated = feed.sync(window.clone()).await.unwrap();
    assert_eq!(revalidated.response.etag.as_deref(), Some("new-tag"));
    assert_eq!(
        revalidated.response.last_modified.as_deref(),
        Some("new-date")
    );
    let _ = feed.sync(window).await;
    let next = &transport.requests()[2];
    assert_eq!(next.etag.as_deref(), Some("new-tag"));
    assert_eq!(next.last_modified.as_deref(), Some("new-date"));
}
