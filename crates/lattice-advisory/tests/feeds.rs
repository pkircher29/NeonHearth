use chrono::{Duration, TimeZone, Utc};
use lattice_advisory::{
    feed::{CisaKevFeed, FeedError, ModifiedWindow, NvdFeed},
    transport::{
        FeedRequest, FixtureReply, FixtureTransport, KEV_URL, MAX_AGGREGATE_RECORDS, MAX_PAGES,
        MAX_RESPONSE_BYTES, MAX_RESULTS_PER_PAGE, NVD_URL, TransportError,
    },
};

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}
fn nvd_page(start: usize, total: usize, items: usize) -> String {
    format!(
        r#"{{"startIndex":{start},"resultsPerPage":{items},"totalResults":{total},"vulnerabilities":[{}]}}"#,
        (0..items).map(|_| "{}").collect::<Vec<_>>().join(",")
    )
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
