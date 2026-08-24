use chrono::{TimeZone, Utc};
use lattice_advisory::transport::{FeedRequest, FeedTransport, FixtureTransport, TransportError};

#[tokio::test]
async fn fixture_transport_returns_bounded_response() {
    let transport = FixtureTransport::from_json("{\"vulnerabilities\":[]}");
    let response = transport
        .get(FeedRequest::nvd(
            0,
            1,
            Utc.timestamp_opt(0, 0).unwrap(),
            Utc.timestamp_opt(1, 0).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(response.body.contains("vulnerabilities"));
}

#[test]
fn fixture_transport_rejects_unsafe_urls() {
    assert!(matches!(
        FeedRequest::url("http://services.nvd.nist.gov/rest/json/cves/2.0"),
        Err(TransportError::UnsafeUrl)
    ));
}
