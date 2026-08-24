use chrono::{TimeZone, Utc};
use lattice_advisory::{
    AdvisoryInput, AdvisorySource, Confidence, Exploitability, Exposure, Freshness,
    NormalizedAdvisory, Remediation, RiskDimensions, Severity, SourceTrust, VersionConstraint,
    match_advisory,
};
use lattice_domain::DeviceId;
use lattice_store::{
    AdvisoryRepository, AdvisoryStoreError, DeviceAdvisory, FeedFetch, connect_memory,
};

fn at(second: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(second, 0).single().unwrap()
}

fn device_id() -> DeviceId {
    DeviceId::parse("018f0000-0000-7000-8000-000000000001").unwrap()
}

fn advisory(source_id: &str) -> NormalizedAdvisory {
    advisory_at(source_id, at(102), at(200), "CVE advisory")
}

fn advisory_at(
    source_id: &str,
    retrieved_at: chrono::DateTime<Utc>,
    cache_expires_at: chrono::DateTime<Utc>,
    title: &str,
) -> NormalizedAdvisory {
    NormalizedAdvisory::new(AdvisoryInput {
        source: AdvisorySource::Nvd,
        source_id: source_id.into(),
        source_url: "https://example.test/advisory".into(),
        title: title.into(),
        vendor: "Acme".into(),
        model: Some("Router".into()),
        firmware: VersionConstraint::Exact("1.2.3".into()),
        published_at: at(100),
        modified_at: at(101),
        retrieved_at,
        cache_expires_at,
        freshness: Freshness::Fresh,
        source_trust: SourceTrust::OfficialApi,
        severity: Severity::High,
        exploitability: Exploitability::ProofOfConcept,
        exposure: Exposure::PotentiallyExposed,
        confidence: Confidence::High,
        remediation: Remediation::Upgrade,
    })
    .unwrap()
}

#[tokio::test]
async fn content_revision_deduplicates_operational_refresh_but_not_changed_content()
-> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = AdvisoryRepository::new(pool.clone());
    let original = advisory("CVE-2026-0099");
    let id = repository.upsert_advisory(&original).await?;
    let refreshed = advisory_at("CVE-2026-0099", at(103), at(250), "CVE advisory");
    assert_eq!(repository.upsert_advisory(&refreshed).await?, id);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM advisories")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 1);
    let (stored_hash, cache): (String, String) =
        sqlx::query_as("SELECT provenance_sha256,cache_expires_at FROM advisories")
            .fetch_one(&pool)
            .await?;
    assert_eq!(stored_hash, refreshed.provenance_sha256());
    assert_eq!(
        cache,
        at(250).to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
    );
    assert_ne!(
        repository
            .upsert_advisory(&advisory_at(
                "CVE-2026-0099",
                at(103),
                at(250),
                "changed title"
            ))
            .await?,
        id
    );
    Ok(())
}

#[tokio::test]
async fn corrupt_persisted_values_are_sanitized_as_corrupt() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    enroll(&pool, device_id()).await;
    let repository = AdvisoryRepository::new(pool.clone());
    let value = advisory("CVE-2026-0888");
    let id = repository.upsert_advisory(&value).await?;
    let matching = match_advisory(None, &value)?;
    repository
        .record_match(
            id,
            device_id(),
            &matching,
            RiskDimensions {
                severity: Severity::High,
                exploitability: Exploitability::Unknown,
                exposure: Exposure::Unknown,
                confidence: Confidence::Low,
                remediation: Remediation::Unknown,
            },
        )
        .await?;
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE advisory_matches SET matched_fields_json='not-json' WHERE advisory_id=?")
        .bind(id.to_string())
        .execute(&pool)
        .await?;
    let error = repository
        .list_device_advisories(device_id(), at(150))
        .await
        .unwrap_err();
    assert_eq!(error, AdvisoryStoreError::Corrupt);
    assert_eq!(error.to_string(), "advisory data is corrupt");
    Ok(())
}

#[tokio::test]
async fn failed_fetches_are_stale_and_url_contract_is_strict() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = AdvisoryRepository::new(pool.clone());
    let failed = FeedFetch::new(
        AdvisorySource::Nvd,
        "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
        at(10),
        at(20),
    )?
    .with_response_metadata(
        Some(503),
        None,
        None,
        Some(lattice_store::FeedFailureClass::Network),
    )?;
    repository.record_feed_fetch(&failed).await?;
    let state: String =
        sqlx::query_scalar("SELECT effective_freshness FROM advisory_source_fetches")
            .fetch_one(&pool)
            .await?;
    assert_eq!(state, "stale");
    let redirect = FeedFetch::new(
        AdvisorySource::Nvd,
        "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
        at(10),
        at(20),
    )?
    .with_response_metadata(Some(302), None, None, None)?;
    repository.record_feed_fetch(&redirect).await?;
    let states: Vec<String> = sqlx::query_scalar(
        "SELECT effective_freshness FROM advisory_source_fetches ORDER BY rowid",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(states, ["stale", "stale"]);
    assert_eq!(repository.expire_sources(at(20)).await?, 0);
    let state: String =
        sqlx::query_scalar("SELECT effective_freshness FROM advisory_source_fetches")
            .fetch_one(&pool)
            .await?;
    assert_eq!(state, "stale");
    for bad in [
        "https://user@services.nvd.nist.gov/rest/json/cves/2.0",
        "https://services.nvd.nist.gov/rest/json/cves/2.0#x",
        "https://services.nvd.nist.gov/rest/json/cves/2.0 x",
        "https://example.test/vendor#x",
    ] {
        assert_eq!(
            FeedFetch::new(AdvisorySource::Nvd, bad.into(), at(10), at(20)).unwrap_err(),
            AdvisoryStoreError::Invalid
        );
    }
    assert_eq!(
        FeedFetch::new(
            AdvisorySource::Vendor,
            "https://user@vendor.example.test/security".into(),
            at(10),
            at(20)
        )
        .unwrap_err(),
        AdvisoryStoreError::Invalid
    );
    for bad in [
        "https://services.nvd.nist.gov:443/rest/json/cves/2.0",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json?x=1",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?x=1",
    ] {
        assert_eq!(
            FeedFetch::new(AdvisorySource::Nvd, bad.into(), at(10), at(20)).unwrap_err(),
            AdvisoryStoreError::Invalid
        );
    }
    assert!(
        FeedFetch::new(
            AdvisorySource::Vendor,
            "https://vendor.example.test/security/advisories".into(),
            at(10),
            at(20)
        )
        .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn official_feed_urls_accept_only_canonical_transport_shapes() -> anyhow::Result<()> {
    let start =
        chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")?.with_timezone(&Utc);
    let end = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00.000Z")?.with_timezone(&Utc);
    let canonical = lattice_advisory::transport::FeedRequest::nvd(0, 1000, start, end)?.url;
    assert!(FeedFetch::new(AdvisorySource::Nvd, canonical, at(10), at(20)).is_ok());
    for bad in [
        "https://services.nvd.nist.gov:443/rest/json/cves/2.0",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&startIndex=1&resultsPerPage=1000&lastModStartDate=2026-01-01T00%3A00%3A00.000Z&lastModEndDate=2026-01-02T00%3A00%3A00.000Z",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=999999&lastModStartDate=2026-01-01T00%3A00%3A00.000Z&lastModEndDate=2026-01-02T00%3A00%3A00.000Z",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=x&resultsPerPage=1000&lastModStartDate=garbage&lastModEndDate=garbage",
    ] {
        assert_eq!(
            FeedFetch::new(AdvisorySource::Nvd, bad.into(), at(10), at(20)).unwrap_err(),
            AdvisoryStoreError::Invalid
        );
    }
    let cisa =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    assert!(FeedFetch::new(AdvisorySource::CisaKev, cisa.into(), at(10), at(20)).is_ok());
    for bad in [
        format!("{cisa}?x=1"),
        "https://www.cisa.gov:443/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            .into(),
    ] {
        assert_eq!(
            FeedFetch::new(AdvisorySource::CisaKev, bad, at(10), at(20)).unwrap_err(),
            AdvisoryStoreError::Invalid
        );
    }
    Ok(())
}

#[tokio::test]
async fn conflict_returns_the_persisted_id_and_content_hash_tampering_fails_closed()
-> anyhow::Result<()> {
    let pool = connect_memory().await?;
    enroll(&pool, device_id()).await;
    let repository = AdvisoryRepository::new(pool.clone());
    let value = advisory("CVE-2026-7777");
    let left = repository.upsert_advisory(&value).await?;
    let right = AdvisoryRepository::new(pool.clone())
        .upsert_advisory(&value)
        .await?;
    assert_eq!(left, right);
    let matching = match_advisory(None, &value)?;
    repository
        .record_match(
            right,
            device_id(),
            &matching,
            RiskDimensions {
                severity: Severity::High,
                exploitability: Exploitability::Unknown,
                exposure: Exposure::Unknown,
                confidence: Confidence::Low,
                remediation: Remediation::Unknown,
            },
        )
        .await?;
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE advisories SET content_revision_sha256=? WHERE advisory_id=?")
        .bind("0".repeat(64))
        .bind(left.to_string())
        .execute(&pool)
        .await?;
    assert_eq!(
        repository
            .list_device_advisories(device_id(), at(12))
            .await
            .unwrap_err(),
        AdvisoryStoreError::Corrupt
    );
    Ok(())
}

#[tokio::test]
async fn provenance_stale_is_never_promoted_by_a_future_cache_expiry() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    enroll(&pool, device_id()).await;
    let repository = AdvisoryRepository::new(pool);
    let mut input = advisory("CVE-2026-8888").input().clone();
    input.freshness = Freshness::Stale;
    input.cache_expires_at = at(300);
    let stale = NormalizedAdvisory::new(input)?;
    let id = repository.upsert_advisory(&stale).await?;
    repository
        .record_match(
            id,
            device_id(),
            &match_advisory(None, &stale)?,
            RiskDimensions {
                severity: Severity::High,
                exploitability: Exploitability::Unknown,
                exposure: Exposure::Unknown,
                confidence: Confidence::Low,
                remediation: Remediation::Unknown,
            },
        )
        .await?;
    assert_eq!(
        repository
            .list_device_advisories(device_id(), at(200))
            .await?[0]
            .freshness,
        Freshness::Stale
    );
    Ok(())
}

#[tokio::test]
async fn persisted_stale_is_monotonic_and_impossible_future_state_is_corrupt() -> anyhow::Result<()>
{
    let pool = connect_memory().await?;
    enroll(&pool, device_id()).await;
    let repository = AdvisoryRepository::new(pool.clone());
    let value = advisory("CVE-2026-8899");
    let id = repository.upsert_advisory(&value).await?;
    repository
        .record_match(
            id,
            device_id(),
            &match_advisory(None, &value)?,
            RiskDimensions {
                severity: Severity::High,
                exploitability: Exploitability::Unknown,
                exposure: Exposure::Unknown,
                confidence: Confidence::Low,
                remediation: Remediation::Unknown,
            },
        )
        .await?;
    sqlx::query("UPDATE advisories SET effective_freshness='stale' WHERE advisory_id=?")
        .bind(id.to_string())
        .execute(&pool)
        .await?;
    assert_eq!(
        repository
            .list_device_advisories(device_id(), at(150))
            .await?[0]
            .freshness,
        Freshness::Stale
    );

    sqlx::query("UPDATE advisories SET effective_freshness='future_dated' WHERE advisory_id=?")
        .bind(id.to_string())
        .execute(&pool)
        .await?;
    assert_eq!(
        repository
            .list_device_advisories(device_id(), at(150))
            .await
            .unwrap_err(),
        AdvisoryStoreError::Corrupt
    );
    Ok(())
}

async fn enroll(pool: &sqlx::SqlitePool, device: DeviceId) {
    sqlx::query("INSERT INTO devices(device_id, first_seen_at, last_seen_at) VALUES (?, ?, ?)")
        .bind(device.to_string())
        .bind(at(1).to_rfc3339())
        .bind(at(1).to_rfc3339())
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn persists_idempotent_advisories_matches_and_effective_freshness() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    enroll(&pool, device_id()).await;
    let repository = AdvisoryRepository::new(pool.clone());
    let value = advisory("CVE-2026-0001");
    let id = repository.upsert_advisory(&value).await?;
    assert_eq!(repository.upsert_advisory(&value).await?, id);
    let matched = match_advisory(
        &lattice_advisory::DeviceIdentity::known("Acme", "Router", "1.2.3").unwrap(),
        &value,
    )?;
    repository
        .record_match(
            id,
            device_id(),
            &matched,
            RiskDimensions {
                severity: Severity::High,
                exploitability: Exploitability::ProofOfConcept,
                exposure: Exposure::PotentiallyExposed,
                confidence: Confidence::High,
                remediation: Remediation::Upgrade,
            },
        )
        .await?;
    let rows: Vec<DeviceAdvisory> = repository
        .list_device_advisories(device_id(), at(199))
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].advisory_id, id);
    assert_eq!(rows[0].freshness, Freshness::Fresh);
    assert_eq!(
        rows[0].matching.label(),
        lattice_advisory::MatchLabel::Exact
    );
    assert_eq!(rows[0].risk.severity, Severity::High);
    assert_eq!(
        repository
            .list_device_advisories(device_id(), at(200))
            .await?[0]
            .freshness,
        Freshness::Fresh
    );
    assert_eq!(
        repository
            .list_device_advisories(device_id(), at(201))
            .await?[0]
            .freshness,
        Freshness::Stale
    );
    assert_eq!(repository.expire_sources(at(201)).await?, 1);
    assert_eq!(repository.expire_sources(at(201)).await?, 0);
    Ok(())
}

#[tokio::test]
async fn match_requires_an_existing_device_and_fetch_metadata_never_stores_bodies()
-> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let repository = AdvisoryRepository::new(pool.clone());
    let value = advisory("CVE-2026-0002");
    let id = repository.upsert_advisory(&value).await?;
    let matched = match_advisory(None, &value)?;
    assert_eq!(
        repository
            .record_match(
                id,
                device_id(),
                &matched,
                RiskDimensions {
                    severity: Severity::High,
                    exploitability: Exploitability::Unknown,
                    exposure: Exposure::Unknown,
                    confidence: Confidence::Low,
                    remediation: Remediation::Unknown,
                }
            )
            .await
            .unwrap_err(),
        AdvisoryStoreError::Constraint
    );
    repository
        .record_feed_fetch(
            &FeedFetch::new(
                AdvisorySource::Nvd,
                "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
                at(102),
                at(200),
            )?
            .with_response_metadata(
                Some(304),
                Some("etag-123".into()),
                Some("Wed, 21 Oct 2015 07:28:00 GMT".into()),
                None,
            )?,
        )
        .await?;
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM pragma_table_info('advisory_source_fetches') ORDER BY cid",
    )
    .fetch_all(&pool)
    .await?;
    assert!(
        !columns
            .iter()
            .any(|name| name.contains("body") || name.contains("secret"))
    );
    Ok(())
}

#[tokio::test]
async fn schema_has_migration_and_advisory_uniqueness() -> anyhow::Result<()> {
    let pool = connect_memory().await?;
    let a = advisory("CVE-2026-0003");
    let repository = AdvisoryRepository::new(pool.clone());
    repository.upsert_advisory(&a).await?;
    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await?;
    assert_eq!(version, 21);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM advisories")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}
