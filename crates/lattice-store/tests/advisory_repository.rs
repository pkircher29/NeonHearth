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
        Freshness::Stale
    );
    assert_eq!(repository.expire_sources(at(200)).await?, 1);
    assert_eq!(repository.expire_sources(at(200)).await?, 0);
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
                "https://example.test/feed".into(),
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
    assert_eq!(version, 18);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM advisories")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}
