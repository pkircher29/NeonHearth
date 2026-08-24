CREATE TABLE advisories (
    advisory_id TEXT PRIMARY KEY NOT NULL
        CHECK(length(advisory_id) = 36)
        CHECK(substr(advisory_id, 9, 1) = '-' AND substr(advisory_id, 14, 1) = '-' AND substr(advisory_id, 19, 1) = '-' AND substr(advisory_id, 24, 1) = '-')
        CHECK(lower(advisory_id) = advisory_id),
    source TEXT NOT NULL CHECK(source IN ('nvd', 'cisa_kev', 'vendor')),
    source_id TEXT NOT NULL CHECK(length(source_id) BETWEEN 1 AND 512),
    content_revision_sha256 TEXT NOT NULL CHECK(length(content_revision_sha256) = 64 AND content_revision_sha256 NOT GLOB '*[^0-9a-f]*'),
    provenance_sha256 TEXT NOT NULL CHECK(length(provenance_sha256) = 64 AND provenance_sha256 NOT GLOB '*[^0-9a-f]*'),
    source_url TEXT NOT NULL CHECK(length(source_url) BETWEEN 9 AND 512 AND source_url GLOB 'https://*'),
    title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 512),
    vendor TEXT NOT NULL CHECK(length(vendor) BETWEEN 1 AND 512),
    model TEXT CHECK(length(model) BETWEEN 1 AND 512),
    firmware_kind TEXT NOT NULL CHECK(firmware_kind IN ('any', 'exact', 'less_than', 'range')),
    firmware_min TEXT CHECK(length(firmware_min) BETWEEN 1 AND 512),
    firmware_max TEXT CHECK(length(firmware_max) BETWEEN 1 AND 512),
    published_at TEXT NOT NULL CHECK(length(published_at) BETWEEN 20 AND 40),
    modified_at TEXT NOT NULL CHECK(length(modified_at) BETWEEN 20 AND 40),
    retrieved_at TEXT NOT NULL CHECK(length(retrieved_at) BETWEEN 20 AND 40),
    cache_expires_at TEXT NOT NULL CHECK(length(cache_expires_at) BETWEEN 20 AND 40),
    provenance_freshness TEXT NOT NULL CHECK(provenance_freshness IN ('fresh', 'stale', 'future_dated')),
    effective_freshness TEXT NOT NULL CHECK(effective_freshness IN ('fresh', 'stale', 'future_dated')),
    source_trust TEXT NOT NULL CHECK(source_trust IN ('official_api', 'verified_signature', 'registered_https', 'invalid')),
    severity TEXT NOT NULL CHECK(severity IN ('none', 'low', 'medium', 'high', 'critical', 'unknown')),
    exploitability TEXT NOT NULL CHECK(exploitability IN ('none', 'proof_of_concept', 'active_known_exploitation', 'unknown')),
    exposure TEXT NOT NULL CHECK(exposure IN ('not_exposed', 'potentially_exposed', 'exposed', 'unknown')),
    confidence TEXT NOT NULL CHECK(confidence IN ('low', 'medium', 'high')),
    remediation TEXT NOT NULL CHECK(remediation IN ('upgrade', 'mitigate', 'monitor', 'none', 'unknown')),
    CHECK(modified_at >= published_at),
    CHECK(cache_expires_at >= retrieved_at),
    CHECK((firmware_kind = 'any' AND firmware_min IS NULL AND firmware_max IS NULL)
       OR (firmware_kind IN ('exact', 'less_than') AND firmware_min IS NOT NULL AND firmware_max IS NULL)
       OR (firmware_kind = 'range' AND firmware_min IS NOT NULL AND firmware_max IS NOT NULL)),
    UNIQUE(source, source_id, provenance_sha256),
    UNIQUE(source, source_id, content_revision_sha256)
);

CREATE TABLE advisory_matches (
    advisory_id TEXT NOT NULL REFERENCES advisories(advisory_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE
        CHECK(length(device_id) = 36 AND lower(device_id) = device_id),
    match_label TEXT NOT NULL CHECK(match_label IN ('exact', 'possible', 'contradicted', 'unknown')),
    matched_fields_json TEXT NOT NULL CHECK(length(matched_fields_json) BETWEEN 2 AND 64),
    explanation TEXT NOT NULL CHECK(length(explanation) BETWEEN 1 AND 512),
    match_confidence TEXT NOT NULL CHECK(match_confidence IN ('low', 'medium', 'high')),
    severity TEXT NOT NULL CHECK(severity IN ('none', 'low', 'medium', 'high', 'critical', 'unknown')),
    exploitability TEXT NOT NULL CHECK(exploitability IN ('none', 'proof_of_concept', 'active_known_exploitation', 'unknown')),
    exposure TEXT NOT NULL CHECK(exposure IN ('not_exposed', 'potentially_exposed', 'exposed', 'unknown')),
    confidence TEXT NOT NULL CHECK(confidence IN ('low', 'medium', 'high')),
    remediation TEXT NOT NULL CHECK(remediation IN ('upgrade', 'mitigate', 'monitor', 'none', 'unknown')),
    PRIMARY KEY(advisory_id, device_id)
);

CREATE TABLE advisory_source_fetches (
    fetch_id TEXT PRIMARY KEY NOT NULL CHECK(length(fetch_id) = 36 AND lower(fetch_id) = fetch_id),
    source TEXT NOT NULL CHECK(source IN ('nvd', 'cisa_kev', 'vendor')),
    source_url TEXT NOT NULL CHECK(length(source_url) BETWEEN 9 AND 512 AND source_url GLOB 'https://*'),
    http_status INTEGER CHECK(http_status BETWEEN 100 AND 599),
    retrieved_at TEXT NOT NULL CHECK(length(retrieved_at) BETWEEN 20 AND 40),
    cache_expires_at TEXT NOT NULL CHECK(length(cache_expires_at) BETWEEN 20 AND 40),
    effective_freshness TEXT NOT NULL CHECK(effective_freshness IN ('fresh', 'stale', 'future_dated')),
    etag TEXT CHECK(length(etag) BETWEEN 1 AND 512),
    last_modified TEXT CHECK(length(last_modified) BETWEEN 1 AND 512),
    failure_class TEXT CHECK(failure_class IN ('network', 'http', 'parse', 'validation', 'rate_limited')),
    CHECK(cache_expires_at >= retrieved_at)
);

CREATE INDEX advisories_source_effective_freshness_idx ON advisories(source, effective_freshness, cache_expires_at);
CREATE INDEX advisory_matches_device_advisory_idx ON advisory_matches(device_id, advisory_id);
CREATE INDEX advisory_source_fetches_source_retrieved_idx ON advisory_source_fetches(source, retrieved_at DESC);

UPDATE install_state SET schema_version = 18 WHERE singleton = 1 AND schema_version < 18;
