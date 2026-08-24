use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use lattice_advisory::{
    Exploitability, Severity, SourceTrust, VersionConstraint,
    kev::parse_kev,
    nvd::{MAX_CPE_DEPTH, MAX_CPE_NODES, parse_nvd},
    transport::{KEV_URL, NVD_URL},
    vendor::{VendorRegistry, VendorSignature, VendorSource, parse_vendor},
};

fn at(n: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(n, 0).unwrap()
}

#[test]
fn nvd_emits_one_deduplicated_advisory_per_cpe_across_nested_nodes() {
    let body = serde_json::json!({"vulnerabilities": [{"cve": {
        "id": "CVE-2026-0001", "published": "1970-01-01T00:00:00Z", "lastModified": "1970-01-01T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
        "configurations": [{"nodes": [{"children": [
            {"cpeMatch": [{"criteria": "cpe:2.3:a:acme:camera:1.0:*:*:*:*:*:*:*"}, {"criteria": "cpe:2.3:a:acme:camera:1.0:*:*:*:*:*:*:*"}]},
            {"cpeMatch": [{"criteria": "cpe:2.3:a:acme:router:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"}]}
        ]}] }]
    }}]}).to_string();
    let result = parse_nvd(&body, at(1), at(2)).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].input().vendor, "acme");
    assert_eq!(
        result[0].input().firmware,
        VersionConstraint::Exact("1.0".into())
    );
    assert_eq!(
        result[1].input().firmware,
        VersionConstraint::LessThan("2.0".into())
    );
}

#[test]
fn nvd_strictly_validates_cve_cpe_escaping_and_cvss_score_precedence() {
    let body = r#"{"vulnerabilities":[{"cve":{"id":"CVE-2026-0002","published":"1970-01-01T00:00:00Z","lastModified":"1970-01-01T00:00:00Z","descriptions":[{"lang":"en","value":"Example vulnerability"}],"metrics":{"cvssMetricV40":[{"cvssData":{"baseScore":7.0}}],"cvssMetricV31":[{"cvssData":{"baseScore":9.1}}]},"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:acme\\:labs:cam\\\\era:*:*:*:*:*:*:*:*"}]}]}]}}]}"#;
    let result = parse_nvd(body, at(1), at(2)).unwrap();
    assert_eq!(result[0].input().vendor, "acme:labs");
    assert_eq!(result[0].input().model.as_deref(), Some("cam\\era"));
    assert_eq!(result[0].input().severity, Severity::High);
    assert!(parse_nvd(&body.replace("CVE-2026-0002", "CVE-2026-12"), at(1), at(2)).is_err());
}

#[test]
fn nvd_rejects_more_than_2000_outputs_before_expanding() {
    let matches = (0..2001)
        .map(|n| format!(r#"{{"criteria":"cpe:2.3:a:acme:p{n}:*:*:*:*:*:*:*:*"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{"vulnerabilities":[{{"cve":{{"id":"CVE-2026-0003","published":"1970-01-01T00:00:00Z","lastModified":"1970-01-01T00:00:00Z","descriptions":[{{"lang":"en","value":"title"}}],"configurations":[{{"nodes":[{{"cpeMatch":[{matches}]}}]}}]}}}}]}}"#
    );
    assert!(parse_nvd(&body, at(1), at(2)).is_err());
}

fn nvd_with_nodes(nodes: serde_json::Value) -> String {
    serde_json::json!({"vulnerabilities":[{"cve":{
        "id":"CVE-2026-0010", "published":"1970-01-01T00:00:00Z", "lastModified":"1970-01-01T00:00:00Z",
        "descriptions":[{"lang":"en","value":"title"}], "configurations":[{"nodes":nodes}]
    }}]}).to_string()
}

#[test]
fn nvd_iterative_traversal_enforces_depth_node_and_json_order_budgets() {
    let mut nested =
        serde_json::json!([{"cpeMatch":[{"criteria":"cpe:2.3:a:acme:deep:1:*:*:*:*:*:*:*"}]}]);
    for _ in 1..MAX_CPE_DEPTH {
        nested = serde_json::json!([{"children":nested}]);
    }
    assert!(parse_nvd(&nvd_with_nodes(nested.clone()), at(1), at(2)).is_ok());
    nested = serde_json::json!([{"children":nested}]);
    assert!(parse_nvd(&nvd_with_nodes(nested), at(1), at(2)).is_err());
    let boundary =
        serde_json::Value::Array((0..MAX_CPE_NODES).map(|_| serde_json::json!({})).collect());
    assert!(parse_nvd(&nvd_with_nodes(boundary), at(1), at(2)).is_ok());
    let wide = serde_json::Value::Array(
        (0..MAX_CPE_NODES + 1)
            .map(|_| serde_json::json!({}))
            .collect(),
    );
    assert!(parse_nvd(&nvd_with_nodes(wide), at(1), at(2)).is_err());
    let ordered = nvd_with_nodes(serde_json::json!([{"cpeMatch":[
        {"criteria":"cpe:2.3:a:acme:first:1:*:*:*:*:*:*:*"}, {"criteria":"cpe:2.3:a:acme:second:1:*:*:*:*:*:*:*"}
    ]}]));
    let values = parse_nvd(&ordered, at(1), at(2)).unwrap();
    assert_eq!(
        values
            .iter()
            .map(|value| value.input().model.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("first"), Some("second")]
    );
}

#[test]
fn nvd_keeps_escaped_wildcards_literal_and_falls_back_for_unescaped_selectors() {
    let escaped = nvd_with_nodes(
        serde_json::json!([{"cpeMatch":[{"criteria":"cpe:2.3:a:acme\\*:\\-camera:\\*:*:*:*:*:*:*:*"}]}]),
    );
    let value = parse_nvd(&escaped, at(1), at(2)).unwrap();
    assert_eq!(value[0].input().vendor, "acme*");
    assert_eq!(value[0].input().model.as_deref(), Some("-camera"));
    assert_eq!(
        value[0].input().firmware,
        VersionConstraint::Exact("*".into())
    );
    let wildcard = nvd_with_nodes(
        serde_json::json!([{"cpeMatch":[{"criteria":"cpe:2.3:a:*:camera:*:*:*:*:*:*:*:*"}]}]),
    );
    let value = parse_nvd(&wildcard, at(1), at(2)).unwrap();
    assert_eq!(value.len(), 1);
    assert_eq!(value[0].input().vendor, "unknown");
    assert_eq!(value[0].input().model, None);
    assert_eq!(value[0].input().firmware, VersionConstraint::Any);
}

#[test]
fn nvd_retains_generic_cves_and_distinguishes_full_cpe_selectors() {
    let bare = r#"{"vulnerabilities":[{"cve":{"id":"CVE-2026-0011","published":"1970-01-01T00:00:00Z","lastModified":"1970-01-01T00:00:00Z","descriptions":[{"lang":"en","value":"title"}]}}]}"#;
    let generic = parse_nvd(bare, at(1), at(2)).unwrap();
    assert_eq!(generic[0].input().vendor, "unknown");
    assert_eq!(generic[0].input().model, None);
    let no_vulnerable = nvd_with_nodes(
        serde_json::json!([{"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:a:acme:camera:1:*:*:*:*:*:*:*"}]}]),
    );
    assert_eq!(
        parse_nvd(&no_vulnerable, at(1), at(2)).unwrap()[0]
            .input()
            .vendor,
        "unknown"
    );
    let body = nvd_with_nodes(serde_json::json!([{"cpeMatch":[
        {"criteria":"cpe:2.3:a:acme:camera:*:*:*:*:*:*:*:*","versionEndExcluding":"2"},
        {"criteria":"cpe:2.3:a:acme:camera:*:*:*:*:*:*:*:*","versionEndExcluding":"3"}
    ]}]));
    assert_eq!(parse_nvd(&body, at(1), at(2)).unwrap().len(), 2);
}

#[test]
fn kev_includes_every_catalog_item_and_requires_documented_fields() {
    let body = r#"{"vulnerabilities":[{"cveID":"CVE-2026-0001","vendorProject":"Acme","product":"Camera","vulnerabilityName":"Acme Camera RCE","dateAdded":"1970-01-01","shortDescription":"desc","requiredAction":"Update","dueDate":"1970-01-02","knownRansomwareCampaignUse":"Unknown"}]}"#;
    let result = parse_kev(body, at(3), at(4)).unwrap();
    assert_eq!(
        result[0].input().exploitability,
        Exploitability::ActiveKnownExploitation
    );
    assert!(
        parse_kev(
            &body.replace("\"requiredAction\":\"Update\",", ""),
            at(3),
            at(4)
        )
        .is_err()
    );
    assert!(parse_kev(&body.replace("CVE-2026-0001", "CVE-x"), at(3), at(4)).is_err());
}

#[test]
fn kev_rejects_overlong_or_control_discarded_text() {
    let body = r#"{"vulnerabilities":[{"cveID":"CVE-2026-0001","vendorProject":"Acme","product":"Camera","vulnerabilityName":"name","dateAdded":"1970-01-01","shortDescription":"desc","requiredAction":"Update","dueDate":"1970-01-02","knownRansomwareCampaignUse":"Unknown"}]}"#;
    assert!(parse_kev(&body.replace("desc", &"x".repeat(513)), at(1), at(2)).is_err());
    assert!(parse_kev(&body.replace("Update", "Up\ndate"), at(1), at(2)).is_err());
}

#[test]
fn registered_unsigned_vendor_document_has_low_trust_and_is_schema_bounded() {
    let body = r#"{"schema_id":"neonhearth.vendor-advisory.v1","advisories":[{"id":"ACME-1","title":"Camera update","vendor":"Acme","model":"Camera","version":"1.2","published_at":"1970-01-01T00:00:00Z","modified_at":"1970-01-01T00:00:00Z","severity":"high","remediation":"upgrade"}]}"#;
    let registry =
        VendorRegistry::new([VendorSource::unsigned("https://advisories.acme.test/feed")]);
    let advisory = parse_vendor(
        body,
        "https://advisories.acme.test/feed",
        None,
        at(1),
        at(2),
        &registry,
    )
    .unwrap();
    assert_eq!(
        advisory[0].input().source_trust,
        SourceTrust::RegisteredHttps
    );
    assert_eq!(
        advisory[0].input().confidence,
        lattice_advisory::Confidence::Low
    );
    assert!(
        parse_vendor(
            body,
            "https://evil.test/feed",
            None,
            at(1),
            at(2),
            &registry
        )
        .is_err()
    );
}

#[test]
fn vendor_registry_rejects_duplicate_source_urls_and_oversized_signature_inputs() {
    let registry = VendorRegistry::new([
        VendorSource::unsigned("https://advisories.acme.test/feed"),
        VendorSource::unsigned("https://advisories.acme.test/feed"),
    ]);
    let body = r#"{"schema_id":"neonhearth.vendor-advisory.v1","advisories":[]}"#;
    assert!(
        parse_vendor(
            body,
            "https://advisories.acme.test/feed",
            None,
            at(1),
            at(2),
            &registry
        )
        .is_err()
    );
    let signature = VendorSignature::new("k".repeat(513), "A".repeat(1000));
    let registry =
        VendorRegistry::new([VendorSource::unsigned("https://advisories.acme.test/feed")]);
    assert!(
        parse_vendor(
            body,
            "https://advisories.acme.test/feed",
            Some(&signature),
            at(1),
            at(2),
            &registry
        )
        .is_err()
    );
}

#[test]
fn vendor_signature_covers_exact_body_and_invalid_signatures_are_low_trust() {
    let body = r#"{"schema_id":"neonhearth.vendor-advisory.v1","advisories":[{"id":"ACME-2","title":"Camera update","vendor":"Acme","version":"1.2","published_at":"1970-01-01T00:00:00Z","modified_at":"1970-01-01T00:00:00Z","severity":"high","remediation":"upgrade"}]}"#;
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let mut signed = b"NeonHearth vendor advisory v1\0".to_vec();
    signed.extend_from_slice(body.as_bytes());
    let signature = VendorSignature::new(
        "acme-2026",
        URL_SAFE_NO_PAD.encode(signing_key.sign(&signed).to_bytes()),
    );
    let registry = VendorRegistry::new([VendorSource::signed(
        "https://advisories.acme.test/feed",
        "acme-2026",
        signing_key.verifying_key().to_bytes(),
    )]);
    assert_eq!(
        parse_vendor(
            body,
            "https://advisories.acme.test/feed",
            Some(&signature),
            at(1),
            at(2),
            &registry
        )
        .unwrap()[0]
            .input()
            .source_trust,
        SourceTrust::VerifiedSignature
    );
    assert_eq!(
        parse_vendor(
            &format!(" {body}"),
            "https://advisories.acme.test/feed",
            Some(&signature),
            at(1),
            at(2),
            &registry
        )
        .unwrap()[0]
            .input()
            .source_trust,
        SourceTrust::Invalid
    );
}

#[test]
fn disabled_or_unknown_vendor_key_with_a_signature_is_never_treated_as_unsigned() {
    let body = r#"{"schema_id":"neonhearth.vendor-advisory.v1","advisories":[{"id":"ACME-3","title":"Camera update","vendor":"Acme","version":"1.2","published_at":"1970-01-01T00:00:00Z","modified_at":"1970-01-01T00:00:00Z","severity":"high","remediation":"upgrade"}]}"#;
    let registry = VendorRegistry::new([VendorSource::signed(
        "https://advisories.acme.test/feed",
        "revoked",
        [1; 32],
    )
    .disabled()]);
    let signature = VendorSignature::new("missing", "A".repeat(86));
    let result = parse_vendor(
        body,
        "https://advisories.acme.test/feed",
        Some(&signature),
        at(1),
        at(2),
        &registry,
    )
    .unwrap();
    assert_eq!(result[0].input().source_trust, SourceTrust::Invalid);
}

#[test]
fn nvd_cpe_range_becomes_opaque_range_constraint() {
    let body = r#"{"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","published":"1970-01-01T00:00:00Z","lastModified":"1970-01-01T00:00:00Z","descriptions":[{"lang":"en","value":"Example vulnerability"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.0}}]},"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:acme:camera:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0","versionEndExcluding":"2.0"}]}]}]}}]}"#;
    let result = parse_nvd(body, at(1), at(2)).unwrap();
    assert_eq!(result[0].input().source_url, NVD_URL);
    assert_eq!(result[0].input().severity, Severity::High);
    assert!(matches!(
        result[0].input().firmware,
        VersionConstraint::Range { .. }
    ));
}

#[test]
fn kev_ransomware_maps_active_exploitation_without_severity() {
    let body = r#"{"vulnerabilities":[{"cveID":"CVE-2026-0001","vendorProject":"Acme","product":"Camera","vulnerabilityName":"Acme Camera RCE","dateAdded":"1970-01-01","shortDescription":"desc","requiredAction":"Update","dueDate":"1970-01-02","knownRansomwareCampaignUse":"Known"}]}"#;
    let result = parse_kev(body, at(3), at(4)).unwrap();
    assert_eq!(result[0].input().source_url, KEV_URL);
    assert_eq!(
        result[0].input().exploitability,
        Exploitability::ActiveKnownExploitation
    );
    assert_eq!(result[0].input().severity, Severity::Unknown);
}
