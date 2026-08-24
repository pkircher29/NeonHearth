use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use lattice_advisory::{
    Exploitability, Severity, SourceTrust, VersionConstraint,
    kev::parse_kev,
    nvd::parse_nvd,
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
