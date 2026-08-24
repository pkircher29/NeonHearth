use chrono::{TimeZone, Utc};
use lattice_advisory::{
    Exploitability, Severity, VersionConstraint,
    kev::parse_kev,
    nvd::parse_nvd,
    transport::{KEV_URL, NVD_URL},
};

fn at(n: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(n, 0).unwrap()
}

#[test]
fn nvd_cpe_range_becomes_opaque_range_constraint() {
    let body = r#"{"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","published":"1970-01-01T00:00:00Z","lastModified":"1970-01-01T00:00:00Z","descriptions":[{"lang":"en","value":"Example vulnerability"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"HIGH"}}]},"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:acme:camera:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0","versionEndExcluding":"2.0"}]}]}]}}]}"#;
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
