use chrono::{TimeZone, Utc};
use lattice_advisory::*;

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}

fn device(vendor: &str, model: &str, firmware: &str) -> DeviceIdentity {
    DeviceIdentity::new(vendor, model, firmware).unwrap()
}

fn advisory(vendor: &str, model: Option<&str>, firmware: VersionConstraint) -> NormalizedAdvisory {
    NormalizedAdvisory::new(AdvisoryInput {
        source: AdvisorySource::Nvd,
        source_id: "CVE-2026-0001".into(),
        source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
        title: "test advisory".into(),
        vendor: vendor.into(),
        model: model.map(str::to_owned),
        firmware,
        published_at: at(0),
        modified_at: at(0),
        retrieved_at: at(10),
        cache_expires_at: at(100),
        freshness: Freshness::Fresh,
        source_trust: SourceTrust::OfficialApi,
        severity: Severity::High,
        exploitability: Exploitability::Unknown,
        exposure: Exposure::Unknown,
        confidence: Confidence::Low,
        remediation: Remediation::Unknown,
    })
    .unwrap()
}

fn exact(v: &str) -> VersionConstraint {
    VersionConstraint::Exact(v.into())
}

#[test]
fn exact_match_is_distinct_from_possible_match() {
    let exact = match_advisory(
        &device("Acme", "Cam-1", "1.2"),
        &advisory("Acme", Some("Cam-1"), exact("1.2")),
    )
    .unwrap();
    assert_eq!(exact.label, MatchLabel::Exact);
    let possible = match_advisory(
        &device("Acme", "Cam-1", "unknown"),
        &advisory("Acme", Some("Cam-1"), VersionConstraint::Any),
    )
    .unwrap();
    assert_eq!(possible.label, MatchLabel::Possible);
}

#[test]
fn mismatches_and_missing_device_are_conservative() {
    assert_eq!(
        match_advisory(
            &device("Other", "Cam-1", "1.2"),
            &advisory("Acme", Some("Cam-1"), exact("1.2"))
        )
        .unwrap()
        .label,
        MatchLabel::Contradicted
    );
    assert_eq!(
        match_advisory(
            &device("Acme", "Cam-1", "1.3"),
            &advisory("Acme", Some("Cam-1"), exact("1.2"))
        )
        .unwrap()
        .label,
        MatchLabel::Contradicted
    );
    assert_eq!(
        match_advisory(None, &advisory("Acme", Some("Cam-1"), exact("1.2")))
            .unwrap()
            .label,
        MatchLabel::Possible
    );
}

#[test]
fn ranges_are_possible_without_provider_comparator() {
    for firmware in [
        VersionConstraint::Range {
            min: "1.9".into(),
            max: "1.10".into(),
        },
        VersionConstraint::LessThan("10".into()),
    ] {
        assert_eq!(
            match_advisory(
                &device("Acme", "Cam-1", "1.10"),
                &advisory("Acme", Some("Cam-1"), firmware)
            )
            .unwrap()
            .label,
            MatchLabel::Possible
        );
    }
}

#[test]
fn freshness_and_trust_never_become_exact() {
    for freshness in [Freshness::Stale, Freshness::FutureDated] {
        let mut a = advisory("Acme", Some("Cam-1"), exact("1.2"));
        let mut input = a.input().clone();
        input.freshness = freshness;
        if freshness == Freshness::FutureDated {
            input.modified_at = at(20);
        }
        a = NormalizedAdvisory::new(input)
            .unwrap_or_else(|_| advisory("Acme", Some("Cam-1"), exact("1.2")));
        assert_ne!(
            match_advisory(&device("Acme", "Cam-1", "1.2"), &a)
                .unwrap()
                .label,
            MatchLabel::Exact
        );
    }
    for trust in [SourceTrust::RegisteredHttps, SourceTrust::Invalid] {
        let mut input = advisory("Acme", Some("Cam-1"), exact("1.2"))
            .input()
            .clone();
        input.source_trust = trust;
        let a = NormalizedAdvisory::new(input).unwrap();
        assert_ne!(
            match_advisory(&device("Acme", "Cam-1", "1.2"), &a)
                .unwrap()
                .label,
            MatchLabel::Exact
        );
    }
}

#[test]
fn ascii_case_matches_but_unicode_is_not_normalized() {
    assert_eq!(
        match_advisory(
            &device("aCME", "CAM-1", "1.2"),
            &advisory("Acme", Some("cam-1"), exact("1.2"))
        )
        .unwrap()
        .label,
        MatchLabel::Exact
    );
    assert_eq!(
        match_advisory(
            &device("Café", "Cam-1", "1.2"),
            &advisory("Café", Some("Cam-1"), exact("1.2"))
        )
        .unwrap()
        .label,
        MatchLabel::Contradicted
    );
}

#[test]
fn contradictory_high_confidence_blocks_exact() {
    let d = device("Acme", "Cam-1", "1.2").contradictory_high_confidence(true);
    assert_eq!(
        match_advisory(&d, &advisory("Acme", Some("Cam-1"), exact("1.2")))
            .unwrap()
            .label,
        MatchLabel::Possible
    );
}

#[test]
fn device_identity_rejects_whitespace_and_supports_serde_round_trip() {
    assert!(DeviceIdentity::new(" Acme", "Cam-1", "1.2").is_err());
    assert!(DeviceIdentity::new("Acme", "Cam-1", "1.2\n").is_err());
    let identity = device("Acme", "Cam-1", "1.2").contradictory_high_confidence(true);
    let restored: DeviceIdentity =
        serde_json::from_str(&serde_json::to_string(&identity).unwrap()).unwrap();
    assert_eq!(restored, identity);
}

#[test]
fn compose_risk_rejects_mixed_source_ids() {
    let first = advisory("Acme", Some("Cam-1"), exact("1.2"));
    let mut input = first.input().clone();
    input.source_id = "CVE-2026-0002".into();
    let second = NormalizedAdvisory::new(input).unwrap();
    assert_eq!(
        compose_risk(&[first, second], None),
        Err(MatchError::MixedSourceIds)
    );
}

#[test]
fn risk_dimensions_remain_independent() {
    let mut nvd = advisory("Acme", Some("Cam-1"), exact("1.2"));
    let mut kev = advisory("Acme", Some("Cam-1"), exact("1.2"));
    let mut ni = nvd.input().clone();
    ni.source_id = "CVE-2026-0002".into();
    ni.severity = Severity::High;
    ni.remediation = Remediation::Upgrade;
    nvd = NormalizedAdvisory::new(ni).unwrap();
    let mut ki = kev.input().clone();
    ki.source = AdvisorySource::CisaKev;
    ki.source_id = "CVE-2026-0002".into();
    ki.exploitability = Exploitability::ActiveKnownExploitation;
    kev = NormalizedAdvisory::new(ki).unwrap();
    let risk = compose_risk(
        &[nvd, kev],
        Some(DeviceEvidence {
            exposure: Exposure::Exposed,
            confidence: Confidence::High,
        }),
    )
    .unwrap();
    assert_eq!(risk.severity, Severity::High);
    assert_eq!(risk.exploitability, Exploitability::ActiveKnownExploitation);
    assert_eq!(risk.exposure, Exposure::Exposed);
    assert_eq!(risk.confidence, Confidence::High);
    assert_eq!(risk.remediation, Remediation::Upgrade);
}
