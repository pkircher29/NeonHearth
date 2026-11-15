use chrono::{TimeZone, Utc};
use lattice_advisory::*;

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}

fn device(vendor: &str, model: &str, firmware: &str) -> DeviceIdentity {
    DeviceIdentity::known(vendor, model, firmware).unwrap()
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
    assert_eq!(exact.label(), MatchLabel::Exact);
    let possible = match_advisory(
        &DeviceIdentity::new("Acme", Some("Cam-1".into()), None).unwrap(),
        &advisory("Acme", Some("Cam-1"), VersionConstraint::Any),
    )
    .unwrap();
    assert_eq!(possible.label(), MatchLabel::Possible);
}

#[test]
fn mismatches_and_missing_device_are_conservative() {
    assert_eq!(
        match_advisory(
            &device("Other", "Cam-1", "1.2"),
            &advisory("Acme", Some("Cam-1"), exact("1.2"))
        )
        .unwrap()
        .label(),
        MatchLabel::Contradicted
    );
    assert_eq!(
        match_advisory(
            &device("Acme", "Cam-1", "1.3"),
            &advisory("Acme", Some("Cam-1"), exact("1.2"))
        )
        .unwrap()
        .label(),
        MatchLabel::Contradicted
    );
    assert_eq!(
        match_advisory(None, &advisory("Acme", Some("Cam-1"), exact("1.2")))
            .unwrap()
            .label(),
        MatchLabel::Possible
    );
}

#[test]
fn ranges_are_compared_numerically_by_a_typed_comparator() {
    // This test previously asserted `Possible` ("no provider comparator"),
    // encoding the bug that ranges were never evaluated. 1.10 is inside
    // 1.9..=1.10 and below 10 when compared as versions, not as text.
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
            .label(),
            MatchLabel::Exact
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
                .label(),
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
                .label(),
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
        .label(),
        MatchLabel::Exact
    );
    assert_eq!(
        match_advisory(
            &device("Café", "Cam-1", "1.2"),
            &advisory("Café", Some("Cam-1"), exact("1.2"))
        )
        .unwrap()
        .label(),
        MatchLabel::Contradicted
    );
}

#[test]
fn contradictory_high_confidence_blocks_exact() {
    let d = device("Acme", "Cam-1", "1.2").contradictory_high_confidence(true);
    assert_eq!(
        match_advisory(&d, &advisory("Acme", Some("Cam-1"), exact("1.2")))
            .unwrap()
            .label(),
        MatchLabel::Contradicted
    );
}

#[test]
fn device_identity_rejects_whitespace_and_supports_serde_round_trip() {
    assert!(DeviceIdentity::new(" Acme", Some("Cam-1".into()), Some("1.2".into())).is_err());
    assert!(DeviceIdentity::new("Acme", Some("Cam-1".into()), Some("1.2\n".into())).is_err());
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
fn absent_optional_identity_fields_never_contradict_or_match_exactly() {
    let d = DeviceIdentity::new("Acme", None, None).unwrap();
    let a = advisory("Acme", Some("Cam-1"), exact("unknown"));
    let matched = match_advisory(&d, &a).unwrap();
    assert_eq!(matched.label(), MatchLabel::Possible);
    assert_eq!(matched.matched_fields(), &[MatchedField::Vendor]);
    let generic = advisory("unknown", None, VersionConstraint::Any);
    assert_eq!(
        match_advisory(&d, &generic).unwrap().label(),
        MatchLabel::Unknown
    );
}

#[test]
fn advisory_match_serializes_as_output_contract() {
    let matched = match_advisory(
        &device("Acme", "Cam-1", "1.2"),
        &advisory("Acme", Some("Cam-1"), exact("1.2")),
    )
    .unwrap();
    let json = serde_json::to_value(&matched).unwrap();
    assert_eq!(json["label"], "Exact");
    assert!(json["matched_fields"].is_array());
}

#[test]
fn invalid_trust_and_empty_selectors_are_unknown_before_missing_device() {
    let mut input = advisory("Acme", Some("Cam-1"), exact("1.2"))
        .input()
        .clone();
    input.source_trust = SourceTrust::Invalid;
    assert_eq!(
        match_advisory(None, &NormalizedAdvisory::new(input).unwrap())
            .unwrap()
            .label(),
        MatchLabel::Unknown
    );
    let generic = advisory("unknown", None, VersionConstraint::Any);
    assert_eq!(
        match_advisory(None, &generic).unwrap().label(),
        MatchLabel::Unknown
    );
}

#[test]
fn risk_ranking_preserves_explicit_none_and_is_order_independent() {
    let mut first = advisory("Acme", Some("Cam-1"), exact("1.2"));
    let mut input = first.input().clone();
    input.severity = Severity::None;
    input.remediation = Remediation::None;
    input.exploitability = Exploitability::None;
    first = NormalizedAdvisory::new(input).unwrap();
    let mut second = advisory("Acme", Some("Cam-1"), exact("1.2"));
    let mut input = second.input().clone();
    input.severity = Severity::Unknown;
    input.remediation = Remediation::Unknown;
    input.exploitability = Exploitability::Unknown;
    second = NormalizedAdvisory::new(input).unwrap();
    let a = compose_risk(&[first.clone(), second.clone()], None).unwrap();
    let b = compose_risk(&[second, first], None).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.severity, Severity::None);
    assert_eq!(a.remediation, Remediation::None);
    assert_eq!(a.exploitability, Exploitability::None);
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

fn label(device: &DeviceIdentity, advisory: &NormalizedAdvisory) -> MatchLabel {
    match_advisory(device, advisory).unwrap().label()
}

#[test]
fn version_prefix_and_build_suffix_do_not_cause_false_contradictions() {
    // Regression: "v1.2.3" in the advisory against "1.2.3" on the device was a
    // byte mismatch and returned Contradicted/High, silently dropping the CVE.
    for (advisory_version, device_version) in [
        ("v1.2.3", "1.2.3"),
        ("1.2.3", "V1.2.3"),
        ("1.2.3", "1.2.3+build7"),
        ("1.2", "1.2.0"),
    ] {
        assert_eq!(
            label(
                &device("Acme", "Cam-1", device_version),
                &advisory("Acme", Some("Cam-1"), exact(advisory_version))
            ),
            MatchLabel::Exact,
            "{advisory_version} vs {device_version}"
        );
    }
    assert_eq!(
        label(
            &device("Acme", "Cam-1", "1.2.4"),
            &advisory("Acme", Some("Cam-1"), exact("1.2.3"))
        ),
        MatchLabel::Contradicted
    );
}

#[test]
fn unparsable_versions_are_possible_never_contradicted() {
    for device_version in ["factory-image", "1.2-rc1"] {
        assert_eq!(
            label(
                &device("Acme", "Cam-1", device_version),
                &advisory("Acme", Some("Cam-1"), exact("1.2"))
            ),
            MatchLabel::Possible,
            "{device_version}"
        );
    }
    assert_eq!(
        label(
            &device("Acme", "Cam-1", "factory-image"),
            &advisory(
                "Acme",
                Some("Cam-1"),
                VersionConstraint::LessThan("2.1".into())
            )
        ),
        MatchLabel::Possible
    );
}

#[test]
fn fixed_firmware_is_not_affected_by_a_less_than_advisory() {
    // Regression: LessThan/Range matched every version, so a device already on
    // the fixed release was reported as possibly vulnerable.
    let fixed_in_2_1 = advisory(
        "Acme",
        Some("Cam-1"),
        VersionConstraint::LessThan("2.1".into()),
    );
    assert_eq!(
        label(&device("Acme", "Cam-1", "3.0"), &fixed_in_2_1),
        MatchLabel::Contradicted
    );
    assert_eq!(
        label(&device("Acme", "Cam-1", "2.1"), &fixed_in_2_1),
        MatchLabel::Contradicted
    );
    assert_eq!(
        label(&device("Acme", "Cam-1", "2.0.9"), &fixed_in_2_1),
        MatchLabel::Exact
    );
    let inclusive = advisory(
        "Acme",
        Some("Cam-1"),
        VersionConstraint::LessThan("<=2.1".into()),
    );
    assert_eq!(
        label(&device("Acme", "Cam-1", "2.1"), &inclusive),
        MatchLabel::Exact
    );
}

#[test]
fn ranges_keep_inclusive_exclusive_and_open_ended_bounds() {
    let range = |min: &str, max: &str| {
        advisory(
            "Acme",
            Some("Cam-1"),
            VersionConstraint::Range {
                min: min.into(),
                max: max.into(),
            },
        )
    };
    let d = |v: &str| device("Acme", "Cam-1", v);
    assert_eq!(label(&d("1.0"), &range("1.0", "<2.0")), MatchLabel::Exact);
    assert_eq!(
        label(&d("2.0"), &range("1.0", "<2.0")),
        MatchLabel::Contradicted
    );
    assert_eq!(
        label(&d("1.0"), &range(">1.0", "2.0")),
        MatchLabel::Contradicted
    );
    assert_eq!(label(&d("9.9"), &range("2.0", "*")), MatchLabel::Exact);
    assert_eq!(
        label(&d("1.9"), &range("2.0", "*")),
        MatchLabel::Contradicted
    );
}

#[test]
fn an_expired_cache_window_blocks_exact_when_a_clock_is_supplied() {
    // Regression: freshness was frozen at parse time, so a week-old cached
    // advisory stayed Exact-eligible forever.
    let value = advisory("Acme", Some("Cam-1"), exact("1.2"));
    let d = device("Acme", "Cam-1", "1.2");
    assert_eq!(
        match_advisory_at(&d, &value, at(100)).unwrap().label(),
        MatchLabel::Exact
    );
    assert_eq!(
        match_advisory_at(&d, &value, at(101)).unwrap().label(),
        MatchLabel::Possible
    );
}
