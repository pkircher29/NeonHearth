use chrono::{DateTime, Duration, TimeZone, Utc};
use lattice_domain::{DeviceId, EvidenceFamily};
use lattice_policy::{
    DeadlineKind, DeadlineWarning, DevicePolicy, Evaluation, Identification, OwnerDecision,
    PolicyEngine, PolicyReason, Protection, RequestedAction, RiskSignal,
};

fn at(hours: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 23, 0, 0, 0).unwrap() + Duration::hours(hours)
}

fn device(first_seen_hours: i64) -> DevicePolicy {
    DevicePolicy {
        device_id: DeviceId::new(),
        first_seen_at: at(first_seen_hours),
        baseline_exempt: false,
        identification: Identification::Unknown,
        owner_decision: OwnerDecision::Pending,
        risk: RiskSignal::None,
        protection: Protection::None,
        extension_until: None,
    }
}

#[test]
fn one_time_baseline_is_half_open_and_clock_rollback_does_not_reopen_it() {
    let engine = PolicyEngine::new(at(0));
    assert!(engine.is_baseline_member(at(0)));
    assert!(engine.is_baseline_member(at(47) + Duration::minutes(59)));
    assert!(!engine.is_baseline_member(at(48)));
    assert!(!engine.is_baseline_member(at(96)));

    let persisted_start = engine.baseline_started_at();
    let restarted = PolicyEngine::new(persisted_start);
    assert_eq!(restarted.baseline_started_at(), persisted_start);
    assert!(!restarted.is_baseline_member(at(48)));
}

#[test]
fn baseline_exemption_prevents_age_quarantine_but_not_danger_quarantine() {
    let engine = PolicyEngine::new(at(0));
    let mut candidate = device(1);
    candidate.baseline_exempt = true;

    assert_eq!(
        engine.evaluate(&candidate, at(400)),
        Evaluation::visible(PolicyReason::BaselineExempt)
    );

    candidate.risk = RiskSignal::HighConfidenceDanger {
        confidence_basis_points: 9_500,
        evidence: "confirmed-command-and-control".into(),
    };
    assert_eq!(
        engine.evaluate(&candidate, at(400)),
        Evaluation::quarantine(PolicyReason::HighConfidenceDanger)
    );
}

#[test]
fn unknown_post_baseline_device_is_due_at_first_seen_plus_48_hours() {
    let engine = PolicyEngine::new(at(0));
    let candidate = device(60);

    let pending = engine.evaluate(&candidate, at(84));
    assert_eq!(pending.deadline.unwrap().kind, DeadlineKind::Unknown48Hours);
    assert_eq!(pending.deadline.unwrap().due_at, at(108));
    assert_eq!(pending.warning, Some(DeadlineWarning::Hours24));
    assert_eq!(pending.requested_action, RequestedAction::None);

    assert_eq!(
        engine.evaluate(&candidate, at(108)),
        Evaluation::quarantine(PolicyReason::UnknownDeadlineExpired)
    );
}

#[test]
fn automatic_identity_requires_threshold_and_two_families_then_uses_first_seen_plus_week() {
    let engine = PolicyEngine::new(at(0));
    let mut candidate = device(60);
    candidate.identification = Identification::Automatic {
        confidence_basis_points: 8_500,
        evidence_families: vec![EvidenceFamily::LinkLayer, EvidenceFamily::Service],
    };

    let pending = engine.evaluate(&candidate, at(84));
    assert_eq!(pending.deadline.unwrap().kind, DeadlineKind::Automatic7Days);
    assert_eq!(pending.deadline.unwrap().due_at, at(228));

    candidate.identification = Identification::Automatic {
        confidence_basis_points: 8_499,
        evidence_families: vec![
            EvidenceFamily::LinkLayer,
            EvidenceFamily::Addressing,
            EvidenceFamily::Naming,
        ],
    };
    assert_eq!(
        engine.evaluate(&candidate, at(108)),
        Evaluation::quarantine(PolicyReason::UnknownDeadlineExpired)
    );

    candidate.identification = Identification::Automatic {
        confidence_basis_points: 9_999,
        evidence_families: vec![EvidenceFamily::Service],
    };
    assert_eq!(
        engine.evaluate(&candidate, at(108)),
        Evaluation::quarantine(PolicyReason::UnknownDeadlineExpired)
    );
}

#[test]
fn duplicate_family_claims_do_not_buy_the_automatic_window() {
    let engine = PolicyEngine::new(at(0));
    let mut candidate = device(60);
    candidate.identification = Identification::Automatic {
        confidence_basis_points: 9_900,
        evidence_families: vec![EvidenceFamily::Service, EvidenceFamily::Service],
    };
    assert_eq!(
        engine.evaluate(&candidate, at(108)),
        Evaluation::quarantine(PolicyReason::UnknownDeadlineExpired)
    );
}

#[test]
fn offline_time_does_not_pause_deadlines_and_one_extension_uses_a_persisted_absolute_time() {
    let engine = PolicyEngine::new(at(0));
    let mut candidate = device(60);
    candidate.extension_until = Some(at(132));

    let extended = engine.evaluate(&candidate, at(120));
    assert_eq!(extended.deadline.unwrap().due_at, at(132));
    assert_eq!(extended.reason, PolicyReason::OwnerExtension);
    assert_eq!(
        engine.evaluate(&candidate, at(132)),
        Evaluation::quarantine(PolicyReason::UnknownDeadlineExpired)
    );
}

#[test]
fn warnings_escalate_at_24_6_and_1_hour_boundaries() {
    let engine = PolicyEngine::new(at(0));
    let candidate = device(60);
    assert_eq!(engine.evaluate(&candidate, at(83)).warning, None);
    assert_eq!(
        engine.evaluate(&candidate, at(84)).warning,
        Some(DeadlineWarning::Hours24)
    );
    assert_eq!(
        engine.evaluate(&candidate, at(102)).warning,
        Some(DeadlineWarning::Hours6)
    );
    assert_eq!(
        engine.evaluate(&candidate, at(107)).warning,
        Some(DeadlineWarning::Hour1)
    );
}

#[test]
fn owner_decisions_override_age_and_rejection_requests_a_permanent_ban() {
    let engine = PolicyEngine::new(at(0));
    let mut candidate = device(60);
    candidate.owner_decision = OwnerDecision::Approved;
    assert_eq!(
        engine.evaluate(&candidate, at(500)),
        Evaluation::visible(PolicyReason::OwnerApproved)
    );

    candidate.owner_decision = OwnerDecision::Rejected;
    assert_eq!(
        engine.evaluate(&candidate, at(500)),
        Evaluation::ban(PolicyReason::OwnerRejected)
    );

    candidate.owner_decision = OwnerDecision::Quarantined;
    assert_eq!(
        engine.evaluate(&candidate, at(61)),
        Evaluation::quarantine(PolicyReason::OwnerQuarantined)
    );
}

#[test]
fn protected_devices_turn_automatic_enforcement_into_owner_attention() {
    let engine = PolicyEngine::new(at(0));
    for protection in [
        Protection::Router,
        Protection::Collector,
        Protection::AdministratorPhone,
        Protection::SafetyDevice,
    ] {
        let mut candidate = device(60);
        candidate.protection = protection;
        let evaluation = engine.evaluate(&candidate, at(200));
        assert_eq!(evaluation.requested_action, RequestedAction::OwnerAttention);
        assert_eq!(evaluation.reason, PolicyReason::ProtectedDevice);
    }
}

#[test]
fn malformed_future_extension_and_low_confidence_danger_fail_closed_to_normal_policy() {
    let engine = PolicyEngine::new(at(0));
    let mut candidate = device(60);
    candidate.extension_until = Some(at(59));
    candidate.risk = RiskSignal::HighConfidenceDanger {
        confidence_basis_points: 8_499,
        evidence: "unconfirmed-finding".into(),
    };
    assert_eq!(
        engine.evaluate(&candidate, at(108)),
        Evaluation::quarantine(PolicyReason::UnknownDeadlineExpired)
    );
}

/// A persisted `first_seen_at` too close to the end of the calendar to carry
/// a deadline must not panic the evaluator (chrono's `+` would); it fails
/// closed to owner attention.
#[test]
fn out_of_range_first_seen_fails_closed_to_owner_attention() {
    let engine = PolicyEngine::new(at(0));
    let mut device = device(0);
    device.first_seen_at = chrono::DateTime::<Utc>::MAX_UTC - chrono::Duration::hours(1);
    let evaluation = engine.evaluate(&device, at(1));
    assert_eq!(evaluation.requested_action, RequestedAction::OwnerAttention);
    assert_eq!(evaluation.reason, PolicyReason::ProtectedDevice);
    assert!(!engine.is_baseline_member(device.first_seen_at));
    // The baseline window itself must not overflow either.
    let late = PolicyEngine::new(chrono::DateTime::<Utc>::MAX_UTC - chrono::Duration::hours(1));
    assert!(!late.is_baseline_member(late.baseline_started_at()));
}
