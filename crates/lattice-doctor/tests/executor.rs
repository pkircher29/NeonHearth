//! Repair executor tests: snapshot -> apply -> verify -> rollback lifecycle,
//! automatic rollback on regression and mid-apply failure, and rollback
//! failures being reported rather than swallowed.

use chrono::{TimeZone, Utc};
use lattice_doctor::FixedClock;
use lattice_doctor::check::{CheckKind, Measurement, Metric, Unit};
use lattice_doctor::executor::{
    FakeRepairTransport, MetricDirection, RepairEventKind, RepairExecutor, RepairOutcome,
    RepairTransportError, RollbackOutcome, RollbackSkipReason, StateEntry, Symptom, TransportCall,
    Verdict,
};
use lattice_doctor::repair::{
    ApprovalAction, ApprovalId, ApprovedRepair, ExecutableRepair, SafeAction, StateKey,
};

fn executor() -> RepairExecutor {
    RepairExecutor::with_clock(FixedClock(
        Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap(),
    ))
}

fn meas(metric: Metric, value: f64) -> Measurement {
    Measurement {
        metric,
        value,
        unit: Unit::Percent,
        observed_at: Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap(),
    }
}

fn loss_symptom() -> Symptom {
    Symptom::new(
        CheckKind::LossLatency,
        Metric::LossPercent,
        MetricDirection::LowerIsBetter,
        1.0,
    )
    .unwrap()
}

fn dns_repair() -> ExecutableRepair {
    ExecutableRepair::Approved(ApprovedRepair::new(
        ApprovalAction::ChangeDnsServers {
            servers: vec!["9.9.9.9".into()],
        },
        ApprovalId::try_new("approval-1").unwrap(),
    ))
}

fn snapshot_entries() -> Vec<StateEntry> {
    vec![StateEntry {
        key: StateKey::DnsServers,
        value: "192.168.1.1".into(),
    }]
}

fn event_names(report: &lattice_doctor::executor::RepairReport) -> Vec<&'static str> {
    report
        .events
        .iter()
        .map(|event| match event.kind {
            RepairEventKind::Started { .. } => "started",
            RepairEventKind::Snapshotted { .. } => "snapshotted",
            RepairEventKind::Applied => "applied",
            RepairEventKind::ApplyFailed { .. } => "apply_failed",
            RepairEventKind::Verified { .. } => "verified",
            RepairEventKind::VerificationFailed { .. } => "verification_failed",
            RepairEventKind::RolledBack { .. } => "rolled_back",
        })
        .collect()
}

#[tokio::test]
async fn improved_repair_reports_before_and_after_without_rollback() {
    let transport = FakeRepairTransport::new()
        .with_snapshot(snapshot_entries())
        .push_measurements(vec![meas(Metric::LossPercent, 10.0)])
        .push_measurements(vec![meas(Metric::LossPercent, 2.0)]);
    let report = executor()
        .execute(&transport, &dns_repair(), &loss_symptom())
        .await;

    assert_eq!(
        report.outcome,
        RepairOutcome::Completed {
            verdict: Verdict::Improved
        }
    );
    let verification = report.verification.as_ref().unwrap();
    assert_eq!(verification.before.value, 10.0);
    assert_eq!(verification.after.value, 2.0);
    assert_eq!(
        report.rollback,
        RollbackOutcome::NotAttempted {
            reason: RollbackSkipReason::NotNeeded
        }
    );
    assert_eq!(
        event_names(&report),
        vec!["started", "snapshotted", "applied", "verified"]
    );
    let sequences: Vec<u32> = report.events.iter().map(|event| event.sequence).collect();
    assert_eq!(sequences, vec![0, 1, 2, 3]);
    assert_eq!(
        transport.calls(),
        vec![
            TransportCall::Snapshot,
            TransportCall::Measure,
            TransportCall::Apply,
            TransportCall::Measure,
        ]
    );
}

#[tokio::test]
async fn unchanged_repair_keeps_the_change_and_reports_it() {
    let transport = FakeRepairTransport::new()
        .with_snapshot(snapshot_entries())
        .push_measurements(vec![meas(Metric::LossPercent, 10.0)])
        .push_measurements(vec![meas(Metric::LossPercent, 9.5)]);
    let report = executor()
        .execute(&transport, &dns_repair(), &loss_symptom())
        .await;

    assert_eq!(
        report.outcome,
        RepairOutcome::Completed {
            verdict: Verdict::Unchanged
        }
    );
    assert_eq!(
        report.rollback,
        RollbackOutcome::NotAttempted {
            reason: RollbackSkipReason::NotNeeded
        }
    );
    assert!(!transport.calls().contains(&TransportCall::Restore));
}

#[tokio::test]
async fn regression_rolls_a_reversible_repair_back_automatically() {
    let transport = FakeRepairTransport::new()
        .with_snapshot(snapshot_entries())
        .push_measurements(vec![meas(Metric::LossPercent, 10.0)])
        .push_measurements(vec![meas(Metric::LossPercent, 30.0)]);
    let report = executor()
        .execute(&transport, &dns_repair(), &loss_symptom())
        .await;

    assert_eq!(
        report.outcome,
        RepairOutcome::Completed {
            verdict: Verdict::Regressed
        }
    );
    assert_eq!(report.rollback, RollbackOutcome::Succeeded);
    assert_eq!(
        event_names(&report),
        vec![
            "started",
            "snapshotted",
            "applied",
            "verified",
            "rolled_back"
        ]
    );
    assert_eq!(
        transport.calls().last().copied(),
        Some(TransportCall::Restore)
    );
    let verification = report.verification.as_ref().unwrap();
    assert_eq!(verification.before.value, 10.0);
    assert_eq!(verification.after.value, 30.0);
}

#[tokio::test]
async fn regression_of_a_non_reversible_repair_is_reported_not_rolled_back() {
    let transport = FakeRepairTransport::new()
        .push_measurements(vec![meas(Metric::LossPercent, 10.0)])
        .push_measurements(vec![meas(Metric::LossPercent, 30.0)]);
    let repair = ExecutableRepair::Safe {
        action: SafeAction::RestartCollectorWorker,
    };
    let report = executor()
        .execute(&transport, &repair, &loss_symptom())
        .await;

    assert_eq!(
        report.outcome,
        RepairOutcome::Completed {
            verdict: Verdict::Regressed
        }
    );
    assert_eq!(
        report.rollback,
        RollbackOutcome::NotAttempted {
            reason: RollbackSkipReason::NotReversible
        }
    );
    assert!(!transport.calls().contains(&TransportCall::Restore));
    assert!(event_names(&report).contains(&"rolled_back"));
}

#[tokio::test]
async fn mid_apply_failure_triggers_rollback_of_a_reversible_repair() {
    let transport = FakeRepairTransport::new()
        .with_snapshot(snapshot_entries())
        .with_apply_error(RepairTransportError::Apply("router rejected change".into()))
        .push_measurements(vec![meas(Metric::LossPercent, 10.0)]);
    let report = executor()
        .execute(&transport, &dns_repair(), &loss_symptom())
        .await;

    assert!(matches!(
        &report.outcome,
        RepairOutcome::ApplyFailed { error } if error.contains("router rejected change")
    ));
    assert_eq!(report.rollback, RollbackOutcome::Succeeded);
    assert_eq!(
        event_names(&report),
        vec!["started", "snapshotted", "apply_failed", "rolled_back"]
    );
    assert_eq!(
        transport.calls(),
        vec![
            TransportCall::Snapshot,
            TransportCall::Measure,
            TransportCall::Apply,
            TransportCall::Restore,
        ]
    );
}

#[tokio::test]
async fn rollback_failure_is_reported_not_swallowed() {
    let transport = FakeRepairTransport::new()
        .with_snapshot(snapshot_entries())
        .with_restore_error(RepairTransportError::Restore("router session lost".into()))
        .push_measurements(vec![meas(Metric::LossPercent, 10.0)])
        .push_measurements(vec![meas(Metric::LossPercent, 30.0)]);
    let report = executor()
        .execute(&transport, &dns_repair(), &loss_symptom())
        .await;

    assert!(matches!(
        &report.rollback,
        RollbackOutcome::Failed { error } if error.contains("router session lost")
    ));
    // The failed rollback also lands in the audit trail.
    assert!(report.events.iter().any(|event| matches!(
        &event.kind,
        RepairEventKind::RolledBack {
            outcome: RollbackOutcome::Failed { .. }
        }
    )));
}

#[tokio::test]
async fn snapshot_failure_stops_before_any_state_change() {
    let transport = FakeRepairTransport::new()
        .with_snapshot_error(RepairTransportError::Snapshot("registry busy".into()));
    let report = executor()
        .execute(&transport, &dns_repair(), &loss_symptom())
        .await;

    assert!(matches!(
        &report.outcome,
        RepairOutcome::SnapshotFailed { error } if error.contains("registry busy")
    ));
    assert_eq!(transport.calls(), vec![TransportCall::Snapshot]);
    assert_eq!(event_names(&report), vec!["started"]);
}

#[tokio::test]
async fn missing_baseline_metric_stops_before_apply() {
    let transport = FakeRepairTransport::new()
        .with_snapshot(snapshot_entries())
        .push_measurements(vec![meas(Metric::RttMs, 20.0)]);
    let report = executor()
        .execute(&transport, &dns_repair(), &loss_symptom())
        .await;

    assert!(matches!(
        &report.outcome,
        RepairOutcome::BaselineFailed { error } if error.contains("LossPercent")
    ));
    assert!(!transport.calls().contains(&TransportCall::Apply));
}

#[tokio::test]
async fn unverifiable_result_rolls_back_and_reports_verification_failure() {
    let transport = FakeRepairTransport::new()
        .with_snapshot(snapshot_entries())
        .push_measurements(vec![meas(Metric::LossPercent, 10.0)])
        .push_measure_error(RepairTransportError::Measure("probe path down".into()));
    let report = executor()
        .execute(&transport, &dns_repair(), &loss_symptom())
        .await;

    assert!(matches!(
        &report.outcome,
        RepairOutcome::VerificationFailed { error } if error.contains("probe path down")
    ));
    assert_eq!(report.rollback, RollbackOutcome::Succeeded);
    assert_eq!(
        event_names(&report),
        vec![
            "started",
            "snapshotted",
            "applied",
            "verification_failed",
            "rolled_back"
        ]
    );
}

#[tokio::test]
async fn higher_is_better_metrics_compare_in_the_right_direction() {
    let symptom = Symptom::new(
        CheckKind::InternetReachability,
        Metric::ReachabilitySuccess,
        MetricDirection::HigherIsBetter,
        0.5,
    )
    .unwrap();
    let transport = FakeRepairTransport::new()
        .push_measurements(vec![meas(Metric::ReachabilitySuccess, 0.0)])
        .push_measurements(vec![meas(Metric::ReachabilitySuccess, 1.0)]);
    let repair = ExecutableRepair::Safe {
        action: SafeAction::RetryRouterSession,
    };
    let report = executor().execute(&transport, &repair, &symptom).await;
    assert_eq!(
        report.outcome,
        RepairOutcome::Completed {
            verdict: Verdict::Improved
        }
    );

    let transport = FakeRepairTransport::new()
        .push_measurements(vec![meas(Metric::ReachabilitySuccess, 1.0)])
        .push_measurements(vec![meas(Metric::ReachabilitySuccess, 0.0)]);
    let repair = ExecutableRepair::Safe {
        action: SafeAction::RefreshAppCaches,
    };
    let report = executor().execute(&transport, &repair, &symptom).await;
    assert_eq!(
        report.outcome,
        RepairOutcome::Completed {
            verdict: Verdict::Regressed
        }
    );
    // RefreshAppCaches is reversible, so the regression rolled back.
    assert_eq!(report.rollback, RollbackOutcome::Succeeded);
}

#[test]
fn symptom_rejects_non_positive_or_non_finite_deltas() {
    assert!(
        Symptom::new(
            CheckKind::LossLatency,
            Metric::LossPercent,
            MetricDirection::LowerIsBetter,
            0.0,
        )
        .is_err()
    );
    assert!(
        Symptom::new(
            CheckKind::LossLatency,
            Metric::LossPercent,
            MetricDirection::LowerIsBetter,
            f64::NAN,
        )
        .is_err()
    );
    assert!(
        Symptom::new(
            CheckKind::LossLatency,
            Metric::LossPercent,
            MetricDirection::LowerIsBetter,
            -1.0,
        )
        .is_err()
    );
}
