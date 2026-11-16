//! Snapshot -> apply -> verify -> rollback repair execution (N4).
//!
//! [`RepairExecutor`] is pure sequencing logic over an injected
//! [`RepairTransport`]. It snapshots the repair's named state keys, measures
//! the original symptom as a baseline, applies exactly one repair, re-measures
//! the same symptom, reports [`Verdict::Improved`] / [`Verdict::Unchanged`] /
//! [`Verdict::Regressed`] with before/after values, and automatically rolls a
//! reversible repair back on regression, on a mid-apply failure, or when
//! verification cannot be measured. Every step lands in a typed, ordered
//! [`RepairEvent`] sequence suitable for persistence.

use crate::check::{CheckKind, Measurement, Metric};
use crate::repair::{
    ApprovalAction, ExecutableRepair, RepairClass, RepairPlan, SafeAction, StateKey,
    UnavailableReason,
};
use crate::{Clock, DoctorError, SystemClock};
use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "test-support"))]
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;
use utoipa::ToSchema;

/// Transport-level failure while snapshotting, applying, restoring, or
/// measuring.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RepairTransportError {
    #[error("snapshot failed: {0}")]
    Snapshot(String),
    #[error("apply failed: {0}")]
    Apply(String),
    #[error("restore failed: {0}")]
    Restore(String),
    #[error("measurement failed: {0}")]
    Measure(String),
}

/// One captured piece of pre-repair state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StateEntry {
    pub key: StateKey,
    /// Opaque serialized state the transport knows how to restore.
    pub value: String,
}

/// Side-effect boundary for repairs. The executor never touches the system.
pub trait RepairTransport: Send + Sync {
    /// Whether this transport can really execute the action a plan proposes.
    /// `None` means it can; `Some(reason)` means a caller must refuse the plan
    /// up front, before any approval is minted or spent. Defaults to "can" so
    /// transports that implement every action need not say so.
    fn unavailable_reason(&self, _plan: &RepairPlan) -> Option<UnavailableReason> {
        None
    }

    fn snapshot(
        &self,
        keys: &[StateKey],
    ) -> impl std::future::Future<Output = Result<Vec<StateEntry>, RepairTransportError>> + Send;

    fn apply(
        &self,
        repair: &ExecutableRepair,
    ) -> impl std::future::Future<Output = Result<(), RepairTransportError>> + Send;

    fn restore(
        &self,
        entries: &[StateEntry],
    ) -> impl std::future::Future<Output = Result<(), RepairTransportError>> + Send;

    /// Re-run the measurements backing one check and return them.
    fn measure(
        &self,
        check: CheckKind,
    ) -> impl std::future::Future<Output = Result<Vec<Measurement>, RepairTransportError>> + Send;
}

/// Which direction moves the symptom metric toward health.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MetricDirection {
    LowerIsBetter,
    HigherIsBetter,
}

/// The measured symptom a repair is judged against: the ORIGINAL check and
/// metric that motivated the repair.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(try_from = "SymptomWire")]
pub struct Symptom {
    check: CheckKind,
    metric: Metric,
    direction: MetricDirection,
    min_meaningful_delta: f64,
}

/// Unvalidated wire form; deserialising a [`Symptom`] re-runs [`Symptom::new`].
#[derive(Deserialize)]
struct SymptomWire {
    check: CheckKind,
    metric: Metric,
    direction: MetricDirection,
    min_meaningful_delta: f64,
}

impl TryFrom<SymptomWire> for Symptom {
    type Error = DoctorError;
    fn try_from(wire: SymptomWire) -> Result<Self, DoctorError> {
        Self::new(
            wire.check,
            wire.metric,
            wire.direction,
            wire.min_meaningful_delta,
        )
    }
}

impl Symptom {
    pub fn new(
        check: CheckKind,
        metric: Metric,
        direction: MetricDirection,
        min_meaningful_delta: f64,
    ) -> Result<Self, DoctorError> {
        if !min_meaningful_delta.is_finite() || min_meaningful_delta <= 0.0 {
            return Err(DoctorError::InvalidSymptom(
                "min_meaningful_delta must be finite and positive",
            ));
        }
        Ok(Self {
            check,
            metric,
            direction,
            min_meaningful_delta,
        })
    }

    pub fn check(&self) -> CheckKind {
        self.check
    }

    pub fn metric(&self) -> Metric {
        self.metric
    }
}

/// Before/after comparison result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Improved,
    Unchanged,
    Regressed,
}

/// The verified comparison, with the actual before/after measurements.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Verification {
    pub verdict: Verdict,
    pub before: Measurement,
    pub after: Measurement,
}

/// Why a rollback was not attempted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RollbackSkipReason {
    /// The repair did not regress anything.
    NotNeeded,
    /// The action cannot be undone by restoring the snapshot.
    NotReversible,
}

/// Result of the automatic rollback decision. A failed rollback is reported,
/// never swallowed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum RollbackOutcome {
    NotAttempted { reason: RollbackSkipReason },
    Succeeded,
    Failed { error: String },
}

/// One step in the auditable repair lifecycle.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "event")]
pub enum RepairEventKind {
    Started {
        class: RepairClass,
        description: String,
    },
    Snapshotted {
        keys: Vec<StateKey>,
        baseline: Measurement,
    },
    Applied,
    ApplyFailed {
        error: String,
    },
    Verified {
        verdict: Verdict,
        before: Measurement,
        after: Measurement,
    },
    VerificationFailed {
        error: String,
    },
    RolledBack {
        outcome: RollbackOutcome,
    },
}

/// A timestamped, ordered lifecycle event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RepairEvent {
    pub sequence: u32,
    pub at: chrono::DateTime<chrono::Utc>,
    pub kind: RepairEventKind,
}

/// Terminal outcome of one execution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum RepairOutcome {
    Completed { verdict: Verdict },
    SnapshotFailed { error: String },
    BaselineFailed { error: String },
    ApplyFailed { error: String },
    VerificationFailed { error: String },
}

/// Full record of one repair execution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RepairReport {
    pub class: RepairClass,
    pub description: String,
    pub outcome: RepairOutcome,
    pub verification: Option<Verification>,
    pub rollback: RollbackOutcome,
    pub events: Vec<RepairEvent>,
}

/// Upper bounds on each transport call so a hung transport cannot stall a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairTimeouts {
    pub snapshot: Duration,
    pub apply: Duration,
    pub restore: Duration,
    pub measure: Duration,
}

impl Default for RepairTimeouts {
    fn default() -> Self {
        Self {
            snapshot: Duration::from_secs(10),
            apply: Duration::from_secs(60),
            restore: Duration::from_secs(60),
            measure: Duration::from_secs(20),
        }
    }
}

/// How long a repair is given to take effect before it is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettleProfile {
    /// Wait after `apply` before the first measurement.
    pub settle: Duration,
    /// While the verdict is `Regressed`, keep re-measuring this long.
    pub verify_window: Duration,
    pub poll_interval: Duration,
}

impl SettleProfile {
    pub const IMMEDIATE: Self = Self {
        settle: Duration::ZERO,
        verify_window: Duration::ZERO,
        poll_interval: Duration::ZERO,
    };

    const fn secs(settle: u64, window: u64, poll: u64) -> Self {
        Self {
            settle: Duration::from_secs(settle),
            verify_window: Duration::from_secs(window),
            poll_interval: Duration::from_secs(poll),
        }
    }

    /// Per-action table: a router reboot needs minutes, a cache refresh none.
    pub fn for_repair(repair: &ExecutableRepair) -> Self {
        match repair {
            ExecutableRepair::Safe { action } => match action {
                SafeAction::RefreshAppCaches => Self::IMMEDIATE,
                SafeAction::RestartCollectorWorker | SafeAction::RepairTailscaleServe => {
                    Self::secs(2, 10, 2)
                }
                SafeAction::RenewCollectorLease => Self::secs(3, 15, 3),
                SafeAction::RetryRouterSession => Self::secs(1, 5, 1),
            },
            ExecutableRepair::Approved(approved) => match approved.action() {
                ApprovalAction::RebootRouter => Self::secs(60, 240, 5),
                ApprovalAction::ResetAdapter { .. } => Self::secs(5, 30, 2),
                ApprovalAction::RenewDhcpLease { .. } => Self::secs(3, 20, 2),
                ApprovalAction::ChangeDnsServers { .. }
                | ApprovalAction::SetDhcpReservation { .. }
                | ApprovalAction::BlockDevice { .. }
                | ApprovalAction::UnblockDevice { .. }
                | ApprovalAction::SetInterfaceMtu { .. } => Self::secs(1, 10, 1),
            },
        }
    }
}

/// Whether verification uses the per-action settle table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlePolicy {
    PerAction,
    /// Measure once, right after apply. For deterministic tests.
    Immediate,
}

/// Executes exactly one repair through a [`RepairTransport`].
#[derive(Clone, Debug)]
pub struct RepairExecutor {
    clock: Arc<dyn Clock>,
    timeouts: RepairTimeouts,
    settle: SettlePolicy,
    rollback_unchanged: bool,
}

impl Default for RepairExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl RepairExecutor {
    pub fn new() -> Self {
        Self::with_clock(SystemClock)
    }

    pub fn with_clock(clock: impl Clock + 'static) -> Self {
        Self {
            clock: Arc::new(clock),
            timeouts: RepairTimeouts::default(),
            settle: SettlePolicy::PerAction,
            rollback_unchanged: false,
        }
    }

    #[must_use]
    pub fn with_timeouts(mut self, timeouts: RepairTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    #[must_use]
    pub fn with_settle_policy(mut self, settle: SettlePolicy) -> Self {
        self.settle = settle;
        self
    }

    /// Roll a reversible repair back when it changed nothing measurable.
    /// Off by default: the change is kept and reported as `Unchanged`.
    #[must_use]
    pub fn rollback_unchanged(mut self, enabled: bool) -> Self {
        self.rollback_unchanged = enabled;
        self
    }

    /// Run the snapshot -> apply -> verify -> rollback lifecycle.
    ///
    /// Only an [`ExecutableRepair`] can enter here: safe-automatic repairs,
    /// or approval-required repairs that already carry their approval token.
    pub async fn execute<T: RepairTransport>(
        &self,
        transport: &T,
        repair: &ExecutableRepair,
        symptom: &Symptom,
    ) -> RepairReport {
        let mut events = EventLog::new(Arc::clone(&self.clock));
        let class = repair.class();
        let description = repair.describe();
        events.push(RepairEventKind::Started {
            class,
            description: description.clone(),
        });
        if !repair.is_decided() {
            let error = "the owner has not chosen which device keeps the address".to_owned();
            events.push(RepairEventKind::ApplyFailed {
                error: error.clone(),
            });
            return finish(
                class,
                description,
                RepairOutcome::ApplyFailed { error },
                None,
                RollbackOutcome::NotAttempted {
                    reason: RollbackSkipReason::NotNeeded,
                },
                events,
            );
        }
        let limits = self.timeouts;
        let profile = match self.settle {
            SettlePolicy::PerAction => SettleProfile::for_repair(repair),
            SettlePolicy::Immediate => SettleProfile::IMMEDIATE,
        };

        let keys = repair.state_keys();
        let snapshot = match bounded(
            limits.snapshot,
            transport.snapshot(&keys),
            RepairTransportError::Snapshot,
        )
        .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return finish(
                    class,
                    description,
                    RepairOutcome::SnapshotFailed {
                        error: error.to_string(),
                    },
                    None,
                    RollbackOutcome::NotAttempted {
                        reason: RollbackSkipReason::NotNeeded,
                    },
                    events,
                );
            }
        };

        let baseline = match measure_symptom(transport, symptom, limits.measure)
            .await
            .and_then(finite)
        {
            Ok(measurement) => measurement,
            Err(error) => {
                return finish(
                    class,
                    description,
                    RepairOutcome::BaselineFailed { error },
                    None,
                    RollbackOutcome::NotAttempted {
                        reason: RollbackSkipReason::NotNeeded,
                    },
                    events,
                );
            }
        };
        events.push(RepairEventKind::Snapshotted {
            keys,
            baseline: baseline.clone(),
        });

        if let Err(error) = bounded(
            limits.apply,
            transport.apply(repair),
            RepairTransportError::Apply,
        )
        .await
        {
            events.push(RepairEventKind::ApplyFailed {
                error: error.to_string(),
            });
            // A mid-apply failure may have left partial state: roll back.
            let rollback = roll_back(
                transport,
                repair,
                &snapshot,
                symptom,
                &baseline,
                &limits,
                &mut events,
            )
            .await;
            return finish(
                class,
                description,
                RepairOutcome::ApplyFailed {
                    error: error.to_string(),
                },
                None,
                rollback,
                events,
            );
        }
        events.push(RepairEventKind::Applied);

        // Give the change time to take effect, then keep re-measuring while
        // the symptom still looks worse: a reboot or adapter bounce is
        // transiently worse than the baseline and is not a regression.
        let after = match settle_and_measure(transport, symptom, &baseline, &limits, profile).await
        {
            Ok(measurement) => measurement,
            Err(error) => {
                events.push(RepairEventKind::VerificationFailed {
                    error: error.clone(),
                });
                // Unverifiable state is unacceptable for a reversible action:
                // return to the snapshot.
                let rollback = roll_back(
                    transport,
                    repair,
                    &snapshot,
                    symptom,
                    &baseline,
                    &limits,
                    &mut events,
                )
                .await;
                return finish(
                    class,
                    description,
                    RepairOutcome::VerificationFailed { error },
                    None,
                    rollback,
                    events,
                );
            }
        };

        let verdict = compare(symptom, baseline.value, after.value);
        events.push(RepairEventKind::Verified {
            verdict,
            before: baseline.clone(),
            after: after.clone(),
        });
        let rollback = if verdict == Verdict::Regressed
            || (verdict == Verdict::Unchanged && self.rollback_unchanged)
        {
            roll_back(
                transport,
                repair,
                &snapshot,
                symptom,
                &baseline,
                &limits,
                &mut events,
            )
            .await
        } else {
            RollbackOutcome::NotAttempted {
                reason: RollbackSkipReason::NotNeeded,
            }
        };
        let verification = Verification {
            verdict,
            before: baseline,
            after,
        };
        finish(
            class,
            description,
            RepairOutcome::Completed { verdict },
            Some(verification),
            rollback,
            events,
        )
    }
}

/// Bounds one transport call; a timeout becomes the call own error variant.
async fn bounded<R>(
    limit: Duration,
    call: impl Future<Output = Result<R, RepairTransportError>>,
    on_timeout: fn(String) -> RepairTransportError,
) -> Result<R, RepairTransportError> {
    match tokio::time::timeout(limit, call).await {
        Ok(result) => result,
        Err(_) => Err(on_timeout(format!(
            "timed out after {} ms",
            limit.as_millis()
        ))),
    }
}

async fn measure_symptom<T: RepairTransport>(
    transport: &T,
    symptom: &Symptom,
    limit: Duration,
) -> Result<Measurement, String> {
    let measurements = bounded(
        limit,
        transport.measure(symptom.check()),
        RepairTransportError::Measure,
    )
    .await
    .map_err(|error| error.to_string())?;
    measurements
        .iter()
        .find(|measurement| measurement.metric == symptom.metric())
        .cloned()
        .ok_or_else(|| {
            format!(
                "symptom metric {:?} missing from re-measurement",
                symptom.metric()
            )
        })
}

/// Waits `settle`, then measures; while the verdict is `Regressed`, polls
/// until `verify_window` elapses. Returns the last usable measurement.
async fn settle_and_measure<T: RepairTransport>(
    transport: &T,
    symptom: &Symptom,
    baseline: &Measurement,
    limits: &RepairTimeouts,
    profile: SettleProfile,
) -> Result<Measurement, String> {
    if !profile.settle.is_zero() {
        tokio::time::sleep(profile.settle).await;
    }
    let deadline = Instant::now() + profile.verify_window;
    let mut last_ok: Option<Measurement> = None;
    let mut last_error = String::new();
    loop {
        match measure_symptom(transport, symptom, limits.measure)
            .await
            .and_then(finite)
        {
            Ok(measurement) => {
                let regressed =
                    compare(symptom, baseline.value, measurement.value) == Verdict::Regressed;
                last_ok = Some(measurement);
                if !regressed {
                    break;
                }
            }
            Err(error) => last_error = error,
        }
        if Instant::now() + profile.poll_interval >= deadline {
            break;
        }
        tokio::time::sleep(profile.poll_interval).await;
    }
    last_ok.ok_or(last_error)
}

/// Rejects a measurement whose value cannot be compared.
fn finite(measurement: Measurement) -> Result<Measurement, String> {
    if measurement.value.is_finite() {
        Ok(measurement)
    } else {
        Err(format!(
            "symptom metric {:?} measured a non-finite value ({})",
            measurement.metric, measurement.value
        ))
    }
}

/// Restores the snapshot and then *proves* it by re-measuring the symptom: a
/// rollback whose restore call returned `Ok` but left the symptom regressed
/// against the baseline is reported as failed, not succeeded.
async fn roll_back<T: RepairTransport>(
    transport: &T,
    repair: &ExecutableRepair,
    snapshot: &[StateEntry],
    symptom: &Symptom,
    baseline: &Measurement,
    limits: &RepairTimeouts,
    events: &mut EventLog,
) -> RollbackOutcome {
    let outcome = if repair.reversible() {
        match bounded(
            limits.restore,
            transport.restore(snapshot),
            RepairTransportError::Restore,
        )
        .await
        {
            Ok(()) => match measure_symptom(transport, symptom, limits.measure)
                .await
                .and_then(finite)
            {
                Ok(restored) => match compare(symptom, baseline.value, restored.value) {
                    Verdict::Regressed => RollbackOutcome::Failed {
                        error: format!(
                            "restore succeeded but the symptom did not return to baseline: \
                             before {} after rollback {}",
                            baseline.value, restored.value
                        ),
                    },
                    Verdict::Improved | Verdict::Unchanged => RollbackOutcome::Succeeded,
                },
                Err(error) => RollbackOutcome::Failed {
                    error: format!("restore succeeded but could not be verified: {error}"),
                },
            },
            Err(error) => RollbackOutcome::Failed {
                error: error.to_string(),
            },
        }
    } else {
        RollbackOutcome::NotAttempted {
            reason: RollbackSkipReason::NotReversible,
        }
    };
    events.push(RepairEventKind::RolledBack {
        outcome: outcome.clone(),
    });
    outcome
}

fn compare(symptom: &Symptom, before: f64, after: f64) -> Verdict {
    let improvement = match symptom.direction {
        MetricDirection::LowerIsBetter => before - after,
        MetricDirection::HigherIsBetter => after - before,
    };
    if improvement >= symptom.min_meaningful_delta {
        Verdict::Improved
    } else if improvement <= -symptom.min_meaningful_delta {
        Verdict::Regressed
    } else {
        Verdict::Unchanged
    }
}

fn finish(
    class: RepairClass,
    description: String,
    outcome: RepairOutcome,
    verification: Option<Verification>,
    rollback: RollbackOutcome,
    events: EventLog,
) -> RepairReport {
    RepairReport {
        class,
        description,
        outcome,
        verification,
        rollback,
        events: events.into_events(),
    }
}

struct EventLog {
    clock: Arc<dyn Clock>,
    events: Vec<RepairEvent>,
}

impl EventLog {
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            events: Vec::new(),
        }
    }

    fn push(&mut self, kind: RepairEventKind) {
        let sequence = self.events.len() as u32;
        self.events.push(RepairEvent {
            sequence,
            at: self.clock.now(),
            kind,
        });
    }

    fn into_events(self) -> Vec<RepairEvent> {
        self.events
    }
}

#[cfg(any(test, feature = "test-support"))]
mod fake {
    use super::*;

    /// Which transport operation was invoked, in order — for test assertions.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TransportCall {
        Snapshot,
        Apply,
        Restore,
        Measure,
    }

    /// Scripted in-memory transport for tests.
    #[derive(Debug)]
    pub struct FakeRepairTransport {
        snapshot_result: Mutex<Result<Vec<StateEntry>, RepairTransportError>>,
        apply_result: Mutex<Result<(), RepairTransportError>>,
        restore_result: Mutex<Result<(), RepairTransportError>>,
        measurements: Mutex<VecDeque<Result<Vec<Measurement>, RepairTransportError>>>,
        calls: Mutex<Vec<TransportCall>>,
        unavailable: Option<UnavailableReason>,
    }

    impl Default for FakeRepairTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FakeRepairTransport {
        pub fn new() -> Self {
            Self {
                snapshot_result: Mutex::new(Ok(Vec::new())),
                apply_result: Mutex::new(Ok(())),
                restore_result: Mutex::new(Ok(())),
                measurements: Mutex::new(VecDeque::new()),
                calls: Mutex::new(Vec::new()),
                unavailable: None,
            }
        }

        /// Makes the transport declare every plan unexecutable for `reason`.
        pub fn with_unavailable(mut self, reason: UnavailableReason) -> Self {
            self.unavailable = Some(reason);
            self
        }

        pub fn with_snapshot(self, entries: Vec<StateEntry>) -> Self {
            *self.snapshot_result.lock().expect("fake lock") = Ok(entries);
            self
        }

        pub fn with_snapshot_error(self, error: RepairTransportError) -> Self {
            *self.snapshot_result.lock().expect("fake lock") = Err(error);
            self
        }

        pub fn with_apply_error(self, error: RepairTransportError) -> Self {
            *self.apply_result.lock().expect("fake lock") = Err(error);
            self
        }

        pub fn with_restore_error(self, error: RepairTransportError) -> Self {
            *self.restore_result.lock().expect("fake lock") = Err(error);
            self
        }

        /// Queue one `measure` reply (first queued serves the baseline).
        pub fn push_measurements(self, measurements: Vec<Measurement>) -> Self {
            self.measurements
                .lock()
                .expect("fake lock")
                .push_back(Ok(measurements));
            self
        }

        pub fn push_measure_error(self, error: RepairTransportError) -> Self {
            self.measurements
                .lock()
                .expect("fake lock")
                .push_back(Err(error));
            self
        }

        pub fn calls(&self) -> Vec<TransportCall> {
            self.calls.lock().expect("fake lock").clone()
        }

        fn record(&self, call: TransportCall) {
            self.calls.lock().expect("fake lock").push(call);
        }
    }

    impl RepairTransport for FakeRepairTransport {
        fn unavailable_reason(&self, _plan: &RepairPlan) -> Option<UnavailableReason> {
            self.unavailable
        }

        async fn snapshot(
            &self,
            _keys: &[StateKey],
        ) -> Result<Vec<StateEntry>, RepairTransportError> {
            self.record(TransportCall::Snapshot);
            self.snapshot_result.lock().expect("fake lock").clone()
        }

        async fn apply(&self, _repair: &ExecutableRepair) -> Result<(), RepairTransportError> {
            self.record(TransportCall::Apply);
            self.apply_result.lock().expect("fake lock").clone()
        }

        async fn restore(&self, _entries: &[StateEntry]) -> Result<(), RepairTransportError> {
            self.record(TransportCall::Restore);
            self.restore_result.lock().expect("fake lock").clone()
        }

        async fn measure(
            &self,
            _check: CheckKind,
        ) -> Result<Vec<Measurement>, RepairTransportError> {
            self.record(TransportCall::Measure);
            self.measurements
                .lock()
                .expect("fake lock")
                .pop_front()
                .unwrap_or_else(|| {
                    Err(RepairTransportError::Measure(
                        "no scripted measurement".into(),
                    ))
                })
        }
    }
}
#[cfg(any(test, feature = "test-support"))]
pub use fake::{FakeRepairTransport, TransportCall};
