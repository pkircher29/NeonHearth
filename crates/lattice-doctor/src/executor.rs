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
use crate::repair::{ExecutableRepair, RepairClass, StateKey};
use crate::{Clock, DoctorError, SystemClock};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
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
pub struct Symptom {
    check: CheckKind,
    metric: Metric,
    direction: MetricDirection,
    min_meaningful_delta: f64,
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

/// Executes exactly one repair through a [`RepairTransport`].
#[derive(Clone, Debug)]
pub struct RepairExecutor {
    clock: Arc<dyn Clock>,
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
        }
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

        let keys = repair.state_keys();
        let snapshot = match transport.snapshot(&keys).await {
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

        let baseline = match measure_symptom(transport, symptom).await.and_then(finite) {
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

        if let Err(error) = transport.apply(repair).await {
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

        // A non-finite re-measurement (NaN from a divide-by-zero, an infinite
        // latency) is not "unchanged": it is unverifiable, so treat it as such.
        let after = match measure_symptom(transport, symptom).await.and_then(finite) {
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
        let rollback = if verdict == Verdict::Regressed {
            roll_back(
                transport,
                repair,
                &snapshot,
                symptom,
                &baseline,
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

async fn measure_symptom<T: RepairTransport>(
    transport: &T,
    symptom: &Symptom,
) -> Result<Measurement, String> {
    let measurements = transport
        .measure(symptom.check())
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
    events: &mut EventLog,
) -> RollbackOutcome {
    let outcome = if repair.reversible() {
        match transport.restore(snapshot).await {
            Ok(()) => match measure_symptom(transport, symptom).await.and_then(finite) {
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
        }
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
    async fn snapshot(&self, _keys: &[StateKey]) -> Result<Vec<StateEntry>, RepairTransportError> {
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

    async fn measure(&self, _check: CheckKind) -> Result<Vec<Measurement>, RepairTransportError> {
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
