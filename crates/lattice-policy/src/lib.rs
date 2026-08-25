//! Device approval and quarantine policy for NeonHearth.

use chrono::{DateTime, Duration, Utc};
pub use lattice_domain::{
    AUTOMATIC_IDENTITY_THRESHOLD_BPS, AUTOMATIC_POLICY_DEADLINE_HOURS, Deadline, DeadlineKind,
    DeadlineWarning, DevicePolicy, Evaluation, Identification, OwnerDecision, PolicyReason,
    Protection, RequestedAction, RiskSignal, UNKNOWN_POLICY_DEADLINE_HOURS,
};

pub const POLICY_VERSION: u32 = 1;
pub const BASELINE_WINDOW: Duration = Duration::hours(48);
pub const UNKNOWN_DEADLINE: Duration = Duration::hours(UNKNOWN_POLICY_DEADLINE_HOURS);
pub const AUTOMATIC_DEADLINE: Duration = Duration::hours(AUTOMATIC_POLICY_DEADLINE_HOURS);
pub const DANGER_THRESHOLD_BPS: u16 = 9_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyEngine {
    baseline_started_at: DateTime<Utc>,
}

impl PolicyEngine {
    /// Constructs an engine from the immutable, persisted install timestamp.
    pub fn new(baseline_started_at: DateTime<Utc>) -> Self {
        Self {
            baseline_started_at,
        }
    }

    pub fn baseline_started_at(self) -> DateTime<Utc> {
        self.baseline_started_at
    }

    pub fn is_baseline_member(self, first_seen_at: DateTime<Utc>) -> bool {
        first_seen_at >= self.baseline_started_at
            && first_seen_at < self.baseline_started_at + BASELINE_WINDOW
    }

    pub fn evaluate(self, device: &DevicePolicy, now: DateTime<Utc>) -> Evaluation {
        match device.owner_decision {
            OwnerDecision::Rejected => {
                return Evaluation::ban(PolicyReason::OwnerRejected);
            }
            OwnerDecision::Quarantined => {
                return Evaluation::quarantine(PolicyReason::OwnerQuarantined);
            }
            OwnerDecision::Pending | OwnerDecision::Approved => {}
        }

        let dangerous = matches!(
            &device.risk,
            RiskSignal::HighConfidenceDanger {
                confidence_basis_points: DANGER_THRESHOLD_BPS..,
                evidence
            } if !evidence.trim().is_empty()
        );
        if dangerous {
            return if device.protection != Protection::None {
                Evaluation::owner_attention()
            } else {
                Evaluation::quarantine(PolicyReason::HighConfidenceDanger)
            };
        }

        if device.owner_decision == OwnerDecision::Approved {
            return Evaluation::visible(PolicyReason::OwnerApproved);
        }

        if device.baseline_exempt {
            return Evaluation::visible(PolicyReason::BaselineExempt);
        }

        let automatically_identified = match &device.identification {
            Identification::Automatic {
                confidence_basis_points: AUTOMATIC_IDENTITY_THRESHOLD_BPS..,
                evidence_families,
            } => {
                evidence_families
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    >= 2
            }
            Identification::Unknown | Identification::Automatic { .. } => false,
        };
        let (kind, original_due, expired_reason) = if automatically_identified {
            (
                DeadlineKind::Automatic7Days,
                device.first_seen_at + AUTOMATIC_DEADLINE,
                PolicyReason::AutomaticDeadlineExpired,
            )
        } else {
            (
                DeadlineKind::Unknown48Hours,
                device.first_seen_at + UNKNOWN_DEADLINE,
                PolicyReason::UnknownDeadlineExpired,
            )
        };

        let due_at = device
            .extension_until
            .filter(|extension| *extension > original_due)
            .unwrap_or(original_due);

        if now >= due_at {
            return if device.protection != Protection::None {
                Evaluation::owner_attention()
            } else {
                Evaluation::quarantine(expired_reason)
            };
        }

        let remaining = due_at - now;
        let warning = if remaining <= Duration::hours(1) {
            Some(DeadlineWarning::Hour1)
        } else if remaining <= Duration::hours(6) {
            Some(DeadlineWarning::Hours6)
        } else if remaining <= Duration::hours(24) {
            Some(DeadlineWarning::Hours24)
        } else {
            None
        };

        Evaluation {
            policy_version: POLICY_VERSION,
            reason: if due_at > original_due {
                PolicyReason::OwnerExtension
            } else {
                PolicyReason::PendingConfirmation
            },
            requested_action: RequestedAction::None,
            deadline: Some(Deadline { kind, due_at }),
            warning,
        }
    }
}
