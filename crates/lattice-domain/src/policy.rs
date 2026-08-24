use crate::DeviceId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Identification {
    Unknown,
    Automatic {
        confidence_basis_points: u16,
        evidence_families: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OwnerDecision {
    Pending,
    Approved,
    Rejected,
    Quarantined,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RiskSignal {
    None,
    HighConfidenceDanger {
        confidence_basis_points: u16,
        evidence: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Protection {
    None,
    Router,
    Collector,
    AdministratorPhone,
    SafetyDevice,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DevicePolicy {
    pub device_id: DeviceId,
    pub first_seen_at: DateTime<Utc>,
    pub baseline_exempt: bool,
    pub identification: Identification,
    pub owner_decision: OwnerDecision,
    pub risk: RiskSignal,
    pub protection: Protection,
    /// A persisted, owner-authorized absolute extension. The repository owns
    /// the one-use constraint.
    pub extension_until: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineKind {
    Unknown48Hours,
    Automatic7Days,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Deadline {
    pub kind: DeadlineKind,
    pub due_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineWarning {
    Hours24,
    Hours6,
    Hour1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestedAction {
    None,
    Quarantine,
    PermanentBan,
    OwnerAttention,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReason {
    PendingConfirmation,
    BaselineExempt,
    HighConfidenceDanger,
    UnknownDeadlineExpired,
    AutomaticDeadlineExpired,
    OwnerExtension,
    OwnerApproved,
    OwnerRejected,
    OwnerQuarantined,
    ProtectedDevice,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Evaluation {
    pub policy_version: u32,
    pub reason: PolicyReason,
    pub requested_action: RequestedAction,
    pub deadline: Option<Deadline>,
    pub warning: Option<DeadlineWarning>,
}

impl Evaluation {
    pub fn visible(reason: PolicyReason) -> Self {
        Self::terminal(reason, RequestedAction::None)
    }

    pub fn quarantine(reason: PolicyReason) -> Self {
        Self::terminal(reason, RequestedAction::Quarantine)
    }

    pub fn ban(reason: PolicyReason) -> Self {
        Self::terminal(reason, RequestedAction::PermanentBan)
    }

    pub fn owner_attention() -> Self {
        Self::terminal(
            PolicyReason::ProtectedDevice,
            RequestedAction::OwnerAttention,
        )
    }

    fn terminal(reason: PolicyReason, requested_action: RequestedAction) -> Self {
        Self {
            policy_version: 1,
            reason,
            requested_action,
            deadline: None,
            warning: None,
        }
    }
}
