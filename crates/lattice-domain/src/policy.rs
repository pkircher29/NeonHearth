use crate::{DeviceId, EvidenceFamily};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub const UNKNOWN_POLICY_DEADLINE_HOURS: i64 = 48;
pub const AUTOMATIC_POLICY_DEADLINE_HOURS: i64 = 7 * 24;
pub const AUTOMATIC_IDENTITY_THRESHOLD_BPS: u16 = 8_500;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Identification {
    Unknown,
    Automatic {
        confidence_basis_points: u16,
        evidence_families: Vec<EvidenceFamily>,
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

/// API-safe result of attempting the requested enforcement action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    NotRequested,
    Verified,
    ManualRequired,
    Failed,
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

/// Basis points are 0..=10_000; larger values are malformed input.
pub const MAX_BASIS_POINTS: u16 = 10_000;

impl Identification {
    /// Checked constructor for an automatic identification.
    pub fn automatic(
        confidence_basis_points: u16,
        evidence_families: Vec<EvidenceFamily>,
    ) -> Result<Self, &'static str> {
        let value = Self::Automatic {
            confidence_basis_points,
            evidence_families,
        };
        value.validate()?;
        Ok(value)
    }

    /// Rejects values that deserialization alone cannot (basis points > 100%).
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Automatic {
                confidence_basis_points,
                ..
            } if *confidence_basis_points > MAX_BASIS_POINTS => {
                Err("confidence basis points exceed 10000")
            }
            _ => Ok(()),
        }
    }
}

impl RiskSignal {
    /// Checked constructor for a danger signal: needs evidence and <= 100%.
    pub fn danger(
        confidence_basis_points: u16,
        evidence: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let value = Self::HighConfidenceDanger {
            confidence_basis_points,
            evidence: evidence.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Rejects a danger signal with no evidence or more than 100% confidence.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::None => Ok(()),
            Self::HighConfidenceDanger {
                confidence_basis_points,
                evidence,
            } => {
                if *confidence_basis_points > MAX_BASIS_POINTS {
                    Err("confidence basis points exceed 10000")
                } else if evidence.trim().is_empty() {
                    Err("danger signal needs evidence")
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn malformed_signals_are_rejected() {
        assert!(RiskSignal::danger(10_001, "x").is_err());
        assert!(RiskSignal::danger(9_000, "  ").is_err());
        assert!(RiskSignal::danger(10_000, "x").is_ok());
        assert!(Identification::automatic(10_001, vec![]).is_err());
        assert!(Identification::automatic(8_500, vec![]).is_ok());
    }
}
