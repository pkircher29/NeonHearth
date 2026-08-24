use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use lattice_domain::{
    DeviceId, DevicePolicy, Evaluation, EventPayload, Identification, OwnerDecision, PolicyChanged,
    PolicyReason, Protection, RequestedAction, RiskSignal,
};
use lattice_event_bus::EventBus;
use lattice_store::PolicyRepository;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorOutcome {
    Verified,
    ManualRequired,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementResult {
    NotRequested,
    Verified,
    ManualRequired,
    Failed,
}

#[async_trait]
pub trait PolicyActuator: Send + Sync {
    async fn enforce(&self, device: DeviceId, action: RequestedAction) -> EnforcementResult;
}

#[derive(Default)]
pub struct ManualRequiredActuator;
#[async_trait]
impl PolicyActuator for ManualRequiredActuator {
    async fn enforce(&self, _device: DeviceId, _action: RequestedAction) -> EnforcementResult {
        EnforcementResult::ManualRequired
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedDecision {
    pub evaluation: Evaluation,
    pub reason: PolicyReason,
    pub policy_version: u32,
    pub evidence_summary: String,
    pub requested_action: RequestedAction,
    pub enforcement: EnforcementResult,
    pub undo_available: bool,
}

pub struct PolicyCoordinator<A = ManualRequiredActuator> {
    repo: PolicyRepository,
    events: Option<EventBus>,
    actuator: Arc<A>,
    last: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<DeviceId, Evaluation>>>,
}

impl PolicyCoordinator<ManualRequiredActuator> {
    pub fn new(repo: PolicyRepository, events: Option<EventBus>) -> Self {
        Self::with_actuator(repo, events, ManualRequiredActuator)
    }
}
impl<A: PolicyActuator + 'static> PolicyCoordinator<A> {
    pub fn with_actuator(repo: PolicyRepository, events: Option<EventBus>, actuator: A) -> Self {
        Self {
            repo,
            events,
            actuator: Arc::new(actuator),
            last: Default::default(),
        }
    }
    pub async fn enroll_and_evaluate(
        &self,
        device: DeviceId,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        let policy = self.repo.enroll(device).await?;
        self.evaluate(policy, now).await
    }
    pub async fn enabled(&self) -> anyhow::Result<bool> {
        Ok(self.repo.baseline_started_at().await?.is_some())
    }
    pub async fn evaluate(
        &self,
        p: DevicePolicy,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        let evaluation = evaluate_policy(&p, now);
        let enforcement = if matches!(
            evaluation.requested_action,
            RequestedAction::None | RequestedAction::OwnerAttention
        ) || p.protection != Protection::None
        {
            EnforcementResult::NotRequested
        } else {
            self.actuator
                .enforce(p.device_id, evaluation.requested_action)
                .await
        };
        let changed = self.last.lock().await.insert(p.device_id, evaluation) != Some(evaluation);
        if changed && let Some(bus) = &self.events {
            bus.publish(
                now,
                EventPayload::PolicyChanged(PolicyChanged {
                    device_id: p.device_id,
                    policy_version: evaluation.policy_version,
                    evaluation,
                    requested_action: evaluation.requested_action,
                    evidence_summary: evidence_summary(&p),
                }),
            )
            .await;
        }
        Ok(AuditedDecision {
            evaluation,
            reason: evaluation.reason,
            policy_version: evaluation.policy_version,
            evidence_summary: evidence_summary(&p),
            requested_action: evaluation.requested_action,
            enforcement,
            undo_available: matches!(
                p.owner_decision,
                OwnerDecision::Approved | OwnerDecision::Quarantined
            ),
        })
    }
    pub async fn approve(
        &self,
        d: DeviceId,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        self.repo
            .set_owner_decision(d, OwnerDecision::Approved)
            .await?;
        self.evaluate(self.repo.load(d).await?.unwrap(), now).await
    }
    pub async fn reject(&self, d: DeviceId, now: DateTime<Utc>) -> anyhow::Result<AuditedDecision> {
        self.repo
            .set_owner_decision(d, OwnerDecision::Rejected)
            .await?;
        self.evaluate(self.repo.load(d).await?.unwrap(), now).await
    }
    pub async fn quarantine(
        &self,
        d: DeviceId,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        self.repo
            .set_owner_decision(d, OwnerDecision::Quarantined)
            .await?;
        self.evaluate(self.repo.load(d).await?.unwrap(), now).await
    }
    pub async fn extend_once(
        &self,
        d: DeviceId,
        until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        self.repo.extend_once(d, until).await?;
        self.evaluate(self.repo.load(d).await?.unwrap(), now).await
    }
}

fn evaluate_policy(p: &DevicePolicy, now: DateTime<Utc>) -> Evaluation {
    if p.baseline_exempt {
        return Evaluation::visible(PolicyReason::BaselineExempt);
    }
    if matches!(p.risk, RiskSignal::HighConfidenceDanger { .. }) {
        return if p.protection == Protection::None {
            Evaluation::ban(PolicyReason::HighConfidenceDanger)
        } else {
            Evaluation::owner_attention()
        };
    }
    match p.owner_decision {
        OwnerDecision::Approved => return Evaluation::visible(PolicyReason::OwnerApproved),
        OwnerDecision::Rejected => return Evaluation::ban(PolicyReason::OwnerRejected),
        OwnerDecision::Quarantined => {
            return if p.protection == Protection::None {
                Evaluation::quarantine(PolicyReason::OwnerQuarantined)
            } else {
                Evaluation::owner_attention()
            };
        }
        OwnerDecision::Pending => {}
    }
    let automatic = matches!(p.identification, Identification::Automatic { confidence_basis_points: 8500.., ref evidence_families } if evidence_families.len() >= 2);
    let due = p
        .extension_until
        .unwrap_or(p.first_seen_at + Duration::hours(if automatic { 168 } else { 48 }));
    if now >= due {
        if p.protection == Protection::None {
            if automatic {
                Evaluation::ban(PolicyReason::AutomaticDeadlineExpired)
            } else {
                Evaluation::quarantine(PolicyReason::UnknownDeadlineExpired)
            }
        } else {
            Evaluation::owner_attention()
        }
    } else {
        Evaluation::visible(PolicyReason::PendingConfirmation)
    }
}
fn evidence_summary(p: &DevicePolicy) -> String {
    match p.risk {
        RiskSignal::HighConfidenceDanger { .. } => "high-confidence danger".into(),
        _ => "policy facts evaluated".into(),
    }
}
