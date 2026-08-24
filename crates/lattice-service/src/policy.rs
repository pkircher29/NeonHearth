use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lattice_domain::{
    DeviceId, DevicePolicy, Evaluation, EventPayload, Identification, OwnerDecision, PolicyChanged,
    PolicyReason, Protection, RequestedAction, RiskSignal,
};
use lattice_event_bus::EventBus;
use lattice_store::{M2StateRepository, PolicyRepository};
use lattice_w6::{
    Connector, DiscoveryStatus, Error as W6Error, RequestedQuarantine, Transport, Verification,
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorOutcome {
    Verified,
    ManualRequired,
    Failed,
}

pub use lattice_domain::EnforcementStatus as EnforcementResult;

#[async_trait]
pub trait PolicyActuator: Send + Sync {
    async fn enforce(&self, device: DeviceId, action: RequestedAction) -> EnforcementResult;
}

/// Policy bridge for an owner-authenticated, trusted W6 connector.
///
/// The fixture contract intentionally maps Quarantine to `DenyInternet` and
/// PermanentBan to `PersistentFilter`; these are safe, explicit fixture
/// capabilities and are not production HTTP endpoint guesses.
pub struct W6PolicyActuator<T> {
    connector: Mutex<Connector<T>>,
}

impl<T: Transport> W6PolicyActuator<T> {
    pub fn new(connector: Connector<T>) -> Self {
        Self {
            connector: Mutex::new(connector),
        }
    }
}

#[async_trait]
impl<T: Transport + 'static> PolicyActuator for W6PolicyActuator<T> {
    async fn enforce(&self, _device: DeviceId, action: RequestedAction) -> EnforcementResult {
        let request = match action {
            RequestedAction::Quarantine => RequestedQuarantine::DenyInternet,
            RequestedAction::PermanentBan => RequestedQuarantine::PersistentFilter,
            _ => return EnforcementResult::ManualRequired,
        };
        let mut connector = self.connector.lock().await;
        if connector.discovery_status() != DiscoveryStatus::Trusted {
            return EnforcementResult::ManualRequired;
        }
        match connector.quarantine(request).await {
            Ok(report) if report.verification == Verification::Verified => {
                EnforcementResult::Verified
            }
            Ok(_)
            | Err(
                W6Error::ManualRequired
                | W6Error::ReadOnly
                | W6Error::CapacityExhausted
                | W6Error::CapabilityUnavailable
                | W6Error::UnknownProfile
                | W6Error::InvalidCapacity,
            ) => EnforcementResult::ManualRequired,
            Err(
                W6Error::Transport
                | W6Error::Authentication
                | W6Error::SessionExpired
                | W6Error::VerificationFailed,
            ) => EnforcementResult::Failed,
        }
    }
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
    presence: Option<M2StateRepository>,
}

impl PolicyCoordinator<ManualRequiredActuator> {
    pub fn new(repo: PolicyRepository, events: Option<EventBus>) -> Self {
        Self::with_actuator(repo, events, ManualRequiredActuator)
    }
    pub fn with_state(
        repo: PolicyRepository,
        events: Option<EventBus>,
        presence: M2StateRepository,
    ) -> Self {
        Self::with_actuator_and_state(repo, events, ManualRequiredActuator, presence)
    }
}
impl<A: PolicyActuator + 'static> PolicyCoordinator<A> {
    pub fn with_actuator(repo: PolicyRepository, events: Option<EventBus>, actuator: A) -> Self {
        Self {
            repo,
            events,
            actuator: Arc::new(actuator),
            presence: None,
        }
    }
    pub fn with_actuator_and_state(
        repo: PolicyRepository,
        events: Option<EventBus>,
        actuator: A,
        presence: M2StateRepository,
    ) -> Self {
        Self {
            repo,
            events,
            actuator: Arc::new(actuator),
            presence: Some(presence),
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
    /// Persist the discovery engine's committed automatic identification
    /// before evaluation so the production deadline uses its durable evidence.
    pub async fn enroll_identification_and_evaluate(
        &self,
        device: DeviceId,
        identification: Option<&lattice_intelligence::Identification>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        let policy = self.repo.enroll(device).await?;
        if let Some(identity) = identification {
            let confidence_basis_points = (identity.confidence.clamp(0.0, 1.0) * 10_000.0) as u16;
            self.repo
                .set_identification(
                    device,
                    Identification::Automatic {
                        confidence_basis_points,
                        evidence_families: identity.families.clone(),
                    },
                )
                .await?;
        }
        self.evaluate(self.repo.load(device).await?.unwrap_or(policy), now)
            .await
    }
    pub async fn enabled(&self) -> anyhow::Result<bool> {
        Ok(self.repo.baseline_started_at().await?.is_some())
    }
    /// Evaluate every persisted policy on a runtime tick.  Deadlines advance
    /// with wall clock time even when no neighbor observations arrive.
    pub async fn sweep(&self, now: DateTime<Utc>) -> anyhow::Result<Vec<AuditedDecision>> {
        let mut decisions = Vec::new();
        for policy in self.repo.list().await? {
            decisions.push(self.evaluate(policy, now).await?);
        }
        Ok(decisions)
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
        if enforcement == EnforcementResult::Verified
            && matches!(
                evaluation.requested_action,
                RequestedAction::Quarantine | RequestedAction::PermanentBan
            )
            && let Some(presence) = &self.presence
        {
            presence.record_verified_block(p.device_id, now).await?;
        }
        let undo_available = matches!(
            p.owner_decision,
            OwnerDecision::Approved | OwnerDecision::Quarantined
        );
        let fingerprint = serde_json::to_string(&(
            evaluation,
            evidence_summary(&p),
            enforcement,
            undo_available,
        ))?;
        if let Some(bus) = &self.events
            && self
                .repo
                .reserve_decision_publication(p.device_id, &fingerprint)
                .await?
        {
            let event = PolicyChanged {
                device_id: p.device_id,
                policy_version: evaluation.policy_version,
                evaluation,
                requested_action: evaluation.requested_action,
                evidence_summary: evidence_summary(&p),
                enforcement_result: enforcement,
                undo_available,
            };
            bus.publish(now, EventPayload::PolicyChanged(event.clone()))
                .await;
            self.repo
                .mark_decision_published(p.device_id, &fingerprint, &event)
                .await?;
        }
        Ok(AuditedDecision {
            evaluation,
            reason: evaluation.reason,
            policy_version: evaluation.policy_version,
            evidence_summary: evidence_summary(&p),
            requested_action: evaluation.requested_action,
            enforcement,
            undo_available,
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
    pub async fn needs_recovery(&self, device: DeviceId) -> anyhow::Result<bool> {
        Ok(self.repo.load(device).await?.is_none())
    }
}

fn evaluate_policy(p: &DevicePolicy, now: DateTime<Utc>) -> Evaluation {
    // Cohort membership is persisted on the policy row; the engine's baseline timestamp is
    // intentionally irrelevant to evaluation after enrollment.
    lattice_policy::PolicyEngine::new(p.first_seen_at).evaluate(p, now)
}
fn evidence_summary(p: &DevicePolicy) -> String {
    match p.risk {
        RiskSignal::HighConfidenceDanger { .. } => "high-confidence danger".into(),
        _ => "policy facts evaluated".into(),
    }
}
