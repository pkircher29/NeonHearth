use anyhow::Context;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lattice_domain::{
    DeviceId, DevicePolicy, Evaluation, EventPayload, Identification, OwnerDecision, PolicyChanged,
    PolicyReason, Protection, RequestedAction, RiskSignal,
};
use lattice_event_bus::EventBus;
use lattice_store::{
    ActuationReservation, M2StateRepository, PolicyRepository, W6PriorStateRepository,
};
use lattice_w6::{
    Connector, DiscoveryStatus, Error as W6Error, RequestedQuarantine, Transport, Verification,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorOutcome {
    Verified,
    ManualRequired,
    Failed,
}

/// Result of a read-only restart reconciliation.  Only `ProvenNotApplied`
/// authorizes another call to `enforce`; every other non-applied result fails
/// closed so an irreversible action cannot be replayed on uncertainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActuationReconciliation {
    VerifiedApplied,
    ProvenNotApplied,
    Indeterminate,
    ManualRequired,
    Failed,
}

pub use lattice_domain::EnforcementStatus as EnforcementResult;

/// Typed refusals from owner policy actions. Anything else that comes back
/// through `anyhow` is a storage or invariant failure, not a client mistake.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PolicyActionError {
    #[error("device is not enrolled in policy")]
    NotEnrolled,
    #[error("cannot replace a pending release until its control state is reconciled")]
    PendingRelease,
}

#[async_trait]
pub trait PolicyActuator: Send + Sync {
    async fn enforce(&self, device: DeviceId, action: RequestedAction) -> EnforcementResult;
    async fn reconcile(
        &self,
        _device: DeviceId,
        _action: RequestedAction,
    ) -> ActuationReconciliation {
        ActuationReconciliation::Indeterminate
    }
    async fn undo_available(&self, _device: DeviceId, _action: RequestedAction) -> bool {
        false
    }
    async fn undo(&self, _device: DeviceId, _action: RequestedAction) -> EnforcementResult {
        EnforcementResult::ManualRequired
    }
}

/// Policy bridge for an owner-authenticated, trusted W6 connector.
///
/// The fixture contract intentionally maps Quarantine to `DenyInternet` and
/// PermanentBan to `PersistentFilter`; these are safe, explicit fixture
/// capabilities and are not production HTTP endpoint guesses.
pub struct W6PolicyActuator<T> {
    connector: Mutex<Connector<T>>,
    previous: Mutex<HashMap<DeviceId, lattice_w6::DeviceState>>,
    durable: Option<W6PriorStateRepository>,
}

impl<T: Transport> W6PolicyActuator<T> {
    pub fn new(connector: Connector<T>) -> Self {
        Self {
            connector: Mutex::new(connector),
            previous: Mutex::new(HashMap::new()),
            durable: None,
        }
    }
    /// Injectable owner-authorized runtime path. The service binary deliberately
    /// stays on `ManualRequiredActuator` until W1 supplies a concrete transport;
    /// this constructor accepts only an already configured, trusted W6 connector.
    pub fn with_sqlite(connector: Connector<T>, pool: sqlx::SqlitePool) -> Self {
        Self {
            connector: Mutex::new(connector),
            previous: Mutex::new(HashMap::new()),
            durable: Some(W6PriorStateRepository::new(pool)),
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
        let prepared = match connector.prepare_quarantine(request).await {
            Ok(prepared) => prepared,
            Err(W6Error::Transport | W6Error::Authentication | W6Error::SessionExpired) => {
                return EnforcementResult::Failed;
            }
            Err(_) => return EnforcementResult::ManualRequired,
        };
        if let Some(durable) = &self.durable
            && durable
                .begin_attempt(_device, action, &prepared.previous)
                .await
                .is_err()
        {
            return EnforcementResult::Failed;
        }
        match connector.apply_prepared(prepared).await {
            Ok(report) if report.verification == Verification::Verified => {
                if let Some(durable) = &self.durable {
                    let after = match connector.read_state().await {
                        Ok(after) => after,
                        Err(_) => return EnforcementResult::Failed,
                    };
                    if durable
                        .mark_verified(_device, action, &after)
                        .await
                        .is_err()
                    {
                        return EnforcementResult::Failed;
                    }
                }
                if self.durable.is_none()
                    && let Some(previous) = report.previous
                {
                    self.previous.lock().await.insert(_device, previous);
                }
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
    async fn reconcile(
        &self,
        device: DeviceId,
        action: RequestedAction,
    ) -> ActuationReconciliation {
        match action {
            RequestedAction::Quarantine => RequestedQuarantine::DenyInternet,
            RequestedAction::PermanentBan => RequestedQuarantine::PersistentFilter,
            _ => return ActuationReconciliation::ManualRequired,
        };
        let attempt = if let Some(durable) = &self.durable {
            match durable.load_attempt(device).await {
                Ok(state) => state,
                Err(_) => return ActuationReconciliation::Indeterminate,
            }
        } else {
            self.previous
                .lock()
                .await
                .get(&device)
                .cloned()
                .map(|state| lattice_store::W6Attempt {
                    restore: state.clone(),
                    action,
                    prepared_before: state,
                    verified_after: None,
                })
        };
        let Some(attempt) = attempt else {
            return ActuationReconciliation::ProvenNotApplied;
        };
        if attempt.action != action {
            return ActuationReconciliation::Indeterminate;
        }
        let mut connector = self.connector.lock().await;
        if connector.discovery_status() != DiscoveryStatus::Trusted {
            return ActuationReconciliation::ManualRequired;
        }
        let current = match connector.read_state().await {
            Ok(state) => state,
            Err(W6Error::Transport | W6Error::Authentication | W6Error::SessionExpired) => {
                return ActuationReconciliation::Failed;
            }
            Err(_) => return ActuationReconciliation::ManualRequired,
        };
        if current == attempt.prepared_before && attempt.verified_after.is_none() {
            return ActuationReconciliation::ProvenNotApplied;
        }
        if attempt
            .verified_after
            .as_ref()
            .is_some_and(|after| after == &current)
        {
            return ActuationReconciliation::VerifiedApplied;
        }
        ActuationReconciliation::Indeterminate
    }
    async fn undo(&self, device: DeviceId, action: RequestedAction) -> EnforcementResult {
        if !matches!(
            action,
            RequestedAction::Quarantine | RequestedAction::PermanentBan
        ) {
            return EnforcementResult::ManualRequired;
        }
        let previous = if let Some(durable) = &self.durable {
            match durable.load(device).await {
                Ok(Some(state)) => Some(state),
                Ok(None) | Err(_) => None,
            }
        } else {
            self.previous.lock().await.get(&device).cloned()
        };
        let Some(previous) = previous else {
            return EnforcementResult::ManualRequired;
        };
        let mut connector = self.connector.lock().await;
        match connector.restore(previous).await {
            Ok(Verification::Verified) => {
                if let Some(durable) = &self.durable {
                    if durable.remove(device).await.is_err() {
                        return EnforcementResult::Failed;
                    }
                } else {
                    self.previous.lock().await.remove(&device);
                }
                EnforcementResult::Verified
            }
            Ok(Verification::Unverified) | Err(W6Error::VerificationFailed) => {
                EnforcementResult::Failed
            }
            Err(_) => EnforcementResult::ManualRequired,
        }
    }
    async fn undo_available(&self, device: DeviceId, action: RequestedAction) -> bool {
        matches!(
            action,
            RequestedAction::Quarantine | RequestedAction::PermanentBan
        ) && (if let Some(durable) = &self.durable {
            durable
                .load(device)
                .await
                .is_ok_and(|state| state.is_some())
        } else {
            self.previous
                .try_lock()
                .is_ok_and(|saved| saved.contains_key(&device))
        })
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
        } else {
            // The committed discovery projection is authoritative.  Do not
            // let an old automatic match extend a device's deadline after its
            // current evidence no longer supports identification.
            self.repo
                .set_identification(device, Identification::Unknown)
                .await?;
        }
        self.evaluate(self.repo.load(device).await?.unwrap_or(policy), now)
            .await
    }
    pub async fn enabled(&self) -> anyhow::Result<bool> {
        Ok(self.repo.baseline_started_at().await?.is_some())
    }
    /// Durable control state is authoritative over contradictory discovery
    /// presence until the router has verified a release.
    pub async fn control_blocks(&self, device: DeviceId) -> anyhow::Result<bool> {
        match &self.presence {
            Some(state) => Ok(state.verified_control_blocked(device).await?),
            None => Ok(false),
        }
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
        let previously_published = self.repo.published_decision(p.device_id).await?;
        // Recover the historical split-ack crash window from older binaries:
        // an acknowledged matching verified decision proves publication was
        // durable, so its exact stale reservation can be retired without any
        // actuator call.
        if let Some(last) = &previously_published
            && last.enforcement_result == EnforcementResult::Verified
            && let Some(attempt) = self.repo.actuation_attempt(p.device_id).await?
            && attempt.policy_version == last.policy_version
            && attempt.action == last.requested_action
            && attempt.decision.as_ref() == Some(last)
        {
            self.repo
                .clear_actuation_attempt(p.device_id, attempt.policy_version, attempt.action)
                .await?;
        }
        let release_action = self.repo.release_retry_action(p.device_id).await?;
        if let Some(action) = release_action {
            if !self.repo.release_retry_due(p.device_id, now).await? {
                if let Some(last) = previously_published {
                    return self
                        .finish(
                            p,
                            evaluation,
                            last.enforcement_result,
                            last.undo_available,
                            now,
                        )
                        .await;
                }
            } else {
                // A crash may happen after the durable control-plane unblock
                // but before the retry row is cleared.  That durable fact is
                // the idempotency fence for restoration: never issue a second
                // undo just to complete cleanup.
                if let Some(presence) = &self.presence
                    && !presence.verified_control_blocked(p.device_id).await?
                {
                    self.repo.clear_release_retry(p.device_id).await?;
                    return self
                        .finish(p, evaluation, EnforcementResult::Verified, false, now)
                        .await;
                }
                let undo = self.actuator.undo(p.device_id, action).await;
                let available = self.actuator.undo_available(p.device_id, action).await;
                if undo == EnforcementResult::Verified {
                    if let Some(presence) = &self.presence {
                        presence.record_verified_unblock(p.device_id, now).await?;
                    }
                    // Retire retry state only after the durable unblock. If
                    // the control write fails, the next sweep must retry.
                    self.repo.clear_release_retry(p.device_id).await?;
                } else {
                    self.repo
                        .schedule_release_retry(p.device_id, action, now)
                        .await?;
                }
                return self.finish(p, evaluation, undo, available, now).await;
            }
        }
        // A pending journal belongs to an exact older decision.  Reconcile it
        // before attempting a newer action: overwriting it would either replay
        // an irreversible mutation or lose the event needed to explain it.
        if let Some(old) = self.repo.actuation_attempt(p.device_id).await?
            && (old.policy_version != evaluation.policy_version
                || old.action != evaluation.requested_action)
        {
            match self.actuator.reconcile(p.device_id, old.action).await {
                ActuationReconciliation::ProvenNotApplied => {
                    self.repo
                        .clear_actuation_attempt(p.device_id, old.policy_version, old.action)
                        .await?;
                }
                ActuationReconciliation::VerifiedApplied => {
                    if let Some(ref event) = old.decision {
                        let mut recovered = event.clone();
                        recovered.undo_available =
                            matches!(
                                old.action,
                                RequestedAction::Quarantine | RequestedAction::PermanentBan
                            ) && self.actuator.undo_available(p.device_id, old.action).await;
                        self.publish_exact(&recovered, Some(&old), now).await?;
                        // PermanentBan is stronger than Quarantine.  Never
                        // claim a downgrade merely by applying the weaker
                        // control over it: first drive the durable restore
                        // state machine (or surface durable owner guidance if
                        // restoration is unavailable).
                        if old.action == RequestedAction::PermanentBan
                            && evaluation.requested_action == RequestedAction::Quarantine
                        {
                            self.repo
                                .schedule_release_retry(p.device_id, old.action, now)
                                .await?;
                            return self
                                .finish(
                                    p,
                                    evaluation,
                                    EnforcementResult::ManualRequired,
                                    false,
                                    now,
                                )
                                .await;
                        }
                    } else {
                        // Legacy entries lack the causality data required to
                        // publish safely. Retire only if a prior ack proves it.
                        let acknowledged = previously_published.as_ref().is_some_and(|last| {
                            last.enforcement_result == EnforcementResult::Verified
                                && last.policy_version == old.policy_version
                                && last.requested_action == old.action
                        });
                        if acknowledged {
                            self.repo
                                .clear_actuation_attempt(
                                    p.device_id,
                                    old.policy_version,
                                    old.action,
                                )
                                .await?;
                        } else {
                            return self
                                .finish(
                                    p,
                                    evaluation,
                                    EnforcementResult::ManualRequired,
                                    false,
                                    now,
                                )
                                .await;
                        }
                    }
                }
                ActuationReconciliation::Indeterminate
                | ActuationReconciliation::ManualRequired
                | ActuationReconciliation::Failed => {
                    return self
                        .finish(p, evaluation, EnforcementResult::ManualRequired, false, now)
                        .await;
                }
            }
        }
        let prior_matches = |result: EnforcementResult| {
            previously_published.as_ref().is_some_and(|last| {
                last.evaluation == evaluation
                    && last.requested_action == evaluation.requested_action
                    && last.enforcement_result == result
            })
        };
        let enforcement = if matches!(
            evaluation.requested_action,
            RequestedAction::None | RequestedAction::OwnerAttention
        ) || p.protection != Protection::None
        {
            EnforcementResult::NotRequested
        } else if prior_matches(EnforcementResult::Verified) {
            // A durable acknowledged verification is an idempotency fence for
            // irreversible actions such as PersistentFilter.
            EnforcementResult::Verified
        } else if prior_matches(EnforcementResult::ManualRequired)
            && !self.repo.enforcement_retry_due(p.device_id, now).await?
        {
            EnforcementResult::ManualRequired
        } else if prior_matches(EnforcementResult::Failed)
            && !self.repo.enforcement_retry_due(p.device_id, now).await?
        {
            EnforcementResult::Failed
        } else {
            // This durable reservation is the idempotency boundary for the
            // physical mutation, not merely for its event publication.
            match self
                .repo
                .reserve_actuation_with_decision(
                    p.device_id,
                    evaluation.policy_version,
                    evaluation.requested_action,
                    now,
                    Some(&self.policy_event(&p, evaluation, EnforcementResult::Verified, false)),
                )
                .await?
            {
                ActuationReservation::Reserved => {
                    self.actuator
                        .enforce(p.device_id, evaluation.requested_action)
                        .await
                }
                ActuationReservation::Existing => match self
                    .actuator
                    .reconcile(p.device_id, evaluation.requested_action)
                    .await
                {
                    ActuationReconciliation::VerifiedApplied => EnforcementResult::Verified,
                    ActuationReconciliation::ProvenNotApplied => {
                        // Readback proved the prior reservation did not reach
                        // the appliance.  Re-reserve before the one permitted
                        // retry; failed/manual results remain rate limited by
                        // the existing enforcement retry schedule.
                        self.repo
                            .clear_actuation_attempt(
                                p.device_id,
                                evaluation.policy_version,
                                evaluation.requested_action,
                            )
                            .await?;
                        self.repo
                            .reserve_actuation_with_decision(
                                p.device_id,
                                evaluation.policy_version,
                                evaluation.requested_action,
                                now,
                                Some(&self.policy_event(
                                    &p,
                                    evaluation,
                                    EnforcementResult::Verified,
                                    false,
                                )),
                            )
                            .await?;
                        self.actuator
                            .enforce(p.device_id, evaluation.requested_action)
                            .await
                    }
                    ActuationReconciliation::Indeterminate
                    | ActuationReconciliation::ManualRequired => EnforcementResult::ManualRequired,
                    ActuationReconciliation::Failed => EnforcementResult::Failed,
                },
            }
        };
        match enforcement {
            EnforcementResult::ManualRequired | EnforcementResult::Failed => {
                self.repo
                    .schedule_enforcement_retry(p.device_id, now)
                    .await?;
            }
            EnforcementResult::Verified | EnforcementResult::NotRequested => {
                self.repo.clear_enforcement_retry(p.device_id).await?;
            }
        }
        if enforcement == EnforcementResult::Verified
            && matches!(
                evaluation.requested_action,
                RequestedAction::Quarantine | RequestedAction::PermanentBan
            )
            && let Some(presence) = &self.presence
        {
            presence.record_verified_block(p.device_id, now).await?;
        }
        let undo_available = enforcement == EnforcementResult::Verified
            && matches!(
                evaluation.requested_action,
                RequestedAction::Quarantine | RequestedAction::PermanentBan
            )
            && self
                .actuator
                .undo_available(p.device_id, evaluation.requested_action)
                .await;
        self.finish(p, evaluation, enforcement, undo_available, now)
            .await
    }
    async fn finish(
        &self,
        p: DevicePolicy,
        evaluation: Evaluation,
        enforcement: EnforcementResult,
        undo_available: bool,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        let event = self.policy_event(&p, evaluation, enforcement, undo_available);
        self.publish_exact(&event, None, now).await?;
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
    fn policy_event(
        &self,
        p: &DevicePolicy,
        evaluation: Evaluation,
        enforcement: EnforcementResult,
        undo_available: bool,
    ) -> PolicyChanged {
        PolicyChanged {
            device_id: p.device_id,
            policy_version: evaluation.policy_version,
            evaluation,
            requested_action: evaluation.requested_action,
            evidence_summary: evidence_summary(p),
            enforcement_result: enforcement,
            undo_available,
        }
    }
    async fn publish_exact(
        &self,
        event: &PolicyChanged,
        attempt: Option<&lattice_store::ActuationAttempt>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let fingerprint = serde_json::to_string(event)?;
        if self
            .repo
            .prepare_exact_decision_publication(event.device_id, &fingerprint, event)
            .await?
        {
            if let Some(bus) = &self.events {
                bus.publish(now, EventPayload::PolicyChanged(event.clone()))
                    .await;
            }
            let matching_attempt = if attempt.is_some() {
                attempt.cloned()
            } else if event.enforcement_result == EnforcementResult::Verified
                && matches!(
                    event.requested_action,
                    RequestedAction::Quarantine | RequestedAction::PermanentBan
                )
            {
                self.repo
                    .actuation_attempt(event.device_id)
                    .await?
                    .filter(|attempt| {
                        attempt.policy_version == event.policy_version
                            && attempt.action == event.requested_action
                            && attempt.decision.as_ref() == Some(event)
                    })
            } else {
                None
            };
            self.repo
                .mark_decision_published_and_clear_attempt(
                    event.device_id,
                    &fingerprint,
                    event,
                    matching_attempt.as_ref(),
                )
                .await?;
        }
        Ok(())
    }
    pub async fn approve(
        &self,
        d: DeviceId,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        if self.repo.load(d).await?.is_none() {
            return Err(PolicyActionError::NotEnrolled.into());
        }
        let prior = self.repo.published_decision(d).await?;
        // A router mutation may be durably verified while its policy event is
        // still only in the journal.  Approval must reconcile that exact
        // action before it can make the policy look harmless: otherwise an
        // owner approval can return NotRequested while the router remains
        // blocked.
        if let Some(attempt) = self.repo.actuation_attempt(d).await?
            && !prior.as_ref().is_some_and(|published| {
                published.enforcement_result == EnforcementResult::Verified
                    && published.policy_version == attempt.policy_version
                    && published.requested_action == attempt.action
            })
        {
            match self.actuator.reconcile(d, attempt.action).await {
                ActuationReconciliation::VerifiedApplied => {
                    let Some(recovered) = attempt.decision.clone() else {
                        return self
                            .approve_pending_release(
                                d,
                                attempt.action,
                                EnforcementResult::ManualRequired,
                                now,
                            )
                            .await;
                    };
                    self.publish_exact(&recovered, Some(&attempt), now).await?;
                    if let Some(presence) = &self.presence {
                        presence.record_verified_block(d, now).await?;
                    }
                    return self.approve_verified_action(d, attempt.action, now).await;
                }
                ActuationReconciliation::ProvenNotApplied => {
                    self.repo
                        .clear_actuation_attempt(d, attempt.policy_version, attempt.action)
                        .await?;
                }
                ActuationReconciliation::Indeterminate
                | ActuationReconciliation::ManualRequired => {
                    return self
                        .approve_pending_release(
                            d,
                            attempt.action,
                            EnforcementResult::ManualRequired,
                            now,
                        )
                        .await;
                }
                ActuationReconciliation::Failed => {
                    return self
                        .approve_pending_release(d, attempt.action, EnforcementResult::Failed, now)
                        .await;
                }
            }
        }
        if let Some(prior) = prior
            && prior.enforcement_result == EnforcementResult::Verified
            && matches!(
                prior.requested_action,
                RequestedAction::Quarantine | RequestedAction::PermanentBan
            )
        {
            return self
                .approve_verified_action(d, prior.requested_action, now)
                .await;
        }
        self.repo
            .set_owner_decision(d, OwnerDecision::Approved)
            .await?;
        let p = self.repo.load(d).await?.context("policy disappeared")?;
        self.evaluate(p, now).await
    }
    async fn approve_verified_action(
        &self,
        d: DeviceId,
        action: RequestedAction,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        self.repo
            .set_owner_decision_and_schedule_release_retry(d, OwnerDecision::Approved, action, now)
            .await?;
        let p = self.repo.load(d).await?.context("policy disappeared")?;
        let can_undo = self.actuator.undo_available(d, action).await;
        let undo = if can_undo {
            self.actuator.undo(d, action).await
        } else {
            EnforcementResult::ManualRequired
        };
        if undo == EnforcementResult::Verified {
            if let Some(presence) = &self.presence {
                presence.record_verified_unblock(d, now).await?;
            }
            self.repo.clear_release_retry(d).await?;
        } else {
            self.repo.schedule_release_retry(d, action, now).await?;
        }
        self.finish(
            p.clone(),
            evaluate_policy(&p, now),
            undo,
            can_undo && undo != EnforcementResult::Verified,
            now,
        )
        .await
    }
    async fn approve_pending_release(
        &self,
        d: DeviceId,
        action: RequestedAction,
        outcome: EnforcementResult,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        self.repo
            .set_owner_decision_and_schedule_release_retry(d, OwnerDecision::Approved, action, now)
            .await?;
        let p = self.repo.load(d).await?.context("policy disappeared")?;
        self.finish(
            p.clone(),
            evaluate_policy(&p, now),
            outcome,
            self.actuator.undo_available(d, action).await,
            now,
        )
        .await
    }
    pub async fn reject(&self, d: DeviceId, now: DateTime<Utc>) -> anyhow::Result<AuditedDecision> {
        self.set_owner_decision_after_release_guard(d, OwnerDecision::Rejected, now)
            .await
    }
    pub async fn quarantine(
        &self,
        d: DeviceId,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        self.set_owner_decision_after_release_guard(d, OwnerDecision::Quarantined, now)
            .await
    }
    /// A queued restoration encodes a previous owner intent. Reconcile or
    /// cancel it before recording a newer intent so it cannot later undo the
    /// newer block. Re-applying the same action is read-only when reconciliation
    /// proves it remains active; stronger/different actions return to the
    /// ordinary journaled enforcement path after cancellation.
    async fn set_owner_decision_after_release_guard(
        &self,
        d: DeviceId,
        owner: OwnerDecision,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        let current = self
            .repo
            .load(d)
            .await?
            .ok_or(PolicyActionError::NotEnrolled)?;
        let mut intended = current.clone();
        intended.owner_decision = owner;
        let evaluation = evaluate_policy(&intended, now);
        if let Some(release_action) = self.repo.release_retry_action(d).await? {
            if evaluation.requested_action == release_action {
                match self.actuator.reconcile(d, release_action).await {
                    ActuationReconciliation::VerifiedApplied => {
                        self.repo.clear_release_retry(d).await?;
                        self.repo.set_owner_decision(d, owner).await?;
                        let p = self.repo.load(d).await?.context("policy disappeared")?;
                        let undo_available = self.actuator.undo_available(d, release_action).await;
                        return self
                            .finish(
                                p,
                                evaluate_policy(&intended, now),
                                EnforcementResult::Verified,
                                undo_available,
                                now,
                            )
                            .await;
                    }
                    ActuationReconciliation::ProvenNotApplied => {
                        self.repo.clear_release_retry(d).await?;
                    }
                    ActuationReconciliation::Indeterminate
                    | ActuationReconciliation::ManualRequired
                    | ActuationReconciliation::Failed => {
                        return Err(PolicyActionError::PendingRelease.into());
                    }
                }
            } else {
                self.repo.clear_release_retry(d).await?;
            }
        }
        self.repo.set_owner_decision(d, owner).await?;
        self.evaluate(self.repo.load(d).await?.context("policy disappeared")?, now)
            .await
    }
    pub async fn extend_once(
        &self,
        d: DeviceId,
        until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<AuditedDecision> {
        if self.repo.load(d).await?.is_none() {
            return Err(PolicyActionError::NotEnrolled.into());
        }
        self.repo.extend_once(d, until).await?;
        let p = self.repo.load(d).await?.context("policy disappeared")?;
        self.evaluate(p, now).await
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
