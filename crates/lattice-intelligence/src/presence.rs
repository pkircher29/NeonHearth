use chrono::{DateTime, Duration, Utc};
use lattice_domain::{DeviceId, PresenceState};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct PresenceConfig {
    pub online_window: Duration,
    pub correction_window: Duration,
    pub retention: Duration,
    pub future_skew: Duration,
    pub join_confirmations: usize,
    pub departure_confirmations: usize,
    pub max_devices: usize,
    pub max_evidence_per_device: usize,
    pub max_history_per_device: usize,
    pub max_source_len: usize,
}
impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            online_window: Duration::seconds(30),
            correction_window: Duration::minutes(5),
            retention: Duration::hours(24),
            future_skew: Duration::seconds(5),
            join_confirmations: 2,
            departure_confirmations: 2,
            max_devices: 4096,
            max_evidence_per_device: 256,
            max_history_per_device: 128,
            max_source_len: 128,
        }
    }
}
impl PresenceConfig {
    fn validate(&self) -> Result<(), PresenceError> {
        if self.online_window <= Duration::zero()
            || self.correction_window <= Duration::zero()
            || self.retention < self.correction_window
            || self.future_skew < Duration::zero()
        {
            return Err(PresenceError::InvalidConfig);
        }
        if [
            self.join_confirmations,
            self.departure_confirmations,
            self.max_devices,
            self.max_evidence_per_device,
            self.max_history_per_device,
            self.max_source_len,
        ]
        .contains(&0)
        {
            return Err(PresenceError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceEvidenceKind {
    Traffic,
    Lease,
    RouterAssociation,
    ProbeSuccess,
    ConfirmationFailure,
    EnforcementBlocked,
    EnforcementUnblocked,
    SensorImpaired,
    SensorRecovered,
    Contradiction,
    ContradictionCleared,
    Evaluation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PresenceEvidence {
    pub device_id: DeviceId,
    pub source: String,
    pub kind: PresenceEvidenceKind,
    pub observed_at: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub trusted: bool,
    pub verified: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PresenceTrigger {
    pub source: String,
    pub kind: PresenceEvidenceKind,
    pub observed_at: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub arrival_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PresenceTransition {
    pub transition_id: u64,
    pub device_id: DeviceId,
    pub from: PresenceState,
    pub to: PresenceState,
    pub occurred_at: DateTime<Utc>,
    pub trigger: PresenceTrigger,
    pub correction_of: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresenceSnapshot {
    pub devices: usize,
    pub evidence: usize,
    pub history: usize,
    pub next_transition: u64,
}
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PresenceError {
    #[error("invalid presence config")]
    InvalidConfig,
    #[error("untrusted evidence")]
    Untrusted,
    #[error("invalid evidence: {0}")]
    InvalidEvidence(&'static str),
    #[error("capacity exceeded: {0}")]
    Capacity(&'static str),
    #[error("device not found")]
    DeviceNotFound,
    #[error("evaluation clock moved backwards")]
    ClockRollback,
    #[error("transition sequence exhausted")]
    SequenceExhausted,
}

#[derive(Clone)]
struct DevicePresence {
    state: PresenceState,
    evidence: Vec<PresenceEvidence>,
    history: VecDeque<PresenceTransition>,
    last_evaluation: DateTime<Utc>,
    join_streak: usize,
    ever_supported: bool,
    blocked: bool,
    impaired: bool,
    contradictory: bool,
}
pub struct PresenceEngine {
    cfg: PresenceConfig,
    devices: HashMap<DeviceId, DevicePresence>,
    next_transition: u64,
}
impl PresenceEngine {
    pub fn new(cfg: PresenceConfig) -> Result<Self, PresenceError> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            devices: HashMap::new(),
            next_transition: 1,
        })
    }
    pub fn snapshot(&self) -> PresenceSnapshot {
        PresenceSnapshot {
            devices: self.devices.len(),
            evidence: self.devices.values().map(|d| d.evidence.len()).sum(),
            history: self.devices.values().map(|d| d.history.len()).sum(),
            next_transition: self.next_transition,
        }
    }
    pub fn state(&self, id: DeviceId) -> Option<PresenceState> {
        self.devices.get(&id).map(|d| d.state)
    }
    pub fn history(&self, id: DeviceId) -> Result<&VecDeque<PresenceTransition>, PresenceError> {
        self.devices
            .get(&id)
            .map(|d| &d.history)
            .ok_or(PresenceError::DeviceNotFound)
    }
    pub fn ingest(
        &mut self,
        e: PresenceEvidence,
        arrival: DateTime<Utc>,
    ) -> Result<Option<PresenceTransition>, PresenceError> {
        self.validate(&e, arrival)?;
        if !self.devices.contains_key(&e.device_id) && self.devices.len() >= self.cfg.max_devices {
            return Err(PresenceError::Capacity("devices"));
        }
        if let Some(d) = self.devices.get(&e.device_id) {
            if arrival < d.last_evaluation {
                return Err(PresenceError::ClockRollback);
            }
            let retained = d
                .evidence
                .iter()
                .filter(|x| arrival.signed_duration_since(x.observed_at) <= self.cfg.retention)
                .count();
            if retained >= self.cfg.max_evidence_per_device {
                return Err(PresenceError::Capacity("evidence"));
            }
        }
        if self.next_transition == u64::MAX {
            return Err(PresenceError::SequenceExhausted);
        }
        let id = e.device_id;
        let initial = DevicePresence {
            state: PresenceState::Unknown,
            evidence: vec![],
            history: VecDeque::new(),
            last_evaluation: arrival,
            join_streak: 0,
            ever_supported: false,
            blocked: false,
            impaired: false,
            contradictory: false,
        };
        let correction = {
            let d = self.devices.entry(id).or_insert(initial);
            d.evidence
                .retain(|x| arrival.signed_duration_since(x.observed_at) <= self.cfg.retention);
            d.last_evaluation = arrival;
            let any_departure = d
                .history
                .iter()
                .rev()
                .find(|x| x.to == PresenceState::Offline)
                .cloned();
            let correct = d
                .history
                .iter()
                .rev()
                .find(|x| {
                    x.to == PresenceState::Offline
                        && arrival.signed_duration_since(x.occurred_at)
                            <= self.cfg.correction_window
                })
                .cloned()
                .filter(|dep| {
                    d.state == PresenceState::Offline
                        && is_real_positive(e.kind)
                        && e.observed_at <= dep.occurred_at
                        && dep.occurred_at.signed_duration_since(e.observed_at)
                            < self.cfg.online_window
                });
            apply_flags(d, &e);
            if is_real_positive(e.kind) {
                d.ever_supported = true;
                d.join_streak = d.join_streak.saturating_add(1);
            }
            d.evidence.push(e.clone());
            sort_evidence(&mut d.evidence);
            let stale_late = correct.is_none()
                && any_departure.is_some_and(|dep| {
                    is_real_positive(e.kind) && e.observed_at <= dep.occurred_at
                });
            (correct.map(|dep| (d.state, dep.transition_id)), stale_late)
        };
        if let Some((from, departure_id)) = correction.0 {
            let tr = self.make_transition(
                id,
                from,
                PresenceState::Online,
                &e,
                arrival,
                Some(departure_id),
            )?;
            let d = self
                .devices
                .get_mut(&id)
                .ok_or(PresenceError::DeviceNotFound)?;
            d.state = PresenceState::Online;
            push_history(d, tr.clone(), self.cfg.max_history_per_device);
            return Ok(Some(tr));
        }
        if correction.1 {
            return Ok(None);
        }
        self.recompute(id, arrival, Some(&e))
    }
    pub fn evaluate(
        &mut self,
        id: DeviceId,
        at: DateTime<Utc>,
    ) -> Result<Option<PresenceTransition>, PresenceError> {
        let d = self.devices.get(&id).ok_or(PresenceError::DeviceNotFound)?;
        if at < d.last_evaluation {
            return Err(PresenceError::ClockRollback);
        }
        if self.next_transition == u64::MAX {
            return Err(PresenceError::SequenceExhausted);
        }
        self.devices
            .get_mut(&id)
            .ok_or(PresenceError::DeviceNotFound)?
            .last_evaluation = at;
        self.recompute(id, at, None)
    }
    fn recompute(
        &mut self,
        id: DeviceId,
        at: DateTime<Utc>,
        trigger: Option<&PresenceEvidence>,
    ) -> Result<Option<PresenceTransition>, PresenceError> {
        let d = self.devices.get(&id).ok_or(PresenceError::DeviceNotFound)?;
        let candidate = candidate(d, at, &self.cfg);
        let gated = if matches!(candidate, PresenceState::Online | PresenceState::Quiet)
            && matches!(d.state, PresenceState::Unknown | PresenceState::Offline)
            && d.join_streak < self.cfg.join_confirmations
        {
            d.state
        } else {
            candidate
        };
        if gated == d.state {
            return Ok(None);
        }
        let synthetic = PresenceEvidence {
            device_id: id,
            source: "presence.timer".into(),
            kind: PresenceEvidenceKind::Evaluation,
            observed_at: at,
            valid_until: None,
            trusted: true,
            verified: true,
        };
        let source = trigger.unwrap_or(&synthetic);
        let tr = self.make_transition(id, d.state, gated, source, at, None)?;
        let d = self
            .devices
            .get_mut(&id)
            .ok_or(PresenceError::DeviceNotFound)?;
        d.state = gated;
        if gated == PresenceState::Offline
            || (gated == PresenceState::Unknown && !d.impaired && !d.contradictory)
        {
            d.join_streak = 0
        }
        push_history(d, tr.clone(), self.cfg.max_history_per_device);
        Ok(Some(tr))
    }
    fn make_transition(
        &mut self,
        id: DeviceId,
        from: PresenceState,
        to: PresenceState,
        e: &PresenceEvidence,
        at: DateTime<Utc>,
        correction: Option<u64>,
    ) -> Result<PresenceTransition, PresenceError> {
        let seq = self.next_transition;
        self.next_transition = self
            .next_transition
            .checked_add(1)
            .ok_or(PresenceError::SequenceExhausted)?;
        Ok(PresenceTransition {
            transition_id: seq,
            device_id: id,
            from,
            to,
            occurred_at: at,
            trigger: PresenceTrigger {
                source: e.source.clone(),
                kind: e.kind,
                observed_at: e.observed_at,
                valid_until: e.valid_until,
                arrival_at: at,
            },
            correction_of: correction,
        })
    }
    fn validate(&self, e: &PresenceEvidence, arrival: DateTime<Utc>) -> Result<(), PresenceError> {
        if !e.trusted {
            return Err(PresenceError::Untrusted);
        }
        if e.source.is_empty() || e.source.len() > self.cfg.max_source_len {
            return Err(PresenceError::InvalidEvidence("source"));
        }
        if arrival
            .checked_add_signed(self.cfg.future_skew)
            .is_some_and(|limit| e.observed_at > limit)
        {
            return Err(PresenceError::InvalidEvidence("future skew"));
        }
        if e.valid_until.is_some_and(|x| x < e.observed_at) {
            return Err(PresenceError::InvalidEvidence("validity"));
        }
        if matches!(
            e.kind,
            PresenceEvidenceKind::EnforcementBlocked | PresenceEvidenceKind::EnforcementUnblocked
        ) && !e.verified
        {
            return Err(PresenceError::InvalidEvidence("unverified enforcement"));
        }
        if e.kind == PresenceEvidenceKind::Evaluation {
            return Err(PresenceError::InvalidEvidence("reserved kind"));
        }
        Ok(())
    }
}

fn apply_flags(d: &mut DevicePresence, e: &PresenceEvidence) {
    match e.kind {
        PresenceEvidenceKind::EnforcementBlocked => d.blocked = true,
        PresenceEvidenceKind::EnforcementUnblocked => d.blocked = false,
        PresenceEvidenceKind::SensorImpaired => d.impaired = true,
        PresenceEvidenceKind::SensorRecovered => d.impaired = false,
        PresenceEvidenceKind::Contradiction => d.contradictory = true,
        PresenceEvidenceKind::ContradictionCleared => d.contradictory = false,
        _ => {}
    }
}
fn candidate(d: &DevicePresence, at: DateTime<Utc>, c: &PresenceConfig) -> PresenceState {
    if d.blocked {
        return PresenceState::Blocked;
    }
    if d.impaired || d.contradictory {
        return PresenceState::Unknown;
    }
    let traffic = d.evidence.iter().any(|e| {
        e.kind == PresenceEvidenceKind::Traffic
            && e.observed_at <= at
            && at.signed_duration_since(e.observed_at) < c.online_window
    });
    if traffic {
        return PresenceState::Online;
    }
    let support = d.evidence.iter().any(|e| {
        matches!(
            e.kind,
            PresenceEvidenceKind::Lease
                | PresenceEvidenceKind::RouterAssociation
                | PresenceEvidenceKind::ProbeSuccess
        ) && e.observed_at <= at
            && e.valid_until.is_some_and(|x| x >= at)
    });
    if support && d.ever_supported {
        return PresenceState::Quiet;
    }
    let support_end = d
        .evidence
        .iter()
        .filter_map(|e| match e.kind {
            PresenceEvidenceKind::Traffic => e.observed_at.checked_add_signed(c.online_window),
            PresenceEvidenceKind::Lease
            | PresenceEvidenceKind::RouterAssociation
            | PresenceEvidenceKind::ProbeSuccess => e.valid_until,
            _ => None,
        })
        .max();
    let failures = d
        .evidence
        .iter()
        .filter(|e| e.kind == PresenceEvidenceKind::ConfirmationFailure && e.observed_at <= at)
        .filter(|e| support_end.is_none_or(|end| e.observed_at > end))
        .count();
    if d.ever_supported && failures >= c.departure_confirmations {
        return PresenceState::Offline;
    }
    PresenceState::Unknown
}
fn is_real_positive(k: PresenceEvidenceKind) -> bool {
    matches!(
        k,
        PresenceEvidenceKind::Traffic
            | PresenceEvidenceKind::Lease
            | PresenceEvidenceKind::RouterAssociation
    )
}
fn sort_evidence(v: &mut [PresenceEvidence]) {
    v.sort_by(|a, b| {
        (a.observed_at, &a.source, a.kind, a.valid_until, a.verified).cmp(&(
            b.observed_at,
            &b.source,
            b.kind,
            b.valid_until,
            b.verified,
        ))
    })
}
fn push_history(d: &mut DevicePresence, t: PresenceTransition, max: usize) {
    if d.history.len() == max {
        d.history.pop_front();
    }
    d.history.push_back(t)
}
