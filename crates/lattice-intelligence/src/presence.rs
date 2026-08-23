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
    pub confirmation_window: Duration,
    pub trusted_sources: Vec<String>,
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
            confirmation_window: Duration::minutes(2),
            trusted_sources: vec!["sensor-a".into()],
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
            || self.retention < self.online_window
            || self.confirmation_window <= Duration::zero()
            || self.future_skew < Duration::zero()
        {
            return Err(PresenceError::InvalidConfig);
        }
        if self.trusted_sources.is_empty()
            || self.trusted_sources.len() > 256
            || self
                .trusted_sources
                .iter()
                .any(|s| s.is_empty() || s.len() > self.max_source_len)
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
impl From<&PresenceTransition> for lattice_domain::PresenceChanged {
    fn from(t: &PresenceTransition) -> Self {
        Self {
            device_id: t.device_id,
            from: t.from,
            to: t.to,
            reason: if t.correction_of.is_some() {
                "late_evidence_correction".into()
            } else {
                "presence_evidence".into()
            },
            trigger_source: t.trigger.source.clone(),
            trigger_kind: t.trigger.kind.as_str().into(),
            evidence_observed_at: t.trigger.observed_at,
            evidence_valid_until: t.trigger.valid_until,
            correction_of: t.correction_of,
        }
    }
}
impl PresenceEvidenceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Traffic => "traffic",
            Self::Lease => "lease",
            Self::RouterAssociation => "router_association",
            Self::ProbeSuccess => "probe_success",
            Self::ConfirmationFailure => "confirmation_failure",
            Self::EnforcementBlocked => "enforcement_blocked",
            Self::EnforcementUnblocked => "enforcement_unblocked",
            Self::SensorImpaired => "sensor_impaired",
            Self::SensorRecovered => "sensor_recovered",
            Self::Contradiction => "contradiction",
            Self::ContradictionCleared => "contradiction_cleared",
            Self::Evaluation => "evaluation",
        }
    }
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
    ever_supported: bool,
    blocked: bool,
    impaired: bool,
    contradictory: bool,
    enforcement_clock: Option<DateTime<Utc>>,
    impairment_clock: Option<DateTime<Utc>>,
    contradiction_clock: Option<DateTime<Utc>>,
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
    /// Returns the retained domain events after `transition_id` in deterministic sequence order.
    ///
    /// This is the lossless event-bus boundary for the bounded retained history: callers can
    /// consume both a late correction and any separate current-state transition produced by the
    /// same ingestion, even though [`Self::ingest`] returns at most one transition for convenience.
    pub fn domain_events_since(
        &self,
        id: DeviceId,
        transition_id: u64,
    ) -> Result<Vec<lattice_domain::PresenceChanged>, PresenceError> {
        let d = self.devices.get(&id).ok_or(PresenceError::DeviceNotFound)?;
        Ok(d.history
            .iter()
            .filter(|transition| transition.transition_id > transition_id)
            .map(lattice_domain::PresenceChanged::from)
            .collect())
    }
    pub fn ingest(
        &mut self,
        e: PresenceEvidence,
        arrival: DateTime<Utc>,
    ) -> Result<Option<PresenceTransition>, PresenceError> {
        self.ingest_authorized(e, arrival, false)
    }
    pub fn record_verified_enforcement(
        &mut self,
        device_id: DeviceId,
        blocked: bool,
        source: &str,
        observed_at: DateTime<Utc>,
        arrival: DateTime<Utc>,
    ) -> Result<Option<PresenceTransition>, PresenceError> {
        self.ingest_authorized(
            PresenceEvidence {
                device_id,
                source: source.into(),
                kind: if blocked {
                    PresenceEvidenceKind::EnforcementBlocked
                } else {
                    PresenceEvidenceKind::EnforcementUnblocked
                },
                observed_at,
                valid_until: None,
            },
            arrival,
            true,
        )
    }
    fn ingest_authorized(
        &mut self,
        e: PresenceEvidence,
        arrival: DateTime<Utc>,
        enforcement_authorized: bool,
    ) -> Result<Option<PresenceTransition>, PresenceError> {
        self.validate(&e, arrival, enforcement_authorized)?;
        if !self.devices.contains_key(&e.device_id) && self.devices.len() >= self.cfg.max_devices {
            return Err(PresenceError::Capacity("devices"));
        }
        if let Some(d) = self.devices.get(&e.device_id) {
            if arrival < d.last_evaluation {
                return Err(PresenceError::ClockRollback);
            }
            if d.evidence.contains(&e) || stale_control(d, &e) {
                return Ok(None);
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
            ever_supported: false,
            blocked: false,
            impaired: false,
            contradictory: false,
            enforcement_clock: None,
            impairment_clock: None,
            contradiction_clock: None,
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
                .and_then(|dep| {
                    support_at(
                        &e,
                        dep.occurred_at,
                        d.ever_supported,
                        self.cfg.online_window,
                    )
                    .map(|target| (dep, target))
                });
            let late = any_departure
                .as_ref()
                .is_some_and(|dep| is_positive(e.kind) && e.observed_at <= dep.occurred_at);
            let current_valid =
                support_at(&e, arrival, d.ever_supported, self.cfg.online_window).is_some();
            apply_flags(d, &e);
            if is_real_positive(e.kind) && (!late || current_valid) {
                d.ever_supported = true;
            }
            if !late || current_valid || !is_positive(e.kind) {
                d.evidence.push(e.clone());
                sort_evidence(&mut d.evidence);
            }
            (
                correct.map(|(dep, target)| (dep.transition_id, target)),
                late && !current_valid,
            )
        };
        let mut correction_event = None;
        if let Some((departure_id, target)) = correction.0 {
            let tr = self.make_transition(
                id,
                PresenceState::Offline,
                target,
                &e,
                arrival,
                Some(departure_id),
            )?;
            let d = self
                .devices
                .get_mut(&id)
                .ok_or(PresenceError::DeviceNotFound)?;
            push_history(d, tr.clone(), self.cfg.max_history_per_device);
            correction_event = Some(tr);
        }
        if correction.1 && correction_event.is_none() {
            return Ok(None);
        }
        Ok(self.recompute(id, arrival, Some(&e))?.or(correction_event))
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
            && confirmations(d, at, self.cfg.confirmation_window, is_real_positive)
                < self.cfg.join_confirmations
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
        };
        let source = trigger.unwrap_or(&synthetic);
        let tr = self.make_transition(id, d.state, gated, source, at, None)?;
        let d = self
            .devices
            .get_mut(&id)
            .ok_or(PresenceError::DeviceNotFound)?;
        d.state = gated;
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
    fn validate(
        &self,
        e: &PresenceEvidence,
        arrival: DateTime<Utc>,
        enforcement_authorized: bool,
    ) -> Result<(), PresenceError> {
        if !self.cfg.trusted_sources.iter().any(|s| s == &e.source) {
            return Err(PresenceError::Untrusted);
        }
        if e.source.is_empty() || e.source.len() > self.cfg.max_source_len {
            return Err(PresenceError::InvalidEvidence("source"));
        }
        let future_limit = arrival
            .checked_add_signed(self.cfg.future_skew)
            .ok_or(PresenceError::InvalidEvidence("time overflow"))?;
        if e.observed_at > future_limit {
            return Err(PresenceError::InvalidEvidence("future skew"));
        }
        if e.valid_until.is_some_and(|x| x < e.observed_at) {
            return Err(PresenceError::InvalidEvidence("validity"));
        }
        if e.kind == PresenceEvidenceKind::Traffic
            && e.observed_at
                .checked_add_signed(self.cfg.online_window)
                .is_none()
        {
            return Err(PresenceError::InvalidEvidence("time overflow"));
        }
        if matches!(
            e.kind,
            PresenceEvidenceKind::EnforcementBlocked | PresenceEvidenceKind::EnforcementUnblocked
        ) && !enforcement_authorized
        {
            return Err(PresenceError::InvalidEvidence("reserved enforcement"));
        }
        if e.kind == PresenceEvidenceKind::Evaluation {
            return Err(PresenceError::InvalidEvidence("reserved kind"));
        }
        Ok(())
    }
}

fn apply_flags(d: &mut DevicePresence, e: &PresenceEvidence) {
    match e.kind {
        PresenceEvidenceKind::EnforcementBlocked
            if d.enforcement_clock.is_none_or(|x| e.observed_at > x) =>
        {
            d.blocked = true;
            d.enforcement_clock = Some(e.observed_at)
        }
        PresenceEvidenceKind::EnforcementUnblocked
            if d.enforcement_clock.is_none_or(|x| e.observed_at > x) =>
        {
            d.blocked = false;
            d.enforcement_clock = Some(e.observed_at)
        }
        PresenceEvidenceKind::SensorImpaired
            if d.impairment_clock.is_none_or(|x| e.observed_at > x) =>
        {
            d.impaired = true;
            d.impairment_clock = Some(e.observed_at)
        }
        PresenceEvidenceKind::SensorRecovered
            if d.impairment_clock.is_none_or(|x| e.observed_at > x) =>
        {
            d.impaired = false;
            d.impairment_clock = Some(e.observed_at)
        }
        PresenceEvidenceKind::Contradiction
            if d.contradiction_clock.is_none_or(|x| e.observed_at > x) =>
        {
            d.contradictory = true;
            d.contradiction_clock = Some(e.observed_at)
        }
        PresenceEvidenceKind::ContradictionCleared
            if d.contradiction_clock.is_none_or(|x| e.observed_at > x) =>
        {
            d.contradictory = false;
            d.contradiction_clock = Some(e.observed_at)
        }
        _ => {}
    }
}
fn stale_control(d: &DevicePresence, e: &PresenceEvidence) -> bool {
    match e.kind {
        PresenceEvidenceKind::EnforcementBlocked | PresenceEvidenceKind::EnforcementUnblocked => {
            d.enforcement_clock.is_some_and(|x| e.observed_at <= x)
        }
        PresenceEvidenceKind::SensorImpaired | PresenceEvidenceKind::SensorRecovered => {
            d.impairment_clock.is_some_and(|x| e.observed_at <= x)
        }
        PresenceEvidenceKind::Contradiction | PresenceEvidenceKind::ContradictionCleared => {
            d.contradiction_clock.is_some_and(|x| e.observed_at <= x)
        }
        _ => false,
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
    let failures = distinct_count(d.evidence.iter().filter(|e| {
        e.kind == PresenceEvidenceKind::ConfirmationFailure
            && e.observed_at <= at
            && support_end.is_none_or(|end| e.observed_at > end)
            && at.signed_duration_since(e.observed_at) <= c.confirmation_window
    }));
    if d.ever_supported && failures >= c.departure_confirmations {
        return PresenceState::Offline;
    }
    if matches!(d.state, PresenceState::Online | PresenceState::Quiet) {
        d.state
    } else {
        PresenceState::Unknown
    }
}
fn is_real_positive(k: PresenceEvidenceKind) -> bool {
    matches!(
        k,
        PresenceEvidenceKind::Traffic
            | PresenceEvidenceKind::Lease
            | PresenceEvidenceKind::RouterAssociation
    )
}
fn is_positive(k: PresenceEvidenceKind) -> bool {
    is_real_positive(k) || k == PresenceEvidenceKind::ProbeSuccess
}
fn support_at(
    e: &PresenceEvidence,
    at: DateTime<Utc>,
    ever: bool,
    online: Duration,
) -> Option<PresenceState> {
    if e.observed_at > at {
        return None;
    }
    match e.kind {
        PresenceEvidenceKind::Traffic if at.signed_duration_since(e.observed_at) < online => {
            Some(PresenceState::Online)
        }
        PresenceEvidenceKind::Lease | PresenceEvidenceKind::RouterAssociation
            if e.valid_until.is_some_and(|x| x >= at) =>
        {
            Some(PresenceState::Quiet)
        }
        PresenceEvidenceKind::ProbeSuccess if ever && e.valid_until.is_some_and(|x| x >= at) => {
            Some(PresenceState::Quiet)
        }
        _ => None,
    }
}
fn sort_evidence(v: &mut [PresenceEvidence]) {
    v.sort_by(|a, b| {
        (a.observed_at, &a.source, a.kind, a.valid_until).cmp(&(
            b.observed_at,
            &b.source,
            b.kind,
            b.valid_until,
        ))
    })
}
fn distinct_count<'a>(it: impl Iterator<Item = &'a PresenceEvidence>) -> usize {
    let mut s = std::collections::HashSet::new();
    for e in it {
        s.insert((e.source.clone(), e.kind, e.observed_at, e.valid_until));
    }
    s.len()
}
fn confirmations(
    d: &DevicePresence,
    at: DateTime<Utc>,
    window: Duration,
    pred: fn(PresenceEvidenceKind) -> bool,
) -> usize {
    distinct_count(d.evidence.iter().filter(|e| {
        pred(e.kind) && e.observed_at <= at && at.signed_duration_since(e.observed_at) <= window
    }))
}
fn push_history(d: &mut DevicePresence, t: PresenceTransition, max: usize) {
    if d.history.len() == max {
        d.history.pop_front();
    }
    d.history.push_back(t)
}
