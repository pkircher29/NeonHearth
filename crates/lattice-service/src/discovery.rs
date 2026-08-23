//! Service-owned boundary joining source-stamped evidence, identity, presence, and flow facts.
//! Sensors submit facts; this module is the only place that correlates them into app events.

use chrono::{DateTime, Utc};
use lattice_domain::{DeviceId, EventPayload, EvidenceFact, PresenceChanged};
use lattice_intelligence::presence::{
    PresenceConfig, PresenceEngine, PresenceError, PresenceEvidence, PresenceEvidenceKind,
    PresenceTransition,
};
use lattice_intelligence::{IdentityConfig, IdentityEngine, IdentityError};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct DiscoveryObservation {
    pub candidate: Option<DeviceId>,
    pub facts: Vec<EvidenceFact>,
    pub presence_source: String,
    pub presence_kind: PresenceEvidenceKind,
    pub observed_at: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct DiscoveryResult {
    pub device_id: DeviceId,
    pub identification: Option<lattice_intelligence::Identification>,
    pub presence: Vec<PresenceTransition>,
    pub events: Vec<EventPayload>,
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
    #[error("presence: {0}")]
    Presence(#[from] PresenceError),
}

pub struct DiscoveryPipeline {
    identity: IdentityEngine,
    presence: PresenceEngine,
}

impl DiscoveryPipeline {
    pub fn new(ids: impl Iterator<Item = DeviceId> + Send) -> Result<Self, DiscoveryError> {
        Ok(Self {
            identity: IdentityEngine::new(IdentityConfig::default(), ids)?,
            presence: PresenceEngine::new(PresenceConfig::default())?,
        })
    }

    pub fn observe(
        &mut self,
        input: DiscoveryObservation,
        arrival: DateTime<Utc>,
    ) -> Result<DiscoveryResult, DiscoveryError> {
        let id = self
            .identity
            .observe_at(input.candidate, input.facts, input.observed_at)?;
        let presence = self.presence.ingest_events(
            PresenceEvidence {
                device_id: id,
                source: input.presence_source,
                kind: input.presence_kind,
                observed_at: input.observed_at,
                valid_until: input.valid_until,
            },
            arrival,
        )?;
        let identification = self.identity.identification_at(id, input.observed_at)?;
        let events = presence
            .iter()
            .map(|t| EventPayload::PresenceChanged(PresenceChanged::from(t)))
            .collect();
        Ok(DiscoveryResult {
            device_id: id,
            identification,
            presence,
            events,
        })
    }

    pub fn evaluate(
        &mut self,
        id: DeviceId,
        at: DateTime<Utc>,
    ) -> Result<Vec<PresenceTransition>, DiscoveryError> {
        Ok(self.presence.evaluate(id, at)?.into_iter().collect())
    }

    pub fn presence_state(&self, id: DeviceId) -> Option<lattice_domain::PresenceState> {
        self.presence.state(id)
    }
}
