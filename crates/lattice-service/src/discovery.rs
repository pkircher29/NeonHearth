//! Service-owned boundary joining source-stamped evidence, identity, presence, and flow facts.
//! Sensors submit facts; this module is the only place that correlates them into app events.

use chrono::{DateTime, Utc};
use lattice_domain::{DeviceId, EventPayload, EvidenceFact, PresenceChanged};
use lattice_intelligence::presence::{
    PresenceConfig, PresenceEngine, PresenceError, PresenceEvidence, PresenceEvidenceKind,
    PresenceTransition,
};
use lattice_intelligence::{IdentityConfig, IdentityEngine, IdentityError};
use lattice_sensor::flow::RollupChange;
use lattice_store::FlowIngestor;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct DiscoveryObservation {
    pub source_id: u64,
    pub candidate: Option<DeviceId>,
    pub facts: Vec<EvidenceFact>,
    pub presence_source: String,
    pub presence_kind: PresenceEvidenceKind,
    pub observed_at: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct DiscoverySource {
    pub id: u64,
    pub name: String,
    pub families: Vec<lattice_domain::EvidenceFamily>,
    pub presence: bool,
}

#[derive(Clone, Debug, Default)]
pub struct DiscoverySources(BTreeMap<u64, DiscoverySource>);
impl DiscoverySources {
    pub fn new(sources: Vec<DiscoverySource>) -> Result<Self, DiscoveryError> {
        if sources.len() > 64 {
            return Err(DiscoveryError::InvalidSource);
        }
        if sources.is_empty()
            || sources.iter().any(|s| {
                s.id == 0
                    || s.name.is_empty()
                    || s.name.len() > 128
                    || s.families.contains(&lattice_domain::EvidenceFamily::Owner)
                    || s.families.is_empty()
                    || s.families
                        .contains(&lattice_domain::EvidenceFamily::RouterHint)
                        && s.families.len() != 1
            })
        {
            return Err(DiscoveryError::InvalidSource);
        }
        let mut map = BTreeMap::new();
        for s in sources {
            if map.values().any(|x: &DiscoverySource| x.name == s.name)
                || s.families
                    .iter()
                    .any(|f| s.families.iter().filter(|x| *x == f).count() != 1)
            {
                return Err(DiscoveryError::InvalidSource);
            }
            if map.insert(s.id, s).is_some() {
                return Err(DiscoveryError::InvalidSource);
            }
        }
        Ok(Self(map))
    }
    pub fn sensor(
        id: u64,
        name: impl Into<String>,
        families: Vec<lattice_domain::EvidenceFamily>,
    ) -> Result<Self, DiscoveryError> {
        Self::new(vec![DiscoverySource {
            id,
            name: name.into(),
            families,
            presence: true,
        }])
    }
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
    #[error("invalid or unregistered discovery source")]
    InvalidSource,
    #[error("flow: {0}")]
    Flow(#[from] lattice_store::FlowStoreError),
}

pub struct DiscoveryPipeline {
    identity: IdentityEngine,
    presence: PresenceEngine,
    sources: DiscoverySources,
}

impl DiscoveryPipeline {
    pub fn new(ids: impl Iterator<Item = DeviceId> + Send) -> Result<Self, DiscoveryError> {
        Self::with_sources(
            ids,
            DiscoverySources::sensor(
                1,
                "sensor-a",
                vec![
                    lattice_domain::EvidenceFamily::LinkLayer,
                    lattice_domain::EvidenceFamily::Service,
                    lattice_domain::EvidenceFamily::Naming,
                ],
            )?,
        )
    }
    pub fn with_sources(
        ids: impl Iterator<Item = DeviceId> + Send,
        sources: DiscoverySources,
    ) -> Result<Self, DiscoveryError> {
        let trusted_sources = sources
            .0
            .values()
            .filter(|s| s.presence)
            .map(|s| s.name.clone())
            .collect();
        let pc = PresenceConfig {
            trusted_sources,
            ..PresenceConfig::default()
        };
        Ok(Self {
            identity: IdentityEngine::new(IdentityConfig::default(), ids)?,
            presence: PresenceEngine::new(pc)?,
            sources,
        })
    }

    fn stage(
        &self,
        input: DiscoveryObservation,
        arrival: DateTime<Utc>,
    ) -> Result<(IdentityEngine, PresenceEngine, DiscoveryResult), DiscoveryError> {
        let source = self
            .sources
            .0
            .get(&input.source_id)
            .ok_or(DiscoveryError::InvalidSource)?;
        if !source.presence
            || input.presence_source != source.name
            || input
                .facts
                .iter()
                .any(|f| f.source != source.name || !source.families.contains(&f.family))
        {
            return Err(DiscoveryError::InvalidSource);
        }
        let mut identity = self.identity.clone();
        let mut presence_engine = self.presence.clone();
        let id = identity.observe_at(input.candidate, input.facts, input.observed_at)?;
        let presence = presence_engine.ingest_events(
            PresenceEvidence {
                device_id: id,
                source: source.name.clone(),
                kind: input.presence_kind,
                observed_at: input.observed_at,
                valid_until: input.valid_until,
            },
            arrival,
        )?;
        let identification = identity.identification_at(id, input.observed_at)?;
        let events = presence
            .iter()
            .map(|t| EventPayload::PresenceChanged(PresenceChanged::from(t)))
            .collect();
        Ok((
            identity,
            presence_engine,
            DiscoveryResult {
                device_id: id,
                identification,
                presence,
                events,
            },
        ))
    }

    pub fn observe(
        &mut self,
        input: DiscoveryObservation,
        arrival: DateTime<Utc>,
    ) -> Result<DiscoveryResult, DiscoveryError> {
        let (identity, presence_engine, result) = self.stage(input, arrival)?;
        self.identity = identity;
        self.presence = presence_engine;
        Ok(result)
    }

    pub async fn observe_with_flow(
        &mut self,
        input: DiscoveryObservation,
        changes: &[RollupChange],
        tick_ms: u64,
        arrival: DateTime<Utc>,
        flow: &mut FlowIngestor,
    ) -> Result<(DiscoveryResult, Option<EventPayload>), DiscoveryError> {
        let (identity, presence_engine, result) = self.stage(input, arrival)?;
        if changes.iter().any(|c| match c {
            RollupChange::Upsert(r) | RollupChange::Correction(r) => {
                r.key.device_id != result.device_id
            }
            RollupChange::Retire(r) => r.key.device_id != result.device_id,
        }) {
            return Err(DiscoveryError::InvalidSource);
        }
        let payload = flow.apply(changes, tick_ms, arrival).await?;
        self.identity = identity;
        self.presence = presence_engine;
        Ok((result, payload))
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
