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
use lattice_store::{
    CheckpointError, CheckpointInput, CommitInput, DeviceProjection, DiscoveryCommit,
    EvidenceProjection, FlowIngestor, FlowRepository, M2StateRepository,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkPresenceKind {
    Present { valid_until: DateTime<Utc> },
    Missed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkPresenceObservation {
    pub source_id: u64,
    pub link_address: lattice_sensor::neighbor::LinkAddress,
    pub observed_at: DateTime<Utc>,
    pub kind: LinkPresenceKind,
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
    pub fn fingerprint(&self) -> String {
        let rows: Vec<String> = self
            .0
            .values()
            .map(|s| {
                let mut families: Vec<_> = s.families.iter().map(|f| format!("{f:?}")).collect();
                families.sort();
                format!(
                    "{}\0{}\0{}\0{}",
                    s.id,
                    s.name,
                    families.join(","),
                    s.presence
                )
            })
            .collect();
        Sha256::digest(
            format!(
                "discovery-pipeline-v1\0identity-default-v1\0presence-default-v1\0{}",
                rows.join("\n")
            )
            .as_bytes(),
        )
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
    }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryPipelineCheckpoint {
    pub version: u16,
    pub source_fingerprint: String,
    pub identity: lattice_intelligence::IdentityCheckpoint,
    pub presence: lattice_intelligence::presence::PresenceCheckpoint,
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
    #[error("presence: {0}")]
    Presence(#[from] PresenceError),
    #[error("invalid or unregistered discovery source")]
    InvalidSource,
    #[error("link presence has no registered binding")]
    UnboundLink,
    #[error("invalid discovery pipeline checkpoint")]
    InvalidCheckpoint,
    #[error("flow: {0}")]
    Flow(#[from] lattice_store::FlowStoreError),
    #[error("live bandwidth: {0}")]
    Live(#[from] lattice_sensor::live::LiveError),
    #[error("checkpoint: {0}")]
    Checkpoint(#[from] CheckpointError),
    #[error("checkpoint encoding: {0}")]
    CheckpointEncoding(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct DiscoveryPipeline {
    identity: IdentityEngine,
    presence: PresenceEngine,
    sources: DiscoverySources,
}

/// Durable, fail-closed discovery boundary. In-memory engines advance only after the same SQLite
/// transaction has accepted their checkpoint, projections, transitions, and flow rollups.
pub struct PersistentDiscoveryPipeline {
    pipeline: DiscoveryPipeline,
    live: lattice_sensor::live::FlowLiveAdapter,
    state: M2StateRepository,
    flow: FlowRepository,
    sequence: i64,
}

#[derive(Clone, Debug)]
pub struct CommittedDiscovery {
    pub result: DiscoveryResult,
    pub payload: Option<EventPayload>,
    pub commit_sequence: i64,
}
#[derive(Clone, Debug)]
pub struct DuplicateDiscovery {
    pub result_summary: Vec<u8>,
    pub resnapshot_required: bool,
}
#[derive(Clone, Debug)]
pub enum DiscoveryPipelineOutcome {
    Committed(Box<CommittedDiscovery>),
    Duplicate(DuplicateDiscovery),
}

impl PersistentDiscoveryPipeline {
    pub async fn open(
        state: M2StateRepository,
        sources: DiscoverySources,
        remaining_ids: impl Iterator<Item = DeviceId> + Send,
        live: lattice_sensor::live::LiveConfig,
        flow_max_batch: usize,
        max_live_rows: usize,
    ) -> Result<Self, DiscoveryError> {
        let fingerprint = sources.fingerprint();
        let (pipeline, sequence) = match state.load(&fingerprint).await? {
            Some(stored) => {
                let checkpoint: DiscoveryPipelineCheckpoint = serde_json::from_slice(&stored.bytes)
                    .map_err(|_| DiscoveryError::InvalidCheckpoint)?;
                (
                    DiscoveryPipeline::from_checkpoint(sources, checkpoint)?,
                    stored.commit_sequence,
                )
            }
            None => (DiscoveryPipeline::with_sources(remaining_ids, sources)?, 0),
        };
        let flow = state.flow_repository(flow_max_batch)?;
        Ok(Self {
            pipeline,
            live: lattice_sensor::live::FlowLiveAdapter::new(live, max_live_rows)?,
            state,
            flow,
            sequence,
        })
    }
    pub fn source_fingerprint(&self) -> String {
        self.pipeline.sources.fingerprint()
    }
    pub fn commit_sequence(&self) -> i64 {
        self.sequence
    }
    pub fn presence_state(&self, id: DeviceId) -> Option<lattice_domain::PresenceState> {
        self.pipeline.presence_state(id)
    }

    pub async fn observe_link_presence_with_flow(
        &mut self,
        observation: LinkPresenceObservation,
        changes: &[RollupChange],
        tick_ms: u64,
        arrival: DateTime<Utc>,
    ) -> Result<DiscoveryPipelineOutcome, DiscoveryError> {
        let source = self
            .pipeline
            .sources
            .0
            .get(&observation.source_id)
            .ok_or(DiscoveryError::InvalidSource)?;
        if !source.presence
            || !source
                .families
                .contains(&lattice_domain::EvidenceFamily::LinkLayer)
        {
            return Err(DiscoveryError::InvalidSource);
        }
        let binding = self
            .state
            .lookup_link_layer_device(observation.link_address, &source.name)
            .await?;
        let (candidate, facts, presence_kind, valid_until) = match observation.kind {
            LinkPresenceKind::Present { valid_until } => {
                if valid_until <= observation.observed_at
                    || observation.observed_at.timestamp_subsec_nanos() != 0
                    || valid_until.timestamp_subsec_nanos() != 0
                {
                    return Err(DiscoveryError::InvalidSource);
                }
                let facts = if binding.is_none() {
                    vec![EvidenceFact {
                        family: lattice_domain::EvidenceFamily::LinkLayer,
                        source: source.name.clone(),
                        key: "mac".into(),
                        value: observation.link_address.to_string(),
                        confidence: 0.9,
                        observed_at: observation.observed_at,
                        expires_at: None,
                        owner_confirmed: false,
                    }]
                } else {
                    Vec::new()
                };
                (
                    binding,
                    facts,
                    PresenceEvidenceKind::NeighborCache,
                    Some(valid_until),
                )
            }
            LinkPresenceKind::Missed => {
                if observation.observed_at.timestamp_subsec_nanos() != 0 {
                    return Err(DiscoveryError::InvalidSource);
                }
                let id = binding.ok_or(DiscoveryError::UnboundLink)?;
                (
                    Some(id),
                    Vec::new(),
                    PresenceEvidenceKind::ConfirmationFailure,
                    None,
                )
            }
        };
        self.observe_with_flow(
            DiscoveryObservation {
                source_id: observation.source_id,
                candidate,
                facts,
                presence_source: source.name.clone(),
                presence_kind,
                observed_at: observation.observed_at,
                valid_until,
            },
            changes,
            tick_ms,
            arrival,
        )
        .await
    }
    pub async fn observe_with_flow(
        &mut self,
        input: DiscoveryObservation,
        changes: &[RollupChange],
        tick_ms: u64,
        arrival: DateTime<Utc>,
    ) -> Result<DiscoveryPipelineOutcome, DiscoveryError> {
        let input_hash = semantic_input_hash(&input, changes)?;
        if let Some(existing) = self.state.discovery_commit(input_hash).await? {
            return Ok(DiscoveryPipelineOutcome::Duplicate(DuplicateDiscovery {
                result_summary: existing.result_summary,
                resnapshot_required: true,
            }));
        }
        let facts = input.facts.clone();
        let source_name = input.presence_source.clone();
        let mut staged_pipeline = self.pipeline.clone();
        let result = staged_pipeline.observe(input, arrival)?;
        if changes.iter().any(|c| match c {
            RollupChange::Upsert(r) | RollupChange::Correction(r) => {
                r.key.device_id != result.device_id
            }
            RollupChange::Retire(r) => r.key.device_id != result.device_id,
        }) {
            return Err(DiscoveryError::InvalidSource);
        }
        let (staged_live, payload) = self.live.staged_payload(tick_ms, changes, arrival)?;
        let next_sequence = self
            .sequence
            .checked_add(1)
            .ok_or(DiscoveryError::InvalidCheckpoint)?;
        let checkpoint = staged_pipeline.checkpoint();
        let checkpoint_bytes = serde_json::to_vec(&checkpoint)?;
        let transitions: Vec<_> = result.presence.iter().map(PresenceChanged::from).collect();
        let summary = serde_json::to_vec(&serde_json::json!({
            "version": 1, "device_id": result.device_id.to_string(), "commit_sequence": next_sequence,
            "event_count": result.events.len(), "presence_transition_count": transitions.len(),
        }))?;
        let commit = CommitInput {
            checkpoint: CheckpointInput {
                format_version: 1,
                bytes: checkpoint_bytes,
                source_fingerprint: checkpoint.source_fingerprint,
                commit_sequence: next_sequence,
                written_at: arrival,
            },
            devices: vec![DeviceProjection {
                device_id: result.device_id,
                first_seen_at: facts.iter().map(|f| f.observed_at).min().unwrap_or(arrival),
                last_seen_at: arrival,
                owner_name: None,
                owner_type: None,
                owner_confirmed: false,
            }],
            evidence: facts
                .into_iter()
                .map(|fact| EvidenceProjection {
                    device_id: result.device_id,
                    fact,
                })
                .collect(),
            transitions,
            discovery: Some(DiscoveryCommit {
                input_hash,
                source: source_name,
                result_summary: summary,
                committed_at: arrival,
            }),
        };
        if let Err(error) = self
            .state
            .commit_with_flow(commit, changes, arrival, &self.flow)
            .await
        {
            if matches!(error, CheckpointError::Conflict(_))
                && let Some(existing) = self.state.discovery_commit(input_hash).await?
            {
                return Ok(DiscoveryPipelineOutcome::Duplicate(DuplicateDiscovery {
                    result_summary: existing.result_summary,
                    resnapshot_required: true,
                }));
            }
            return Err(error.into());
        }
        self.pipeline = staged_pipeline;
        self.live = staged_live;
        self.sequence = next_sequence;
        Ok(DiscoveryPipelineOutcome::Committed(Box::new(
            CommittedDiscovery {
                result,
                payload,
                commit_sequence: next_sequence,
            },
        )))
    }
}

fn semantic_input_hash(
    input: &DiscoveryObservation,
    changes: &[RollupChange],
) -> Result<[u8; 32], DiscoveryError> {
    let mut facts: Vec<_> = input
        .facts
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    facts.sort_by_key(|value| serde_json::to_string(value).expect("JSON value serializes"));
    let mut flow: Vec<_> = changes
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    flow.sort_by_key(|value| serde_json::to_string(value).expect("JSON value serializes"));
    let canonical = serde_json::json!({"version":1,"source_id":input.source_id,"candidate":input.candidate.map(|id|id.to_string()),"facts":facts,"presence_source":input.presence_source,"presence_kind":input.presence_kind,"observed_at":input.observed_at,"valid_until":input.valid_until,"flow":flow});
    let hash = Sha256::digest(serde_json::to_vec(&canonical)?);
    Ok(hash.into())
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

    pub fn checkpoint(&self) -> DiscoveryPipelineCheckpoint {
        DiscoveryPipelineCheckpoint {
            version: 1,
            source_fingerprint: self.sources.fingerprint(),
            identity: self.identity.checkpoint(),
            presence: self.presence.checkpoint(),
        }
    }

    pub fn from_checkpoint(
        sources: DiscoverySources,
        c: DiscoveryPipelineCheckpoint,
    ) -> Result<Self, DiscoveryError> {
        if c.version != 1 || c.source_fingerprint != sources.fingerprint() {
            return Err(DiscoveryError::InvalidCheckpoint);
        }
        let trusted_sources = sources
            .0
            .values()
            .filter(|s| s.presence)
            .map(|s| s.name.clone())
            .collect();
        let config = PresenceConfig {
            trusted_sources,
            ..PresenceConfig::default()
        };
        Ok(Self {
            identity: IdentityEngine::from_checkpoint(IdentityConfig::default(), c.identity)?,
            presence: PresenceEngine::from_checkpoint(config, c.presence)?,
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
        if input.candidate.is_some() && !input.facts.is_empty() {
            return Err(DiscoveryError::InvalidSource);
        }
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
