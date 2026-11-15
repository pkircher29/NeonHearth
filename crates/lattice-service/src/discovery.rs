//! Service-owned boundary joining source-stamped evidence, identity, presence, and flow facts.
//! Sensors submit facts; this module is the only place that correlates them into app events.

use crate::{AppState, ServiceRuntimeStatus};
use chrono::{DateTime, TimeZone, Utc};
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

/// Service-owned policy for translating neighbor snapshots into durable presence facts.
#[derive(Clone, Debug)]
pub struct NeighborCoordinatorConfig {
    pub poll_interval: chrono::Duration,
    pub support_ttl: chrono::Duration,
    pub tracker: lattice_sensor::neighbor::NeighborTrackerConfig,
}
impl Default for NeighborCoordinatorConfig {
    fn default() -> Self {
        Self {
            poll_interval: chrono::Duration::seconds(5),
            support_ttl: chrono::Duration::seconds(4),
            tracker: Default::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum NeighborCoordinatorError {
    #[error("neighbor snapshot: {0}")]
    Snapshot(#[from] lattice_sensor::neighbor::NeighborError),
    #[error("discovery: {0}")]
    Discovery(#[from] DiscoveryError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NeighborInterfaceBinding {
    interface: lattice_sensor::InterfaceId,
    source_id: u64,
}
impl NeighborInterfaceBinding {
    const SOURCE_NAMESPACE: u64 = 0x4e45_4947;

    /// Creates the only supported neighbor-source binding for an interface.
    /// The source ID is namespaced and derived solely from the nonzero interface ID.
    pub fn for_interface(
        interface: lattice_sensor::InterfaceId,
    ) -> Result<Self, NeighborCoordinatorError> {
        if interface.get() == 0 {
            return Err(NeighborCoordinatorError::Snapshot(
                lattice_sensor::neighbor::NeighborError::InvalidConfig,
            ));
        }
        Ok(Self {
            interface,
            source_id: (Self::SOURCE_NAMESPACE << 32) | u64::from(interface.get()),
        })
    }
    pub fn interface(self) -> lattice_sensor::InterfaceId {
        self.interface
    }
    pub fn source_id(self) -> u64 {
        self.source_id
    }
    pub fn safe_name(self) -> String {
        format!("neighbor-interface-{}", self.interface.get())
    }
}

/// Produces the sole deterministic mapping from configured network interfaces to discovery
/// sources. Wiring must use this helper rather than inventing independently named sources.
pub fn neighbor_discovery_sources(
    bindings: &[NeighborInterfaceBinding],
) -> Result<DiscoverySources, DiscoveryError> {
    validate_neighbor_bindings(bindings).map_err(|_| DiscoveryError::InvalidSource)?;
    let mut ordered = bindings.to_vec();
    ordered.sort();
    DiscoverySources::new(
        ordered
            .into_iter()
            .map(|binding| DiscoverySource {
                id: binding.source_id(),
                name: binding.safe_name(),
                families: vec![lattice_domain::EvidenceFamily::LinkLayer],
                presence: true,
            })
            .collect(),
    )
}

fn validate_neighbor_bindings(
    bindings: &[NeighborInterfaceBinding],
) -> Result<(), NeighborCoordinatorError> {
    if bindings.is_empty()
        || bindings
            .iter()
            .any(|b| b.interface().get() == 0 || b.source_id() == 0)
        || bindings
            .iter()
            .map(|b| b.interface())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != bindings.len()
        || bindings
            .iter()
            .map(|b| b.source_id())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != bindings.len()
    {
        return Err(NeighborCoordinatorError::Snapshot(
            lattice_sensor::neighbor::NeighborError::InvalidConfig,
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct NeighborCycle {
    outcomes: Vec<DiscoveryPipelineOutcome>,
    commit_sequence: i64,
}
impl NeighborCycle {
    pub fn outcomes(&self) -> &[DiscoveryPipelineOutcome] {
        &self.outcomes
    }
    pub fn commit_sequence(&self) -> i64 {
        self.commit_sequence
    }
}

/// Coordinates one injected snapshot source. Failed snapshots are deliberately inert.
pub struct NeighborCoordinator<S, A = crate::policy::ManualRequiredActuator> {
    source: S,
    bindings: BTreeMap<lattice_sensor::InterfaceId, u64>,
    config: NeighborCoordinatorConfig,
    tracker: lattice_sensor::neighbor::NeighborTracker,
    pipeline: PersistentDiscoveryPipeline,
    state: AppState,
    policy: crate::policy::PolicyCoordinator<A>,
}
impl<S: lattice_sensor::neighbor::NeighborSnapshotSource>
    NeighborCoordinator<S, crate::policy::ManualRequiredActuator>
{
    pub fn new<I>(
        source: S,
        pipeline: PersistentDiscoveryPipeline,
        state: AppState,
        bindings: I,
        config: NeighborCoordinatorConfig,
    ) -> Result<Self, NeighborCoordinatorError>
    where
        I: IntoIterator<Item = NeighborInterfaceBinding>,
    {
        let bindings: Vec<_> = bindings.into_iter().collect();
        validate_neighbor_bindings(&bindings)?;
        let expected_sources = neighbor_discovery_sources(&bindings)?;
        if pipeline.source_fingerprint() != expected_sources.fingerprint() {
            return Err(NeighborCoordinatorError::Discovery(
                DiscoveryError::InvalidSource,
            ));
        }
        if config.poll_interval <= chrono::Duration::zero()
            || config.support_ttl <= chrono::Duration::zero()
            || config.support_ttl >= config.poll_interval
        {
            return Err(NeighborCoordinatorError::Snapshot(
                lattice_sensor::neighbor::NeighborError::InvalidConfig,
            ));
        }
        let policy_state = lattice_store::M2StateRepository::new(pipeline.state.pool().clone());
        let policy_repo = lattice_store::PolicyRepository::new(pipeline.state.pool().clone());
        let policy_events = state.events().clone();
        Self::with_policy(
            source,
            pipeline,
            state,
            bindings,
            config,
            crate::policy::PolicyCoordinator::with_state(
                policy_repo,
                Some(policy_events),
                policy_state,
            ),
        )
    }
}
impl<
    S: lattice_sensor::neighbor::NeighborSnapshotSource,
    A: crate::policy::PolicyActuator + 'static,
> NeighborCoordinator<S, A>
{
    pub fn with_policy<I>(
        source: S,
        pipeline: PersistentDiscoveryPipeline,
        state: AppState,
        bindings: I,
        config: NeighborCoordinatorConfig,
        policy: crate::policy::PolicyCoordinator<A>,
    ) -> Result<Self, NeighborCoordinatorError>
    where
        I: IntoIterator<Item = NeighborInterfaceBinding>,
    {
        let bindings: Vec<_> = bindings.into_iter().collect();
        validate_neighbor_bindings(&bindings)?;
        let expected_sources = neighbor_discovery_sources(&bindings)?;
        if pipeline.source_fingerprint() != expected_sources.fingerprint() {
            return Err(NeighborCoordinatorError::Discovery(
                DiscoveryError::InvalidSource,
            ));
        }
        if config.poll_interval <= chrono::Duration::zero()
            || config.support_ttl <= chrono::Duration::zero()
            || config.support_ttl >= config.poll_interval
        {
            return Err(NeighborCoordinatorError::Snapshot(
                lattice_sensor::neighbor::NeighborError::InvalidConfig,
            ));
        }
        Ok(Self {
            source,
            bindings: bindings
                .into_iter()
                .map(|binding| (binding.interface(), binding.source_id()))
                .collect(),
            tracker: lattice_sensor::neighbor::NeighborTracker::new(config.tracker.clone())?,
            pipeline,
            state,
            policy,
            config,
        })
    }
    async fn flush_and_publish(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<(), NeighborCoordinatorError> {
        let transitions = match self.pipeline.flush_refreshed(observed_at).await {
            Ok(transitions) => transitions,
            Err(error) => {
                self.state
                    .transition_service_status(ServiceRuntimeStatus::Degraded, observed_at)
                    .await;
                return Err(error.into());
            }
        };
        for transition in transitions {
            if !matches!(
                self.policy.control_blocks(transition.device_id).await,
                Ok(false)
            ) {
                continue;
            }
            self.state
                .events()
                .publish(
                    transition.occurred_at,
                    EventPayload::PresenceChanged(transition),
                )
                .await;
        }
        Ok(())
    }
    pub fn poll_interval(&self) -> chrono::Duration {
        self.config.poll_interval
    }
    pub fn support_ttl(&self) -> chrono::Duration {
        self.config.support_ttl
    }
    fn floor_second(t: DateTime<Utc>) -> DateTime<Utc> {
        Utc.timestamp_opt(t.timestamp(), 0)
            .single()
            .expect("UTC seconds are representable")
    }
    pub fn commit_sequence(&self) -> i64 {
        self.pipeline.commit_sequence()
    }
    pub fn pipeline(&self) -> &PersistentDiscoveryPipeline {
        &self.pipeline
    }
    pub async fn cycle(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<NeighborCycle, NeighborCoordinatorError> {
        let rows = match self.source.snapshot().await {
            Ok(rows) => rows,
            Err(error) => {
                self.state
                    .transition_service_status(
                        ServiceRuntimeStatus::Degraded,
                        Self::floor_second(now),
                    )
                    .await;
                return Err(error.into());
            }
        };
        let observed_at = Self::floor_second(now);
        let mut policy_degraded = false;
        let policy_enabled = match self.policy.enabled().await {
            Ok(enabled) => enabled,
            Err(error) => {
                policy_degraded = true;
                tracing::warn!("policy enabled-state lookup degraded: {error}");
                self.state
                    .transition_service_status(ServiceRuntimeStatus::Degraded, observed_at)
                    .await;
                false
            }
        };
        // A quiet network still needs policy progress: deadline warnings and
        // expiry actions are driven by the durable clock, not new sightings.
        if policy_enabled && let Err(error) = self.policy.sweep(observed_at).await {
            policy_degraded = true;
            tracing::warn!("policy runtime sweep degraded: {error}");
            self.state
                .transition_service_status(ServiceRuntimeStatus::Degraded, observed_at)
                .await;
        }
        let rows = rows
            .into_iter()
            .filter(|row| self.bindings.contains_key(&row.interface()))
            .collect();
        // A cycle may durably commit a prefix before a later observation fails. Keep the
        // tracker staged until every generated observation and its event publication succeeds;
        // then a retry starts from the pre-cycle snapshot and safely reconciles that prefix.
        let mut staged_tracker = self.tracker.clone();
        let events = match staged_tracker.observe(rows, observed_at) {
            Ok(events) => events,
            Err(error) => {
                self.state
                    .transition_service_status(ServiceRuntimeStatus::Degraded, observed_at)
                    .await;
                return Err(error.into());
            }
        };
        let mut out = Vec::new();
        for event in events {
            let (device, kind) = match event {
                lattice_sensor::neighbor::NeighborEvent::Appeared { device, .. }
                | lattice_sensor::neighbor::NeighborEvent::Confirmed { device, .. } => (
                    device,
                    LinkPresenceKind::Present {
                        valid_until: observed_at + self.config.support_ttl,
                    },
                ),
                lattice_sensor::neighbor::NeighborEvent::Missed { device, .. } => {
                    (device, LinkPresenceKind::Missed)
                }
                lattice_sensor::neighbor::NeighborEvent::Departed { .. } => continue,
            };
            let Some(source_id) = self.bindings.get(&device.interface()).copied() else {
                continue;
            };
            out.push(LinkPresenceObservation {
                source_id,
                link_address: device.link_address(),
                observed_at,
                kind,
            });
        }
        let mut outcomes = Vec::new();
        for observation in out {
            // Steady-state refreshes of an already-Online device are applied to the live
            // engine in memory. Only state changes reach the store (see
            // `refresh_link_presence`), so a quiet network costs no SQLite writes.
            // Unknown MACs are admitted at a bounded rate per interface and a miss for a
            // never-admitted device is ignored (it used to abort the whole cycle).
            match self.pipeline.admit_link_presence(&observation).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    self.state
                        .transition_service_status(ServiceRuntimeStatus::Degraded, observed_at)
                        .await;
                    return Err(error.into());
                }
            }
            match self.pipeline.refresh_link_presence(&observation).await {
                Ok(RefreshOutcome::Refreshed) => continue,
                Ok(RefreshOutcome::NeedsCommit) => {}
                Err(error) => {
                    self.state
                        .transition_service_status(ServiceRuntimeStatus::Degraded, observed_at)
                        .await;
                    return Err(error.into());
                }
            }
            // Transitions produced by earlier refreshes must reach the store before a
            // commit that checkpoints the engine they already changed.
            if self.pipeline.has_pending_transitions() {
                self.flush_and_publish(observed_at).await?;
            }
            let outcome = match self
                .pipeline
                .observe_link_presence_with_flow(observation, &[], 0, observation.observed_at)
                .await
            {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.state
                        .transition_service_status(ServiceRuntimeStatus::Degraded, observed_at)
                        .await;
                    return Err(error.into());
                }
            };
            // The pipeline returns only after the SQLite transaction commits; publishing here
            // therefore enforces durable-commit-before-event-publish.
            if let DiscoveryPipelineOutcome::Committed(ref committed) = outcome {
                if policy_enabled
                    && let Err(error) = self
                        .policy
                        .enroll_identification_and_evaluate(
                            committed.result.device_id,
                            committed.result.identification.as_ref(),
                            observed_at,
                        )
                        .await
                {
                    policy_degraded = true;
                    tracing::warn!(
                        "policy evaluation degraded after durable discovery commit: {error}"
                    );
                    self.state
                        .transition_service_status(ServiceRuntimeStatus::Degraded, observed_at)
                        .await;
                }
                for payload in &committed.result.events {
                    if let EventPayload::PresenceChanged(change) = payload {
                        match self.policy.control_blocks(change.device_id).await {
                            Ok(true) => continue,
                            Ok(false) => {}
                            Err(error) => {
                                policy_degraded = true;
                                tracing::warn!(
                                    "policy control-state lookup degraded before presence publication: {error}"
                                );
                                self.state
                                    .transition_service_status(
                                        ServiceRuntimeStatus::Degraded,
                                        observed_at,
                                    )
                                    .await;
                                // Fail closed: do not publish a discovery state
                                // that might contradict an active control block.
                                continue;
                            }
                        }
                    }
                    self.state
                        .events()
                        .publish(payload_occurred_at(payload, observed_at), payload.clone())
                        .await;
                }
                if let Some(payload) = committed.payload.clone() {
                    self.state
                        .events()
                        .publish(payload_occurred_at(&payload, observed_at), payload)
                        .await;
                }
            } else if let DiscoveryPipelineOutcome::Duplicate(ref duplicate) = outcome
                && let Ok(summary) =
                    serde_json::from_slice::<serde_json::Value>(&duplicate.result_summary)
                && let Some(device) = summary.get("device_id").and_then(serde_json::Value::as_str)
                && let Ok(device) = DeviceId::parse(device)
                && self.policy.needs_recovery(device).await.unwrap_or(false)
                && let Err(error) = self.policy.enroll_and_evaluate(device, observed_at).await
            {
                policy_degraded = true;
                tracing::warn!(
                    "policy recovery degraded after duplicate durable discovery: {error}"
                );
                self.state
                    .transition_service_status(ServiceRuntimeStatus::Degraded, observed_at)
                    .await;
            }
            outcomes.push(outcome);
        }
        self.flush_and_publish(observed_at).await?;
        self.tracker = staged_tracker;
        if !policy_degraded {
            self.state
                .transition_service_status(ServiceRuntimeStatus::Ready, observed_at)
                .await;
        }
        Ok(NeighborCycle {
            outcomes,
            commit_sequence: self.pipeline.commit_sequence(),
        })
    }
}

fn payload_occurred_at(payload: &EventPayload, fallback: DateTime<Utc>) -> DateTime<Utc> {
    match payload {
        EventPayload::PresenceChanged(change) => change.occurred_at,
        EventPayload::BandwidthFrame(frame) => frame.emitted_at,
        EventPayload::ServiceStatus(_) => fallback,
        EventPayload::PolicyChanged(_) => fallback,
        EventPayload::HomeChanged(_) => fallback,
    }
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum LinkPresenceKind {
    Present { valid_until: DateTime<Utc> },
    Missed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LinkPresenceObservation {
    pub source_id: u64,
    pub link_address: lattice_sensor::neighbor::LinkAddress,
    pub observed_at: DateTime<Utc>,
    pub kind: LinkPresenceKind,
}

impl std::fmt::Debug for LinkPresenceObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkPresenceObservation")
            .field("source_id", &self.source_id)
            .field("link_address", &"[redacted]")
            .field("observed_at", &self.observed_at)
            .field("kind", &self.kind)
            .finish()
    }
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
    /// (source id, link address) -> device, valid until the next commit.
    bound: std::collections::HashMap<(u64, lattice_sensor::neighbor::LinkAddress), DeviceId>,
    /// Transitions produced by in-memory refreshes that still need persisting.
    pending_transitions: Vec<PresenceTransition>,
    refreshed_since_persist: bool,
    last_persist_at: Option<DateTime<Utc>>,
    serializations: u64,
    /// Admission times of recently created identities, per source.
    new_identities: BTreeMap<u64, std::collections::VecDeque<DateTime<Utc>>>,
}

/// New device identities allowed per interface source per [`IDENTITY_WINDOW`]. A neighbor
/// flood (spoofed or randomized MACs) is cut off here instead of growing the device table
/// without bound.
const MAX_NEW_IDENTITIES_PER_WINDOW: usize = 256;
const IDENTITY_WINDOW: chrono::Duration = chrono::Duration::minutes(10);

/// Outcome of [`PersistentDiscoveryPipeline::refresh_link_presence`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshOutcome {
    /// Applied to the live engine; nothing durable changed.
    Refreshed,
    /// Not a steady-state refresh; the caller must use the full commit path.
    NeedsCommit,
}

/// Longest an in-memory presence refresh may stay unpersisted. After a crash the engine
/// resumes from the last checkpoint; every device then re-`Appeared`s in the fresh tracker and
/// is recommitted, so this only bounds how stale the restored evidence TTLs are.
const REFRESH_CHECKPOINT_INTERVAL: chrono::Duration = chrono::Duration::minutes(5);

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
        let mut migrated = false;
        let (pipeline, sequence) = match state.load(&fingerprint).await {
            Ok(Some(stored)) => {
                let checkpoint: DiscoveryPipelineCheckpoint = serde_json::from_slice(&stored.bytes)
                    .map_err(|_| DiscoveryError::InvalidCheckpoint)?;
                (
                    DiscoveryPipeline::from_checkpoint(sources, checkpoint)?,
                    stored.commit_sequence,
                )
            }
            Ok(None) => (DiscoveryPipeline::with_sources(remaining_ids, sources)?, 0),
            // The set of observed interfaces changed since the checkpoint was written. That is
            // normal (cable unplugged, Wi-Fi toggled), so carry the state forward instead of
            // refusing to start.
            Err(error) if error.to_string().contains("source fingerprint mismatch") => {
                migrated = true;
                migrate_checkpoint(&state, sources).await?
            }
            Err(error) => return Err(error.into()),
        };
        let flow = state.flow_repository(flow_max_batch)?;
        Ok(Self {
            pipeline,
            live: lattice_sensor::live::FlowLiveAdapter::new(live, max_live_rows)?,
            state,
            flow,
            sequence,
            bound: Default::default(),
            pending_transitions: Vec::new(),
            // A migrated checkpoint is rewritten under the new source set by the first flush.
            refreshed_since_persist: migrated,
            last_persist_at: None,
            serializations: 0,
            new_identities: BTreeMap::new(),
        })
    }
    /// Decides whether an observation may reach the commit path. Known devices always pass.
    /// New MACs are rate limited per source; a `Missed` event for a device that was never
    /// admitted is dropped.
    pub async fn admit_link_presence(
        &mut self,
        observation: &LinkPresenceObservation,
    ) -> Result<bool, DiscoveryError> {
        let Some(source_name) = self
            .pipeline
            .sources
            .0
            .get(&observation.source_id)
            .map(|s| s.name.clone())
        else {
            // Unregistered source: the full path reports the error.
            return Ok(true);
        };
        let key = (observation.source_id, observation.link_address);
        let bound = match self.bound.get(&key) {
            Some(id) => Some(*id),
            None => {
                let found = self
                    .state
                    .lookup_link_layer_device(observation.link_address, &source_name)
                    .await?;
                if let Some(id) = found {
                    self.bound.insert(key, id);
                }
                found
            }
        };
        if bound.is_some() {
            return Ok(true);
        }
        if matches!(observation.kind, LinkPresenceKind::Missed) {
            return Ok(false);
        }
        let log = self
            .new_identities
            .entry(observation.source_id)
            .or_default();
        while log
            .front()
            .is_some_and(|at| observation.observed_at - *at >= IDENTITY_WINDOW)
        {
            log.pop_front();
        }
        if log.len() >= MAX_NEW_IDENTITIES_PER_WINDOW {
            return Ok(false);
        }
        log.push_back(observation.observed_at);
        Ok(true)
    }
    /// Evaluates devices whose only evidence came from sources that are no longer observed
    /// (an interface that went away between runs), so they do not stay Online forever. The
    /// resulting transitions are persisted by the next [`Self::flush_refreshed`].
    pub fn reconcile_orphans(&mut self, now: DateTime<Utc>) {
        let current: std::collections::BTreeSet<&str> = self
            .pipeline
            .sources
            .0
            .values()
            .map(|s| s.name.as_str())
            .collect();
        let orphans: Vec<DeviceId> = self
            .pipeline
            .presence
            .checkpoint()
            .devices
            .into_iter()
            .filter(|d| {
                matches!(
                    d.state,
                    lattice_domain::PresenceState::Online | lattice_domain::PresenceState::Quiet
                ) && !d.evidence.is_empty()
                    && d.evidence
                        .iter()
                        .all(|e| !current.contains(e.source.as_str()))
            })
            .map(|d| d.device_id)
            .collect();
        for id in orphans {
            if let Ok(Some(transition)) = self.pipeline.presence.evaluate(id, now) {
                self.pending_transitions.push(transition);
            }
        }
    }
    /// Number of full checkpoint serializations performed since the pipeline opened.
    pub fn checkpoint_serializations(&self) -> u64 {
        self.serializations
    }
    pub fn has_pending_transitions(&self) -> bool {
        !self.pending_transitions.is_empty()
    }
    /// Applies a steady-state `Present` refresh for a device that is already `Online` to the
    /// live presence engine without touching the store. Anything else (unknown MAC, device not
    /// yet Online, validation problems) is left to the full commit path.
    pub async fn refresh_link_presence(
        &mut self,
        observation: &LinkPresenceObservation,
    ) -> Result<RefreshOutcome, DiscoveryError> {
        let LinkPresenceKind::Present { valid_until } = observation.kind else {
            return Ok(RefreshOutcome::NeedsCommit);
        };
        if observation.observed_at.timestamp_subsec_nanos() != 0
            || valid_until <= observation.observed_at
            || valid_until.timestamp_subsec_nanos() != 0
        {
            return Ok(RefreshOutcome::NeedsCommit);
        }
        let Some(source_name) = self
            .pipeline
            .sources
            .0
            .get(&observation.source_id)
            .filter(|s| {
                s.presence
                    && s.families
                        .contains(&lattice_domain::EvidenceFamily::LinkLayer)
            })
            .map(|s| s.name.clone())
        else {
            return Ok(RefreshOutcome::NeedsCommit);
        };
        let key = (observation.source_id, observation.link_address);
        let id = match self.bound.get(&key) {
            Some(id) => *id,
            None => match self
                .state
                .lookup_link_layer_device(observation.link_address, &source_name)
                .await?
            {
                Some(id) => {
                    self.bound.insert(key, id);
                    id
                }
                None => return Ok(RefreshOutcome::NeedsCommit),
            },
        };
        if self.pipeline.presence.state(id) != Some(lattice_domain::PresenceState::Online) {
            return Ok(RefreshOutcome::NeedsCommit);
        }
        match self.pipeline.presence.ingest_events(
            PresenceEvidence {
                device_id: id,
                source: source_name,
                kind: PresenceEvidenceKind::NeighborCache,
                observed_at: observation.observed_at,
                valid_until: Some(valid_until),
            },
            observation.observed_at,
        ) {
            Ok(transitions) => {
                self.refreshed_since_persist = true;
                self.pending_transitions.extend(transitions);
                Ok(RefreshOutcome::Refreshed)
            }
            Err(_) => Ok(RefreshOutcome::NeedsCommit),
        }
    }
    /// Persists in-memory refreshes: immediately when they produced transitions, otherwise at
    /// most once per [`REFRESH_CHECKPOINT_INTERVAL`]. One commit covers the whole cycle.
    pub async fn flush_refreshed(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<Vec<PresenceChanged>, DiscoveryError> {
        let due = self.refreshed_since_persist
            && self
                .last_persist_at
                .is_none_or(|at| now - at >= REFRESH_CHECKPOINT_INTERVAL);
        if self.pending_transitions.is_empty() && !due {
            return Ok(Vec::new());
        }
        let next_sequence = self
            .sequence
            .checked_add(1)
            .ok_or(DiscoveryError::InvalidCheckpoint)?;
        let checkpoint = self.pipeline.checkpoint();
        let checkpoint_bytes = serde_json::to_vec(&checkpoint)?;
        self.serializations += 1;
        let transitions: Vec<_> = self
            .pending_transitions
            .iter()
            .map(PresenceChanged::from)
            .collect();
        let commit = CommitInput {
            checkpoint: CheckpointInput {
                format_version: 1,
                bytes: checkpoint_bytes,
                source_fingerprint: checkpoint.source_fingerprint,
                commit_sequence: next_sequence,
                written_at: now,
            },
            devices: Vec::new(),
            evidence: Vec::new(),
            transitions: transitions.clone(),
            discovery: None,
        };
        self.state
            .commit_with_flow(commit, &[], now, &self.flow)
            .await?;
        self.sequence = next_sequence;
        self.pending_transitions.clear();
        self.refreshed_since_persist = false;
        self.last_persist_at = Some(now);
        Ok(transitions)
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
        if observation.observed_at.timestamp_subsec_nanos() != 0
            || arrival.timestamp_subsec_nanos() != 0
            || arrival < observation.observed_at
            || matches!(observation.kind, LinkPresenceKind::Present { valid_until }
                if valid_until <= observation.observed_at || valid_until.timestamp_subsec_nanos() != 0)
        {
            return Err(DiscoveryError::InvalidSource);
        }
        let source_name = self
            .pipeline
            .sources
            .0
            .get(&observation.source_id)
            .filter(|source| {
                source.presence
                    && source
                        .families
                        .contains(&lattice_domain::EvidenceFamily::LinkLayer)
            })
            .map(|source| source.name.clone())
            .ok_or(DiscoveryError::InvalidSource)?;
        let input_hash = link_presence_input_hash(&observation, &source_name, changes)?;
        if let Some(existing) = self.state.discovery_commit(input_hash).await? {
            return Ok(DiscoveryPipelineOutcome::Duplicate(DuplicateDiscovery {
                result_summary: existing.result_summary,
                resnapshot_required: true,
            }));
        }
        let binding = self
            .state
            .lookup_link_layer_device(observation.link_address, &source_name)
            .await?;
        let (candidate, facts, presence_kind, valid_until) = match observation.kind {
            LinkPresenceKind::Present { valid_until } => {
                let facts = if binding.is_none() {
                    vec![EvidenceFact {
                        family: lattice_domain::EvidenceFamily::LinkLayer,
                        source: source_name.clone(),
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
                let id = binding.ok_or(DiscoveryError::UnboundLink)?;
                (
                    Some(id),
                    Vec::new(),
                    PresenceEvidenceKind::ConfirmationFailure,
                    None,
                )
            }
        };
        self.observe_with_flow_hashed(
            DiscoveryObservation {
                source_id: observation.source_id,
                candidate,
                facts,
                presence_source: source_name,
                presence_kind,
                observed_at: observation.observed_at,
                valid_until,
            },
            changes,
            tick_ms,
            arrival,
            input_hash,
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
        self.observe_with_flow_hashed(input, changes, tick_ms, arrival, input_hash)
            .await
    }
    async fn observe_with_flow_hashed(
        &mut self,
        input: DiscoveryObservation,
        changes: &[RollupChange],
        tick_ms: u64,
        arrival: DateTime<Utc>,
        input_hash: [u8; 32],
    ) -> Result<DiscoveryPipelineOutcome, DiscoveryError> {
        if let Some(existing) = self.state.discovery_commit(input_hash).await? {
            return Ok(DiscoveryPipelineOutcome::Duplicate(DuplicateDiscovery {
                result_summary: existing.result_summary,
                resnapshot_required: true,
            }));
        }
        let facts = input.facts.clone();
        let source_name = input.presence_source.clone();
        // stage already clones identity and presence for rollback. Reuse those
        // staged engines instead of cloning the entire pipeline a second time.
        let (identity, presence, result) = self.pipeline.stage(input, arrival)?;
        let staged_pipeline = DiscoveryPipeline {
            identity,
            presence,
            sources: self.pipeline.sources.clone(),
        };
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
        self.serializations += 1;
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
        // The staged engines were cloned from the live ones, so this checkpoint already
        // contains every in-memory refresh.
        self.bound.clear();
        self.refreshed_since_persist = false;
        self.last_persist_at = Some(arrival);
        Ok(DiscoveryPipelineOutcome::Committed(Box::new(
            CommittedDiscovery {
                result,
                payload,
                commit_sequence: next_sequence,
            },
        )))
    }
}

/// Loads the stored checkpoint whatever source set it was written under, keeps a copy of its
/// bytes in `state_checkpoint_backups`, and rebuilds the engines for `sources`. Presence
/// evidence recorded under sources that are no longer observed stays trusted so the engine
/// accepts it; device identities and presence history carry over unchanged.
async fn migrate_checkpoint(
    state: &M2StateRepository,
    sources: DiscoverySources,
) -> Result<(DiscoveryPipeline, i64), DiscoveryError> {
    let stored_fingerprint: String =
        sqlx::query_scalar("SELECT source_fingerprint FROM state_checkpoints WHERE singleton=1")
            .fetch_one(state.pool())
            .await
            .map_err(|_| DiscoveryError::InvalidCheckpoint)?;
    let stored = state
        .load(&stored_fingerprint)
        .await?
        .ok_or(DiscoveryError::InvalidCheckpoint)?;
    let mut checkpoint: DiscoveryPipelineCheckpoint =
        serde_json::from_slice(&stored.bytes).map_err(|_| DiscoveryError::InvalidCheckpoint)?;
    sqlx::query("INSERT INTO state_checkpoint_backups(saved_at,source_fingerprint,commit_sequence,checkpoint_bytes) VALUES(?,?,?,?)")
        .bind(Utc::now().to_rfc3339())
        .bind(&stored_fingerprint)
        .bind(stored.commit_sequence)
        .bind(&stored.bytes)
        .execute(state.pool())
        .await
        .map_err(|_| DiscoveryError::InvalidCheckpoint)?;
    // Keep only the newest few copies.
    let _ = sqlx::query("DELETE FROM state_checkpoint_backups WHERE id NOT IN (SELECT id FROM state_checkpoint_backups ORDER BY id DESC LIMIT 8)")
        .execute(state.pool())
        .await;
    tracing::warn!(
        commit_sequence = stored.commit_sequence,
        "discovery interface set changed; checkpoint backed up and migrated"
    );
    checkpoint.source_fingerprint = sources.fingerprint();
    let pipeline = DiscoveryPipeline::from_checkpoint(sources, checkpoint)?;
    Ok((pipeline, stored.commit_sequence))
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

fn link_presence_input_hash(
    observation: &LinkPresenceObservation,
    source_name: &str,
    changes: &[RollupChange],
) -> Result<[u8; 32], DiscoveryError> {
    let mut flow: Vec<_> = changes
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    flow.sort_by_key(|value| serde_json::to_string(value).expect("JSON value serializes"));
    let canonical = serde_json::json!({
        "version": 1,
        "kind": "link_presence",
        "source_id": observation.source_id,
        "source": source_name,
        "link_address": observation.link_address.to_string(),
        "observed_at": observation.observed_at,
        "presence_kind": observation.kind,
        "flow": flow,
    });
    Ok(Sha256::digest(serde_json::to_vec(&canonical)?).into())
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
        // Evidence recorded under an interface that is not observed this run must still load.
        let mut extra: Vec<String> = Vec::new();
        for device in &c.presence.devices {
            extra.extend(device.evidence.iter().map(|e| e.source.clone()));
            extra.extend(device.history.iter().map(|t| t.trigger.source.clone()));
        }
        extra.sort();
        extra.dedup();
        Self::from_checkpoint_with_extra_sources(sources, c, extra)
    }

    /// As [`Self::from_checkpoint`], additionally trusting `extra` source names that appear in
    /// the checkpoint's recorded evidence (sources from a previous interface set).
    pub fn from_checkpoint_with_extra_sources(
        sources: DiscoverySources,
        c: DiscoveryPipelineCheckpoint,
        extra: Vec<String>,
    ) -> Result<Self, DiscoveryError> {
        if c.version != 1 || c.source_fingerprint != sources.fingerprint() {
            return Err(DiscoveryError::InvalidCheckpoint);
        }
        let mut trusted_sources: Vec<String> = sources
            .0
            .values()
            .filter(|s| s.presence)
            .map(|s| s.name.clone())
            .collect();
        for name in extra {
            if !trusted_sources.contains(&name) {
                trusted_sources.push(name);
            }
        }
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
