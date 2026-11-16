use crate::auth::Principal;
use chrono::Utc;
use lattice_domain::{EventPayload, ServiceStatus};
use lattice_event_bus::EventBus;
use lattice_store::M2StateRepository;
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, broadcast},
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRuntimeStatus {
    Ready,
    Degraded,
}
impl ServiceRuntimeStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
        }
    }
    fn detail(self) -> &'static str {
        match self {
            Self::Ready => "neighbor discovery recovered",
            Self::Degraded => "neighbor discovery unavailable",
        }
    }
}

pub(crate) const EVENT_TICKET_TTL: Duration = Duration::from_secs(30);
pub(crate) const MAX_OUTSTANDING_EVENT_TICKETS: usize = 64;
/// One phone session may hold this many unredeemed tickets.
pub(crate) const MAX_TICKETS_PER_PHONE: usize = 8;
/// Slots of the global cap that phone sessions can never occupy, so the
/// owner UI can always get a ticket.
pub(crate) const OWNER_RESERVED_TICKETS: usize = 8;
/// Concurrent event WebSockets the service will serve.
pub(crate) const MAX_EVENT_SOCKETS: usize = 32;

/// Timing bounds on an event WebSocket. Production uses [`Default`]; tests
/// shrink them through [`AppState::with_socket_limits`].
#[derive(Clone, Copy, Debug)]
pub struct SocketLimits {
    /// Server ping cadence.
    pub ping_interval: Duration,
    /// A socket that sends nothing (not even a pong) this long is closed.
    pub idle_timeout: Duration,
    /// Hard cap on one socket's lifetime; clients reconnect and resume.
    pub max_lifetime: Duration,
    /// How often a phone socket re-validates its session against storage.
    pub session_recheck: Duration,
    /// A write that cannot complete in this long closes the socket.
    pub send_timeout: Duration,
}

impl Default for SocketLimits {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(60 * 60),
            session_recheck: Duration::from_secs(30),
            send_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TicketLimitReached;
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InvalidServiceToken;
impl fmt::Display for InvalidServiceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid service token configuration")
    }
}
impl std::error::Error for InvalidServiceToken {}

fn validate_token(token: &str) -> Result<(), InvalidServiceToken> {
    let distinct = token.bytes().collect::<BTreeSet<_>>().len();
    if token.len() < 32
        || distinct < 8
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(InvalidServiceToken);
    }
    Ok(())
}

struct TicketRecord {
    expires_at: Instant,
    principal: Principal,
}

#[derive(Clone)]
pub struct AppState {
    network_monitor: crate::network_monitor::NetworkMonitor,
    host_monitor: crate::host_monitor::HostMonitor,
    scans: crate::network_scan::ScanHub,
    automation: crate::automation::AutomationHub,
    token: Arc<RwLock<SecretString>>,
    token_file: Option<PathBuf>,
    events: EventBus,
    state_repository: M2StateRepository,
    event_tickets: Arc<Mutex<HashMap<String, TicketRecord>>>,
    sockets: Arc<Semaphore>,
    socket_limits: SocketLimits,
    revocations: broadcast::Sender<Uuid>,
    host_policy: crate::security::HostPolicy,
    failed_tasks: Arc<std::sync::Mutex<BTreeSet<&'static str>>>,
    // This lock spans both the state transition and event publication.  No observer can
    // observe a changed status without its corresponding transition event being queued.
    service_status: Arc<Mutex<ServiceRuntimeStatus>>,
    camera_sessions: Option<Arc<crate::cameras::CameraSessionManager>>,
    camera_media: crate::cameras::production::CameraMediaStatus,
    camera_onboarding: Option<Arc<crate::cameras::onboarding::CameraOnboarding>>,
    worker_control: crate::runtime::WorkerControl,
}
impl AppState {
    pub fn new(
        token: impl Into<String>,
        state_repository: M2StateRepository,
    ) -> Result<Self, InvalidServiceToken> {
        let token = token.into();
        validate_token(&token)?;
        Ok(Self {
            network_monitor: crate::network_monitor::NetworkMonitor::new(
                state_repository.pool().clone(),
            ),
            host_monitor: crate::host_monitor::HostMonitor::new(state_repository.pool().clone()),
            scans: crate::network_scan::ScanHub::new(state_repository.pool().clone()),
            automation: crate::automation::AutomationHub::new(state_repository.pool().clone()),
            token: Arc::new(RwLock::new(SecretString::from(token))),
            token_file: None,
            events: EventBus::new(4096, 1024),
            state_repository,
            event_tickets: Arc::new(Mutex::new(HashMap::new())),
            sockets: Arc::new(Semaphore::new(MAX_EVENT_SOCKETS)),
            socket_limits: SocketLimits::default(),
            revocations: broadcast::channel(64).0,
            host_policy: crate::security::HostPolicy::default(),
            failed_tasks: Arc::new(std::sync::Mutex::new(BTreeSet::new())),
            service_status: Arc::new(Mutex::new(ServiceRuntimeStatus::Ready)),
            camera_sessions: None,
            camera_media: crate::cameras::production::CameraMediaStatus::not_configured(),
            camera_onboarding: None,
            worker_control: crate::runtime::WorkerControl::new(),
        })
    }
    /// Installs the part that adds and removes cameras and reports that a
    /// camera can be added.
    #[must_use]
    pub fn with_camera_onboarding(
        mut self,
        onboarding: Arc<crate::cameras::onboarding::CameraOnboarding>,
    ) -> Self {
        self.camera_onboarding = Some(onboarding);
        self.camera_media = crate::cameras::production::CameraMediaStatus::ready(
            "Camera media and camera setup were supplied by the host process.",
        );
        self
    }
    /// The handle the Doctor uses to restart the discovery worker in place.
    pub fn worker_control(&self) -> &crate::runtime::WorkerControl {
        &self.worker_control
    }
    #[must_use]
    pub fn with_camera_sessions(
        mut self,
        camera_sessions: Arc<crate::cameras::CameraSessionManager>,
    ) -> Self {
        camera_sessions.start_background_reaper();
        self.camera_sessions = Some(camera_sessions);
        self.camera_media = crate::cameras::production::CameraMediaStatus::injected();
        self
    }
    /// Installs the outcome of the production camera media startup: the
    /// session manager when every prerequisite held, and in every case the
    /// status the routes report (the specific reason when it did not).
    #[must_use]
    pub fn with_camera_media(
        mut self,
        build: crate::cameras::production::CameraMediaBuild,
    ) -> Self {
        let status = build.status;
        self = match build.manager {
            Some(manager) => self.with_camera_sessions(manager),
            None => self,
        };
        self.camera_onboarding = build.onboarding;
        self.camera_media = status;
        self
    }
    pub(crate) fn camera_onboarding(
        &self,
    ) -> Option<&Arc<crate::cameras::onboarding::CameraOnboarding>> {
        self.camera_onboarding.as_ref()
    }
    pub(crate) fn camera_media_status(&self) -> &crate::cameras::production::CameraMediaStatus {
        &self.camera_media
    }
    /// Overrides the WebSocket timing bounds (tests; production keeps the defaults).
    #[must_use]
    pub fn with_socket_limits(mut self, limits: SocketLimits) -> Self {
        self.socket_limits = limits;
        self
    }
    /// Where a rotated owner token is persisted (and read back at startup).
    #[must_use]
    pub fn with_token_file(mut self, path: PathBuf) -> Self {
        self.token_file = Some(path);
        self
    }
    /// Records the loopback port the listener is actually bound to. The Serve
    /// mapping, the funnel checks and the Host allowlist all derive from it.
    pub fn set_bound_port(&self, port: u16) {
        self.host_policy.set_port(port);
    }
    pub fn bound_port(&self) -> u16 {
        self.host_policy.port()
    }
    pub(crate) fn host_policy(&self) -> &crate::security::HostPolicy {
        &self.host_policy
    }
    pub(crate) fn socket_limits(&self) -> SocketLimits {
        self.socket_limits
    }
    pub(crate) fn camera_sessions(&self) -> Option<&Arc<crate::cameras::CameraSessionManager>> {
        self.camera_sessions.as_ref()
    }
    pub fn events(&self) -> &EventBus {
        &self.events
    }
    pub fn host_monitor(&self) -> &crate::host_monitor::HostMonitor {
        &self.host_monitor
    }
    pub fn network_monitor(&self) -> &crate::network_monitor::NetworkMonitor {
        &self.network_monitor
    }
    pub fn automation(&self) -> &crate::automation::AutomationHub {
        &self.automation
    }
    pub fn scans(&self) -> &crate::network_scan::ScanHub {
        &self.scans
    }
    pub async fn service_status(&self) -> String {
        self.service_status.lock().await.as_str().to_owned()
    }

    fn failed_task_summary(&self) -> Option<String> {
        let failed = self
            .failed_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (!failed.is_empty()).then(|| {
            format!(
                "background task failed: {}",
                failed.iter().copied().collect::<Vec<_>>().join(", ")
            )
        })
    }

    /// Marks a supervised background task as dead and degrades the service
    /// status (visible in `/state` and the event stream). The degradation
    /// persists until restart: a later "ready" transition cannot hide it.
    pub async fn report_task_failure(&self, task: &'static str) {
        self.failed_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(task);
        tracing::error!(task, "background task stopped; service degraded");
        self.transition_service_status(ServiceRuntimeStatus::Degraded, Utc::now())
            .await;
    }

    pub async fn transition_service_status(
        &self,
        status: ServiceRuntimeStatus,
        occurred_at: chrono::DateTime<Utc>,
    ) {
        let failed = self.failed_task_summary();
        let status = if failed.is_some() {
            ServiceRuntimeStatus::Degraded
        } else {
            status
        };
        let mut current = self.service_status.lock().await;
        if *current == status {
            return;
        }
        *current = status;
        self.events
            .publish(
                occurred_at,
                EventPayload::ServiceStatus(ServiceStatus {
                    state: status.as_str().to_owned(),
                    detail: failed.unwrap_or_else(|| status.detail().to_owned()),
                }),
            )
            .await;
    }
    pub(crate) fn state_repository(&self) -> &M2StateRepository {
        &self.state_repository
    }
    pub(crate) fn token_matches(&self, supplied: &str) -> bool {
        let token = self
            .token
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        supplied
            .as_bytes()
            .ct_eq(token.expose_secret().as_bytes())
            .into()
    }

    /// Replaces the owner token in memory, and on disk when a token file is
    /// configured (so the new token survives a restart). The old token stops
    /// working immediately.
    pub(crate) fn rotate_token(&self, new: String) -> Result<(), InvalidServiceToken> {
        validate_token(&new)?;
        if let Some(path) = &self.token_file {
            crate::vault::write_private_atomically(path, new.as_bytes())
                .map_err(|_| InvalidServiceToken)?;
        }
        *self
            .token
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = SecretString::from(new);
        Ok(())
    }

    /// Admits one more event WebSocket, or `None` at the cap.
    pub(crate) fn try_acquire_socket(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.sockets).try_acquire_owned().ok()
    }

    /// Announces that a phone session was revoked so live sockets can close.
    pub(crate) fn announce_session_revoked(&self, session: Uuid) {
        // No receivers simply means no live sockets.
        let _ = self.revocations.send(session);
    }
    pub(crate) fn subscribe_revocations(&self) -> broadcast::Receiver<Uuid> {
        self.revocations.subscribe()
    }

    pub(crate) async fn issue_event_ticket(
        &self,
        now: Instant,
        principal: Principal,
    ) -> Result<String, TicketLimitReached> {
        let mut tickets = self.event_tickets.lock().await;
        tickets.retain(|_, record| record.expires_at >= now);
        let refused = tickets.len() >= MAX_OUTSTANDING_EVENT_TICKETS
            || match principal {
                // The owner is bound only by the global cap (the documented
                // contract: 64 outstanding tickets).
                Principal::Owner => false,
                // A phone session holds a few, and phones together never take
                // the slots reserved for the owner.
                Principal::Phone(_) => {
                    let phone_held = tickets
                        .values()
                        .filter(|record| record.principal != Principal::Owner)
                        .count();
                    let own = tickets
                        .values()
                        .filter(|record| record.principal == principal)
                        .count();
                    own >= MAX_TICKETS_PER_PHONE
                        || phone_held >= MAX_OUTSTANDING_EVENT_TICKETS - OWNER_RESERVED_TICKETS
                }
            };
        if refused {
            return Err(TicketLimitReached);
        }
        let ticket = Uuid::new_v4().to_string();
        tickets.insert(
            ticket.clone(),
            TicketRecord {
                expires_at: now + EVENT_TICKET_TTL,
                principal,
            },
        );
        Ok(ticket)
    }

    /// Redeems a ticket exactly once, returning the principal it was issued to.
    pub(crate) async fn consume_event_ticket(
        &self,
        ticket: &str,
        now: Instant,
    ) -> Option<Principal> {
        let mut tickets = self.event_tickets.lock().await;
        tickets.retain(|_, record| record.expires_at >= now);
        tickets.remove(ticket).map(|record| record.principal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_store::{M2StateRepository, connect_memory};
    use tokio::time::{Duration, Instant};

    const TOKEN: &str = "owner-token-0123456789abcdefghijkl";

    async fn state() -> AppState {
        AppState::new(
            TOKEN,
            M2StateRepository::new(connect_memory().await.unwrap()),
        )
        .expect("valid token")
    }

    #[tokio::test]
    async fn event_ticket_is_bounded_one_time_and_expires() {
        let state = state().await;
        let now = Instant::now();
        // Spread across principals so the global cap, not the per-principal
        // quota, is what ends the run.
        let principals: Vec<_> = (0..MAX_OUTSTANDING_EVENT_TICKETS)
            .map(|index| {
                if index % MAX_TICKETS_PER_PHONE == 0 {
                    Principal::Owner
                } else {
                    Principal::Phone(Uuid::from_u128(index as u128))
                }
            })
            .collect();
        let mut tickets = Vec::new();
        for principal in &principals {
            if let Ok(ticket) = state.issue_event_ticket(now, *principal).await {
                tickets.push(ticket);
            }
        }
        assert!(tickets.len() > MAX_TICKETS_PER_PHONE);
        let ticket = tickets[0].clone();
        assert_eq!(
            tickets
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            tickets.len()
        );

        assert!(!ticket.contains(TOKEN));
        assert_eq!(
            state.consume_event_ticket(&ticket, now).await,
            Some(Principal::Owner)
        );
        assert_eq!(state.consume_event_ticket(&ticket, now).await, None);

        let expired = state
            .issue_event_ticket(now + Duration::from_secs(31), Principal::Owner)
            .await
            .unwrap();
        assert_eq!(state.event_tickets.lock().await.len(), 1);
        assert_eq!(
            state
                .consume_event_ticket(&expired, now + Duration::from_secs(62))
                .await,
            None
        );
        assert_eq!(state.consume_event_ticket("unknown", now).await, None);
    }

    #[tokio::test]
    async fn one_principal_cannot_starve_another_of_tickets() {
        let state = state().await;
        let now = Instant::now();
        let phone = Principal::Phone(Uuid::new_v4());
        for _ in 0..MAX_TICKETS_PER_PHONE {
            state.issue_event_ticket(now, phone).await.unwrap();
        }
        assert!(state.issue_event_ticket(now, phone).await.is_err());
        // The owner is unaffected, and a ticket stays bound to its principal.
        let owner = state
            .issue_event_ticket(now, Principal::Owner)
            .await
            .unwrap();
        assert_eq!(
            state.consume_event_ticket(&owner, now).await,
            Some(Principal::Owner)
        );
    }

    #[tokio::test]
    async fn the_owner_may_hold_the_full_global_cap_and_phones_leave_it_room() {
        let state = state().await;
        let now = Instant::now();
        for _ in 0..MAX_OUTSTANDING_EVENT_TICKETS {
            state
                .issue_event_ticket(now, Principal::Owner)
                .await
                .unwrap();
        }
        assert!(
            state
                .issue_event_ticket(now, Principal::Owner)
                .await
                .is_err()
        );
        // Phones fill every slot except the owner's reserve.
        let state = self::state().await;
        let mut granted = 0;
        for index in 0..MAX_OUTSTANDING_EVENT_TICKETS {
            let phone = Principal::Phone(Uuid::from_u128(index as u128 / 4 + 1));
            if state.issue_event_ticket(now, phone).await.is_ok() {
                granted += 1;
            }
        }
        assert_eq!(
            granted,
            MAX_OUTSTANDING_EVENT_TICKETS - OWNER_RESERVED_TICKETS
        );
        assert!(
            state
                .issue_event_ticket(now, Principal::Owner)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn token_validation_and_rotation() {
        assert!(
            AppState::new(
                "a".repeat(40),
                M2StateRepository::new(connect_memory().await.unwrap())
            )
            .is_err()
        );
        let state = state().await;
        assert!(state.token_matches(TOKEN));
        let new = "rotated-token-9876543210zyxwvutsrq";
        state.rotate_token(new.to_owned()).unwrap();
        assert!(!state.token_matches(TOKEN));
        assert!(state.token_matches(new));
        assert!(state.rotate_token("short".to_owned()).is_err());
        assert!(state.token_matches(new));
    }

    #[tokio::test]
    async fn rotation_persists_to_the_token_file_and_a_bad_token_leaves_it_alone() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("owner-token");
        let state = state().await.with_token_file(file.clone());
        let new = "rotated-token-9876543210zyxwvutsrq";
        state.rotate_token(new.to_owned()).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), new);
        assert!(state.rotate_token("short".to_owned()).is_err());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), new);
    }

    #[tokio::test]
    async fn a_failed_background_task_degrades_status_and_survives_recovery() {
        let state = state().await;
        assert_eq!(state.service_status().await, "ready");
        state.report_task_failure("host_monitor").await;
        assert_eq!(state.service_status().await, "degraded");
        // Neighbor discovery recovering must not mask the dead task.
        state
            .transition_service_status(ServiceRuntimeStatus::Ready, Utc::now())
            .await;
        assert_eq!(state.service_status().await, "degraded");
    }
}
