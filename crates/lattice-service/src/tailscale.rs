//! M6 remote phone access (T1–T4): Tailscale detection + private Serve,
//! Funnel refusal, forwarded-identity header stripping, phone pairing
//! sessions with PIN step-up, and command replay dedup.
//!
//! Contract: docs/architecture/m6-remote-access-contracts.md.
//!
//! Three principals exist in this service:
//!
//! * **Owner bearer** — the existing service token; accepted everywhere
//!   except the integrations read surface.
//! * **Phone session** — an id + secret pair minted by `POST /remote/pair`;
//!   accepted only on the read allowlist plus (with a live PIN step-up
//!   grace) the high-impact routes. Recognized by the
//!   [`remote_access_layer`] middleware, which authenticates the pair
//!   against SHA-256 hashes and inserts [`PhoneAuthorized`] so the bearer
//!   extractor accepts the request.
//! * **Integration token** — see `crate::integrations`; accepted ONLY under
//!   `/api/v1/integrations/v1/`.
//!
//! Identity is never taken from headers: `Tailscale-User-*` and
//! `X-Forwarded-*` are stripped from every request before routing, so no
//! handler can ever observe (let alone trust) them.

use crate::{AppState, auth::Authorized};
use axum::{
    Json,
    body::{Body, Bytes},
    extract::{FromRequestParts, Path as AxumPath, Request, State},
    http::{HeaderValue, Method, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use lattice_doctor::{Clock, SystemClock};
use lattice_store::{
    AuditActor, AuditCategory, AuditLog, NewAuditEntry, NewPhoneSession, PhoneSessionRow,
    RemoteAccessRepository,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use utoipa::ToSchema;
use uuid::Uuid;

/// Phone session lifetime; every successful authentication slides it forward.
const PHONE_SESSION_TTL_DAYS: i64 = 30;
/// Step-up grace after a correct PIN (contract: 5 minutes).
const STEPUP_GRACE_MINUTES: i64 = 5;
/// Failed-PIN budget per window before the session locks.
const PIN_MAX_FAILURES: u32 = 5;
/// Failed-PIN accounting window and lock duration.
const PIN_WINDOW_MINUTES: i64 = 15;
/// Per-session replay window: the newest ids whose results are retained.
const COMMAND_DEDUP_WINDOW: usize = 128;
/// Largest response body the dedup cache will buffer.
const MAX_CACHED_COMMAND_BODY: usize = 2 * 1024 * 1024;
/// The loopback port the production service binds (see `main.rs`).
const DEFAULT_LOOPBACK_PORT: u16 = 58120;
/// The tailnet HTTPS port Serve exposes privately.
const SERVE_HTTPS_PORT: u16 = 443;
/// Marks a replayed command response so clients can tell it was not re-run.
const REPLAYED_HEADER: &str = "x-command-replayed";
/// Command ids travel in this header on mutating phone requests.
const COMMAND_ID_HEADER: &str = "x-command-id";
/// How often a phone session's sliding expiry is written back. Every
/// authenticated request used to issue an UPDATE, which turned read polling
/// into write traffic on SQLite; one touch a minute keeps the 30-day window
/// sliding with no observable difference.
const SESSION_TOUCH_INTERVAL_SECS: i64 = 60;
/// Concurrent integration long-polls one token may hold open.
const MAX_LONG_POLLS_PER_TOKEN: usize = 4;

// ---------------------------------------------------------------------------
// Tailscale control seam (T1/T2). There is deliberately NO Funnel operation
// on this trait: nothing in this service can request public exposure.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct TailscaleDaemon {
    pub running: bool,
    #[schema(max_length = 64)]
    pub backend_state: String,
    #[schema(max_length = 256)]
    pub dns_name: Option<String>,
}

/// One tailnet-HTTPS → local-target Serve mapping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ServeMapping {
    pub https_port: u16,
    #[schema(max_length = 256)]
    pub target: String,
}

/// The daemon's current serve/funnel configuration as read back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServeState {
    pub mappings: Vec<ServeMapping>,
    /// Ports for which Funnel (public exposure) is enabled.
    pub funnel_ports: Vec<u16>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TailscaleError {
    #[error("tailscale binary path is not configured")]
    NotConfigured,
    #[error("tailscale daemon is unavailable: {0}")]
    DaemonUnavailable(String),
    #[error("tailscale CLI failed: {0}")]
    Cli(String),
}

#[async_trait::async_trait]
pub trait TailscaleControl: Send + Sync {
    async fn daemon_status(&self) -> Result<TailscaleDaemon, TailscaleError>;
    async fn serve_state(&self) -> Result<ServeState, TailscaleError>;
    /// Applies one private Serve mapping (tailnet HTTPS → loopback listener).
    async fn apply_serve(&self, mapping: &ServeMapping) -> Result<(), TailscaleError>;
}

/// Production control: shells out to an explicitly configured tailscale
/// binary (env `NEONHEARTH_TAILSCALE_BIN`); never guesses a PATH lookup.
pub struct SystemTailscaleControl {
    binary: Option<PathBuf>,
}

impl SystemTailscaleControl {
    pub fn new(binary: PathBuf) -> Self {
        Self {
            binary: Some(binary),
        }
    }

    /// A control with no binary configured: every operation reports
    /// [`TailscaleError::NotConfigured`].
    pub fn unconfigured() -> Self {
        Self { binary: None }
    }

    pub fn from_env() -> Self {
        Self {
            binary: std::env::var_os("NEONHEARTH_TAILSCALE_BIN").map(PathBuf::from),
        }
    }

    async fn run(&self, args: &[&str]) -> Result<String, TailscaleError> {
        let binary = self.binary.as_ref().ok_or(TailscaleError::NotConfigured)?;
        let output = tokio::process::Command::new(binary)
            .args(args)
            .output()
            .await
            .map_err(|error| TailscaleError::DaemonUnavailable(error.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TailscaleError::Cli(stderr.trim().to_owned()));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[async_trait::async_trait]
impl TailscaleControl for SystemTailscaleControl {
    async fn daemon_status(&self) -> Result<TailscaleDaemon, TailscaleError> {
        parse_status_json(&self.run(&["status", "--json"]).await?)
    }

    async fn serve_state(&self) -> Result<ServeState, TailscaleError> {
        parse_serve_json(&self.run(&["serve", "status", "--json"]).await?)
    }

    async fn apply_serve(&self, mapping: &ServeMapping) -> Result<(), TailscaleError> {
        let https = format!("--https={}", mapping.https_port);
        self.run(&["serve", "--bg", &https, &mapping.target])
            .await?;
        Ok(())
    }
}

/// Parses `tailscale status --json` down to the fields the service uses.
fn parse_status_json(raw: &str) -> Result<TailscaleDaemon, TailscaleError> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|_| TailscaleError::Cli("status output is not JSON".into()))?;
    let backend_state = value["BackendState"]
        .as_str()
        .unwrap_or("Unknown")
        .to_owned();
    Ok(TailscaleDaemon {
        running: backend_state == "Running",
        backend_state,
        dns_name: value["Self"]["DNSName"]
            .as_str()
            .map(|name| name.trim_end_matches('.').to_owned()),
    })
}

/// Parses `tailscale serve status --json`: Web proxy handlers plus the
/// AllowFunnel map (any true entry means public exposure on that port).
fn parse_serve_json(raw: &str) -> Result<ServeState, TailscaleError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(ServeState::default());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|_| TailscaleError::Cli("serve status output is not JSON".into()))?;
    let mut state = ServeState::default();
    if let Some(web) = value["Web"].as_object() {
        for (host_port, config) in web {
            let Some(port) = parse_host_port(host_port) else {
                continue;
            };
            if let Some(handlers) = config["Handlers"].as_object() {
                for handler in handlers.values() {
                    if let Some(proxy) = handler["Proxy"].as_str() {
                        state.mappings.push(ServeMapping {
                            https_port: port,
                            target: proxy.to_owned(),
                        });
                    }
                }
            }
        }
    }
    if let Some(funnel) = value["AllowFunnel"].as_object() {
        for (host_port, enabled) in funnel {
            if enabled.as_bool() == Some(true)
                && let Some(port) = parse_host_port(host_port)
            {
                state.funnel_ports.push(port);
            }
        }
    }
    Ok(state)
}

fn parse_host_port(host_port: &str) -> Option<u16> {
    host_port.rsplit(':').next()?.parse().ok()
}

/// Scriptable fake for tests: injected daemon/serve answers plus a record of
/// every applied mapping. Applying a mapping also updates the fake's serve
/// state so idempotency is observable through the trait.
pub struct FakeTailscaleControl {
    inner: std::sync::Mutex<FakeTailscaleInner>,
}

struct FakeTailscaleInner {
    daemon: Result<TailscaleDaemon, TailscaleError>,
    serve: Result<ServeState, TailscaleError>,
    apply_error: Option<TailscaleError>,
    applied: Vec<ServeMapping>,
}

impl Default for FakeTailscaleControl {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeTailscaleControl {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(FakeTailscaleInner {
                daemon: Ok(TailscaleDaemon {
                    running: true,
                    backend_state: "Running".to_owned(),
                    dns_name: Some("neonhearth.tailnet.ts.net".to_owned()),
                }),
                serve: Ok(ServeState::default()),
                apply_error: None,
                applied: Vec::new(),
            }),
        }
    }

    pub fn set_daemon(&self, daemon: Result<TailscaleDaemon, TailscaleError>) {
        self.inner.lock().unwrap().daemon = daemon;
    }

    pub fn set_serve(&self, serve: Result<ServeState, TailscaleError>) {
        self.inner.lock().unwrap().serve = serve;
    }

    pub fn set_apply_error(&self, error: Option<TailscaleError>) {
        self.inner.lock().unwrap().apply_error = error;
    }

    /// Enables Funnel for a port in the fake's serve state.
    pub fn enable_funnel(&self, port: u16) {
        let mut inner = self.inner.lock().unwrap();
        if let Ok(serve) = &mut inner.serve {
            serve.funnel_ports.push(port);
        }
    }

    pub fn applied(&self) -> Vec<ServeMapping> {
        self.inner.lock().unwrap().applied.clone()
    }
}

#[async_trait::async_trait]
impl TailscaleControl for FakeTailscaleControl {
    async fn daemon_status(&self) -> Result<TailscaleDaemon, TailscaleError> {
        self.inner.lock().unwrap().daemon.clone()
    }

    async fn serve_state(&self) -> Result<ServeState, TailscaleError> {
        self.inner.lock().unwrap().serve.clone()
    }

    async fn apply_serve(&self, mapping: &ServeMapping) -> Result<(), TailscaleError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(error) = inner.apply_error.clone() {
            return Err(error);
        }
        inner.applied.push(mapping.clone());
        if let Ok(serve) = &mut inner.serve
            && !serve.mappings.contains(mapping)
        {
            serve.mappings.push(mapping.clone());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Service-owned remote access state.
// ---------------------------------------------------------------------------

struct RemoteShared {
    tailscale: Arc<dyn TailscaleControl>,
    clock: Arc<dyn Clock>,
    loopback_port: u16,
    pool: SqlitePool,
    /// Per-session replay windows. A `std` mutex: every critical section is
    /// short and never spans an `.await`, which also lets the in-flight guard
    /// release a command from `Drop` when a handler future is cancelled.
    dedup: Mutex<HashMap<Uuid, SessionDedup>>,
    /// Per-integration-token long-poll admission.
    long_polls: Mutex<HashMap<Uuid, Arc<Semaphore>>>,
}

impl RemoteShared {
    fn lock_dedup(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, SessionDedup>> {
        // A poisoned window only means a panicking handler; the map itself
        // is always left consistent by the short critical sections.
        self.dedup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drops a session's replay window (revocation, expiry).
    fn forget_session(&self, session_id: Uuid) {
        self.lock_dedup().remove(&session_id);
    }

    /// Completes an in-flight command: stores the settled response (or, when
    /// `cached` is `None`, releases the id so a waiting duplicate executes)
    /// and wakes every duplicate parked on it.
    fn finish_command(&self, session_id: Uuid, command_id: Uuid, cached: Option<CachedCommand>) {
        let mut dedup = self.lock_dedup();
        let Some(window) = dedup.get_mut(&session_id) else {
            return;
        };
        let notify = match cached {
            Some(cached) => window.settle(command_id, cached),
            None => window.release(command_id),
        };
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
    }
}

/// Cloneable handle to the remote-access state (tailscale control, clock,
/// and per-session command dedup windows).
#[derive(Clone)]
pub struct RemoteAccessState {
    shared: Arc<RemoteShared>,
}

impl RemoteAccessState {
    /// Production remote access for this service instance.
    pub fn for_service(state: &AppState) -> Self {
        Self::with_parts(
            state,
            Arc::new(SystemTailscaleControl::from_env()),
            Arc::new(SystemClock),
            DEFAULT_LOOPBACK_PORT,
        )
    }

    /// Assemble remote access with injected control, clock, and loopback
    /// port — the seam tests use for fake tailscale and expiry clocks.
    pub fn with_parts(
        state: &AppState,
        tailscale: Arc<dyn TailscaleControl>,
        clock: Arc<dyn Clock>,
        loopback_port: u16,
    ) -> Self {
        Self {
            shared: Arc::new(RemoteShared {
                tailscale,
                clock,
                loopback_port,
                pool: state.state_repository().pool().clone(),
                dedup: Mutex::new(HashMap::new()),
                long_polls: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Admits one more concurrent long-poll for `token_id`, or `None` when
    /// the token already holds [`MAX_LONG_POLLS_PER_TOKEN`] open. The permit
    /// releases itself when the poll's future completes or is dropped.
    pub(crate) fn long_poll_permit(&self, token_id: Uuid) -> Option<OwnedSemaphorePermit> {
        let mut polls = self
            .shared
            .long_polls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Idle tokens hold no permits; drop their entries so the map is
        // bounded by the tokens that are actually polling.
        polls.retain(|id, semaphore| {
            *id == token_id || semaphore.available_permits() < MAX_LONG_POLLS_PER_TOKEN
        });
        let semaphore = polls
            .entry(token_id)
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_LONG_POLLS_PER_TOKEN)));
        Arc::clone(semaphore).try_acquire_owned().ok()
    }

    fn repository(&self) -> RemoteAccessRepository {
        RemoteAccessRepository::new(self.shared.pool.clone())
    }

    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.shared.pool
    }

    fn now(&self) -> DateTime<Utc> {
        self.shared.clock.now()
    }
}

// ---------------------------------------------------------------------------
// Principals.
// ---------------------------------------------------------------------------

/// Inserted by [`remote_access_layer`] once a phone session authenticated
/// AND the requested route is allowed for phone principals. Its presence is
/// what makes the bearer extractor accept a phone request; it cannot be
/// forged from the wire because HTTP carries no extensions.
#[derive(Clone, Debug)]
pub struct PhoneAuthorized {
    pub session_id: Uuid,
}

/// Extractor for routes that require specifically a phone principal
/// (`POST /remote/stepup`).
pub struct PhonePrincipal(pub Uuid);

impl<S: Send + Sync> FromRequestParts<S> for PhonePrincipal {
    type Rejection = Response;
    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let session = parts
            .extensions
            .get::<PhoneAuthorized>()
            .map(|principal| principal.session_id);
        async move {
            session
                .map(Self)
                .ok_or_else(|| StatusCode::FORBIDDEN.into_response())
        }
    }
}

// ---------------------------------------------------------------------------
// Middleware: header stripping, phone authentication, step-up gate, dedup.
// ---------------------------------------------------------------------------

/// Forwarded-identity headers stripped from every request before routing.
/// Identity from headers is NEVER used for authorization (T2).
pub(crate) fn strip_forwarded_identity_headers(headers: &mut axum::http::HeaderMap) {
    let forwarded: Vec<axum::http::HeaderName> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            name.starts_with("tailscale-user-")
                || name.starts_with("x-forwarded-")
                || name == "x-real-ip"
        })
        .cloned()
        .collect();
    for name in forwarded {
        headers.remove(&name);
    }
}

/// What a phone principal may do with a route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhoneAccess {
    /// Allowed with a live session alone.
    Read,
    /// Allowed only with a live PIN step-up grace.
    HighImpact,
    /// Never allowed for phone principals (owner bearer only).
    Denied,
}

fn classify_phone_access(method: &Method, path: &str) -> PhoneAccess {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let rest: &[&str] = match segments.as_slice() {
        ["api", "v1", rest @ ..] => rest,
        _ => return PhoneAccess::Denied,
    };
    match (method, rest) {
        (&Method::GET, ["health" | "state" | "cameras" | "openapi.json"])
        | (&Method::GET, ["cameras", _])
        | (&Method::GET, ["cameras", _, "health" | "inventory"])
        | (&Method::GET, ["devices", _, "advisories"])
        | (&Method::GET, ["home"])
        | (&Method::GET, ["home", "draft"])
        | (&Method::GET, ["doctor", "report"])
        | (&Method::GET, ["remote", "status"])
        | (&Method::GET, ["events"])
        | (&Method::POST, ["remote", "stepup"])
        | (&Method::POST, ["events", "ticket"]) => PhoneAccess::Read,
        (&Method::POST, ["policy", "action"])
        | (&Method::POST, ["doctor", "run" | "approvals" | "repair"])
        | (&Method::PUT, ["home", "plan"])
        | (&Method::PUT | &Method::DELETE, ["home", "placements", _])
        | (&Method::PUT | &Method::DELETE, ["home", "draft"])
        | (_, ["audit", ..]) => PhoneAccess::HighImpact,
        _ => PhoneAccess::Denied,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub(crate) fn sha256_hex(value: &str) -> String {
    hex_encode(&Sha256::digest(value.as_bytes()))
}

fn hashes_match(supplied: &str, stored: &str) -> bool {
    supplied.as_bytes().ct_eq(stored.as_bytes()).into()
}

/// The `PhoneSession <id>:<secret>` credentials, when that scheme is used.
/// `Err` means the scheme was present but unusable (ambiguous or malformed).
fn phone_credentials(headers: &axum::http::HeaderMap) -> Result<Option<(Uuid, String)>, ()> {
    let values: Vec<_> = headers.get_all(header::AUTHORIZATION).iter().collect();
    let phone_headers = values
        .iter()
        .filter(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.starts_with("PhoneSession "))
        })
        .count();
    if phone_headers == 0 {
        return Ok(None);
    }
    if values.len() != 1 {
        return Err(());
    }
    let value = values[0].to_str().map_err(|_| ())?;
    let credentials = value.strip_prefix("PhoneSession ").ok_or(())?;
    let (id, secret) = credentials.split_once(':').ok_or(())?;
    let id = Uuid::parse_str(id).map_err(|_| ())?;
    if secret.is_empty() {
        return Err(());
    }
    Ok(Some((id, secret.to_owned())))
}

#[derive(Clone)]
struct CachedCommand {
    status: StatusCode,
    content_type: Option<HeaderValue>,
    body: Bytes,
}

/// One command id's place in a session's replay window.
enum CommandSlot {
    /// A request with this id is executing; duplicates wait on the notify.
    Pending(Arc<Notify>),
    /// The settled response, replayed verbatim to duplicates.
    Done(CachedCommand),
}

#[derive(Default)]
struct SessionDedup {
    /// Settled ids, oldest first, for bounded eviction.
    order: VecDeque<Uuid>,
    slots: HashMap<Uuid, CommandSlot>,
}

impl SessionDedup {
    /// Claims `command_id` for the calling request. The in-flight marker
    /// closes the check-then-execute window: a duplicate that arrives while
    /// the first request is still running parks on the returned notify
    /// instead of executing a second time.
    fn begin(&mut self, command_id: Uuid) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        self.slots
            .insert(command_id, CommandSlot::Pending(Arc::clone(&notify)));
        notify
    }

    /// Stores the settled response for `command_id`, evicting the oldest
    /// settled entries beyond the window.
    fn settle(&mut self, command_id: Uuid, response: CachedCommand) -> Option<Arc<Notify>> {
        let previous = self.slots.insert(command_id, CommandSlot::Done(response));
        if !matches!(previous, Some(CommandSlot::Done(_))) {
            self.order.push_back(command_id);
        }
        while self.order.len() > COMMAND_DEDUP_WINDOW {
            if let Some(evicted) = self.order.pop_front() {
                self.slots.remove(&evicted);
            }
        }
        match previous {
            Some(CommandSlot::Pending(notify)) => Some(notify),
            _ => None,
        }
    }

    /// Forgets an in-flight `command_id` whose request produced nothing worth
    /// replaying (a 5xx, an oversized body, or a cancelled handler).
    fn release(&mut self, command_id: Uuid) -> Option<Arc<Notify>> {
        match self.slots.get(&command_id) {
            Some(CommandSlot::Pending(_)) => match self.slots.remove(&command_id) {
                Some(CommandSlot::Pending(notify)) => Some(notify),
                _ => None,
            },
            _ => None,
        }
    }

    #[cfg(test)]
    fn settled(&self, command_id: &Uuid) -> bool {
        matches!(self.slots.get(command_id), Some(CommandSlot::Done(_)))
    }
}

/// Releases a claimed command id if the executing request never settles it
/// (a client disconnect drops the handler future mid-flight). Without this a
/// parked duplicate would wait forever.
struct InFlightCommand<'a> {
    shared: &'a RemoteShared,
    session_id: Uuid,
    command_id: Uuid,
    settled: bool,
}

impl InFlightCommand<'_> {
    fn settle(mut self, cached: Option<CachedCommand>) {
        self.settled = true;
        self.shared
            .finish_command(self.session_id, self.command_id, cached);
    }
}

impl Drop for InFlightCommand<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.shared
                .finish_command(self.session_id, self.command_id, None);
        }
    }
}

fn replayed_response(cached: &CachedCommand) -> Response {
    let mut response = Response::builder()
        .status(cached.status)
        .header(REPLAYED_HEADER, "true");
    if let Some(content_type) = &cached.content_type {
        response = response.header(header::CONTENT_TYPE, content_type);
    }
    response
        .body(Body::from(cached.body.clone()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// The remote-access layer around every route: strips forwarded-identity
/// headers (T2), dispatches the integrations surface to its dedicated
/// principal (I1/I2), authenticates phone sessions with the step-up gate
/// (T3), and serves replayed command ids from the dedup window (T4).
/// Owner-bearer and anonymous requests pass through untouched.
pub(crate) async fn remote_access_layer(
    State(remote): State<RemoteAccessState>,
    mut request: Request,
    next: Next,
) -> Response {
    strip_forwarded_identity_headers(request.headers_mut());
    if request
        .uri()
        .path()
        .starts_with(crate::integrations::SURFACE_PREFIX)
    {
        return crate::integrations::authorize_integration(&remote, request, next).await;
    }
    let credentials = match phone_credentials(request.headers()) {
        Ok(None) => return next.run(request).await,
        Ok(Some(credentials)) => credentials,
        Err(()) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let (session_id, secret) = credentials;
    let repository = remote.repository();
    let session = match repository.load_phone_session(session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let now = remote.now();
    if session.revoked || now >= session.expires_at {
        // A dead session's replay window can never be consulted again.
        remote.shared.forget_session(session_id);
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !hashes_match(&sha256_hex(&secret), &session.secret_hash) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // Classify before touching storage: a request this principal may never
    // make should not cost a write.
    let access = classify_phone_access(request.method(), request.uri().path());
    if access == PhoneAccess::Denied {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Sliding expiry: successful authentication moves it forward, written
    // back at most once per SESSION_TOUCH_INTERVAL_SECS.
    let touch_due = session.last_used_at.is_none_or(|last_used_at| {
        now - last_used_at >= Duration::seconds(SESSION_TOUCH_INTERVAL_SECS)
    });
    if touch_due
        && repository
            .touch_phone_session(
                session_id,
                now,
                now + Duration::days(PHONE_SESSION_TTL_DAYS),
            )
            .await
            .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if access == PhoneAccess::HighImpact {
        let live = session
            .stepup_expires_at
            .is_some_and(|expires_at| now < expires_at);
        if !live {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    request
        .extensions_mut()
        .insert(PhoneAuthorized { session_id });

    // T4: command replay dedup for mutating phone requests.
    let mutating = !matches!(*request.method(), Method::GET | Method::HEAD);
    let command_id = request
        .headers()
        .get(COMMAND_ID_HEADER)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| Uuid::parse_str(value).ok())
        })
        .filter(|_| mutating);
    let command_id = match command_id {
        // A high-impact command without a replay id cannot be made
        // idempotent; refuse it rather than silently running it unprotected.
        None if mutating && access == PhoneAccess::HighImpact => {
            return StatusCode::BAD_REQUEST.into_response();
        }
        None => return next.run(request).await,
        Some(None) => return StatusCode::BAD_REQUEST.into_response(),
        Some(Some(command_id)) => command_id,
    };
    // Claim the id, or replay / wait on whoever holds it. The claim and the
    // lookup happen under one lock so two concurrent duplicates can never
    // both miss.
    loop {
        let notify: Arc<Notify>;
        let notified = {
            let mut dedup = remote.shared.lock_dedup();
            let window = dedup.entry(session_id).or_default();
            match window.slots.get(&command_id) {
                Some(CommandSlot::Done(cached)) => return replayed_response(cached),
                Some(CommandSlot::Pending(pending)) => {
                    notify = Arc::clone(pending);
                    // Register interest before the lock is released so a
                    // settle that lands in between still wakes this waiter.
                    // Boxed so the guard stays confined to this block and is
                    // never held across the await below.
                    let mut notified = Box::pin(notify.notified());
                    notified.as_mut().enable();
                    notified
                }
                None => {
                    window.begin(command_id);
                    break;
                }
            }
        };
        notified.await;
    }
    let in_flight = InFlightCommand {
        shared: &remote.shared,
        session_id,
        command_id,
        settled: false,
    };
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_CACHED_COMMAND_BODY).await else {
        in_flight.settle(None);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    // A 5xx is a transient failure, not a settled outcome: caching it would
    // pin the client's retry to the failure. Release the id instead so the
    // retry executes for real.
    let cached = (!parts.status.is_server_error()).then(|| CachedCommand {
        status: parts.status,
        content_type: parts.headers.get(header::CONTENT_TYPE).cloned(),
        body: bytes.clone(),
    });
    in_flight.settle(cached);
    Response::from_parts(parts, Body::from(bytes))
}

// ---------------------------------------------------------------------------
// Audit helper (category Approval for all remote-access changes).
// ---------------------------------------------------------------------------

async fn append_audit(
    pool: &SqlitePool,
    occurred_at: DateTime<Utc>,
    action: &str,
    subject: String,
    detail: serde_json::Value,
) -> Result<(), ()> {
    let audit = AuditLog::new(pool.clone());
    match audit
        .append(NewAuditEntry {
            occurred_at,
            actor: AuditActor::Owner,
            category: AuditCategory::Approval,
            action: action.to_owned(),
            subject: Some(subject),
            detail,
        })
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => {
            tracing::error!(%error, action, "remote access audit append failed");
            Err(())
        }
    }
}

// ---------------------------------------------------------------------------
// PIN hashing (Argon2id for the low-entropy PIN; SHA-256 elsewhere is for
// high-entropy random secrets only).
// ---------------------------------------------------------------------------

fn hash_pin(pin: &str) -> Result<String, ()> {
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| ())?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| ())?;
    Argon2::default()
        .hash_password(pin.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| ())
}

fn verify_pin(pin: &str, hash: &str) -> bool {
    use argon2::password_hash::PasswordHash;
    use argon2::{Argon2, PasswordVerifier};
    PasswordHash::new(hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(pin.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

fn valid_pin_format(pin: &str) -> bool {
    pin.len() == 6 && pin.bytes().all(|byte| byte.is_ascii_digit())
}

fn random_secret_hex() -> Result<String, ()> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    Ok(hex_encode(&bytes))
}

// ---------------------------------------------------------------------------
// Routes: Serve configuration + status (T1/T2).
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct RemoteServeResponse {
    pub configured: bool,
    /// False when the desired mapping was already present (idempotent call).
    pub changed: bool,
    pub https_port: u16,
    #[schema(max_length = 256)]
    pub target: String,
    #[schema(max_length = 256)]
    pub dns_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RemoteStatusResponse {
    pub daemon: Option<TailscaleDaemon>,
    #[schema(max_length = 512)]
    pub daemon_error: Option<String>,
    pub serve_configured: bool,
    /// True when Funnel (public exposure) is enabled for the serve port —
    /// the service refuses to configure Serve while this holds.
    pub funnel_conflict: bool,
    pub loopback_port: u16,
}

/// Typed outcome of [`configure_private_serve`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteServeError {
    /// Funnel is enabled for the port Serve would use; there is no override.
    #[error("funnel (public exposure) is enabled for the serve port; refusing")]
    FunnelEnabled,
    #[error(transparent)]
    Tailscale(#[from] TailscaleError),
}

fn loopback_target(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// Idempotently configures private tailnet HTTPS → loopback Serve. Refuses
/// with [`RemoteServeError::FunnelEnabled`] when Funnel is on for our port
/// or for any port that proxies to our loopback target (T2).
pub async fn configure_private_serve(
    remote: &RemoteAccessState,
) -> Result<RemoteServeResponse, RemoteServeError> {
    let shared = &remote.shared;
    let daemon = shared.tailscale.daemon_status().await?;
    if !daemon.running {
        return Err(TailscaleError::DaemonUnavailable(format!(
            "backend state is {}",
            daemon.backend_state
        ))
        .into());
    }
    let serve = shared.tailscale.serve_state().await?;
    let target = loopback_target(shared.loopback_port);
    let funnel_on_our_port = serve.funnel_ports.contains(&SERVE_HTTPS_PORT);
    let funnel_on_our_target = serve.mappings.iter().any(|mapping| {
        mapping.target == target && serve.funnel_ports.contains(&mapping.https_port)
    });
    if funnel_on_our_port || funnel_on_our_target {
        return Err(RemoteServeError::FunnelEnabled);
    }
    let desired = ServeMapping {
        https_port: SERVE_HTTPS_PORT,
        target: target.clone(),
    };
    let changed = if serve.mappings.contains(&desired) {
        false
    } else {
        shared.tailscale.apply_serve(&desired).await?;
        true
    };
    Ok(RemoteServeResponse {
        configured: true,
        changed,
        https_port: SERVE_HTTPS_PORT,
        target,
        dns_name: daemon.dns_name,
    })
}

#[derive(Serialize, ToSchema)]
pub struct RemoteError {
    #[schema(max_length = 512)]
    pub error: String,
}

fn remote_error(status: StatusCode, error: impl Into<String>) -> Response {
    (
        status,
        Json(RemoteError {
            error: error.into(),
        }),
    )
        .into_response()
}

#[utoipa::path(post, path = "/api/v1/remote/serve", responses((status = 200, body = RemoteServeResponse), (status = 401), (status = 409, body = RemoteError, description = "funnel is enabled for the serve port; refused"), (status = 503, body = RemoteError)), security(("bearer_auth" = [])))]
pub(crate) async fn serve_route(
    _: Authorized,
    axum::Extension(remote): axum::Extension<RemoteAccessState>,
) -> Response {
    let now = remote.now();
    match configure_private_serve(&remote).await {
        Ok(result) => {
            let audited = append_audit(
                remote.pool(),
                now,
                "tailscale_serve_configured",
                loopback_target(remote.shared.loopback_port),
                serde_json::json!({
                    "changed": result.changed,
                    "https_port": result.https_port,
                    "target": result.target,
                }),
            )
            .await;
            if audited.is_err() {
                return remote_error(StatusCode::SERVICE_UNAVAILABLE, "audit log unavailable");
            }
            Json(result).into_response()
        }
        Err(RemoteServeError::FunnelEnabled) => {
            // The refusal itself is audited; if even that fails the refusal
            // still stands (denying is always safe unaudited).
            let _ = append_audit(
                remote.pool(),
                now,
                "tailscale_serve_refused_funnel",
                loopback_target(remote.shared.loopback_port),
                serde_json::json!({ "reason": "funnel_enabled" }),
            )
            .await;
            remote_error(
                StatusCode::CONFLICT,
                "funnel (public exposure) is enabled for the serve port; refusing to configure serve",
            )
        }
        Err(RemoteServeError::Tailscale(error)) => {
            remote_error(StatusCode::SERVICE_UNAVAILABLE, error.to_string())
        }
    }
}

#[utoipa::path(get, path = "/api/v1/remote/status", responses((status = 200, body = RemoteStatusResponse), (status = 401)), security(("bearer_auth" = [])))]
pub(crate) async fn status_route(
    _: Authorized,
    axum::Extension(remote): axum::Extension<RemoteAccessState>,
) -> Response {
    let shared = &remote.shared;
    let (daemon, daemon_error) = match shared.tailscale.daemon_status().await {
        Ok(daemon) => (Some(daemon), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let target = loopback_target(shared.loopback_port);
    let (serve_configured, funnel_conflict) = match shared.tailscale.serve_state().await {
        Ok(serve) => (
            serve
                .mappings
                .iter()
                .any(|mapping| mapping.https_port == SERVE_HTTPS_PORT && mapping.target == target),
            serve.funnel_ports.contains(&SERVE_HTTPS_PORT)
                || serve.mappings.iter().any(|mapping| {
                    mapping.target == target && serve.funnel_ports.contains(&mapping.https_port)
                }),
        ),
        Err(_) => (false, false),
    };
    Json(RemoteStatusResponse {
        daemon,
        daemon_error,
        serve_configured,
        funnel_conflict,
        loopback_port: shared.loopback_port,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Routes: phone session pairing + management (T3).
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    #[schema(min_length = 1, max_length = 128)]
    pub device_label: String,
    /// Exactly six ASCII digits; Argon2id-hashed at rest.
    #[schema(min_length = 6, max_length = 6, pattern = "^[0-9]{6}$")]
    pub pin: String,
}

#[derive(Serialize, ToSchema)]
pub struct PairResponse {
    #[schema(value_type = String, format = Uuid)]
    pub session_id: Uuid,
    /// Shown exactly once; only its SHA-256 is stored.
    #[schema(min_length = 64, max_length = 64)]
    pub secret: String,
    pub expires_at: DateTime<Utc>,
}

#[utoipa::path(post, path = "/api/v1/remote/pair", request_body = PairRequest, responses((status = 200, body = PairResponse), (status = 400), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn pair_route(
    _: Authorized,
    axum::Extension(remote): axum::Extension<RemoteAccessState>,
    body: Result<Json<PairRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = body else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if request.device_label.is_empty()
        || request.device_label.len() > 128
        || !valid_pin_format(&request.pin)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(secret) = random_secret_hex() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(pin_hash) = hash_pin(&request.pin) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let now = remote.now();
    let session = NewPhoneSession {
        id: Uuid::new_v4(),
        secret_hash: sha256_hex(&secret),
        device_label: request.device_label.clone(),
        pin_hash,
        created_at: now,
        expires_at: now + Duration::days(PHONE_SESSION_TTL_DAYS),
    };
    let repository = remote.repository();
    if repository.insert_phone_session(&session).await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let audited = append_audit(
        remote.pool(),
        now,
        "phone_session_paired",
        session.id.to_string(),
        serde_json::json!({
            "device_label": session.device_label,
            "expires_at": session.expires_at,
        }),
    )
    .await;
    if audited.is_err() {
        // An unaudited pairing must not exist: withdraw it.
        let _ = repository.revoke_phone_session(session.id).await;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(PairResponse {
        session_id: session.id,
        secret,
        expires_at: session.expires_at,
    })
    .into_response()
}

#[derive(Serialize, ToSchema)]
pub struct PhoneSessionProjection {
    #[schema(value_type = String, format = Uuid)]
    pub session_id: Uuid,
    #[schema(max_length = 128)]
    pub device_label: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

#[derive(Serialize, ToSchema)]
pub struct PhoneSessionList {
    pub items: Vec<PhoneSessionProjection>,
}

#[utoipa::path(get, path = "/api/v1/remote/sessions", responses((status = 200, body = PhoneSessionList), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn sessions_route(
    _: Authorized,
    axum::Extension(remote): axum::Extension<RemoteAccessState>,
) -> Response {
    match remote.repository().list_phone_sessions().await {
        Ok(sessions) => Json(PhoneSessionList {
            items: sessions
                .into_iter()
                .map(|session| PhoneSessionProjection {
                    session_id: session.id,
                    device_label: session.device_label,
                    created_at: session.created_at,
                    expires_at: session.expires_at,
                    last_used_at: session.last_used_at,
                    revoked: session.revoked,
                })
                .collect(),
        })
        .into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[utoipa::path(delete, path = "/api/v1/remote/sessions/{id}", params(("id" = String, Path, format = Uuid)), responses((status = 204), (status = 400), (status = 401), (status = 404), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn revoke_session_route(
    _: Authorized,
    axum::Extension(remote): axum::Extension<RemoteAccessState>,
    path: Result<AxumPath<String>, axum::extract::rejection::PathRejection>,
) -> Response {
    let Ok(AxumPath(id)) = path else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match remote.repository().revoke_phone_session(id).await {
        Ok(true) => {
            remote.shared.forget_session(id);
            // Revocation only removes privileges, so it stands even when the
            // audit append fails; the failure is surfaced as 503 instead of
            // silently succeeding.
            let audited = append_audit(
                remote.pool(),
                remote.now(),
                "phone_session_revoked",
                id.to_string(),
                serde_json::json!({}),
            )
            .await;
            if audited.is_err() {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Routes: PIN step-up (T3).
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StepupRequest {
    #[schema(min_length = 6, max_length = 6, pattern = "^[0-9]{6}$")]
    pub pin: String,
}

#[derive(Serialize, ToSchema)]
pub struct StepupResponse {
    /// End of the five-minute high-impact grace window.
    pub expires_at: DateTime<Utc>,
}

/// Charges one failed PIN attempt. The window/count/lock accounting is a
/// single atomic store update, so N concurrent wrong guesses are charged as
/// N failures — a stolen session cannot widen its guess budget by racing.
async fn handle_pin_failure(
    remote: &RemoteAccessState,
    session: &PhoneSessionRow,
    now: DateTime<Utc>,
) -> Response {
    let outcome = match remote
        .repository()
        .record_pin_failure(
            session.id,
            now,
            Duration::minutes(PIN_WINDOW_MINUTES),
            PIN_MAX_FAILURES,
        )
        .await
    {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let audited = append_audit(
        remote.pool(),
        now,
        "stepup_failed",
        session.id.to_string(),
        serde_json::json!({
            "failures_in_window": outcome.failed_count,
            "locked": outcome.locked_until.is_some(),
            "locked_until": outcome.locked_until,
        }),
    )
    .await;
    if audited.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if outcome.locked_until.is_some() {
        StatusCode::TOO_MANY_REQUESTS.into_response()
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

#[utoipa::path(post, path = "/api/v1/remote/stepup", request_body = StepupRequest, responses((status = 200, body = StepupResponse), (status = 400), (status = 401), (status = 403, description = "wrong PIN, or the caller is not a phone session"), (status = 429, description = "PIN attempts locked"), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn stepup_route(
    principal: PhonePrincipal,
    axum::Extension(remote): axum::Extension<RemoteAccessState>,
    body: Result<Json<StepupRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = body else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let repository = remote.repository();
    let session = match repository.load_phone_session(principal.0).await {
        Ok(Some(session)) => session,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let now = remote.now();
    if session
        .pin_locked_until
        .is_some_and(|locked_until| now < locked_until)
    {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    if !valid_pin_format(&request.pin) || !verify_pin(&request.pin, &session.pin_hash) {
        return handle_pin_failure(&remote, &session, now).await;
    }
    let expires_at = now + Duration::minutes(STEPUP_GRACE_MINUTES);
    if repository
        .grant_stepup(session.id, expires_at)
        .await
        .is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let audited = append_audit(
        remote.pool(),
        now,
        "stepup_granted",
        session.id.to_string(),
        serde_json::json!({ "expires_at": expires_at }),
    )
    .await;
    if audited.is_err() {
        // An unaudited grace must not exist: withdraw it.
        let _ = repository
            .grant_stepup(session.id, now - Duration::seconds(1))
            .await;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(StepupResponse { expires_at }).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_forwarded_identity_headers_and_keeps_the_rest() {
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in [
            ("tailscale-user-login", "attacker@example.com"),
            ("tailscale-user-name", "Attacker"),
            ("tailscale-user-profile-pic", "https://example.test/pic"),
            ("x-forwarded-for", "203.0.113.9"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "evil.example"),
            ("x-real-ip", "203.0.113.9"),
            ("authorization", "Bearer abc"),
            ("content-type", "application/json"),
        ] {
            headers.append(name, value.parse().unwrap());
        }
        strip_forwarded_identity_headers(&mut headers);
        let mut remaining: Vec<_> = headers.keys().map(|name| name.as_str()).collect();
        remaining.sort_unstable();
        assert_eq!(remaining, ["authorization", "content-type"]);
    }

    #[test]
    fn phone_access_classification_matches_the_contract() {
        use PhoneAccess::{Denied, HighImpact, Read};
        for (method, path, expected) in [
            (Method::GET, "/api/v1/state", Read),
            (Method::GET, "/api/v1/cameras", Read),
            (Method::GET, "/api/v1/cameras/abc/health", Read),
            (Method::GET, "/api/v1/home", Read),
            (Method::GET, "/api/v1/home/draft", Read),
            (Method::GET, "/api/v1/doctor/report", Read),
            (Method::POST, "/api/v1/events/ticket", Read),
            (Method::POST, "/api/v1/remote/stepup", Read),
            (Method::POST, "/api/v1/policy/action", HighImpact),
            (Method::POST, "/api/v1/doctor/run", HighImpact),
            (Method::POST, "/api/v1/doctor/approvals", HighImpact),
            (Method::POST, "/api/v1/doctor/repair", HighImpact),
            (Method::PUT, "/api/v1/home/plan", HighImpact),
            (Method::PUT, "/api/v1/home/placements/x", HighImpact),
            (Method::DELETE, "/api/v1/home/draft", HighImpact),
            (Method::GET, "/api/v1/audit/modules", HighImpact),
            (Method::POST, "/api/v1/remote/pair", Denied),
            (Method::GET, "/api/v1/remote/sessions", Denied),
            (Method::DELETE, "/api/v1/remote/sessions/x", Denied),
            (Method::POST, "/api/v1/remote/serve", Denied),
            (Method::POST, "/api/v1/integrations/tokens", Denied),
            (Method::GET, "/api/v1/integrations/v1/devices", Denied),
            (Method::POST, "/api/v1/cameras/abc/sessions", Denied),
            (Method::GET, "/api/v1/cameras/abc/snapshot", Denied),
            (Method::GET, "/other", Denied),
        ] {
            assert_eq!(
                classify_phone_access(&method, path),
                expected,
                "{method} {path}"
            );
        }
    }

    #[test]
    fn status_json_parses_backend_state_and_dns_name() {
        let daemon = parse_status_json(
            r#"{"BackendState":"Running","Self":{"DNSName":"host.tail.ts.net."}}"#,
        )
        .unwrap();
        assert!(daemon.running);
        assert_eq!(daemon.dns_name.as_deref(), Some("host.tail.ts.net"));
        let stopped = parse_status_json(r#"{"BackendState":"Stopped"}"#).unwrap();
        assert!(!stopped.running);
        assert_eq!(stopped.dns_name, None);
        assert!(parse_status_json("not json").is_err());
    }

    #[test]
    fn serve_json_parses_mappings_and_funnel_ports() {
        let state = parse_serve_json(
            r#"{
                "Web": {"host.tail.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:58120"}}}},
                "AllowFunnel": {"host.tail.ts.net:443": true, "host.tail.ts.net:8443": false}
            }"#,
        )
        .unwrap();
        assert_eq!(
            state.mappings,
            vec![ServeMapping {
                https_port: 443,
                target: "http://127.0.0.1:58120".to_owned(),
            }]
        );
        assert_eq!(state.funnel_ports, vec![443]);
        assert_eq!(parse_serve_json("").unwrap(), ServeState::default());
    }

    #[test]
    fn phone_credentials_parse_and_reject_ambiguity() {
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(phone_credentials(&headers), Ok(None));
        headers.insert("authorization", "Bearer abc".parse().unwrap());
        assert_eq!(phone_credentials(&headers), Ok(None));

        let id = Uuid::new_v4();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!("PhoneSession {id}:sekrit").parse().unwrap(),
        );
        assert_eq!(
            phone_credentials(&headers),
            Ok(Some((id, "sekrit".to_owned())))
        );

        // Ambiguous: two Authorization headers, one of them a phone scheme.
        headers.append("authorization", "Bearer abc".parse().unwrap());
        assert_eq!(phone_credentials(&headers), Err(()));

        // Malformed phone credentials.
        for bad in ["PhoneSession nope", "PhoneSession :x", "PhoneSession "] {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert("authorization", bad.parse().unwrap());
            assert_eq!(phone_credentials(&headers), Err(()), "{bad}");
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!("PhoneSession {id}:").parse().unwrap(),
        );
        assert_eq!(phone_credentials(&headers), Err(()));
    }

    #[test]
    fn pin_hashing_round_trips_and_rejects_wrong_pins() {
        let hash = hash_pin("123456").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_pin("123456", &hash));
        assert!(!verify_pin("654321", &hash));
        assert!(!verify_pin("123456", "not-a-phc-string"));
    }

    #[test]
    fn dedup_window_is_bounded_to_the_newest_entries() {
        let mut window = SessionDedup::default();
        let cached = CachedCommand {
            status: StatusCode::OK,
            content_type: None,
            body: Bytes::new(),
        };
        let first = Uuid::new_v4();
        window.begin(first);
        window.settle(first, cached.clone());
        for _ in 0..COMMAND_DEDUP_WINDOW {
            let id = Uuid::new_v4();
            window.begin(id);
            window.settle(id, cached.clone());
        }
        assert_eq!(window.slots.len(), COMMAND_DEDUP_WINDOW);
        assert!(!window.settled(&first));
    }

    #[test]
    fn in_flight_commands_are_released_not_settled_and_survive_eviction() {
        let mut window = SessionDedup::default();
        let cached = CachedCommand {
            status: StatusCode::OK,
            content_type: None,
            body: Bytes::new(),
        };
        let pending = Uuid::new_v4();
        let notify = window.begin(pending);
        // Settled entries evict around a pending one: it is not in `order`.
        for _ in 0..(COMMAND_DEDUP_WINDOW + 8) {
            let id = Uuid::new_v4();
            window.begin(id);
            window.settle(id, cached.clone());
        }
        assert!(matches!(
            window.slots.get(&pending),
            Some(CommandSlot::Pending(_))
        ));
        // Releasing hands back the same notify so waiters can be woken, and
        // releasing an already-settled or unknown id is a no-op.
        let released = window.release(pending).expect("pending id releases");
        assert!(Arc::ptr_eq(&released, &notify));
        assert!(window.release(pending).is_none());
        assert!(!window.slots.contains_key(&pending));
        let done = *window.order.back().unwrap();
        assert!(window.release(done).is_none());
        assert!(window.settled(&done));
    }
}
