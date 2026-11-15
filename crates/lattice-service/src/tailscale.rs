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

use crate::{
    AppState,
    auth::{Authorized, Principal},
};
use axum::{
    Json,
    body::Body,
    extract::{FromRequestParts, Path as AxumPath, Request, State},
    http::{Method, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use lattice_doctor::{Clock, SystemClock};
use lattice_store::{
    AuditCategory, AuditLog, CommandReplay, NewAuditEntry, NewPhoneSession, PhoneSessionRow,
    PinReservation, RemoteAccessRepository,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use utoipa::ToSchema;
use uuid::Uuid;

/// Phone session lifetime; every successful authentication slides it forward.
const PHONE_SESSION_TTL_DAYS: i64 = 30;
/// Absolute session age: sliding expiry never extends past this, so a stolen
/// secret cannot live forever and the owner must re-pair periodically.
const PHONE_SESSION_MAX_LIFETIME_DAYS: i64 = 180;
/// Concurrent Argon2 computations (PIN verify/hash) the service will run.
const PIN_WORKERS: usize = 2;
/// Step-up grace after a correct PIN (contract: 5 minutes).
const STEPUP_GRACE_MINUTES: i64 = 5;
/// Failed-PIN budget per window before the session locks.
const PIN_MAX_FAILURES: u32 = 5;
/// Failed-PIN accounting window and lock duration.
const PIN_WINDOW_MINUTES: i64 = 15;
/// Per-session replay window: the newest settled command records retained.
const COMMAND_REPLAY_KEEP: u32 = 128;
/// Largest request body buffered to fingerprint a phone command.
const MAX_COMMAND_REQUEST_BODY: usize = 2 * 1024 * 1024;
/// Largest response body persisted for replay; bigger responses replay as
/// their status alone (flagged with `x-command-body-omitted`).
const MAX_PERSISTED_COMMAND_BODY: usize = 256 * 1024;
/// Largest response body the layer will buffer at all.
const MAX_COMMAND_RESPONSE_BODY: usize = 8 * 1024 * 1024;
/// Marks a replayed response whose body was too large to retain.
const BODY_OMITTED_HEADER: &str = "x-command-body-omitted";
/// Longest a tailscale CLI call may run before it is killed.
const TAILSCALE_CLI_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
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
        let mut command = tokio::process::Command::new(binary);
        // A hung CLI must not outlive the request that started it.
        command.args(args).kill_on_drop(true);
        let output = match tokio::time::timeout(TAILSCALE_CLI_TIMEOUT, command.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                tracing::warn!(%error, "tailscale CLI could not be started");
                return Err(TailscaleError::DaemonUnavailable(
                    "the tailscale CLI could not be started".into(),
                ));
            }
            Err(_) => {
                tracing::warn!("tailscale CLI timed out");
                return Err(TailscaleError::DaemonUnavailable(
                    "the tailscale CLI timed out".into(),
                ));
            }
        };
        if !output.status.success() {
            // Raw stderr can carry paths and account details; log it, never
            // return it to API callers.
            tracing::warn!(
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "tailscale CLI failed"
            );
            return Err(TailscaleError::Cli(
                "the tailscale CLI reported an error".into(),
            ));
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
#[cfg(any(test, feature = "test-support"))]
pub struct FakeTailscaleControl {
    inner: std::sync::Mutex<FakeTailscaleInner>,
}

#[cfg(any(test, feature = "test-support"))]
struct FakeTailscaleInner {
    daemon: Result<TailscaleDaemon, TailscaleError>,
    serve: Result<ServeState, TailscaleError>,
    apply_error: Option<TailscaleError>,
    applied: Vec<ServeMapping>,
}

#[cfg(any(test, feature = "test-support"))]
impl Default for FakeTailscaleControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
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
    host_policy: crate::security::HostPolicy,
    /// In-process single-flight for command ids: a duplicate that arrives
    /// while the first copy executes parks on the notify instead of racing
    /// it. The durable record (see `claim_command`) is what guarantees a
    /// command never runs twice, across restarts and cancellations too. A
    /// `std` mutex: every critical section is short and never spans an
    /// `.await`, which also lets the in-flight guard release from `Drop`.
    pending: Mutex<HashMap<(Uuid, Uuid), Arc<Notify>>>,
    /// Per-integration-token long-poll admission.
    long_polls: Mutex<HashMap<Uuid, Arc<Semaphore>>>,
    /// Bounds concurrent Argon2 work so PIN traffic cannot starve the runtime.
    pin_gate: Arc<Semaphore>,
    pin_verifications: AtomicUsize,
}

impl RemoteShared {
    fn lock_pending(&self) -> std::sync::MutexGuard<'_, HashMap<(Uuid, Uuid), Arc<Notify>>> {
        // A poisoned map only means a panicking handler; the map itself is
        // always left consistent by the short critical sections.
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Frees an in-flight command id and wakes every duplicate parked on it.
    fn release_pending(&self, key: (Uuid, Uuid)) {
        let notify = self.lock_pending().remove(&key);
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
    }
}

/// Cloneable handle to the remote-access state (tailscale control, clock,
/// and the in-flight command registry).
#[derive(Clone)]
pub struct RemoteAccessState {
    shared: Arc<RemoteShared>,
}

impl RemoteAccessState {
    /// Production remote access for this service instance. The Serve target
    /// follows the port the listener is actually bound to.
    pub fn for_service(state: &AppState) -> Self {
        Self::with_parts(
            state,
            Arc::new(SystemTailscaleControl::from_env()),
            Arc::new(SystemClock),
            state.bound_port(),
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
                host_policy: state.host_policy().clone(),
                pending: Mutex::new(HashMap::new()),
                long_polls: Mutex::new(HashMap::new()),
                pin_gate: Arc::new(Semaphore::new(PIN_WORKERS)),
                pin_verifications: AtomicUsize::new(0),
            }),
        }
    }

    /// Asks the tailscale daemon for its DNS name and allows it as a `Host`.
    /// Best effort: without a daemon only loopback names are served.
    pub async fn prime_host_policy(&self) {
        if let Ok(Ok(daemon)) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.shared.tailscale.daemon_status(),
        )
        .await
            && let Some(name) = daemon.dns_name
        {
            self.shared.host_policy.allow_tailnet_name(&name);
        }
    }

    /// Number of PIN verifications (Argon2 runs) performed. Exposed so tests
    /// can prove the attempt budget bounds the work, not just the outcome.
    #[doc(hidden)]
    pub fn pin_verifications(&self) -> usize {
        self.shared.pin_verifications.load(Ordering::SeqCst)
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

    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.shared.clock.now()
    }

    /// Runs CPU-heavy PIN work on the blocking pool behind a small gate.
    async fn pin_work<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let permit = Arc::clone(&self.shared.pin_gate)
            .acquire_owned()
            .await
            .ok()?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .ok()
    }

    async fn verify_pin_blocking(&self, pin: String, hash: String) -> bool {
        self.shared.pin_verifications.fetch_add(1, Ordering::SeqCst);
        self.pin_work(move || verify_pin(&pin, &hash))
            .await
            .unwrap_or(false)
    }

    async fn hash_pin_blocking(&self, pin: String) -> Option<String> {
        self.pin_work(move || hash_pin(&pin).ok()).await.flatten()
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

/// Frees the in-flight marker for a command id however the handler ends,
/// including being dropped mid-flight by a timeout or a client disconnect.
/// The durable record is deliberately NOT touched: a command that may have
/// run stays claimed, so a retry can never execute it a second time.
struct InFlightCommand<'a> {
    shared: &'a RemoteShared,
    key: (Uuid, Uuid),
}

impl Drop for InFlightCommand<'_> {
    fn drop(&mut self) {
        self.shared.release_pending(self.key);
    }
}

fn command_error(status: StatusCode, error: &'static str) -> Response {
    remote_error(status, error)
}

fn replayed_response(record: &CommandReplay) -> Response {
    let mut response = Response::builder()
        .status(StatusCode::from_u16(record.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(REPLAYED_HEADER, "true");
    if let Some(content_type) = &record.content_type {
        response = response.header(header::CONTENT_TYPE, content_type);
    }
    if record.body_omitted {
        response = response.header(BODY_OMITTED_HEADER, "true");
    }
    response
        .body(Body::from(record.body.clone()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Binds a command id to exactly one request: method, target and body.
fn request_fingerprint(method: &Method, target: &str, body: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(method.as_str().as_bytes());
    digest.update([0]);
    digest.update(target.as_bytes());
    digest.update([0]);
    digest.update(body);
    hex_encode(&digest.finalize())
}

/// Runs one mutating phone command at most once (T4).
///
/// The durable claim is written BEFORE the handler runs and completed after,
/// so every way the first attempt can end leaves a record behind:
/// * finished (any status, including 5xx, because the effect may have
///   happened): the stored response is replayed;
/// * service restart, crash, or the handler being cancelled mid-flight: the
///   record stays in flight and a retry gets 409 "outcome unknown" instead of
///   a second execution;
/// * the same id with a different method/path/body: 409, not a replay.
async fn run_command(
    remote: &RemoteAccessState,
    session_id: Uuid,
    command_id: Uuid,
    request: Request,
    next: Next,
) -> Response {
    let key = (session_id, command_id);
    let (parts, body) = request.into_parts();
    let Ok(request_body) = axum::body::to_bytes(body, MAX_COMMAND_REQUEST_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let target = parts.uri.path_and_query().map_or_else(
        || parts.uri.path().to_owned(),
        |value| value.as_str().to_owned(),
    );
    let fingerprint = request_fingerprint(&parts.method, &target, &request_body);
    let request = Request::from_parts(parts, Body::from(request_body));

    // Become the single in-process executor of this id, or wait for the one
    // that is. The claim and the lookup happen under one lock.
    loop {
        let notify: Arc<Notify>;
        let notified = {
            let mut pending = remote.shared.lock_pending();
            match pending.get(&key) {
                Some(existing) => {
                    notify = Arc::clone(existing);
                    // Register interest before the lock is released so a
                    // release that lands in between still wakes this waiter.
                    // Boxed so the guard stays confined to this block and is
                    // never held across the await below.
                    let mut notified = Box::pin(notify.notified());
                    notified.as_mut().enable();
                    notified
                }
                None => {
                    pending.insert(key, Arc::new(Notify::new()));
                    break;
                }
            }
        };
        notified.await;
    }
    let _in_flight = InFlightCommand {
        shared: &remote.shared,
        key,
    };

    let repository = remote.repository();
    match repository
        .claim_command(session_id, command_id, &fingerprint, remote.now())
        .await
    {
        Ok(None) => {}
        Ok(Some(record)) => {
            if record.fingerprint != fingerprint {
                return command_error(
                    StatusCode::CONFLICT,
                    "command id was already used for a different request",
                );
            }
            if !record.completed {
                return command_error(
                    StatusCode::CONFLICT,
                    "command outcome unknown: it may have run; check state before issuing a new command",
                );
            }
            return replayed_response(&record);
        }
        Err(error) => {
            tracing::error!(%error, "phone command claim failed; command not executed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let Ok(bytes) = axum::body::to_bytes(body, MAX_COMMAND_RESPONSE_BODY).await else {
        // The command ran but its response cannot be held: settle the record
        // so a retry is refused as already executed, and tell the caller.
        if let Err(error) = repository
            .complete_command(
                session_id,
                command_id,
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                None,
                None,
                COMMAND_REPLAY_KEEP,
            )
            .await
        {
            tracing::error!(%error, "phone command completion failed");
        }
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let persisted = (bytes.len() <= MAX_PERSISTED_COMMAND_BODY).then_some(&bytes[..]);
    if let Err(error) = repository
        .complete_command(
            session_id,
            command_id,
            parts.status.as_u16(),
            content_type.as_deref(),
            persisted,
            COMMAND_REPLAY_KEEP,
        )
        .await
    {
        // The record stays in flight: a retry is refused, never re-run.
        tracing::error!(%error, "phone command completion failed");
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// The remote-access layer around every route: strips forwarded-identity
/// headers (T2), dispatches the integrations surface to its dedicated
/// principal (I1/I2), authenticates phone sessions with the step-up gate
/// (T3), and runs mutating phone commands at most once (T4).
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
        Err(error) => {
            tracing::error!(%error, "phone session lookup failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let now = remote.now();
    // A session also dies at an absolute age, however recently it was used:
    // sliding expiry alone would let a stolen secret live forever.
    let hard_expiry = session.created_at + Duration::days(PHONE_SESSION_MAX_LIFETIME_DAYS);
    if session.revoked || now >= session.expires_at || now >= hard_expiry {
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
    // Sliding expiry: successful authentication moves it forward (never past
    // the absolute cap), written back at most once per
    // SESSION_TOUCH_INTERVAL_SECS. The write only lands on a live session.
    let touch_due = session.last_used_at.is_none_or(|last_used_at| {
        now - last_used_at >= Duration::seconds(SESSION_TOUCH_INTERVAL_SECS)
    });
    if touch_due {
        let next_expiry = (now + Duration::days(PHONE_SESSION_TTL_DAYS)).min(hard_expiry);
        match repository
            .touch_phone_session(session_id, now, next_expiry)
            .await
        {
            Ok(true) => {}
            Ok(false) => return StatusCode::UNAUTHORIZED.into_response(),
            Err(error) => {
                tracing::error!(%error, "phone session touch failed");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        }
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

    // T4: at-most-once execution for mutating phone requests.
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
    match command_id {
        // A high-impact command without a replay id cannot be made
        // idempotent; refuse it rather than silently running it unprotected.
        None if mutating && access == PhoneAccess::HighImpact => {
            StatusCode::BAD_REQUEST.into_response()
        }
        None => next.run(request).await,
        Some(None) => StatusCode::BAD_REQUEST.into_response(),
        Some(Some(command_id)) => run_command(&remote, session_id, command_id, request, next).await,
    }
}

// ---------------------------------------------------------------------------
// Audit helper (category Approval for all remote-access changes).
// ---------------------------------------------------------------------------

async fn append_audit(
    pool: &SqlitePool,
    occurred_at: DateTime<Utc>,
    principal: Principal,
    action: &str,
    subject: String,
    detail: serde_json::Value,
) -> Result<(), ()> {
    let audit = AuditLog::new(pool.clone());
    match audit
        .append(NewAuditEntry {
            occurred_at,
            actor: principal.audit_actor(),
            category: AuditCategory::Approval,
            action: action.to_owned(),
            subject: Some(subject),
            detail: principal.annotate(detail),
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

/// True when a Serve proxy target points at our loopback listener, however
/// the operator spelled it: `http://127.0.0.1:P`, `localhost:P`, `[::1]:P`,
/// with or without scheme or trailing path. Exact string comparison missed
/// `localhost`, which would let a Funnel on another port go unnoticed.
fn targets_our_listener(target: &str, port: u16) -> bool {
    let target = target.trim();
    let with_scheme = if target.contains("://") {
        target.to_owned()
    } else {
        format!("http://{target}")
    };
    let Ok(url) = url::Url::parse(&with_scheme) else {
        return false;
    };
    let host_is_loopback = match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    host_is_loopback && url.port_or_known_default() == Some(port)
}

/// Funnel exposes our listener when it is on the Serve port itself or on any
/// port whose mapping proxies to our listener.
fn funnel_exposes_us(serve: &ServeState, port: u16) -> bool {
    serve.funnel_ports.contains(&SERVE_HTTPS_PORT)
        || serve.mappings.iter().any(|mapping| {
            serve.funnel_ports.contains(&mapping.https_port)
                && targets_our_listener(&mapping.target, port)
        })
}

/// Idempotently configures private tailnet HTTPS → loopback Serve. Refuses
/// with [`RemoteServeError::FunnelEnabled`] when Funnel is on for our port
/// or for any port that proxies to our loopback target (T2).
pub async fn configure_private_serve(
    remote: &RemoteAccessState,
) -> Result<RemoteServeResponse, RemoteServeError> {
    let shared = &remote.shared;
    let daemon = shared.tailscale.daemon_status().await?;
    if let Some(name) = &daemon.dns_name {
        shared.host_policy.allow_tailnet_name(name);
    }
    if !daemon.running {
        return Err(TailscaleError::DaemonUnavailable(format!(
            "backend state is {}",
            daemon.backend_state
        ))
        .into());
    }
    let serve = shared.tailscale.serve_state().await?;
    let target = loopback_target(shared.loopback_port);
    if funnel_exposes_us(&serve, shared.loopback_port) {
        return Err(RemoteServeError::FunnelEnabled);
    }
    let desired = ServeMapping {
        https_port: SERVE_HTTPS_PORT,
        target: target.clone(),
    };
    let already = serve.mappings.iter().any(|mapping| {
        mapping.https_port == SERVE_HTTPS_PORT
            && targets_our_listener(&mapping.target, shared.loopback_port)
    });
    let changed = if already {
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
    principal: Principal,
    axum::Extension(remote): axum::Extension<RemoteAccessState>,
) -> Response {
    let now = remote.now();
    match configure_private_serve(&remote).await {
        Ok(result) => {
            let audited = append_audit(
                remote.pool(),
                now,
                principal,
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
                principal,
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
    let (serve_configured, funnel_conflict) = match shared.tailscale.serve_state().await {
        Ok(serve) => (
            serve.mappings.iter().any(|mapping| {
                mapping.https_port == SERVE_HTTPS_PORT
                    && targets_our_listener(&mapping.target, shared.loopback_port)
            }),
            funnel_exposes_us(&serve, shared.loopback_port),
        ),
        Err(error) => {
            tracing::warn!(%error, "tailscale serve state unavailable");
            (false, false)
        }
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
    principal: Principal,
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
    let Some(pin_hash) = remote.hash_pin_blocking(request.pin.clone()).await else {
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
    if let Err(error) = repository.insert_phone_session(&session).await {
        tracing::error!(%error, "phone session insert failed");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let audited = append_audit(
        remote.pool(),
        now,
        principal,
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
        Err(error) => {
            tracing::error!(%error, "phone session list failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

#[utoipa::path(delete, path = "/api/v1/remote/sessions/{id}", params(("id" = String, Path, format = Uuid)), responses((status = 204), (status = 400), (status = 401), (status = 404), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn revoke_session_route(
    principal: Principal,
    State(state): State<AppState>,
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
            // Close any live event socket this session holds right now; the
            // sockets also re-check storage periodically as a backstop.
            state.announce_session_revoked(id);
            // Revocation only removes privileges, so it stands even when the
            // audit append fails; the failure is surfaced as 503 instead of
            // silently succeeding.
            let audited = append_audit(
                remote.pool(),
                remote.now(),
                principal,
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
        Err(error) => {
            tracing::error!(%error, "phone session revoke failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
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

/// Completes a failed, already-reserved PIN attempt: locks the session when
/// the reservation spent the last of the budget, and audits the failure.
async fn handle_pin_failure(
    remote: &RemoteAccessState,
    principal: Principal,
    session: &PhoneSessionRow,
    attempt: u32,
    now: DateTime<Utc>,
) -> Response {
    let outcome = match remote
        .repository()
        .finish_pin_failure(
            session.id,
            attempt,
            now,
            Duration::minutes(PIN_WINDOW_MINUTES),
            PIN_MAX_FAILURES,
        )
        .await
    {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::error!(%error, "pin failure accounting failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let audited = append_audit(
        remote.pool(),
        now,
        principal,
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
    let actor = Principal::Phone(principal.0);
    let repository = remote.repository();
    let session = match repository.load_phone_session(principal.0).await {
        Ok(Some(session)) => session,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::error!(%error, "phone session lookup failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let now = remote.now();
    // Reserve the attempt BEFORE evaluating the PIN. The reservation is one
    // atomic statement, so however many guesses race, at most the window's
    // budget is ever verified; the rest are refused unevaluated.
    let attempt = match repository
        .reserve_pin_attempt(
            session.id,
            now,
            Duration::minutes(PIN_WINDOW_MINUTES),
            PIN_MAX_FAILURES,
        )
        .await
    {
        Ok(PinReservation::Reserved { attempt }) => attempt,
        Ok(PinReservation::Locked { .. }) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
        Ok(PinReservation::NoSession) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::error!(%error, "pin attempt reservation failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let verified = valid_pin_format(&request.pin)
        && remote
            .verify_pin_blocking(request.pin.clone(), session.pin_hash.clone())
            .await;
    if !verified {
        return handle_pin_failure(&remote, actor, &session, attempt, now).await;
    }
    let expires_at = now + Duration::minutes(STEPUP_GRACE_MINUTES);
    match repository.grant_stepup(session.id, now, expires_at).await {
        Ok(true) => {}
        // The session locked while this (correct) guess was in flight: the
        // budget was already spent, so the grant is refused.
        Ok(false) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
        Err(error) => {
            tracing::error!(%error, "step-up grant failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    let audited = append_audit(
        remote.pool(),
        now,
        actor,
        "stepup_granted",
        session.id.to_string(),
        serde_json::json!({ "expires_at": expires_at }),
    )
    .await;
    if audited.is_err() {
        // An unaudited grace must not exist: withdraw it.
        let _ = repository.revoke_stepup(session.id).await;
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
            (Method::POST, "/api/v1/clock/acknowledge", Denied),
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
    fn serve_targets_are_compared_by_host_and_port_not_by_spelling() {
        for ours in [
            "http://127.0.0.1:58120",
            "http://localhost:58120",
            "localhost:58120",
            "127.0.0.1:58120/",
            "http://[::1]:58120",
            "HTTP://LocalHost:58120",
        ] {
            assert!(targets_our_listener(ours, 58120), "{ours}");
        }
        for other in [
            "http://127.0.0.1:58121",
            "http://192.168.1.5:58120",
            "http://example.com:58120",
            "not a target",
            "",
        ] {
            assert!(!targets_our_listener(other, 58120), "{other}");
        }
        // Funnel on another port that proxies to `localhost` is still ours.
        let serve = ServeState {
            mappings: vec![ServeMapping {
                https_port: 8443,
                target: "http://localhost:58120".to_owned(),
            }],
            funnel_ports: vec![8443],
        };
        assert!(funnel_exposes_us(&serve, 58120));
        assert!(!funnel_exposes_us(&serve, 58121));
    }

    #[test]
    fn request_fingerprint_binds_method_target_and_body() {
        let base = request_fingerprint(&Method::POST, "/api/v1/policy/action", b"{}");
        assert_eq!(
            base,
            request_fingerprint(&Method::POST, "/api/v1/policy/action", b"{}")
        );
        assert_ne!(
            base,
            request_fingerprint(&Method::PUT, "/api/v1/policy/action", b"{}")
        );
        assert_ne!(
            base,
            request_fingerprint(&Method::POST, "/api/v1/home/plan", b"{}")
        );
        assert_ne!(
            base,
            request_fingerprint(&Method::POST, "/api/v1/policy/action", b"{ }")
        );
    }

    // -- Replay layer and PIN gate, driven through the real layer ---------

    use axum::routing::post;
    use std::sync::atomic::AtomicUsize as TestCounter;
    use tower::ServiceExt as _;

    const COMMAND_PATH: &str = "/api/v1/events/ticket";

    async fn remote_for_tests() -> (RemoteAccessState, AppState) {
        let state = AppState::new(
            "owner-token-0123456789abcdefghijkl",
            lattice_store::M2StateRepository::new(lattice_store::connect_memory().await.unwrap()),
        )
        .unwrap();
        let remote = RemoteAccessState::with_parts(
            &state,
            Arc::new(FakeTailscaleControl::new()),
            Arc::new(SystemClock),
            58120,
        );
        (remote, state)
    }

    /// A router whose only route answers with the given status and body size
    /// behind the real remote-access layer, plus a live phone credential.
    async fn command_fixture(
        status: StatusCode,
        body_len: usize,
    ) -> (axum::Router, String, Arc<TestCounter>) {
        let (remote, _state) = remote_for_tests().await;
        let secret = random_secret_hex().unwrap();
        let id = Uuid::new_v4();
        let now = remote.now();
        remote
            .repository()
            .insert_phone_session(&NewPhoneSession {
                id,
                secret_hash: sha256_hex(&secret),
                device_label: "test".to_owned(),
                pin_hash: hash_pin("123456").unwrap(),
                created_at: now,
                expires_at: now + Duration::days(30),
            })
            .await
            .unwrap();
        let calls = Arc::new(TestCounter::new(0));
        let counter = Arc::clone(&calls);
        let router = axum::Router::new()
            .route(
                COMMAND_PATH,
                post(move || {
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        (status, vec![b'x'; body_len])
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                remote,
                remote_access_layer,
            ));
        (router, format!("PhoneSession {id}:{secret}"), calls)
    }

    async fn send_command(router: &axum::Router, credential: &str, command_id: Uuid) -> Response {
        router
            .clone()
            .oneshot(
                axum::http::Request::post(COMMAND_PATH)
                    .header(header::AUTHORIZATION, credential)
                    .header("x-command-id", command_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_server_error_is_replayed_and_never_executed_again() {
        let (router, credential, calls) =
            command_fixture(StatusCode::INTERNAL_SERVER_ERROR, 4).await;
        let command_id = Uuid::new_v4();
        let first = send_command(&router, &credential, command_id).await;
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(first.headers().get(REPLAYED_HEADER).is_none());
        let retry = send_command(&router, &credential, command_id).await;
        // The effect may have happened despite the 5xx, so the retry gets the
        // stored answer and the handler ran exactly once.
        assert_eq!(retry.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(retry.headers().get(REPLAYED_HEADER).unwrap(), "true");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_response_too_large_to_retain_replays_as_status_only() {
        let (router, credential, calls) =
            command_fixture(StatusCode::OK, MAX_PERSISTED_COMMAND_BODY + 1).await;
        let command_id = Uuid::new_v4();
        let first = send_command(&router, &credential, command_id).await;
        assert_eq!(first.status(), StatusCode::OK);
        let body = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.len(), MAX_PERSISTED_COMMAND_BODY + 1);
        let retry = send_command(&router, &credential, command_id).await;
        assert_eq!(retry.status(), StatusCode::OK);
        assert_eq!(retry.headers().get(REPLAYED_HEADER).unwrap(), "true");
        assert_eq!(retry.headers().get(BODY_OMITTED_HEADER).unwrap(), "true");
        let body = axum::body::to_bytes(retry.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_response_beyond_the_buffer_limit_settles_as_500_and_is_not_re_run() {
        let (router, credential, calls) =
            command_fixture(StatusCode::OK, MAX_COMMAND_RESPONSE_BODY + 1).await;
        let command_id = Uuid::new_v4();
        let first = send_command(&router, &credential, command_id).await;
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let retry = send_command(&router, &credential, command_id).await;
        assert_eq!(retry.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(retry.headers().get(REPLAYED_HEADER).unwrap(), "true");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// The gate is an upper bound, so the assertion cannot be flaky: however
    /// the scheduler interleaves eight tasks, no more than `PIN_WORKERS` may
    /// ever be inside the blocking section together.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pin_work_never_exceeds_the_worker_gate() {
        let (remote, _state) = remote_for_tests().await;
        let current = Arc::new(TestCounter::new(0));
        let peak = Arc::new(TestCounter::new(0));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let remote = remote.clone();
                let current = Arc::clone(&current);
                let peak = Arc::clone(&peak);
                tokio::spawn(async move {
                    remote
                        .pin_work(move || {
                            let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            // Hold the slot long enough for overlap to occur.
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            current.fetch_sub(1, Ordering::SeqCst);
                        })
                        .await
                })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.unwrap(), Some(()));
        }
        let peak = peak.load(Ordering::SeqCst);
        assert!((1..=PIN_WORKERS).contains(&peak), "peak was {peak}");
    }

    /// Finding 7: the Serve target follows the port the listener is bound to.
    #[tokio::test]
    async fn the_serve_target_follows_the_bound_port() {
        let (_remote, state) = remote_for_tests().await;
        state.set_bound_port(58199);
        let remote = RemoteAccessState::for_service(&state);
        assert_eq!(remote.shared.loopback_port, 58199);
        assert_eq!(
            loopback_target(remote.shared.loopback_port),
            "http://127.0.0.1:58199"
        );
    }
}
