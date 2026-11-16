//! Adding and removing a camera.
//!
//! Adding a camera is the one place the owner hands NeonHearth a camera's
//! password. What is checked, in this order, before anything is kept:
//!
//! 1. the address is an IPv4 literal in the private (RFC 1918) ranges, inside
//!    the subnet of an interface that is up and is a real wired or Wi-Fi
//!    adapter, and is neither this machine's own address nor that subnet's
//!    network or broadcast address ([`approve_address`]);
//! 2. the owner is not spraying the LAN (a small per-minute attempt budget);
//! 3. the attempt is written to the audit log before any packet is sent;
//! 4. the camera is asked for its ONVIF inventory at exactly that address, over
//!    an interface-bound connection that follows no redirect, and every stream
//!    address it returns must name that same host ([`StagingSink`]);
//! 5. only then are secrets written to the vault and one store transaction
//!    records the camera, its streams and the approval of its host. A failure
//!    after the vault write removes what was written.
//!
//! The approval ([`lattice_store::CameraTarget`]) is stored with the camera and
//! is the only way a camera's address is ever reachable: [`CameraTargetBook`]
//! is the production target registry, rebuilt from those rows at startup and
//! re-checked against the live interface inventory on every session.

use super::{
    ApprovedRtspTarget, CameraSessionError, CameraSessionManager, CameraTargetRegistry, Upstream,
    onvif_http::{ForeignServiceFlag, HttpOnvifTransport},
    parse_camera_id,
};
use crate::{AppState, Principal, vault::Vault};
use async_trait::async_trait;
use axum::{
    Json,
    extract::{
        Path as AxumPath, State,
        rejection::{JsonRejection, PathRejection},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use lattice_camera::{
    CameraClassification, CameraHealth, CameraId, CameraInventory, CameraProfile, Confidence,
    InventoryLimits, OnvifCredential, OnvifError, OnvifHealth, OnvifRequest, OnvifResponseWriter,
    OnvifTransport, StreamId, StreamSecretSink, StreamSourceRef, TargetAddress,
    inventory as run_inventory,
};
use lattice_sensor::{
    Address, AuthorizedBinding, InterfaceId, InterfaceInventory, InterfaceOverride,
    SystemInterfaceManager, TargetApproval, TargetGuard, TargetGuardError,
};
use lattice_store::{
    AuditCategory, AuditLog, CameraInventoryRecord, CameraRecord, CameraRepository, CameraTarget,
    NewAuditEntry,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use url::{Host, Url};
use utoipa::ToSchema;
use uuid::Uuid;

/// How many add attempts the owner may make per [`RATE_WINDOW`].
pub const RATE_LIMIT: usize = 6;
pub const RATE_WINDOW: Duration = Duration::from_secs(60);
/// The ONVIF port used when the owner does not give one.
pub const DEFAULT_ONVIF_PORT: u16 = 80;
const DEFAULT_RTSP_PORT: u16 = 554;
const ONVIF_PATH: &str = "/onvif/device_service";
const MAX_NAME_CHARS: usize = 64;
const MAX_USERNAME_BYTES: usize = 128;
const MAX_PASSWORD_BYTES: usize = 256;

// ---------------------------------------------------------------------------
// Which address may be approved.
// ---------------------------------------------------------------------------

/// Why an address cannot be approved. Every variant reaches the owner as the
/// same plain answer ("not on your network"); the variant is kept for the
/// audit log and for tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressRefusal {
    /// Not an IP address literal (a hostname, or text that is not an address).
    NotAnIpAddress,
    /// Not a private IPv4 unicast address: public, loopback, link-local,
    /// multicast, broadcast, unspecified, or IPv6.
    NotPrivateIpv4,
    /// One of this machine's own addresses.
    OwnAddress,
    /// The network or broadcast address of the subnet it is in.
    NetworkOrBroadcast,
    /// Not inside the subnet of any usable local interface.
    NotOnLocalNetwork,
}

/// An address that passed [`approve_address`], with the interface it was
/// approved on and the local address connections to it must be bound to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedHost {
    pub interface_name: String,
    pub interface: InterfaceId,
    pub address: Ipv4Addr,
    pub binding: AuthorizedBinding,
}

fn v4_contains(network: Ipv4Addr, prefix: u8, target: Ipv4Addr) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    u32::from(network) & mask == u32::from(target) & mask
}

/// Decides whether `input` may be approved as a camera's one host, judged
/// against the interfaces in `inventory` as they are right now.
pub fn approve_address(
    input: &str,
    inventory: &InterfaceInventory,
) -> Result<ApprovedHost, AddressRefusal> {
    approve_on(input, inventory, None)
}

fn approve_on(
    input: &str,
    inventory: &InterfaceInventory,
    only_interface: Option<&str>,
) -> Result<ApprovedHost, AddressRefusal> {
    let ip: IpAddr = input
        .trim()
        .parse()
        .map_err(|_| AddressRefusal::NotAnIpAddress)?;
    let IpAddr::V4(address) = ip else {
        return Err(AddressRefusal::NotPrivateIpv4);
    };
    if address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_unspecified()
        || !address.is_private()
    {
        return Err(AddressRefusal::NotPrivateIpv4);
    }
    if inventory
        .interfaces()
        .any(|interface| interface.addresses.iter().any(|local| local.ip == ip))
    {
        return Err(AddressRefusal::OwnAddress);
    }
    let interface = inventory
        .interfaces()
        // Up, not loopback, not a tunnel, VM or container adapter, not the
        // corporate-role interface: the same rule the network scan uses.
        .filter(|interface| interface.discovery_eligible(InterfaceOverride::Default))
        .filter(|interface| only_interface.is_none_or(|name| interface.name == name))
        .find(|interface| {
            interface.addresses.iter().any(|local| match local.ip {
                IpAddr::V4(network) => v4_contains(network, local.prefix, address),
                IpAddr::V6(_) => false,
            })
        })
        .ok_or(AddressRefusal::NotOnLocalNetwork)?;
    let guard = TargetGuard::new(
        inventory.clone(),
        [],
        [TargetApproval {
            interface: interface.id,
            prefix: Address { ip, prefix: 32 },
        }],
    )
    .map_err(|_| AddressRefusal::NotOnLocalNetwork)?;
    let binding = guard
        .authorized_binding(interface.id, ip)
        .map_err(|error| match error {
            TargetGuardError::BroadcastOrNetworkAddress => AddressRefusal::NetworkOrBroadcast,
            _ => AddressRefusal::NotOnLocalNetwork,
        })?;
    Ok(ApprovedHost {
        interface_name: interface.name.clone(),
        interface: interface.id,
        address,
        binding,
    })
}

// ---------------------------------------------------------------------------
// Seams: the interface inventory and the ONVIF transport.
// ---------------------------------------------------------------------------

/// The local interface inventory could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfacesUnavailable;

/// Where the live interface inventory comes from.
#[async_trait]
pub trait InterfaceSource: Send + Sync {
    async fn snapshot(&self) -> Result<InterfaceInventory, InterfacesUnavailable>;
}

/// The operating system's interface inventory.
pub struct SystemInterfaces;

#[async_trait]
impl InterfaceSource for SystemInterfaces {
    async fn snapshot(&self) -> Result<InterfaceInventory, InterfacesUnavailable> {
        tokio::task::spawn_blocking(|| SystemInterfaceManager.snapshot())
            .await
            .map_err(|_| InterfacesUnavailable)?
            .map_err(|_| InterfacesUnavailable)
    }
}

/// A fixed, replaceable interface inventory for tests.
#[cfg(any(test, feature = "test-support"))]
pub struct FixedInterfaces(StdMutex<InterfaceInventory>);

#[cfg(any(test, feature = "test-support"))]
impl FixedInterfaces {
    #[must_use]
    pub fn new(inventory: InterfaceInventory) -> Self {
        Self(StdMutex::new(inventory))
    }
    pub fn set(&self, inventory: InterfaceInventory) {
        *self.0.lock().expect("fixed interfaces poisoned") = inventory;
    }
}

#[cfg(any(test, feature = "test-support"))]
#[async_trait]
impl InterfaceSource for FixedInterfaces {
    async fn snapshot(&self) -> Result<InterfaceInventory, InterfacesUnavailable> {
        Ok(self.0.lock().expect("fixed interfaces poisoned").clone())
    }
}

/// Builds the ONVIF transport used for one add attempt.
pub trait OnvifConnector: Send + Sync {
    fn transport(
        &self,
        host: &ApprovedHost,
        foreign_service: ForeignServiceFlag,
    ) -> Result<Arc<dyn OnvifTransport>, OnvifError>;
}

/// The production connector: plain HTTP bound to the approved interface.
pub struct SystemOnvifConnector;

impl OnvifConnector for SystemOnvifConnector {
    fn transport(
        &self,
        host: &ApprovedHost,
        foreign_service: ForeignServiceFlag,
    ) -> Result<Arc<dyn OnvifTransport>, OnvifError> {
        Ok(Arc::new(HttpOnvifTransport::new(
            host.address,
            host.binding.source,
            foreign_service,
        )?))
    }
}

/// Lets the generic inventory run over a boxed transport.
struct DynTransport(Arc<dyn OnvifTransport>);

#[async_trait]
impl OnvifTransport for DynTransport {
    async fn request(
        &self,
        target: &TargetAddress,
        request: &OnvifRequest,
        credential: Option<&OnvifCredential>,
        response: &mut OnvifResponseWriter,
    ) -> Result<(), OnvifError> {
        self.0.request(target, request, credential, response).await
    }
}

// ---------------------------------------------------------------------------
// The production target registry.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct StoredTarget {
    interface: String,
    address: Ipv4Addr,
    rtsp_port: u16,
    allow_basic: bool,
}

/// The production [`CameraTargetRegistry`]: one approved host per camera, kept
/// in step with the `camera_targets` table. A lookup never trusts the stored
/// row alone. It re-reads the live interface inventory and approves the single
/// stored /32 through a [`TargetGuard`] on the interface it was approved on, so
/// an interface that went down, was renamed, changed subnet, or now owns the
/// address itself makes the camera unreachable (fail closed) until it matches
/// again.
pub struct CameraTargetBook {
    interfaces: Arc<dyn InterfaceSource>,
    entries: Mutex<HashMap<CameraId, StoredTarget>>,
}

impl CameraTargetBook {
    #[must_use]
    pub fn new(interfaces: Arc<dyn InterfaceSource>) -> Self {
        Self {
            interfaces,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Replaces the book with every approval in the store.
    pub async fn load(
        &self,
        repository: &CameraRepository,
    ) -> Result<usize, lattice_store::CameraStoreError> {
        let targets = repository.list_camera_targets().await?;
        let mut entries = self.entries.lock().await;
        entries.clear();
        for target in &targets {
            entries.insert(target.camera_id, stored(target));
        }
        Ok(entries.len())
    }

    pub async fn register(&self, target: &CameraTarget) {
        self.entries
            .lock()
            .await
            .insert(target.camera_id, stored(target));
    }

    pub async fn unregister(&self, camera: CameraId) {
        self.entries.lock().await.remove(&camera);
    }

    pub async fn address_in_use(&self, address: Ipv4Addr) -> bool {
        self.entries
            .lock()
            .await
            .values()
            .any(|entry| entry.address == address)
    }

    pub async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.entries.lock().await.is_empty()
    }
}

fn stored(target: &CameraTarget) -> StoredTarget {
    StoredTarget {
        interface: target.interface.clone(),
        address: target.address,
        rtsp_port: target.rtsp_port,
        allow_basic: target.allow_basic,
    }
}

#[async_trait]
impl CameraTargetRegistry for CameraTargetBook {
    async fn authorized_binding(
        &self,
        camera: CameraId,
        _stream: StreamId,
    ) -> Result<ApprovedRtspTarget, CameraSessionError> {
        let entry = self
            .entries
            .lock()
            .await
            .get(&camera)
            .cloned()
            .ok_or(CameraSessionError::Unavailable)?;
        let inventory = self
            .interfaces
            .snapshot()
            .await
            .map_err(|_| CameraSessionError::Unavailable)?;
        let host = approve_on(
            &entry.address.to_string(),
            &inventory,
            Some(&entry.interface),
        )
        .map_err(|_| CameraSessionError::Unavailable)?;
        Ok(ApprovedRtspTarget::new(host.binding, entry.rtsp_port)?
            .with_basic_auth_allowed(entry.allow_basic))
    }
}

// ---------------------------------------------------------------------------
// Stream addresses.
// ---------------------------------------------------------------------------

/// The [`StreamSecretSink`] for an add attempt. The inventory hands it the
/// stream addresses the camera returned; it refuses the whole batch unless
/// every one names the approved host, then stages, in memory only, the
/// addresses with the camera's sign-in embedded as the media proxy expects
/// them. Staged addresses are written to the vault by the caller once the
/// whole inventory has succeeded, because the vault is asynchronous and this
/// trait is not. The references this sink returns are placeholders that are
/// never stored.
struct StagingSink {
    host: Ipv4Addr,
    username: String,
    password: SecretString,
    staged: StdMutex<Vec<(StreamId, SecretString)>>,
    rtsp_port: StdMutex<Option<u16>>,
    mismatch: AtomicBool,
}

impl StagingSink {
    fn new(host: Ipv4Addr, username: String, password: SecretString) -> Self {
        Self {
            host,
            username,
            password,
            staged: StdMutex::new(Vec::new()),
            rtsp_port: StdMutex::new(None),
            mismatch: AtomicBool::new(false),
        }
    }

    fn mismatch(&self) -> bool {
        self.mismatch.load(Ordering::SeqCst)
    }

    fn take(&self) -> (Vec<(StreamId, SecretString)>, u16) {
        let staged = std::mem::take(&mut *self.staged.lock().expect("staged streams poisoned"));
        let port = self
            .rtsp_port
            .lock()
            .expect("rtsp port poisoned")
            .unwrap_or(DEFAULT_RTSP_PORT);
        (staged, port)
    }

    /// The stream address to keep: the camera's own, minus any sign-in it
    /// embedded, plus the owner's. `Err(true)` when it names another host or
    /// port than the others, `Err(false)` when it is unusable.
    fn compose(&self, advertised: &SecretString) -> Result<(SecretString, u16), bool> {
        let mut url = Url::parse(advertised.expose_secret()).map_err(|_| false)?;
        if url.scheme() != "rtsp" {
            return Err(false);
        }
        let host = match url.host().ok_or(false)? {
            Host::Ipv4(host) => IpAddr::V4(host),
            Host::Ipv6(host) => IpAddr::V6(host),
            // `rtsp` is not a "special" scheme, so a numeric host parses as a
            // domain; only an IP literal that equals the approved host passes.
            Host::Domain(host) => host.parse::<IpAddr>().map_err(|_| true)?,
        };
        if host != IpAddr::V4(self.host) {
            return Err(true);
        }
        let port = url.port().unwrap_or(DEFAULT_RTSP_PORT);
        url.set_username(&self.username).map_err(|_| false)?;
        // `Url` leaves a literal `%` alone, so encode everything but
        // alphanumerics ourselves; the proxy percent-decodes it back exactly.
        let password =
            utf8_percent_encode(self.password.expose_secret(), NON_ALPHANUMERIC).to_string();
        url.set_password(Some(&password)).map_err(|_| false)?;
        let composed = SecretString::from(url.to_string());
        // The same parser the media proxy uses at session start: a source it
        // would refuse is refused now, not at the first live view.
        Upstream::parse(composed.clone()).map_err(|_| false)?;
        Ok((composed, port))
    }
}

impl StreamSecretSink for StagingSink {
    fn store_all(
        &self,
        sources: Vec<(StreamId, SecretString)>,
    ) -> Result<Vec<StreamSourceRef>, OnvifError> {
        let mut staged = Vec::with_capacity(sources.len());
        let mut port: Option<u16> = None;
        for (stream, advertised) in sources {
            match self.compose(&advertised) {
                Ok((composed, this_port)) => {
                    if port.is_some_and(|port| port != this_port) {
                        // One approval names one RTSP port.
                        self.mismatch.store(true, Ordering::SeqCst);
                        return Err(OnvifError::Sink);
                    }
                    port = Some(this_port);
                    staged.push((stream, composed));
                }
                Err(elsewhere) => {
                    self.mismatch.store(elsewhere, Ordering::SeqCst);
                    return Err(OnvifError::Sink);
                }
            }
        }
        let placeholders = (0..staged.len())
            .map(|index| StreamSourceRef::new(format!("staged-{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        *self.staged.lock().expect("staged streams poisoned") = staged;
        *self.rtsp_port.lock().expect("rtsp port poisoned") = port;
        Ok(placeholders)
    }
}

// ---------------------------------------------------------------------------
// Adding and removing.
// ---------------------------------------------------------------------------

/// What the owner submitted. The password is a secret from the moment it is
/// taken off the wire and has no `Debug`.
pub struct AddCameraInput {
    pub address: String,
    pub username: String,
    pub password: SecretString,
    pub name: Option<String>,
    pub onvif_port: u16,
    pub allow_basic: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddedCamera {
    pub camera_id: CameraId,
    pub name: Option<String>,
    pub streams: Vec<StreamId>,
}

/// Why an add did not happen. Each maps to one plain answer for the owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddFailure {
    InvalidRequest,
    NotOnYourNetwork(AddressRefusal),
    AlreadyAdded,
    RateLimited,
    Busy,
    /// Nothing answered at the address, or the answer was cut off.
    Unreachable,
    /// The camera answered and refused the user name or password.
    SignInRefused,
    /// Something answered, but not like an ONVIF camera.
    UnexpectedAnswer,
    /// The device answered the first ONVIF request with "no such page", as a
    /// camera does when ONVIF is switched off in its settings.
    OnvifNotEnabled,
    /// The camera advertised a service or a video stream on another host.
    StreamsElsewhere,
    /// The camera has no video stream to show.
    NoStreams,
    /// The store, the vault or the interface list failed.
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoveFailure {
    NotFound,
    /// The camera is disabled, but some of its stored data could not be
    /// removed yet; removing it again retries.
    Incomplete,
}

pub struct CameraOnboarding {
    pool: SqlitePool,
    repository: CameraRepository,
    vault: Arc<dyn Vault>,
    book: Arc<CameraTargetBook>,
    manager: Arc<CameraSessionManager>,
    interfaces: Arc<dyn InterfaceSource>,
    connector: Arc<dyn OnvifConnector>,
    attempts: StdMutex<VecDeque<Instant>>,
    busy: Mutex<()>,
}

impl std::fmt::Debug for CameraOnboarding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CameraOnboarding")
    }
}

impl CameraOnboarding {
    #[must_use]
    pub fn new(
        pool: SqlitePool,
        vault: Arc<dyn Vault>,
        book: Arc<CameraTargetBook>,
        manager: Arc<CameraSessionManager>,
        interfaces: Arc<dyn InterfaceSource>,
        connector: Arc<dyn OnvifConnector>,
    ) -> Self {
        Self {
            repository: CameraRepository::new(pool.clone()),
            pool,
            vault,
            book,
            manager,
            interfaces,
            connector,
            attempts: StdMutex::new(VecDeque::new()),
            busy: Mutex::new(()),
        }
    }

    fn take_attempt(&self) -> Result<(), AddFailure> {
        let now = Instant::now();
        let mut attempts = self.attempts.lock().expect("attempt log poisoned");
        while attempts
            .front()
            .is_some_and(|at| now.duration_since(*at) >= RATE_WINDOW)
        {
            attempts.pop_front();
        }
        if attempts.len() >= RATE_LIMIT {
            return Err(AddFailure::RateLimited);
        }
        attempts.push_back(now);
        Ok(())
    }

    async fn audit(
        &self,
        principal: Principal,
        action: &str,
        subject: CameraId,
        detail: serde_json::Value,
    ) -> Result<(), ()> {
        AuditLog::new(self.pool.clone())
            .append(NewAuditEntry {
                occurred_at: Utc::now(),
                actor: principal.audit_actor(),
                category: AuditCategory::Approval,
                action: action.to_owned(),
                subject: Some(subject.to_string()),
                detail: principal.annotate(detail),
            })
            .await
            .map(|_| ())
            .map_err(|error| {
                tracing::error!(%error, action, "camera audit append failed");
            })
    }

    /// Adds a camera. See the module documentation for the order of checks.
    pub async fn add(
        self: &Arc<Self>,
        principal: Principal,
        input: AddCameraInput,
    ) -> Result<AddedCamera, AddFailure> {
        let name = validate_input(&input)?;
        let inventory = self
            .interfaces
            .snapshot()
            .await
            .map_err(|_| AddFailure::Unavailable)?;
        let host =
            approve_address(&input.address, &inventory).map_err(AddFailure::NotOnYourNetwork)?;
        if self.book.address_in_use(host.address).await {
            return Err(AddFailure::AlreadyAdded);
        }
        let credential = OnvifCredential::new(input.username.clone(), input.password.clone())
            .map_err(|_| AddFailure::InvalidRequest)?;
        let target = TargetAddress::new(
            IpAddr::V4(host.address),
            input.onvif_port,
            false,
            ONVIF_PATH,
        )
        .map_err(|_| AddFailure::InvalidRequest)?;
        self.take_attempt()?;
        let _one_at_a_time = self.busy.try_lock().map_err(|_| AddFailure::Busy)?;

        let camera_id = CameraId::from_uuid(Uuid::now_v7());
        // Intent first: nothing is sent to the camera unless this is recorded.
        // The user name and password are deliberately not part of it.
        self.audit(
            principal,
            "camera_add_requested",
            camera_id,
            serde_json::json!({
                "address": host.address.to_string(),
                "interface": host.interface_name,
                "onvif_port": input.onvif_port,
                "allow_basic": input.allow_basic,
                "named": name.is_some(),
            }),
        )
        .await
        .map_err(|()| AddFailure::Unavailable)?;

        let foreign = ForeignServiceFlag::default();
        let transport = DynTransport(
            self.connector
                .transport(&host, foreign.clone())
                .map_err(|_| AddFailure::Unreachable)?,
        );
        let sink = StagingSink::new(host.address, input.username.clone(), input.password.clone());
        let found = run_inventory(
            &transport,
            &sink,
            target,
            Some(&credential),
            InventoryLimits::default(),
        )
        .await;
        let found = match found {
            Ok(found) => found,
            Err(error) => {
                let failure = classify(error, &foreign, &sink);
                // Which step failed and why, never a body, address-bearing
                // value, user name or password.
                tracing::warn!(
                    step = foreign.step(),
                    http_status = ?foreign.http_status(),
                    onvif_error = ?error,
                    stream_host_mismatch = sink.mismatch(),
                    foreign_service = foreign.foreign_service(),
                    reason = failure_code(failure),
                    "camera add refused"
                );
                self.refused(principal, camera_id, &host, failure).await;
                return Err(failure);
            }
        };
        let (staged, rtsp_port) = sink.take();
        if staged.is_empty() {
            tracing::warn!(
                step = "profiles",
                reason = failure_code(AddFailure::NoStreams),
                "camera add refused"
            );
            self.refused(principal, camera_id, &host, AddFailure::NoStreams)
                .await;
            return Err(AddFailure::NoStreams);
        }

        // From here on a vault write exists. The rest runs in its own task so
        // a client that disconnects cannot stop it between the vault and the
        // store and leave a secret behind.
        let this = Arc::clone(self);
        let plan = CommitPlan {
            principal,
            camera_id,
            host,
            name,
            onvif_port: input.onvif_port,
            rtsp_port,
            allow_basic: input.allow_basic,
            found,
            staged,
        };
        tokio::spawn(async move { this.commit(plan).await })
            .await
            .map_err(|_| AddFailure::Unavailable)?
    }

    async fn refused(
        &self,
        principal: Principal,
        camera_id: CameraId,
        host: &ApprovedHost,
        failure: AddFailure,
    ) {
        let _ = self
            .audit(
                principal,
                "camera_add_refused",
                camera_id,
                serde_json::json!({
                    "address": host.address.to_string(),
                    "reason": failure_code(failure),
                }),
            )
            .await;
    }

    async fn commit(&self, plan: CommitPlan) -> Result<AddedCamera, AddFailure> {
        let CommitPlan {
            principal,
            camera_id,
            host,
            name,
            onvif_port,
            rtsp_port,
            allow_basic,
            found,
            staged,
        } = plan;
        let mut written: Vec<(StreamId, StreamSourceRef)> = Vec::with_capacity(staged.len());
        for (stream, source) in staged {
            match self
                .vault
                .put_stream_source(camera_id, stream, source)
                .await
            {
                Ok(reference) => written.push((stream, reference)),
                Err(_) => {
                    self.discard(camera_id, &written).await;
                    return Err(AddFailure::Unavailable);
                }
            }
        }
        let now = Utc::now();
        let Ok(confidence) = Confidence::new(1.0) else {
            self.discard(camera_id, &written).await;
            return Err(AddFailure::Unavailable);
        };
        let profiles: Vec<CameraProfile> = written
            .iter()
            .map(|(stream, reference)| CameraProfile::new(*stream, reference.clone()))
            .collect();
        let record = CameraRecord {
            id: camera_id,
            classification: CameraClassification::Camera,
            confidence,
            health: match found.health {
                OnvifHealth::Healthy => CameraHealth::Healthy,
                OnvifHealth::Degraded => CameraHealth::Degraded,
            },
            observed_at: now,
        };
        let inventory = CameraInventoryRecord {
            manufacturer: found.manufacturer.clone(),
            model: found.model.clone(),
            firmware: found.firmware.clone(),
            serial: found.serial.clone(),
            capabilities: found.capabilities.clone(),
            health: found.health,
        };
        let target = CameraTarget {
            camera_id,
            interface: host.interface_name.clone(),
            address: host.address,
            onvif_port,
            rtsp_port,
            allow_basic,
            approved_at: now,
            name: name.clone(),
        };
        if let Err(error) = self
            .repository
            .insert_onboarded_camera(&record, &inventory, &profiles, &target)
            .await
        {
            self.discard(camera_id, &written).await;
            return Err(match error {
                lattice_store::CameraStoreError::Conflict => AddFailure::AlreadyAdded,
                _ => AddFailure::Unavailable,
            });
        }
        self.book.register(&target).await;
        let _ = self
            .audit(
                principal,
                "camera_added",
                camera_id,
                serde_json::json!({
                    "address": host.address.to_string(),
                    "streams": written.len(),
                }),
            )
            .await;
        Ok(AddedCamera {
            camera_id,
            name,
            streams: written.iter().map(|(stream, _)| *stream).collect(),
        })
    }

    /// Removes secrets written for an add that did not complete.
    async fn discard(&self, camera_id: CameraId, written: &[(StreamId, StreamSourceRef)]) {
        if written.is_empty() {
            return;
        }
        if self
            .vault
            .delete_camera_secrets(camera_id, None, written)
            .await
            .is_err()
        {
            tracing::error!("a camera add failed and its stored secrets could not all be removed");
        }
    }

    /// Removes a camera. This is a revocation, so it acts first (live views
    /// are closed and the host approval is withdrawn before anything else) and
    /// the audit entry is written afterwards on a best-effort basis.
    pub async fn remove(
        &self,
        principal: Principal,
        camera: CameraId,
    ) -> Result<(), RemoveFailure> {
        if self
            .repository
            .load_camera(camera)
            .await
            .map_err(|_| RemoveFailure::Incomplete)?
            .is_none()
        {
            return Err(RemoveFailure::NotFound);
        }
        self.manager.close_camera_sessions(camera).await;
        self.book.unregister(camera).await;
        let mut complete = self.repository.delete_camera_target(camera).await.is_ok();
        match self.repository.load_stream_refs(camera).await {
            Ok(profiles) => {
                let references: Vec<_> = profiles
                    .iter()
                    .map(|profile| (profile.stream_id(), profile.source_ref().clone()))
                    .collect();
                if self
                    .vault
                    .delete_camera_secrets(camera, None, &references)
                    .await
                    .is_err()
                {
                    complete = false;
                }
            }
            Err(_) => complete = false,
        }
        // A view that raced the unregistration above.
        self.manager.close_camera_sessions(camera).await;
        if complete {
            complete = self.repository.delete_camera(camera).await.is_ok();
        }
        let _ = self
            .audit(
                principal,
                "camera_removed",
                camera,
                serde_json::json!({ "complete": complete }),
            )
            .await;
        if complete {
            Ok(())
        } else {
            Err(RemoveFailure::Incomplete)
        }
    }
}

struct CommitPlan {
    principal: Principal,
    camera_id: CameraId,
    host: ApprovedHost,
    name: Option<String>,
    onvif_port: u16,
    rtsp_port: u16,
    allow_basic: bool,
    found: CameraInventory,
    staged: Vec<(StreamId, SecretString)>,
}

fn classify(error: OnvifError, foreign: &ForeignServiceFlag, sink: &StagingSink) -> AddFailure {
    match error {
        OnvifError::Authentication => AddFailure::SignInRefused,
        OnvifError::Transport | OnvifError::Timeout | OnvifError::Tls => AddFailure::Unreachable,
        OnvifError::Sink if sink.mismatch() => AddFailure::StreamsElsewhere,
        OnvifError::InvalidResponse if foreign.foreign_service() => AddFailure::StreamsElsewhere,
        // The device answered the very first ONVIF request as "no such page":
        // a camera with ONVIF switched off does exactly this.
        OnvifError::InvalidResponse
            if foreign.at_first_step()
                && matches!(foreign.http_status(), Some(404 | 405 | 501)) =>
        {
            AddFailure::OnvifNotEnabled
        }
        OnvifError::Sink => AddFailure::UnexpectedAnswer,
        OnvifError::InvalidResponse
        | OnvifError::ResponseTooLarge
        | OnvifError::InvalidMetadata => AddFailure::UnexpectedAnswer,
        OnvifError::InvalidTarget
        | OnvifError::InvalidCredential
        | OnvifError::InvalidReference
        | OnvifError::RequestTooLarge
        | OnvifError::InvalidLimits => AddFailure::InvalidRequest,
    }
}

/// Checks the shape of the submitted fields and returns the cleaned name.
fn validate_input(input: &AddCameraInput) -> Result<Option<String>, AddFailure> {
    let password_len = input.password.expose_secret().len();
    if input.address.len() > 64
        || input.username.is_empty()
        || input.username.len() > MAX_USERNAME_BYTES
        || password_len == 0
        || password_len > MAX_PASSWORD_BYTES
        || input.onvif_port == 0
    {
        return Err(AddFailure::InvalidRequest);
    }
    match input.name.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(name)
            if name.chars().count() <= MAX_NAME_CHARS && !name.chars().any(char::is_control) =>
        {
            Ok(Some(name.to_owned()))
        }
        Some(_) => Err(AddFailure::InvalidRequest),
    }
}

// ---------------------------------------------------------------------------
// HTTP routes.
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AddCameraBody {
    /// The camera's IPv4 address on your network (never a hostname).
    pub address: String,
    pub username: String,
    #[schema(write_only)]
    pub password: String,
    pub name: Option<String>,
    /// Defaults to 80.
    pub onvif_port: Option<u16>,
    /// Allow the less secure RTSP Basic sign-in. Defaults to false.
    pub allow_basic: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct AddedStream {
    pub stream_id: String,
}

#[derive(Serialize, ToSchema)]
pub struct AddedCameraResponse {
    pub camera_id: String,
    pub name: Option<String>,
    pub streams: Vec<AddedStream>,
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(add_camera_route, remove_camera_route),
    components(schemas(AddCameraBody, AddedCameraResponse, AddedStream))
)]
pub struct OnboardingApiDoc;

fn failure_code(failure: AddFailure) -> &'static str {
    match failure {
        AddFailure::InvalidRequest => "invalid_request",
        AddFailure::NotOnYourNetwork(_) => "not_on_your_network",
        AddFailure::AlreadyAdded => "already_added",
        AddFailure::RateLimited => "rate_limited",
        AddFailure::Busy => "busy",
        AddFailure::Unreachable => "unreachable",
        AddFailure::SignInRefused => "sign_in_refused",
        AddFailure::UnexpectedAnswer => "unexpected_answer",
        AddFailure::StreamsElsewhere => "streams_elsewhere",
        AddFailure::NoStreams => "no_streams",
        AddFailure::OnvifNotEnabled => "onvif_not_enabled",
        AddFailure::Unavailable => "unavailable",
    }
}

fn failure_status(failure: AddFailure) -> StatusCode {
    match failure {
        AddFailure::InvalidRequest => StatusCode::BAD_REQUEST,
        AddFailure::AlreadyAdded => StatusCode::CONFLICT,
        AddFailure::RateLimited | AddFailure::Busy => StatusCode::TOO_MANY_REQUESTS,
        AddFailure::Unreachable => StatusCode::BAD_GATEWAY,
        AddFailure::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        // Not 401/403: those mean "your session is not allowed" to the app.
        AddFailure::NotOnYourNetwork(_)
        | AddFailure::SignInRefused
        | AddFailure::UnexpectedAnswer
        | AddFailure::StreamsElsewhere
        | AddFailure::NoStreams
        | AddFailure::OnvifNotEnabled => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

/// The plain sentence for the owner. It never contains the address, the user
/// name or anything the camera sent.
fn failure_message(failure: AddFailure) -> &'static str {
    match failure {
        AddFailure::InvalidRequest => "Check the address, user name and password and try again.",
        AddFailure::NotOnYourNetwork(_) => {
            "That address is not on your network. Use the camera's private address on a network this computer is connected to."
        }
        AddFailure::AlreadyAdded => "A camera is already added at that address.",
        AddFailure::RateLimited => "Too many tries. Wait a minute and try again.",
        AddFailure::Busy => "Another camera is being added. Try again in a moment.",
        AddFailure::Unreachable => {
            "Could not reach the camera. Check that it is powered on and on the same network."
        }
        AddFailure::SignInRefused => "The camera refused that user name or password.",
        AddFailure::UnexpectedAnswer => "That device did not answer like a camera.",
        AddFailure::StreamsElsewhere => {
            "The camera points its video somewhere else, so it was not added."
        }
        AddFailure::NoStreams => "The camera has no video stream to show.",
        AddFailure::OnvifNotEnabled => {
            "ONVIF does not appear to be enabled on that device. Turn ONVIF on in the camera's settings, then try again."
        }
        AddFailure::Unavailable => "The camera could not be saved. Try again shortly.",
    }
}

fn failure_response(failure: AddFailure) -> Response {
    (
        failure_status(failure),
        Json(serde_json::json!({
            "error": failure_code(failure),
            "message": failure_message(failure),
        })),
    )
        .into_response()
}

/// 503 for a machine without camera media. The `error` is a code the app maps
/// to "video support not available", and `reason` / `detail` say why.
fn video_unavailable(state: &AppState) -> Response {
    let status = state.camera_media_status();
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "video_unavailable",
            "reason": status.reason,
            "detail": status.detail,
        })),
    )
        .into_response()
}

#[utoipa::path(post, path = "/api/v1/cameras", request_body = AddCameraBody, responses((status = 201, body = AddedCameraResponse), (status = 400), (status = 401), (status = 403), (status = 409), (status = 422), (status = 429), (status = 502), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn add_camera_route(
    principal: Principal,
    State(state): State<AppState>,
    body: Result<Json<AddCameraBody>, JsonRejection>,
) -> Response {
    if principal != Principal::Owner {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(onboarding) = state.camera_onboarding() else {
        return video_unavailable(&state);
    };
    let Ok(Json(body)) = body else {
        return failure_response(AddFailure::InvalidRequest);
    };
    let input = AddCameraInput {
        address: body.address,
        username: body.username,
        password: SecretString::from(body.password),
        name: body.name,
        onvif_port: body.onvif_port.unwrap_or(DEFAULT_ONVIF_PORT),
        allow_basic: body.allow_basic.unwrap_or(false),
    };
    match onboarding.add(principal, input).await {
        Ok(added) => (
            StatusCode::CREATED,
            Json(AddedCameraResponse {
                camera_id: added.camera_id.to_string(),
                name: added.name,
                streams: added
                    .streams
                    .into_iter()
                    .map(|stream| AddedStream {
                        stream_id: stream.to_string(),
                    })
                    .collect(),
            }),
        )
            .into_response(),
        Err(failure) => failure_response(failure),
    }
}

#[utoipa::path(delete, path = "/api/v1/cameras/{id}", params(("id" = String, Path, format = Uuid, min_length = 36, max_length = 36, pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")), responses((status = 204), (status = 400), (status = 401), (status = 403), (status = 404), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn remove_camera_route(
    principal: Principal,
    State(state): State<AppState>,
    path: Result<AxumPath<String>, PathRejection>,
) -> Response {
    if principal != Principal::Owner {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(onboarding) = state.camera_onboarding() else {
        return video_unavailable(&state);
    };
    let Ok(AxumPath(camera)) = path else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(camera) = parse_camera_id(&camera) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match onboarding.remove(principal, camera).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(RemoveFailure::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(RemoveFailure::Incomplete) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "incomplete",
                "message": "The camera was turned off, but some of its stored data could not be removed yet. Remove it again to finish.",
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_sensor::{Interface, InterfaceClass};

    fn interface(
        id: u32,
        name: &str,
        class: InterfaceClass,
        up: bool,
        ips: &[(&str, u8)],
    ) -> Interface {
        Interface {
            id: InterfaceId::new(id),
            name: name.to_owned(),
            description: None,
            up,
            class,
            addresses: ips
                .iter()
                .map(|(ip, prefix)| Address {
                    ip: ip.parse().unwrap(),
                    prefix: *prefix,
                })
                .collect(),
            owner_role: None,
        }
    }

    fn inventory() -> InterfaceInventory {
        InterfaceInventory::new(vec![
            interface(1, "lo", InterfaceClass::Loopback, true, &[("127.0.0.1", 8)]),
            interface(
                2,
                "eth0",
                InterfaceClass::PhysicalWired,
                true,
                &[("192.168.1.10", 24), ("fe80::1", 64)],
            ),
            interface(
                3,
                "wlan0",
                InterfaceClass::PhysicalWifi,
                true,
                &[("10.20.0.5", 16)],
            ),
            interface(
                4,
                "wg0",
                InterfaceClass::VpnTunnel,
                true,
                &[("172.16.5.1", 24)],
            ),
            interface(
                5,
                "eth1",
                InterfaceClass::PhysicalWired,
                false,
                &[("192.168.7.1", 24)],
            ),
            interface(
                6,
                "eth2",
                InterfaceClass::PhysicalWired,
                true,
                &[("203.0.113.9", 24)],
            ),
        ])
    }

    #[test]
    fn private_addresses_inside_a_usable_subnet_are_approved_on_that_interface() {
        let wired = approve_address("192.168.1.50", &inventory()).unwrap();
        assert_eq!(wired.interface_name, "eth0");
        assert_eq!(wired.address, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(
            wired.binding.source,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(
            wired.binding.target,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))
        );
        // Surrounding whitespace is not part of the literal.
        assert_eq!(
            approve_address(" 192.168.1.50 ", &inventory()).unwrap(),
            wired
        );
        let wifi = approve_address("10.20.200.7", &inventory()).unwrap();
        assert_eq!(wifi.interface_name, "wlan0");
        assert_eq!(wifi.binding.source, IpAddr::V4(Ipv4Addr::new(10, 20, 0, 5)));
    }

    #[test]
    fn the_address_validation_table() {
        use AddressRefusal::{
            NetworkOrBroadcast, NotAnIpAddress, NotOnLocalNetwork, NotPrivateIpv4, OwnAddress,
        };
        let table: &[(&str, AddressRefusal)] = &[
            // Not literals: no DNS is ever involved.
            ("camera.local", NotAnIpAddress),
            ("camera", NotAnIpAddress),
            ("", NotAnIpAddress),
            ("192.168.1.50.nip.io", NotAnIpAddress),
            ("192.168.1.50:80", NotAnIpAddress),
            ("http://192.168.1.50", NotAnIpAddress),
            ("0xC0A80132", NotAnIpAddress),
            ("3232235826", NotAnIpAddress),
            ("192.168.001.050", NotAnIpAddress),
            // Not private unicast IPv4.
            ("127.0.0.1", NotPrivateIpv4),
            ("127.1.2.3", NotPrivateIpv4),
            ("169.254.1.1", NotPrivateIpv4),
            ("224.0.0.251", NotPrivateIpv4),
            ("239.255.255.250", NotPrivateIpv4),
            ("255.255.255.255", NotPrivateIpv4),
            ("0.0.0.0", NotPrivateIpv4),
            ("8.8.8.8", NotPrivateIpv4),
            ("203.0.113.50", NotPrivateIpv4),
            ("100.64.0.1", NotPrivateIpv4),
            ("::1", NotPrivateIpv4),
            ("fe80::1", NotPrivateIpv4),
            ("fd00::5", NotPrivateIpv4),
            ("::ffff:192.168.1.50", NotPrivateIpv4),
            // This machine's own addresses.
            ("192.168.1.10", OwnAddress),
            ("10.20.0.5", OwnAddress),
            ("172.16.5.1", OwnAddress),
            // The subnet's network and broadcast addresses.
            ("192.168.1.0", NetworkOrBroadcast),
            ("192.168.1.255", NetworkOrBroadcast),
            ("10.20.255.255", NetworkOrBroadcast),
            // Private, but not in any usable subnet.
            ("192.168.2.50", NotOnLocalNetwork),
            ("10.21.0.5", NotOnLocalNetwork),
            ("10.0.0.1", NotOnLocalNetwork),
            // A tunnel, and an interface that is down, do not count.
            ("172.16.5.9", NotOnLocalNetwork),
            ("192.168.7.9", NotOnLocalNetwork),
        ];
        for (input, expected) in table {
            assert_eq!(
                approve_address(input, &inventory()),
                Err(*expected),
                "{input:?}"
            );
        }
    }

    #[test]
    fn a_subnet_that_is_not_private_cannot_carry_a_camera() {
        // eth2 is up and wired but holds a public address; a private camera
        // address is not in its subnet, and its own subnet is not private.
        assert_eq!(
            approve_address("203.0.113.50", &inventory()),
            Err(AddressRefusal::NotPrivateIpv4)
        );
        assert_eq!(
            approve_address("192.168.9.9", &inventory()),
            Err(AddressRefusal::NotOnLocalNetwork)
        );
    }

    #[test]
    fn an_interface_marked_corporate_is_not_used() {
        let mut corporate = interface(
            2,
            "eth0",
            InterfaceClass::PhysicalWired,
            true,
            &[("192.168.1.10", 24)],
        );
        corporate.owner_role = Some(lattice_sensor::InterfaceRole::Corporate);
        assert_eq!(
            approve_address("192.168.1.50", &InterfaceInventory::new(vec![corporate])),
            Err(AddressRefusal::NotOnLocalNetwork)
        );
    }

    fn sink(host: Ipv4Addr) -> StagingSink {
        StagingSink::new(
            host,
            "admin".to_owned(),
            SecretString::from("pa:ss/w@rd%41#?"),
        )
    }

    fn stream(uri: &str) -> Vec<(StreamId, SecretString)> {
        vec![(StreamId::new(), SecretString::from(uri))]
    }

    #[test]
    fn staged_sources_embed_the_sign_in_exactly_and_name_the_approved_host() {
        let host = Ipv4Addr::new(192, 168, 1, 50);
        let sink = sink(host);
        sink.store_all(stream("rtsp://192.168.1.50:8554/live/main?x=1"))
            .unwrap();
        let (staged, port) = sink.take();
        assert_eq!(port, 8554);
        let source = staged[0].1.expose_secret().to_owned();
        // The media proxy reads back exactly what the owner typed.
        let parsed = Upstream::parse(SecretString::from(source.clone())).unwrap();
        assert_eq!(parsed.host, IpAddr::V4(host));
        assert_eq!(parsed.port, 8554);
        assert_eq!(parsed.username.as_deref(), Some("admin"));
        assert_eq!(
            parsed.password.as_ref().unwrap().expose_secret(),
            "pa:ss/w@rd%41#?"
        );
        assert!(
            !source.contains("pa:ss/w@rd%41#?"),
            "password is percent-encoded"
        );
    }

    #[test]
    fn a_sign_in_the_camera_embedded_in_its_own_address_is_replaced() {
        let host = Ipv4Addr::new(192, 168, 1, 50);
        let sink = sink(host);
        sink.store_all(stream("rtsp://root:factory@192.168.1.50/main"))
            .unwrap();
        let (staged, port) = sink.take();
        assert_eq!(port, 554);
        assert!(!staged[0].1.expose_secret().contains("factory"));
        assert!(staged[0].1.expose_secret().starts_with("rtsp://admin:"));
    }

    #[test]
    fn stream_addresses_on_another_host_or_port_refuse_the_whole_batch() {
        let host = Ipv4Addr::new(192, 168, 1, 50);
        for elsewhere in [
            "rtsp://192.168.1.51/main",
            "rtsp://127.0.0.1/main",
            "rtsp://evil.example/main",
            "rtsp://192.168.1.50.evil.example/main",
        ] {
            let sink = sink(host);
            assert_eq!(
                sink.store_all(stream(elsewhere)).unwrap_err(),
                OnvifError::Sink,
                "{elsewhere}"
            );
            assert!(sink.mismatch(), "{elsewhere}");
            assert!(sink.take().0.is_empty(), "nothing is staged");
        }
        // One good address does not excuse a bad one beside it.
        let sink = sink(host);
        let mixed = vec![
            (StreamId::new(), SecretString::from("rtsp://192.168.1.50/a")),
            (StreamId::new(), SecretString::from("rtsp://192.168.1.99/b")),
        ];
        assert!(sink.store_all(mixed).is_err());
        assert!(sink.take().0.is_empty());
        // Two ports under one approval are refused too.
        let sink = self::sink(host);
        let ports = vec![
            (
                StreamId::new(),
                SecretString::from("rtsp://192.168.1.50:554/a"),
            ),
            (
                StreamId::new(),
                SecretString::from("rtsp://192.168.1.50:8554/b"),
            ),
        ];
        assert!(sink.store_all(ports).is_err());
        assert!(sink.mismatch());
        // Not RTSP at all is unusable, not "elsewhere".
        let sink = self::sink(host);
        assert!(sink.store_all(stream("http://192.168.1.50/x")).is_err());
        assert!(!sink.mismatch());
    }

    fn target(camera: u128, address: Ipv4Addr, interface: &str) -> CameraTarget {
        CameraTarget {
            camera_id: CameraId::from_uuid(Uuid::from_u128(camera)),
            interface: interface.to_owned(),
            address,
            onvif_port: 80,
            rtsp_port: 554,
            allow_basic: true,
            approved_at: Utc::now(),
            name: None,
        }
    }

    #[tokio::test]
    async fn the_book_approves_only_what_still_matches_the_live_network() {
        let interfaces = Arc::new(FixedInterfaces::new(inventory()));
        let book = CameraTargetBook::new(interfaces.clone());
        let camera = CameraId::from_uuid(Uuid::from_u128(1));
        let stream = StreamId::from_uuid(Uuid::from_u128(2));
        assert!(book.is_empty().await);
        assert!(book.authorized_binding(camera, stream).await.is_err());

        book.register(&target(1, Ipv4Addr::new(192, 168, 1, 50), "eth0"))
            .await;
        assert!(book.address_in_use(Ipv4Addr::new(192, 168, 1, 50)).await);
        let approved = book.authorized_binding(camera, stream).await.unwrap();
        assert_eq!(approved.port(), 554);
        assert!(approved.basic_auth_allowed());
        assert_eq!(
            approved.binding().target,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))
        );
        assert_eq!(
            approved.binding().source,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))
        );

        // The interface goes down: refused, then approved again when it is back.
        let before = inventory();
        let down = InterfaceInventory::new(
            before
                .interfaces()
                .map(|i| Interface {
                    up: i.up && i.name != "eth0",
                    ..i.clone()
                })
                .collect(),
        );
        interfaces.set(down);
        assert!(book.authorized_binding(camera, stream).await.is_err());
        interfaces.set(inventory());
        assert!(book.authorized_binding(camera, stream).await.is_ok());

        // The subnet changes under the stored address: refused.
        interfaces.set(InterfaceInventory::new(vec![interface(
            2,
            "eth0",
            InterfaceClass::PhysicalWired,
            true,
            &[("192.168.2.10", 24)],
        )]));
        assert!(book.authorized_binding(camera, stream).await.is_err());

        // The address now belongs to this machine: refused.
        interfaces.set(InterfaceInventory::new(vec![interface(
            2,
            "eth0",
            InterfaceClass::PhysicalWired,
            true,
            &[("192.168.1.50", 24)],
        )]));
        assert!(book.authorized_binding(camera, stream).await.is_err());

        // The interface the address was approved on is gone, but another
        // interface covers the same subnet: still refused, the approval
        // names an interface.
        interfaces.set(InterfaceInventory::new(vec![interface(
            9,
            "eth9",
            InterfaceClass::PhysicalWired,
            true,
            &[("192.168.1.10", 24)],
        )]));
        assert!(book.authorized_binding(camera, stream).await.is_err());

        book.unregister(camera).await;
        interfaces.set(inventory());
        assert!(book.authorized_binding(camera, stream).await.is_err());
    }

    #[tokio::test]
    async fn the_book_is_rebuilt_from_the_store() {
        let pool = lattice_store::connect_memory().await.unwrap();
        let repository = CameraRepository::new(pool);
        let stored = target(7, Ipv4Addr::new(10, 20, 3, 4), "wlan0");
        repository
            .upsert_camera(&CameraRecord {
                id: stored.camera_id,
                classification: CameraClassification::Camera,
                confidence: Confidence::new(1.0).unwrap(),
                health: CameraHealth::Unknown,
                observed_at: Utc::now(),
            })
            .await
            .unwrap();
        repository.put_camera_target(&stored).await.unwrap();
        let book = CameraTargetBook::new(Arc::new(FixedInterfaces::new(inventory())));
        assert_eq!(book.load(&repository).await.unwrap(), 1);
        assert_eq!(book.len().await, 1);
        assert!(
            book.authorized_binding(stored.camera_id, StreamId::new())
                .await
                .is_ok()
        );
    }

    #[test]
    fn input_validation_cleans_the_name_and_bounds_the_fields() {
        let input =
            |name: Option<&str>, username: &str, password: &str, port: u16| AddCameraInput {
                address: "192.168.1.50".to_owned(),
                username: username.to_owned(),
                password: SecretString::from(password),
                name: name.map(str::to_owned),
                onvif_port: port,
                allow_basic: false,
            };
        assert_eq!(validate_input(&input(None, "u", "p", 80)), Ok(None));
        assert_eq!(validate_input(&input(Some("  "), "u", "p", 80)), Ok(None));
        assert_eq!(
            validate_input(&input(Some(" Porch "), "u", "p", 80)),
            Ok(Some("Porch".to_owned()))
        );
        for bad in [
            input(Some(&"n".repeat(65)), "u", "p", 80),
            input(Some("a\nb"), "u", "p", 80),
            input(None, "", "p", 80),
            input(None, &"u".repeat(129), "p", 80),
            input(None, "u", "", 80),
            input(None, "u", &"p".repeat(257), 80),
            input(None, "u", "p", 0),
        ] {
            assert_eq!(validate_input(&bad), Err(AddFailure::InvalidRequest));
        }
    }
}
