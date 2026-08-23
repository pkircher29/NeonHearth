//! Guarded, bounded active discovery. Network I/O is reachable only through `ActiveEngine`.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lattice_domain::{EvidenceFact, EvidenceFamily};
use secrecy::SecretString;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
    sync::Notify,
};

use crate::{InterfaceId, TargetGuard};

pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;
pub const MAX_FACT_VALUE_BYTES: usize = 512;
pub const MAX_QUEUE: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ProbeTransport {
    Icmp,
    LinkLayer,
    Tcp,
    Tls,
    Udp,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredPrivilege {
    None,
    Raw,
    Admin,
    Credential,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeDescriptor {
    pub id: String,
    pub version: u16,
    pub transport: ProbeTransport,
    pub ports: Vec<u16>,
    pub privilege: RequiredPrivilege,
    pub potential_side_effects: &'static str,
    pub timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub evidence_families: Vec<EvidenceFamily>,
    pub credential_required: bool,
    pub owner_start_required: bool,
    request: Vec<u8>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CatalogError {
    #[error("duplicate probe id")]
    Duplicate,
    #[error("invalid probe descriptor")]
    Invalid,
}

#[derive(Clone, Debug)]
pub struct ProbeCatalog {
    descriptors: BTreeMap<String, ProbeDescriptor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CuratedPlan {
    Default,
    OwnerFullPort,
}

impl ProbeCatalog {
    pub fn new(items: Vec<ProbeDescriptor>) -> Result<Self, CatalogError> {
        let mut descriptors = BTreeMap::new();
        for item in items {
            if item.id.is_empty()
                || item.version == 0
                || item.ports.is_empty()
                || item.max_request_bytes > 4096
                || item.max_response_bytes > MAX_RESPONSE_BYTES
                || item.request.len() > item.max_request_bytes
            {
                return Err(CatalogError::Invalid);
            }
            if descriptors.insert(item.id.clone(), item).is_some() {
                return Err(CatalogError::Duplicate);
            }
        }
        Ok(Self { descriptors })
    }
    pub fn len(&self) -> usize {
        self.descriptors.len()
    }
    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }
    pub fn get(&self, id: &str) -> Option<&ProbeDescriptor> {
        self.descriptors.get(id)
    }
    pub fn plan(&self, plan: CuratedPlan) -> Vec<&ProbeDescriptor> {
        self.descriptors
            .values()
            .filter(|p| match plan {
                CuratedPlan::Default => !p.owner_start_required,
                CuratedPlan::OwnerFullPort => p.owner_start_required,
            })
            .collect()
    }
}

fn descriptor(
    id: &str,
    transport: ProbeTransport,
    port: u16,
    privilege: RequiredPrivilege,
    request: &[u8],
) -> ProbeDescriptor {
    ProbeDescriptor {
        id: id.into(),
        version: 1,
        transport,
        ports: vec![port],
        privilege,
        potential_side_effects: "May create a normal service connection or one unicast request",
        timeout: Duration::from_secs(3),
        max_request_bytes: 1024,
        max_response_bytes: 4096,
        evidence_families: vec![EvidenceFamily::Service],
        credential_required: privilege == RequiredPrivilege::Credential,
        owner_start_required: false,
        request: request.to_vec(),
    }
}

pub fn catalog() -> Result<ProbeCatalog, CatalogError> {
    let tcp = [
        ("ssh", 22),
        ("ftp", 21),
        ("telnet", 23),
        ("smtp", 25),
        ("dns", 53),
        ("http", 80),
        ("https", 443),
        ("smb", 445),
        ("rdp", 3389),
        ("vnc", 5900),
        ("mqtt", 1883),
        ("mqtts", 8883),
        ("amqp", 5672),
        ("amqps", 5671),
        ("rtsp", 554),
        ("ipp", 631),
        ("printer", 9100),
        ("camera-web", 8080),
        ("camera-alt", 8000),
        ("mysql", 3306),
        ("postgres", 5432),
        ("mssql", 1433),
        ("redis", 6379),
        ("mongodb", 27017),
        ("oracle", 1521),
        ("coap-tcp", 5683),
        ("home-assistant", 8123),
        ("upnp-web", 5000),
    ];
    let mut items: Vec<_> = tcp
        .into_iter()
        .map(|(name, port)| {
            let request = if name == "http"
                || name == "camera-web"
                || name == "camera-alt"
                || name == "upnp-web"
                || name == "home-assistant"
            {
                b"HEAD / HTTP/1.0\r\nConnection: close\r\n\r\n".as_slice()
            } else {
                &[]
            };
            let transport = if matches!(name, "https" | "mqtts" | "amqps") {
                ProbeTransport::Tls
            } else {
                ProbeTransport::Tcp
            };
            descriptor(
                &format!("tcp.{name}.{port}"),
                transport,
                port,
                RequiredPrivilege::None,
                request,
            )
        })
        .collect();
    let udp: [(&str, u16, &[u8]); 11] = [
        (
            "dns",
            53,
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01",
        ),
        ("dhcp", 67, b""),
        ("ntp", 123, b"\x1b\0\0\0\0\0\0\0"),
        (
            "ssdp",
            1900,
            b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\nMX: 1\r\n\r\n",
        ),
        ("nbns", 137, b"\x12\x34\x01\x10\0\x01\0\0\0\0\0\0"),
        ("mdns", 5353, b"\x12\x34\0\0\0\0\0\0\0\0\0\0"),
        (
            "ws-discovery",
            3702,
            b"<e:Envelope xmlns:e='http://www.w3.org/2003/05/soap-envelope'/>",
        ),
        (
            "onvif",
            3702,
            b"<e:Envelope xmlns:e='http://www.w3.org/2003/05/soap-envelope'/>",
        ),
        (
            "sip",
            5060,
            b"OPTIONS sip:device SIP/2.0\r\nContent-Length: 0\r\n\r\n",
        ),
        ("coap", 5683, b"\x40\x01\x12\x34"),
        ("iot", 6666, b"\0\0\0\0"),
    ];
    items.extend(udp.into_iter().map(|(name, port, req)| {
        descriptor(
            &format!("udp.{name}.{port}"),
            ProbeTransport::Udp,
            port,
            RequiredPrivilege::None,
            req,
        )
    }));
    let mut snmp = descriptor(
        "udp.snmp.161",
        ProbeTransport::Udp,
        161,
        RequiredPrivilege::Credential,
        b"",
    );
    snmp.owner_start_required = true;
    items.push(snmp);
    items.push(descriptor(
        "icmp.echo.v4",
        ProbeTransport::Icmp,
        0,
        RequiredPrivilege::Raw,
        b"",
    ));
    items.push(descriptor(
        "icmp.echo.v6",
        ProbeTransport::Icmp,
        0,
        RequiredPrivilege::Raw,
        b"",
    ));
    items.push(descriptor(
        "link.arp",
        ProbeTransport::LinkLayer,
        0,
        RequiredPrivilege::Raw,
        b"",
    ));
    items.push(descriptor(
        "link.ndp",
        ProbeTransport::LinkLayer,
        0,
        RequiredPrivilege::Raw,
        b"",
    ));
    for port in 1..=64u16 {
        let mut p = descriptor(
            &format!("full.tcp.{port}"),
            ProbeTransport::Tcp,
            port,
            RequiredPrivilege::None,
            b"",
        );
        p.owner_start_required = true;
        items.push(p);
    }
    ProbeCatalog::new(items)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProbeMode {
    Default,
    OwnerFullPort,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeRequest {
    pub interface: InterfaceId,
    pub target: IpAddr,
    pub probe_id: String,
    pub mode: ProbeMode,
    pub owner_approved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportResponse {
    Success(Vec<(String, String)>),
    Refused,
    Timeout,
}
#[derive(Clone, Debug, PartialEq)]
pub enum ProbeOutcome {
    Success { facts: Vec<EvidenceFact> },
    Refused { source: String },
    Timeout { source: String },
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ActiveError {
    #[error("target authorization failed")]
    Unauthorized,
    #[error("unknown probe")]
    UnknownProbe,
    #[error("owner approval required")]
    OwnerApprovalRequired,
    #[error("credential required")]
    CredentialRequired,
    #[error("operation cancelled")]
    Cancelled,
    #[error("probe unavailable")]
    Unavailable,
    #[error("probe permission denied")]
    PermissionDenied,
    #[error("bounded network operation failed")]
    Network,
    #[error("response exceeded limit")]
    ResponseLimit,
    #[error("invalid scheduler configuration")]
    InvalidConfig,
    #[error("scheduler queue is full")]
    QueueFull,
}

#[async_trait]
pub trait ActiveProbeAdapter: Send + Sync {
    fn descriptor(&self) -> &ProbeDescriptor;
    async fn execute(
        &self,
        request: &ProbeRequest,
        credential: Option<&SecretString>,
    ) -> Result<TransportResponse, ActiveError>;
}

#[async_trait]
pub trait AttemptTransport: Send + Sync {
    async fn attempt(
        &self,
        request: &ProbeRequest,
        descriptor: &ProbeDescriptor,
        credential: Option<&SecretString>,
    ) -> Result<TransportResponse, ActiveError>;
}

pub struct ActiveEngine<T> {
    guard: Arc<TargetGuard>,
    transport: Arc<T>,
    catalog: ProbeCatalog,
    stopped: AtomicBool,
    stop_notify: Notify,
}
impl<T: AttemptTransport> ActiveEngine<T> {
    pub fn new(guard: Arc<TargetGuard>, transport: Arc<T>, catalog: ProbeCatalog) -> Self {
        Self {
            guard,
            transport,
            catalog,
            stopped: AtomicBool::new(false),
            stop_notify: Notify::new(),
        }
    }
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.stop_notify.notify_waiters();
    }
    pub async fn execute(
        &self,
        request: ProbeRequest,
        credential: Option<&SecretString>,
    ) -> Result<ProbeOutcome, ActiveError> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(ActiveError::Cancelled);
        }
        let descriptor = self
            .catalog
            .get(&request.probe_id)
            .ok_or(ActiveError::UnknownProbe)?;
        if !request.owner_approved {
            return Err(ActiveError::OwnerApprovalRequired);
        }
        if descriptor.owner_start_required && request.mode != ProbeMode::OwnerFullPort {
            return Err(ActiveError::OwnerApprovalRequired);
        }
        if descriptor.credential_required && credential.is_none() {
            return Err(ActiveError::CredentialRequired);
        }
        // This check is deliberately adjacent to the only transport call. The target and
        // interface are immutable fields of the request passed to the transport.
        self.guard
            .authorize(request.interface, request.target)
            .map_err(|_| ActiveError::Unauthorized)?;
        let response = tokio::select! {
            biased;
            () = self.stop_notify.notified() => return Err(ActiveError::Cancelled),
            result = tokio::time::timeout(descriptor.timeout, self.transport.attempt(&request, descriptor, credential)) => {
                result.map_err(|_| ActiveError::Network)??
            }
        };
        normalize(descriptor, response)
    }
}

fn normalize(
    descriptor: &ProbeDescriptor,
    response: TransportResponse,
) -> Result<ProbeOutcome, ActiveError> {
    let source = format!("active.{}.v{}", descriptor.id, descriptor.version);
    match response {
        TransportResponse::Refused => Ok(ProbeOutcome::Refused { source }),
        TransportResponse::Timeout => Ok(ProbeOutcome::Timeout { source }),
        TransportResponse::Success(values) => {
            if values.len() > 32 {
                return Err(ActiveError::ResponseLimit);
            }
            let now = Utc::now();
            let mut facts = Vec::new();
            for (key, value) in values {
                if key.len() > 64 || value.len() > MAX_FACT_VALUE_BYTES {
                    return Err(ActiveError::ResponseLimit);
                }
                facts.push(EvidenceFact {
                    family: EvidenceFamily::Service,
                    source: source.clone(),
                    key,
                    value,
                    confidence: 0.7,
                    observed_at: now,
                    expires_at: now.checked_add_signed(chrono::Duration::minutes(10)),
                    owner_confirmed: false,
                });
            }
            Ok(ProbeOutcome::Success { facts })
        }
    }
}

/// Bounded numeric-target transport. It never resolves names and never follows redirects.
pub struct SystemTransport;
#[async_trait]
impl AttemptTransport for SystemTransport {
    async fn attempt(
        &self,
        request: &ProbeRequest,
        descriptor: &ProbeDescriptor,
        _credential: Option<&SecretString>,
    ) -> Result<TransportResponse, ActiveError> {
        let port = *descriptor.ports.first().ok_or(ActiveError::Unavailable)?;
        match descriptor.transport {
            ProbeTransport::Tcp => tcp_attempt(request.target, port, descriptor).await,
            ProbeTransport::Udp => udp_attempt(request.target, port, descriptor).await,
            // Raw ICMP/link-layer access is an explicit platform boundary. Until the
            // privileged capture backend is installed it reports unavailable, never success.
            ProbeTransport::Icmp => icmp_attempt(request.target, descriptor.timeout).await,
            ProbeTransport::LinkLayer => Err(ActiveError::PermissionDenied),
            ProbeTransport::Tls => Err(ActiveError::Unavailable),
        }
    }
}

async fn icmp_attempt(ip: IpAddr, timeout: Duration) -> Result<TransportResponse, ActiveError> {
    use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence, SurgeError};
    let config = Config::builder()
        .kind(if ip.is_ipv4() { ICMP::V4 } else { ICMP::V6 })
        .build();
    let client = Client::new(&config).map_err(|error| match error.kind() {
        std::io::ErrorKind::PermissionDenied => ActiveError::PermissionDenied,
        std::io::ErrorKind::Unsupported => ActiveError::Unavailable,
        _ => ActiveError::Network,
    })?;
    let mut pinger = client.pinger(ip, PingIdentifier(0x4e48)).await;
    pinger.timeout(timeout);
    match pinger.ping(PingSequence(0), b"NeonHearth").await {
        Ok((_packet, latency)) => Ok(TransportResponse::Success(vec![(
            "latency_ms".into(),
            latency.as_millis().to_string(),
        )])),
        Err(SurgeError::IOError(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(ActiveError::PermissionDenied)
        }
        Err(SurgeError::Timeout { .. }) => Ok(TransportResponse::Timeout),
        Err(_) => Err(ActiveError::Network),
    }
}

async fn tcp_attempt(
    ip: IpAddr,
    port: u16,
    d: &ProbeDescriptor,
) -> Result<TransportResponse, ActiveError> {
    let socket = match ip {
        IpAddr::V4(_) => TcpSocket::new_v4(),
        IpAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|_| ActiveError::Network)?;
    let mut stream = match socket.connect(SocketAddr::new(ip, port)).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            return Ok(TransportResponse::Refused);
        }
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            return Ok(TransportResponse::Timeout);
        }
        Err(_) => return Err(ActiveError::Network),
    };
    let request = if d.id.contains("http") || d.id.contains("camera") || d.id.contains("web") {
        format!("HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n").into_bytes()
    } else {
        d.request.clone()
    };
    if !request.is_empty() {
        stream
            .write_all(&request)
            .await
            .map_err(|_| ActiveError::Network)?;
    }
    let mut buf = vec![0; d.max_response_bytes.min(MAX_RESPONSE_BYTES)];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    buf.truncate(n);
    let metadata = if d.id.contains("http") || d.id.contains("camera") || d.id.contains("web") {
        parse_http_metadata(&buf)?
    } else {
        let text = String::from_utf8_lossy(&buf);
        let first: String = text
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(MAX_FACT_VALUE_BYTES)
            .collect();
        if first.is_empty() {
            vec![]
        } else {
            vec![("banner".into(), first)]
        }
    };
    Ok(TransportResponse::Success(metadata))
}

/// Extracts only allowlisted HTTP metadata. Bodies and redirect locations are ignored.
pub fn parse_http_metadata(bytes: &[u8]) -> Result<Vec<(String, String)>, ActiveError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ActiveError::ResponseLimit);
    }
    let head = bytes.split(|byte| *byte == b'\n').take(64);
    let mut facts = Vec::new();
    for (index, raw) in head.enumerate() {
        let line = std::str::from_utf8(raw)
            .map_err(|_| ActiveError::Network)?
            .trim_end_matches('\r');
        if index == 0 {
            if let Some(status) = line
                .split_ascii_whitespace()
                .nth(1)
                .filter(|value| value.len() == 3 && value.bytes().all(|b| b.is_ascii_digit()))
            {
                facts.push(("status".into(), status.into()));
            }
            continue;
        }
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let key = if name.eq_ignore_ascii_case("server") {
            Some("server")
        } else if name.eq_ignore_ascii_case("content-type") {
            Some("content_type")
        } else {
            None
        };
        if let Some(key) = key {
            let value: String = value
                .trim()
                .chars()
                .take(MAX_FACT_VALUE_BYTES)
                .filter(|c| !c.is_control())
                .collect();
            facts.push((key.into(), value));
        }
    }
    Ok(facts)
}

async fn udp_attempt(
    ip: IpAddr,
    port: u16,
    d: &ProbeDescriptor,
) -> Result<TransportResponse, ActiveError> {
    if d.request.is_empty() {
        return Err(ActiveError::Unavailable);
    }
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|_| ActiveError::Network)?;
    socket
        .connect(SocketAddr::new(ip, port))
        .await
        .map_err(|_| ActiveError::Network)?;
    socket
        .send(&d.request)
        .await
        .map_err(|_| ActiveError::Network)?;
    let mut response = vec![0u8; d.max_response_bytes.min(MAX_RESPONSE_BYTES)];
    let n = socket
        .recv(&mut response)
        .await
        .map_err(|_| ActiveError::Network)?;
    if n > d.max_response_bytes {
        return Err(ActiveError::ResponseLimit);
    }
    Ok(TransportResponse::Success(vec![(
        "response_bytes".into(),
        n.to_string(),
    )]))
}

#[derive(Clone, Copy, Debug)]
pub struct BudgetConfig {
    pub global_concurrency: usize,
    pub per_host_concurrency: usize,
    pub per_subnet_burst: usize,
    pub refill: Duration,
}
impl BudgetConfig {
    pub fn new(
        global: usize,
        host: usize,
        subnet: usize,
        refill: Duration,
    ) -> Result<Self, ActiveError> {
        if global == 0
            || global > 256
            || host == 0
            || host > 16
            || host > global
            || subnet == 0
            || subnet > 1024
            || refill.is_zero()
            || refill > Duration::from_secs(3600)
        {
            return Err(ActiveError::InvalidConfig);
        }
        Ok(Self {
            global_concurrency: global,
            per_host_concurrency: host,
            per_subnet_burst: subnet,
            refill,
        })
    }
}
impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            global_concurrency: 32,
            per_host_concurrency: 2,
            per_subnet_burst: 64,
            refill: Duration::from_secs(1),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SchedulerConfig {
    pub budgets: BudgetConfig,
    pub queue_capacity: usize,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    pub jitter_percent: u8,
}
impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            budgets: BudgetConfig::default(),
            queue_capacity: 2048,
            base_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            jitter_percent: 10,
        }
    }
}

pub trait Clock: Send + Sync {
    fn monotonic(&self) -> Duration;
    fn wall(&self) -> DateTime<Utc>;
    fn jitter_unit(&self) -> u32;
}
pub struct FakeClock {
    wall: DateTime<Utc>,
    monotonic_nanos: AtomicU64,
    jitter: AtomicU64,
}
impl FakeClock {
    pub fn new(wall: DateTime<Utc>) -> Self {
        Self {
            wall,
            monotonic_nanos: AtomicU64::new(0),
            jitter: AtomicU64::new(0),
        }
    }
    pub fn advance(&self, duration: Duration) {
        self.monotonic_nanos.fetch_add(
            duration.as_nanos().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }
    pub fn set_jitter_unit(&self, value: u32) {
        self.jitter.store(u64::from(value), Ordering::Relaxed);
    }
}
impl Clock for FakeClock {
    fn monotonic(&self) -> Duration {
        Duration::from_nanos(self.monotonic_nanos.load(Ordering::Relaxed))
    }
    fn wall(&self) -> DateTime<Utc> {
        self.wall
    }
    fn jitter_unit(&self) -> u32 {
        self.jitter.load(Ordering::Relaxed) as u32
    }
}
pub struct SystemClock {
    started: Instant,
}
impl Default for SystemClock {
    fn default() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}
impl Clock for SystemClock {
    fn monotonic(&self) -> Duration {
        self.started.elapsed()
    }
    fn wall(&self) -> DateTime<Utc> {
        Utc::now()
    }
    fn jitter_unit(&self) -> u32 {
        self.started.elapsed().subsec_nanos()
    }
}

pub struct Scheduler<C> {
    config: SchedulerConfig,
    clock: Arc<C>,
    high: BTreeMap<IpAddr, VecDeque<ProbeRequest>>,
    low: VecDeque<ProbeRequest>,
    hosts: VecDeque<IpAddr>,
    queued: BTreeSet<(InterfaceId, IpAddr, String, ProbeMode)>,
    failures: HashMap<String, u8>,
    stopped: bool,
    active: usize,
    active_hosts: HashMap<IpAddr, usize>,
    host_rates: HashMap<IpAddr, TokenBucket>,
    subnet_rates: HashMap<SubnetKey, TokenBucket>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SubnetKey {
    V4(u32),
    V6(u128),
}
fn subnet(ip: IpAddr) -> SubnetKey {
    match ip {
        IpAddr::V4(ip) => SubnetKey::V4(u32::from(ip) & 0xffff_ff00),
        IpAddr::V6(ip) => SubnetKey::V6(u128::from(ip) & (u128::MAX << 64)),
    }
}
struct TokenBucket {
    tokens: usize,
    last: Duration,
}
impl TokenBucket {
    fn available(&mut self, now: Duration, capacity: usize, refill: Duration) -> bool {
        if now > self.last && now.saturating_sub(self.last) >= refill {
            let periods = now.saturating_sub(self.last).as_nanos() / refill.as_nanos();
            self.tokens = self
                .tokens
                .saturating_add(periods.min(usize::MAX as u128) as usize)
                .min(capacity);
            self.last = self
                .last
                .saturating_add(refill.saturating_mul(periods.min(u128::from(u32::MAX)) as u32));
        }
        self.tokens > 0
    }
}
impl<C: Clock> Scheduler<C> {
    pub fn new(config: SchedulerConfig, clock: Arc<C>) -> Result<Self, ActiveError> {
        BudgetConfig::new(
            config.budgets.global_concurrency,
            config.budgets.per_host_concurrency,
            config.budgets.per_subnet_burst,
            config.budgets.refill,
        )?;
        if config.queue_capacity == 0
            || config.queue_capacity > MAX_QUEUE
            || config.base_backoff.is_zero()
            || config.max_backoff < config.base_backoff
            || config.jitter_percent > 25
        {
            return Err(ActiveError::InvalidConfig);
        }
        Ok(Self {
            config,
            clock,
            high: BTreeMap::new(),
            low: VecDeque::new(),
            hosts: VecDeque::new(),
            queued: BTreeSet::new(),
            failures: HashMap::new(),
            stopped: false,
            active: 0,
            active_hosts: HashMap::new(),
            host_rates: HashMap::new(),
            subnet_rates: HashMap::new(),
        })
    }
    pub fn enqueue(&mut self, request: ProbeRequest) -> Result<bool, ActiveError> {
        if self.stopped {
            return Err(ActiveError::Cancelled);
        }
        if self.queued.len() >= self.config.queue_capacity {
            return Err(ActiveError::QueueFull);
        }
        let key = (
            request.interface,
            request.target,
            request.probe_id.clone(),
            request.mode,
        );
        if !self.queued.insert(key) {
            return Ok(false);
        }
        if request.mode == ProbeMode::OwnerFullPort {
            self.low.push_back(request);
        } else {
            if !self.high.contains_key(&request.target) {
                self.hosts.push_back(request.target);
            }
            self.high
                .entry(request.target)
                .or_default()
                .push_back(request);
        }
        Ok(true)
    }
    pub fn next_request(&mut self) -> Option<ProbeRequest> {
        if self.stopped {
            return None;
        }
        let request = if let Some(host) = self.hosts.pop_front() {
            let queue = self.high.get_mut(&host)?;
            let item = queue.pop_front();
            if queue.is_empty() {
                self.high.remove(&host);
            } else {
                self.hosts.push_back(host);
            }
            item
        } else {
            self.low.pop_front()
        }?;
        self.queued.remove(&(
            request.interface,
            request.target,
            request.probe_id.clone(),
            request.mode,
        ));
        Some(request)
    }
    pub fn stop(&mut self) {
        self.stopped = true;
        self.high.clear();
        self.low.clear();
        self.hosts.clear();
        self.queued.clear();
    }
    /// Atomically reserves concurrency and rate budgets. Uses monotonic time, so wall-clock
    /// corrections do not create bursts. After suspend, refill is capped at bucket capacity.
    pub fn try_start(&mut self, request: &ProbeRequest) -> bool {
        if self.stopped
            || self.active >= self.config.budgets.global_concurrency
            || self.active_hosts.get(&request.target).copied().unwrap_or(0)
                >= self.config.budgets.per_host_concurrency
        {
            return false;
        }
        let now = self.clock.monotonic();
        let host_capacity = self.config.budgets.per_host_concurrency.saturating_mul(4);
        let host = self
            .host_rates
            .entry(request.target)
            .or_insert(TokenBucket {
                tokens: host_capacity,
                last: now,
            });
        let network = self
            .subnet_rates
            .entry(subnet(request.target))
            .or_insert(TokenBucket {
                tokens: self.config.budgets.per_subnet_burst,
                last: now,
            });
        if !host.available(now, host_capacity, self.config.budgets.refill)
            || !network.available(
                now,
                self.config.budgets.per_subnet_burst,
                self.config.budgets.refill,
            )
        {
            return false;
        }
        host.tokens -= 1;
        network.tokens -= 1;
        self.active += 1;
        *self.active_hosts.entry(request.target).or_default() += 1;
        true
    }
    pub fn finish(&mut self, request: &ProbeRequest) {
        self.active = self.active.saturating_sub(1);
        if let Some(active) = self.active_hosts.get_mut(&request.target) {
            *active = active.saturating_sub(1);
            if *active == 0 {
                self.active_hosts.remove(&request.target);
            }
        }
    }
    pub fn retry_delay(&mut self, host: &str, attempt: u8) -> Duration {
        let failures = self.failures.entry(host.into()).or_insert(0);
        *failures = (*failures).max(attempt.saturating_add(1)).min(16);
        let multiplier = 1u32
            .checked_shl(u32::from((*failures - 1).min(15)))
            .unwrap_or(u32::MAX);
        self.config
            .base_backoff
            .checked_mul(multiplier)
            .unwrap_or(self.config.max_backoff)
            .min(self.config.max_backoff)
    }
    pub fn record_success(&mut self, host: &str) {
        self.failures.remove(host);
    }
    pub fn jitter(&self, duration: Duration) -> Duration {
        let max = duration.mul_f64(f64::from(self.config.jitter_percent) / 100.0);
        if max.is_zero() {
            return Duration::ZERO;
        }
        let ceiling = max.as_nanos().min(u128::from(u32::MAX)) as u64;
        Duration::from_nanos(u64::from(self.clock.jitter_unit()) % (ceiling + 1))
    }
}
