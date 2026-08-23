//! Guarded, bounded active discovery. Network I/O is reachable only through `ActiveEngine`.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lattice_domain::{EvidenceFact, EvidenceFamily};
use secrecy::ExposeSecret;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
    sync::Notify,
};
use zeroize::Zeroizing;

use crate::{AuthorizedBinding, InterfaceId, TargetGuard};

mod active_udp;
mod scheduler_runner;
pub use active_udp::{
    NonceSource, UdpProbe, build_udp_probe, build_udp_probe_with_nonce, parse_udp_reply,
};
pub use scheduler_runner::{
    CredentialSourceError, ExecutionCredentialSource, RunnerEvent, SchedulerRunner,
};

#[derive(Debug)]
pub enum ProbeCredential {
    SnmpV1 {
        community: SecretString,
    },
    SnmpV2c {
        community: SecretString,
    },
    SnmpV3 {
        username: SecretString,
        authentication: Option<SnmpAuthentication>,
        privacy: Option<SnmpPrivacy>,
    },
}
#[derive(Debug)]
pub struct SnmpAuthentication {
    pub protocol: SnmpAuthProtocol,
    pub password: SecretString,
}
#[derive(Clone, Copy, Debug)]
pub enum SnmpAuthProtocol {
    Sha1,
    Sha256,
    Sha512,
}
#[derive(Debug)]
pub struct SnmpPrivacy {
    pub protocol: SnmpPrivProtocol,
    pub password: SecretString,
}
#[derive(Clone, Copy, Debug)]
pub enum SnmpPrivProtocol {
    Aes128,
    Aes256,
}

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetClass {
    Presence,
    Discovery,
    Inventory,
    OwnerFullPort,
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
    pub budget_class: BudgetClass,
    pub rate_cost: u8,
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
    OwnerInventory,
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
                || item.rate_cost == 0
                || item.potential_side_effects.is_empty()
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
    pub fn override_timeout(&mut self, id: &str, timeout: Duration) -> Result<(), CatalogError> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(CatalogError::Invalid);
        }
        self.descriptors
            .get_mut(id)
            .ok_or(CatalogError::Invalid)?
            .timeout = timeout;
        Ok(())
    }
    fn resolve(&self, id: &str) -> Option<ProbeDescriptor> {
        if let Some(descriptor) = self.descriptors.get(id) {
            return Some(descriptor.clone());
        }
        let port = id.strip_prefix("full.tcp.")?.parse::<u16>().ok()?;
        if port == 0 {
            return None;
        }
        let mut descriptor =
            descriptor(id, ProbeTransport::Tcp, port, RequiredPrivilege::None, b"");
        descriptor.owner_start_required = true;
        descriptor.budget_class = BudgetClass::OwnerFullPort;
        descriptor.rate_cost = 2;
        descriptor.potential_side_effects =
            "One TCP handshake; may be logged by the target service";
        Some(descriptor)
    }
    pub fn plan(&self, plan: CuratedPlan) -> Vec<&ProbeDescriptor> {
        self.descriptors
            .values()
            .filter(|p| match plan {
                CuratedPlan::Default => !p.owner_start_required,
                CuratedPlan::OwnerInventory => {
                    p.owner_start_required
                        && p.budget_class == BudgetClass::Inventory
                        && p.credential_required
                }
                CuratedPlan::OwnerFullPort => p.budget_class == BudgetClass::OwnerFullPort,
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
    let (side_effects, budget_class, rate_cost) = if id.starts_with("icmp.") {
        (
            "One ICMP echo; target may answer or log it",
            BudgetClass::Presence,
            1,
        )
    } else if id.starts_with("link.") {
        (
            "One local-link neighbor query through the privileged capture backend",
            BudgetClass::Presence,
            1,
        )
    } else if id.starts_with("udp.dhcp") {
        (
            "One unicast DHCPINFORM from the active interface address; server may audit it",
            BudgetClass::Discovery,
            2,
        )
    } else if id.starts_with("udp.snmp") {
        (
            "Two read-only SNMP GET varbinds; agent may audit the supplied owner credential",
            BudgetClass::Inventory,
            4,
        )
    } else if id.starts_with("udp.") {
        (
            "One protocol-shaped unicast discovery request; target may answer or log it",
            BudgetClass::Discovery,
            1,
        )
    } else if transport == ProbeTransport::Tls {
        (
            "One TLS handshake for certificate metadata; target may log it",
            BudgetClass::Discovery,
            3,
        )
    } else {
        (
            "One TCP handshake and optional non-auth greeting; target service may log it",
            BudgetClass::Discovery,
            2,
        )
    };
    ProbeDescriptor {
        id: id.into(),
        version: 1,
        transport,
        ports: vec![port],
        privilege,
        potential_side_effects: side_effects,
        timeout: Duration::from_secs(3),
        max_request_bytes: 1024,
        max_response_bytes: 4096,
        evidence_families: match transport {
            ProbeTransport::Tls => vec![EvidenceFamily::Cryptographic, EvidenceFamily::Service],
            ProbeTransport::Icmp => vec![EvidenceFamily::Addressing],
            ProbeTransport::LinkLayer => vec![EvidenceFamily::LinkLayer],
            ProbeTransport::Tcp | ProbeTransport::Udp => vec![EvidenceFamily::Service],
        },
        budget_class,
        rate_cost,
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
    let udp: [(&str, u16, &[u8]); 12] = [
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
        ("rtsp", 554, b""),
        ("lifx", 56700, b""),
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
    snmp.budget_class = BudgetClass::Inventory;
    snmp.rate_cost = 4;
    snmp.potential_side_effects =
        "Two read-only SNMP GET varbinds; agent may audit the supplied owner credential";
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
        p.budget_class = BudgetClass::OwnerFullPort;
        p.rate_cost = 2;
        p.potential_side_effects = "One TCP handshake; may be logged by the target service";
        items.push(p);
    }
    ProbeCatalog::new(items)
}

/// The explicit full TCP range, generated lazily for the bounded low-priority queue.
pub fn owner_full_port_probe_ids() -> impl Iterator<Item = String> {
    (1..=u16::MAX).map(|port| format!("full.tcp.{port}"))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProbeMode {
    Default,
    OwnerInventory,
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
    #[error("credential retrieval timed out")]
    CredentialTimeout,
    #[error("operation cancelled")]
    Cancelled,
    #[error("probe unavailable")]
    Unavailable,
    #[error("probe permission denied")]
    PermissionDenied,
    #[error("bounded network operation failed")]
    Network,
    #[error("internal probe execution failed")]
    Internal,
    #[error("response exceeded limit")]
    ResponseLimit,
    #[error("response correlation failed")]
    Correlation,
    #[error("invalid scheduler configuration")]
    InvalidConfig,
    #[error("scheduler queue is full")]
    QueueFull,
}

pub async fn recv_bounded_datagram(
    socket: &UdpSocket,
    cap: usize,
) -> Result<(Vec<u8>, SocketAddr), ActiveError> {
    if cap == 0 || cap > MAX_RESPONSE_BYTES {
        return Err(ActiveError::ResponseLimit);
    }
    let mut buffer = vec![0u8; cap.checked_add(1).ok_or(ActiveError::ResponseLimit)?];
    let (n, peer) = socket
        .recv_from(&mut buffer)
        .await
        .map_err(|_| ActiveError::Network)?;
    if n > cap {
        return Err(ActiveError::ResponseLimit);
    }
    buffer.truncate(n);
    Ok((buffer, peer))
}

pub trait ActiveProbeAdapter: Send + Sync {
    fn descriptor(&self) -> &ProbeDescriptor;
    fn build_request(
        &self,
        request: &ProbeRequest,
        credential: Option<&ProbeCredential>,
    ) -> Result<Vec<u8>, ActiveError>;
    fn parse_response(
        &self,
        request: &ProbeRequest,
        peer: SocketAddr,
        response: &[u8],
    ) -> Result<Vec<(String, String)>, ActiveError>;
}

#[async_trait]
pub trait AttemptTransport: Send + Sync {
    async fn attempt(
        &self,
        guard: &TargetGuard,
        request: &ProbeRequest,
        descriptor: &ProbeDescriptor,
        credential: Option<&ProbeCredential>,
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
        credential: Option<&ProbeCredential>,
    ) -> Result<ProbeOutcome, ActiveError> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(ActiveError::Cancelled);
        }
        let descriptor = self
            .catalog
            .resolve(&request.probe_id)
            .ok_or(ActiveError::UnknownProbe)?;
        if !request.owner_approved {
            return Err(ActiveError::OwnerApprovalRequired);
        }
        if descriptor.owner_start_required {
            let authorized_mode = match descriptor.budget_class {
                BudgetClass::OwnerFullPort => request.mode == ProbeMode::OwnerFullPort,
                _ => request.mode == ProbeMode::OwnerInventory,
            };
            if !authorized_mode {
                return Err(ActiveError::OwnerApprovalRequired);
            }
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
            result = tokio::time::timeout(descriptor.timeout, self.transport.attempt(&self.guard, &request, &descriptor, credential)) => {
                match result { Ok(response) => response?, Err(_) => TransportResponse::Timeout }
            }
        };
        normalize(&descriptor, response)
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
                    family: descriptor
                        .evidence_families
                        .first()
                        .copied()
                        .unwrap_or(EvidenceFamily::Service),
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
        guard: &TargetGuard,
        request: &ProbeRequest,
        descriptor: &ProbeDescriptor,
        _credential: Option<&ProbeCredential>,
    ) -> Result<TransportResponse, ActiveError> {
        let port = *descriptor.ports.first().ok_or(ActiveError::Unavailable)?;
        match descriptor.transport {
            ProbeTransport::Tcp => tcp_attempt(guard, request, port, descriptor).await,
            ProbeTransport::Udp => udp_attempt(guard, request, port, descriptor, _credential).await,
            // Raw ICMP/link-layer access is an explicit platform boundary. Until the
            // privileged capture backend is installed it reports unavailable, never success.
            ProbeTransport::Icmp => icmp_attempt(guard, request, descriptor.timeout).await,
            ProbeTransport::LinkLayer => Err(ActiveError::PermissionDenied),
            ProbeTransport::Tls => tls_attempt(guard, request, port, descriptor).await,
        }
    }
}

#[derive(Debug)]
struct FingerprintOnlyVerifier;
impl rustls::client::danger::ServerCertVerifier for FingerprintOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

async fn tls_attempt(
    guard: &TargetGuard,
    request: &ProbeRequest,
    port: u16,
    d: &ProbeDescriptor,
) -> Result<TransportResponse, ActiveError> {
    use std::sync::Arc;
    let ip = request.target;
    let binding = guard
        .authorized_binding(request.interface, ip)
        .map_err(|_| ActiveError::Unauthorized)?;
    let socket = match ip {
        IpAddr::V4(_) => TcpSocket::new_v4(),
        IpAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|_| ActiveError::Network)?;
    socket
        .bind(binding.source_socket())
        .map_err(|_| ActiveError::Unavailable)?;
    verify_local_binding(
        socket.local_addr().map_err(|_| ActiveError::Network)?,
        binding.source,
    )?;
    pin_socket_to_interface(&socket, binding)?;
    guard
        .authorize(request.interface, ip)
        .map_err(|_| ActiveError::Unauthorized)?;
    let stream = match socket.connect(binding.target_socket(port)).await {
        Ok(stream) => stream,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            return Ok(TransportResponse::Refused);
        }
        Err(_) => return Err(ActiveError::Network),
    };
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FingerprintOnlyVerifier))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::IpAddress(ip.into());
    verify_local_binding(
        stream.local_addr().map_err(|_| ActiveError::Network)?,
        binding.source,
    )?;
    pin_socket_to_interface(&stream, binding)?;
    guard
        .authorize(request.interface, ip)
        .map_err(|_| ActiveError::Unauthorized)?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .map_err(|_| ActiveError::Network)?;
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or(ActiveError::Network)?;
    certificate_metadata(cert.as_ref(), d.max_response_bytes)
}

fn certificate_metadata(der: &[u8], max_bytes: usize) -> Result<TransportResponse, ActiveError> {
    use x509_parser::{extensions::GeneralName, parse_x509_certificate};
    if der.len() > max_bytes.min(MAX_RESPONSE_BYTES) {
        return Err(ActiveError::ResponseLimit);
    }
    let (_, certificate) = parse_x509_certificate(der).map_err(|_| ActiveError::Network)?;
    let fingerprint = Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut facts = vec![
        ("certificate_sha256".into(), fingerprint),
        ("certificate_trust".into(), "unverified".into()),
        (
            "certificate_subject".into(),
            certificate
                .subject()
                .to_string()
                .chars()
                .take(MAX_FACT_VALUE_BYTES)
                .collect(),
        ),
        (
            "certificate_not_before".into(),
            certificate
                .validity()
                .not_before
                .to_rfc2822()
                .unwrap_or_else(|_| "invalid".into()),
        ),
        (
            "certificate_not_after".into(),
            certificate
                .validity()
                .not_after
                .to_rfc2822()
                .unwrap_or_else(|_| "invalid".into()),
        ),
    ];
    if let Ok(Some(san)) = certificate.subject_alternative_name() {
        let mut names = Vec::new();
        for name in san.value.general_names.iter().take(16) {
            match name {
                GeneralName::DNSName(value) => names.push((*value).to_owned()),
                GeneralName::IPAddress(value) => names.push(render_ip_san(value)?),
                _ => {}
            }
        }
        let names = names.join(",");
        if !names.is_empty() {
            facts.push((
                "certificate_san".into(),
                names.chars().take(MAX_FACT_VALUE_BYTES).collect(),
            ));
        }
    }
    Ok(TransportResponse::Success(facts))
}

pub fn render_ip_san(value: &[u8]) -> Result<String, ActiveError> {
    match value.len() {
        4 => Ok(Ipv4Addr::new(value[0], value[1], value[2], value[3]).to_string()),
        16 => Ok(
            Ipv6Addr::from(<[u8; 16]>::try_from(value).map_err(|_| ActiveError::Network)?)
                .to_string(),
        ),
        _ => Err(ActiveError::Network),
    }
}

async fn icmp_attempt(
    guard: &TargetGuard,
    request: &ProbeRequest,
    timeout: Duration,
) -> Result<TransportResponse, ActiveError> {
    use std::num::NonZeroU32;
    use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence, SurgeError};
    let ip = request.target;
    let binding = guard
        .authorized_binding(request.interface, ip)
        .map_err(|_| ActiveError::Unauthorized)?;
    let config = Config::builder()
        .kind(if ip.is_ipv4() { ICMP::V4 } else { ICMP::V6 })
        .bind(binding.source_socket())
        .interface_index(NonZeroU32::new(binding.interface_index).ok_or(ActiveError::Unavailable)?)
        .build();
    let client = Client::new(&config).map_err(|error| match error.kind() {
        std::io::ErrorKind::PermissionDenied => ActiveError::PermissionDenied,
        std::io::ErrorKind::Unsupported => ActiveError::Unavailable,
        _ => ActiveError::Network,
    })?;
    let mut pinger = client.pinger(ip, PingIdentifier(0x4e48)).await;
    pinger.timeout(timeout);
    guard
        .authorize(request.interface, ip)
        .map_err(|_| ActiveError::Unauthorized)?;
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
    guard: &TargetGuard,
    probe_request: &ProbeRequest,
    port: u16,
    d: &ProbeDescriptor,
) -> Result<TransportResponse, ActiveError> {
    let ip = probe_request.target;
    let binding = guard
        .authorized_binding(probe_request.interface, ip)
        .map_err(|_| ActiveError::Unauthorized)?;
    let socket = match ip {
        IpAddr::V4(_) => TcpSocket::new_v4(),
        IpAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|_| ActiveError::Network)?;
    socket
        .bind(binding.source_socket())
        .map_err(|_| ActiveError::Unavailable)?;
    verify_local_binding(
        socket.local_addr().map_err(|_| ActiveError::Network)?,
        binding.source,
    )?;
    pin_socket_to_interface(&socket, binding)?;
    guard
        .authorize(probe_request.interface, ip)
        .map_err(|_| ActiveError::Unauthorized)?;
    let mut stream = match socket.connect(binding.target_socket(port)).await {
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
        verify_local_binding(
            stream.local_addr().map_err(|_| ActiveError::Network)?,
            binding.source,
        )?;
        pin_socket_to_interface(&stream, binding)?;
        guard
            .authorize(probe_request.interface, ip)
            .map_err(|_| ActiveError::Unauthorized)?;
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
    guard: &TargetGuard,
    request: &ProbeRequest,
    port: u16,
    d: &ProbeDescriptor,
    credential: Option<&ProbeCredential>,
) -> Result<TransportResponse, ActiveError> {
    let ip = request.target;
    let binding = guard
        .authorized_binding(request.interface, ip)
        .map_err(|_| ActiveError::Unauthorized)?;
    let socket = UdpSocket::bind(binding.source_socket())
        .await
        .map_err(|_| ActiveError::Unavailable)?;
    verify_local_binding(
        socket.local_addr().map_err(|_| ActiveError::Network)?,
        binding.source,
    )?;
    pin_socket_to_interface(&socket, binding)?;
    guard
        .authorize(request.interface, ip)
        .map_err(|_| ActiveError::Unauthorized)?;
    socket
        .connect(binding.target_socket(port))
        .await
        .map_err(|_| ActiveError::Network)?;
    let local_v4 = match socket.local_addr().map_err(|_| ActiveError::Network)?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    };
    if d.id == "udp.snmp.161" {
        return snmp_attempt(guard, request, socket, credential).await;
    }
    let probe = build_udp_probe(&d.id, ip, local_v4, credential)?;
    if probe.port != port || probe.bytes.len() > d.max_request_bytes {
        return Err(ActiveError::ResponseLimit);
    }
    verify_local_binding(
        socket.local_addr().map_err(|_| ActiveError::Network)?,
        binding.source,
    )?;
    pin_socket_to_interface(&socket, binding)?;
    guard
        .authorize(request.interface, ip)
        .map_err(|_| ActiveError::Unauthorized)?;
    socket
        .send(&probe.bytes)
        .await
        .map_err(|_| ActiveError::Network)?;
    let (response, peer) =
        recv_bounded_datagram(&socket, d.max_response_bytes.min(MAX_RESPONSE_BYTES)).await?;
    Ok(TransportResponse::Success(parse_udp_reply(
        &d.id, &probe, peer, &response,
    )?))
}

fn verify_local_binding(local: SocketAddr, expected: IpAddr) -> Result<(), ActiveError> {
    if local.ip() == expected {
        Ok(())
    } else {
        Err(ActiveError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn pin_socket_to_interface<S: std::os::fd::AsFd>(
    socket: &S,
    binding: AuthorizedBinding,
) -> Result<(), ActiveError> {
    use std::num::NonZeroU32;
    let index = NonZeroU32::new(binding.interface_index).ok_or(ActiveError::Unavailable)?;
    let socket = socket2::SockRef::from(socket);
    match binding.target {
        IpAddr::V4(_) => {
            socket
                .bind_device_by_index_v4(Some(index))
                .map_err(|_| ActiveError::PermissionDenied)?;
            if socket
                .device_index_v4()
                .map_err(|_| ActiveError::Unavailable)?
                != Some(index)
            {
                return Err(ActiveError::Unavailable);
            }
        }
        IpAddr::V6(_) => {
            socket
                .bind_device_by_index_v6(Some(index))
                .map_err(|_| ActiveError::PermissionDenied)?;
            if socket
                .device_index_v6()
                .map_err(|_| ActiveError::Unavailable)?
                != Some(index)
            {
                return Err(ActiveError::Unavailable);
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn pin_socket_to_interface<S: std::os::windows::io::AsRawSocket>(
    socket: &S,
    binding: AuthorizedBinding,
) -> Result<(), ActiveError> {
    use std::mem::size_of;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, getsockopt,
        setsockopt,
    };
    let raw = socket.as_raw_socket() as usize;
    let (level, option, configured) = match binding.target {
        IpAddr::V4(_) => (IPPROTO_IP, IP_UNICAST_IF, binding.interface_index.to_be()),
        IpAddr::V6(_) => (IPPROTO_IPV6, IPV6_UNICAST_IF, binding.interface_index),
    };
    let result = unsafe {
        setsockopt(
            raw,
            level,
            option,
            (&configured as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        return Err(ActiveError::PermissionDenied);
    }
    let mut actual = 0u32;
    let mut len = size_of::<u32>() as i32;
    let result = unsafe {
        getsockopt(
            raw,
            level,
            option,
            (&mut actual as *mut u32).cast(),
            &mut len,
        )
    };
    if result == SOCKET_ERROR || len != size_of::<u32>() as i32 || actual != configured {
        return Err(ActiveError::Unavailable);
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn pin_socket_to_interface<S>(_: &S, _: AuthorizedBinding) -> Result<(), ActiveError> {
    Err(ActiveError::Unavailable)
}

struct GuardedSnmpTransport {
    guard: TargetGuard,
    request: ProbeRequest,
    socket: UdpSocket,
    peer: SocketAddr,
    local: SocketAddr,
}
impl async_snmp::Transport for GuardedSnmpTransport {
    async fn send(&self, data: &[u8]) -> async_snmp::Result<()> {
        if data.len() > 4096 {
            return Err(Box::new(async_snmp::Error::Network {
                target: self.peer,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bounded request rejected",
                ),
            }));
        }
        verify_local_binding(
            self.socket.local_addr().map_err(|source| {
                Box::new(async_snmp::Error::Network {
                    target: self.peer,
                    source,
                })
            })?,
            self.local.ip(),
        )
        .map_err(|error| {
            Box::new(async_snmp::Error::Network {
                target: self.peer,
                source: std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    error.to_string(),
                ),
            })
        })?;
        let binding = self
            .guard
            .authorized_binding(self.request.interface, self.request.target)
            .map_err(|_| {
                Box::new(async_snmp::Error::Network {
                    target: self.peer,
                    source: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "target authorization failed",
                    ),
                })
            })?;
        pin_socket_to_interface(&self.socket, binding).map_err(|error| {
            Box::new(async_snmp::Error::Network {
                target: self.peer,
                source: std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    error.to_string(),
                ),
            })
        })?;
        self.guard
            .authorize(self.request.interface, self.request.target)
            .map_err(|_| {
                Box::new(async_snmp::Error::Network {
                    target: self.peer,
                    source: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "target authorization failed",
                    ),
                })
            })?;
        self.socket.send(data).await.map_err(|source| {
            Box::new(async_snmp::Error::Network {
                target: self.peer,
                source,
            })
        })?;
        Ok(())
    }
    async fn request_with<T, F>(
        &self,
        data: &[u8],
        registration: async_snmp::RequestRegistration,
        mut validate: F,
    ) -> async_snmp::Result<T>
    where
        T: Send,
        F: FnMut(bytes::Bytes, SocketAddr) -> async_snmp::Result<async_snmp::Candidate<T>> + Send,
    {
        self.send(data).await?;
        let started = tokio::time::Instant::now();
        let deadline = registration.deadline();
        let elapsed = deadline.saturating_duration_since(started);
        loop {
            let received =
                tokio::time::timeout_at(deadline, recv_bounded_datagram(&self.socket, 4096))
                    .await
                    .map_err(|_| {
                        Box::new(async_snmp::Error::Timeout {
                            target: self.peer,
                            elapsed,
                            retries: 0,
                        })
                    })?
                    .map_err(|error| {
                        Box::new(async_snmp::Error::Network {
                            target: self.peer,
                            source: std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                error.to_string(),
                            ),
                        })
                    })?;
            let (buffer, source) = received;
            if source != self.peer {
                continue;
            }
            if matches!(
                registration.evaluate_response_identity(&buffer, true),
                async_snmp::ResponseIdentity::Reject
            ) {
                continue;
            }
            match validate(bytes::Bytes::from(buffer), source)? {
                async_snmp::Candidate::Accept(value) => return Ok(value),
                async_snmp::Candidate::Reject => continue,
            }
        }
    }
    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    fn local_addr(&self) -> SocketAddr {
        self.local
    }
    fn is_reliable(&self) -> bool {
        false
    }
    fn send_capacity(&self) -> usize {
        4096
    }
}

async fn snmp_attempt(
    guard: &TargetGuard,
    request: &ProbeRequest,
    socket: UdpSocket,
    credential: Option<&ProbeCredential>,
) -> Result<TransportResponse, ActiveError> {
    let credential = credential.ok_or(ActiveError::CredentialRequired)?;
    if matches!(
        credential,
        ProbeCredential::SnmpV1 { .. } | ProbeCredential::SnmpV2c { .. }
    ) {
        return snmp_community_attempt(guard, request, socket, credential).await;
    }
    let auth = match credential {
        ProbeCredential::SnmpV1 { .. } | ProbeCredential::SnmpV2c { .. } => {
            unreachable!("community credentials handled above")
        }
        ProbeCredential::SnmpV3 {
            username,
            authentication,
            privacy,
        } => {
            let mut config = async_snmp::UsmConfig::new(username.expose_secret().to_owned());
            if let Some(authentication) = authentication {
                let protocol = match authentication.protocol {
                    SnmpAuthProtocol::Sha1 => async_snmp::AuthProtocol::Sha1,
                    SnmpAuthProtocol::Sha256 => async_snmp::AuthProtocol::Sha256,
                    SnmpAuthProtocol::Sha512 => async_snmp::AuthProtocol::Sha512,
                };
                config = if let Some(privacy) = privacy {
                    let privacy_protocol = match privacy.protocol {
                        SnmpPrivProtocol::Aes128 => async_snmp::PrivProtocol::Aes128,
                        SnmpPrivProtocol::Aes256 => async_snmp::PrivProtocol::Aes256Blumenthal,
                    };
                    config
                        .auth_priv(
                            protocol,
                            authentication.password.expose_secret(),
                            privacy_protocol,
                            privacy.password.expose_secret(),
                        )
                        .map_err(|_| ActiveError::CredentialRequired)?
                } else {
                    config
                        .auth(protocol, authentication.password.expose_secret())
                        .map_err(|_| ActiveError::CredentialRequired)?
                };
            } else if privacy.is_some() {
                return Err(ActiveError::CredentialRequired);
            }
            async_snmp::Auth::Usm(config)
        }
    };
    let peer = socket.peer_addr().map_err(|_| ActiveError::Network)?;
    let local = socket.local_addr().map_err(|_| ActiveError::Network)?;
    let transport = GuardedSnmpTransport {
        guard: guard.clone(),
        request: request.clone(),
        socket,
        peer,
        local,
    };
    let client = async_snmp::ClientBuilder::new(auth)
        .request_timeout(Duration::from_secs(3))
        .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
        .build_with_transport(transport)
        .map_err(|_| ActiveError::CredentialRequired)?;
    let response = match client
        .get_many(&[
            async_snmp::oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            async_snmp::oid!(1, 3, 6, 1, 2, 1, 1, 2, 0),
        ])
        .await
    {
        Ok(response) => response,
        Err(error) if matches!(error.kind(), async_snmp::ErrorKind::Timeout) => {
            return Ok(TransportResponse::Timeout);
        }
        Err(_) => return Err(ActiveError::Network),
    };
    Ok(TransportResponse::Success(normalize_snmp_inventory(
        response,
    )?))
}

#[cfg(test)]
const SNMP_REQUEST_ID: i32 = 0x4e48_1234;
const SYS_DESCR_OID: &[u8] = &[0x2b, 6, 1, 2, 1, 1, 1, 0];
const SYS_OBJECT_ID_OID: &[u8] = &[0x2b, 6, 1, 2, 1, 1, 2, 0];

async fn snmp_community_attempt(
    guard: &TargetGuard,
    request: &ProbeRequest,
    socket: UdpSocket,
    credential: &ProbeCredential,
) -> Result<TransportResponse, ActiveError> {
    let (version, community) = match credential {
        ProbeCredential::SnmpV1 { community } => (0, community),
        ProbeCredential::SnmpV2c { community } => (1, community),
        _ => return Err(ActiveError::CredentialRequired),
    };
    let mut nonce = [0u8; 4];
    getrandom::fill(&mut nonce).map_err(|_| ActiveError::Unavailable)?;
    let request_id = i32::from_be_bytes(nonce) & i32::MAX;
    let wire = build_snmp_community_request(version, community.expose_secret(), request_id)?;
    let binding = guard
        .authorized_binding(request.interface, request.target)
        .map_err(|_| ActiveError::Unauthorized)?;
    verify_local_binding(
        socket.local_addr().map_err(|_| ActiveError::Network)?,
        binding.source,
    )?;
    pin_socket_to_interface(&socket, binding)?;
    guard
        .authorize(request.interface, request.target)
        .map_err(|_| ActiveError::Unauthorized)?;
    socket.send(&wire).await.map_err(|_| ActiveError::Network)?;
    let (response, peer) = recv_bounded_datagram(&socket, 4096).await?;
    let response = Zeroizing::new(response);
    if peer != socket.peer_addr().map_err(|_| ActiveError::Network)? {
        return Err(ActiveError::Correlation);
    }
    Ok(TransportResponse::Success(parse_snmp_community_response(
        &response,
        version,
        community.expose_secret(),
        request_id,
    )?))
}

fn build_snmp_community_request(
    version: i32,
    community: &str,
    request_id: i32,
) -> Result<Zeroizing<Vec<u8>>, ActiveError> {
    if community.is_empty() || community.len() > 64 || community.as_bytes().contains(&0) {
        return Err(ActiveError::CredentialRequired);
    }
    let varbinds = [SYS_DESCR_OID, SYS_OBJECT_ID_OID]
        .into_iter()
        .map(|oid| ber(0x30, [ber(0x06, oid.to_vec()), ber(0x05, vec![])].concat()))
        .collect::<Vec<_>>()
        .concat();
    let pdu = ber(
        0xa0,
        [
            ber_int(request_id),
            ber_int(0),
            ber_int(0),
            ber(0x30, varbinds),
        ]
        .concat(),
    );
    let message = ber(
        0x30,
        [
            ber_int(version),
            ber(0x04, community.as_bytes().to_vec()),
            pdu,
        ]
        .concat(),
    );
    if message.len() > 4096 {
        return Err(ActiveError::ResponseLimit);
    }
    Ok(Zeroizing::new(message))
}
fn ber(tag: u8, value: Vec<u8>) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8)
    } else {
        out.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8])
    }
    out.extend(value);
    out
}
fn ber_int(value: i32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
    let mut content = bytes[first..].to_vec();
    if content.first().is_some_and(|byte| byte & 0x80 != 0) {
        content.insert(0, 0)
    }
    ber(0x02, content)
}
fn tlv<'a>(input: &mut &'a [u8], expected: u8) -> Result<&'a [u8], ActiveError> {
    if input.len() < 2 || input[0] != expected {
        return Err(ActiveError::Network);
    }
    let first = input[1];
    let (mut header, mut len) = (2usize, usize::from(first));
    if first & 0x80 != 0 {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 2 || input.len() < 2 + count {
            return Err(ActiveError::Network);
        }
        header += count;
        len = 0;
        for byte in &input[2..header] {
            len = (len << 8) | usize::from(*byte)
        }
    }
    if len > MAX_RESPONSE_BYTES || header + len > input.len() {
        return Err(ActiveError::ResponseLimit);
    }
    let value = &input[header..header + len];
    *input = &input[header + len..];
    Ok(value)
}
fn integer(input: &mut &[u8]) -> Result<i32, ActiveError> {
    let value = tlv(input, 0x02)?;
    if value.is_empty() || value.len() > 5 {
        return Err(ActiveError::Network);
    }
    let mut out = 0i64;
    for byte in value {
        out = (out << 8) | i64::from(*byte)
    }
    i32::try_from(out).map_err(|_| ActiveError::Network)
}
fn parse_snmp_community_response(
    bytes: &[u8],
    expected_version: i32,
    community: &str,
    request_id: i32,
) -> Result<Vec<(String, String)>, ActiveError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ActiveError::ResponseLimit);
    }
    let mut top = bytes;
    let mut message = tlv(&mut top, 0x30)?;
    if !top.is_empty() || integer(&mut message)? != expected_version {
        return Err(ActiveError::Correlation);
    }
    let actual = tlv(&mut message, 0x04)?;
    if actual.len() != community.len() || !bool::from(actual.ct_eq(community.as_bytes())) {
        return Err(ActiveError::Correlation);
    }
    let mut pdu = tlv(&mut message, 0xa2)?;
    if !message.is_empty() || integer(&mut pdu)? != request_id {
        return Err(ActiveError::Correlation);
    }
    if integer(&mut pdu)? != 0 || integer(&mut pdu)? != 0 {
        return Err(ActiveError::Network);
    }
    let mut list = tlv(&mut pdu, 0x30)?;
    if !pdu.is_empty() {
        return Err(ActiveError::Network);
    }
    let mut facts = vec![];
    let (mut seen_descr, mut seen_object_id) = (false, false);
    while !list.is_empty() {
        if facts.len() >= 2 {
            return Err(ActiveError::ResponseLimit);
        }
        let mut binding = tlv(&mut list, 0x30)?;
        let oid = tlv(&mut binding, 0x06)?;
        if oid == SYS_DESCR_OID {
            if seen_descr {
                return Err(ActiveError::Correlation);
            }
            seen_descr = true;
            let value = tlv(&mut binding, 0x04)?;
            if value.len() > MAX_FACT_VALUE_BYTES {
                return Err(ActiveError::ResponseLimit);
            }
            facts.push((
                "sys_descr".into(),
                String::from_utf8_lossy(value)
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect(),
            ))
        } else if oid == SYS_OBJECT_ID_OID {
            if seen_object_id {
                return Err(ActiveError::Correlation);
            }
            seen_object_id = true;
            let value = tlv(&mut binding, 0x06)?;
            facts.push(("sys_object_id".into(), decode_oid(value)?))
        } else {
            return Err(ActiveError::Correlation);
        }
        if !binding.is_empty() {
            return Err(ActiveError::Network);
        }
    }
    if !seen_descr || !seen_object_id {
        return Err(ActiveError::Network);
    }
    Ok(facts)
}
fn decode_oid(bytes: &[u8]) -> Result<String, ActiveError> {
    let first = *bytes.first().ok_or(ActiveError::Network)?;
    let mut parts = vec![(first / 40).to_string(), (first % 40).to_string()];
    let mut value = 0u32;
    let mut open = false;
    for byte in &bytes[1..] {
        open = true;
        value = value
            .checked_shl(7)
            .and_then(|v| v.checked_add(u32::from(byte & 0x7f)))
            .ok_or(ActiveError::ResponseLimit)?;
        if byte & 0x80 == 0 {
            parts.push(value.to_string());
            value = 0;
            open = false
        }
    }
    if open {
        return Err(ActiveError::Network);
    }
    Ok(parts.join("."))
}

#[cfg(test)]
mod snmp_wire_tests {
    use super::*;
    fn response(version: i32, community: &str, id: i32) -> Vec<u8> {
        let bindings = [
            ber(
                0x30,
                [
                    ber(0x06, SYS_DESCR_OID.to_vec()),
                    ber(0x04, b"Camera".to_vec()),
                ]
                .concat(),
            ),
            ber(
                0x30,
                [
                    ber(0x06, SYS_OBJECT_ID_OID.to_vec()),
                    ber(0x06, [0x2b, 6, 1, 4, 1, 0].to_vec()),
                ]
                .concat(),
            ),
        ]
        .concat();
        let pdu = ber(
            0xa2,
            [ber_int(id), ber_int(0), ber_int(0), ber(0x30, bindings)].concat(),
        );
        ber(
            0x30,
            [
                ber_int(version),
                ber(0x04, community.as_bytes().to_vec()),
                pdu,
            ]
            .concat(),
        )
    }
    #[test]
    fn community_wire_validates_version_secret_and_request_id() {
        let good = response(1, "owner-secret", SNMP_REQUEST_ID);
        assert_eq!(
            parse_snmp_community_response(&good, 1, "owner-secret", SNMP_REQUEST_ID)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            parse_snmp_community_response(&good, 0, "owner-secret", SNMP_REQUEST_ID).unwrap_err(),
            ActiveError::Correlation
        );
        assert_eq!(
            parse_snmp_community_response(&good, 1, "wrong", SNMP_REQUEST_ID).unwrap_err(),
            ActiveError::Correlation
        );
        assert_eq!(
            parse_snmp_community_response(&good, 1, "owner-secret", 1).unwrap_err(),
            ActiveError::Correlation
        );
        assert_eq!(
            parse_snmp_community_response(
                &vec![0; MAX_RESPONSE_BYTES + 1],
                1,
                "owner-secret",
                SNMP_REQUEST_ID
            )
            .unwrap_err(),
            ActiveError::ResponseLimit
        );
    }

    #[test]
    fn community_wire_rejects_duplicate_or_missing_inventory_oids() {
        let good = response(1, "owner-secret", SNMP_REQUEST_ID);
        let second_oid = good
            .windows(SYS_OBJECT_ID_OID.len())
            .position(|window| window == SYS_OBJECT_ID_OID)
            .expect("object id oid");
        let mut duplicate = good.clone();
        duplicate[second_oid..second_oid + SYS_DESCR_OID.len()].copy_from_slice(SYS_DESCR_OID);
        assert!(
            parse_snmp_community_response(&duplicate, 1, "owner-secret", SNMP_REQUEST_ID).is_err()
        );

        let mut missing = good;
        missing[second_oid] ^= 1;
        assert!(
            parse_snmp_community_response(&missing, 1, "owner-secret", SNMP_REQUEST_ID).is_err()
        );
    }
    #[test]
    fn community_request_buffer_is_zeroizing_and_bounded() {
        let request = build_snmp_community_request(1, "owner-secret", SNMP_REQUEST_ID).unwrap();
        assert!(request.windows(12).any(|window| window == b"owner-secret"));
        assert!(request.len() < 4096);
        assert_eq!(
            build_snmp_community_request(1, &"x".repeat(65), SNMP_REQUEST_ID).unwrap_err(),
            ActiveError::CredentialRequired
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod interface_pin_tests {
    use super::*;
    use std::num::NonZeroU32;

    #[tokio::test]
    async fn linux_pin_sets_and_verifies_the_requested_interface_index() {
        let loopback = pnet_datalink::interfaces()
            .into_iter()
            .find(|interface| interface.is_loopback())
            .expect("loopback interface");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let binding = AuthorizedBinding {
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            interface_index: loopback.index,
            target: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        pin_socket_to_interface(&socket, binding).unwrap();
        assert_eq!(
            socket2::SockRef::from(&socket).device_index_v4().unwrap(),
            NonZeroU32::new(loopback.index)
        );
    }

    #[tokio::test]
    async fn linux_pin_fails_closed_for_an_invalid_interface_index() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let binding = AuthorizedBinding {
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            interface_index: u32::MAX,
            target: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        assert!(pin_socket_to_interface(&socket, binding).is_err());
    }
}

pub fn normalize_snmp_inventory(
    response: async_snmp::FixedCardinalityResponse,
) -> Result<Vec<(String, String)>, ActiveError> {
    if !response.anomalies.is_empty() || response.varbinds.len() != 2 {
        return Err(ActiveError::Network);
    }
    let mut facts = vec![];
    for binding in response.varbinds {
        if binding.oid == async_snmp::oid!(1, 3, 6, 1, 2, 1, 1, 1, 0) {
            if let async_snmp::Value::OctetString(value) = binding.value {
                if value.len() > MAX_FACT_VALUE_BYTES {
                    return Err(ActiveError::ResponseLimit);
                }
                facts.push((
                    "sys_descr".into(),
                    String::from_utf8_lossy(&value)
                        .chars()
                        .filter(|c| !c.is_control())
                        .collect(),
                ));
            }
        } else if binding.oid == async_snmp::oid!(1, 3, 6, 1, 2, 1, 1, 2, 0)
            && let async_snmp::Value::ObjectIdentifier(value) = binding.value
        {
            facts.push(("sys_object_id".into(), value.to_string()));
        }
    }
    if facts.len() != 2 {
        return Err(ActiveError::Network);
    }
    Ok(facts)
}

#[derive(Clone, Copy, Debug)]
pub struct BudgetConfig {
    pub global_concurrency: usize,
    pub per_host_concurrency: usize,
    pub global_rate_burst: usize,
    pub per_subnet_burst: usize,
    pub refill: Duration,
}
impl BudgetConfig {
    pub fn new(
        global: usize,
        host: usize,
        global_rate_burst: usize,
        subnet: usize,
        refill: Duration,
    ) -> Result<Self, ActiveError> {
        if global == 0
            || global > 256
            || host == 0
            || host > 16
            || host > global
            || global_rate_burst == 0
            || global_rate_burst > 4096
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
            global_rate_burst,
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
            global_rate_burst: 128,
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
    pub state_capacity: usize,
    pub state_ttl: Duration,
    pub max_retry_attempts: u8,
    pub credential_timeout: Duration,
}
impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            budgets: BudgetConfig::default(),
            queue_capacity: 2048,
            base_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            jitter_percent: 10,
            state_capacity: 2048,
            state_ttl: Duration::from_secs(30 * 60),
            max_retry_attempts: 5,
            credential_timeout: Duration::from_secs(2),
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
    failures: HashMap<WorkKey, FailureState>,
    stopped: bool,
    active: usize,
    active_hosts: HashMap<IpAddr, usize>,
    global_rate: TokenBucket,
    host_rates: HashMap<IpAddr, TokenBucket>,
    subnet_rates: HashMap<SubnetKey, TokenBucket>,
    high_admissions_since_low: usize,
}

const HIGH_ADMISSIONS_BEFORE_LOW: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    Admitted,
    ConcurrencyLimited,
    EligibleAt(Duration),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WorkKey {
    pub interface: InterfaceId,
    pub target: IpAddr,
    pub probe_id: String,
}
impl From<&ProbeRequest> for WorkKey {
    fn from(request: &ProbeRequest) -> Self {
        Self {
            interface: request.interface,
            target: request.target,
            probe_id: request.probe_id.clone(),
        }
    }
}
struct FailureState {
    count: u8,
    last_used: Duration,
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
    last_used: Duration,
}
impl TokenBucket {
    fn available(&mut self, now: Duration, capacity: usize, refill: Duration) -> bool {
        self.last_used = now;
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
            config.budgets.global_rate_burst,
            config.budgets.per_subnet_burst,
            config.budgets.refill,
        )?;
        if config.queue_capacity == 0
            || config.queue_capacity > MAX_QUEUE
            || config.base_backoff.is_zero()
            || config.max_backoff < config.base_backoff
            || config.jitter_percent > 25
            || config.state_capacity == 0
            || config.state_capacity > MAX_QUEUE
            || config.state_ttl.is_zero()
            || config.max_retry_attempts == 0
            || config.max_retry_attempts > 16
            || config.credential_timeout.is_zero()
            || config.credential_timeout > Duration::from_secs(30)
        {
            return Err(ActiveError::InvalidConfig);
        }
        let now = clock.monotonic();
        let global_rate_burst = config.budgets.global_rate_burst;
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
            global_rate: TokenBucket {
                tokens: global_rate_burst,
                last: now,
                last_used: now,
            },
            host_rates: HashMap::new(),
            subnet_rates: HashMap::new(),
            high_admissions_since_low: 0,
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
        let choose_low = !self.low.is_empty()
            && (self.hosts.is_empty()
                || self.high_admissions_since_low >= HIGH_ADMISSIONS_BEFORE_LOW);
        let request = if choose_low {
            self.high_admissions_since_low = 0;
            self.low.pop_front()
        } else if let Some(host) = self.hosts.pop_front() {
            let queue = self.high.get_mut(&host)?;
            let item = queue.pop_front();
            if queue.is_empty() {
                self.high.remove(&host);
            } else {
                self.hosts.push_back(host);
            }
            if item.is_some() {
                self.high_admissions_since_low = self.high_admissions_since_low.saturating_add(1);
            }
            item
        } else {
            self.high_admissions_since_low = 0;
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
    pub fn queue_len(&self) -> usize {
        self.queued.len()
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
        self.try_start_cost(request, 1)
    }
    pub fn try_start_cost(&mut self, request: &ProbeRequest, cost: u8) -> bool {
        self.admission_decision(request, cost) == AdmissionDecision::Admitted
    }
    pub fn admission_decision(&mut self, request: &ProbeRequest, cost: u8) -> AdmissionDecision {
        if self.stopped
            || cost == 0
            || self.active >= self.config.budgets.global_concurrency
            || self.active_hosts.get(&request.target).copied().unwrap_or(0)
                >= self.config.budgets.per_host_concurrency
        {
            return AdmissionDecision::ConcurrencyLimited;
        }
        let now = self.clock.monotonic();
        self.evict_state(now);
        let host_capacity = self.config.budgets.per_host_concurrency.saturating_mul(4);
        if self.host_rates.len() >= self.config.state_capacity
            && !self.host_rates.contains_key(&request.target)
        {
            let deadline = self
                .host_rates
                .values()
                .map(|bucket| bucket.last_used.saturating_add(self.config.state_ttl))
                .min()
                .unwrap_or_else(|| now.saturating_add(self.config.state_ttl));
            return AdmissionDecision::EligibleAt(deadline);
        }
        let subnet_key = subnet(request.target);
        if self.subnet_rates.len() >= self.config.state_capacity
            && !self.subnet_rates.contains_key(&subnet_key)
        {
            let deadline = self
                .subnet_rates
                .values()
                .map(|bucket| bucket.last_used.saturating_add(self.config.state_ttl))
                .min()
                .unwrap_or_else(|| now.saturating_add(self.config.state_ttl));
            return AdmissionDecision::EligibleAt(deadline);
        }
        let host = self
            .host_rates
            .entry(request.target)
            .or_insert(TokenBucket {
                tokens: host_capacity,
                last: now,
                last_used: now,
            });
        let network = self.subnet_rates.entry(subnet_key).or_insert(TokenBucket {
            tokens: self.config.budgets.per_subnet_burst,
            last: now,
            last_used: now,
        });
        let cost = usize::from(cost);
        self.global_rate.available(
            now,
            self.config.budgets.global_rate_burst,
            self.config.budgets.refill,
        );
        host.available(now, host_capacity, self.config.budgets.refill);
        network.available(
            now,
            self.config.budgets.per_subnet_burst,
            self.config.budgets.refill,
        );
        let missing_global = cost.saturating_sub(self.global_rate.tokens);
        let missing_host = cost.saturating_sub(host.tokens);
        let missing_subnet = cost.saturating_sub(network.tokens);
        let missing = missing_global.max(missing_host).max(missing_subnet);
        if missing > 0 {
            let periods = u32::try_from(missing).unwrap_or(u32::MAX);
            return AdmissionDecision::EligibleAt(
                now.saturating_add(self.config.budgets.refill.saturating_mul(periods)),
            );
        }
        self.global_rate.tokens -= cost;
        host.tokens -= cost;
        network.tokens -= cost;
        self.active += 1;
        *self.active_hosts.entry(request.target).or_default() += 1;
        AdmissionDecision::Admitted
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
    pub fn retry_delay(&mut self, request: &ProbeRequest, attempt: u8) -> Duration {
        let now = self.clock.monotonic();
        self.evict_state(now);
        let key = WorkKey::from(request);
        if self.failures.len() >= self.config.state_capacity && !self.failures.contains_key(&key) {
            return self.config.max_backoff;
        }
        let failures = self.failures.entry(key).or_insert(FailureState {
            count: 0,
            last_used: now,
        });
        failures.last_used = now;
        failures.count = failures.count.max(attempt.saturating_add(1)).min(16);
        let multiplier = 1u32
            .checked_shl(u32::from((failures.count - 1).min(15)))
            .unwrap_or(u32::MAX);
        self.config
            .base_backoff
            .checked_mul(multiplier)
            .unwrap_or(self.config.max_backoff)
            .min(self.config.max_backoff)
    }
    pub fn record_success(&mut self, request: &ProbeRequest) {
        self.failures.remove(&WorkKey::from(request));
    }
    pub fn jitter(&self, duration: Duration) -> Duration {
        let max = duration.mul_f64(f64::from(self.config.jitter_percent) / 100.0);
        if max.is_zero() {
            return Duration::ZERO;
        }
        let ceiling = max.as_nanos().min(u128::from(u32::MAX)) as u64;
        Duration::from_nanos(u64::from(self.clock.jitter_unit()) % (ceiling + 1))
    }
    fn evict_state(&mut self, now: Duration) {
        let ttl = self.config.state_ttl;
        self.host_rates
            .retain(|_, state| now.saturating_sub(state.last_used) <= ttl);
        self.subnet_rates
            .retain(|_, state| now.saturating_sub(state.last_used) <= ttl);
        self.failures
            .retain(|_, state| now.saturating_sub(state.last_used) <= ttl);
    }
    pub fn state_sizes(&self) -> (usize, usize, usize) {
        (
            self.host_rates.len(),
            self.subnet_rates.len(),
            self.failures.len(),
        )
    }
}
