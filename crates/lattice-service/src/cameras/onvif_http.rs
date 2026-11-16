//! The production ONVIF transport: SOAP over plain HTTP to one approved
//! camera address.
//!
//! The transport implements exactly what [`OnvifTransport`] specifies. The
//! inventory builds each SOAP request and the bounded response writer; this
//! module adds the WS-UsernameToken (digest) security header the library
//! leaves to the transport, POSTs the request, and streams the answer into the
//! writer. Nothing else leaves the machine.
//!
//! What it refuses, in addition to the library's own bounds:
//! - any target other than the single approved IPv4 address, or any TLS target
//!   (the owner approved an address, and this build speaks plain ONVIF HTTP);
//! - redirects (never followed, so a camera cannot bounce the request, and the
//!   password digest, to another host);
//! - proxies (the environment's proxy settings are ignored);
//! - a source address other than the approved interface's own, so the traffic
//!   cannot leave through a different network;
//! - a `GetCapabilities` answer that advertises a service address on any host
//!   other than the approved one.
//!
//! The password never appears in the request: only a digest of a fresh nonce,
//! a timestamp and the password does, so a LAN observer cannot replay it later.

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use lattice_camera::{
    OnvifAction, OnvifCredential, OnvifError, OnvifRequest, OnvifResponseWriter, OnvifTransport,
    TargetAddress,
};
use secrecy::ExposeSecret;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use url::{Host, Url};
use zeroize::Zeroizing;

#[cfg(any(test, feature = "test-support"))]
use std::net::SocketAddr;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How much of an error reply is read to recognise a SOAP "not authorized"
/// fault. Nothing from it is stored or returned.
const FAULT_BODY_LIMIT: usize = 8 * 1024;
const WSSE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const PASSWORD_DIGEST: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const BASE64_BINARY: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

/// Set by the transport when the camera advertised a service on another host,
/// so the caller can tell that refusal from an ordinary protocol error.
pub type ForeignServiceFlag = Arc<AtomicBool>;

pub struct HttpOnvifTransport {
    approved: Ipv4Addr,
    client: reqwest::Client,
    foreign_service: ForeignServiceFlag,
    #[cfg(any(test, feature = "test-support"))]
    endpoint_override: Option<SocketAddr>,
}

impl HttpOnvifTransport {
    /// A transport for one approved camera address, with every connection bound
    /// to `source`, the local address of the approved interface.
    pub fn new(
        approved: Ipv4Addr,
        source: IpAddr,
        foreign_service: ForeignServiceFlag,
    ) -> Result<Self, OnvifError> {
        Ok(Self {
            approved,
            client: client_builder()
                .local_address(Some(source))
                .build()
                .map_err(|_| OnvifError::Transport)?,
            foreign_service,
            #[cfg(any(test, feature = "test-support"))]
            endpoint_override: None,
        })
    }

    /// Test seam: the requests still name the approved address (and are
    /// refused for any other), but the TCP connection goes to `endpoint`, a
    /// loopback listener standing in for the camera. Production code cannot
    /// construct this: the field and the constructor do not exist without the
    /// `test-support` feature, and [`TargetAddress`] refuses loopback anyway.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_loopback_endpoint(
        approved: Ipv4Addr,
        endpoint: SocketAddr,
        foreign_service: ForeignServiceFlag,
    ) -> Result<Self, OnvifError> {
        Ok(Self {
            approved,
            client: client_builder()
                .build()
                .map_err(|_| OnvifError::Transport)?,
            foreign_service,
            endpoint_override: Some(endpoint),
        })
    }

    fn url(&self, target: &TargetAddress) -> String {
        #[cfg(any(test, feature = "test-support"))]
        {
            if let Some(endpoint) = self.endpoint_override {
                return format!("http://{endpoint}{}", target.path());
            }
        }
        format!(
            "http://{}:{}{}",
            self.approved,
            target.port(),
            target.path()
        )
    }
}

fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .pool_max_idle_per_host(0)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .http1_only()
}

fn map_send_error(error: &reqwest::Error) -> OnvifError {
    if error.is_timeout() {
        OnvifError::Timeout
    } else {
        OnvifError::Transport
    }
}

#[async_trait]
impl OnvifTransport for HttpOnvifTransport {
    async fn request(
        &self,
        target: &TargetAddress,
        request: &OnvifRequest,
        credential: Option<&OnvifCredential>,
        response: &mut OnvifResponseWriter,
    ) -> Result<(), OnvifError> {
        if target.address() != IpAddr::V4(self.approved) || target.tls() {
            return Err(OnvifError::InvalidTarget);
        }
        let body = signed_request(request.request_bytes(), credential)?;
        let mut reply = self
            .client
            .post(self.url(target))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/soap+xml; charset=utf-8",
            )
            .timeout(request.timeout())
            .body(body)
            .send()
            .await
            .map_err(|error| map_send_error(&error))?;
        let status = reply.status();
        if status.is_redirection() {
            // Redirects are never followed; the camera gets no say in where
            // the next request, or the credential digest, goes.
            return Err(OnvifError::Transport);
        }
        if !status.is_success() {
            let mut fault = Vec::new();
            while fault.len() < FAULT_BODY_LIMIT {
                match reply.chunk().await {
                    Ok(Some(chunk)) => fault.extend_from_slice(&chunk),
                    Ok(None) | Err(_) => break,
                }
            }
            return Err(
                if status.as_u16() == 401 || status.as_u16() == 403 || is_not_authorized(&fault) {
                    OnvifError::Authentication
                } else {
                    OnvifError::InvalidResponse
                },
            );
        }
        if reply
            .content_length()
            .is_some_and(|length| length > request.max_response_bytes() as u64)
        {
            return Err(OnvifError::ResponseTooLarge);
        }
        let inspect = matches!(request.action(), OnvifAction::GetCapabilities);
        let mut copy = Vec::new();
        while let Some(chunk) = reply
            .chunk()
            .await
            .map_err(|error| map_send_error(&error))?
        {
            // The writer enforces the response cap before retaining anything.
            response.append_chunk(&chunk)?;
            if inspect {
                copy.extend_from_slice(&chunk);
            }
        }
        if inspect && !service_addresses_are_on(&copy, self.approved) {
            self.foreign_service.store(true, Ordering::SeqCst);
            return Err(OnvifError::InvalidResponse);
        }
        Ok(())
    }
}

/// True when the (already bounded) error body is a SOAP fault saying the
/// credentials were not accepted.
fn is_not_authorized(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    text.contains("notauthorized")
        || text.contains("not authorized")
        || text.contains("unauthorized")
        || text.contains("failedauthentication")
}

/// Every `XAddr` text in the document, in order. Only the element's local name
/// is matched, so any namespace prefix works.
fn service_addresses(xml: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(xml);
    let mut found = Vec::new();
    for (index, _) in text.match_indices("XAddr>") {
        let Some(open) = text[..index].rfind('<') else {
            continue;
        };
        let name = &text[open + 1..index + "XAddr".len()];
        if name.starts_with('/') {
            continue;
        }
        let local = name.rsplit(':').next().unwrap_or(name);
        if local != "XAddr" {
            continue;
        }
        let start = index + "XAddr>".len();
        let end = text[start..]
            .find('<')
            .map_or(text.len(), |end| start + end);
        found.push(text[start..end].trim().to_owned());
    }
    found
}

/// Whether every service address the camera advertised is on `approved`.
/// A hostname, an unparseable address, or any other IP is refused.
fn service_addresses_are_on(xml: &[u8], approved: Ipv4Addr) -> bool {
    service_addresses(xml).iter().all(|address| {
        let Ok(url) = Url::parse(address) else {
            return false;
        };
        let host = match url.host() {
            Some(Host::Ipv4(host)) => IpAddr::V4(host),
            Some(Host::Ipv6(host)) => IpAddr::V6(host),
            Some(Host::Domain(host)) => match host.parse::<IpAddr>() {
                Ok(host) => host,
                Err(_) => return false,
            },
            None => return false,
        };
        host == IpAddr::V4(approved)
    })
}

/// Inserts the WS-UsernameToken digest header into the library's request. The
/// username is restricted to `[A-Za-z0-9._-]` by [`OnvifCredential`], so no
/// XML escaping is needed.
fn signed_request(
    bytes: &[u8],
    credential: Option<&OnvifCredential>,
) -> Result<Vec<u8>, OnvifError> {
    let Some(credential) = credential else {
        return Ok(bytes.to_vec());
    };
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| OnvifError::Transport)?;
    let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let header = security_header(credential, &nonce, &created);
    let marker = b"<s:Header>";
    let at = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or(OnvifError::InvalidTarget)?
        + marker.len();
    let mut signed = Vec::with_capacity(bytes.len() + header.len());
    signed.extend_from_slice(&bytes[..at]);
    signed.extend_from_slice(header.as_bytes());
    signed.extend_from_slice(&bytes[at..]);
    Ok(signed)
}

fn security_header(credential: &OnvifCredential, nonce: &[u8], created: &str) -> String {
    let digest = password_digest(nonce, created, credential.password().expose_secret());
    format!(
        "<wsse:Security xmlns:wsse=\"{WSSE}\" xmlns:wsu=\"{WSU}\" s:mustUnderstand=\"1\"><wsse:UsernameToken><wsse:Username>{}</wsse:Username><wsse:Password Type=\"{PASSWORD_DIGEST}\">{digest}</wsse:Password><wsse:Nonce EncodingType=\"{BASE64_BINARY}\">{}</wsse:Nonce><wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security>",
        credential.username(),
        BASE64.encode(nonce),
    )
}

/// `base64(sha1(nonce + created + password))`, the WS-Security UsernameToken
/// profile's `PasswordDigest`.
pub(crate) fn password_digest(nonce: &[u8], created: &str, password: &str) -> String {
    let mut input = Zeroizing::new(Vec::with_capacity(
        nonce.len() + created.len() + password.len(),
    ));
    input.extend_from_slice(nonce);
    input.extend_from_slice(created.as_bytes());
    input.extend_from_slice(password.as_bytes());
    BASE64.encode(sha1(&input))
}

/// SHA-1, needed only because the WS-Security digest is defined with it. It
/// is not used to protect anything stored.
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut message = Zeroizing::new(data.to_vec());
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(data.len() as u64).wrapping_mul(8).to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut words = [0_u32; 80];
        for (word, bytes) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999_u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut digest = [0_u8; 20];
    for (bytes, word) in digest.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// An in-process stand-in for a camera, listening on loopback, for tests of
/// this transport and of the add-camera route. It speaks just enough HTTP and
/// ONVIF for the library's inventory, checks the WS-UsernameToken digest, and
/// can misbehave in the ways the transport must refuse.
#[cfg(any(test, feature = "test-support"))]
pub mod fake_device {
    use super::{BASE64, password_digest};
    use base64::Engine as _;
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    #[derive(Clone, Debug)]
    pub enum Behavior {
        /// Answers every action correctly.
        Normal,
        /// Answers every request with a redirect to this URL.
        Redirect(String),
        /// Sends a body far larger than the response cap, with a length.
        Oversized,
        /// Sends an endless-looking body without a length, then closes.
        OversizedWithoutLength,
        /// Answers 401 whatever the credentials are.
        Unauthorized,
    }

    #[derive(Clone, Debug)]
    pub struct Config {
        pub username: String,
        pub password: String,
        /// The URI returned by `GetStreamUri`.
        pub stream_uri: String,
        /// A service address advertised in `GetCapabilities`.
        pub capabilities_xaddr: Option<String>,
        pub behavior: Behavior,
    }

    impl Config {
        #[must_use]
        pub fn new(username: &str, password: &str, stream_uri: &str) -> Self {
            Self {
                username: username.to_owned(),
                password: password.to_owned(),
                stream_uri: stream_uri.to_owned(),
                capabilities_xaddr: None,
                behavior: Behavior::Normal,
            }
        }
    }

    pub struct FakeOnvifDevice {
        addr: SocketAddr,
        requests: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl Drop for FakeOnvifDevice {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl FakeOnvifDevice {
        /// Starts listening on an ephemeral loopback port.
        pub async fn start(config: Config) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake device");
            let addr = listener.local_addr().expect("fake device address");
            let requests = Arc::new(AtomicUsize::new(0));
            let counter = requests.clone();
            let config = Arc::new(config);
            let task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let config = config.clone();
                    let counter = counter.clone();
                    tokio::spawn(async move {
                        let _ = serve(stream, &config, &counter).await;
                    });
                }
            });
            Self {
                addr,
                requests,
                task,
            }
        }

        #[must_use]
        pub fn addr(&self) -> SocketAddr {
            self.addr
        }

        /// How many requests this device has received.
        #[must_use]
        pub fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<String> {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > 256 * 1024 {
                return None;
            }
            let text = String::from_utf8_lossy(&buffer).into_owned();
            if let Some(split) = text.find("\r\n\r\n") {
                let length = text[..split]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if buffer.len() >= split + 4 + length {
                    return Some(text);
                }
            }
        }
    }

    fn between<'a>(text: &'a str, open: &str, close: &str) -> Option<&'a str> {
        let start = text.find(open)? + open.len();
        let end = text[start..].find(close)? + start;
        Some(&text[start..end])
    }

    fn authorized(request: &str, config: &Config) -> bool {
        let (Some(username), Some(digest), Some(nonce), Some(created)) = (
            between(request, "<wsse:Username>", "</wsse:Username>"),
            between(request, "PasswordDigest\">", "</wsse:Password>"),
            between(request, "Base64Binary\">", "</wsse:Nonce>"),
            between(request, "<wsu:Created>", "</wsu:Created>"),
        ) else {
            return false;
        };
        let Ok(nonce) = BASE64.decode(nonce) else {
            return false;
        };
        username == config.username && digest == password_digest(&nonce, created, &config.password)
    }

    async fn serve(
        mut stream: tokio::net::TcpStream,
        config: &Config,
        requests: &AtomicUsize,
    ) -> Option<()> {
        let request = read_request(&mut stream).await?;
        requests.fetch_add(1, Ordering::SeqCst);
        let reply: Vec<u8> = match &config.behavior {
            Behavior::Redirect(location) => format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
            Behavior::Unauthorized => {
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            }
            Behavior::Oversized => {
                let body = vec![b'x'; 2 * 1024 * 1024];
                let mut reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                reply.extend_from_slice(&body);
                reply
            }
            Behavior::OversizedWithoutLength => {
                let mut reply = b"HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nConnection: close\r\n\r\n".to_vec();
                reply.extend_from_slice(&vec![b'x'; 2 * 1024 * 1024]);
                reply
            }
            Behavior::Normal => {
                if authorized(&request, config) {
                    let body = answer(&request, config);
                    let mut reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    reply.extend_from_slice(body.as_bytes());
                    reply
                } else {
                    let body = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>ter:NotAuthorized</s:Value></s:Subcode></s:Code><s:Reason><s:Text>Sender not Authorized</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>";
                    format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .into_bytes()
                }
            }
        };
        // The client may stop reading an oversized body early; that is fine.
        let _ = stream.write_all(&reply).await;
        let _ = stream.shutdown().await;
        Some(())
    }

    fn answer(request: &str, config: &Config) -> String {
        let message_id = between(request, "<wsa:MessageID>", "</wsa:MessageID>").unwrap_or("");
        let (action, body) = if request.contains("<tds:GetDeviceInformation/>") {
            ("http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse", "<tds:GetDeviceInformationResponse><tds:Manufacturer>FakeCam</tds:Manufacturer><tds:Model>F1</tds:Model><tds:FirmwareVersion>1.0</tds:FirmwareVersion><tds:SerialNumber>FAKE-1</tds:SerialNumber></tds:GetDeviceInformationResponse>".to_owned())
        } else if request.contains("<tds:GetCapabilities>") {
            let media = config.capabilities_xaddr.as_ref().map_or_else(
                || "<tt:Media/>".to_owned(),
                |xaddr| format!("<tt:Media><tt:XAddr>{xaddr}</tt:XAddr></tt:Media>"),
            );
            (
                "http://www.onvif.org/ver10/device/wsdl/GetCapabilitiesResponse",
                format!(
                    "<tds:GetCapabilitiesResponse><tds:Capabilities>{media}</tds:Capabilities></tds:GetCapabilitiesResponse>"
                ),
            )
        } else if request.contains("<trt:GetProfiles/>") {
            (
                "http://www.onvif.org/ver10/media/wsdl/GetProfilesResponse",
                "<trt:GetProfilesResponse><trt:Profiles token=\"main\"/></trt:GetProfilesResponse>"
                    .to_owned(),
            )
        } else if request.contains("<trt:GetStreamUri>") {
            (
                "http://www.onvif.org/ver10/media/wsdl/GetStreamUriResponse",
                format!(
                    "<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>{}</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>",
                    config.stream_uri
                ),
            )
        } else {
            ("http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse", "<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:DateTimeType>NTP</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings><tt:UTCDateTime><tt:Time><tt:Hour>12</tt:Hour><tt:Minute>34</tt:Minute><tt:Second>56</tt:Second></tt:Time><tt:Date><tt:Year>2026</tt:Year><tt:Month>8</tt:Month><tt:Day>24</tt:Day></tt:Date></tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>".to_owned())
        };
        format!(
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Header><wsa:Action>{action}</wsa:Action><wsa:RelatesTo>{message_id}</wsa:RelatesTo></s:Header><s:Body>{body}</s:Body></s:Envelope>"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::fake_device::{Behavior, Config, FakeOnvifDevice};
    use super::*;
    use lattice_camera::{
        CameraProfile, InventoryLimits, StreamId, StreamSecretSink, StreamSourceRef, inventory,
    };
    use secrecy::SecretString;
    use std::sync::Mutex;

    const APPROVED: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
    const PASSWORD: &str = "transport-test-password-sentinel";

    #[test]
    fn sha1_matches_the_published_test_vectors() {
        let hex = |digest: [u8; 20]| {
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            hex(sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // A multi-block message.
        assert_eq!(
            hex(sha1(&vec![b'a'; 1000])),
            "291e9a6c66994949b57ba5e650361e98fc36b1ba"
        );
    }

    #[test]
    fn password_digest_is_base64_of_sha1_of_nonce_created_password() {
        // A known answer computed independently with a reference SHA-1
        // (Python hashlib) over the raw nonce, then the timestamp, then the
        // password.
        let nonce = BASE64.decode("LKqI6G/AikKCQrN0zqZFlg==").unwrap();
        assert_eq!(
            password_digest(&nonce, "2003-07-16T01:24:32Z", "taadtaadpstcsm"),
            "vjwUgK9DkI4e3lonFkyGHvQPKlE="
        );
    }

    #[test]
    fn service_addresses_are_read_with_any_prefix_and_checked_against_the_host() {
        let xml = br#"<tt:Media><tt:XAddr>http://192.168.1.50/onvif/media</tt:XAddr></tt:Media>
            <Events><XAddr> http://192.168.1.50:8080/x </XAddr></Events><tt:Other>XAddr></tt:Other>"#;
        assert_eq!(
            service_addresses(xml),
            vec![
                "http://192.168.1.50/onvif/media".to_owned(),
                "http://192.168.1.50:8080/x".to_owned()
            ]
        );
        assert!(service_addresses_are_on(xml, APPROVED));
        assert!(service_addresses_are_on(b"<tt:Media/>", APPROVED));
        for refused in [
            "http://192.168.1.51/onvif",
            "http://camera.example/onvif",
            "http://127.0.0.1/onvif",
            "not a url",
        ] {
            let xml = format!("<tt:XAddr>{refused}</tt:XAddr>");
            assert!(
                !service_addresses_are_on(xml.as_bytes(), APPROVED),
                "{refused}"
            );
        }
    }

    #[test]
    fn the_security_header_never_contains_the_password() {
        let credential =
            OnvifCredential::new("admin", SecretString::from(PASSWORD.to_owned())).unwrap();
        let header = security_header(&credential, &[7; 16], "2026-01-01T00:00:00Z");
        assert!(!header.contains(PASSWORD));
        assert!(header.contains("<wsse:Username>admin</wsse:Username>"));
        assert!(header.contains("PasswordDigest"));
    }

    #[derive(Default)]
    struct CollectingSink(Mutex<Vec<String>>);
    impl StreamSecretSink for CollectingSink {
        fn store_all(
            &self,
            sources: Vec<(StreamId, SecretString)>,
        ) -> Result<Vec<StreamSourceRef>, OnvifError> {
            let mut seen = self.0.lock().unwrap();
            sources
                .into_iter()
                .enumerate()
                .map(|(index, (_, source))| {
                    seen.push(source.expose_secret().to_owned());
                    StreamSourceRef::new(format!("test-ref-{index}"))
                })
                .collect()
        }
    }

    fn target() -> TargetAddress {
        TargetAddress::new(IpAddr::V4(APPROVED), 80, false, "/onvif/device_service").unwrap()
    }

    fn credential(password: &str) -> OnvifCredential {
        OnvifCredential::new("admin", SecretString::from(password.to_owned())).unwrap()
    }

    async fn run(
        device: &FakeOnvifDevice,
        flag: &ForeignServiceFlag,
        password: &str,
    ) -> Result<Vec<CameraProfile>, OnvifError> {
        let transport =
            HttpOnvifTransport::with_loopback_endpoint(APPROVED, device.addr(), flag.clone())
                .unwrap();
        let sink = CollectingSink::default();
        inventory(
            &transport,
            &sink,
            target(),
            Some(&credential(password)),
            InventoryLimits::default(),
        )
        .await
        .map(|inventory| inventory.profiles)
    }

    fn config(stream_uri: &str) -> Config {
        Config::new("admin", PASSWORD, stream_uri)
    }

    #[tokio::test]
    async fn a_full_inventory_succeeds_against_a_loopback_fake_device() {
        let device = FakeOnvifDevice::start(config("rtsp://192.168.1.50:554/main")).await;
        let flag = ForeignServiceFlag::default();
        let profiles = run(&device, &flag, PASSWORD).await.unwrap();
        assert_eq!(profiles.len(), 1);
        // Device info, capabilities, profiles, one stream URI, date and time.
        assert_eq!(device.requests(), 5);
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_wrong_password_is_an_authentication_failure() {
        let device = FakeOnvifDevice::start(config("rtsp://192.168.1.50/main")).await;
        let flag = ForeignServiceFlag::default();
        assert_eq!(
            run(&device, &flag, "not-the-password").await.unwrap_err(),
            OnvifError::Authentication
        );
        // It stopped at the first refused request.
        assert_eq!(device.requests(), 1);
    }

    #[tokio::test]
    async fn a_401_is_an_authentication_failure() {
        let mut fake = config("rtsp://192.168.1.50/main");
        fake.behavior = Behavior::Unauthorized;
        let device = FakeOnvifDevice::start(fake).await;
        assert_eq!(
            run(&device, &ForeignServiceFlag::default(), PASSWORD)
                .await
                .unwrap_err(),
            OnvifError::Authentication
        );
    }

    #[tokio::test]
    async fn a_redirect_is_refused_and_never_followed() {
        let elsewhere = FakeOnvifDevice::start(config("rtsp://192.168.1.50/main")).await;
        let mut fake = config("rtsp://192.168.1.50/main");
        fake.behavior =
            Behavior::Redirect(format!("http://{}/onvif/device_service", elsewhere.addr()));
        let device = FakeOnvifDevice::start(fake).await;
        assert_eq!(
            run(&device, &ForeignServiceFlag::default(), PASSWORD)
                .await
                .unwrap_err(),
            OnvifError::Transport
        );
        assert_eq!(device.requests(), 1);
        assert_eq!(elsewhere.requests(), 0, "the redirect target was contacted");
    }

    #[tokio::test]
    async fn an_oversized_response_is_refused_with_and_without_a_length() {
        for behavior in [Behavior::Oversized, Behavior::OversizedWithoutLength] {
            let mut fake = config("rtsp://192.168.1.50/main");
            fake.behavior = behavior.clone();
            let device = FakeOnvifDevice::start(fake).await;
            assert_eq!(
                run(&device, &ForeignServiceFlag::default(), PASSWORD)
                    .await
                    .unwrap_err(),
                OnvifError::ResponseTooLarge,
                "{behavior:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_service_address_on_another_host_is_refused_and_flagged() {
        let mut fake = config("rtsp://192.168.1.50/main");
        fake.capabilities_xaddr = Some("http://192.168.1.99/onvif/media".to_owned());
        let device = FakeOnvifDevice::start(fake).await;
        let flag = ForeignServiceFlag::default();
        assert_eq!(
            run(&device, &flag, PASSWORD).await.unwrap_err(),
            OnvifError::InvalidResponse
        );
        assert!(flag.load(Ordering::SeqCst));
        // Device information and capabilities only: nothing after the refusal.
        assert_eq!(device.requests(), 2);
    }

    #[tokio::test]
    async fn a_service_address_on_the_approved_host_is_accepted() {
        let mut fake = config("rtsp://192.168.1.50/main");
        fake.capabilities_xaddr = Some("http://192.168.1.50/onvif/media".to_owned());
        let device = FakeOnvifDevice::start(fake).await;
        assert!(
            run(&device, &ForeignServiceFlag::default(), PASSWORD)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn only_the_approved_address_may_be_requested() {
        let device = FakeOnvifDevice::start(config("rtsp://192.168.1.50/main")).await;
        let transport = HttpOnvifTransport::with_loopback_endpoint(
            APPROVED,
            device.addr(),
            ForeignServiceFlag::default(),
        )
        .unwrap();
        let other = TargetAddress::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 51)), 80, false, "/x")
            .unwrap();
        let tls = TargetAddress::new(IpAddr::V4(APPROVED), 443, true, "/x").unwrap();
        for target in [other, tls] {
            let error = inventory(
                &transport,
                &CollectingSink::default(),
                target,
                Some(&credential(PASSWORD)),
                InventoryLimits::default(),
            )
            .await
            .unwrap_err();
            assert_eq!(error, OnvifError::InvalidTarget);
        }
        assert_eq!(device.requests(), 0);
    }
}
