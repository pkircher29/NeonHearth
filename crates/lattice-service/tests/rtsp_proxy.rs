use async_trait::async_trait;
use lattice_camera::{HlsSessionId, LoopbackSourceToken};
use lattice_sensor::{AuthorizedBinding, InterfaceClass, SystemInterfaceManager};
use lattice_service::cameras::{
    ApprovedRtspTarget, AuthorizedRtspConnector, FakeAuthorizedRtspConnector, LoopbackRtspProxy,
    RtspConnection, RtspProxyError, RtspProxyLimits, SystemAuthorizedRtspConnector,
};
use secrecy::SecretString;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::Instant,
};

const PASSWORD: &str = "proxy-password-leak-sentinel";

#[cfg(target_os = "linux")]
fn loopback_binding(interface_index: u32) -> AuthorizedBinding {
    AuthorizedBinding {
        source: IpAddr::V4(Ipv4Addr::LOCALHOST),
        interface_index,
        target: IpAddr::V4(Ipv4Addr::LOCALHOST),
    }
}

#[cfg(target_os = "linux")]
fn loopback_interface_index() -> u32 {
    SystemInterfaceManager
        .snapshot()
        .unwrap()
        .interfaces()
        .find(|interface| interface.class == InterfaceClass::Loopback)
        .expect("loopback interface")
        .id
        .get()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn system_connector_accepts_an_os_verified_interface_pin() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

    let connection = SystemAuthorizedRtspConnector
        .connect(loopback_binding(loopback_interface_index()), port)
        .await
        .unwrap();
    drop(connection);
    accept.await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn system_connector_rejects_an_invalid_interface_before_connecting() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let result = SystemAuthorizedRtspConnector
        .connect(loopback_binding(u32::MAX), port)
        .await;
    assert!(matches!(result, Err(RtspProxyError::Unavailable)));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "invalid interface must be rejected before any upstream connection"
    );
}

fn binding(target: [u8; 4]) -> AuthorizedBinding {
    AuthorizedBinding {
        source: IpAddr::V4(Ipv4Addr::new(192, 168, 4, 5)),
        interface_index: 7,
        target: IpAddr::V4(Ipv4Addr::from(target)),
    }
}

fn approved(target: [u8; 4]) -> ApprovedRtspTarget {
    ApprovedRtspTarget::new(binding(target), 8554).unwrap()
}

fn limits() -> RtspProxyLimits {
    RtspProxyLimits {
        max_connections: 2,
        max_header_bytes: 4096,
        max_body_bytes: 8192,
        max_interleaved_frame_bytes: 4096,
        io_timeout: Duration::from_secs(2),
        lease_ttl: Duration::from_secs(30),
    }
}

async fn request(port: u16, value: &[u8]) -> Vec<u8> {
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    client.write_all(value).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    response
}

async fn read_rtsp_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
    }
    response
}

fn authorization(request: &[u8]) -> &str {
    std::str::from_utf8(request)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("Authorization: "))
        .expect("authorization header")
}

fn quoted_parameter<'a>(header: &'a str, name: &str) -> &'a str {
    let prefix = format!("{name}=\"");
    let value = header
        .split(", ")
        .find_map(|part| part.strip_prefix(&prefix))
        .expect("quoted digest parameter");
    value.strip_suffix('"').expect("closing quote")
}

#[tokio::test]
async fn proxy_rejects_target_mismatch_before_any_connection_and_redacts_failures() {
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(Vec::new()));
    let error = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.99:8554/live")),
        approved([192, 168, 4, 22]),
        connector.clone(),
        limits(),
    )
    .await
    .unwrap_err();
    assert_eq!(error, RtspProxyError::TargetMismatch);
    assert_eq!(connector.connection_count().await, 0);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(PASSWORD));
    assert!(!rendered.contains("192.168"));

    let error = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8555/live")),
        approved([192, 168, 4, 22]),
        connector.clone(),
        limits(),
    )
    .await
    .unwrap_err();
    assert_eq!(error, RtspProxyError::TargetMismatch);
    assert_eq!(connector.connection_count().await, 0);
}

#[tokio::test]
async fn proxy_accepts_only_exact_token_path_and_methods_on_loopback() {
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(vec![
        b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ]));
    let token =
        LoopbackSourceToken::from_canonical("0190c6d1-1234-7abc-8def-0123456789ab").unwrap();
    let proxy = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        token.clone(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        connector.clone(),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(proxy.local_addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        proxy.endpoint(),
        format!(
            "rtsp://127.0.0.1:{}/source/{token}",
            proxy.local_addr().port()
        )
    );

    let wrong = request(
        proxy.local_addr().port(),
        b"DESCRIBE rtsp://127.0.0.1/source/wrong RTSP/1.0\r\nCSeq: 1\r\n\r\n",
    )
    .await;
    assert!(wrong.starts_with(b"RTSP/1.0 403"));
    let traversal = request(
        proxy.local_addr().port(),
        format!(
            "DESCRIBE rtsp://127.0.0.1:{}/source/{token}/../secret RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            proxy.local_addr().port()
        )
        .as_bytes(),
    )
    .await;
    assert!(traversal.starts_with(b"RTSP/1.0 400") || traversal.starts_with(b"RTSP/1.0 403"));
    let method = request(
        proxy.local_addr().port(),
        format!(
            "DELETE rtsp://127.0.0.1:{}/source/{token} RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            proxy.local_addr().port()
        )
        .as_bytes(),
    )
    .await;
    assert!(method.starts_with(b"RTSP/1.0 405"));
    let wrong_port = request(
        proxy.local_addr().port(),
        format!(
            "OPTIONS rtsp://127.0.0.1:{}/source/{token} RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            proxy.local_addr().port() + 1
        )
        .as_bytes(),
    )
    .await;
    assert!(wrong_port.starts_with(b"RTSP/1.0 403"));
    assert_eq!(connector.connection_count().await, 0);
}

struct DelayedFrameConnector;

#[async_trait]
impl AuthorizedRtspConnector for DelayedFrameConnector {
    async fn connect(
        &self,
        _binding: AuthorizedBinding,
        _port: u16,
    ) -> Result<Box<dyn RtspConnection>, RtspProxyError> {
        let (proxy, mut fixture) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                fixture.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            fixture
                .write_all(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            fixture.write_all(&[b'$', 0, 0, 3, 1, 2, 3]).await.unwrap();
        });
        Ok(Box::new(proxy))
    }
}

struct NonCooperativeConnector {
    entered: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

#[async_trait]
impl AuthorizedRtspConnector for NonCooperativeConnector {
    async fn connect(
        &self,
        _binding: AuthorizedBinding,
        _port: u16,
    ) -> Result<Box<dyn RtspConnection>, RtspProxyError> {
        self.entered.store(true, Ordering::Release);
        while !self.stop.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        Err(RtspProxyError::Unavailable)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_shutdown_is_bounded_when_a_connection_task_will_not_yield() {
    let owner = HlsSessionId::new();
    let entered = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let mut bounded = limits();
    bounded.io_timeout = Duration::from_millis(20);
    let proxy = LoopbackRtspProxy::start(
        owner.clone(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        Arc::new(NonCooperativeConnector {
            entered: entered.clone(),
            stop: stop.clone(),
        }),
        bounded,
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    client
        .write_all(format!("OPTIONS {} RTSP/1.0\r\nCSeq: 1\r\n\r\n", proxy.endpoint()).as_bytes())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(100), async {
        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let result = tokio::time::timeout(Duration::from_millis(200), proxy.shutdown(&owner)).await;
    stop.store(true, Ordering::Release);
    assert!(matches!(result, Ok(Err(RtspProxyError::Timeout))));
}

#[tokio::test]
async fn delayed_interleaved_frames_flow_without_another_client_request() {
    let owner = HlsSessionId::new();
    let proxy = LoopbackRtspProxy::start(
        owner.clone(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        Arc::new(DelayedFrameConnector),
        limits(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    client
        .write_all(format!("PLAY {} RTSP/1.0\r\nCSeq: 1\r\n\r\n", proxy.endpoint()).as_bytes())
        .await
        .unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_millis(250), async {
        while !received.ends_with(&[b'$', 0, 0, 3, 1, 2, 3]) {
            let mut byte = [0_u8; 1];
            client.read_exact(&mut byte).await.unwrap();
            received.push(byte[0]);
        }
    })
    .await
    .expect("proxy stalled after PLAY response");
    proxy.shutdown(&owner).await.unwrap();
}

#[tokio::test]
async fn basic_auth_is_injected_and_sdp_and_location_are_rewritten_to_the_lease() {
    let sdp = b"v=0\r\no=- 1 1 IN IP4 192.168.4.22\r\nc=IN IP4 192.168.4.22\r\na=control:rtsp://192.168.4.22:8554/live/trackID=1\r\n";
    let response = format!(
        "RTSP/1.0 200 OK\r\nCSeq: 7\r\nContent-Base: rtsp://192.168.4.22:8554/live/\r\nLocation: rtsp://192.168.4.22:8554/live\r\nRTP-Info: url=rtsp://192.168.4.22:8554/live/trackID=1;seq=7\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;source=192.168.4.22\r\nX-Upstream-Debug: rtsp://192.168.4.22/private\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n",
        sdp.len()
    ).into_bytes().into_iter().chain(sdp.iter().copied()).collect();
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(vec![response]));
    let token = LoopbackSourceToken::new();
    let proxy = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        token.clone(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        connector.clone(),
        limits(),
    )
    .await
    .unwrap();
    let uri = proxy.endpoint();
    let response = request(
        proxy.local_addr().port(),
        format!("DESCRIBE {uri} RTSP/1.0\r\nCSeq: 7\r\nAccept: application/sdp\r\n\r\n").as_bytes(),
    )
    .await;
    let text = String::from_utf8(response).unwrap();
    assert!(text.contains(&format!("Content-Base: {uri}/")));
    assert!(text.contains(&format!("Location: {uri}")));
    assert!(text.contains(&format!("a=control:{uri}/trackID=1")));
    assert!(text.contains(&format!("RTP-Info: url={uri}/trackID=1;seq=7")));
    assert!(!text.contains("X-Upstream-Debug"));
    assert!(!text.contains("192.168.4.22"));
    assert!(!text.contains(PASSWORD));
    let upstream = String::from_utf8(connector.requests().await.concat()).unwrap();
    assert!(upstream.contains("Authorization: Basic "));
    assert!(upstream.starts_with("DESCRIBE rtsp://192.168.4.22:8554/live RTSP/1.0"));
    assert!(!upstream.contains(&token.to_string()));
}

#[tokio::test]
async fn parameterized_mixed_case_sdp_media_type_is_rewritten() {
    let sdp = b"v=0\r\na=control:rtsp://192.168.4.22:8554/live/trackID=1\r\n";
    let response = format!(
        "RTSP/1.0 200 OK\r\nCSeq: 8\r\nContent-Type: Application/SDP; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
        sdp.len()
    )
    .into_bytes()
    .into_iter()
    .chain(sdp.iter().copied())
    .collect();
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(vec![response]));
    let proxy = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        connector,
        limits(),
    )
    .await
    .unwrap();
    let response = request(
        proxy.local_addr().port(),
        format!("DESCRIBE {} RTSP/1.0\r\nCSeq: 8\r\n\r\n", proxy.endpoint()).as_bytes(),
    )
    .await;
    let text = String::from_utf8(response).unwrap();
    assert!(text.contains(&format!("a=control:{}/trackID=1", proxy.endpoint())));
    assert!(!text.contains("192.168.4.22"));
}

#[tokio::test]
async fn setup_transport_is_single_copy_stripped_and_tcp_only() {
    let response = b"RTSP/1.0 200 OK\r\nCSeq: 10\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;source=192.168.4.22;destination=192.168.4.5\r\nContent-Length: 0\r\n\r\n".to_vec();
    let proxy = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        Arc::new(FakeAuthorizedRtspConnector::new(vec![response])),
        limits(),
    )
    .await
    .unwrap();
    let response = request(
        proxy.local_addr().port(),
        format!(
            "SETUP {}/trackID=1 RTSP/1.0\r\nCSeq: 10\r\n\r\n",
            proxy.endpoint()
        )
        .as_bytes(),
    )
    .await;
    let text = String::from_utf8(response).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("Transport:"))
            .collect::<Vec<_>>(),
        ["Transport: RTP/AVP/TCP;unicast;interleaved=0-1"]
    );
    assert!(!text.to_ascii_lowercase().contains("source="));
    assert!(!text.to_ascii_lowercase().contains("destination="));

    for transport in [
        "RTP/AVP;unicast;client_port=8000-8001",
        "RTP/AVP/TCP;;interleaved=0-1",
    ] {
        let response = format!(
            "RTSP/1.0 200 OK\r\nCSeq: 11\r\nTransport: {transport}\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes();
        let proxy = LoopbackRtspProxy::start(
            HlsSessionId::new(),
            LoopbackSourceToken::new(),
            SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
            approved([192, 168, 4, 22]),
            Arc::new(FakeAuthorizedRtspConnector::new(vec![response])),
            limits(),
        )
        .await
        .unwrap();
        let response = request(
            proxy.local_addr().port(),
            format!(
                "SETUP {}/trackID=1 RTSP/1.0\r\nCSeq: 11\r\n\r\n",
                proxy.endpoint()
            )
            .as_bytes(),
        )
        .await;
        assert!(response.is_empty(), "unsafe Transport was forwarded");
    }
}

#[tokio::test]
async fn rtp_info_rejects_a_residual_external_rtsp_url_after_expected_rewrite() {
    let response = b"RTSP/1.0 200 OK\r\nCSeq: 12\r\nRTP-Info: url=rtsp://192.168.4.22:8554/live/trackID=1;seq=1,url=rtsp://evil.example/private;seq=2\r\nContent-Length: 0\r\n\r\n".to_vec();
    let proxy = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        Arc::new(FakeAuthorizedRtspConnector::new(vec![response])),
        limits(),
    )
    .await
    .unwrap();
    let response = request(
        proxy.local_addr().port(),
        format!("PLAY {} RTSP/1.0\r\nCSeq: 12\r\n\r\n", proxy.endpoint()).as_bytes(),
    )
    .await;
    assert!(
        response.is_empty(),
        "mixed RTP-Info leaked a residual external RTSP URL: {}",
        String::from_utf8_lossy(&response)
    );
}

#[tokio::test]
async fn digest_challenge_is_answered_internally_and_never_forwarded() {
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(vec![
        b"RTSP/1.0 401 Unauthorized\r\nCSeq: 9\r\nWWW-Authenticate: Digest realm=\"camera\", nonce=\"abc123\", algorithm=MD5, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"RTSP/1.0 200 OK\r\nCSeq: 9\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ]));
    let proxy = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        connector.clone(),
        limits(),
    )
    .await
    .unwrap();
    let response = request(
        proxy.local_addr().port(),
        format!("DESCRIBE {} RTSP/1.0\r\nCSeq: 9\r\n\r\n", proxy.endpoint()).as_bytes(),
    )
    .await;
    assert!(response.starts_with(b"RTSP/1.0 200"));
    assert!(!String::from_utf8_lossy(&response).contains("WWW-Authenticate"));
    let requests = connector.requests().await;
    assert_eq!(requests.len(), 2);
    let second = String::from_utf8_lossy(&requests[1]);
    assert!(second.contains("Authorization: Digest username=\"viewer\""));
    assert!(second.contains("realm=\"camera\""));
    assert!(second.contains("nonce=\"abc123\""));
    assert!(second.contains("qop=auth"));
    assert!(!second.contains(PASSWORD));
}

#[tokio::test]
async fn repeated_digest_nonce_increments_nc_and_changes_authorization() {
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(vec![
        b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"camera\", nonce=\"same-nonce\", algorithm=MD5, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\nWWW-Authenticate: Digest realm=\"camera\", nonce=\"same-nonce\", algorithm=MD5, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ]));
    let proxy = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        connector.clone(),
        limits(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    for cseq in [1, 2] {
        client
            .write_all(
                format!(
                    "DESCRIBE {} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n",
                    proxy.endpoint()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            read_rtsp_head(&mut client)
                .await
                .starts_with(b"RTSP/1.0 200")
        );
    }
    let requests = connector.requests().await;
    assert_eq!(requests.len(), 4);
    let first = authorization(&requests[1]);
    let second = authorization(&requests[3]);
    assert!(first.contains("nc=00000001"));
    assert!(second.contains("nc=00000002"));
    assert_ne!(first, second);
    let cnonce = quoted_parameter(first, "cnonce");
    assert_eq!(cnonce.len(), 32);
    assert!(cnonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(quoted_parameter(second, "cnonce"), cnonce);
    assert_ne!(cnonce, "neonhearth");
}

#[tokio::test]
async fn digest_new_and_stale_nonces_reset_count_and_rotate_cnonce() {
    let challenge = |cseq: u8, nonce: &str, stale: bool| {
        format!(
            "RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"camera\", nonce=\"{nonce}\", algorithm=MD5, qop=\"AUTH\"{}\r\nContent-Length: 0\r\n\r\n",
            if stale { ", stale=TRUE" } else { "" }
        )
        .into_bytes()
    };
    let ok = |cseq: u8| {
        format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: 0\r\n\r\n").into_bytes()
    };
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(vec![
        challenge(1, "nonce-one", false),
        ok(1),
        challenge(2, "nonce-two", false),
        ok(2),
        challenge(3, "nonce-two", true),
        ok(3),
    ]));
    let proxy = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        connector.clone(),
        limits(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    for cseq in [1, 2, 3] {
        client
            .write_all(
                format!(
                    "OPTIONS {} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n",
                    proxy.endpoint()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            read_rtsp_head(&mut client)
                .await
                .starts_with(b"RTSP/1.0 200")
        );
    }
    let requests = connector.requests().await;
    let headers = [
        authorization(&requests[1]),
        authorization(&requests[3]),
        authorization(&requests[5]),
    ];
    assert!(headers.iter().all(|header| header.contains("nc=00000001")));
    let cnonces = headers.map(|header| quoted_parameter(header, "cnonce"));
    assert_ne!(cnonces[0], cnonces[1]);
    assert_ne!(cnonces[1], cnonces[2]);
}

#[tokio::test]
async fn digest_rejects_unsupported_qop_without_forwarding_credentials() {
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(vec![
        b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"camera\", nonce=\"abc\", algorithm=MD5, qop=\"auth-int\"\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ]));
    let proxy = LoopbackRtspProxy::start(
        HlsSessionId::new(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        connector.clone(),
        limits(),
    )
    .await
    .unwrap();
    let response = request(
        proxy.local_addr().port(),
        format!("DESCRIBE {} RTSP/1.0\r\nCSeq: 1\r\n\r\n", proxy.endpoint()).as_bytes(),
    )
    .await;
    assert!(response.is_empty());
    assert_eq!(connector.requests().await.len(), 1);
}

#[tokio::test]
async fn lease_enforces_owner_expiry_and_interleaved_frame_bound() {
    let mut small = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n".to_vec();
    small.extend_from_slice(&[b'$', 0, 0, 3, 1, 2, 3]);
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(vec![small]));
    let owner = HlsSessionId::new();
    let mut short = limits();
    short.lease_ttl = Duration::from_millis(30);
    let proxy = LoopbackRtspProxy::start(
        owner.clone(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        connector,
        short,
    )
    .await
    .unwrap();
    assert_eq!(
        proxy.shutdown(&HlsSessionId::new()).await,
        Err(RtspProxyError::WrongOwner)
    );
    tokio::time::sleep_until(Instant::now() + Duration::from_millis(50)).await;
    if let Ok(mut expired_client) = TcpStream::connect(proxy.local_addr()).await {
        expired_client
            .write_all(
                format!("OPTIONS {} RTSP/1.0\r\nCSeq: 1\r\n\r\n", proxy.endpoint()).as_bytes(),
            )
            .await
            .unwrap();
        let mut expired = Vec::new();
        expired_client.read_to_end(&mut expired).await.unwrap();
        assert!(expired.is_empty() || expired.starts_with(b"RTSP/1.0 403"));
    }
    proxy.shutdown(&owner).await.unwrap();

    let mut capped = limits();
    capped.max_interleaved_frame_bytes = 2;
    let connector = Arc::new(FakeAuthorizedRtspConnector::new(vec![vec![
        b'$', 0, 0, 3, 1, 2, 3,
    ]]));
    let owner = HlsSessionId::new();
    let proxy = LoopbackRtspProxy::start(
        owner.clone(),
        LoopbackSourceToken::new(),
        SecretString::from(format!("rtsp://viewer:{PASSWORD}@192.168.4.22:8554/live")),
        approved([192, 168, 4, 22]),
        connector,
        capped,
    )
    .await
    .unwrap();
    let response = request(
        proxy.local_addr().port(),
        format!("PLAY {} RTSP/1.0\r\nCSeq: 1\r\n\r\n", proxy.endpoint()).as_bytes(),
    )
    .await;
    assert!(response.is_empty());
    proxy.shutdown(&owner).await.unwrap();
}
