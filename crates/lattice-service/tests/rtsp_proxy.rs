use async_trait::async_trait;
use lattice_camera::{HlsSessionId, LoopbackSourceToken};
use lattice_sensor::AuthorizedBinding;
use lattice_service::cameras::{
    ApprovedRtspTarget, AuthorizedRtspConnector, FakeAuthorizedRtspConnector, LoopbackRtspProxy,
    RtspConnection, RtspProxyError, RtspProxyLimits,
};
use secrecy::SecretString;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

const PASSWORD: &str = "proxy-password-leak-sentinel";

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
