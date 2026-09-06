use super::*;

fn response(body: &str, extra: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn facts(bytes: &[u8]) -> BTreeMap<String, String> {
    parse(bytes).unwrap().unwrap().facts.into_iter().collect()
}

#[test]
fn web_identification_omits_secrets_scripts_redirect_targets_and_body_text() {
    let result = facts(&response(
        "<!-- <title>Wrong camera</title> --><script>const x='<title>Wrong router</title>'</script><meta content='ESPHome 2026' name='generator'><TITLE>Kitchen &amp; Hall &#x1f4a1;</TITLE><form><input value='private-password'></form>",
        "Server: ESPHome\r\nSet-Cookie: session=SECRET\r\nAuthorization: SECRET\r\nLocation: http://127.0.0.1/private?token=SECRET\r\n",
    ));
    assert_eq!(result["web_title"], "Kitchen & Hall 💡");
    assert_eq!(result["web_generator"], "ESPHome 2026");
    assert_eq!(result["web_identity_hint"], "ESPHome");
    assert!(!format!("{result:?}").contains("SECRET"));
    assert!(!format!("{result:?}").contains("private-password"));
    assert!(!format!("{result:?}").contains("127.0.0.1"));
}

#[test]
fn web_identification_handles_chunked_html_and_quoted_attributes() {
    let body =
        "<meta content='Tasmota > 14' name=generator><title>Shelly &quot;Living room&quot;</title>";
    let split = 61;
    let encoded = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n{:x}\r\n{}\r\n{:x};ext=yes\r\n{}\r\n0\r\n\r\n",
        split,
        &body[..split],
        body.len() - split,
        &body[split..]
    );
    let result = facts(encoded.as_bytes());
    assert_eq!(result["web_title"], "Shelly \"Living room\"");
    assert_eq!(result["web_generator"], "Tasmota > 14");
    assert_eq!(result["web_identity_hint"], "Shelly");
}

#[test]
fn web_identification_rejects_invalid_framing_and_bounds_work() {
    for bytes in [
        b"SSH-2.0-OpenSSH\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\ngarbage\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
    ] { assert!(parse(bytes).is_err(), "{bytes:?}"); }
    assert!(parse(&vec![b'a'; MAX_RESPONSE_BYTES + 1]).is_err());
    let header = format!(
        "HTTP/1.1 200 OK\r\nServer: {}\r\n\r\n",
        "a".repeat(HEADER_CAP)
    );
    assert!(parse(header.as_bytes()).is_err());
    let result = facts(&response(
        &format!("<title>{}</title>", "💡".repeat(2000)),
        "",
    ));
    assert!(result["web_title"].len() <= MAX_FACT_VALUE_BYTES);
    assert!(!text("x\u{202e}\0y").contains('\u{202e}'));
}

#[test]
fn web_identification_handles_auth_without_retaining_the_challenge() {
    let result = facts(b"HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"Synology NAS\", nonce=\"SECRET\"\r\n\r\n");
    assert_eq!(result["web_status"], "401");
    assert_eq!(result["web_auth_realm"], "Synology NAS");
    assert_eq!(result["web_identity_hint"], "Synology NAS");
    assert!(!format!("{result:?}").contains("SECRET"));
    let generic = facts(&response(
        "<title>Welcome to nginx</title>",
        "Server: nginx\r\n",
    ));
    assert!(!generic.contains_key("web_identity_hint"));
    assert!(
        !facts(&response("<title>complex application</title>", ""))
            .contains_key("web_identity_hint")
    );
}

#[test]
fn web_identification_skips_compressed_and_non_html_bodies() {
    let result = facts(&response(
        "<title>Must not be read</title>",
        "Content-Encoding: gzip\r\n",
    ));
    assert!(!result.contains_key("web_title"));
    assert_eq!(result["web_read_limit"], "Encoded body skipped");
    let result = facts(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"private\":\"<title>SECRET</title>\"}");
    assert!(!format!("{result:?}").contains("SECRET"));
}

#[tokio::test]
async fn web_identification_reads_fragmented_http_with_a_credential_free_numeric_host() {
    let (mut client, mut server) = tokio::io::duplex(32768);
    let task = tokio::spawn(async move {
        let mut request = vec![];
        loop {
            let b = server.read_u8().await.unwrap();
            request.push(b);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET / HTTP/1.1\r\nHost: [fd00::1234]:8123\r\n"));
        assert!(!request.contains("Authorization"));
        assert!(!request.contains("Cookie"));
        for part in response("<title>Home Assistant</title>", "Server: Python\r\n").chunks(7) {
            if server.write_all(part).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    let result: BTreeMap<_, _> = exchange(&mut client, "fd00::1234".parse().unwrap(), 8123)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(result["web_title"], "Home Assistant");
    assert_eq!(result["web_identity_hint"], "Home Assistant");
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn web_identification_slow_peer_keeps_headers_and_stops_at_deadline() {
    let (mut client, mut server) = tokio::io::duplex(32768);
    let task = tokio::spawn(async move {
        let mut request = [0; 1024];
        let _ = server.read(&mut request).await.unwrap();
        server.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Slow device\r\n\r\n<title>unfinished").await.unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    let started = tokio::time::Instant::now();
    let result: BTreeMap<_, _> = exchange(&mut client, "192.168.1.2".parse().unwrap(), 80)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(result["web_server"], "Slow device");
    assert!(result.contains_key("web_read_limit"));
    assert!(tokio::time::Instant::now() - started < Duration::from_secs(2));
    task.abort();
}

#[tokio::test]
async fn web_identification_never_follows_redirect_or_requests_another_path() {
    let (mut client, mut server) = tokio::io::duplex(32768);
    let task = tokio::spawn(async move {
        let mut request = [0; 1024];
        let _ = server.read(&mut request).await.unwrap();
        server.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\nSet-Cookie: SECRET\r\n\r\n").await.unwrap();
        match tokio::time::timeout(Duration::from_millis(100), server.read(&mut request)).await {
            Ok(Ok(0)) | Err(_) => {}
            other => panic!("Unexpected redirect request: {other:?}"),
        }
    });
    let result: BTreeMap<_, _> = exchange(&mut client, "192.168.1.2".parse().unwrap(), 80)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(result["web_status"], "302");
    assert_eq!(result["web_redirect"], "Not followed");
    assert!(!format!("{result:?}").contains("169.254"));
    drop(client);
    task.await.unwrap();
}

#[test]
fn web_identification_is_owner_only_and_excludes_non_web_ports() {
    for port in [0, 22, 25, 53, 445, 1883, 8009, 8883, 9100, 27017] {
        assert!(web_probe_ids(port).is_none());
        assert!(descriptor(&format!("web.http.{port}")).is_none());
    }
    assert!(descriptor("web.http.080").is_none());
    assert!(descriptor("web.ftp.80").is_none());
    let d = descriptor("web.https.8443").unwrap();
    assert!(d.owner_start_required);
    assert_eq!(d.budget_class, BudgetClass::Inventory);
    assert_eq!(d.max_response_bytes, MAX_RESPONSE_BYTES);
    assert_eq!(web_probe_ids(443).unwrap()[0], "web.https.443");
}

#[tokio::test]
async fn web_identification_reads_https_with_an_unverified_self_signed_certificate() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    let cert = CertificateDer::from(include_bytes!("fixtures/certificate.der").to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/private-test-key.der").to_vec(),
    ));
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    let (client, server) = tokio::io::duplex(65536);
    let task = tokio::spawn(async move {
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            .accept(server)
            .await
            .unwrap();
        let mut request = [0; 1024];
        let n = tls.read(&mut request).await.unwrap();
        assert!(
            std::str::from_utf8(&request[..n])
                .unwrap()
                .starts_with("GET / HTTP/1.1")
        );
        assert!(tls.get_ref().1.peer_certificates().is_none());
        tls.write_all(&response(
            "<title>Synology DiskStation</title>",
            "Server: nginx\r\n",
        ))
        .await
        .unwrap();
        tls.shutdown().await.unwrap();
    });
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(tls_config().unwrap()))
        .connect(
            ServerName::IpAddress("192.168.1.2".parse::<IpAddr>().unwrap().into()),
            client,
        )
        .await
        .unwrap();
    let TransportResponse::Success(cert_facts) = certificate_metadata(
        tls.get_ref().1.peer_certificates().unwrap()[0].as_ref(),
        MAX_RESPONSE_BYTES,
    )
    .unwrap() else {
        panic!("certificate not parsed");
    };
    assert!(cert_facts.contains(&("certificate_trust".into(), "unverified".into())));
    assert!(
        cert_facts
            .iter()
            .any(|(key, value)| key == "certificate_sha256" && value.len() == 64)
    );
    let result: BTreeMap<_, _> = exchange(&mut tls, "192.168.1.2".parse().unwrap(), 443)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(result["web_title"], "Synology DiskStation");
    assert_eq!(result["web_identity_hint"], "Synology NAS");
    task.await.unwrap();
}
