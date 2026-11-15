//! Owner-started web identification. Only GET / to a numeric, interface-pinned
//! target; no proxy, DNS, redirects, cookies, credentials, scripts or subresources.
use super::*;
use tokio::io::{AsyncRead, AsyncWrite};

const HEADER_CAP: usize = 8192;
const READ_TIME: Duration = Duration::from_millis(1500);

/// Web candidates only: never send HTTP to e.g. raw printer, SSH or MQTT ports.
/// The second scheme is tried only when the first did not return HTTP metadata.
pub fn web_probe_ids(port: u16) -> Option<[String; 2]> {
    let tls_first = match port {
        443 | 4443 | 5001 | 6443 | 7443 | 8443 | 9443 | 10443 => true,
        80 | 81 | 82 | 83 | 88 | 631 | 800 | 3000 | 3001 | 4200 | 5000 | 5002 | 5357 | 5800
        | 7000 | 7001 | 8000 | 8001 | 8006 | 8008 | 8010 | 8080 | 8081 | 8082 | 8083 | 8084
        | 8088 | 8090 | 8123 | 8181 | 8200 | 8880 | 8888 | 9000 | 9090 | 10000 | 32400 => false,
        _ => return None,
    };
    let schemes = if tls_first {
        ["https", "http"]
    } else {
        ["http", "https"]
    };
    Some(schemes.map(|scheme| format!("web.{scheme}.{port}")))
}

pub(super) fn descriptor(id: &str) -> Option<ProbeDescriptor> {
    let (scheme, port) = id.strip_prefix("web.")?.split_once('.')?;
    let port = port.parse::<u16>().ok()?;
    if !web_probe_ids(port)?.iter().any(|candidate| candidate == id) {
        return None;
    }
    let mut d = super::descriptor(
        id,
        if scheme == "https" {
            ProbeTransport::Tls
        } else {
            ProbeTransport::Tcp
        },
        port,
        RequiredPrivilege::None,
        b"",
    );
    d.owner_start_required = true;
    d.budget_class = BudgetClass::Inventory;
    d.max_response_bytes = MAX_RESPONSE_BYTES;
    d.evidence_families = vec![EvidenceFamily::Service];
    d.potential_side_effects = "One unauthenticated GET /, optionally over TLS; target may log it";
    Some(d)
}

pub(super) async fn attempt(
    guard: &TargetGuard,
    request: &ProbeRequest,
    d: &ProbeDescriptor,
) -> Result<TransportResponse, ActiveError> {
    let port = d.ports[0];
    let binding = guard
        .authorized_binding(request.interface, request.target)
        .map_err(|_| ActiveError::Unauthorized)?;
    let socket = if request.target.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
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
        .authorize(request.interface, request.target)
        .map_err(|_| ActiveError::Unauthorized)?;
    let mut stream = match socket.connect(binding.target_socket(port)).await {
        Ok(stream) => stream,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            return Ok(TransportResponse::Refused);
        }
        Err(_) => return Err(ActiveError::Network),
    };
    verify_local_binding(
        stream.local_addr().map_err(|_| ActiveError::Network)?,
        binding.source,
    )?;
    pin_socket_to_interface(&stream, binding)?;
    guard
        .authorize(request.interface, request.target)
        .map_err(|_| ActiveError::Unauthorized)?;
    let https = d.transport == ProbeTransport::Tls;
    let mut facts = if https {
        let config = tls_config()?;
        let name = rustls::pki_types::ServerName::IpAddress(request.target.into());
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .map_err(|_| ActiveError::Protocol)?;
        let cert = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or(ActiveError::Protocol)?;
        let TransportResponse::Success(mut facts) =
            certificate_metadata(cert.as_ref(), MAX_RESPONSE_BYTES)?
        else {
            return Err(ActiveError::Protocol);
        };
        guard
            .authorize(request.interface, request.target)
            .map_err(|_| ActiveError::Unauthorized)?;
        match exchange(&mut tls, request.target, port).await {
            Ok(web) => facts.extend(web),
            Err(_) => facts.push((
                "web_probe_status".into(),
                "TLS responded; no readable HTTP response".into(),
            )),
        }
        facts
    } else {
        exchange(&mut stream, request.target, port).await?
    };
    if facts.iter().any(|(key, _)| key == "web_status") {
        facts.push((
            "web_scheme".into(),
            if https { "https" } else { "http" }.into(),
        ));
    }
    // Also bound certificate text by UTF-8 bytes before the engine normalizes it.
    for (_, value) in &mut facts {
        *value = text(value);
    }
    Ok(TransportResponse::Success(facts))
}

fn tls_config() -> Result<rustls::ClientConfig, ActiveError> {
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ActiveError::Internal)?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(DiscoveryVerifier))
    .with_no_client_auth())
}

/// Local appliances commonly have private/self-signed certificates. Discovery
/// does not authenticate their identity, but still verifies handshake signatures.
/// This verifier is private to this credential-free, root-page-only probe.
#[derive(Debug)]
struct DiscoveryVerifier;
impl rustls::client::danger::ServerCertVerifier for DiscoveryVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ip: IpAddr,
    port: u16,
) -> Result<Vec<(String, String)>, ActiveError> {
    // SocketAddr formats IPv6 brackets and includes nondefault ports correctly.
    let host = SocketAddr::new(ip, port);
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NeonHearth-Discovery/1\r\nAccept: text/html, application/xhtml+xml\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| ActiveError::Network)?;
    let deadline = tokio::time::Instant::now() + READ_TIME;
    let mut bytes = Vec::with_capacity(MAX_RESPONSE_BYTES);
    let mut buffer = [0; 2048];
    let mut interrupted = false;
    while bytes.len() < MAX_RESPONSE_BYTES {
        let room = buffer.len().min(MAX_RESPONSE_BYTES - bytes.len());
        match tokio::time::timeout_at(deadline, stream.read(&mut buffer[..room])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => bytes.extend_from_slice(&buffer[..n]),
            _ => {
                interrupted = true;
                break;
            }
        }
        if let Some(parsed) = parse(&bytes)? {
            if parsed.complete {
                return Ok(parsed.facts);
            }
        } else if bytes.len() >= HEADER_CAP {
            return Err(ActiveError::ResponseLimit);
        }
    }
    let mut parsed = parse(&bytes)?.ok_or(ActiveError::Protocol)?;
    if !parsed.complete && (interrupted || bytes.len() == MAX_RESPONSE_BYTES) {
        parsed.facts.push((
            "web_read_limit".into(),
            "Partial response: size or time limit reached".into(),
        ));
    }
    Ok(parsed.facts)
}

struct Parsed {
    facts: Vec<(String, String)>,
    complete: bool,
}

fn parse(bytes: &[u8]) -> Result<Option<Parsed>, ActiveError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ActiveError::ResponseLimit);
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let offset = match response.parse(bytes).map_err(|_| ActiveError::Protocol)? {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(offset) => offset,
    };
    if offset > HEADER_CAP {
        return Err(ActiveError::ResponseLimit);
    }
    let status = response
        .code
        .filter(|code| (100..=599).contains(code))
        .ok_or(ActiveError::Protocol)?;
    if status < 200 {
        return Err(ActiveError::Protocol);
    }
    let mut facts = BTreeMap::from([("web_status".into(), status.to_string())]);
    let mut content_length = None;
    let mut chunked = false;
    let mut encoding = false;
    let mut html = false;
    let mut seen = BTreeSet::new();
    for header in response.headers {
        let name = header.name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(header.value);
        let value = value.trim();
        // Ambiguous framing is rejected, not interpreted as a second message.
        if matches!(name.as_str(), "content-length" | "transfer-encoding")
            && !seen.insert(name.clone())
        {
            return Err(ActiveError::Protocol);
        }
        match name.as_str() {
            "content-length" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ActiveError::Protocol);
                }
                content_length = Some(value.parse::<usize>().map_err(|_| ActiveError::Protocol)?);
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err(ActiveError::Protocol);
                }
                chunked = true;
            }
            "content-encoding" => encoding |= !value.eq_ignore_ascii_case("identity"),
            "content-type" => {
                let mime = value.split(';').next().unwrap_or("").trim();
                html = mime.eq_ignore_ascii_case("text/html")
                    || mime.eq_ignore_ascii_case("application/xhtml+xml");
                facts
                    .entry("web_content_type".into())
                    .or_insert_with(|| text(value));
            }
            "server" => {
                facts
                    .entry("web_server".into())
                    .or_insert_with(|| text(value));
            }
            "x-powered-by" => {
                facts
                    .entry("web_powered_by".into())
                    .or_insert_with(|| text(value));
            }
            "www-authenticate" => {
                // Retain only the descriptive realm; never challenge tokens/nonces.
                if let Some(realm) = auth_realm(value) {
                    facts.entry("web_auth_realm".into()).or_insert(realm);
                }
            }
            // Location, Set-Cookie and all other fields are deliberately omitted.
            _ => {}
        }
    }
    if chunked && content_length.is_some() {
        return Err(ActiveError::Protocol);
    }
    let body = &bytes[offset..];
    let no_body = matches!(status, 204 | 304) || (300..400).contains(&status) || !html || encoding;
    let (decoded, complete) = if no_body {
        (vec![], true)
    } else if chunked {
        chunks(body)?
    } else {
        (
            body[..content_length.unwrap_or(body.len()).min(body.len())].to_vec(),
            content_length.is_some_and(|len| body.len() >= len),
        )
    };
    if encoding {
        facts.insert("web_read_limit".into(), "Encoded body skipped".into());
    }
    if (300..400).contains(&status) {
        facts.insert("web_redirect".into(), "Not followed".into());
    }
    if html && !no_body {
        let body = String::from_utf8_lossy(&decoded);
        html_metadata(&body, &mut facts);
    }
    let complete = complete || facts.contains_key("web_title");
    if let Some(hint) = identity_hint(&facts) {
        facts.insert("web_identity_hint".into(), hint.into());
    }
    Ok(Some(Parsed {
        facts: facts.into_iter().collect(),
        complete,
    }))
}

fn chunks(bytes: &[u8]) -> Result<(Vec<u8>, bool), ActiveError> {
    let mut rest = bytes;
    let mut decoded = Vec::new();
    for _ in 0..1024 {
        let Some(end) = rest.windows(2).position(|s| s == b"\r\n") else {
            return Ok((decoded, false));
        };
        if end > 128 {
            return Err(ActiveError::Protocol);
        }
        let size = std::str::from_utf8(&rest[..end])
            .map_err(|_| ActiveError::Protocol)?
            .split(';')
            .next()
            .unwrap_or("");
        if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ActiveError::Protocol);
        }
        let size = usize::from_str_radix(size, 16).map_err(|_| ActiveError::Protocol)?;
        rest = &rest[end + 2..];
        if size == 0 {
            return Ok((decoded, true));
        }
        decoded.extend_from_slice(&rest[..size.min(rest.len())]);
        if rest.len() < size.saturating_add(2) {
            return Ok((decoded, false));
        }
        if &rest[size..size + 2] != b"\r\n" {
            return Err(ActiveError::Protocol);
        }
        rest = &rest[size + 2..];
    }
    Err(ActiveError::ResponseLimit)
}

fn text(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(*c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .scan(0, |len, c| {
            *len += c.len_utf8();
            (*len <= MAX_FACT_VALUE_BYTES).then_some(c)
        })
        .collect()
}

fn auth_realm(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let start = lower.find("realm=\"")?;
    if start > 0 && !matches!(value.as_bytes()[start - 1], b' ' | b'\t' | b',') {
        return None;
    }
    let rest = &value[start + 7..];
    Some(text(rest.split('"').next()?))
}

fn html_text(value: &str) -> String {
    // Decode a bounded subset of entities into text, never markup.
    let mut result = String::new();
    let mut rest = value;
    while let Some(index) = rest.find('&') {
        result.push_str(&rest[..index]);
        rest = &rest[index..];
        let Some(end) = rest.find(';').filter(|end| *end <= 12) else {
            result.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let c = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            "nbsp" => Some(' '),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                u32::from_str_radix(&entity[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
            }
            _ if entity.starts_with('#') => {
                entity[1..].parse::<u32>().ok().and_then(char::from_u32)
            }
            _ => None,
        };
        if let Some(c) = c {
            result.push(c);
        } else {
            result.push_str(&rest[..=end]);
        }
        rest = &rest[end + 1..];
    }
    result.push_str(rest);
    text(&result.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn html_metadata(body: &str, facts: &mut BTreeMap<String, String>) {
    let lower = body.to_ascii_lowercase();
    let mut pos = 0;
    // Read just title/generator tags. Ignore comments and raw script/style text.
    while let Some(start) = lower[pos..].find('<').map(|n| n + pos) {
        if lower[start..].starts_with("<!--") {
            let Some(end) = lower[start + 4..].find("-->") else {
                break;
            };
            pos = start + 4 + end + 3;
            continue;
        }
        let Some(end) = tag_end(&lower, start + 1) else {
            break;
        };
        let tag = &lower[start + 1..end];
        let name = tag
            .split_ascii_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches('/');
        pos = end + 1;
        if matches!(name, "script" | "style" | "textarea" | "template") {
            let Some(close) = lower[pos..].find(&format!("</{name}")).map(|n| n + pos) else {
                break;
            };
            let Some(end) = tag_end(&lower, close + 2) else {
                break;
            };
            pos = end + 1;
            continue;
        }
        if name == "title" && !facts.contains_key("web_title") {
            if let Some(close) = lower[pos..].find("</title>").map(|n| n + pos) {
                let title = html_text(&body[pos..close]);
                if !title.is_empty() {
                    facts.insert("web_title".into(), title);
                }
                pos = close + 8;
            }
        } else if name == "meta" && !facts.contains_key("web_generator") {
            let attrs = attributes(&body[start + 1 + name.len()..end]);
            if attrs
                .get("name")
                .is_some_and(|name| name.eq_ignore_ascii_case("generator"))
                && let Some(value) = attrs.get("content")
            {
                facts.insert("web_generator".into(), html_text(value));
            }
        }
    }
}

fn tag_end(body: &str, start: usize) -> Option<usize> {
    let mut quote = None;
    for (i, b) in body.as_bytes()[start..].iter().copied().enumerate() {
        match (quote, b) {
            (Some(q), b) if q == b => quote = None,
            (None, b'\'' | b'"') => quote = Some(b),
            (None, b'>') => return Some(start + i),
            _ => {}
        }
    }
    None
}

fn attributes(mut rest: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for _ in 0..32 {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let end = rest
            .find(|c: char| c.is_ascii_whitespace() || c == '=')
            .unwrap_or(rest.len());
        if end == 0 {
            break;
        }
        let name = rest[..end].to_ascii_lowercase();
        rest = rest[end..].trim_start();
        if !rest.starts_with('=') {
            continue;
        }
        rest = rest[1..].trim_start();
        let value;
        if rest.starts_with(['\'', '"']) {
            let quote = rest.as_bytes()[0] as char;
            rest = &rest[1..];
            let Some(end) = rest.find(quote) else {
                break;
            };
            value = &rest[..end];
            rest = &rest[end + 1..];
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            value = &rest[..end];
            rest = &rest[end..];
        }
        if matches!(name.as_str(), "name" | "content") {
            result.entry(name).or_insert_with(|| value.to_owned());
        }
    }
    result
}

fn identity_hint(facts: &BTreeMap<String, String>) -> Option<&'static str> {
    let signatures = [
        ("home assistant", "Home Assistant"),
        ("esphome", "ESPHome"),
        ("tasmota", "Tasmota"),
        ("shelly", "Shelly"),
        ("synology", "Synology NAS"),
        ("qnap", "QNAP NAS"),
        ("proxmox", "Proxmox"),
        ("unifi", "UniFi"),
        ("openwrt", "OpenWrt"),
        ("routeros", "MikroTik RouterOS"),
        ("mikrotik", "MikroTik"),
        ("pi-hole", "Pi-hole"),
        ("adguard home", "AdGuard Home"),
        ("octoprint", "OctoPrint"),
        ("jellyfin", "Jellyfin"),
        ("plex", "Plex"),
        ("reolink", "Reolink camera"),
        ("hikvision", "Hikvision"),
        ("amcrest", "Amcrest camera"),
        ("fritz!box", "FRITZ!Box"),
    ];
    for key in ["web_title", "web_generator", "web_server", "web_auth_realm"] {
        if let Some(value) = facts.get(key) {
            let lower = value.to_ascii_lowercase();
            for (needle, hint) in signatures {
                if lower.match_indices(needle).any(|(i, _)| {
                    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
                    (i == 0 || !word(lower.as_bytes()[i - 1]))
                        && lower
                            .as_bytes()
                            .get(i + needle.len())
                            .is_none_or(|b| !word(*b))
                }) {
                    return Some(hint);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests;
