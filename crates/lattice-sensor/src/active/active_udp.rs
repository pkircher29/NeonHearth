use quick_xml::{
    NsReader,
    events::Event,
    name::{Namespace, ResolveResult},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::{ActiveError, MAX_FACT_VALUE_BYTES, MAX_RESPONSE_BYTES, ProbeCredential};

#[derive(Clone, Debug)]
pub struct UdpProbe {
    pub bytes: Vec<u8>,
    pub port: u16,
    target: IpAddr,
    correlation: Correlation,
}

#[derive(Clone, Debug)]
enum Correlation {
    Tx16(u16),
    Mdns(Vec<u8>),
    Tx32(u32),
    Ntp([u8; 8]),
    Text(&'static str),
    Soap(&'static str),
    Coap { id: u16, token: [u8; 4] },
    Lifx { source: u32, sequence: u8 },
}

pub fn build_udp_probe(
    id: &str,
    target: IpAddr,
    local_v4: Option<Ipv4Addr>,
    _credential: Option<&ProbeCredential>,
) -> Result<UdpProbe, ActiveError> {
    let (port, bytes, correlation) = match id {
        "udp.dns.53" => {
            let port = 53;
            let tx=0x1234u16; let mut b=vec![]; b.extend_from_slice(&tx.to_be_bytes()); b.extend_from_slice(&[0x01,0x00,0,1,0,0,0,0,0,0]); b.extend_from_slice(&[0,0,2,0,1]);
            (port,b,Correlation::Tx16(tx))
        }
        "udp.mdns.5353" => { let mut question=vec![];for label in ["_services","_dns-sd","_udp","local"]{question.push(label.len() as u8);question.extend_from_slice(label.as_bytes())}question.push(0);question.extend_from_slice(&12u16.to_be_bytes());question.extend_from_slice(&0x8001u16.to_be_bytes());let mut b=vec![0,0,0,0,0,1,0,0,0,0,0,0];b.extend_from_slice(&question);(5353,b,Correlation::Mdns(question)) }
        "udp.dhcp.67" => {
            let local=local_v4.filter(|ip| !ip.is_unspecified()).ok_or(ActiveError::Unavailable)?; let tx=0x4e481234u32;
            let mut b=vec![0u8;240]; b[0]=1;b[1]=0;b[2]=0;b[3]=0;b[4..8].copy_from_slice(&tx.to_be_bytes());b[12..16].copy_from_slice(&local.octets());b[236..240].copy_from_slice(&[99,130,83,99]); b.extend_from_slice(&[53,1,8,55,4,1,3,6,15,255]);
            (67,b,Correlation::Tx32(tx))
        }
        "udp.ntp.123" => { let nonce=[0x4e,0x48,0x20,0x26,0x08,0x23,0x12,0x34]; let mut b=vec![0u8;48];b[0]=0x23;b[40..48].copy_from_slice(&nonce);(123,b,Correlation::Ntp(nonce)) }
        "udp.ssdp.1900" => (1900,format!("M-SEARCH * HTTP/1.1\r\nHOST: {target}:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n").into_bytes(),Correlation::Text("HTTP/1.1")),
        "udp.nbns.137" => { let tx=0x1234u16;let mut b=vec![];b.extend_from_slice(&tx.to_be_bytes());b.extend_from_slice(&[0x01,0x10,0,1,0,0,0,0,0,0,0x20]);let mut encoded=[b'A';32];encoded[0]=b'C';encoded[1]=b'K';b.extend_from_slice(&encoded);b.extend_from_slice(&[0,0,0x21,0,1]);(137,b,Correlation::Tx16(tx)) }
        "udp.ws-discovery.3702" | "udp.onvif.3702" => { let message="urn:uuid:00000000-0000-0000-0000-000000001234";let body=format!("<e:Envelope xmlns:e='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' xmlns:d='http://schemas.xmlsoap.org/ws/2005/04/discovery'><e:Header><a:MessageID>{message}</a:MessageID><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action></e:Header><e:Body><d:Probe/></e:Body></e:Envelope>");(3702,body.into_bytes(),Correlation::Soap(message)) }
        "udp.sip.5060" => (5060,format!("OPTIONS sip:{target} SIP/2.0\r\nVia: SIP/2.0/UDP neonhearth.invalid;branch=z9hG4bK-1234\r\nFrom: <sip:neonhearth@invalid>;tag=1234\r\nTo: <sip:{target}>\r\nCall-ID: nh-1234\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n").into_bytes(),Correlation::Text("nh-1234")),
        "udp.rtsp.554" => (554,format!("OPTIONS rtsp://{target}/ RTSP/1.0\r\nCSeq: 4660\r\nUser-Agent: NeonHearth/1\r\n\r\n").into_bytes(),Correlation::Text("4660")),
        "udp.coap.5683" => { let token=[0x4e,0x48,0x12,0x34];let id=0x1234u16;let mut b=vec![0x44,0x01];b.extend_from_slice(&id.to_be_bytes());b.extend_from_slice(&token);(5683,b,Correlation::Coap{id,token}) }
        "udp.lifx.56700" => { let source=0x4e481234u32;let sequence=0x23;let mut b=vec![0u8;36];b[0..2].copy_from_slice(&36u16.to_le_bytes());b[2..4].copy_from_slice(&0x3400u16.to_le_bytes());b[4..8].copy_from_slice(&source.to_le_bytes());b[23]=sequence;b[32..34].copy_from_slice(&2u16.to_le_bytes());(56700,b,Correlation::Lifx{source,sequence}) }
        _ => return Err(ActiveError::UnknownProbe),
    };
    Ok(UdpProbe {
        bytes,
        port,
        target,
        correlation,
    })
}

pub fn parse_udp_reply(
    id: &str,
    probe: &UdpProbe,
    peer: SocketAddr,
    bytes: &[u8],
) -> Result<Vec<(String, String)>, ActiveError> {
    if peer.ip() != probe.target || peer.port() != probe.port {
        return Err(ActiveError::Correlation);
    }
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ActiveError::ResponseLimit);
    }
    match id {
        "udp.dns.53" => dns(probe, bytes),
        "udp.mdns.5353" => mdns(probe, bytes),
        "udp.dhcp.67" => dhcp(probe, bytes),
        "udp.ntp.123" => ntp(probe, bytes),
        "udp.ssdp.1900" => headers(
            probe,
            bytes,
            &[("st", "service_type"), ("usn", "usn"), ("server", "server")],
        ),
        "udp.nbns.137" => nbns(probe, bytes),
        "udp.ws-discovery.3702" | "udp.onvif.3702" => soap(probe, bytes),
        "udp.sip.5060" => session_headers(
            probe,
            bytes,
            "SIP/2.0",
            &[("call-id", "nh-1234"), ("cseq", "1 OPTIONS")],
            &[
                ("server", "server"),
                ("user-agent", "user_agent"),
                ("allow", "allow"),
            ],
        ),
        "udp.rtsp.554" => session_headers(
            probe,
            bytes,
            "RTSP/1.0",
            &[("cseq", "4660")],
            &[("server", "server"), ("public", "public")],
        ),
        "udp.coap.5683" => coap(probe, bytes),
        "udp.lifx.56700" => lifx(probe, bytes),
        _ => Err(ActiveError::UnknownProbe),
    }
}

fn tx16(probe: &UdpProbe, bytes: &[u8]) -> Result<(), ActiveError> {
    let Correlation::Tx16(expected) = probe.correlation else {
        return Err(ActiveError::Correlation);
    };
    if bytes.len() < 2 || u16::from_be_bytes([bytes[0], bytes[1]]) != expected {
        Err(ActiveError::Correlation)
    } else {
        Ok(())
    }
}
fn dns(probe: &UdpProbe, b: &[u8]) -> Result<Vec<(String, String)>, ActiveError> {
    tx16(probe, b)?;
    if b.len() < 12 || b[2] & 0x80 == 0 {
        return Err(ActiveError::Network);
    }
    let q = usize::from(u16::from_be_bytes([b[4], b[5]]));
    let a = usize::from(u16::from_be_bytes([b[6], b[7]]));
    if q > 8 || a > 32 {
        return Err(ActiveError::ResponseLimit);
    }
    let mut p = 12;
    for _ in 0..q {
        p = skip_name(b, p)?;
        p = p
            .checked_add(4)
            .filter(|p| *p <= b.len())
            .ok_or(ActiveError::Network)?;
    }
    let mut out = vec![];
    for _ in 0..a {
        p = skip_name(b, p)?;
        if p + 10 > b.len() {
            return Err(ActiveError::Network);
        }
        let kind = u16::from_be_bytes([b[p], b[p + 1]]);
        let len = usize::from(u16::from_be_bytes([b[p + 8], b[p + 9]]));
        p += 10;
        if p + len > b.len() {
            return Err(ActiveError::Network);
        }
        let value = if kind == 1 && len == 4 {
            Ipv4Addr::new(b[p], b[p + 1], b[p + 2], b[p + 3]).to_string()
        } else {
            format!("type:{kind};bytes:{len}")
        };
        out.push(("answer".into(), value));
        p += len;
    }
    Ok(out)
}
fn mdns(probe: &UdpProbe, b: &[u8]) -> Result<Vec<(String, String)>, ActiveError> {
    let Correlation::Mdns(expected) = &probe.correlation else {
        return Err(ActiveError::Correlation);
    };
    if b.len() < 12
        || b[0..2] != [0, 0]
        || b[2] & 0x80 == 0
        || u16::from_be_bytes([b[4], b[5]]) != 1
    {
        return Err(ActiveError::Correlation);
    }
    let question_end = skip_name(b, 12)?
        .checked_add(4)
        .filter(|end| *end <= b.len())
        .ok_or(ActiveError::Network)?;
    if &b[12..question_end] != expected.as_slice() {
        return Err(ActiveError::Correlation);
    }
    let count = usize::from(u16::from_be_bytes([b[6], b[7]]));
    if count == 0 || count > 32 {
        return Err(ActiveError::ResponseLimit);
    }
    let mut p = question_end;
    let mut facts = vec![];
    for _ in 0..count {
        let name_start = p;
        p = skip_name(b, p)?;
        if p + 10 > b.len() {
            return Err(ActiveError::Network);
        }
        let kind = u16::from_be_bytes([b[p], b[p + 1]]);
        let len = usize::from(u16::from_be_bytes([b[p + 8], b[p + 9]]));
        if kind != 12 || b[name_start] & 0xc0 != 0xc0 || b.get(name_start + 1) != Some(&12) {
            return Err(ActiveError::Correlation);
        }
        p += 10;
        if p + len > b.len() {
            return Err(ActiveError::Network);
        }
        facts.push(("answer".into(), format!("ptr_bytes:{len}")));
        p += len
    }
    Ok(facts)
}
fn skip_name(b: &[u8], mut p: usize) -> Result<usize, ActiveError> {
    for _ in 0..128 {
        let n = *b.get(p).ok_or(ActiveError::Network)?;
        if n == 0 {
            return Ok(p + 1);
        }
        if n & 0xc0 == 0xc0 {
            return if p + 2 <= b.len() {
                Ok(p + 2)
            } else {
                Err(ActiveError::Network)
            };
        }
        if n > 63 {
            return Err(ActiveError::Network);
        }
        p = p
            .checked_add(1 + usize::from(n))
            .filter(|p| *p <= b.len())
            .ok_or(ActiveError::Network)?;
    }
    Err(ActiveError::ResponseLimit)
}
fn dhcp(probe: &UdpProbe, b: &[u8]) -> Result<Vec<(String, String)>, ActiveError> {
    let Correlation::Tx32(tx) = probe.correlation else {
        return Err(ActiveError::Correlation);
    };
    if b.len() < 241
        || b[0] != 2
        || u32::from_be_bytes([b[4], b[5], b[6], b[7]]) != tx
        || b[236..240] != [99, 130, 83, 99]
    {
        return Err(ActiveError::Correlation);
    }
    let mut p = 240;
    let mut out = vec![];
    for _ in 0..64 {
        let code = *b.get(p).ok_or(ActiveError::Network)?;
        p += 1;
        if code == 255 {
            break;
        }
        if code == 0 {
            continue;
        }
        let len = usize::from(*b.get(p).ok_or(ActiveError::Network)?);
        p += 1;
        if p + len > b.len() {
            return Err(ActiveError::Network);
        };
        let v = &b[p..p + len];
        match (code, len) {
            (54, 4) => out.push((
                "server_id".into(),
                Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string(),
            )),
            (15, _) | (60, _) => {
                out.push((if code == 15 { "domain" } else { "vendor" }.into(), safe(v)))
            }
            _ => {}
        }
        p += len;
    }
    Ok(out)
}
fn ntp(probe: &UdpProbe, b: &[u8]) -> Result<Vec<(String, String)>, ActiveError> {
    let Correlation::Ntp(nonce) = probe.correlation else {
        return Err(ActiveError::Correlation);
    };
    if b.len() != 48 || b[0] & 7 != 4 || b[24..32] != nonce {
        return Err(ActiveError::Correlation);
    }
    Ok(vec![
        ("stratum".into(), b[1].to_string()),
        ("reference_id".into(), safe(&b[12..16])),
    ])
}
fn headers(
    probe: &UdpProbe,
    b: &[u8],
    allowed: &[(&str, &str)],
) -> Result<Vec<(String, String)>, ActiveError> {
    let Correlation::Text(needle) = probe.correlation else {
        return Err(ActiveError::Correlation);
    };
    let text = std::str::from_utf8(b).map_err(|_| ActiveError::Network)?;
    if !text.contains(needle) || !text.lines().next().is_some_and(|line| line.contains("200")) {
        return Err(ActiveError::Correlation);
    }
    let mut out = vec![];
    for line in text.lines().take(64) {
        if let Some((name, value)) = line.split_once(':') {
            for (wanted, key) in allowed {
                if name.eq_ignore_ascii_case(wanted) {
                    out.push(((*key).into(), bounded(value.trim())));
                }
            }
        }
    }
    Ok(out)
}
fn session_headers(
    probe: &UdpProbe,
    b: &[u8],
    protocol: &str,
    correlations: &[(&str, &str)],
    allowed: &[(&str, &str)],
) -> Result<Vec<(String, String)>, ActiveError> {
    let Correlation::Text(configured) = probe.correlation else {
        return Err(ActiveError::Correlation);
    };
    if correlations
        .first()
        .is_none_or(|(_, value)| *value != configured)
        || b.len() > MAX_RESPONSE_BYTES
    {
        return Err(ActiveError::Correlation);
    }
    let text = std::str::from_utf8(b).map_err(|_| ActiveError::Network)?;
    let (head, _body) = text.split_once("\r\n\r\n").ok_or(ActiveError::Network)?;
    if head
        .as_bytes()
        .windows(2)
        .filter(|pair| pair[1] == b'\n')
        .any(|pair| pair[0] != b'\r')
        || head
            .as_bytes()
            .windows(2)
            .filter(|pair| pair[0] == b'\r')
            .any(|pair| pair[1] != b'\n')
    {
        return Err(ActiveError::Network);
    }
    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or(ActiveError::Network)?;
    let mut parts = status.split_ascii_whitespace();
    if parts.next() != Some(protocol)
        || parts
            .next()
            .is_none_or(|code| code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(ActiveError::Correlation);
    }
    let (mut found, mut out) = (vec![None::<String>; correlations.len()], vec![]);
    for line in lines.take(64) {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err(ActiveError::Network);
        }
        let (name, value) = line.split_once(':').ok_or(ActiveError::Network)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ActiveError::Network);
        }
        let value = value.trim();
        for (index, (correlation_name, _)) in correlations.iter().enumerate() {
            if name.eq_ignore_ascii_case(correlation_name)
                && found[index].replace(value.to_owned()).is_some()
            {
                return Err(ActiveError::Correlation);
            }
        }
        for (wanted, key) in allowed {
            if name.eq_ignore_ascii_case(wanted) {
                out.push(((*key).into(), bounded(value)))
            }
        }
    }
    if correlations
        .iter()
        .zip(found.iter())
        .any(|((_, expected), value)| value.as_deref() != Some(*expected))
    {
        return Err(ActiveError::Correlation);
    }
    Ok(out)
}
fn nbns(probe: &UdpProbe, b: &[u8]) -> Result<Vec<(String, String)>, ActiveError> {
    tx16(probe, b)?;
    if b.len() < 12 || b[2] & 0x80 == 0 {
        return Err(ActiveError::Network);
    }
    let mut p = 12;
    p = skip_name(b, p)?;
    p += 4;
    p = skip_name(b, p)?;
    if p + 10 > b.len() {
        return Err(ActiveError::Network);
    }
    let len = usize::from(u16::from_be_bytes([b[p + 8], b[p + 9]]));
    p += 10;
    if p + len > b.len() || len < 1 {
        return Err(ActiveError::Network);
    }
    let count = usize::from(b[p]);
    if count > 16 || 1 + count * 18 > len {
        return Err(ActiveError::ResponseLimit);
    }
    let mut out = vec![];
    for i in 0..count {
        let start = p + 1 + i * 18;
        out.push((
            "node_name".into(),
            safe(&b[start..start + 15]).trim().to_owned(),
        ));
    }
    Ok(out)
}
fn soap(probe: &UdpProbe, b: &[u8]) -> Result<Vec<(String, String)>, ActiveError> {
    let Correlation::Soap(id) = probe.correlation else {
        return Err(ActiveError::Correlation);
    };
    const SOAP: &[u8] = b"http://www.w3.org/2003/05/soap-envelope";
    const WSA: &[u8] = b"http://www.w3.org/2005/08/addressing";
    const WSD05: &[u8] = b"http://schemas.xmlsoap.org/ws/2005/04/discovery";
    const WSD09: &[u8] = b"http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01";
    if b.len() > MAX_RESPONSE_BYTES || std::str::from_utf8(b).is_err() {
        return Err(ActiveError::ResponseLimit);
    }
    let mut reader = NsReader::from_reader(b);
    reader.config_mut().trim_text(true);
    let mut buffer = vec![];
    let (mut depth, mut events) = (0usize, 0usize);
    let (mut envelope, mut header, mut body, mut matches_depth, mut probe_depth) =
        (None, None, None, None, None);
    let (mut root_seen, mut relates_seen) = (false, false);
    let mut current = None::<(&'static str, usize, bool)>;
    let mut stack: Vec<(Vec<u8>, Option<Vec<u8>>)> = vec![];
    let mut out = vec![];
    loop {
        events += 1;
        if events > 256 {
            return Err(ActiveError::ResponseLimit);
        }
        let (resolved, event) = reader
            .read_resolved_event_into(&mut buffer)
            .map_err(|_| ActiveError::Network)?;
        match event {
            Event::Start(element) => {
                if current.is_some() {
                    return Err(ActiveError::Network);
                }
                depth += 1;
                if depth > 32 {
                    return Err(ActiveError::ResponseLimit);
                }
                let ns = match &resolved {
                    ResolveResult::Bound(Namespace(uri)) => Some(uri.to_vec()),
                    _ => None,
                };
                let namespace_is = |wanted: &[u8]| matches!(resolved,ResolveResult::Bound(Namespace(uri))if uri==wanted);
                let is_wsd = namespace_is(WSD05) || namespace_is(WSD09);
                stack.push((element.name().as_ref().to_vec(), ns));
                match element.local_name().as_ref() {
                    b"Envelope" if depth == 1 && namespace_is(SOAP) && !root_seen => {
                        root_seen = true;
                        envelope = Some(depth)
                    }
                    b"Header" if envelope == Some(depth - 1) && namespace_is(SOAP) => {
                        header = Some(depth)
                    }
                    b"Body" if envelope == Some(depth - 1) && namespace_is(SOAP) => {
                        body = Some(depth)
                    }
                    b"RelatesTo"
                        if header == Some(depth - 1) && namespace_is(WSA) && !relates_seen =>
                    {
                        current = Some(("relates", depth, false))
                    }
                    b"RelatesTo" if namespace_is(WSA) => return Err(ActiveError::Correlation),
                    b"ProbeMatches" if body == Some(depth - 1) && is_wsd => {
                        matches_depth = Some(depth)
                    }
                    b"ProbeMatch" if matches_depth == Some(depth - 1) && is_wsd => {
                        probe_depth = Some(depth)
                    }
                    b"Types" if probe_depth == Some(depth - 1) && is_wsd => {
                        current = Some(("types", depth, false))
                    }
                    b"Scopes" if probe_depth == Some(depth - 1) && is_wsd => {
                        current = Some(("scopes", depth, false))
                    }
                    b"XAddrs" if probe_depth == Some(depth - 1) && is_wsd => {
                        current = Some(("xaddrs", depth, false))
                    }
                    _ if depth == 1 => return Err(ActiveError::Network),
                    _ => {}
                }
            }
            Event::Text(text) => {
                if let Some((key, at, consumed)) = current {
                    if at != depth || consumed {
                        return Err(ActiveError::Network);
                    }
                    let value = text
                        .decode()
                        .map_err(|_| ActiveError::Network)?
                        .into_owned();
                    if value.len() > MAX_FACT_VALUE_BYTES {
                        return Err(ActiveError::ResponseLimit);
                    }
                    current = Some((key, at, true));
                    if key == "relates" {
                        if value != id {
                            return Err(ActiveError::Correlation);
                        }
                        relates_seen = true
                    } else {
                        out.push((key.into(), bounded(&value)))
                    }
                }
            }
            Event::End(element) => {
                let ns = match &resolved {
                    ResolveResult::Bound(Namespace(uri)) => Some(*uri),
                    _ => None,
                };
                let (name, start_ns) = stack.pop().ok_or(ActiveError::Network)?;
                if name.as_slice() != element.name().as_ref() || start_ns.as_deref() != ns {
                    return Err(ActiveError::Network);
                }
                if current.is_some_and(|(_, at, _)| at == depth) {
                    current = None
                }
                if probe_depth == Some(depth) {
                    probe_depth = None
                }
                if matches_depth == Some(depth) {
                    matches_depth = None
                }
                if header == Some(depth) {
                    header = None
                }
                if body == Some(depth) {
                    body = None
                }
                if envelope == Some(depth) {
                    envelope = None
                }
                depth = depth.checked_sub(1).ok_or(ActiveError::Network)?
            }
            Event::DocType(_)
            | Event::Decl(_)
            | Event::PI(_)
            | Event::GeneralRef(_)
            | Event::CData(_) => return Err(ActiveError::Network),
            Event::Eof => break,
            Event::Empty(_) | Event::Comment(_) => {}
        }
        buffer.clear();
    }
    if depth != 0 || !root_seen || !relates_seen || out.is_empty() || !stack.is_empty() {
        return Err(ActiveError::Correlation);
    }
    Ok(out)
}
fn coap(probe: &UdpProbe, b: &[u8]) -> Result<Vec<(String, String)>, ActiveError> {
    let Correlation::Coap { id, token } = probe.correlation else {
        return Err(ActiveError::Correlation);
    };
    if b.len() < 8 || b[0] & 0x0f != 4 || u16::from_be_bytes([b[2], b[3]]) != id || b[4..8] != token
    {
        return Err(ActiveError::Correlation);
    }
    Ok(vec![(
        "code".into(),
        format!("{}.{}", b[1] >> 5, b[1] & 31),
    )])
}
fn lifx(probe: &UdpProbe, b: &[u8]) -> Result<Vec<(String, String)>, ActiveError> {
    let Correlation::Lifx { source, sequence } = probe.correlation else {
        return Err(ActiveError::Correlation);
    };
    if b.len() < 44
        || usize::from(u16::from_le_bytes([b[0], b[1]])) != b.len()
        || u32::from_le_bytes([b[4], b[5], b[6], b[7]]) != source
        || b[23] != sequence
        || u16::from_le_bytes([b[32], b[33]]) != 3
    {
        return Err(ActiveError::Correlation);
    }
    Ok(vec![
        ("service".into(), b[36].to_string()),
        (
            "service_port".into(),
            u32::from_le_bytes([b[40], b[41], b[42], b[43]]).to_string(),
        ),
    ])
}
fn safe(v: &[u8]) -> String {
    bounded(&String::from_utf8_lossy(v))
}
fn bounded(v: &str) -> String {
    v.chars()
        .filter(|c| !c.is_control())
        .take(MAX_FACT_VALUE_BYTES)
        .collect()
}
