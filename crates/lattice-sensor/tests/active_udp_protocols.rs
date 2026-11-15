use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};

use lattice_sensor::active::{
    ActiveError, NonceSource, ProbeCredential, UdpProbe, build_udp_probe_with_nonce,
    parse_udp_reply,
};

struct FixedNonce;
impl NonceSource for FixedNonce {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), ActiveError> {
        bytes.copy_from_slice(&[0, 0, 0, 0, 0, 0, 4, 210, 0, 0, 0, 1, 0, 0x12, 0x34, 0]);
        Ok(())
    }
}

fn build_udp_probe(
    id: &str,
    target: IpAddr,
    local_v4: Option<Ipv4Addr>,
    credential: Option<&ProbeCredential>,
) -> Result<UdpProbe, ActiveError> {
    build_udp_probe_with_nonce(id, target, local_v4, credential, &FixedNonce)
}

struct IncrementingNonce(AtomicU8);
impl NonceSource for IncrementingNonce {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), ActiveError> {
        let value = self.0.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        bytes.fill(value);
        Ok(())
    }
}

#[test]
fn successive_attempts_use_distinct_nonces_and_replay_is_rejected() {
    let source = IncrementingNonce(AtomicU8::new(0));
    let target = "192.168.50.1".parse().unwrap();
    for id in [
        "udp.dns.53",
        "udp.dhcp.67",
        "udp.ntp.123",
        "udp.nbns.137",
        "udp.ws-discovery.3702",
        "udp.onvif.3702",
        "udp.sip.5060",
        "udp.rtsp.554",
        "udp.coap.5683",
        "udp.lifx.56700",
    ] {
        let first = build_udp_probe_with_nonce(
            id,
            target,
            Some(Ipv4Addr::new(192, 168, 50, 2)),
            None,
            &source,
        )
        .unwrap();
        let second = build_udp_probe_with_nonce(
            id,
            target,
            Some(Ipv4Addr::new(192, 168, 50, 2)),
            None,
            &source,
        )
        .unwrap();
        assert_ne!(first.bytes, second.bytes, "{id}");
    }
    let first = build_udp_probe_with_nonce("udp.dns.53", target, None, None, &source).unwrap();
    let second = build_udp_probe_with_nonce("udp.dns.53", target, None, None, &source).unwrap();
    assert_ne!(first.bytes[..2], second.bytes[..2]);
    let mut replay = first.bytes.clone();
    replay[2] = 0x81;
    replay[3] = 0x80;
    assert_eq!(
        parse_udp_reply("udp.dns.53", &second, SocketAddr::new(target, 53), &replay).unwrap_err(),
        ActiveError::Correlation
    );
}

fn roundtrip_case(id: &str, response: Vec<u8>, expected_key: &str) {
    let target: IpAddr = "192.168.50.1".parse().unwrap();
    let probe = build_udp_probe(id, target, Some(Ipv4Addr::new(192, 168, 50, 2)), None).unwrap();
    let facts = parse_udp_reply(id, &probe, SocketAddr::new(target, probe.port), &response)
        .unwrap_or_else(|error| panic!("{id}: {error:?}"));
    assert!(
        facts.iter().any(|(key, _)| key == expected_key),
        "{id}: {facts:?}"
    );
}

#[test]
fn dns_requires_matching_transaction_and_parses_answers() {
    let id = "udp.dns.53";
    let target = "192.168.50.1".parse().unwrap();
    let probe = build_udp_probe(id, target, None, None).unwrap();
    let mut response = probe.bytes.clone();
    response[2] = 0x81;
    response[3] = 0x80;
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 192, 168, 50, 9,
    ]);
    roundtrip_case(id, response.clone(), "answer");
    response[1] ^= 1;
    assert_eq!(
        parse_udp_reply(id, &probe, SocketAddr::new(target, probe.port), &response).unwrap_err(),
        ActiveError::Correlation
    );
}

#[test]
fn mdns_uses_zero_id_unicast_dns_sd_and_correlates_the_echoed_question() {
    let target = "192.168.50.1".parse().unwrap();
    let probe = build_udp_probe("udp.mdns.5353", target, None, None).unwrap();
    assert_eq!(&probe.bytes[..2], &[0, 0]);
    assert_eq!(&probe.bytes[probe.bytes.len() - 2..], &[0x80, 0x01]);
    let mut response = probe.bytes.clone();
    response[2] = 0x84;
    response[3] = 0;
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c, 0, 0x0c, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x0c]);
    let facts = parse_udp_reply(
        "udp.mdns.5353",
        &probe,
        SocketAddr::new(target, 5353),
        &response,
    )
    .unwrap();
    assert!(facts.iter().any(|(key, _)| key == "answer"));
    let question_type = probe.bytes.len() - 4;
    response[question_type + 1] ^= 1;
    assert_eq!(
        parse_udp_reply(
            "udp.mdns.5353",
            &probe,
            SocketAddr::new(target, 5353),
            &response
        )
        .unwrap_err(),
        ActiveError::Correlation
    );
}

#[test]
fn ntp_requires_origin_nonce_and_extracts_stratum() {
    let target = "192.168.50.1".parse().unwrap();
    let probe = build_udp_probe("udp.ntp.123", target, None, None).unwrap();
    let mut response = vec![0u8; 48];
    response[0] = 0x24;
    response[1] = 2;
    response[24..32].copy_from_slice(&probe.bytes[40..48]);
    roundtrip_case("udp.ntp.123", response.clone(), "stratum");
    response[24] ^= 1;
    assert_eq!(
        parse_udp_reply(
            "udp.ntp.123",
            &probe,
            SocketAddr::new(target, 123),
            &response
        )
        .unwrap_err(),
        ActiveError::Correlation
    );
}

#[test]
fn text_discovery_protocols_correlate_and_emit_allowlisted_metadata() {
    let cases = [
        (
            "udp.ssdp.1900",
            b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:abc\r\nServer: test\r\n\r\n"
                .to_vec(),
            "service_type",
        ),
        (
            "udp.sip.5060",
            b"SIP/2.0 200 OK\r\nCall-ID: nh-1234\r\nCSeq: 1 OPTIONS\r\nServer: test\r\nAllow: OPTIONS\r\n\r\n"
                .to_vec(),
            "server",
        ),
        (
            "udp.rtsp.554",
            b"RTSP/1.0 200 OK\r\nCSeq: 0\r\nServer: test\r\nPublic: OPTIONS\r\n\r\n".to_vec(),
            "server",
        ),
    ];
    for (id, response, key) in cases {
        roundtrip_case(id, response, key);
    }
}

#[test]
fn soap_discovery_requires_relates_to_and_parses_types() {
    for id in ["udp.ws-discovery.3702", "udp.onvif.3702"] {
        let response = b"<e:Envelope xmlns:e='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' xmlns:d='http://schemas.xmlsoap.org/ws/2005/04/discovery'><e:Header><a:RelatesTo>urn:uuid:00000000-0000-04d2-0000-000100123400</a:RelatesTo></e:Header><e:Body><d:ProbeMatches><d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter</d:Types><d:XAddrs>http://192.168.50.1/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>".to_vec();
        roundtrip_case(id, response, "types");
    }
}

#[test]
fn soap_rejects_wrong_namespaces_scope_duplicates_and_substring_spoofs() {
    let target = "192.168.50.1".parse().unwrap();
    for id in ["udp.ws-discovery.3702", "udp.onvif.3702"] {
        let probe = build_udp_probe(id, target, None, None).unwrap();
        let peer = SocketAddr::new(target, 3702);
        let cases = [
            "<e:Envelope xmlns:e='urn:wrong'><e:Header><RelatesTo>urn:uuid:00000000-0000-0000-0000-000000001234</RelatesTo></e:Header></e:Envelope>",
            "<e:Envelope xmlns:e='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing'><e:Body><a:RelatesTo>urn:uuid:00000000-0000-0000-0000-000000001234</a:RelatesTo></e:Body></e:Envelope>",
            "<e:Envelope xmlns:e='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing'><e:Header><a:RelatesTo>urn:uuid:00000000-0000-0000-0000-000000001234</a:RelatesTo><a:RelatesTo>urn:uuid:00000000-0000-0000-0000-000000001234</a:RelatesTo></e:Header></e:Envelope>",
            "<e:Envelope xmlns:e='http://www.w3.org/2003/05/soap-envelope'><!-- urn:uuid:00000000-0000-0000-0000-000000001234 --><e:Body>ProbeMatch Types</e:Body></e:Envelope>",
        ];
        for body in cases {
            assert!(
                parse_udp_reply(id, &probe, peer, body.as_bytes()).is_err(),
                "{id}: {body}"
            );
        }
    }
}

#[test]
fn sip_and_rtsp_require_exact_unique_correlation_headers() {
    let target = "192.168.50.1".parse().unwrap();
    let cases: [(&str, u16, &[&str]); 2] = [
        (
            "udp.sip.5060",
            5060,
            &[
                "SIP/2.0 200 OK\r\nServer: Call-ID: nh-1234\r\n\r\n",
                "SIP/2.0 200 OK\r\nCall-ID: wrong\r\nX: nh-1234\r\n\r\n",
                "SIP/2.0 200 OK\r\nCall-ID: nh-1234\r\nCall-ID: nh-1234\r\n\r\n",
                "SIP/2.0 200 OK\r\nCall-ID: nh-1234\r\nCSeq: wrong\r\n\r\n",
            ],
        ),
        (
            "udp.rtsp.554",
            554,
            &[
                "RTSP/1.0 200 OK\r\nServer: CSeq: 4660\r\n\r\n",
                "RTSP/1.0 200 OK\r\nCSeq: 999\r\nX: 4660\r\n\r\n",
                "RTSP/1.0 200 OK\r\nCSeq: 4660\r\nCSeq: 4660\r\n\r\n",
            ],
        ),
    ];
    for (id, port, responses) in cases {
        let probe = build_udp_probe(id, target, None, None).unwrap();
        for response in responses {
            assert!(
                parse_udp_reply(
                    id,
                    &probe,
                    SocketAddr::new(target, port),
                    response.as_bytes()
                )
                .is_err(),
                "{id}: {response}"
            );
        }
    }
}

#[test]
fn coap_and_lifx_correlate_binary_headers() {
    let target = "192.168.50.1".parse().unwrap();
    let coap = build_udp_probe("udp.coap.5683", target, None, None).unwrap();
    let mut coap_reply = vec![0x64, 0x45, coap.bytes[2], coap.bytes[3]];
    coap_reply.extend_from_slice(&coap.bytes[4..8]);
    roundtrip_case("udp.coap.5683", coap_reply, "code");
    let lifx = build_udp_probe("udp.lifx.56700", target, None, None).unwrap();
    let mut reply = lifx.bytes.clone();
    reply[32..34].copy_from_slice(&3u16.to_le_bytes());
    reply.extend_from_slice(&[1, 0, 0, 0, 0x84, 0xdd, 0, 0]);
    let reply_len = reply.len() as u16;
    reply[0..2].copy_from_slice(&reply_len.to_le_bytes());
    roundtrip_case("udp.lifx.56700", reply, "service_port");
}

#[test]
fn dhcp_inform_and_nbns_parse_only_correlated_bounded_metadata() {
    let target = "192.168.50.1".parse().unwrap();
    let dhcp = build_udp_probe(
        "udp.dhcp.67",
        target,
        Some(Ipv4Addr::new(192, 168, 50, 2)),
        None,
    )
    .unwrap();
    let mut reply = dhcp.bytes[..dhcp.bytes.len() - 1].to_vec();
    reply[0] = 2;
    reply.extend_from_slice(&[54, 4, 192, 168, 50, 1, 60, 4, b't', b'e', b's', b't', 255]);
    roundtrip_case("udp.dhcp.67", reply, "server_id");
    let nbns = build_udp_probe("udp.nbns.137", target, None, None).unwrap();
    let mut response = nbns.bytes.clone();
    response[2] = 0x85;
    response[3] = 0;
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    let mut node = [b' '; 15];
    node[..4].copy_from_slice(b"HOME");
    let mut rdata = vec![1];
    rdata.extend_from_slice(&node);
    rdata.extend_from_slice(&[0, 4, 0]);
    rdata.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    response.extend_from_slice(&[0xc0, 0x0c, 0, 0x21, 0, 1, 0, 0, 0, 1]);
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);
    roundtrip_case("udp.nbns.137", response, "node_name");

    // RFC 1002 node-status replies commonly omit the question section entirely.
    let mut no_question = nbns.bytes[..12].to_vec();
    no_question[2..4].copy_from_slice(&[0x85, 0]);
    no_question[4..6].copy_from_slice(&[0, 0]);
    no_question[6..8].copy_from_slice(&[0, 1]);
    no_question.extend_from_slice(&nbns.bytes[12..nbns.bytes.len() - 4]);
    no_question.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 1]);
    no_question.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    no_question.extend_from_slice(&rdata);
    let facts = parse_udp_reply(
        "udp.nbns.137",
        &nbns,
        SocketAddr::new(target, 137),
        &no_question,
    )
    .unwrap();
    assert!(
        facts
            .iter()
            .any(|(key, value)| key == "node_name" && value == "HOME")
    );
    assert!(
        facts
            .iter()
            .any(|(key, value)| key == "node_name_kind" && value == "unique")
    );
    let flags_at = no_question.len() - rdata.len() + 17;
    let mut group = no_question.clone();
    group[flags_at] |= 0x80;
    let group_facts =
        parse_udp_reply("udp.nbns.137", &nbns, SocketAddr::new(target, 137), &group).unwrap();
    assert!(!group_facts.iter().any(|(key, _)| key == "node_name"));
    let mut conflicting = no_question.clone();
    conflicting[flags_at] |= 0x08;
    assert!(
        parse_udp_reply(
            "udp.nbns.137",
            &nbns,
            SocketAddr::new(target, 137),
            &conflicting
        )
        .unwrap()
        .is_empty()
    );
    no_question[0] ^= 1;
    assert!(
        parse_udp_reply(
            "udp.nbns.137",
            &nbns,
            SocketAddr::new(target, 137),
            &no_question,
        )
        .is_err()
    );
}

#[test]
fn every_parser_rejects_wrong_peer_and_oversized_or_malformed_input() {
    let ids = [
        "udp.dns.53",
        "udp.dhcp.67",
        "udp.ntp.123",
        "udp.ssdp.1900",
        "udp.nbns.137",
        "udp.mdns.5353",
        "udp.ws-discovery.3702",
        "udp.onvif.3702",
        "udp.sip.5060",
        "udp.rtsp.554",
        "udp.coap.5683",
        "udp.lifx.56700",
    ];
    let target = "192.168.50.1".parse().unwrap();
    for id in ids {
        let probe =
            build_udp_probe(id, target, Some(Ipv4Addr::new(192, 168, 50, 2)), None).unwrap();
        assert_eq!(
            parse_udp_reply(id, &probe, "192.168.50.99:9".parse().unwrap(), &probe.bytes)
                .unwrap_err(),
            ActiveError::Correlation,
            "{id}"
        );
        assert_eq!(
            parse_udp_reply(
                id,
                &probe,
                SocketAddr::new(target, probe.port),
                &vec![0; 16_385]
            )
            .unwrap_err(),
            ActiveError::ResponseLimit,
            "{id}"
        );
        assert!(
            parse_udp_reply(id, &probe, SocketAddr::new(target, probe.port), b"bad").is_err(),
            "{id}"
        );
    }
}

#[test]
fn every_transaction_bearing_protocol_rejects_a_mismatch() {
    let target = "192.168.50.1".parse().unwrap();
    let cases: [(&str, Vec<u8>); 7] = [
        ("udp.dhcp.67", vec![2; 250]),
        ("udp.nbns.137", {
            let mut response = vec![0; 20];
            response[0] = 1;
            response
        }),
        (
            "udp.ws-discovery.3702",
            b"<e:Envelope xmlns:e='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' xmlns:d='http://schemas.xmlsoap.org/ws/2005/04/discovery'><e:Header><a:RelatesTo>urn:uuid:wrong</a:RelatesTo></e:Header><e:Body><d:ProbeMatches><d:ProbeMatch><d:Types>x</d:Types></d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>".to_vec(),
        ),
        (
            "udp.onvif.3702",
            b"<e:Envelope xmlns:e='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' xmlns:d='http://schemas.xmlsoap.org/ws/2005/04/discovery'><e:Header><a:RelatesTo>urn:uuid:wrong</a:RelatesTo></e:Header><e:Body><d:ProbeMatches><d:ProbeMatch><d:Types>x</d:Types></d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>".to_vec(),
        ),
        (
            "udp.sip.5060",
            b"SIP/2.0 200 OK\r\nCall-ID: wrong\r\n\r\n".to_vec(),
        ),
        (
            "udp.rtsp.554",
            b"RTSP/1.0 200 OK\r\nCSeq: 999\r\n\r\n".to_vec(),
        ),
        ("udp.coap.5683", vec![0x64, 0x45, 0, 1, 0, 0, 0, 0]),
    ];
    for (id, response) in cases {
        let probe =
            build_udp_probe(id, target, Some(Ipv4Addr::new(192, 168, 50, 2)), None).unwrap();
        assert_eq!(
            parse_udp_reply(id, &probe, SocketAddr::new(target, probe.port), &response)
                .unwrap_err(),
            ActiveError::Correlation,
            "{id}"
        );
    }
    let probe = build_udp_probe("udp.lifx.56700", target, None, None).unwrap();
    let mut response = vec![0u8; 44];
    response[0..2].copy_from_slice(&44u16.to_le_bytes());
    response[23] = 0x23;
    response[32..34].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(
        parse_udp_reply(
            "udp.lifx.56700",
            &probe,
            SocketAddr::new(target, 56700),
            &response
        )
        .unwrap_err(),
        ActiveError::Correlation
    );
}
