use lattice_sensor::{OfflinePassiveAdapter, PassiveOptions};
use pcap_file::pcap::PcapReader;
use std::{fs, io::Cursor, path::PathBuf};

const EXPECTED: &[&str] = &[
    "arp",
    "dhcpv4",
    "dhcpv6",
    "dns-query",
    "igmp",
    "ipv6-ndp",
    "llmnr",
    "mdns-dns-sd",
    "mld",
    "nbns",
    "onvif-discovery",
    "ssdp-upnp",
    "tcp-flow",
    "udp-flow",
    "ws-discovery",
];
fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pcap")
}
#[test]
fn fixture_inventory_is_exact_protocol_matrix() {
    let mut names: Vec<_> = fs::read_dir(fixtures())
        .unwrap()
        .map(|e| {
            e.unwrap()
                .file_name()
                .into_string()
                .unwrap()
                .trim_end_matches(".pcap")
                .to_owned()
        })
        .collect();
    names.sort();
    assert_eq!(names, EXPECTED);
}

#[test]
fn fixtures_are_real_ethernet_ip_or_arp_not_private_metadata_envelopes() {
    for name in EXPECTED {
        let bytes = fs::read(fixtures().join(format!("{name}.pcap"))).unwrap();
        let frame = &bytes[24 + 16..];
        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
        assert!(matches!(ether_type, 0x0806 | 0x0800 | 0x86dd));
        assert_ne!(ether_type, 0x88b5);
        if ether_type == 0x0800 && frame[23] == 17 {
            let ihl = usize::from(frame[14] & 15) * 4;
            let port = u16::from_be_bytes([frame[14 + ihl], frame[15 + ihl]]);
            assert!(port > 0);
        }
    }
}

fn wire_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for bytes in parts {
        for pair in bytes.chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[test]
fn generated_ip_and_transport_checksums_are_wire_valid() {
    for name in EXPECTED {
        let pcap = fs::read(fixtures().join(format!("{name}.pcap"))).unwrap();
        let mut reader = PcapReader::new(Cursor::new(&pcap)).unwrap();
        while let Some(packet) = reader.next_packet() {
            let packet = packet.unwrap();
            let f = packet.data.as_ref();
            match u16::from_be_bytes([f[12], f[13]]) {
                0x0800 => {
                    let ip = &f[14..];
                    let ihl = usize::from(ip[0] & 15) * 4;
                    assert_eq!(wire_checksum(&[&ip[..ihl]]), 0, "{name} IPv4");
                    let body = &ip[ihl..usize::from(u16::from_be_bytes([ip[2], ip[3]]))];
                    if matches!(ip[9], 6 | 17) {
                        let len = (body.len() as u16).to_be_bytes();
                        assert_eq!(
                            wire_checksum(&[&ip[12..20], &[0, ip[9]], &len, body]),
                            0,
                            "{name} transport"
                        );
                    } else if ip[9] == 2 {
                        assert_eq!(wire_checksum(&[body]), 0, "{name} IGMP");
                    }
                }
                0x86dd => {
                    let ip = &f[14..];
                    let mut next = ip[6];
                    let mut at = 40;
                    if next == 0 {
                        next = ip[at];
                        at += (usize::from(ip[at + 1]) + 1) * 8;
                    }
                    let body = &ip[at..40 + usize::from(u16::from_be_bytes([ip[4], ip[5]]))];
                    let len = (body.len() as u32).to_be_bytes();
                    assert_eq!(
                        wire_checksum(&[&ip[8..40], &len, &[0, 0, 0, next], body]),
                        0,
                        "{name} IPv6 transport"
                    );
                }
                _ => {}
            }
        }
    }
}
#[test]
fn every_fixture_normalizes_sanitized_metadata() {
    let adapter = OfflinePassiveAdapter;
    for name in EXPECTED {
        let p = fixtures().join(format!("{name}.pcap"));
        let obs = adapter
            .ingest_pcap(
                "fixture0",
                &fs::read(p).unwrap(),
                &PassiveOptions::default(),
            )
            .unwrap();
        assert_eq!(
            obs.len(),
            match *name {
                "dhcpv4" => 3,
                "dhcpv6" => 8,
                _ => 1,
            }
        );
        for one in &obs {
            assert_eq!(one.protocol, *name);
            assert_eq!(one.interface, "fixture0");
            if *name != "dhcpv6" {
                assert!(one.subject_mac.is_some());
            }
            assert!(
                one.facts
                    .iter()
                    .all(|f| f.source == format!("passive.{name}")
                        && f.confidence >= 0.0
                        && f.confidence <= 1.0
                        && !f.owner_confirmed
                        && f.expires_at > Some(f.observed_at))
            );
            assert!(!serde_json::to_string(one).unwrap().contains("NH1|"));
        }
    }
}

#[test]
fn expected_facts_and_protocol_ttls_are_exact() {
    let cases = [
        ("arp", "sender_ip", "192.0.2.10", 300),
        ("dhcpv4", "hostname", "lab-client", 3600),
        ("dhcpv6", "fqdn", "lab-v6.example.test", 3600),
        ("dns-query", "query", "update.example.test", 300),
        ("igmp", "group", "239.255.0.1", 300),
        ("ipv6-ndp", "source_lladdr", "00:11:22:33:44:55", 300),
        ("llmnr", "query", "workstation.local", 300),
        ("mdns-dns-sd", "service_target", "printer.local:9000", 120),
        ("mld", "group", "ff02::1", 300),
        ("nbns", "name", "WORKSTATION", 300),
        (
            "onvif-discovery",
            "types",
            "dn:NetworkVideoTransmitter",
            300,
        ),
        ("ssdp-upnp", "location", "http://192.0.2.20/desc.xml", 1800),
        ("ws-discovery", "xaddrs", "http://192.0.2.30/device", 300),
        ("tcp-flow", "bytes", "15", 300),
        ("udp-flow", "dst", "192.0.2.41:4243", 300),
    ];
    for (name, key, value, ttl) in cases {
        let observations = OfflinePassiveAdapter
            .ingest_pcap(
                "fixture0",
                &fs::read(fixtures().join(format!("{name}.pcap"))).unwrap(),
                &PassiveOptions::default(),
            )
            .unwrap();
        let observation = observations
            .iter()
            .find(|o| o.facts.iter().any(|f| f.key == key))
            .unwrap();
        let fact = observation
            .facts
            .iter()
            .find(|fact| fact.key == key)
            .unwrap();
        assert_eq!(fact.source, format!("passive.{name}"));
        assert_eq!(fact.value, value);
        assert_eq!(
            fact.expires_at.unwrap() - fact.observed_at,
            chrono::Duration::seconds(ttl)
        );
        assert_eq!(
            observation.subject_mac.as_deref(),
            Some("00:11:22:33:44:55")
        );
    }
}

#[test]
fn every_fixture_has_the_exact_semantic_fact_set() {
    let cases: &[(&str, &[(&str, &str)])] = &[
        (
            "arp",
            &[
                ("sender_ip", "192.0.2.10"),
                ("sender_mac", "00:11:22:33:44:55"),
            ],
        ),
        (
            "dhcpv4",
            &[
                ("chaddr", "00:11:22:33:44:55"),
                ("yiaddr", "192.0.2.100"),
                ("hostname", "lab-client"),
                ("client_id", "01001122334455"),
            ],
        ),
        (
            "dhcpv6",
            &[
                ("client_duid", "0001000100000001001122334455"),
                ("iaaddr", "2001:db8::2"),
                ("preferred_lifetime", "600"),
                ("valid_lifetime", "1200"),
                ("fqdn", "lab-v6.example.test"),
            ],
        ),
        ("dns-query", &[("query", "update.example.test")]),
        ("igmp", &[("group", "239.255.0.1")]),
        (
            "ipv6-ndp",
            &[
                ("target", "2001:db8::10"),
                ("source_lladdr", "00:11:22:33:44:55"),
            ],
        ),
        ("llmnr", &[("query", "workstation.local")]),
        (
            "mdns-dns-sd",
            &[
                (
                    "service_instance",
                    "_http._tcp.local -> Neon Printer._http._tcp.local",
                ),
                ("service_target", "printer.local:9000"),
                ("txt", "note=lab"),
                ("host_address", "192.0.2.20"),
            ],
        ),
        ("mld", &[("group", "ff02::1")]),
        ("nbns", &[("name", "WORKSTATION"), ("suffix", "0x20")]),
        (
            "onvif-discovery",
            &[
                ("endpoint", "urn:uuid:camera-1"),
                ("types", "dn:NetworkVideoTransmitter"),
                ("scopes", "onvif://www.onvif.org/name/Camera"),
                ("xaddrs", "http://192.0.2.30/onvif/device_service"),
            ],
        ),
        (
            "ssdp-upnp",
            &[
                ("service_type", "upnp:rootdevice"),
                ("usn", "uuid:11111111-2222-3333-4444-555555555555"),
                ("location", "http://192.0.2.20/desc.xml"),
            ],
        ),
        (
            "tcp-flow",
            &[
                ("src", "192.0.2.10:51515"),
                ("dst", "192.0.2.40:443"),
                ("bytes", "15"),
            ],
        ),
        (
            "udp-flow",
            &[
                ("src", "192.0.2.10:4242"),
                ("dst", "192.0.2.41:4243"),
                ("bytes", "15"),
            ],
        ),
        (
            "ws-discovery",
            &[
                ("endpoint", "urn:uuid:device-1"),
                ("types", "dn:Device"),
                ("scopes", "urn:example:lab"),
                ("xaddrs", "http://192.0.2.30/device"),
            ],
        ),
    ];
    for (name, expected) in cases {
        let observations = OfflinePassiveAdapter
            .ingest_pcap(
                "x",
                &fs::read(fixtures().join(format!("{name}.pcap"))).unwrap(),
                &PassiveOptions::default(),
            )
            .unwrap();
        let one = if *name == "dhcpv4" {
            observations
                .iter()
                .find(|o| o.facts.iter().any(|f| f.key == "yiaddr"))
                .unwrap()
        } else if *name == "dhcpv6" {
            observations
                .iter()
                .find(|o| o.facts.iter().any(|f| f.key == "iaaddr"))
                .unwrap()
        } else {
            &observations[0]
        };
        let actual: Vec<_> = one
            .facts
            .iter()
            .filter(|f| f.key != "mac")
            .map(|f| (f.key.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(&actual, expected, "{name}");
    }
}

#[test]
fn mdns_emits_record_semantics_with_per_record_ttls() {
    let one = OfflinePassiveAdapter
        .ingest_pcap(
            "x",
            &fs::read(fixtures().join("mdns-dns-sd.pcap")).unwrap(),
            &PassiveOptions::default(),
        )
        .unwrap()
        .pop()
        .unwrap();
    let expected = [
        (
            "service_instance",
            "_http._tcp.local -> Neon Printer._http._tcp.local",
            4500,
        ),
        ("service_target", "printer.local:9000", 120),
        ("txt", "note=lab", 300),
        ("host_address", "192.0.2.20", 60),
    ];
    for (key, value, ttl) in expected {
        let fact = one.facts.iter().find(|f| f.key == key).unwrap();
        assert_eq!(fact.value, value);
        assert_eq!(
            fact.expires_at.unwrap() - fact.observed_at,
            chrono::Duration::seconds(ttl)
        );
    }
}

#[test]
fn dhcp_fields_are_protocol_fields_not_opaque_payloads() {
    let load = |name: &str, required: &str| {
        OfflinePassiveAdapter
            .ingest_pcap(
                "x",
                &fs::read(fixtures().join(format!("{name}.pcap"))).unwrap(),
                &PassiveOptions::default(),
            )
            .unwrap()
            .into_iter()
            .find(|o| o.facts.iter().any(|f| f.key == required))
            .unwrap()
    };
    let v4 = load("dhcpv4", "yiaddr");
    for (key, value) in [
        ("yiaddr", "192.0.2.100"),
        ("chaddr", "00:11:22:33:44:55"),
        ("client_id", "01001122334455"),
    ] {
        assert_eq!(v4.facts.iter().find(|f| f.key == key).unwrap().value, value);
    }
    let v6 = load("dhcpv6", "iaaddr");
    for key in [
        "client_duid",
        "fqdn",
        "iaaddr",
        "preferred_lifetime",
        "valid_lifetime",
    ] {
        assert!(v6.facts.iter().any(|f| f.key == key), "missing {key}");
    }
    assert!(!v6.facts.iter().any(|f| f.key == "client_id"));
}

#[test]
fn flow_payload_secrets_never_escape_normalized_values_or_json() {
    for (name, secret) in [
        ("tcp-flow", "NEON_TCP_SECRET"),
        ("udp-flow", "NEON_UDP_SECRET"),
    ] {
        let obs = OfflinePassiveAdapter
            .ingest_pcap(
                "x",
                &fs::read(fixtures().join(format!("{name}.pcap"))).unwrap(),
                &PassiveOptions::default(),
            )
            .unwrap();
        let json = serde_json::to_string(&obs).unwrap();
        assert!(!json.contains(secret));
        assert!(
            obs.iter()
                .flat_map(|o| &o.facts)
                .all(|f| !f.value.contains(secret))
        );
    }
}

#[test]
fn classic_pcap_supports_big_endian_and_multiple_records() {
    let little = fs::read(fixtures().join("arp.pcap")).unwrap();
    let mut big = Vec::new();
    big.extend(0xa1b2c3d4u32.to_be_bytes());
    big.extend(2u16.to_be_bytes());
    big.extend(4u16.to_be_bytes());
    big.extend(0i32.to_be_bytes());
    big.extend(0u32.to_be_bytes());
    big.extend(65535u32.to_be_bytes());
    big.extend(1u32.to_be_bytes());
    let frame = &little[40..];
    for sec in [1_704_067_200u32, 1_704_067_201] {
        big.extend(sec.to_be_bytes());
        big.extend(123_000u32.to_be_bytes());
        big.extend((frame.len() as u32).to_be_bytes());
        big.extend((frame.len() as u32).to_be_bytes());
        big.extend(frame);
    }
    let obs = OfflinePassiveAdapter
        .ingest_pcap("x", &big, &PassiveOptions::default())
        .unwrap();
    assert_eq!(obs.len(), 2);
    assert_eq!(obs[0].observed_at.timestamp_subsec_millis(), 123);
}

#[test]
fn pcap_rejects_non_ethernet_and_bad_record_lengths() {
    let mut p = fs::read(fixtures().join("arp.pcap")).unwrap();
    p[20..24].copy_from_slice(&101u32.to_le_bytes());
    assert!(
        OfflinePassiveAdapter
            .ingest_pcap("x", &p, &PassiveOptions::default())
            .is_err()
    );
    let mut p = fs::read(fixtures().join("arp.pcap")).unwrap();
    p[32..36].copy_from_slice(&70_000u32.to_le_bytes());
    assert!(
        OfflinePassiveAdapter
            .ingest_pcap("x", &p, &PassiveOptions::default())
            .is_err()
    );
}

fn udp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0xff; 6];
    frame.extend([0, 17, 34, 51, 68, 85]);
    frame.extend(0x0800u16.to_be_bytes());
    let mut ip = vec![
        0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 10, 239, 255, 255, 250,
    ];
    ip[2..4].copy_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
    let mut udp = Vec::new();
    udp.extend(src_port.to_be_bytes());
    udp.extend(dst_port.to_be_bytes());
    udp.extend(((8 + payload.len()) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(payload);
    ip.extend(udp);
    frame.extend(ip);
    frame
}

#[test]
fn dns_pointer_loops_and_malformed_counts_are_rejected() {
    let looped = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1];
    let err = lattice_sensor::PassiveAdapter::normalize(
        &OfflinePassiveAdapter,
        "x",
        chrono::Utc::now(),
        &udp_frame(53000, 53, &looped),
        &PassiveOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(err, lattice_sensor::PassiveParseError::Metadata));
    let truncated = [0, 1, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(53000, 53, &truncated),
            &PassiveOptions::default()
        )
        .is_err()
    );
}

#[test]
fn xml_dtd_entities_depth_and_event_budgets_are_rejected() {
    for xml in [
        b"<!DOCTYPE x [<!ENTITY boom 'x'>]><Envelope>&boom;</Envelope>".as_slice(),
        format!("{}{}", "<x>".repeat(33), "</x>".repeat(33)).as_bytes(),
    ] {
        assert!(
            lattice_sensor::PassiveAdapter::normalize(
                &OfflinePassiveAdapter,
                "x",
                chrono::Utc::now(),
                &udp_frame(3702, 3702, xml),
                &PassiveOptions::default()
            )
            .is_err()
        );
    }
}

#[test]
fn ws_discovery_requires_standard_namespaces_and_document_scope() {
    let wrong_all = br#"<s:Envelope xmlns:s="urn:fake-soap" xmlns:a="urn:fake-wsa" xmlns:d="urn:fake-wsd"><s:Body><d:ProbeMatch><a:EndpointReference><a:Address>urn:spoof</a:Address></a:EndpointReference><d:Types>dn:Device</d:Types><d:XAddrs>http://spoof</d:XAddrs></d:ProbeMatch></s:Body></s:Envelope>"#;
    let outside = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:d="http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"><d:Types>dn:Device</d:Types></s:Envelope>"#;
    let unbound = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><d:ProbeMatch><d:Types>dn:Device</d:Types></d:ProbeMatch></s:Body></s:Envelope>"#;
    let mixed = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="urn:fake-wsa" xmlns:d="urn:fake-wsd"><s:Body><d:ProbeMatch><a:EndpointReference><a:Address>urn:spoof</a:Address></a:EndpointReference><d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>onvif://www.onvif.org/name/Camera</d:Scopes></d:ProbeMatch></s:Body></s:Envelope>"#;
    for (label, xml) in [
        ("wrong", wrong_all.as_slice()),
        ("outside", outside.as_slice()),
        ("unbound", unbound.as_slice()),
        ("mixed", mixed.as_slice()),
    ] {
        assert!(
            lattice_sensor::PassiveAdapter::normalize(
                &OfflinePassiveAdapter,
                "x",
                chrono::Utc::now(),
                &udp_frame(3702, 3702, xml),
                &PassiveOptions::default()
            )
            .is_err(),
            "{label}"
        );
    }
}

#[test]
fn ws_discovery_fixtures_use_supported_standard_namespaces() {
    for name in ["ws-discovery", "onvif-discovery"] {
        let bytes = fs::read(fixtures().join(format!("{name}.pcap"))).unwrap();
        let wire = String::from_utf8_lossy(&bytes);
        assert!(wire.contains("http://www.w3.org/2003/05/soap-envelope"));
        assert!(wire.contains("http://www.w3.org/2005/08/addressing"));
        assert!(wire.contains("discovery/2009/01") || wire.contains("ws/2005/04/discovery"));
        assert_eq!(
            OfflinePassiveAdapter
                .ingest_pcap("x", &bytes, &PassiveOptions::default())
                .unwrap()[0]
                .protocol,
            name
        );
    }
}

#[test]
fn invalid_utf8_and_oversized_metadata_are_rejected() {
    let oversized = vec![b'x'; 2_049];
    for (label, payload) in [
        ("invalid utf8", &[0xff, 0xfe][..]),
        ("oversized", oversized.as_slice()),
    ] {
        assert!(
            lattice_sensor::PassiveAdapter::normalize(
                &OfflinePassiveAdapter,
                "x",
                chrono::Utc::now(),
                &udp_frame(3702, 3702, payload),
                &PassiveOptions::default(),
            )
            .is_err(),
            "{label}"
        );
    }
}

#[test]
fn invalid_tcp_data_offset_and_udp_declared_length_are_rejected() {
    let mut tcp = fs::read(fixtures().join("tcp-flow.pcap")).unwrap();
    tcp[40 + 14 + 20 + 12] = 0xf0;
    assert!(
        OfflinePassiveAdapter
            .ingest_pcap("x", &tcp, &PassiveOptions::default())
            .is_err()
    );
    let mut udp = fs::read(fixtures().join("udp-flow.pcap")).unwrap();
    udp[40 + 14 + 20 + 4..40 + 14 + 20 + 6].copy_from_slice(&0xffffu16.to_be_bytes());
    assert!(
        OfflinePassiveAdapter
            .ingest_pcap("x", &udp, &PassiveOptions::default())
            .is_err()
    );
}

#[test]
fn fragmented_ip_packets_are_not_normalized_without_reassembly() {
    let mut v4 = fs::read(fixtures().join("udp-flow.pcap")).unwrap()[40..].to_vec();
    v4[14 + 6..14 + 8].copy_from_slice(&1u16.to_be_bytes());
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &v4,
            &PassiveOptions::default()
        )
        .unwrap()
        .is_empty()
    );

    let mut v6 = fs::read(fixtures().join("ipv6-ndp.pcap")).unwrap()[40..].to_vec();
    let payload_len = u16::from_be_bytes([v6[18], v6[19]]) + 8;
    v6[18..20].copy_from_slice(&payload_len.to_be_bytes());
    v6[20] = 44;
    v6.splice(54..54, [58, 0, 0, 1, 0, 0, 0, 1]);
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &v6,
            &PassiveOptions::default()
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn dhcp_client_and_server_identities_are_separate_observations() {
    for name in ["dhcpv4", "dhcpv6"] {
        let observations = OfflinePassiveAdapter
            .ingest_pcap(
                "x",
                &fs::read(fixtures().join(format!("{name}.pcap"))).unwrap(),
                &PassiveOptions::default(),
            )
            .unwrap();
        assert!(
            observations.len() >= 2,
            "{name} needs client and server observations"
        );
        for one in &observations {
            let has_client = one.facts.iter().any(|f| {
                matches!(
                    f.key.as_str(),
                    "client_id" | "client_duid" | "hostname" | "fqdn" | "chaddr"
                )
            });
            let has_server = one
                .facts
                .iter()
                .any(|f| matches!(f.key.as_str(), "server_id" | "server_duid"));
            assert!(!(has_client && has_server), "mixed DHCP identity: {one:?}");
        }
        assert!(observations.iter().any(|o| {
            o.facts
                .iter()
                .any(|f| f.key == "service" && f.value.contains("dhcp"))
        }));
        let server = observations
            .iter()
            .find(|o| o.subject_ip.is_some() && o.facts.iter().any(|f| f.key == "service"))
            .unwrap();
        assert_eq!(server.subject_mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(
            server.subject_ip.unwrap().to_string(),
            if name == "dhcpv4" {
                "192.0.2.1"
            } else {
                "2001:db8::1"
            }
        );
        let leased = observations
            .iter()
            .find(|o| {
                o.facts
                    .iter()
                    .any(|f| matches!(f.key.as_str(), "yiaddr" | "iaaddr"))
            })
            .unwrap();
        assert_eq!(leased.subject_mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(
            leased.subject_ip.unwrap().to_string(),
            if name == "dhcpv4" {
                "192.0.2.100"
            } else {
                "2001:db8::2"
            }
        );
    }
}

#[test]
fn dhcpv6_direction_and_relay_context_never_cross_identity_subjects() {
    let observations = OfflinePassiveAdapter
        .ingest_pcap(
            "x",
            &fs::read(fixtures().join("dhcpv6.pcap")).unwrap(),
            &PassiveOptions::default(),
        )
        .unwrap();
    assert_eq!(observations.len(), 8);
    assert!(
        observations
            .iter()
            .all(|o| o.subject_mac.as_deref() != Some("66:55:44:33:22:11"))
    );
    for one in &observations {
        let client = one.facts.iter().any(|f| f.key == "client_duid");
        let server = one.facts.iter().any(|f| f.key == "server_duid");
        assert!(!(client && server));
        if client {
            assert_ne!(
                one.subject_ip.map(|x| x.to_string()).as_deref(),
                Some("2001:db8::1")
            );
        }
    }
    let referenced: Vec<_> = observations
        .iter()
        .filter(|o| o.facts.iter().any(|f| f.key == "server_duid") && o.subject_ip.is_none())
        .collect();
    assert!(referenced.len() >= 3);
    assert!(referenced.iter().all(|o| o.subject_mac.is_none()));
    let direct = observations
        .iter()
        .find(|o| o.facts.iter().any(|f| f.key == "server_duid") && o.subject_ip.is_some())
        .unwrap();
    assert_eq!(direct.subject_ip.unwrap().to_string(), "2001:db8::1");
    assert_eq!(direct.subject_mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
}

fn relay_message(kind: u8, inner: &[u8]) -> Vec<u8> {
    let mut q = vec![kind, 0];
    q.extend([0u8; 32]);
    q.extend([0, 9]);
    q.extend((inner.len() as u16).to_be_bytes());
    q.extend(inner);
    q
}

#[test]
fn dhcpv6_relay_headers_messages_and_recursion_are_bounded() {
    let missing = vec![12, 0];
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 547, &missing),
            &PassiveOptions::default()
        )
        .is_err()
    );
    let inner = [1, 0, 0, 1];
    let mut duplicate = relay_message(12, &inner);
    duplicate.extend([0, 9, 0, 4, 1, 0, 0, 1]);
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 547, &duplicate),
            &PassiveOptions::default()
        )
        .is_err()
    );
    let huge = relay_message(12, &vec![0u8; 16_385]);
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 547, &huge),
            &PassiveOptions::default()
        )
        .is_err()
    );
    let nested = relay_message(12, &relay_message(12, &relay_message(12, &inner)));
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 547, &nested),
            &PassiveOptions::default()
        )
        .is_err()
    );
}

#[test]
fn relayed_dhcpv4_reply_does_not_attach_relay_mac_to_server_identity() {
    let bytes = fs::read(fixtures().join("dhcpv4.pcap")).unwrap();
    let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
    reader.next_packet().unwrap().unwrap();
    let mut reply = reader.next_packet().unwrap().unwrap().data.into_owned();
    reply[14 + 12..14 + 16].copy_from_slice(&[192, 0, 2, 254]);
    let observations = lattice_sensor::PassiveAdapter::normalize(
        &OfflinePassiveAdapter,
        "x",
        chrono::Utc::now(),
        &reply,
        &PassiveOptions::default(),
    )
    .unwrap();
    let server = observations
        .iter()
        .find(|o| o.facts.iter().any(|f| f.key == "service"))
        .unwrap();
    assert_eq!(server.subject_ip.unwrap().to_string(), "192.0.2.1");
    assert_eq!(server.subject_mac, None);
}

#[test]
fn dhcp_option_amplification_and_duplicate_singletons_are_rejected() {
    let zero_duid = [7, 0, 0, 1, 0, 1, 0, 0];
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 546, &zero_duid),
            &PassiveOptions::default()
        )
        .is_err()
    );
    let mut repeated = vec![7, 0, 0, 1];
    for _ in 0..65 {
        repeated.extend([0xfe, 0xdc, 0, 0]);
    }
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 546, &repeated),
            &PassiveOptions::default()
        )
        .is_err()
    );
    let duplicate = [7, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 2];
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 546, &duplicate),
            &PassiveOptions::default()
        )
        .is_err()
    );
    let mut huge_duid = vec![7, 0, 0, 1, 0, 1];
    huge_duid.extend(60_000u16.to_be_bytes());
    huge_duid.extend(vec![1; 60_000]);
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 546, &huge_duid),
            &PassiveOptions::default()
        )
        .is_err()
    );
    let mut fqdn = vec![7, 0, 0, 1, 0, 39, 0x04, 0x01, 0];
    fqdn.extend(vec![b'a'; 1024]);
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 546, &fqdn),
            &PassiveOptions::default()
        )
        .is_err()
    );
    let duplicate_fqdn = [7, 0, 0, 1, 0, 39, 0, 2, 0, 0, 0, 39, 0, 2, 0, 0];
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 546, &duplicate_fqdn),
            &PassiveOptions::default()
        )
        .is_err()
    );

    let mut many_addresses = vec![7, 0, 0, 1, 0, 3, 0, 0];
    let mut ia = vec![0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0];
    for index in 0..9u8 {
        let mut addr = [0u8; 24];
        addr[15] = index + 1;
        addr[19] = 1;
        addr[23] = 2;
        ia.extend([0, 5, 0, 24]);
        ia.extend(addr);
    }
    let ia_len = (ia.len() as u16).to_be_bytes();
    many_addresses[6..8].copy_from_slice(&ia_len);
    many_addresses.extend(ia);
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &udp_frame(547, 546, &many_addresses),
            &PassiveOptions::default()
        )
        .is_err()
    );
}

#[test]
fn chrono_max_timestamp_returns_typed_error_instead_of_panicking() {
    let frame = fs::read(fixtures().join("arp.pcap")).unwrap()[40..].to_vec();
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::DateTime::<chrono::Utc>::MAX_UTC,
            &frame,
            &PassiveOptions::default()
        )
        .is_err()
    );
}

#[test]
fn pcap_input_and_record_aggregation_are_bounded() {
    let oversized = vec![0u8; 4 * 1024 * 1024 + 1];
    assert!(
        OfflinePassiveAdapter
            .ingest_pcap("x", &oversized, &PassiveOptions::default())
            .is_err()
    );
    let one = fs::read(fixtures().join("arp.pcap")).unwrap();
    let record = &one[24..];
    let mut many = one[..24].to_vec();
    for _ in 0..4097 {
        many.extend(record);
    }
    assert!(
        OfflinePassiveAdapter
            .ingest_pcap("x", &many, &PassiveOptions::default())
            .is_err()
    );
}

#[test]
fn xml_fields_reject_nested_or_detached_text_and_namespace_rebinding() {
    let ns = "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:d=\"http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01\"";
    let cases = [
        format!(
            "<s:Envelope {ns}><s:Body><d:ProbeMatch><d:Types></d:Types>dn:Device</d:ProbeMatch></s:Body></s:Envelope>"
        ),
        format!(
            "<s:Envelope {ns}><s:Body><d:ProbeMatch><d:Types><fake>dn:Device</fake></d:Types></d:ProbeMatch></s:Body></s:Envelope>"
        ),
        format!(
            "<s:Envelope {ns} xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\"><s:Body><d:ProbeMatch><d:Types><fake xmlns:dn=\"urn:spoof\">dn:NetworkVideoTransmitter</fake></d:Types></d:ProbeMatch></s:Body></s:Envelope>"
        ),
        format!(
            "<s:Envelope {ns}><s:Body><d:ProbeMatch><d:wrapper><d:Types>dn:Device</d:Types></d:wrapper></d:ProbeMatch></s:Body></s:Envelope>"
        ),
        format!(
            "<s:Envelope {ns} xmlns:a=\"http://www.w3.org/2005/08/addressing\"><s:Body><d:ProbeMatch><d:wrapper><a:EndpointReference><a:Address>urn:spoof</a:Address></a:EndpointReference></d:wrapper></d:ProbeMatch></s:Body></s:Envelope>"
        ),
        format!(
            "<s:Envelope {ns}><s:Body><d:ProbeMatch><d:Types>dn:Device</d:Scopes></d:ProbeMatch></s:Body></s:Envelope>"
        ),
        format!(
            "<s:Envelope {ns} xmlns:a=\"http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01\" xmlns:b=\"http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01\"><s:Body><d:ProbeMatch><a:Types>dn:Device</b:Types></d:ProbeMatch></s:Body></s:Envelope>"
        ),
    ];
    for xml in cases {
        assert!(
            lattice_sensor::PassiveAdapter::normalize(
                &OfflinePassiveAdapter,
                "x",
                chrono::Utc::now(),
                &udp_frame(3702, 3702, xml.as_bytes()),
                &PassiveOptions::default()
            )
            .is_err()
        );
    }
}
#[test]
fn dns_queries_respect_privacy_switch() {
    let bytes = fs::read(fixtures().join("dns-query.pcap")).unwrap();
    let observations = OfflinePassiveAdapter
        .ingest_pcap(
            "x",
            &bytes,
            &PassiveOptions {
                metadata_enabled: false,
            },
        )
        .unwrap();
    assert!(
        observations
            .iter()
            .all(|observation| observation.facts.iter().all(|fact| fact.key != "query"))
    );
}
#[test]
fn malformed_and_unsupported_inputs_are_bounded() {
    let adapter = OfflinePassiveAdapter;
    assert!(
        adapter
            .ingest_pcap("x", &[0; 3], &PassiveOptions::default())
            .is_err()
    );
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &adapter,
            "x",
            chrono::Utc::now(),
            &[0; 14],
            &PassiveOptions::default()
        )
        .unwrap()
        .is_empty()
    );
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &adapter,
            "x",
            chrono::Utc::now(),
            &[0; 13],
            &PassiveOptions::default()
        )
        .is_err()
    );
}

#[test]
fn invalid_utf8_oversized_text_and_xml_entities_are_rejected_without_observation() {
    let mut bytes = fs::read(fixtures().join("ws-discovery.pcap")).unwrap();
    let at = 24 + 16 + 14 + 20 + 8;
    bytes[at..at + 9].copy_from_slice(b"<!DOCTYPE");
    // The frame itself is rejected...
    let frame = PcapReader::new(Cursor::new(bytes.as_slice()))
        .unwrap()
        .next_packet()
        .unwrap()
        .unwrap()
        .data
        .into_owned();
    assert!(
        lattice_sensor::PassiveAdapter::normalize(
            &OfflinePassiveAdapter,
            "x",
            chrono::Utc::now(),
            &frame,
            &PassiveOptions::default()
        )
        .is_err()
    );
    // ...and an offline ingest counts it as skipped without producing an observation.
    let report = OfflinePassiveAdapter
        .ingest_pcap_report("x", &bytes, &PassiveOptions::default())
        .unwrap();
    assert!(report.observations.is_empty());
    assert_eq!(report.skipped_frames, 1);
}

fn pcap_from_frames(frames: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xa1b2_c3d4u32.to_le_bytes());
    out.extend(2u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(65535u32.to_le_bytes());
    out.extend(1u32.to_le_bytes());
    for (n, frame) in frames.iter().enumerate() {
        out.extend((1_704_067_200u32 + n as u32).to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend((frame.len() as u32).to_le_bytes());
        out.extend((frame.len() as u32).to_le_bytes());
        out.extend(*frame);
    }
    out
}

/// An mDNS response carrying `count` A records for `a.local`.
fn mdns_response_with_a_records(count: u16) -> Vec<u8> {
    let mut payload = vec![0, 0, 0x84, 0];
    payload.extend(0u16.to_be_bytes());
    payload.extend(count.to_be_bytes());
    payload.extend([0, 0, 0, 0]);
    for n in 0..count {
        payload.extend([1, b'a', 5, b'l', b'o', b'c', b'a', b'l', 0]);
        payload.extend(1u16.to_be_bytes());
        payload.extend(1u16.to_be_bytes());
        payload.extend(60u32.to_be_bytes());
        payload.extend(4u16.to_be_bytes());
        payload.extend([192, 0, 2, (n % 200) as u8 + 1]);
    }
    payload
}

#[test]
fn offline_ingest_skips_malformed_frames_and_reports_the_count() {
    let arp = fs::read(fixtures().join("arp.pcap")).unwrap();
    let mut reader = PcapReader::new(Cursor::new(arp.as_slice())).unwrap();
    let good = reader.next_packet().unwrap().unwrap().data.into_owned();
    let looped_dns = udp_frame(
        53000,
        53,
        &[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1],
    );
    let odd_nbns = udp_frame(137, 137, &[1, 2, 3]);
    let capture = pcap_from_frames(&[&good, &looped_dns, &good, &odd_nbns]);
    let report = OfflinePassiveAdapter
        .ingest_pcap_report("x", &capture, &PassiveOptions::default())
        .unwrap();
    assert_eq!(report.skipped_frames, 2);
    assert_eq!(report.observations.len(), 2);
    assert!(
        report
            .observations
            .iter()
            .all(|observation| observation.protocol == "arp")
    );
    // The plain entry point keeps its shape and the same tolerance.
    assert_eq!(
        OfflinePassiveAdapter
            .ingest_pcap("x", &capture, &PassiveOptions::default())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn offline_ingest_still_rejects_a_capture_that_is_mostly_garbage() {
    let odd_nbns = udp_frame(137, 137, &[1, 2, 3]);
    let frames: Vec<&[u8]> = (0..=lattice_sensor::MAX_SKIPPED_FRAMES)
        .map(|_| odd_nbns.as_slice())
        .collect();
    assert!(matches!(
        OfflinePassiveAdapter.ingest_pcap_report(
            "x",
            &pcap_from_frames(&frames),
            &PassiveOptions::default()
        ),
        Err(lattice_sensor::PassiveParseError::Metadata)
    ));
}

#[test]
fn oversized_mdns_responses_keep_their_leading_records_instead_of_failing() {
    let frame = udp_frame(5353, 5353, &mdns_response_with_a_records(40));
    let observations = lattice_sensor::PassiveAdapter::normalize(
        &OfflinePassiveAdapter,
        "x",
        chrono::Utc::now(),
        &frame,
        &PassiveOptions::default(),
    )
    .unwrap();
    let addresses = observations
        .iter()
        .flat_map(|observation| observation.facts.iter())
        .filter(|fact| fact.key == "host_address")
        .count();
    assert!(addresses > 0 && addresses < 40, "kept {addresses} of 40");
    assert_eq!(
        addresses,
        lattice_sensor::passive::MAX_FACTS_PER_OBSERVATION - 1
    );
}
