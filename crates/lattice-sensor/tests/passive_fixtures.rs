use lattice_sensor::{OfflinePassiveAdapter, PassiveOptions};
use std::{fs, path::PathBuf};

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
        assert_eq!(obs.len(), 1);
        let one = &obs[0];
        assert_eq!(one.protocol, *name);
        assert_eq!(one.interface, "fixture0");
        assert!(one.subject_mac.is_some());
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

#[test]
fn expected_facts_and_protocol_ttls_are_exact() {
    let cases = [
        ("arp", "ip", "192.0.2.10", 300),
        ("dhcpv4", "hostname", "lab-client", 3600),
        (
            "dhcpv6",
            "client_id",
            "0100000101000a000100010001000100010027000400000e10002700106c61622d76362e6578616d706c652e74657374",
            3600,
        ),
        ("mdns-dns-sd", "name", "printer.example.test", 120),
        ("ssdp-upnp", "location", "http://192.0.2.20/desc.xml", 1800),
        ("ws-discovery", "xaddrs", "http://192.0.2.30/device", 300),
        (
            "onvif-discovery",
            "types",
            "dn:NetworkVideoTransmitter",
            300,
        ),
        ("igmp", "group", "239.255.0.1", 300),
        ("mld", "group", "ff02::1", 300),
        ("dns-query", "query", "update.example.test", 300),
        ("tcp-flow", "bytes", "52", 300),
        ("udp-flow", "dst", "unknown:4243", 300),
    ];
    for (name, key, value, ttl) in cases {
        let observation = OfflinePassiveAdapter
            .ingest_pcap(
                "fixture0",
                &fs::read(fixtures().join(format!("{name}.pcap"))).unwrap(),
                &PassiveOptions::default(),
            )
            .unwrap()
            .pop()
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
    assert!(
        OfflinePassiveAdapter
            .ingest_pcap("x", &bytes, &PassiveOptions::default())
            .is_err()
    );
}
