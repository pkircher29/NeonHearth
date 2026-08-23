use std::{fs, path::PathBuf};

const CASES: &[(&str, &str)] = &[
    ("arp", "ip=192.0.2.10;binding=00:11:22:33:44:55"),
    ("ipv6-ndp", "ip=2001:db8::10;binding=00:11:22:33:44:55"),
    (
        "dhcpv4",
        "hostname=lab-client;client_id=01-001122334455;server=192.0.2.1;lease=3600",
    ),
    (
        "dhcpv6",
        "hostname=lab-v6;client_id=00010001;server=2001:db8::1;lease=3600",
    ),
    (
        "mdns-dns-sd",
        "name=printer.example.test;service=_ipp._tcp.example.test;ttl=120",
    ),
    (
        "ssdp-upnp",
        "st=upnp:rootdevice;usn=uuid:11111111-2222-3333-4444-555555555555;location=http://192.0.2.20/desc.xml;max_age=1800",
    ),
    ("llmnr", "name=workstation.example.test"),
    ("nbns", "name=WORKSTATION"),
    (
        "ws-discovery",
        "endpoint=urn:uuid:11111111-2222-3333-4444-555555555555;types=dn:NetworkVideoTransmitter;scopes=onvif://www.onvif.org/name/Camera;xaddrs=http://192.0.2.30/onvif/device_service",
    ),
    (
        "onvif-discovery",
        "endpoint=urn:uuid:11111111-2222-3333-4444-555555555555;types=dn:NetworkVideoTransmitter;scopes=onvif://www.onvif.org/name/Camera;xaddrs=http://192.0.2.30/onvif/device_service",
    ),
    ("igmp", "group=239.255.0.1"),
    ("mld", "group=ff02::1"),
    ("dns-query", "query=update.example.test"),
    (
        "tcp-flow",
        "src=192.0.2.10:51515;dst=192.0.2.40:443;bytes=512",
    ),
    (
        "udp-flow",
        "src=192.0.2.10:5353;dst=192.0.2.41:5353;bytes=256",
    ),
];

fn main() {
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/lattice-sensor/tests/fixtures/pcap");
    fs::create_dir_all(&out).unwrap();
    for (name, fields) in CASES {
        let mut file = Vec::new();
        file.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        file.extend_from_slice(&2u16.to_le_bytes());
        file.extend_from_slice(&4u16.to_le_bytes());
        file.extend_from_slice(&0i32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&65_535u32.to_le_bytes());
        file.extend_from_slice(&1u32.to_le_bytes());
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[0, 17, 34, 51, 68, 85]);
        frame.extend_from_slice(&0x88b5u16.to_be_bytes());
        frame.extend_from_slice(format!("NH1|{name}|{fields}").as_bytes());
        file.extend_from_slice(&1_704_067_200u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        file.extend_from_slice(&frame);
        fs::write(out.join(format!("{name}.pcap")), file).unwrap();
    }
}
