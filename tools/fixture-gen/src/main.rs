use std::{fs, path::PathBuf};
fn eth(ty: u16, p: Vec<u8>) -> Vec<u8> {
    let mut v = vec![255; 6];
    v.extend([0, 17, 34, 51, 68, 85]);
    v.extend(ty.to_be_bytes());
    v.extend(p);
    v
}
fn v4(proto: u8, src: [u8; 4], dst: [u8; 4], p: Vec<u8>) -> Vec<u8> {
    let mut v = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
    v.extend(src);
    v.extend(dst);
    let n = (20 + p.len()) as u16;
    v[2..4].copy_from_slice(&n.to_be_bytes());
    v.extend(p);
    eth(0x0800, v)
}
fn v6(next: u8, src: [u8; 16], dst: [u8; 16], p: Vec<u8>) -> Vec<u8> {
    let mut v = vec![0x60, 0, 0, 0];
    v.extend(((p.len()) as u16).to_be_bytes());
    v.extend([next, 64]);
    v.extend(src);
    v.extend(dst);
    v.extend(p);
    eth(0x86dd, v)
}
fn udp(s: u16, d: u16, p: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend(s.to_be_bytes());
    v.extend(d.to_be_bytes());
    v.extend(((8 + p.len()) as u16).to_be_bytes());
    v.extend([0, 0]);
    v.extend(p);
    v
}
fn dns(name: &str, resp: bool, ttl: u32) -> Vec<u8> {
    let mut v = vec![0x12, 0x34, if resp { 0x81 } else { 1 }, 0];
    v.extend(if resp {
        [0, 1, 0, 1, 0, 0, 0, 0]
    } else {
        [0, 1, 0, 0, 0, 0, 0, 0]
    });
    for x in name.split('.') {
        v.push(x.len() as u8);
        v.extend(x.as_bytes())
    }
    v.push(0);
    v.extend([0, 1, 0, 1]);
    if resp {
        v.extend([0xc0, 12, 0, 1, 0, 1]);
        v.extend(ttl.to_be_bytes());
        v.extend([0, 4, 192, 0, 2, 20])
    }
    v
}
fn pcap(n: &str, f: Vec<u8>) {
    let o = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/lattice-sensor/tests/fixtures/pcap");
    let mut v = Vec::new();
    v.extend(0xa1b2c3d4u32.to_le_bytes());
    v.extend(2u16.to_le_bytes());
    v.extend(4u16.to_le_bytes());
    v.extend(0i32.to_le_bytes());
    v.extend(0u32.to_le_bytes());
    v.extend(65535u32.to_le_bytes());
    v.extend(1u32.to_le_bytes());
    v.extend(1_704_067_200u32.to_le_bytes());
    v.extend(0u32.to_le_bytes());
    v.extend((f.len() as u32).to_le_bytes());
    v.extend((f.len() as u32).to_le_bytes());
    v.extend(f);
    fs::write(o.join(format!("{n}.pcap")), v).unwrap()
}
fn main() {
    let o = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/lattice-sensor/tests/fixtures/pcap");
    fs::create_dir_all(o).unwrap();
    let s = [192, 0, 2, 10];
    let mut a = vec![0, 1, 8, 0, 6, 4, 0, 1];
    a.extend([0, 17, 34, 51, 68, 85]);
    a.extend(s);
    a.extend([0; 6]);
    a.extend([192, 0, 2, 1]);
    pcap("arp", eth(0x0806, a));
    let mut nd = vec![135, 0, 0, 0];
    nd.extend([0; 4]);
    nd.extend([0x20, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16]);
    nd.extend([1, 1, 0, 17, 34, 51, 68, 85]);
    pcap(
        "ipv6-ndp",
        v6(
            58,
            [0x20, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            [255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            nd,
        ),
    );
    let mut dh = vec![1, 1, 6, 0, 18, 52, 86, 120];
    dh.extend([0; 16]);
    dh.extend([0, 17, 34, 51, 68, 85]);
    dh.extend([0; 206]);
    dh.extend([99, 130, 83, 99, 12, 10]);
    dh.extend(b"lab-client");
    dh.extend([
        61, 7, 1, 0, 17, 34, 51, 68, 85, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 14, 16, 255,
    ]);
    pcap("dhcpv4", v4(17, [0; 4], [255; 4], udp(68, 67, &dh)));
    let mut dh6 = vec![
        1, 0, 0, 1, 1, 0, 10, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 39, 0, 4, 0, 0, 14, 16, 0, 39, 0, 16,
    ];
    dh6.extend(b"lab-v6.example.test");
    pcap(
        "dhcpv6",
        v6(
            17,
            [0x20, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            [0x20, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            udp(546, 547, &dh6),
        ),
    );
    pcap(
        "mdns-dns-sd",
        v4(
            17,
            [192, 0, 2, 20],
            [224, 0, 0, 251],
            udp(5353, 5353, &dns("printer.example.test", true, 120)),
        ),
    );
    pcap(
        "llmnr",
        v4(
            17,
            [192, 0, 2, 21],
            [224, 0, 0, 252],
            udp(5355, 5355, &dns("workstation.example.test", false, 0)),
        ),
    );
    pcap(
        "nbns",
        v4(
            17,
            [192, 0, 2, 22],
            [192, 0, 2, 255],
            udp(
                137,
                137,
                b"\x12\x34\x01\x10\0\x01\0\0\0\0\0\0\x20WORKSTATION     \0\0\x20\0\x01",
            ),
        ),
    );
    let ss=b"NOTIFY * HTTP/1.1\r\nNT:upnp:rootdevice\r\nUSN:uuid:11111111-2222-3333-4444-555555555555\r\nLOCATION:http://192.0.2.20/desc.xml\r\nCACHE-CONTROL:max-age=1800\r\n\r\n";
    pcap(
        "ssdp-upnp",
        v4(
            17,
            [192, 0, 2, 20],
            [239, 255, 255, 250],
            udp(1900, 1900, ss),
        ),
    );
    let x=b"<Envelope><ProbeMatch><EndpointReference>urn:uuid:11111111-2222-3333-4444-555555555555</EndpointReference><Types>dn:Device</Types><Scopes>urn:example:lab</Scopes><XAddrs>http://192.0.2.30/device</XAddrs></ProbeMatch></Envelope>";
    for n in ["ws-discovery"] {
        pcap(
            n,
            v4(
                17,
                [192, 0, 2, 30],
                [239, 255, 255, 250],
                udp(3702, 3702, x),
            ),
        )
    }
    let x=b"<Envelope><ProbeMatch><EndpointReference>urn:uuid:11111111-2222-3333-4444-555555555555</EndpointReference><Types>dn:NetworkVideoTransmitter</Types><Scopes>onvif://www.onvif.org/name/Camera</Scopes><XAddrs>http://192.0.2.30/onvif/device_service</XAddrs></ProbeMatch></Envelope>";
    pcap(
        "onvif-discovery",
        v4(
            17,
            [192, 0, 2, 30],
            [239, 255, 255, 250],
            udp(3702, 3702, x),
        ),
    );
    pcap(
        "igmp",
        v4(2, s, [239, 255, 0, 1], vec![0x16, 0, 0, 0, 239, 255, 0, 1]),
    );
    pcap(
        "mld",
        v6(
            58,
            [0x20, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            [255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            vec![
                131, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
        ),
    );
    pcap(
        "dns-query",
        v4(
            17,
            s,
            [192, 0, 2, 53],
            udp(53000, 53, &dns("update.example.test", false, 0)),
        ),
    );
    let mut t = Vec::new();
    t.extend(51515u16.to_be_bytes());
    t.extend(443u16.to_be_bytes());
    t.extend([0; 8]);
    t.extend([0x50, 0x18, 0, 0, 0, 0, 0, 0]);
    t.extend([0; 32]);
    pcap("tcp-flow", v4(6, s, [192, 0, 2, 40], t));
    pcap(
        "udp-flow",
        v4(17, s, [192, 0, 2, 41], udp(4242, 4243, &[0; 16])),
    )
}
