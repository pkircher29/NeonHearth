use std::{fs, path::PathBuf};
const MAC: [u8; 6] = [0, 17, 34, 51, 68, 85];
const S4: [u8; 4] = [192, 0, 2, 10];
const S6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
fn sum(mut a: u32, b: &[u8]) -> u32 {
    for p in b.chunks(2) {
        a += u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)]) as u32;
        a = (a & 65535) + (a >> 16)
    }
    a
}
fn cks(parts: &[&[u8]]) -> u16 {
    let mut a = 0;
    for p in parts {
        a = sum(a, p)
    }
    while a >> 16 > 0 {
        a = (a & 65535) + (a >> 16)
    }
    !(a as u16)
}
fn eth(t: u16, p: Vec<u8>) -> Vec<u8> {
    let mut v = vec![255; 6];
    v.extend(MAC);
    v.extend(t.to_be_bytes());
    v.extend(p);
    v
}
fn source_mac(mut frame: Vec<u8>, mac: [u8; 6]) -> Vec<u8> {
    frame[6..12].copy_from_slice(&mac);
    frame
}
fn set4(p: &mut [u8], s: [u8; 4], d: [u8; 4], protocol: u8) {
    let checksum_at = if protocol == 17 { 6 } else { 16 };
    p[checksum_at..checksum_at + 2].fill(0);
    let l = (p.len() as u16).to_be_bytes();
    let c = cks(&[&s, &d, &[0, protocol], &l, p]);
    p[checksum_at..checksum_at + 2].copy_from_slice(&c.to_be_bytes())
}
fn set6(p: &mut [u8], s: [u8; 16], d: [u8; 16], n: u8) {
    let at = if n == 17 { 6 } else { 2 };
    p[at..at + 2].fill(0);
    let l = (p.len() as u32).to_be_bytes();
    let c = cks(&[&s, &d, &l, &[0, 0, 0, n], p]);
    p[at..at + 2].copy_from_slice(&c.to_be_bytes())
}
fn v4(n: u8, s: [u8; 4], d: [u8; 4], mut p: Vec<u8>) -> Vec<u8> {
    if matches!(n, 6 | 17) {
        set4(&mut p, s, d, n)
    }
    let mut h = vec![0x45, 0, 0, 0, 0x12, 0x34, 0, 0, 64, n, 0, 0];
    h.extend(s);
    h.extend(d);
    h[2..4].copy_from_slice(&((20 + p.len()) as u16).to_be_bytes());
    let c = cks(&[&h]);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h.extend(p);
    eth(0x800, h)
}
fn v6(n: u8, s: [u8; 16], d: [u8; 16], mut p: Vec<u8>) -> Vec<u8> {
    if matches!(n, 17 | 58) {
        set6(&mut p, s, d, n)
    }
    let mut h = vec![0x60, 0, 0, 0];
    h.extend((p.len() as u16).to_be_bytes());
    h.extend([n, 64]);
    h.extend(s);
    h.extend(d);
    h.extend(p);
    eth(0x86dd, h)
}
fn hop(s: [u8; 16], d: [u8; 16], mut p: Vec<u8>) -> Vec<u8> {
    set6(&mut p, s, d, 58);
    let mut x = vec![58, 0, 5, 2, 0, 0, 1, 0];
    x.extend(p);
    let mut h = vec![0x60, 0, 0, 0];
    h.extend((x.len() as u16).to_be_bytes());
    h.extend([0, 1]);
    h.extend(s);
    h.extend(d);
    h.extend(x);
    eth(0x86dd, h)
}
fn udp(s: u16, d: u16, b: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend(s.to_be_bytes());
    p.extend(d.to_be_bytes());
    p.extend(((8 + b.len()) as u16).to_be_bytes());
    p.extend([0, 0]);
    p.extend(b);
    p
}
fn tcp(s: u16, d: u16, b: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend(s.to_be_bytes());
    p.extend(d.to_be_bytes());
    p.extend([0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0x10, 0, 0, 0, 0, 0]);
    p.extend(b);
    p
}
fn name(n: &str, v: &mut Vec<u8>) {
    for x in n.split('.') {
        v.push(x.len() as u8);
        v.extend(x.as_bytes())
    }
    v.push(0)
}
fn dns(n: &str) -> Vec<u8> {
    let mut v = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    name(n, &mut v);
    v.extend([0, 1, 0, 1]);
    v
}
fn mdns() -> Vec<u8> {
    let mut d = vec![0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0];
    name("_http._tcp.local", &mut d);
    d.extend([0, 12, 0, 1]);
    d.extend(4500u32.to_be_bytes());
    let mut r = Vec::new();
    name("Neon Printer._http._tcp.local", &mut r);
    d.extend((r.len() as u16).to_be_bytes());
    d.extend(r);
    name("Neon Printer._http._tcp.local", &mut d);
    d.extend([0, 33, 0, 1]);
    d.extend(120u32.to_be_bytes());
    let mut r = vec![0, 0, 0, 0, 0x23, 0x28];
    name("printer.local", &mut r);
    d.extend((r.len() as u16).to_be_bytes());
    d.extend(r);
    name("Neon Printer._http._tcp.local", &mut d);
    d.extend([0, 16, 0, 1]);
    d.extend(300u32.to_be_bytes());
    d.extend([0, 9, 8]);
    d.extend(b"note=lab");
    name("printer.local", &mut d);
    d.extend([0, 1, 0, 1]);
    d.extend(60u32.to_be_bytes());
    d.extend([0, 4, 192, 0, 2, 20]);
    d
}
fn opt(c: u16, b: &[u8], v: &mut Vec<u8>) {
    v.extend(c.to_be_bytes());
    v.extend((b.len() as u16).to_be_bytes());
    v.extend(b)
}
fn dh6() -> Vec<u8> {
    let mut d = vec![7, 0, 0, 1];
    opt(1, &[0, 1, 0, 1, 0, 0, 0, 1, 0, 17, 34, 51, 68, 85], &mut d);
    opt(
        2,
        &[0, 1, 0, 1, 0, 0, 0, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        &mut d,
    );
    let mut ia = vec![0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut a = S6.to_vec();
    a.extend(600u32.to_be_bytes());
    a.extend(1200u32.to_be_bytes());
    opt(5, &a, &mut ia);
    opt(3, &ia, &mut d);
    let mut f = vec![0];
    name("lab-v6.example.test", &mut f);
    opt(39, &f, &mut d);
    d
}
fn dh6_request() -> Vec<u8> {
    let mut d = vec![1, 0, 0, 1];
    opt(1, &[0, 1, 0, 1, 0, 0, 0, 1, 0, 17, 34, 51, 68, 85], &mut d);
    opt(3, &[0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0], &mut d);
    let mut f = vec![0];
    name("lab-v6.example.test", &mut f);
    opt(39, &f, &mut d);
    d
}
fn dh4() -> Vec<u8> {
    let mut d = vec![
        2, 1, 6, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 100, 0, 0, 0, 0,
    ];
    d.extend([0; 4]);
    d.extend(MAC);
    d.extend([0; 10]);
    d.resize(236, 0);
    d.extend([99, 130, 83, 99, 0, 12, 10]);
    d.extend(b"lab-client");
    d.extend([
        61, 7, 1, 0, 17, 34, 51, 68, 85, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 14, 16, 255,
    ]);
    d
}
fn dh4_request() -> Vec<u8> {
    let mut d = dh4();
    d[0] = 1;
    d[16..20].fill(0);
    let server = d
        .windows(6)
        .position(|x| x == [54, 4, 192, 0, 2, 1])
        .unwrap();
    d.drain(server..server + 6);
    d
}
fn nbns() -> Vec<u8> {
    let mut d = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32];
    let mut r = [b' '; 16];
    r[..11].copy_from_slice(b"WORKSTATION");
    r[15] = 0x20;
    for b in r {
        d.push(b'A' + (b >> 4));
        d.push(b'A' + (b & 15))
    }
    d.push(0);
    d.extend([0, 32, 0, 1]);
    d
}
fn save(n: &str, f: Vec<u8>) {
    save_many(n, &[f])
}
fn save_many(n: &str, frames: &[Vec<u8>]) {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/lattice-sensor/tests/fixtures/pcap");
    let mut v = Vec::new();
    v.extend(0xa1b2c3d4u32.to_le_bytes());
    v.extend(2u16.to_le_bytes());
    v.extend(4u16.to_le_bytes());
    v.extend(0i32.to_le_bytes());
    v.extend(0u32.to_le_bytes());
    v.extend(65535u32.to_le_bytes());
    v.extend(1u32.to_le_bytes());
    for (index, f) in frames.iter().enumerate() {
        v.extend((1_704_067_200u32 + index as u32).to_le_bytes());
        v.extend(123_000u32.to_le_bytes());
        v.extend((f.len() as u32).to_le_bytes());
        v.extend((f.len() as u32).to_le_bytes());
        v.extend(f);
    }
    fs::write(p.join(format!("{n}.pcap")), v).unwrap()
}
fn main() {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/lattice-sensor/tests/fixtures/pcap");
    fs::create_dir_all(p).unwrap();
    let mut a = vec![0, 1, 8, 0, 6, 4, 0, 1];
    a.extend(MAC);
    a.extend(S4);
    a.extend([0; 6]);
    a.extend([192, 0, 2, 1]);
    save("arp", eth(0x806, a));
    let d6 = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 16];
    let mut nd = vec![135, 0, 0, 0, 0, 0, 0, 0];
    nd.extend([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16]);
    nd.extend([1, 1]);
    nd.extend(MAC);
    save("ipv6-ndp", v6(58, S6, d6, nd));
    save_many(
        "dhcpv4",
        &[
            v4(17, [0; 4], [255; 4], udp(68, 67, &dh4_request())),
            source_mac(
                v4(17, [192, 0, 2, 1], [255; 4], udp(67, 68, &dh4())),
                [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            ),
        ],
    );
    save_many(
        "dhcpv6",
        &[
            v6(
                17,
                S6,
                [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2],
                udp(546, 547, &dh6_request()),
            ),
            source_mac(
                v6(
                    17,
                    [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    S6,
                    udp(547, 546, &dh6()),
                ),
                [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            ),
        ],
    );
    save(
        "mdns-dns-sd",
        v4(
            17,
            [192, 0, 2, 20],
            [224, 0, 0, 251],
            udp(5353, 5353, &mdns()),
        ),
    );
    save(
        "llmnr",
        v4(
            17,
            [192, 0, 2, 21],
            [224, 0, 0, 252],
            udp(5355, 5355, &dns("workstation.local")),
        ),
    );
    save(
        "dns-query",
        v4(
            17,
            S4,
            [192, 0, 2, 53],
            udp(53000, 53, &dns("update.example.test")),
        ),
    );
    save(
        "nbns",
        v4(
            17,
            [192, 0, 2, 22],
            [192, 0, 2, 255],
            udp(137, 137, &nbns()),
        ),
    );
    let s=b"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nUSN: uuid:11111111-2222-3333-4444-555555555555\r\nLOCATION: http://192.0.2.20/desc.xml\r\nCACHE-CONTROL: max-age=1800\r\n\r\n";
    save(
        "ssdp-upnp",
        v4(
            17,
            [192, 0, 2, 20],
            [239, 255, 255, 250],
            udp(1900, 1900, s),
        ),
    );
    let w=br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="urn:example"><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:device-1</a:Address></a:EndpointReference><d:Types>dn:Device</d:Types><d:Scopes>urn:example:lab</d:Scopes><d:XAddrs>http://192.0.2.30/device</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#;
    save(
        "ws-discovery",
        v4(
            17,
            [192, 0, 2, 30],
            [239, 255, 255, 250],
            udp(3702, 3702, w),
        ),
    );
    let o=br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:d="http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:camera-1</a:Address></a:EndpointReference><d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>onvif://www.onvif.org/name/Camera</d:Scopes><d:XAddrs>http://192.0.2.30/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#;
    save(
        "onvif-discovery",
        v4(
            17,
            [192, 0, 2, 30],
            [239, 255, 255, 250],
            udp(3702, 3702, o),
        ),
    );
    let mut g = vec![0x16, 0, 0, 0, 239, 255, 0, 1];
    let c = cks(&[&g]);
    g[2..4].copy_from_slice(&c.to_be_bytes());
    save("igmp", v4(2, S4, [239, 255, 0, 1], g));
    let mut m = vec![131, 0, 0, 0, 0, 0, 0, 0];
    m.extend([0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    save(
        "mld",
        hop(S6, [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], m),
    );
    save(
        "tcp-flow",
        v4(6, S4, [192, 0, 2, 40], tcp(51515, 443, b"NEON_TCP_SECRET")),
    );
    save(
        "udp-flow",
        v4(17, S4, [192, 0, 2, 41], udp(4242, 4243, b"NEON_UDP_SECRET")),
    );
}
